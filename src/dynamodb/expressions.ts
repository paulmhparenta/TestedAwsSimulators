/**
 * DynamoDB expression language for the simulator: a tokenizer, recursive
 * descent parsers for condition/filter, key condition, update and projection
 * expressions, and their evaluators.
 *
 * Grammar (from the DynamoDB developer guide):
 *
 *   condition ::= operand comparator operand
 *               | operand BETWEEN operand AND operand
 *               | operand IN ( operand (, operand)* )
 *               | function
 *               | condition AND condition | condition OR condition
 *               | NOT condition | ( condition )
 *   comparator ::= = | <> | < | <= | > | >=
 *   function   ::= attribute_exists(path) | attribute_not_exists(path)
 *                | attribute_type(path, :type) | begins_with(path, operand)
 *                | contains(path, operand)
 *   operand    ::= path | :value | size(path)
 *   path       ::= name ( . name | [ n ] )*       name ::= identifier | #placeholder
 *
 *   update     ::= ( SET action (, action)* | REMOVE path (, path)*
 *                  | ADD path :value (, path :value)* | DELETE path :value (, ...)* )+
 *   action     ::= path = value
 *   value      ::= term | term + term | term - term
 *   term       ::= path | :value | if_not_exists(path, term) | list_append(term, term)
 *
 * Precedence, lowest first: OR, AND, NOT, then comparisons and functions.
 * Keywords are case-insensitive; function names are case-sensitive, as on
 * DynamoDB. A bare identifier that is a DynamoDB reserved word is refused.
 *
 * Error messages copy DynamoDB's wording, prefixed "Invalid <Kind>Expression: ".
 */

import {
  addNumbers,
  ATTRIBUTE_TYPES,
  compareScalars,
  describeValue,
  typeOf,
  ValidationError,
  valuesEqual,
  type AttributeValue,
  type Item,
} from './attribute-value';
import { DYNAMODB_RESERVED_WORDS } from './reserved-words';

export type ExpressionKind =
  | 'ConditionExpression'
  | 'FilterExpression'
  | 'KeyConditionExpression'
  | 'UpdateExpression'
  | 'ProjectionExpression';

export type PathElement = { readonly name: string } | { readonly index: number };
export type Path = readonly PathElement[];

/**
 * The ExpressionAttributeNames / ExpressionAttributeValues of one request, and
 * which placeholders the parsed expressions used. DynamoDB refuses a request
 * that supplies a placeholder no expression uses.
 */
export class ExpressionContext {
  readonly usedNames = new Set<string>();
  readonly usedValues = new Set<string>();

  constructor(
    readonly names: Readonly<Record<string, string>> | undefined,
    readonly values: Readonly<Record<string, AttributeValue>> | undefined,
  ) {}

  /** Throws DynamoDB's error for any supplied placeholder no expression used. */
  assertAllUsed(): void {
    const unusedNames = Object.keys(this.names ?? {}).filter((k) => !this.usedNames.has(k));
    if (unusedNames.length > 0) {
      throw new ValidationError(`Value provided in ExpressionAttributeNames unused in expressions: keys: {${unusedNames.join(', ')}}`);
    }
    const unusedValues = Object.keys(this.values ?? {}).filter((k) => !this.usedValues.has(k));
    if (unusedValues.length > 0) {
      throw new ValidationError(`Value provided in ExpressionAttributeValues unused in expressions: keys: {${unusedValues.join(', ')}}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

type TokenType = 'name' | 'value' | 'ident' | 'number' | 'punct' | 'eof';

interface Token {
  readonly type: TokenType;
  readonly text: string;
}

const TWO_CHAR_PUNCT = ['<>', '<=', '>='];
const ONE_CHAR_PUNCT = '=<>(),.[]+-';

function tokenize(kind: ExpressionKind, source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const fail = (text: string): never => {
    throw new ValidationError(`Invalid ${kind}: Syntax error; token: "${text}", near: "${source.slice(Math.max(0, i - 10), i + 10)}"`);
  };
  while (i < source.length) {
    const ch = source[i]!;
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }
    const rest = source.slice(i);
    let m: RegExpExecArray | null;
    if ((m = /^#[A-Za-z0-9_]+/.exec(rest))) {
      tokens.push({ type: 'name', text: m[0] });
    } else if ((m = /^:[A-Za-z0-9_]+/.exec(rest))) {
      tokens.push({ type: 'value', text: m[0] });
    } else if ((m = /^[A-Za-z][A-Za-z0-9_]*/.exec(rest))) {
      tokens.push({ type: 'ident', text: m[0] });
    } else if ((m = /^[0-9]+/.exec(rest))) {
      tokens.push({ type: 'number', text: m[0] });
    } else if (TWO_CHAR_PUNCT.includes(rest.slice(0, 2))) {
      tokens.push({ type: 'punct', text: rest.slice(0, 2) });
    } else if (ONE_CHAR_PUNCT.includes(ch)) {
      tokens.push({ type: 'punct', text: ch });
    } else {
      fail(ch);
    }
    i += (m ? m[0].length : tokens[tokens.length - 1]!.text.length);
  }
  tokens.push({ type: 'eof', text: '<EOF>' });
  return tokens;
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

export type Operand =
  | { readonly k: 'path'; readonly path: Path }
  | { readonly k: 'value'; readonly value: AttributeValue; readonly placeholder: string }
  | { readonly k: 'size'; readonly path: Path };

export type Comparator = '=' | '<>' | '<' | '<=' | '>' | '>=';

export type Condition =
  | { readonly k: 'cmp'; readonly op: Comparator; readonly left: Operand; readonly right: Operand }
  | { readonly k: 'between'; readonly operand: Operand; readonly low: Operand; readonly high: Operand }
  | { readonly k: 'in'; readonly operand: Operand; readonly list: readonly Operand[] }
  | { readonly k: 'fn'; readonly name: ConditionFunction; readonly args: readonly Operand[] }
  | { readonly k: 'and'; readonly left: Condition; readonly right: Condition }
  | { readonly k: 'or'; readonly left: Condition; readonly right: Condition }
  | { readonly k: 'not'; readonly operand: Condition };

type ConditionFunction = 'attribute_exists' | 'attribute_not_exists' | 'attribute_type' | 'begins_with' | 'contains';
const CONDITION_FUNCTIONS: readonly string[] = ['attribute_exists', 'attribute_not_exists', 'attribute_type', 'begins_with', 'contains'];
const COMPARATORS: readonly string[] = ['=', '<>', '<', '<=', '>', '>='];

export type UpdateTerm =
  | { readonly k: 'path'; readonly path: Path }
  | { readonly k: 'value'; readonly value: AttributeValue }
  | { readonly k: 'if_not_exists'; readonly path: Path; readonly fallback: UpdateTerm }
  | { readonly k: 'list_append'; readonly left: UpdateTerm; readonly right: UpdateTerm };

export type SetValue =
  | { readonly k: 'term'; readonly term: UpdateTerm }
  | { readonly k: 'arith'; readonly op: '+' | '-'; readonly left: UpdateTerm; readonly right: UpdateTerm };

export interface UpdateAst {
  readonly set: ReadonlyArray<{ readonly path: Path; readonly value: SetValue }>;
  readonly remove: readonly Path[];
  readonly add: ReadonlyArray<{ readonly path: Path; readonly value: AttributeValue }>;
  readonly delete: ReadonlyArray<{ readonly path: Path; readonly value: AttributeValue }>;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

const TYPE_WORDS: Record<string, string> = {
  S: 'STRING', N: 'NUMBER', B: 'BINARY', SS: 'SET', NS: 'SET', BS: 'SET', M: 'MAP', L: 'LIST', NULL: 'NULL', BOOL: 'BOOLEAN',
};

export function formatPath(path: Path): string {
  return `[${path.map((e) => ('name' in e ? e.name : `[${e.index}]`)).join(', ')}]`;
}

class Parser {
  private pos = 0;
  private readonly tokens: Token[];

  constructor(
    private readonly kind: ExpressionKind,
    private readonly source: string,
    private readonly ctx: ExpressionContext,
  ) {
    if (source.trim() === '') throw new ValidationError(`Invalid ${kind}: The expression can not be empty;`);
    this.tokens = tokenize(kind, source);
  }

  error(message: string): ValidationError {
    return new ValidationError(`Invalid ${this.kind}: ${message}`);
  }

  private peek(offset = 0): Token {
    return this.tokens[Math.min(this.pos + offset, this.tokens.length - 1)]!;
  }

  private next(): Token {
    const token = this.peek();
    if (token.type !== 'eof') this.pos += 1;
    return token;
  }

  syntaxError(token = this.peek()): ValidationError {
    const near = this.tokens.slice(Math.max(0, this.pos - 1), this.pos + 2)
      .filter((t) => t.type !== 'eof').map((t) => t.text).join(' ');
    return this.error(`Syntax error; token: "${token.text}", near: "${near}"`);
  }

  private isPunct(text: string, offset = 0): boolean {
    const t = this.peek(offset);
    return t.type === 'punct' && t.text === text;
  }

  private isKeyword(word: string): boolean {
    const t = this.peek();
    return t.type === 'ident' && t.text.toUpperCase() === word;
  }

  private expectPunct(text: string): void {
    if (!this.isPunct(text)) throw this.syntaxError();
    this.next();
  }

  expectEnd(): void {
    if (this.peek().type !== 'eof') throw this.syntaxError();
  }

  atEnd(): boolean {
    return this.peek().type === 'eof';
  }

  // ── Paths and values ──────────────────────────────────────────────────────

  private pathName(token: Token): string {
    if (token.type === 'name') {
      const resolved = this.ctx.names?.[token.text];
      if (resolved === undefined) {
        throw this.error(`An expression attribute name used in the document path is not defined; attribute name: ${token.text}`);
      }
      this.ctx.usedNames.add(token.text);
      return resolved;
    }
    if (token.type === 'ident') {
      if (DYNAMODB_RESERVED_WORDS.has(token.text.toUpperCase())) {
        throw this.error(`Attribute name is a reserved keyword; reserved keyword: ${token.text}`);
      }
      return token.text;
    }
    throw this.syntaxError(token);
  }

  parsePath(): Path {
    const elements: PathElement[] = [{ name: this.pathName(this.next()) }];
    for (;;) {
      if (this.isPunct('.')) {
        this.next();
        elements.push({ name: this.pathName(this.next()) });
      } else if (this.isPunct('[')) {
        this.next();
        const n = this.next();
        if (n.type !== 'number') throw this.syntaxError(n);
        this.expectPunct(']');
        elements.push({ index: Number(n.text) });
      } else {
        return elements;
      }
    }
  }

  private valueToken(token: Token): AttributeValue {
    const value = this.ctx.values?.[token.text];
    if (value === undefined) {
      throw this.error(`An expression attribute value used in expression is not defined; attribute value: ${token.text}`);
    }
    this.ctx.usedValues.add(token.text);
    return value;
  }

  private startsPath(): boolean {
    const t = this.peek();
    return t.type === 'name' || (t.type === 'ident' && !this.isPunct('(', 1));
  }

  // ── Conditions ────────────────────────────────────────────────────────────

  parseCondition(): Condition {
    let left = this.parseAnd();
    while (this.isKeyword('OR')) {
      this.next();
      left = { k: 'or', left, right: this.parseAnd() };
    }
    return left;
  }

  private parseAnd(): Condition {
    let left = this.parseNot();
    while (this.isKeyword('AND')) {
      this.next();
      left = { k: 'and', left, right: this.parseNot() };
    }
    return left;
  }

  private parseNot(): Condition {
    if (this.isKeyword('NOT')) {
      this.next();
      return { k: 'not', operand: this.parseNot() };
    }
    return this.parsePrimary();
  }

  private parsePrimary(): Condition {
    if (this.isPunct('(')) {
      this.next();
      const inner = this.parseCondition();
      this.expectPunct(')');
      return inner;
    }
    const t = this.peek();
    if (t.type === 'ident' && this.isPunct('(', 1) && t.text !== 'size') {
      if (!CONDITION_FUNCTIONS.includes(t.text)) throw this.error(`Invalid function name; function: ${t.text}`);
      const fn = this.parseFunction();
      if (this.peek().type === 'punct' && COMPARATORS.includes(this.peek().text)) {
        throw this.error(`The function is not allowed to be used this way in an expression; function: ${t.text}`);
      }
      return fn;
    }
    const operand = this.parseOperand();
    const op = this.peek();
    if (op.type === 'punct' && COMPARATORS.includes(op.text)) {
      this.next();
      const right = this.parseOperand();
      if (op.text !== '=' && op.text !== '<>') {
        this.assertOrderable(op.text, operand);
        this.assertOrderable(op.text, right);
      }
      return { k: 'cmp', op: op.text as Comparator, left: operand, right };
    }
    if (this.isKeyword('BETWEEN')) {
      this.next();
      const low = this.parseOperand();
      if (!this.isKeyword('AND')) throw this.syntaxError();
      this.next();
      const high = this.parseOperand();
      for (const o of [operand, low, high]) this.assertOrderable('BETWEEN', o);
      if (low.k === 'value' && high.k === 'value') {
        const order = compareScalars(low.value, high.value);
        if (order === null || order > 0) {
          throw this.error(`The BETWEEN operator requires upper bound to be greater than or equal to lower bound; lower bound operand: AttributeValue: ${describeValue(low.value)}, upper bound operand: AttributeValue: ${describeValue(high.value)}`);
        }
      }
      return { k: 'between', operand, low, high };
    }
    if (this.isKeyword('IN')) {
      this.next();
      this.expectPunct('(');
      const list: Operand[] = [this.parseOperand()];
      while (this.isPunct(',')) {
        this.next();
        list.push(this.parseOperand());
      }
      this.expectPunct(')');
      if (list.length > 100) {
        throw this.error(`The IN operator is provided with too many operands; number of operands: ${list.length}`);
      }
      return { k: 'in', operand, list };
    }
    throw this.syntaxError();
  }

  private assertOrderable(op: string, operand: Operand): void {
    if (operand.k === 'value' && !['N', 'S', 'B'].includes(typeOf(operand.value))) {
      throw this.error(`Incorrect operand type for operator or function; operator or function: ${op}, operand type: ${TYPE_WORDS[typeOf(operand.value)]}`);
    }
  }

  parseOperand(): Operand {
    const t = this.peek();
    if (t.type === 'value') {
      this.next();
      return { k: 'value', value: this.valueToken(t), placeholder: t.text };
    }
    if (t.type === 'ident' && t.text === 'size' && this.isPunct('(', 1)) {
      this.next();
      this.next();
      if (!this.startsPath()) throw this.error('Operator or function requires a document path; operator or function: size');
      const path = this.parsePath();
      this.expectPunct(')');
      return { k: 'size', path };
    }
    if (t.type === 'ident' && this.isPunct('(', 1)) {
      if (CONDITION_FUNCTIONS.includes(t.text)) {
        throw this.error(`The function is not allowed to be used this way in an expression; function: ${t.text}`);
      }
      throw this.error(`Invalid function name; function: ${t.text}`);
    }
    if (this.startsPath()) return { k: 'path', path: this.parsePath() };
    throw this.syntaxError();
  }

  private parseFunction(): Condition {
    const name = this.next().text as ConditionFunction;
    this.expectPunct('(');
    const args: Operand[] = [this.parseOperand()];
    while (this.isPunct(',')) {
      this.next();
      args.push(this.parseOperand());
    }
    this.expectPunct(')');
    const arity = name === 'attribute_exists' || name === 'attribute_not_exists' ? 1 : 2;
    if (args.length !== arity) {
      throw this.error(`Incorrect number of operands for operator or function; operator or function: ${name}, number of operands: ${args.length}`);
    }
    if (args[0]!.k !== 'path') {
      throw this.error(`Operator or function requires a document path; operator or function: ${name}`);
    }
    const second = args[1];
    if (name === 'attribute_type') {
      if (second?.k !== 'value') throw this.error('Incorrect operand type for operator or function; operator or function: attribute_type, operand type: PATH');
      if (typeOf(second.value) !== 'S') {
        throw this.error(`Incorrect operand type for operator or function; operator or function: attribute_type, operand type: ${TYPE_WORDS[typeOf(second.value)]}`);
      }
      const typeName = (second.value as { S: string }).S;
      if (!(ATTRIBUTE_TYPES as readonly string[]).includes(typeName)) {
        throw this.error(`Invalid attribute type name found; type: ${typeName}, valid types: { B,NULL,SS,BOOL,L,BS,N,NS,S,M }`);
      }
    }
    if (name === 'begins_with' && second?.k === 'value' && !['S', 'B'].includes(typeOf(second.value))) {
      throw this.error(`Incorrect operand type for operator or function; operator or function: begins_with, operand type: ${TYPE_WORDS[typeOf(second.value)]}`);
    }
    if (name === 'contains' && second?.k === 'path' && formatPath(second.path) === formatPath((args[0] as { path: Path }).path)) {
      throw this.error('The first and second operands of the contains function must be distinct; operator or function: contains');
    }
    return { k: 'fn', name, args };
  }

  // ── Update expressions ────────────────────────────────────────────────────

  parseUpdate(): UpdateAst {
    const ast = { set: [], remove: [], add: [], delete: [] } as {
      set: Array<{ path: Path; value: SetValue }>;
      remove: Path[];
      add: Array<{ path: Path; value: AttributeValue }>;
      delete: Array<{ path: Path; value: AttributeValue }>;
    };
    const seen = new Set<string>();
    if (this.atEnd()) throw this.syntaxError();
    while (!this.atEnd()) {
      const t = this.next();
      const clause = t.type === 'ident' ? t.text.toUpperCase() : '';
      if (!['SET', 'REMOVE', 'ADD', 'DELETE'].includes(clause)) throw this.syntaxError(t);
      if (seen.has(clause)) throw this.error(`The "${clause}" section can only be used once in an update expression;`);
      seen.add(clause);
      do {
        const path = this.parsePath();
        if (clause === 'SET') {
          this.expectPunct('=');
          ast.set.push({ path, value: this.parseSetValue() });
        } else if (clause === 'REMOVE') {
          ast.remove.push(path);
        } else {
          const v = this.next();
          if (v.type !== 'value') throw this.syntaxError(v);
          const value = this.valueToken(v);
          const type = typeOf(value);
          if (clause === 'ADD' && !['N', 'SS', 'NS', 'BS'].includes(type)) {
            throw this.error(`Incorrect operand type for operator or function; operator: ADD, operand type: ${TYPE_WORDS[type]}`);
          }
          if (clause === 'DELETE' && !['SS', 'NS', 'BS'].includes(type)) {
            throw this.error(`Incorrect operand type for operator or function; operator: DELETE, operand type: ${TYPE_WORDS[type]}`);
          }
          (clause === 'ADD' ? ast.add : ast.delete).push({ path, value });
        }
      } while (this.isPunct(',') && this.next());
    }
    return ast;
  }

  private parseSetValue(): SetValue {
    const left = this.parseTerm();
    if (this.isPunct('+') || this.isPunct('-')) {
      const op = this.next().text as '+' | '-';
      const right = this.parseTerm();
      for (const term of [left, right]) {
        if (term.k === 'value' && typeOf(term.value) !== 'N') {
          throw this.error(`Incorrect operand type for operator or function; operator or function: ${op}, operand type: ${TYPE_WORDS[typeOf(term.value)]}`);
        }
      }
      return { k: 'arith', op, left, right };
    }
    return { k: 'term', term: left };
  }

  private parseTerm(): UpdateTerm {
    const t = this.peek();
    if (t.type === 'value') {
      this.next();
      return { k: 'value', value: this.valueToken(t) };
    }
    if (t.type === 'ident' && this.isPunct('(', 1)) {
      this.next();
      this.next();
      if (t.text === 'if_not_exists') {
        if (!this.startsPath()) throw this.error('Operator or function requires a document path; operator or function: if_not_exists');
        const path = this.parsePath();
        this.expectPunct(',');
        const fallback = this.parseTerm();
        this.expectPunct(')');
        return { k: 'if_not_exists', path, fallback };
      }
      if (t.text === 'list_append') {
        const left = this.parseTerm();
        this.expectPunct(',');
        const right = this.parseTerm();
        this.expectPunct(')');
        for (const term of [left, right]) {
          if (term.k === 'value' && typeOf(term.value) !== 'L') {
            throw this.error(`Incorrect operand type for operator or function; operator or function: list_append, operand type: ${TYPE_WORDS[typeOf(term.value)]}`);
          }
        }
        return { k: 'list_append', left, right };
      }
      throw this.error(`Invalid function name; function: ${t.text}`);
    }
    if (this.startsPath()) return { k: 'path', path: this.parsePath() };
    throw this.syntaxError();
  }

  // ── Projection ────────────────────────────────────────────────────────────

  parseProjection(): Path[] {
    const paths: Path[] = [this.parsePath()];
    while (this.isPunct(',')) {
      this.next();
      paths.push(this.parsePath());
    }
    return paths;
  }
}

// ---------------------------------------------------------------------------
// Public parse entry points
// ---------------------------------------------------------------------------

export function parseCondition(kind: 'ConditionExpression' | 'FilterExpression' | 'KeyConditionExpression', source: string, ctx: ExpressionContext): Condition {
  const parser = new Parser(kind, source, ctx);
  const condition = parser.parseCondition();
  parser.expectEnd();
  return condition;
}

export function parseUpdate(source: string, ctx: ExpressionContext): UpdateAst {
  const parser = new Parser('UpdateExpression', source, ctx);
  const ast = parser.parseUpdate();
  parser.expectEnd();
  assertNoOverlap('UpdateExpression', [
    ...ast.set.map((a) => a.path), ...ast.remove, ...ast.add.map((a) => a.path), ...ast.delete.map((a) => a.path),
  ]);
  return ast;
}

export function parseProjection(source: string, ctx: ExpressionContext): Path[] {
  const parser = new Parser('ProjectionExpression', source, ctx);
  const paths = parser.parseProjection();
  parser.expectEnd();
  assertNoOverlap('ProjectionExpression', paths);
  return paths;
}

function assertNoOverlap(kind: ExpressionKind, paths: readonly Path[]): void {
  for (let i = 0; i < paths.length; i++) {
    for (let j = i + 1; j < paths.length; j++) {
      const a = paths[i]!;
      const b = paths[j]!;
      const n = Math.min(a.length, b.length);
      let conflict = false;
      let k = 0;
      for (; k < n; k++) {
        const x = a[k]!;
        const y = b[k]!;
        if ('name' in x && 'name' in y) {
          if (x.name !== y.name) break;
        } else if ('index' in x && 'index' in y) {
          if (x.index !== y.index) break;
        } else {
          conflict = true;
          break;
        }
      }
      if (conflict) {
        throw new ValidationError(`Invalid ${kind}: Two document paths conflict with each other; must remove or rewrite one of these paths; path one: ${formatPath(a)}, path two: ${formatPath(b)}`);
      }
      if (k === n) {
        throw new ValidationError(`Invalid ${kind}: Two document paths overlap with each other; must remove or rewrite one of these paths; path one: ${formatPath(a)}, path two: ${formatPath(b)}`);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export function resolvePath(item: Item, path: Path): AttributeValue | undefined {
  let current: AttributeValue | undefined = { M: item };
  for (const element of path) {
    if (current === undefined) return undefined;
    if ('name' in element) {
      current = 'M' in current ? current.M[element.name] : undefined;
    } else {
      current = 'L' in current ? current.L[element.index] : undefined;
    }
  }
  return current;
}

/**
 * DynamoDB's size(): string length, binary bytes, set/list/map element count.
 * String length is counted in UTF-8 bytes, matching how DynamoDB measures
 * strings everywhere else.
 */
function sizeOf(value: AttributeValue | undefined): AttributeValue | undefined {
  if (value === undefined) return undefined;
  let n: number;
  if ('S' in value) n = Buffer.byteLength(value.S, 'utf8');
  else if ('B' in value) n = Buffer.from(value.B, 'base64').length;
  else if ('SS' in value) n = value.SS.length;
  else if ('NS' in value) n = value.NS.length;
  else if ('BS' in value) n = value.BS.length;
  else if ('L' in value) n = value.L.length;
  else if ('M' in value) n = Object.keys(value.M).length;
  else return undefined;
  return { N: String(n) };
}

function evalOperand(item: Item, operand: Operand): AttributeValue | undefined {
  if (operand.k === 'value') return operand.value;
  if (operand.k === 'path') return resolvePath(item, operand.path);
  return sizeOf(resolvePath(item, operand.path));
}

function ordered(a: AttributeValue | undefined, b: AttributeValue | undefined): number | null {
  if (a === undefined || b === undefined) return null;
  return compareScalars(a, b);
}

export function evaluateCondition(item: Item, condition: Condition): boolean {
  switch (condition.k) {
    case 'and':
      return evaluateCondition(item, condition.left) && evaluateCondition(item, condition.right);
    case 'or':
      return evaluateCondition(item, condition.left) || evaluateCondition(item, condition.right);
    case 'not':
      return !evaluateCondition(item, condition.operand);
    case 'cmp': {
      const a = evalOperand(item, condition.left);
      const b = evalOperand(item, condition.right);
      if (condition.op === '=') return a !== undefined && b !== undefined && valuesEqual(a, b);
      // A missing attribute is "not equal" to anything, as on DynamoDB.
      if (condition.op === '<>') return a === undefined || b === undefined || !valuesEqual(a, b);
      const order = ordered(a, b);
      if (order === null) return false;
      switch (condition.op) {
        case '<': return order < 0;
        case '<=': return order <= 0;
        case '>': return order > 0;
        case '>=': return order >= 0;
      }
      return false;
    }
    case 'between': {
      const v = evalOperand(item, condition.operand);
      const lo = ordered(v, evalOperand(item, condition.low));
      const hi = ordered(v, evalOperand(item, condition.high));
      return lo !== null && hi !== null && lo >= 0 && hi <= 0;
    }
    case 'in': {
      const v = evalOperand(item, condition.operand);
      if (v === undefined) return false;
      return condition.list.some((o) => {
        const candidate = evalOperand(item, o);
        return candidate !== undefined && valuesEqual(v, candidate);
      });
    }
    case 'fn': {
      const target = evalOperand(item, condition.args[0]!);
      const arg = condition.args[1] ? evalOperand(item, condition.args[1]) : undefined;
      switch (condition.name) {
        case 'attribute_exists':
          return target !== undefined;
        case 'attribute_not_exists':
          return target === undefined;
        case 'attribute_type':
          return target !== undefined && arg !== undefined && 'S' in arg && typeOf(target) === arg.S;
        case 'begins_with':
          if (target === undefined || arg === undefined) return false;
          if ('S' in target && 'S' in arg) return target.S.startsWith(arg.S);
          if ('B' in target && 'B' in arg) {
            const t = Buffer.from(target.B, 'base64');
            const p = Buffer.from(arg.B, 'base64');
            return t.length >= p.length && t.subarray(0, p.length).equals(p);
          }
          return false;
        case 'contains':
          if (target === undefined || arg === undefined) return false;
          if ('S' in target) return 'S' in arg && target.S.includes(arg.S);
          if ('SS' in target) return 'S' in arg && target.SS.includes(arg.S);
          if ('NS' in target) return 'N' in arg && target.NS.some((n) => valuesEqual({ N: n }, arg));
          if ('BS' in target) return 'B' in arg && target.BS.includes(arg.B);
          if ('L' in target) return target.L.some((element) => valuesEqual(element, arg));
          return false;
      }
    }
  }
}

/** Every top-level attribute name a condition reads. */
export function topLevelNames(condition: Condition): Set<string> {
  const names = new Set<string>();
  const fromOperand = (o: Operand): void => {
    if (o.k !== 'value') {
      const first = o.path[0];
      if (first && 'name' in first) names.add(first.name);
    }
  };
  const walk = (c: Condition): void => {
    switch (c.k) {
      case 'and':
      case 'or':
        walk(c.left);
        walk(c.right);
        break;
      case 'not':
        walk(c.operand);
        break;
      case 'cmp':
        fromOperand(c.left);
        fromOperand(c.right);
        break;
      case 'between':
        [c.operand, c.low, c.high].forEach(fromOperand);
        break;
      case 'in':
        [c.operand, ...c.list].forEach(fromOperand);
        break;
      case 'fn':
        c.args.forEach(fromOperand);
        break;
    }
  };
  walk(condition);
  return names;
}

// ---------------------------------------------------------------------------
// Update application
// ---------------------------------------------------------------------------

const INVALID_PATH = 'The document path provided in the update expression is invalid for update';
const WRONG_TYPE = 'An operand in the update expression has an incorrect data type';

function updateError(message: string): ValidationError {
  return new ValidationError(`Invalid UpdateExpression: ${message}`);
}

function evalTerm(original: Item, term: UpdateTerm): AttributeValue {
  switch (term.k) {
    case 'value':
      return term.value;
    case 'path': {
      const v = resolvePath(original, term.path);
      if (v === undefined) throw updateError('The provided expression refers to an attribute that does not exist in the item');
      return v;
    }
    case 'if_not_exists':
      return resolvePath(original, term.path) ?? evalTerm(original, term.fallback);
    case 'list_append': {
      const a = evalTerm(original, term.left);
      const b = evalTerm(original, term.right);
      for (const v of [a, b]) {
        if (!('L' in v)) {
          throw updateError(`Incorrect operand type for operator or function; operator or function: list_append, operand type: ${TYPE_WORDS[typeOf(v)]}`);
        }
      }
      return { L: [...(a as { L: AttributeValue[] }).L, ...(b as { L: AttributeValue[] }).L] };
    }
  }
}

function evalSetValue(original: Item, value: SetValue): AttributeValue {
  if (value.k === 'term') return structuredClone(evalTerm(original, value.term));
  const a = evalTerm(original, value.left);
  const b = evalTerm(original, value.right);
  if (!('N' in a) || !('N' in b)) throw updateError(WRONG_TYPE);
  return { N: addNumbers(a.N, b.N, value.op === '-') };
}

function parentOf(item: Item, path: Path): AttributeValue | undefined {
  return path.length === 1 ? { M: item } : resolvePath(item, path.slice(0, -1));
}

function assign(item: Item, path: Path, value: AttributeValue): void {
  const parent = parentOf(item, path);
  const last = path[path.length - 1]!;
  if (parent === undefined) throw updateError(INVALID_PATH);
  if ('name' in last) {
    if (!('M' in parent)) throw updateError(INVALID_PATH);
    parent.M[last.name] = value;
  } else {
    if (!('L' in parent)) throw updateError(INVALID_PATH);
    // An index past the end appends, as on DynamoDB.
    if (last.index >= parent.L.length) parent.L.push(value);
    else parent.L[last.index] = value;
  }
}

function removeAt(item: Item, path: Path): void {
  const parent = parentOf(item, path);
  const last = path[path.length - 1]!;
  if (parent === undefined) throw updateError(INVALID_PATH);
  if ('name' in last) {
    if (!('M' in parent)) throw updateError(INVALID_PATH);
    delete parent.M[last.name];
  } else {
    if (!('L' in parent)) throw updateError(INVALID_PATH);
    if (last.index < parent.L.length) parent.L.splice(last.index, 1);
  }
}

/**
 * Applies an update to a copy of `original`. Every operand is read from the
 * item as it was before the update, as DynamoDB does. Returns the new item and
 * the paths the update touched (for UPDATED_OLD / UPDATED_NEW).
 */
export function applyUpdate(original: Item, ast: UpdateAst, keyNames: readonly string[]): { item: Item; paths: Path[] } {
  const touched = [...ast.set.map((a) => a.path), ...ast.remove, ...ast.add.map((a) => a.path), ...ast.delete.map((a) => a.path)];
  for (const path of touched) {
    const first = path[0]!;
    if ('name' in first && keyNames.includes(first.name)) {
      throw new ValidationError(`One or more parameter values were invalid: Cannot update attribute ${first.name}. This attribute is part of the key`);
    }
  }
  const values = ast.set.map((action) => evalSetValue(original, action.value));
  const item = structuredClone(original);
  ast.set.forEach((action, i) => assign(item, action.path, values[i]!));

  // Remove list elements from the highest index down so earlier removals do
  // not shift later ones.
  const removals = [...ast.remove].sort((a, b) => {
    const x = a[a.length - 1]!;
    const y = b[b.length - 1]!;
    return 'index' in x && 'index' in y ? y.index - x.index : 0;
  });
  for (const path of removals) removeAt(item, path);

  for (const { path, value } of ast.add) {
    const existing = resolvePath(item, path);
    if (existing === undefined) {
      assign(item, path, structuredClone(value));
      continue;
    }
    if ('N' in existing && 'N' in value) {
      assign(item, path, { N: addNumbers(existing.N, value.N) });
      continue;
    }
    const type = typeOf(value);
    if (typeOf(existing) !== type || !['SS', 'NS', 'BS'].includes(type)) throw updateError(WRONG_TYPE);
    const current = (existing as Record<string, string[]>)[type]!;
    const merged = [...current, ...(value as Record<string, string[]>)[type]!.filter((m) => !current.includes(m))];
    assign(item, path, { [type]: merged } as AttributeValue);
  }

  for (const { path, value } of ast.delete) {
    const existing = resolvePath(item, path);
    if (existing === undefined) continue;
    const type = typeOf(value);
    if (typeOf(existing) !== type) throw updateError(WRONG_TYPE);
    const drop = (value as Record<string, string[]>)[type]!;
    const remaining = (existing as Record<string, string[]>)[type]!.filter((m) => !drop.includes(m));
    if (remaining.length === 0) removeAt(item, path);
    else assign(item, path, { [type]: remaining } as AttributeValue);
  }
  return { item, paths: touched };
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

type ProjectionNode =
  | { kind: 'leaf'; value: AttributeValue }
  | { kind: 'map'; children: Map<string, ProjectionNode> }
  | { kind: 'list'; children: Map<number, ProjectionNode> };

/**
 * Keeps only the given document paths of an item. A projected list keeps the
 * selected elements in index order, closed up, as DynamoDB returns them.
 */
export function project(item: Item, paths: readonly Path[]): Item {
  const root: ProjectionNode = { kind: 'map', children: new Map() };
  for (const path of paths) {
    const value = resolvePath(item, path);
    if (value === undefined) continue;
    let node: ProjectionNode = root;
    path.forEach((element, i) => {
      const isLast = i === path.length - 1;
      const nextElement = path[i + 1];
      const make = (): ProjectionNode => (isLast
        ? { kind: 'leaf', value: structuredClone(value) }
        : nextElement && 'index' in nextElement
          ? { kind: 'list', children: new Map() }
          : { kind: 'map', children: new Map() });
      if (node.kind === 'map' && 'name' in element) {
        const child = node.children.get(element.name) ?? make();
        node.children.set(element.name, child);
        node = child;
      } else if (node.kind === 'list' && 'index' in element) {
        const child = node.children.get(element.index) ?? make();
        node.children.set(element.index, child);
        node = child;
      }
    });
  }
  const toValue = (node: ProjectionNode): AttributeValue => {
    if (node.kind === 'leaf') return node.value;
    if (node.kind === 'list') {
      return { L: [...node.children.entries()].sort((a, b) => a[0] - b[0]).map(([, child]) => toValue(child)) };
    }
    return { M: Object.fromEntries([...node.children.entries()].map(([k, child]) => [k, toValue(child)])) };
  };
  return (toValue(root) as { M: Item }).M;
}
