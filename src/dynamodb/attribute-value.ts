/**
 * DynamoDB AttributeValue handling for the simulator: validation, number
 * canonicalisation and exact decimal arithmetic, ordering, equality and item
 * size.
 *
 * Values are kept in their wire shape (`{ "S": "x" }`, `{ "N": "1.5" }`, ...).
 * Numbers are stored as canonical decimal strings and compared and added as
 * exact decimals (a BigInt coefficient and a power-of-ten exponent), never as
 * JavaScript doubles, because DynamoDB numbers carry 38 significant digits.
 */

export type AttributeValue =
  | { S: string }
  | { N: string }
  | { B: string }
  | { SS: string[] }
  | { NS: string[] }
  | { BS: string[] }
  | { M: Record<string, AttributeValue> }
  | { L: AttributeValue[] }
  | { NULL: true }
  | { BOOL: boolean };

export type Item = Record<string, AttributeValue>;

export type AttributeType = 'S' | 'N' | 'B' | 'SS' | 'NS' | 'BS' | 'M' | 'L' | 'NULL' | 'BOOL';

export const ATTRIBUTE_TYPES: readonly AttributeType[] = ['S', 'N', 'B', 'SS', 'NS', 'BS', 'M', 'L', 'NULL', 'BOOL'];

/** A DynamoDB ValidationException raised while checking or combining values. */
export class ValidationError extends Error {}

export function typeOf(value: AttributeValue): AttributeType {
  return Object.keys(value)[0] as AttributeType;
}

// ---------------------------------------------------------------------------
// Decimal numbers
// ---------------------------------------------------------------------------

/** value = sign(coefficient) * |coefficient| * 10^exponent, coefficient without trailing zeros. */
export interface Decimal {
  readonly coefficient: bigint;
  readonly exponent: number;
}

const NUMBER_PATTERN = /^\s*([+-]?)(\d*)(?:\.(\d*))?(?:[eE]([+-]?\d+))?\s*$/;
const MAX_SIGNIFICANT_DIGITS = 38;

/** Parses and range-checks a DynamoDB number, as DynamoDB does on every write. */
export function parseDecimal(raw: string): Decimal {
  const match = NUMBER_PATTERN.exec(raw);
  const intPart = match?.[2] ?? '';
  const fracPart = match?.[3] ?? '';
  if (!match || (intPart === '' && fracPart === '')) {
    throw new ValidationError('A value provided cannot be converted into a number');
  }
  const digits = (intPart + fracPart).replace(/^0+/, '');
  let exponent = Number(match[4] ?? '0') - fracPart.length;
  if (digits === '') return { coefficient: 0n, exponent: 0 };
  const trimmed = digits.replace(/0+$/, '');
  exponent += digits.length - trimmed.length;
  if (trimmed.length > MAX_SIGNIFICANT_DIGITS) {
    throw new ValidationError('Attempting to store more than 38 significant digits in a Number');
  }
  // Magnitude = 0.trimmed * 10^(exponent + trimmed.length). DynamoDB allows
  // positive magnitudes from 1E-130 up to 9.9999999999999999999999999999999999999E+125.
  const magnitudeExponent = exponent + trimmed.length - 1; // exponent of the leading digit
  if (magnitudeExponent > 125) {
    throw new ValidationError('Number overflow. Attempting to store a number with magnitude larger than supported range');
  }
  if (magnitudeExponent < -130) {
    throw new ValidationError('Number underflow. Attempting to store a number with magnitude smaller than supported range');
  }
  const coefficient = BigInt(trimmed) * (match[1] === '-' ? -1n : 1n);
  return { coefficient, exponent };
}

export function formatDecimal(value: Decimal): string {
  if (value.coefficient === 0n) return '0';
  const negative = value.coefficient < 0n;
  const digits = (negative ? -value.coefficient : value.coefficient).toString();
  let out: string;
  if (value.exponent >= 0) {
    out = digits + '0'.repeat(value.exponent);
  } else {
    const point = digits.length + value.exponent;
    out = point > 0
      ? `${digits.slice(0, point)}.${digits.slice(point)}`
      : `0.${'0'.repeat(-point)}${digits}`;
  }
  return negative ? `-${out}` : out;
}

/** The canonical string DynamoDB stores and returns for a number. */
export function canonicalNumber(raw: string): string {
  return formatDecimal(parseDecimal(raw));
}

function align(a: Decimal, b: Decimal): [bigint, bigint] {
  const exponent = Math.min(a.exponent, b.exponent);
  return [
    a.coefficient * 10n ** BigInt(a.exponent - exponent),
    b.coefficient * 10n ** BigInt(b.exponent - exponent),
  ];
}

export function compareDecimals(a: Decimal, b: Decimal): number {
  const [x, y] = align(a, b);
  return x < y ? -1 : x > y ? 1 : 0;
}

function normalise(coefficient: bigint, exponent: number): Decimal {
  if (coefficient === 0n) return { coefficient: 0n, exponent: 0 };
  let c = coefficient;
  let e = exponent;
  while (c % 10n === 0n) {
    c /= 10n;
    e += 1;
  }
  return { coefficient: c, exponent: e };
}

/** Exact a + b (or a - b), re-checked against DynamoDB's number range. */
export function addNumbers(a: string, b: string, subtract = false): string {
  const x = parseDecimal(a);
  const y = parseDecimal(b);
  const exponent = Math.min(x.exponent, y.exponent);
  const [cx, cy] = align(x, y);
  const result = formatDecimal(normalise(subtract ? cx - cy : cx + cy, exponent));
  return canonicalNumber(result);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function isBase64(value: string): boolean {
  return /^[A-Za-z0-9+/]*={0,2}$/.test(value) && value.length % 4 === 0;
}

const SET_LABEL: Record<'SS' | 'NS' | 'BS', string> = { SS: 'string', NS: 'number', BS: 'binary' };

/**
 * Validates a value from a request and returns it in canonical form: numbers
 * normalised, binary re-encoded. Messages copy DynamoDB's.
 */
export function validateAttributeValue(raw: unknown): AttributeValue {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ValidationError('Supplied AttributeValue is empty, must contain exactly one of the supported datatypes');
  }
  const keys = Object.keys(raw);
  if (keys.length === 0) {
    throw new ValidationError('Supplied AttributeValue is empty, must contain exactly one of the supported datatypes');
  }
  if (keys.length > 1) {
    throw new ValidationError('Supplied AttributeValue has more than one datatypes set, must contain exactly one of the supported datatypes');
  }
  const type = keys[0]!;
  const value = (raw as Record<string, unknown>)[type];
  switch (type) {
    case 'S':
      if (typeof value !== 'string') throw new ValidationError('Invalid attribute value type');
      return { S: value };
    case 'N':
      if (typeof value !== 'string') throw new ValidationError('Invalid attribute value type');
      return { N: canonicalNumber(value) };
    case 'B':
      if (typeof value !== 'string' || !isBase64(value)) throw new ValidationError('Invalid attribute value type');
      return { B: Buffer.from(value, 'base64').toString('base64') };
    case 'BOOL':
      if (typeof value !== 'boolean') throw new ValidationError('Invalid attribute value type');
      return { BOOL: value };
    case 'NULL':
      if (value !== true) {
        throw new ValidationError('One or more parameter values were invalid: Null attribute value types must have the value of true');
      }
      return { NULL: true };
    case 'SS':
    case 'NS':
    case 'BS': {
      if (!Array.isArray(value)) throw new ValidationError('Invalid attribute value type');
      if (value.length === 0) {
        throw new ValidationError(`One or more parameter values were invalid: An ${SET_LABEL[type]} set  may not be empty`);
      }
      const members = value.map((m) => {
        if (typeof m !== 'string') throw new ValidationError('Invalid attribute value type');
        if (type === 'NS') return canonicalNumber(m);
        if (type === 'BS') {
          if (!isBase64(m)) throw new ValidationError('Invalid attribute value type');
          return Buffer.from(m, 'base64').toString('base64');
        }
        return m;
      });
      if (new Set(members).size !== members.length) {
        throw new ValidationError(`One or more parameter values were invalid: Input collection [${value.join(', ')}] contains duplicates.`);
      }
      return { [type]: members } as AttributeValue;
    }
    case 'L':
      if (!Array.isArray(value)) throw new ValidationError('Invalid attribute value type');
      return { L: value.map(validateAttributeValue) };
    case 'M': {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new ValidationError('Invalid attribute value type');
      }
      const out: Record<string, AttributeValue> = {};
      for (const [k, v] of Object.entries(value)) out[k] = validateAttributeValue(v);
      return { M: out };
    }
    default:
      throw new ValidationError(`Supplied AttributeValue has an unknown datatype: ${type}`);
  }
}

export function validateItem(raw: unknown, what = 'Item'): Item {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ValidationError(`${what} must be a map of attribute values`);
  }
  const out: Item = {};
  for (const [name, value] of Object.entries(raw)) {
    if (name.length === 0) {
      throw new ValidationError('One or more parameter values were invalid: An AttributeValue may not contain an empty attribute name');
    }
    out[name] = validateAttributeValue(value);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

function bytesOf(value: AttributeValue): Buffer {
  if ('S' in value) return Buffer.from(value.S, 'utf8');
  if ('B' in value) return Buffer.from(value.B, 'base64');
  throw new Error('bytesOf on a non-string, non-binary value');
}

/**
 * Orders two scalar values of the same type the way DynamoDB does: numbers
 * numerically, strings by UTF-8 bytes, binary by unsigned bytes.
 * Returns null when the values cannot be ordered against each other.
 */
export function compareScalars(a: AttributeValue, b: AttributeValue): number | null {
  const type = typeOf(a);
  if (type !== typeOf(b)) return null;
  if (type === 'N') return compareDecimals(parseDecimal((a as { N: string }).N), parseDecimal((b as { N: string }).N));
  if (type === 'S' || type === 'B') return Buffer.compare(bytesOf(a), bytesOf(b));
  return null;
}

export function valuesEqual(a: AttributeValue, b: AttributeValue): boolean {
  const type = typeOf(a);
  if (type !== typeOf(b)) return false;
  switch (type) {
    case 'S':
    case 'N':
    case 'B':
      return compareScalars(a, b) === 0;
    case 'BOOL':
      return (a as { BOOL: boolean }).BOOL === (b as { BOOL: boolean }).BOOL;
    case 'NULL':
      return true;
    case 'SS':
    case 'NS':
    case 'BS': {
      const x = (a as Record<string, string[]>)[type]!;
      const y = (b as Record<string, string[]>)[type]!;
      return x.length === y.length && x.every((m) => y.includes(m));
    }
    case 'L': {
      const x = (a as { L: AttributeValue[] }).L;
      const y = (b as { L: AttributeValue[] }).L;
      return x.length === y.length && x.every((v, i) => valuesEqual(v, y[i]!));
    }
    case 'M': {
      const x = (a as { M: Item }).M;
      const y = (b as { M: Item }).M;
      const keys = Object.keys(x);
      return keys.length === Object.keys(y).length && keys.every((k) => y[k] !== undefined && valuesEqual(x[k]!, y[k]!));
    }
  }
}

// ---------------------------------------------------------------------------
// Size
// ---------------------------------------------------------------------------

function numberSize(n: string): number {
  const digits = n.replace(/^-/, '').replace('.', '').replace(/^0+/, '').replace(/0+$/, '');
  return Math.ceil(Math.max(digits.length, 1) / 2) + 1;
}

/**
 * Approximates DynamoDB's item size accounting: attribute names plus values,
 * numbers at about one byte per two significant digits plus one, and three
 * bytes of overhead per list or map plus one per element.
 */
export function valueSize(value: AttributeValue): number {
  if ('S' in value) return Buffer.byteLength(value.S, 'utf8');
  if ('N' in value) return numberSize(value.N);
  if ('B' in value) return Buffer.from(value.B, 'base64').length;
  if ('BOOL' in value || 'NULL' in value) return 1;
  if ('SS' in value) return value.SS.reduce((n, s) => n + Buffer.byteLength(s, 'utf8'), 0);
  if ('NS' in value) return value.NS.reduce((n, s) => n + numberSize(s), 0);
  if ('BS' in value) return value.BS.reduce((n, s) => n + Buffer.from(s, 'base64').length, 0);
  if ('L' in value) return 3 + value.L.reduce((n, v) => n + valueSize(v) + 1, 0);
  return 3 + Object.entries(value.M).reduce((n, [k, v]) => n + Buffer.byteLength(k, 'utf8') + valueSize(v) + 1, 0);
}

export function itemSize(item: Item): number {
  return Object.entries(item).reduce((n, [k, v]) => n + Buffer.byteLength(k, 'utf8') + valueSize(v), 0);
}

export function cloneValue<T extends AttributeValue | Item>(value: T): T {
  return structuredClone(value);
}

/** A short rendering for error messages, e.g. `{N:5}`. */
export function describeValue(value: AttributeValue): string {
  const type = typeOf(value);
  const inner = (value as Record<string, unknown>)[type];
  return `{${type}:${typeof inner === 'string' || typeof inner === 'boolean' ? String(inner) : JSON.stringify(inner)}}`;
}
