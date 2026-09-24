/**
 * In-memory DynamoDB simulator for local development and tests.
 *
 * Speaks the AWS JSON 1.0 protocol that `@aws-sdk/client-dynamodb` (and so
 * `@aws-sdk/lib-dynamodb`'s DynamoDBDocumentClient) uses:
 *   POST /   X-Amz-Target: DynamoDB_20120810.<Operation>
 *            Content-Type: application/x-amz-json-1.0
 *
 * Errors are DynamoDB's: `{"__type":"com.amazonaws.dynamodb.v20120810#<Name>","message":...}`,
 * with ValidationException under `com.amazon.coral.validate#`, so the SDK
 * raises the same exception classes it raises against AWS.
 *
 * Expressions (condition, filter, key condition, update, projection) go
 * through a real tokenizer and recursive descent parser; see expressions.ts.
 * Numbers are exact 38-digit decimals, never JavaScript doubles.
 *
 * Anything this simulator does not implement (local secondary indexes,
 * streams, PartiQL, the legacy Expected/AttributesToGet/KeyConditions
 * parameters, consumed-capacity reporting, ...) is refused with HTTP 400 and a
 * message naming it, never silently ignored.
 */

import express from 'express';
import { createHash, randomUUID } from 'node:crypto';

import { listen, readRawBody, type RunningSimulator } from '../shared/server';
import {
  compareScalars,
  itemSize,
  typeOf,
  validateAttributeValue,
  validateItem,
  ValidationError,
  valuesEqual,
  type AttributeValue,
  type Item,
} from './attribute-value';
import {
  applyUpdate,
  evaluateCondition,
  ExpressionContext,
  parseCondition,
  parseProjection,
  parseUpdate,
  project,
  topLevelNames,
  type Condition,
  type Operand,
  type Path,
} from './expressions';

export const DYNAMODB_SIMULATOR_DEFAULT_PORT = 38310;
export const DYNAMODB_SIMULATOR_DEFAULT_ACCOUNT_ID = '000000000000';
export const DYNAMODB_SIMULATOR_DEFAULT_REGION = 'us-east-1';

/** DynamoDB limits, each from the DynamoDB developer guide. */
const MAX_ITEM_SIZE = 400 * 1024;
const MAX_PAGE_BYTES = 1024 * 1024; // Query and Scan read at most 1 MB per call
const MAX_BATCH_GET_KEYS = 100;
const MAX_BATCH_WRITE_REQUESTS = 25;
const MAX_TRANSACT_ITEMS = 100;
const IDEMPOTENCY_WINDOW_MS = 10 * 60 * 1000;

export type DynamoDbAttributeValue = AttributeValue;
export type DynamoDbItem = Item;

type KeyType = 'S' | 'N' | 'B';

export interface DynamoDbSimulatorOptions {
  /** Clock in epoch milliseconds, for CreationDateTime and idempotency windows. Default `Date.now`. */
  readonly now?: () => number;
  /** Account id in table ARNs. Default `000000000000`. */
  readonly accountId?: string;
  /** Region in table ARNs. Default `us-east-1`. */
  readonly region?: string;
}

export interface DynamoDbTableSummary {
  readonly name: string;
  readonly arn: string;
  readonly partitionKey: string;
  readonly sortKey: string | null;
  readonly attributeDefinitions: Readonly<Record<string, KeyType>>;
  readonly globalSecondaryIndexes: readonly string[];
  readonly billingMode: 'PAY_PER_REQUEST' | 'PROVISIONED';
  readonly timeToLive: { readonly enabled: boolean; readonly attributeName: string | null };
  readonly itemCount: number;
}

export interface DynamoDbSimulator {
  readonly app: express.Express;
  /** Deletes every table. */
  reset(): void;
  listTables(): readonly DynamoDbTableSummary[];
  /**
   * Every item in a table, in wire format (`{ pk: { S: 'a' } }`), ordered by
   * partition key then sort key. Throws when the table does not exist.
   */
  dumpTable(name: string): readonly DynamoDbItem[];
}

interface KeySchema {
  readonly hash: string;
  readonly range: string | null;
}

interface GlobalSecondaryIndex {
  readonly name: string;
  readonly arn: string;
  readonly schema: KeySchema;
  readonly projectionType: 'ALL' | 'KEYS_ONLY' | 'INCLUDE';
  readonly nonKeyAttributes: readonly string[];
  readonly provisioned: { read: number; write: number } | null;
}

interface Table {
  readonly name: string;
  readonly arn: string;
  readonly id: string;
  readonly createdAt: number;
  readonly schema: KeySchema;
  readonly attributeTypes: ReadonlyMap<string, KeyType>;
  readonly gsis: readonly GlobalSecondaryIndex[];
  readonly billingMode: 'PAY_PER_REQUEST' | 'PROVISIONED';
  readonly provisioned: { read: number; write: number } | null;
  readonly deletionProtection: boolean;
  ttl: { enabled: boolean; attributeName: string | null };
  readonly items: Map<string, Item>;
}

type Json = Record<string, unknown>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

const NS = 'com.amazonaws.dynamodb.v20120810#';

class DynamoError extends Error {
  constructor(
    readonly type: string,
    message: string,
    readonly extra: Json = {},
    readonly status = 400,
  ) {
    super(message);
  }
}

const errors = {
  validation: (message: string) => new DynamoError('com.amazon.coral.validate#ValidationException', message),
  resourceNotFound: (message = 'Requested resource not found') => new DynamoError(`${NS}ResourceNotFoundException`, message),
  resourceInUse: (message: string) => new DynamoError(`${NS}ResourceInUseException`, message),
  unsupported: (what: string) => new DynamoError('com.amazon.coral.validate#ValidationException',
    `${what} is not supported by the tested-aws-simulators DynamoDB simulator.`),
  conditionalCheckFailed: (item?: Item) => new DynamoError(`${NS}ConditionalCheckFailedException`,
    'The conditional request failed', item ? { Item: item } : {}),
};

function asValidation(err: unknown): never {
  if (err instanceof ValidationError) throw errors.validation(err.message);
  throw err;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function isPlainObject(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Legacy parameters DynamoDB still accepts, which this simulator refuses by name. */
const LEGACY_PARAMETERS = [
  'Expected', 'ConditionalOperator', 'AttributesToGet', 'KeyConditions', 'QueryFilter', 'ScanFilter', 'AttributeUpdates',
];

function requireAllowedKeys(op: string, body: Json, allowed: readonly string[], context = ''): void {
  for (const key of Object.keys(body)) {
    if (allowed.includes(key)) continue;
    if (LEGACY_PARAMETERS.includes(key)) {
      throw errors.unsupported(`The legacy parameter ${context}${key} on ${op} (use the expression parameters instead)`);
    }
    throw errors.unsupported(`Parameter ${context}${key} on ${op}`);
  }
}

function requireString(body: Json, name: string, label = name): string {
  const value = body[name];
  if (typeof value !== 'string' || value === '') {
    throw errors.validation(`1 validation error detected: Value null at '${label}' failed to satisfy constraint: Member must not be null`);
  }
  return value;
}

function optionalString(body: Json, name: string): string | undefined {
  const value = body[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') throw errors.validation(`${name} must be a string`);
  return value;
}

/** ReturnConsumedCapacity / ReturnItemCollectionMetrics are accepted only as NONE. */
function refuseMetrics(op: string, body: Json): void {
  for (const key of ['ReturnConsumedCapacity', 'ReturnItemCollectionMetrics']) {
    const value = body[key];
    if (value !== undefined && value !== 'NONE') throw errors.unsupported(`${key}=${String(value)} on ${op}`);
  }
}

/**
 * Builds the expression context for a request, with DynamoDB's own checks on
 * the placeholder maps. `hasExpressions` is whether the request carries any
 * expression that could use them.
 */
function expressionContext(body: Json, hasExpressions: boolean): ExpressionContext {
  const rawNames = body['ExpressionAttributeNames'];
  const rawValues = body['ExpressionAttributeValues'];
  let names: Record<string, string> | undefined;
  let values: Record<string, AttributeValue> | undefined;
  if (rawNames !== undefined) {
    if (!hasExpressions) throw errors.validation('ExpressionAttributeNames can only be specified when using expressions');
    if (!isPlainObject(rawNames) || Object.keys(rawNames).length === 0) throw errors.validation('ExpressionAttributeNames must not be empty');
    names = {};
    for (const [key, value] of Object.entries(rawNames)) {
      if (!/^#[A-Za-z0-9_]+$/.test(key)) throw errors.validation(`ExpressionAttributeNames contains invalid key: Syntax error; key: "${key}"`);
      if (typeof value !== 'string' || value === '') {
        throw errors.validation(`ExpressionAttributeNames contains invalid value: Empty attribute name for key ${key}`);
      }
      names[key] = value;
    }
  }
  if (rawValues !== undefined) {
    if (!hasExpressions) throw errors.validation('ExpressionAttributeValues can only be specified when using expressions');
    if (!isPlainObject(rawValues) || Object.keys(rawValues).length === 0) throw errors.validation('ExpressionAttributeValues must not be empty');
    values = {};
    for (const [key, value] of Object.entries(rawValues)) {
      if (!/^:[A-Za-z0-9_]+$/.test(key)) throw errors.validation(`ExpressionAttributeValues contains invalid key: Syntax error; key: "${key}"`);
      try {
        values[key] = validateAttributeValue(value);
      } catch (err) {
        if (err instanceof ValidationError) {
          throw errors.validation(`ExpressionAttributeValues contains invalid value: ${err.message} for key ${key}`);
        }
        throw err;
      }
    }
  }
  return new ExpressionContext(names, values);
}

function wrap<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    return asValidation(err);
  }
}

// ---------------------------------------------------------------------------
// Keys and ordering
// ---------------------------------------------------------------------------

function keyTypeOf(value: AttributeValue): string {
  return typeOf(value);
}

function scalarText(value: AttributeValue): string {
  return 'S' in value ? value.S : 'N' in value ? value.N : 'B' in value ? value.B : '';
}

/** A stable map key for the given attributes of an item. */
function encodeKey(item: Item, names: readonly string[]): string {
  return JSON.stringify(names.map((n) => {
    const v = item[n];
    return v ? [keyTypeOf(v), scalarText(v)] : null;
  }));
}

function tableKeyNames(schema: KeySchema): string[] {
  return schema.range ? [schema.hash, schema.range] : [schema.hash];
}

function compareByNames(a: Item, b: Item, names: readonly string[]): number {
  for (const name of names) {
    const x = a[name];
    const y = b[name];
    if (!x || !y) continue;
    const order = compareScalars(x, y) ?? 0;
    if (order !== 0) return order;
  }
  return 0;
}

/** FNV-1a over the partition key, for parallel scan segments. */
function segmentOf(item: Item, hashName: string, totalSegments: number): number {
  const text = encodeKey(item, [hashName]);
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h % totalSegments;
}

// ---------------------------------------------------------------------------
// Simulator factory
// ---------------------------------------------------------------------------

export function createDynamoDbSimulator(options: DynamoDbSimulatorOptions = {}): DynamoDbSimulator {
  const now = options.now ?? Date.now;
  const accountId = options.accountId ?? DYNAMODB_SIMULATOR_DEFAULT_ACCOUNT_ID;
  const region = options.region ?? DYNAMODB_SIMULATOR_DEFAULT_REGION;
  const tables = new Map<string, Table>();
  const transactionTokens = new Map<string, { hash: string; at: number }>();

  function getTable(name: unknown): Table {
    if (typeof name !== 'string' || name === '') {
      throw errors.validation("1 validation error detected: Value null at 'tableName' failed to satisfy constraint: Member must not be null");
    }
    const table = tables.get(name);
    if (!table) throw errors.resourceNotFound();
    return table;
  }

  // ── Item and key validation ───────────────────────────────────────────────

  function assertKeyValue(name: string, value: AttributeValue): void {
    if (('S' in value && value.S === '') || ('B' in value && value.B === '')) {
      throw errors.validation(`One or more parameter values are not valid. The AttributeValue for a key attribute cannot contain an empty ${'S' in value ? 'string' : 'binary'} value. Key: ${name}`);
    }
  }

  /** Validates a Key parameter: exactly the table's key attributes, right types. */
  function validateKey(table: Table, raw: unknown): Item {
    if (!isPlainObject(raw)) {
      throw errors.validation("1 validation error detected: Value null at 'key' failed to satisfy constraint: Member must not be null");
    }
    const key = wrap(() => validateItem(raw, 'Key'));
    const names = tableKeyNames(table.schema);
    const mismatch = Object.keys(key).length !== names.length
      || names.some((n) => key[n] === undefined || keyTypeOf(key[n]!) !== table.attributeTypes.get(n));
    if (mismatch) throw errors.validation('The provided key element does not match the schema');
    for (const n of names) assertKeyValue(n, key[n]!);
    return key;
  }

  /** Checks a whole item: table keys, secondary index keys and size. */
  function validateStoredItem(table: Table, item: Item): void {
    for (const name of tableKeyNames(table.schema)) {
      const value = item[name];
      if (value === undefined) throw errors.validation(`One or more parameter values were invalid: Missing the key ${name} in the item`);
      const expected = table.attributeTypes.get(name)!;
      if (keyTypeOf(value) !== expected) {
        throw errors.validation(`One or more parameter values were invalid: Type mismatch for key ${name} expected: ${expected} actual: ${keyTypeOf(value)}`);
      }
      assertKeyValue(name, value);
    }
    for (const gsi of table.gsis) {
      for (const name of tableKeyNames(gsi.schema)) {
        const value = item[name];
        if (value === undefined) continue; // sparse index: the item is simply not in it
        const expected = table.attributeTypes.get(name)!;
        if (keyTypeOf(value) !== expected) {
          throw errors.validation(`One or more parameter values were invalid: Type mismatch for Index Key ${name} Expected: ${expected} Actual: ${keyTypeOf(value)} IndexName: ${gsi.name}`);
        }
        if (('S' in value && value.S === '') || ('B' in value && value.B === '')) {
          throw errors.validation(`One or more parameter values are not valid. A value specified for a secondary index key is not supported. The AttributeValue for a key attribute cannot contain an empty string value. IndexName: ${gsi.name}, IndexKey: ${name}`);
        }
      }
    }
    if (itemSize(item) > MAX_ITEM_SIZE) throw errors.validation('Item size has exceeded the maximum allowed size');
  }

  function keyOfItem(table: Table, item: Item): string {
    return encodeKey(item, tableKeyNames(table.schema));
  }

  // ── Table description ─────────────────────────────────────────────────────

  function keySchemaJson(schema: KeySchema): Json[] {
    const out: Json[] = [{ AttributeName: schema.hash, KeyType: 'HASH' }];
    if (schema.range) out.push({ AttributeName: schema.range, KeyType: 'RANGE' });
    return out;
  }

  function throughputJson(p: { read: number; write: number } | null): Json {
    return { NumberOfDecreasesToday: 0, ReadCapacityUnits: p?.read ?? 0, WriteCapacityUnits: p?.write ?? 0 };
  }

  function gsiView(gsi: GlobalSecondaryIndex, table: Table, item: Item): Item {
    if (gsi.projectionType === 'ALL') return item;
    const keep = new Set([...tableKeyNames(table.schema), ...tableKeyNames(gsi.schema), ...gsi.nonKeyAttributes]);
    return Object.fromEntries(Object.entries(item).filter(([k]) => keep.has(k)));
  }

  function gsiMembers(table: Table, gsi: GlobalSecondaryIndex): Item[] {
    return [...table.items.values()].filter((item) => tableKeyNames(gsi.schema).every((n) => item[n] !== undefined));
  }

  function describe(table: Table, status: 'ACTIVE' | 'CREATING' | 'DELETING' = 'ACTIVE'): Json {
    const items = [...table.items.values()];
    const description: Json = {
      TableName: table.name,
      TableArn: table.arn,
      TableId: table.id,
      TableStatus: status,
      CreationDateTime: table.createdAt / 1000,
      KeySchema: keySchemaJson(table.schema),
      AttributeDefinitions: [...table.attributeTypes.entries()].map(([AttributeName, AttributeType]) => ({ AttributeName, AttributeType })),
      ItemCount: items.length,
      TableSizeBytes: items.reduce((n, i) => n + itemSize(i), 0),
      ProvisionedThroughput: throughputJson(table.provisioned),
      DeletionProtectionEnabled: table.deletionProtection,
    };
    if (table.billingMode === 'PAY_PER_REQUEST') {
      description['BillingModeSummary'] = { BillingMode: 'PAY_PER_REQUEST', LastUpdateToPayPerRequestDateTime: table.createdAt / 1000 };
    }
    if (table.gsis.length > 0) {
      description['GlobalSecondaryIndexes'] = table.gsis.map((gsi) => {
        const members = gsiMembers(table, gsi);
        const projection: Json = { ProjectionType: gsi.projectionType };
        if (gsi.projectionType === 'INCLUDE') projection['NonKeyAttributes'] = [...gsi.nonKeyAttributes];
        return {
          IndexName: gsi.name,
          IndexArn: gsi.arn,
          KeySchema: keySchemaJson(gsi.schema),
          Projection: projection,
          IndexStatus: status === 'CREATING' ? 'CREATING' : 'ACTIVE',
          ItemCount: members.length,
          IndexSizeBytes: members.reduce((n, i) => n + itemSize(gsiView(gsi, table, i)), 0),
          ProvisionedThroughput: throughputJson(gsi.provisioned),
        };
      });
    }
    return description;
  }

  // ── Table operations ──────────────────────────────────────────────────────

  function parseKeySchema(raw: unknown, context: string): KeySchema {
    if (!Array.isArray(raw) || raw.length < 1 || raw.length > 2) {
      throw errors.validation(`1 validation error detected: Value at '${context}' failed to satisfy constraint: Member must have length less than or equal to 2 and greater than or equal to 1`);
    }
    const elements = raw.map((e) => {
      if (!isPlainObject(e) || typeof e['AttributeName'] !== 'string' || (e['KeyType'] !== 'HASH' && e['KeyType'] !== 'RANGE')) {
        throw errors.validation(`Invalid KeySchema: each element needs an AttributeName and a KeyType of HASH or RANGE`);
      }
      return { name: e['AttributeName'], type: e['KeyType'] as 'HASH' | 'RANGE' };
    });
    if (elements[0]!.type !== 'HASH') throw errors.validation('Invalid KeySchema: The first KeySchemaElement is not a HASH key type');
    if (elements[1] && elements[1].type !== 'RANGE') throw errors.validation('Invalid KeySchema: The second KeySchemaElement is not a RANGE key type');
    if (elements[1] && elements[1].name === elements[0]!.name) {
      throw errors.validation('Invalid KeySchema: Both the Hash Key and the Range Key element in the KeySchema have the same name');
    }
    return { hash: elements[0]!.name, range: elements[1]?.name ?? null };
  }

  function parseThroughput(raw: unknown, billingMode: 'PAY_PER_REQUEST' | 'PROVISIONED', what: string): { read: number; write: number } | null {
    if (billingMode === 'PAY_PER_REQUEST') {
      if (raw !== undefined) {
        throw errors.validation('One or more parameter values were invalid: Neither ReadCapacityUnits nor WriteCapacityUnits can be specified when BillingMode is PAY_PER_REQUEST');
      }
      return null;
    }
    if (!isPlainObject(raw)) {
      throw errors.validation(`One or more parameter values were invalid: ReadCapacityUnits and WriteCapacityUnits must both be specified when BillingMode is PROVISIONED${what}`);
    }
    const read = raw['ReadCapacityUnits'];
    const write = raw['WriteCapacityUnits'];
    if (typeof read !== 'number' || typeof write !== 'number' || read < 1 || write < 1) {
      throw errors.validation('One or more parameter values were invalid: ReadCapacityUnits and WriteCapacityUnits must both be at least 1');
    }
    return { read, write };
  }

  function createTable(body: Json): Json {
    requireAllowedKeys('CreateTable', body, [
      'TableName', 'KeySchema', 'AttributeDefinitions', 'GlobalSecondaryIndexes', 'BillingMode', 'ProvisionedThroughput',
      'DeletionProtectionEnabled', 'LocalSecondaryIndexes', 'StreamSpecification',
    ]);
    const name = requireString(body, 'TableName', 'tableName');
    if (!/^[A-Za-z0-9_.-]{3,255}$/.test(name)) {
      throw errors.validation(`1 validation error detected: Value '${name}' at 'tableName' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+ and have length between 3 and 255`);
    }
    if (body['LocalSecondaryIndexes'] !== undefined) throw errors.unsupported('LocalSecondaryIndexes');
    const stream = body['StreamSpecification'];
    if (stream !== undefined && !(isPlainObject(stream) && stream['StreamEnabled'] === false)) {
      throw errors.unsupported('StreamSpecification with StreamEnabled true (DynamoDB Streams)');
    }
    const schema = parseKeySchema(body['KeySchema'], 'keySchema');
    const billing = body['BillingMode'] ?? 'PROVISIONED';
    if (billing !== 'PROVISIONED' && billing !== 'PAY_PER_REQUEST') {
      throw errors.validation(`1 validation error detected: Value '${String(billing)}' at 'billingMode' failed to satisfy constraint: Member must satisfy enum value set: [PROVISIONED, PAY_PER_REQUEST]`);
    }
    const provisioned = parseThroughput(body['ProvisionedThroughput'], billing, '');

    const definitions = body['AttributeDefinitions'];
    if (!Array.isArray(definitions) || definitions.length === 0) {
      throw errors.validation("1 validation error detected: Value null at 'attributeDefinitions' failed to satisfy constraint: Member must not be null");
    }
    const attributeTypes = new Map<string, KeyType>();
    for (const d of definitions) {
      if (!isPlainObject(d) || typeof d['AttributeName'] !== 'string' || !['S', 'N', 'B'].includes(String(d['AttributeType']))) {
        throw errors.validation('One or more parameter values were invalid: AttributeDefinitions need an AttributeName and an AttributeType of S, N or B');
      }
      if (attributeTypes.has(d['AttributeName'])) {
        throw errors.validation(`Cannot have two attributes with the same name: ${d['AttributeName']}`);
      }
      attributeTypes.set(d['AttributeName'], d['AttributeType'] as KeyType);
    }

    const rawGsis = body['GlobalSecondaryIndexes'];
    const gsis: GlobalSecondaryIndex[] = [];
    if (rawGsis !== undefined) {
      if (!Array.isArray(rawGsis) || rawGsis.length === 0) {
        throw errors.validation('One or more parameter values were invalid: List of GlobalSecondaryIndexes is empty');
      }
      for (const raw of rawGsis) {
        if (!isPlainObject(raw)) throw errors.validation('Each GlobalSecondaryIndex must be an object');
        requireAllowedKeys('CreateTable', raw, ['IndexName', 'KeySchema', 'Projection', 'ProvisionedThroughput'], 'GlobalSecondaryIndexes[].');
        const indexName = requireString(raw, 'IndexName', 'globalSecondaryIndexes.member.indexName');
        if (!/^[A-Za-z0-9_.-]{3,255}$/.test(indexName)) {
          throw errors.validation(`1 validation error detected: Value '${indexName}' at 'globalSecondaryIndexes.member.indexName' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+`);
        }
        if (gsis.some((g) => g.name === indexName)) {
          throw errors.validation(`One or more parameter values were invalid: Duplicate index name: ${indexName}`);
        }
        const projection = raw['Projection'];
        if (!isPlainObject(projection)) {
          throw errors.validation(`One or more parameter values were invalid: Projection is missing for index ${indexName}`);
        }
        const projectionType = projection['ProjectionType'];
        if (projectionType !== 'ALL' && projectionType !== 'KEYS_ONLY' && projectionType !== 'INCLUDE') {
          throw errors.validation(`One or more parameter values were invalid: Unknown ProjectionType for index ${indexName}: ${String(projectionType)}`);
        }
        const nonKey = projection['NonKeyAttributes'];
        if (projectionType === 'INCLUDE') {
          if (!Array.isArray(nonKey) || nonKey.length === 0 || !nonKey.every((n) => typeof n === 'string')) {
            throw errors.validation('One or more parameter values were invalid: ProjectionType is INCLUDE, but NonKeyAttributes is not specified');
          }
        } else if (nonKey !== undefined) {
          throw errors.validation(`One or more parameter values were invalid: ProjectionType is ${projectionType}, but NonKeyAttributes is specified`);
        }
        gsis.push({
          name: indexName,
          arn: `arn:aws:dynamodb:${region}:${accountId}:table/${name}/index/${indexName}`,
          schema: parseKeySchema(raw['KeySchema'], 'globalSecondaryIndexes.member.keySchema'),
          projectionType,
          nonKeyAttributes: projectionType === 'INCLUDE' ? (nonKey as string[]) : [],
          provisioned: parseThroughput(raw['ProvisionedThroughput'], billing, ` for index ${indexName}`),
        });
      }
    }

    const used = new Set([...tableKeyNames(schema), ...gsis.flatMap((g) => tableKeyNames(g.schema))]);
    const undefinedKeys = [...used].filter((n) => !attributeTypes.has(n));
    if (undefinedKeys.length > 0) {
      throw errors.validation(`One or more parameter values were invalid: Some index key attributes are not defined in AttributeDefinitions. Keys: [${undefinedKeys.join(', ')}], AttributeDefinitions: [${[...attributeTypes.keys()].join(', ')}]`);
    }
    if (attributeTypes.size !== used.size) {
      throw errors.validation(`One or more parameter values were invalid: Number of attributes in KeySchema does not exactly match number of attributes defined in AttributeDefinitions`);
    }
    if (tables.has(name)) throw errors.resourceInUse(`Table already exists: ${name}`);
    const deletionProtection = body['DeletionProtectionEnabled'];
    if (deletionProtection !== undefined && typeof deletionProtection !== 'boolean') {
      throw errors.validation('DeletionProtectionEnabled must be a boolean');
    }

    const table: Table = {
      name,
      arn: `arn:aws:dynamodb:${region}:${accountId}:table/${name}`,
      id: randomUUID(),
      createdAt: now(),
      schema,
      attributeTypes,
      gsis,
      billingMode: billing,
      provisioned,
      deletionProtection: deletionProtection === true,
      ttl: { enabled: false, attributeName: null },
      items: new Map(),
    };
    tables.set(name, table);
    // Real DynamoDB answers CREATING; DescribeTable (and so the SDK's
    // waitUntilTableExists) sees ACTIVE straight away.
    return { TableDescription: describe(table, 'CREATING') };
  }

  // ── Item operations: shared machinery ─────────────────────────────────────

  type ReturnOnFailure = 'NONE' | 'ALL_OLD';

  /** One write, validated up front and applied later, so transactions can be all-or-nothing. */
  interface PreparedWrite {
    readonly table: Table;
    readonly key: string;
    readonly condition: Condition | null;
    readonly returnOnFailure: ReturnOnFailure;
    /** Returns the item to store, null to delete, or undefined for no change. */
    compute(current: Item | undefined): Item | null | undefined;
  }

  function returnOnFailure(body: Json): ReturnOnFailure {
    const value = body['ReturnValuesOnConditionCheckFailure'] ?? 'NONE';
    if (value !== 'NONE' && value !== 'ALL_OLD') {
      throw errors.validation(`1 validation error detected: Value '${String(value)}' at 'returnValuesOnConditionCheckFailure' failed to satisfy constraint: Member must satisfy enum value set: [ALL_OLD, NONE]`);
    }
    return value;
  }

  function parseConditionParam(body: Json, ctx: ExpressionContext): Condition | null {
    const source = optionalString(body, 'ConditionExpression');
    return source === undefined ? null : wrap(() => parseCondition('ConditionExpression', source, ctx));
  }

  function preparePut(op: string, body: Json, allowed: readonly string[]): PreparedWrite {
    requireAllowedKeys(op, body, allowed);
    const table = getTable(body['TableName']);
    if (!isPlainObject(body['Item'])) {
      throw errors.validation("1 validation error detected: Value null at 'item' failed to satisfy constraint: Member must not be null");
    }
    const item = wrap(() => validateItem(body['Item']));
    validateStoredItem(table, item);
    const ctx = expressionContext(body, body['ConditionExpression'] !== undefined);
    const condition = parseConditionParam(body, ctx);
    wrap(() => ctx.assertAllUsed());
    return { table, key: keyOfItem(table, item), condition, returnOnFailure: returnOnFailure(body), compute: () => item };
  }

  function prepareDelete(op: string, body: Json, allowed: readonly string[]): PreparedWrite {
    requireAllowedKeys(op, body, allowed);
    const table = getTable(body['TableName']);
    const key = validateKey(table, body['Key']);
    const ctx = expressionContext(body, body['ConditionExpression'] !== undefined);
    const condition = parseConditionParam(body, ctx);
    wrap(() => ctx.assertAllUsed());
    return { table, key: keyOfItem(table, key), condition, returnOnFailure: returnOnFailure(body), compute: () => null };
  }

  function prepareUpdate(op: string, body: Json, allowed: readonly string[]): PreparedWrite & { paths: () => Path[] } {
    requireAllowedKeys(op, body, allowed);
    const table = getTable(body['TableName']);
    const key = validateKey(table, body['Key']);
    const source = optionalString(body, 'UpdateExpression');
    const ctx = expressionContext(body, source !== undefined || body['ConditionExpression'] !== undefined);
    const ast = source === undefined ? null : wrap(() => parseUpdate(source, ctx));
    const condition = parseConditionParam(body, ctx);
    wrap(() => ctx.assertAllUsed());
    let touched: Path[] = [];
    return {
      table,
      key: keyOfItem(table, key),
      condition,
      returnOnFailure: returnOnFailure(body),
      compute(current) {
        const base = current ?? structuredClone(key);
        if (!ast) return base;
        const result = wrap(() => applyUpdate(base, ast, tableKeyNames(table.schema)));
        touched = result.paths;
        validateStoredItem(table, result.item);
        return result.item;
      },
      paths: () => touched,
    };
  }

  function prepareConditionCheck(body: Json): PreparedWrite {
    requireAllowedKeys('TransactWriteItems', body, [
      'TableName', 'Key', 'ConditionExpression', 'ExpressionAttributeNames', 'ExpressionAttributeValues',
      'ReturnValuesOnConditionCheckFailure',
    ], 'ConditionCheck.');
    const table = getTable(body['TableName']);
    const key = validateKey(table, body['Key']);
    if (body['ConditionExpression'] === undefined) {
      throw errors.validation("1 validation error detected: Value null at 'transactItems.member.conditionCheck.conditionExpression' failed to satisfy constraint: Member must not be null");
    }
    const ctx = expressionContext(body, true);
    const condition = parseConditionParam(body, ctx);
    wrap(() => ctx.assertAllUsed());
    return { table, key: keyOfItem(table, key), condition, returnOnFailure: returnOnFailure(body), compute: () => undefined };
  }

  /** Runs one prepared write outside a transaction and returns the old and new item. */
  function executeWrite(write: PreparedWrite): { old: Item | undefined; next: Item | undefined } {
    const old = write.table.items.get(write.key);
    if (write.condition && !evaluateCondition(old ?? {}, write.condition)) {
      throw errors.conditionalCheckFailed(write.returnOnFailure === 'ALL_OLD' ? old : undefined);
    }
    const next = write.compute(old);
    if (next === null) write.table.items.delete(write.key);
    else if (next !== undefined) write.table.items.set(write.key, next);
    return { old, next: next ?? undefined };
  }

  function projectionParam(body: Json, ctx: ExpressionContext): Path[] | null {
    const source = optionalString(body, 'ProjectionExpression');
    return source === undefined ? null : wrap(() => parseProjection(source, ctx));
  }

  // ── Query and Scan ────────────────────────────────────────────────────────

  interface Source {
    readonly table: Table;
    readonly gsi: GlobalSecondaryIndex | null;
    readonly schema: KeySchema;
    /** The attribute names that order the rows and make up LastEvaluatedKey. */
    readonly orderNames: readonly string[];
    readonly rows: Item[];
  }

  function sourceFor(table: Table, body: Json): Source {
    const indexName = optionalString(body, 'IndexName');
    if (indexName === undefined) {
      return {
        table, gsi: null, schema: table.schema, orderNames: tableKeyNames(table.schema), rows: [...table.items.values()],
      };
    }
    const gsi = table.gsis.find((g) => g.name === indexName);
    if (!gsi) throw errors.validation(`The table does not have the specified index: ${indexName}`);
    if (body['ConsistentRead'] === true) throw errors.validation('Consistent reads are not supported on global secondary indexes');
    const orderNames = [...tableKeyNames(gsi.schema), ...tableKeyNames(table.schema).filter((n) => !tableKeyNames(gsi.schema).includes(n))];
    return { table, gsi, schema: gsi.schema, orderNames, rows: gsiMembers(table, gsi).map((item) => gsiView(gsi, table, item)) };
  }

  type SelectMode = 'ALL_ATTRIBUTES' | 'ALL_PROJECTED_ATTRIBUTES' | 'SPECIFIC_ATTRIBUTES' | 'COUNT';

  function selectMode(body: Json, source: Source, projection: Path[] | null): SelectMode {
    const raw = body['Select'];
    if (raw !== undefined && !['ALL_ATTRIBUTES', 'ALL_PROJECTED_ATTRIBUTES', 'SPECIFIC_ATTRIBUTES', 'COUNT'].includes(String(raw))) {
      throw errors.validation(`1 validation error detected: Value '${String(raw)}' at 'select' failed to satisfy constraint: Member must satisfy enum value set: [SPECIFIC_ATTRIBUTES, COUNT, ALL_ATTRIBUTES, ALL_PROJECTED_ATTRIBUTES]`);
    }
    const mode = (raw as SelectMode | undefined)
      ?? (projection ? 'SPECIFIC_ATTRIBUTES' : source.gsi ? 'ALL_PROJECTED_ATTRIBUTES' : 'ALL_ATTRIBUTES');
    if (mode !== 'SPECIFIC_ATTRIBUTES' && projection) {
      throw errors.validation(`Cannot specify the ProjectionExpression when choosing to get ${mode}`);
    }
    if (mode === 'SPECIFIC_ATTRIBUTES' && !projection) {
      throw errors.validation('Select type SPECIFIC_ATTRIBUTES requires a ProjectionExpression');
    }
    if (mode === 'ALL_PROJECTED_ATTRIBUTES' && !source.gsi) {
      throw errors.validation('ALL_PROJECTED_ATTRIBUTES can be used only when Querying using an IndexName');
    }
    if (mode === 'ALL_ATTRIBUTES' && source.gsi && source.gsi.projectionType !== 'ALL') {
      throw errors.validation(`One or more parameter values were invalid: Select type ALL_ATTRIBUTES is not supported for global secondary index ${source.gsi.name} because its projection type is not ALL`);
    }
    return mode;
  }

  function limitParam(body: Json): number | undefined {
    const limit = body['Limit'];
    if (limit === undefined) return undefined;
    if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1) {
      throw errors.validation(`1 validation error detected: Value '${String(limit)}' at 'limit' failed to satisfy constraint: Member must have value greater than or equal to 1`);
    }
    return limit;
  }

  /** Validates ExclusiveStartKey: exactly the attributes a LastEvaluatedKey would carry. */
  function startKeyParam(body: Json, source: Source): Item | null {
    const raw = body['ExclusiveStartKey'];
    if (raw === undefined) return null;
    const key = wrap(() => validateItem(raw, 'ExclusiveStartKey'));
    const names = source.orderNames;
    const ok = Object.keys(key).length === names.length
      && names.every((n) => key[n] !== undefined && keyTypeOf(key[n]!) === source.table.attributeTypes.get(n));
    if (!ok) throw errors.validation('The provided starting key is invalid: The provided key element does not match the schema');
    return key;
  }

  interface PageResult {
    items: Item[];
    count: number;
    scanned: number;
    lastEvaluatedKey: Item | null;
  }

  function readPage(rows: Item[], source: Source, body: Json, filter: Condition | null, projection: Path[] | null, mode: SelectMode, startKey: Item | null, descending: boolean): PageResult {
    const direction = descending ? -1 : 1;
    const ordered = rows.slice().sort((a, b) => direction * compareByNames(a, b, source.orderNames));
    let start = 0;
    if (startKey) {
      start = ordered.findIndex((row) => direction * compareByNames(row, startKey, source.orderNames) > 0);
      if (start < 0) start = ordered.length;
    }
    const limit = limitParam(body);
    const result: PageResult = { items: [], count: 0, scanned: 0, lastEvaluatedKey: null };
    let bytes = 0;
    for (let i = start; i < ordered.length; i++) {
      const row = ordered[i]!;
      result.scanned += 1;
      bytes += itemSize(row);
      if (!filter || evaluateCondition(row, filter)) {
        result.count += 1;
        if (mode !== 'COUNT') result.items.push(projection ? project(row, projection) : structuredClone(row));
      }
      // DynamoDB returns a LastEvaluatedKey whenever it stops at Limit or at
      // 1 MB, even when no items remain, so a caller can see an empty last page.
      if ((limit !== undefined && result.scanned >= limit) || bytes >= MAX_PAGE_BYTES) {
        result.lastEvaluatedKey = Object.fromEntries(source.orderNames.map((n) => [n, structuredClone(row[n]!)]));
        break;
      }
    }
    return result;
  }

  function pageResponse(page: PageResult, mode: SelectMode): Json {
    const out: Json = { Count: page.count, ScannedCount: page.scanned };
    if (mode !== 'COUNT') out['Items'] = page.items;
    if (page.lastEvaluatedKey) out['LastEvaluatedKey'] = page.lastEvaluatedKey;
    return out;
  }

  /**
   * Reduces a KeyConditionExpression to "partition key = value" plus an
   * optional sort key condition, with DynamoDB's refusals for anything else.
   */
  function analyseKeyCondition(condition: Condition, source: Source): { hash: AttributeValue; range: Condition | null } {
    const parts: Condition[] = [];
    const collect = (c: Condition): void => {
      if (c.k === 'and') {
        collect(c.left);
        collect(c.right);
      } else {
        parts.push(c);
      }
    };
    collect(condition);
    if (parts.length > 2) throw errors.validation('Invalid KeyConditionExpression: The expression can only contain up to two key conditions');

    const keyName = (o: Operand): string | null => {
      if (o.k !== 'path' || o.path.length !== 1) return null;
      const first = o.path[0]!;
      return 'name' in first ? first.name : null;
    };
    const checkValueType = (name: string, o: Operand): void => {
      if (o.k !== 'value') throw errors.validation('Query key condition not supported');
      if (keyTypeOf(o.value) !== source.table.attributeTypes.get(name)) {
        throw errors.validation('One or more parameter values were invalid: Condition parameter type does not match schema type');
      }
    };

    let hash: AttributeValue | null = null;
    let range: Condition | null = null;
    const seen = new Set<string>();
    for (const part of parts) {
      let name: string | null = null;
      if (part.k === 'cmp') name = keyName(part.left);
      else if (part.k === 'between') name = keyName(part.operand);
      else if (part.k === 'fn' && part.name === 'begins_with') name = keyName(part.args[0]!);
      else throw errors.validation('Invalid operator used in KeyConditionExpression: ' + (part.k === 'fn' ? part.name : part.k.toUpperCase()));

      if (name === null) throw errors.validation('Query key condition not supported');
      if (seen.has(name)) throw errors.validation('KeyConditionExpressions must only contain one condition per key');
      seen.add(name);
      if (name === source.schema.hash) {
        if (part.k !== 'cmp' || part.op !== '=') throw errors.validation('Query key condition not supported');
        checkValueType(name, part.right);
        hash = (part.right as { value: AttributeValue }).value;
      } else if (name === source.schema.range) {
        if (part.k === 'cmp') {
          if (part.op === '<>') throw errors.validation('Unsupported operator on KeyConditionExpression: operator: <>');
          checkValueType(name, part.right);
        } else if (part.k === 'between') {
          checkValueType(name, part.low);
          checkValueType(name, part.high);
        } else if (part.k === 'fn') {
          const prefix = part.args[1]!;
          checkValueType(name, prefix);
          if (source.table.attributeTypes.get(name) === 'N') {
            throw errors.validation('Invalid KeyConditionExpression: Incorrect operand type for operator or function; operator or function: begins_with, operand type: N');
          }
        }
        range = part;
      } else {
        throw errors.validation(`Query condition missed key schema element: ${source.schema.hash}`);
      }
    }
    if (hash === null) throw errors.validation(`Query condition missed key schema element: ${source.schema.hash}`);
    return { hash, range };
  }

  function filterParam(body: Json, ctx: ExpressionContext, keyNames: readonly string[] | null): Condition | null {
    const source = optionalString(body, 'FilterExpression');
    if (source === undefined) return null;
    const filter = wrap(() => parseCondition('FilterExpression', source, ctx));
    if (keyNames) {
      for (const name of topLevelNames(filter)) {
        if (keyNames.includes(name)) {
          throw errors.validation(`Filter Expression can only contain non-primary key attributes: Primary key attribute: ${name}`);
        }
      }
    }
    return filter;
  }

  function query(body: Json): Json {
    requireAllowedKeys('Query', body, [
      'TableName', 'IndexName', 'KeyConditionExpression', 'FilterExpression', 'ProjectionExpression',
      'ExpressionAttributeNames', 'ExpressionAttributeValues', 'ScanIndexForward', 'Limit', 'ExclusiveStartKey',
      'Select', 'ConsistentRead', 'ReturnConsumedCapacity',
    ]);
    refuseMetrics('Query', body);
    const table = getTable(body['TableName']);
    const source = sourceFor(table, body);
    const keySource = optionalString(body, 'KeyConditionExpression');
    if (keySource === undefined) {
      throw errors.validation('Either the KeyConditions or KeyConditionExpression parameter must be specified in the request.');
    }
    const ctx = expressionContext(body, true);
    const keyCondition = wrap(() => parseCondition('KeyConditionExpression', keySource, ctx));
    const { hash, range } = analyseKeyCondition(keyCondition, source);
    const filter = filterParam(body, ctx, tableKeyNames(source.schema));
    const projection = projectionParam(body, ctx);
    wrap(() => ctx.assertAllUsed());
    const mode = selectMode(body, source, projection);
    const startKey = startKeyParam(body, source);
    const forward = body['ScanIndexForward'] ?? true;
    if (typeof forward !== 'boolean') throw errors.validation('ScanIndexForward must be a boolean');

    const rows = source.rows.filter((row) => {
      const h = row[source.schema.hash];
      if (!h || !valuesEqual(h, hash)) return false;
      return range === null || evaluateCondition(row, range);
    });
    return pageResponse(readPage(rows, source, body, filter, projection, mode, startKey, !forward), mode);
  }

  function scan(body: Json): Json {
    requireAllowedKeys('Scan', body, [
      'TableName', 'IndexName', 'FilterExpression', 'ProjectionExpression', 'ExpressionAttributeNames',
      'ExpressionAttributeValues', 'Limit', 'ExclusiveStartKey', 'Select', 'ConsistentRead', 'Segment', 'TotalSegments',
      'ReturnConsumedCapacity',
    ]);
    refuseMetrics('Scan', body);
    const table = getTable(body['TableName']);
    const source = sourceFor(table, body);
    const hasExpressions = body['FilterExpression'] !== undefined || body['ProjectionExpression'] !== undefined;
    const ctx = expressionContext(body, hasExpressions);
    const filter = filterParam(body, ctx, null);
    const projection = projectionParam(body, ctx);
    wrap(() => ctx.assertAllUsed());
    const mode = selectMode(body, source, projection);
    const startKey = startKeyParam(body, source);

    const segment = body['Segment'];
    const total = body['TotalSegments'];
    let rows = source.rows;
    if (segment !== undefined || total !== undefined) {
      if (total === undefined) throw errors.validation('The TotalSegments parameter is required but was not present in the request when parameter Segment is present');
      if (segment === undefined) throw errors.validation('The Segment parameter is required but was not present in the request when parameter TotalSegments is present');
      if (typeof total !== 'number' || !Number.isInteger(total) || total < 1 || total > 1_000_000) {
        throw errors.validation(`1 validation error detected: Value '${String(total)}' at 'totalSegments' failed to satisfy constraint: Member must have value between 1 and 1000000`);
      }
      if (typeof segment !== 'number' || !Number.isInteger(segment) || segment < 0 || segment >= total) {
        throw errors.validation(`The Segment parameter is zero-based and must be less than parameter TotalSegments: Segment: ${String(segment)} is not less than TotalSegments: ${total}`);
      }
      rows = rows.filter((row) => segmentOf(row, source.schema.hash, total) === segment);
    }
    return pageResponse(readPage(rows, source, body, filter, projection, mode, startKey, false), mode);
  }

  // ── Operation table ───────────────────────────────────────────────────────

  const PUT_KEYS = [
    'TableName', 'Item', 'ConditionExpression', 'ExpressionAttributeNames', 'ExpressionAttributeValues', 'ReturnValues',
    'ReturnValuesOnConditionCheckFailure', 'ReturnConsumedCapacity', 'ReturnItemCollectionMetrics',
  ];
  const DELETE_KEYS = [
    'TableName', 'Key', 'ConditionExpression', 'ExpressionAttributeNames', 'ExpressionAttributeValues', 'ReturnValues',
    'ReturnValuesOnConditionCheckFailure', 'ReturnConsumedCapacity', 'ReturnItemCollectionMetrics',
  ];
  const UPDATE_KEYS = [...DELETE_KEYS, 'UpdateExpression'];

  function oldOnlyReturnValues(body: Json): 'NONE' | 'ALL_OLD' {
    const value = body['ReturnValues'] ?? 'NONE';
    if (value !== 'NONE' && value !== 'ALL_OLD') throw errors.validation('Return values set to invalid value');
    return value;
  }

  type Handler = (body: Json) => Json;

  const handlers: Record<string, Handler> = {
    CreateTable: createTable,

    DescribeTable(body) {
      requireAllowedKeys('DescribeTable', body, ['TableName']);
      const name = requireString(body, 'TableName', 'tableName');
      const table = tables.get(name);
      if (!table) throw errors.resourceNotFound(`Requested resource not found: Table: ${name} not found`);
      return { Table: describe(table) };
    },

    ListTables(body) {
      requireAllowedKeys('ListTables', body, ['ExclusiveStartTableName', 'Limit']);
      const limit = body['Limit'] ?? 100;
      if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > 100) {
        throw errors.validation(`1 validation error detected: Value '${String(limit)}' at 'limit' failed to satisfy constraint: Member must have value less than or equal to 100`);
      }
      const after = optionalString(body, 'ExclusiveStartTableName');
      const names = [...tables.keys()].sort().filter((n) => after === undefined || n > after);
      const page = names.slice(0, limit);
      const out: Json = { TableNames: page };
      if (names.length > limit) out['LastEvaluatedTableName'] = page[page.length - 1];
      return out;
    },

    DeleteTable(body) {
      requireAllowedKeys('DeleteTable', body, ['TableName']);
      const table = getTable(body['TableName']);
      if (table.deletionProtection) {
        throw errors.validation('Resource cannot be deleted as it is currently protected against deletion. Disable deletion protection first.');
      }
      tables.delete(table.name);
      return { TableDescription: describe(table, 'DELETING') };
    },

    UpdateTimeToLive(body) {
      requireAllowedKeys('UpdateTimeToLive', body, ['TableName', 'TimeToLiveSpecification']);
      const table = getTable(body['TableName']);
      const spec = body['TimeToLiveSpecification'];
      if (!isPlainObject(spec) || typeof spec['Enabled'] !== 'boolean' || typeof spec['AttributeName'] !== 'string' || spec['AttributeName'] === '') {
        throw errors.validation("1 validation error detected: Value null at 'timeToLiveSpecification' failed to satisfy constraint: Member must not be null");
      }
      const enabled = spec['Enabled'];
      const attributeName = spec['AttributeName'];
      if (enabled && table.ttl.enabled) throw errors.validation('TimeToLive is already enabled');
      if (!enabled && !table.ttl.enabled) throw errors.validation('TimeToLive is already disabled');
      if (!enabled && table.ttl.attributeName !== attributeName) {
        throw errors.validation(`TimeToLive is active on a different AttributeName: current AttributeName is ${String(table.ttl.attributeName)}`);
      }
      table.ttl = { enabled, attributeName: enabled ? attributeName : null };
      return { TimeToLiveSpecification: { Enabled: enabled, AttributeName: attributeName } };
    },

    DescribeTimeToLive(body) {
      requireAllowedKeys('DescribeTimeToLive', body, ['TableName']);
      const table = getTable(body['TableName']);
      const description: Json = { TimeToLiveStatus: table.ttl.enabled ? 'ENABLED' : 'DISABLED' };
      if (table.ttl.attributeName) description['AttributeName'] = table.ttl.attributeName;
      return { TimeToLiveDescription: description };
    },

    PutItem(body) {
      refuseMetrics('PutItem', body);
      const returnValues = body['ReturnValues'] ?? 'NONE';
      if (returnValues !== 'NONE' && returnValues !== 'ALL_OLD') {
        throw errors.validation('ReturnValues can only be ALL_OLD or NONE');
      }
      const { old } = executeWrite(preparePut('PutItem', body, PUT_KEYS));
      return returnValues === 'ALL_OLD' && old ? { Attributes: old } : {};
    },

    GetItem(body) {
      requireAllowedKeys('GetItem', body, [
        'TableName', 'Key', 'ProjectionExpression', 'ExpressionAttributeNames', 'ConsistentRead', 'ReturnConsumedCapacity',
      ]);
      refuseMetrics('GetItem', body);
      const table = getTable(body['TableName']);
      const key = validateKey(table, body['Key']);
      const ctx = expressionContext(body, body['ProjectionExpression'] !== undefined);
      const projection = projectionParam(body, ctx);
      wrap(() => ctx.assertAllUsed());
      const item = table.items.get(keyOfItem(table, key));
      if (!item) return {};
      return { Item: projection ? project(item, projection) : structuredClone(item) };
    },

    DeleteItem(body) {
      refuseMetrics('DeleteItem', body);
      const returnValues = oldOnlyReturnValues(body);
      const { old } = executeWrite(prepareDelete('DeleteItem', body, DELETE_KEYS));
      return returnValues === 'ALL_OLD' && old ? { Attributes: old } : {};
    },

    UpdateItem(body) {
      refuseMetrics('UpdateItem', body);
      const returnValues = body['ReturnValues'] ?? 'NONE';
      if (!['NONE', 'ALL_OLD', 'UPDATED_OLD', 'ALL_NEW', 'UPDATED_NEW'].includes(String(returnValues))) {
        throw errors.validation(`1 validation error detected: Value '${String(returnValues)}' at 'returnValues' failed to satisfy constraint: Member must satisfy enum value set: [ALL_NEW, UPDATED_OLD, ALL_OLD, NONE, UPDATED_NEW]`);
      }
      const write = prepareUpdate('UpdateItem', body, UPDATE_KEYS);
      const { old, next } = executeWrite(write);
      let attributes: Item | undefined;
      switch (returnValues) {
        case 'ALL_OLD': attributes = old; break;
        case 'ALL_NEW': attributes = next; break;
        case 'UPDATED_OLD': attributes = project(old ?? {}, write.paths()); break;
        case 'UPDATED_NEW': attributes = project(next ?? {}, write.paths()); break;
      }
      return attributes && Object.keys(attributes).length > 0 ? { Attributes: structuredClone(attributes) } : {};
    },

    Query: query,
    Scan: scan,

    BatchGetItem(body) {
      requireAllowedKeys('BatchGetItem', body, ['RequestItems', 'ReturnConsumedCapacity']);
      refuseMetrics('BatchGetItem', body);
      const requestItems = body['RequestItems'];
      if (!isPlainObject(requestItems) || Object.keys(requestItems).length === 0) {
        throw errors.validation("1 validation error detected: Value null at 'requestItems' failed to satisfy constraint: Member must have length greater than or equal to 1");
      }
      let total = 0;
      const plans: Array<{ table: Table; keys: Item[]; projection: Path[] | null }> = [];
      for (const [tableName, request] of Object.entries(requestItems)) {
        if (!isPlainObject(request)) throw errors.validation('Each RequestItems entry must be an object');
        requireAllowedKeys('BatchGetItem', request, ['Keys', 'ProjectionExpression', 'ExpressionAttributeNames', 'ConsistentRead'], 'RequestItems[].');
        const table = getTable(tableName);
        const rawKeys = request['Keys'];
        if (!Array.isArray(rawKeys) || rawKeys.length === 0) {
          throw errors.validation("1 validation error detected: Value at 'requestItems.member.keys' failed to satisfy constraint: Member must have length greater than or equal to 1");
        }
        const keys = rawKeys.map((k) => validateKey(table, k));
        if (new Set(keys.map((k) => keyOfItem(table, k))).size !== keys.length) {
          throw errors.validation('Provided list of item keys contains duplicates');
        }
        total += keys.length;
        const ctx = expressionContext(request, request['ProjectionExpression'] !== undefined);
        const projection = projectionParam(request, ctx);
        wrap(() => ctx.assertAllUsed());
        plans.push({ table, keys, projection });
      }
      if (total > MAX_BATCH_GET_KEYS) {
        throw errors.validation('Too many items requested for the BatchGetItem call');
      }
      const responses: Record<string, Item[]> = {};
      for (const { table, keys, projection } of plans) {
        responses[table.name] = keys
          .map((k) => table.items.get(keyOfItem(table, k)))
          .filter((item): item is Item => item !== undefined)
          .map((item) => (projection ? project(item, projection) : structuredClone(item)));
      }
      return { Responses: responses, UnprocessedKeys: {} };
    },

    BatchWriteItem(body) {
      requireAllowedKeys('BatchWriteItem', body, ['RequestItems', 'ReturnConsumedCapacity', 'ReturnItemCollectionMetrics']);
      refuseMetrics('BatchWriteItem', body);
      const requestItems = body['RequestItems'];
      if (!isPlainObject(requestItems) || Object.keys(requestItems).length === 0) {
        throw errors.validation("1 validation error detected: Value null at 'requestItems' failed to satisfy constraint: Member must have length greater than or equal to 1");
      }
      const writes: PreparedWrite[] = [];
      for (const [tableName, requests] of Object.entries(requestItems)) {
        if (!Array.isArray(requests) || requests.length === 0) {
          throw errors.validation("1 validation error detected: Value at 'requestItems' failed to satisfy constraint: Map value must satisfy constraint: [Member must have length greater than or equal to 1]");
        }
        const seen = new Set<string>();
        for (const request of requests) {
          if (!isPlainObject(request) || Object.keys(request).length !== 1) {
            throw errors.validation('Supplied AttributeValue has more than one datatypes set, must contain exactly one of the supported datatypes');
          }
          let write: PreparedWrite;
          if (isPlainObject(request['PutRequest'])) {
            write = preparePut('BatchWriteItem', { TableName: tableName, ...request['PutRequest'] }, ['TableName', 'Item']);
          } else if (isPlainObject(request['DeleteRequest'])) {
            write = prepareDelete('BatchWriteItem', { TableName: tableName, ...request['DeleteRequest'] }, ['TableName', 'Key']);
          } else {
            throw errors.validation('Each BatchWriteItem request must be a PutRequest or a DeleteRequest');
          }
          if (seen.has(write.key)) throw errors.validation('Provided list of item keys contains duplicates');
          seen.add(write.key);
          writes.push(write);
        }
      }
      if (writes.length > MAX_BATCH_WRITE_REQUESTS) {
        throw errors.validation(`1 validation error detected: Value at 'requestItems' failed to satisfy constraint: Map value must satisfy constraint: [Member must have length less than or equal to ${MAX_BATCH_WRITE_REQUESTS}, Member must have length greater than or equal to 1]`);
      }
      for (const write of writes) executeWrite(write);
      return { UnprocessedItems: {} };
    },

    TransactWriteItems(body) {
      requireAllowedKeys('TransactWriteItems', body, [
        'TransactItems', 'ClientRequestToken', 'ReturnConsumedCapacity', 'ReturnItemCollectionMetrics',
      ]);
      refuseMetrics('TransactWriteItems', body);
      const transactItems = body['TransactItems'];
      if (!Array.isArray(transactItems) || transactItems.length === 0) {
        throw errors.validation("1 validation error detected: Value null at 'transactItems' failed to satisfy constraint: Member must not be null");
      }
      if (transactItems.length > MAX_TRANSACT_ITEMS) {
        throw errors.validation(`1 validation error detected: Value '[...]' at 'transactItems' failed to satisfy constraint: Member must have length less than or equal to ${MAX_TRANSACT_ITEMS}`);
      }

      const token = optionalString(body, 'ClientRequestToken');
      const requestHash = createHash('sha256').update(JSON.stringify(transactItems)).digest('hex');
      if (token !== undefined) {
        const previous = transactionTokens.get(token);
        if (previous && now() - previous.at < IDEMPOTENCY_WINDOW_MS) {
          if (previous.hash !== requestHash) {
            throw new DynamoError(`${NS}IdempotentParameterMismatchException`,
              'Transaction with the same ClientRequestToken and different parameters has already been processed');
          }
          return {}; // already applied: DynamoDB does not apply it twice
        }
      }

      const writes: PreparedWrite[] = transactItems.map((entry) => {
        if (!isPlainObject(entry) || Object.keys(entry).length !== 1) {
          throw errors.validation('TransactItems can only contain one of Check, Put, Update or Delete');
        }
        const [kind, inner] = Object.entries(entry)[0]!;
        if (!isPlainObject(inner)) throw errors.validation(`TransactItems ${kind} must be an object`);
        const allowed = (keys: string[]): string[] => keys.filter((k) => k !== 'ReturnValues'
          && k !== 'ReturnConsumedCapacity' && k !== 'ReturnItemCollectionMetrics');
        switch (kind) {
          case 'Put': return preparePut('TransactWriteItems', inner, allowed(PUT_KEYS));
          case 'Delete': return prepareDelete('TransactWriteItems', inner, allowed(DELETE_KEYS));
          case 'Update': return prepareUpdate('TransactWriteItems', inner, allowed(UPDATE_KEYS));
          case 'ConditionCheck': return prepareConditionCheck(inner);
          default: throw errors.validation(`TransactItems can only contain one of Check, Put, Update or Delete; found ${kind}`);
        }
      });
      const targets = writes.map((w) => `${w.table.name}\u0000${w.key}`);
      if (new Set(targets).size !== targets.length) {
        throw errors.validation('Transaction request cannot include multiple operations on one item');
      }

      // Evaluate every write against the state before the transaction; apply
      // none unless all succeed.
      const results: Array<Item | null | undefined> = [];
      const reasons: Json[] = [];
      let cancelled = false;
      for (const write of writes) {
        const current = write.table.items.get(write.key);
        if (write.condition && !evaluateCondition(current ?? {}, write.condition)) {
          cancelled = true;
          const reason: Json = { Code: 'ConditionalCheckFailed', Message: 'The conditional request failed' };
          if (write.returnOnFailure === 'ALL_OLD' && current) reason['Item'] = current;
          reasons.push(reason);
          results.push(undefined);
          continue;
        }
        try {
          results.push(write.compute(current));
          reasons.push({ Code: 'None' });
        } catch (err) {
          if (!(err instanceof DynamoError) || !err.type.endsWith('#ValidationException')) throw err;
          cancelled = true;
          reasons.push({ Code: 'ValidationError', Message: err.message });
          results.push(undefined);
        }
      }
      if (cancelled) {
        throw new DynamoError(`${NS}TransactionCanceledException`,
          `Transaction cancelled, please refer cancellation reasons for specific reasons [${reasons.map((r) => r['Code']).join(', ')}]`,
          { CancellationReasons: reasons });
      }
      writes.forEach((write, i) => {
        const next = results[i];
        if (next === null) write.table.items.delete(write.key);
        else if (next !== undefined) write.table.items.set(write.key, next);
      });
      if (token !== undefined) transactionTokens.set(token, { hash: requestHash, at: now() });
      return {};
    },

    TransactGetItems(body) {
      requireAllowedKeys('TransactGetItems', body, ['TransactItems', 'ReturnConsumedCapacity']);
      refuseMetrics('TransactGetItems', body);
      const transactItems = body['TransactItems'];
      if (!Array.isArray(transactItems) || transactItems.length === 0 || transactItems.length > MAX_TRANSACT_ITEMS) {
        throw errors.validation(`1 validation error detected: Value at 'transactItems' failed to satisfy constraint: Member must have length less than or equal to ${MAX_TRANSACT_ITEMS} and greater than or equal to 1`);
      }
      const plans = transactItems.map((entry) => {
        if (!isPlainObject(entry) || !isPlainObject(entry['Get']) || Object.keys(entry).length !== 1) {
          throw errors.validation('TransactGetItems entries must each contain a Get');
        }
        const get = entry['Get'];
        requireAllowedKeys('TransactGetItems', get, ['TableName', 'Key', 'ProjectionExpression', 'ExpressionAttributeNames'], 'Get.');
        const table = getTable(get['TableName']);
        const key = validateKey(table, get['Key']);
        const ctx = expressionContext(get, get['ProjectionExpression'] !== undefined);
        const projection = projectionParam(get, ctx);
        wrap(() => ctx.assertAllUsed());
        return { table, key: keyOfItem(table, key), projection };
      });
      const targets = plans.map((p) => `${p.table.name}\u0000${p.key}`);
      if (new Set(targets).size !== targets.length) {
        throw errors.validation('Transaction request cannot include multiple operations on one item');
      }
      return {
        Responses: plans.map(({ table, key, projection }) => {
          const item = table.items.get(key);
          if (!item) return {};
          return { Item: projection ? project(item, projection) : structuredClone(item) };
        }),
      };
    },
  };

  // ── HTTP ──────────────────────────────────────────────────────────────────

  function sendError(res: express.Response, err: DynamoError): void {
    res.status(err.status)
      .setHeader('x-amzn-RequestId', randomUUID())
      .type('application/x-amz-json-1.0')
      .send(JSON.stringify({ __type: err.type, message: err.message, ...err.extra }));
  }

  const app = express();

  app.post('/__local/reset', (_req, res) => {
    reset();
    res.status(204).end();
  });

  app.post('/', async (req, res) => {
    try {
      const target = req.headers['x-amz-target'];
      if (typeof target !== 'string' || !target.startsWith('DynamoDB_20120810.')) {
        throw new DynamoError('com.amazon.coral.service#UnknownOperationException',
          `Missing or unknown X-Amz-Target ${String(target ?? '')}; expected DynamoDB_20120810.<Operation>`);
      }
      const op = target.slice('DynamoDB_20120810.'.length);
      const raw = (await readRawBody(req)).toString('utf8');
      let body: unknown;
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        throw new DynamoError('com.amazon.coral.service#SerializationException', 'Start of structure or map found where not expected.');
      }
      if (!isPlainObject(body)) throw new DynamoError('com.amazon.coral.service#SerializationException', 'The request body must be a JSON object.');
      const handler = handlers[op];
      if (!handler) {
        throw new DynamoError('com.amazon.coral.service#UnknownOperationException',
          `Operation ${op} is not supported by the tested-aws-simulators DynamoDB simulator.`);
      }
      const result = handler(body);
      res.status(200)
        .setHeader('x-amzn-RequestId', randomUUID())
        .type('application/x-amz-json-1.0')
        .send(JSON.stringify(result));
    } catch (err) {
      if (err instanceof DynamoError) {
        sendError(res, err);
        return;
      }
      if (err instanceof ValidationError) {
        sendError(res, errors.validation(err.message));
        return;
      }
      console.error('[dynamodb-simulator] Error handling request', err);
      sendError(res, new DynamoError(`${NS}InternalServerError`, 'Internal simulator error', {}, 500));
    }
  });

  app.use((req, res) => {
    sendError(res, new DynamoError('com.amazon.coral.service#UnknownOperationException', `No DynamoDB route for ${req.method} ${req.path}.`, {}, 404));
  });

  // ── Hooks ─────────────────────────────────────────────────────────────────

  function reset(): void {
    tables.clear();
    transactionTokens.clear();
  }

  function listTables(): readonly DynamoDbTableSummary[] {
    return [...tables.values()]
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
      .map((t) => ({
        name: t.name,
        arn: t.arn,
        partitionKey: t.schema.hash,
        sortKey: t.schema.range,
        attributeDefinitions: Object.fromEntries(t.attributeTypes),
        globalSecondaryIndexes: t.gsis.map((g) => g.name),
        billingMode: t.billingMode,
        timeToLive: { ...t.ttl },
        itemCount: t.items.size,
      }));
  }

  function dumpTable(name: string): readonly Item[] {
    const table = tables.get(name);
    if (!table) throw new Error(`[dynamodb-simulator] No table named ${name}`);
    const names = tableKeyNames(table.schema);
    return [...table.items.values()].sort((a, b) => compareByNames(a, b, names)).map((i) => structuredClone(i));
  }

  return { app, reset, listTables, dumpTable };
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export interface StartDynamoDbSimulatorOptions extends DynamoDbSimulatorOptions {
  /** Default `DYNAMODB_SIMULATOR_PORT` env var, else 38310. Pass 0 for a free port. */
  readonly port?: number;
  readonly host?: string;
}

export async function startDynamoDbSimulator(
  options: StartDynamoDbSimulatorOptions = {},
): Promise<RunningSimulator & { readonly simulator: DynamoDbSimulator }> {
  const port = options.port ?? Number(process.env.DYNAMODB_SIMULATOR_PORT ?? DYNAMODB_SIMULATOR_DEFAULT_PORT);
  const simulator = createDynamoDbSimulator(options);
  const running = await listen(simulator.app, port, options.host);
  console.log(`DynamoDB simulator listening on ${running.url}`);
  return { ...running, simulator };
}
