import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  ConditionalCheckFailedException,
  CreateTableCommand,
  DeleteTableCommand,
  DescribeTableCommand,
  DescribeTimeToLiveCommand,
  DynamoDBClient,
  DynamoDBServiceException,
  GetItemCommand,
  ListTablesCommand,
  PutItemCommand,
  QueryCommand as LowLevelQueryCommand,
  ResourceInUseException,
  ResourceNotFoundException,
  TransactionCanceledException,
  UpdateItemCommand as LowLevelUpdateItemCommand,
  UpdateTableCommand,
  UpdateTimeToLiveCommand,
  waitUntilTableExists,
  type CreateTableCommandInput,
} from '@aws-sdk/client-dynamodb';
import {
  BatchGetCommand,
  BatchWriteCommand,
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  paginateQuery,
  PutCommand,
  QueryCommand,
  ScanCommand,
  TransactGetCommand,
  TransactWriteCommand,
  UpdateCommand,
  type QueryCommandInput,
  type QueryCommandOutput,
  type ScanCommandInput,
  type ScanCommandOutput,
} from '@aws-sdk/lib-dynamodb';

import { startDynamoDbSimulator, type DynamoDbSimulator } from './dynamodb-simulator';
import type { RunningSimulator } from '../shared/server';

/**
 * Every case drives the simulator through the real AWS SDK v3 clients: the
 * low-level DynamoDBClient where the wire format matters, and the
 * DynamoDBDocumentClient most applications use.
 */
let running: RunningSimulator & { simulator: DynamoDbSimulator };
let ddb: DynamoDBClient;
let doc: DynamoDBDocumentClient;

beforeAll(async () => {
  running = await startDynamoDbSimulator({ port: 0 });
  ddb = new DynamoDBClient({
    endpoint: running.url,
    region: 'us-east-1',
    credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
  });
  doc = DynamoDBDocumentClient.from(ddb, { marshallOptions: { removeUndefinedValues: true } });
});

afterAll(async () => {
  ddb.destroy();
  await running.close();
});

beforeEach(() => {
  running.simulator.reset();
});

const TABLE = 'things';

async function createTable(overrides: Partial<CreateTableCommandInput> = {}): Promise<void> {
  await ddb.send(new CreateTableCommand({
    TableName: TABLE,
    BillingMode: 'PAY_PER_REQUEST',
    KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }, { AttributeName: 'sk', KeyType: 'RANGE' }],
    AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }, { AttributeName: 'sk', AttributeType: 'S' }],
    ...overrides,
  }));
}

async function createHashTable(label = TABLE): Promise<void> {
  await ddb.send(new CreateTableCommand({
    TableName: label,
    BillingMode: 'PAY_PER_REQUEST',
    KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
    AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
  }));
}

async function failure(promise: Promise<unknown>): Promise<DynamoDBServiceException> {
  const err = await promise.then(() => null, (e: unknown) => e);
  if (!(err instanceof DynamoDBServiceException)) throw new Error(`expected a DynamoDBServiceException, got ${String(err)}`);
  return err;
}

async function validationMessage(promise: Promise<unknown>): Promise<string> {
  const err = await failure(promise);
  expect(err.name).toBe('ValidationException');
  expect(err.$metadata.httpStatusCode).toBe(400);
  return err.message;
}

// ---------------------------------------------------------------------------

describe('tables', () => {
  it('creates a table, answering CREATING, then describes it as ACTIVE', async () => {
    const created = await ddb.send(new CreateTableCommand({
      TableName: TABLE,
      BillingMode: 'PAY_PER_REQUEST',
      KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }, { AttributeName: 'sk', KeyType: 'RANGE' }],
      AttributeDefinitions: [
        { AttributeName: 'pk', AttributeType: 'S' },
        { AttributeName: 'sk', AttributeType: 'N' },
        { AttributeName: 'gpk', AttributeType: 'S' },
      ],
      GlobalSecondaryIndexes: [{
        IndexName: 'byG',
        KeySchema: [{ AttributeName: 'gpk', KeyType: 'HASH' }],
        Projection: { ProjectionType: 'KEYS_ONLY' },
      }],
    }));
    expect(created.TableDescription?.TableStatus).toBe('CREATING');

    await waitUntilTableExists({ client: ddb, maxWaitTime: 5, minDelay: 1 }, { TableName: TABLE });
    const { Table } = await ddb.send(new DescribeTableCommand({ TableName: TABLE }));
    expect(Table).toMatchObject({
      TableName: TABLE,
      TableStatus: 'ACTIVE',
      TableArn: `arn:aws:dynamodb:us-east-1:000000000000:table/${TABLE}`,
      KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }, { AttributeName: 'sk', KeyType: 'RANGE' }],
      BillingModeSummary: { BillingMode: 'PAY_PER_REQUEST' },
      ItemCount: 0,
      GlobalSecondaryIndexes: [expect.objectContaining({ IndexName: 'byG', IndexStatus: 'ACTIVE', Projection: { ProjectionType: 'KEYS_ONLY' } })],
    });
    expect(Table?.CreationDateTime).toBeInstanceOf(Date);
  });

  it('refuses to create a table that exists', async () => {
    await createTable();
    await expect(createTable()).rejects.toBeInstanceOf(ResourceInUseException);
  });

  it('refuses AttributeDefinitions that no key uses', async () => {
    const message = await validationMessage(createTable({
      AttributeDefinitions: [
        { AttributeName: 'pk', AttributeType: 'S' },
        { AttributeName: 'sk', AttributeType: 'S' },
        { AttributeName: 'extra', AttributeType: 'S' },
      ],
    }));
    expect(message).toContain('Number of attributes in KeySchema does not exactly match');
  });

  it('refuses a key attribute absent from AttributeDefinitions', async () => {
    const message = await validationMessage(createTable({ AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }] }));
    expect(message).toContain('Some index key attributes are not defined in AttributeDefinitions');
  });

  it('requires ProvisionedThroughput for PROVISIONED and refuses it for PAY_PER_REQUEST', async () => {
    expect(await validationMessage(createTable({ BillingMode: 'PROVISIONED' }))).toContain('ReadCapacityUnits');
    expect(await validationMessage(createTable({ ProvisionedThroughput: { ReadCapacityUnits: 1, WriteCapacityUnits: 1 } })))
      .toContain('PAY_PER_REQUEST');
    await createTable({ BillingMode: 'PROVISIONED', ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 } });
  });

  it('refuses local secondary indexes loudly', async () => {
    const message = await validationMessage(createTable({
      LocalSecondaryIndexes: [{
        IndexName: 'lsi',
        KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }, { AttributeName: 'sk', KeyType: 'RANGE' }],
        Projection: { ProjectionType: 'ALL' },
      }],
    }));
    expect(message).toContain('LocalSecondaryIndexes is not supported');
  });

  it('lists tables in name order, paging with Limit', async () => {
    for (const label of ['ccc', 'aaa', 'bbb']) await createHashTable(label);

    const first = await ddb.send(new ListTablesCommand({ Limit: 2 }));
    expect(first.TableNames).toEqual(['aaa', 'bbb']);
    expect(first.LastEvaluatedTableName).toBe('bbb');
    const second = await ddb.send(new ListTablesCommand({ Limit: 2, ExclusiveStartTableName: first.LastEvaluatedTableName }));
    expect(second.TableNames).toEqual(['ccc']);
    expect(second.LastEvaluatedTableName).toBeUndefined();
  });

  it('deletes a table', async () => {
    await createTable();
    const res = await ddb.send(new DeleteTableCommand({ TableName: TABLE }));
    expect(res.TableDescription?.TableStatus).toBe('DELETING');

    await expect(ddb.send(new DescribeTableCommand({ TableName: TABLE }))).rejects.toBeInstanceOf(ResourceNotFoundException);
    await expect(doc.send(new GetCommand({ TableName: TABLE, Key: { pk: 'a', sk: 'b' } }))).rejects.toBeInstanceOf(ResourceNotFoundException);
  });

  it('refuses to delete a table with deletion protection', async () => {
    await createTable({ DeletionProtectionEnabled: true });
    expect(await validationMessage(ddb.send(new DeleteTableCommand({ TableName: TABLE })))).toContain('protected against deletion');
  });

  it('records and describes time to live', async () => {
    await createTable();
    expect((await ddb.send(new DescribeTimeToLiveCommand({ TableName: TABLE }))).TimeToLiveDescription?.TimeToLiveStatus).toBe('DISABLED');

    await ddb.send(new UpdateTimeToLiveCommand({ TableName: TABLE, TimeToLiveSpecification: { Enabled: true, AttributeName: 'expiresAt' } }));
    expect((await ddb.send(new DescribeTimeToLiveCommand({ TableName: TABLE }))).TimeToLiveDescription)
      .toEqual({ TimeToLiveStatus: 'ENABLED', AttributeName: 'expiresAt' });

    expect(await validationMessage(ddb.send(new UpdateTimeToLiveCommand({
      TableName: TABLE, TimeToLiveSpecification: { Enabled: true, AttributeName: 'expiresAt' },
    })))).toContain('already enabled');
  });
});

// ---------------------------------------------------------------------------

describe('items', () => {
  beforeEach(createTable);

  it('stores and returns every attribute type', async () => {
    const item = {
      pk: 'p', sk: 's',
      str: 'hello', num: 42.5, big: 12345678901234567890n, bool: true, nul: null,
      bin: new Uint8Array([1, 2, 255]),
      letters: [1, 'two', { three: 3 }],
      info: { nested: { deep: ['x'] } },
      strings: new Set(['a', 'b']),
      numbers: new Set([1, 2]),
      empty: '',
      emptyList: [],
      emptyMap: {},
    };
    await doc.send(new PutCommand({ TableName: TABLE, Item: item }));

    const { Item } = await doc.send(new GetCommand({ TableName: TABLE, Key: { pk: 'p', sk: 's' } }));
    // The DocumentClient hands back a number beyond 2^53 as a BigInt, exactly.
    expect(Item).toEqual(item);
  });

  it('returns no Item for a absent key', async () => {
    const res = await doc.send(new GetCommand({ TableName: TABLE, Key: { pk: 'nope', sk: 'nope' }, ConsistentRead: true }));
    expect(res.Item).toBeUndefined();
  });

  it('stores numbers in DynamoDB canonical form, exactly', async () => {
    await ddb.send(new PutItemCommand({
      TableName: TABLE,
      Item: {
        pk: { S: 'n' }, sk: { S: 'n' },
        a: { N: '1.50' }, b: { N: '1E+2' }, c: { N: '-0.000' }, d: { N: '12345678901234567890123456789012345678' },
        e: { N: '0.1e-5' },
      },
    }));

    const { Item } = await ddb.send(new GetItemCommand({ TableName: TABLE, Key: { pk: { S: 'n' }, sk: { S: 'n' } } }));
    expect(Item).toMatchObject({
      a: { N: '1.5' }, b: { N: '100' }, c: { N: '0' }, d: { N: '12345678901234567890123456789012345678' }, e: { N: '0.000001' },
    });
  });

  it('refuses a number with more than 38 significant digits', async () => {
    const message = await validationMessage(ddb.send(new PutItemCommand({
      TableName: TABLE,
      Item: { pk: { S: 'n' }, sk: { S: 'n' }, a: { N: '123456789012345678901234567890123456789' } },
    })));
    expect(message).toContain('38 significant digits');
  });

  it('refuses an item with a absent key attribute', async () => {
    const message = await validationMessage(doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'p' } })));
    expect(message).toBe('One or more parameter values were invalid: Missing the key sk in the item');
  });

  it('refuses an item whose key has the wrong type', async () => {
    const message = await validationMessage(doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'p', sk: 5 } })));
    expect(message).toBe('One or more parameter values were invalid: Type mismatch for key sk expected: S actual: N');
  });

  it('refuses an empty string key', async () => {
    const message = await validationMessage(doc.send(new PutCommand({ TableName: TABLE, Item: { pk: '', sk: 's' } })));
    expect(message).toContain('cannot contain an empty string value');
  });

  it('refuses a Key that does not match the schema', async () => {
    expect(await validationMessage(doc.send(new GetCommand({ TableName: TABLE, Key: { pk: 'p' } }))))
      .toBe('The provided key element does not match the schema');
    expect(await validationMessage(doc.send(new GetCommand({ TableName: TABLE, Key: { pk: 'p', sk: 's', extra: 1 } }))))
      .toBe('The provided key element does not match the schema');
  });

  it('refuses an empty set', async () => {
    const message = await validationMessage(ddb.send(new PutItemCommand({
      TableName: TABLE, Item: { pk: { S: 'p' }, sk: { S: 's' }, tags: { SS: [] } },
    })));
    expect(message).toContain('may not be empty');
  });

  it('refuses a set with duplicates', async () => {
    const message = await validationMessage(ddb.send(new PutItemCommand({
      TableName: TABLE, Item: { pk: { S: 'p' }, sk: { S: 's' }, nums: { NS: ['1', '1.0'] } },
    })));
    expect(message).toContain('contains duplicates');
  });

  it('refuses an item over 400 KB', async () => {
    const message = await validationMessage(doc.send(new PutCommand({
      TableName: TABLE, Item: { pk: 'p', sk: 's', blob: 'x'.repeat(410 * 1024) },
    })));
    expect(message).toBe('Item size has exceeded the maximum allowed size');
  });

  it('projects nested paths and letters elements', async () => {
    await doc.send(new PutCommand({
      TableName: TABLE,
      Item: { pk: 'p', sk: 's', a: { b: 1, c: 2 }, letters: ['x', 'y', 'z'], alt: 'o' },
    }));

    const { Item } = await doc.send(new GetCommand({
      TableName: TABLE, Key: { pk: 'p', sk: 's' },
      ProjectionExpression: 'a.c, letters[2], letters[0], #o',
      ExpressionAttributeNames: { '#o': 'alt' },
    }));
    expect(Item).toEqual({ a: { c: 2 }, letters: ['x', 'z'], alt: 'o' });
  });

  it('replaces an item on Put and returns the old one with ReturnValues ALL_OLD', async () => {
    await doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'p', sk: 's', v: 1 } }));
    const res = await doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'p', sk: 's', w: 2 }, ReturnValues: 'ALL_OLD' }));

    expect(res.Attributes).toEqual({ pk: 'p', sk: 's', v: 1 });
    expect((await doc.send(new GetCommand({ TableName: TABLE, Key: { pk: 'p', sk: 's' } }))).Item).toEqual({ pk: 'p', sk: 's', w: 2 });
  });

  it('refuses a Put ReturnValues alt than NONE or ALL_OLD', async () => {
    expect(await validationMessage(doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'p', sk: 's' }, ReturnValues: 'ALL_NEW' }))))
      .toBe('ReturnValues can only be ALL_OLD or NONE');
  });

  it('fails a conditional Put with ConditionalCheckFailedException', async () => {
    const put = (): Promise<unknown> => doc.send(new PutCommand({
      TableName: TABLE, Item: { pk: 'p', sk: 's', v: 1 }, ConditionExpression: 'attribute_not_exists(pk)',
    }));
    await put();

    const err = await failure(put());
    expect(err).toBeInstanceOf(ConditionalCheckFailedException);
    expect(err.message).toBe('The conditional request failed');
  });

  it('returns the existing item on a failed condition with ReturnValuesOnConditionCheckFailure', async () => {
    await doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'p', sk: 's', v: 1 } }));

    const err = await failure(ddb.send(new PutItemCommand({
      TableName: TABLE,
      Item: { pk: { S: 'p' }, sk: { S: 's' } },
      ConditionExpression: 'attribute_not_exists(pk)',
      ReturnValuesOnConditionCheckFailure: 'ALL_OLD',
    })));
    expect(err).toBeInstanceOf(ConditionalCheckFailedException);
    expect((err as ConditionalCheckFailedException).Item).toEqual({ pk: { S: 'p' }, sk: { S: 's' }, v: { N: '1' } });
  });

  it('deletes an item, conditionally, returning the old item', async () => {
    await doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'p', sk: 's', v: 1 } }));

    await expect(doc.send(new DeleteCommand({
      TableName: TABLE, Key: { pk: 'p', sk: 's' }, ConditionExpression: 'v = :two', ExpressionAttributeValues: { ':two': 2 },
    }))).rejects.toBeInstanceOf(ConditionalCheckFailedException);

    const res = await doc.send(new DeleteCommand({ TableName: TABLE, Key: { pk: 'p', sk: 's' }, ReturnValues: 'ALL_OLD' }));
    expect(res.Attributes).toEqual({ pk: 'p', sk: 's', v: 1 });
    expect((await doc.send(new GetCommand({ TableName: TABLE, Key: { pk: 'p', sk: 's' } }))).Item).toBeUndefined();
  });

  it('accepts a delete of a absent item', async () => {
    const res = await doc.send(new DeleteCommand({ TableName: TABLE, Key: { pk: 'x', sk: 'y' }, ReturnValues: 'ALL_OLD' }));
    expect(res.Attributes).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------

describe('expression validation', () => {
  beforeEach(async () => {
    await createTable();
    await doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'p', sk: 's', status: 'open' } }));
  });

  const update = (input: Omit<ConstructorParameters<typeof UpdateCommand>[0], 'TableName' | 'Key'>): Promise<unknown> =>
    doc.send(new UpdateCommand({ TableName: TABLE, Key: { pk: 'p', sk: 's' }, ...input }));

  it('refuses a reserved word used as a bare attribute name', async () => {
    expect(await validationMessage(update({ UpdateExpression: 'SET status = :s', ExpressionAttributeValues: { ':s': 'x' } })))
      .toBe('Invalid UpdateExpression: Attribute name is a reserved keyword; reserved keyword: status');
    await update({ UpdateExpression: 'SET #s = :s', ExpressionAttributeNames: { '#s': 'status' }, ExpressionAttributeValues: { ':s': 'x' } });
  });

  it('refuses an undefined expression attribute value', async () => {
    expect(await validationMessage(update({ UpdateExpression: 'SET a = :absent', ExpressionAttributeValues: { ':alt': 1 } })))
      .toBe('Invalid UpdateExpression: An expression attribute value used in expression is not defined; attribute value: :absent');
  });

  it('refuses an undefined expression attribute name', async () => {
    expect(await validationMessage(update({ UpdateExpression: 'SET #a = :v', ExpressionAttributeValues: { ':v': 1 } })))
      .toContain('An expression attribute name used in the document path is not defined; attribute name: #a');
  });

  it('refuses unused expression attribute values and names', async () => {
    expect(await validationMessage(update({ UpdateExpression: 'SET a = :v', ExpressionAttributeValues: { ':v': 1, ':unused': 2 } })))
      .toBe('Value provided in ExpressionAttributeValues unused in expressions: keys: {:unused}');
    expect(await validationMessage(update({
      UpdateExpression: 'SET a = :v', ExpressionAttributeValues: { ':v': 1 }, ExpressionAttributeNames: { '#n': 'x' },
    }))).toBe('Value provided in ExpressionAttributeNames unused in expressions: keys: {#n}');
  });

  it('refuses expression attribute values without any expression', async () => {
    expect(await validationMessage(doc.send(new PutCommand({
      TableName: TABLE, Item: { pk: 'q', sk: 's' }, ExpressionAttributeValues: { ':v': 1 },
    })))).toBe('ExpressionAttributeValues can only be specified when using expressions');
  });

  it('refuses a syntax error, naming the token', async () => {
    expect(await validationMessage(update({ ConditionExpression: 'a = = :v', ExpressionAttributeValues: { ':v': 1 } })))
      .toMatch(/^Invalid ConditionExpression: Syntax error; token: "="/);
    expect(await validationMessage(update({ ConditionExpression: '_hidden = :v', ExpressionAttributeValues: { ':v': 1 } })))
      .toMatch(/Syntax error; token: "_"/);
  });

  it('refuses an unknown function', async () => {
    expect(await validationMessage(update({ ConditionExpression: 'starts_with(a, :v)', ExpressionAttributeValues: { ':v': 'x' } })))
      .toBe('Invalid ConditionExpression: Invalid function name; function: starts_with');
  });

  it('refuses function names in the wrong case, as DynamoDB does', async () => {
    expect(await validationMessage(update({ ConditionExpression: 'ATTRIBUTE_EXISTS(a)' })))
      .toContain('Invalid function name; function: ATTRIBUTE_EXISTS');
  });

  it('refuses an invalid attribute_type type', async () => {
    expect(await validationMessage(update({ ConditionExpression: 'attribute_type(a, :t)', ExpressionAttributeValues: { ':t': 'STRING' } })))
      .toContain('Invalid attribute type name found; type: STRING');
  });

  it('refuses BETWEEN with a lower bound above the upper bound', async () => {
    expect(await validationMessage(update({
      ConditionExpression: 'a BETWEEN :hi AND :lo', ExpressionAttributeValues: { ':hi': 5, ':lo': 1 },
    }))).toContain('The BETWEEN operator requires upper bound to be greater than or equal to lower bound');
  });

  it('refuses IN with more than 100 operands', async () => {
    const values = Object.fromEntries(Array.from({ length: 101 }, (_, i) => [`:v${i}`, i]));
    expect(await validationMessage(update({
      ConditionExpression: `a IN (${Object.keys(values).join(', ')})`, ExpressionAttributeValues: values,
    }))).toContain('The IN operator is provided with too many operands; number of operands: 101');
  });

  it('refuses an ordering comparison against a constant letters', async () => {
    expect(await validationMessage(update({ ConditionExpression: 'a < :l', ExpressionAttributeValues: { ':l': [1] } })))
      .toContain('Incorrect operand type for operator or function; operator or function: <, operand type: LIST');
  });

  it('refuses a function used as an operand', async () => {
    expect(await validationMessage(update({ ConditionExpression: 'begins_with(a, :v) = :t', ExpressionAttributeValues: { ':v': 'x', ':t': true } })))
      .toContain('The function is not allowed to be used this way in an expression; function: begins_with');
  });
});

// ---------------------------------------------------------------------------

describe('condition expressions', () => {
  const ITEM = {
    pk: 'p', sk: 's',
    n: 10, s: 'banana', b: new Uint8Array([1, 2, 3]),
    flag: true, nothing: null,
    tags: new Set(['red', 'green']), nums: new Set([1, 5]),
    letters: ['a', 'b', 3],
    info: { nested: { deep: 'x' }, arr: [{ v: 1 }, { v: 2 }] },
    'dotted.name': 'yes',
    unicode: '\u{1F600}', // above U+FFFF: sorts after U+FFFD by UTF-8 bytes
  };

  beforeEach(async () => {
    await createTable();
    await doc.send(new PutCommand({ TableName: TABLE, Item: ITEM }));
  });

  async function holds(expression: string, values?: Record<string, unknown>, names?: Record<string, string>): Promise<boolean> {
    try {
      await doc.send(new UpdateCommand({
        TableName: TABLE,
        Key: { pk: 'p', sk: 's' },
        ConditionExpression: expression,
        ExpressionAttributeValues: values,
        ExpressionAttributeNames: names,
      }));
      return true;
    } catch (err) {
      if (err instanceof ConditionalCheckFailedException) return false;
      throw err;
    }
  }

  it('compares numbers numerically, not as strings', async () => {
    expect(await holds('n > :nine', { ':nine': 9 })).toBe(true);
    expect(await holds('n < :hundred', { ':hundred': 100 })).toBe(true);
    expect(await holds('n = :ten', { ':ten': 10.0 })).toBe(true);
    expect(await holds('n >= :ten AND n <= :ten', { ':ten': 10 })).toBe(true);
  });

  it('compares strings by UTF-8 bytes', async () => {
    expect(await holds('s > :apple', { ':apple': 'apple' })).toBe(true);
    expect(await holds('s < :lower', { ':lower': 'banana_' })).toBe(true);
    expect(await holds('unicode > :bmp', { ':bmp': '�' })).toBe(true);
  });

  it('treats <> on a absent attribute as true and ordering on one as false', async () => {
    expect(await holds('absent <> :v', { ':v': 1 })).toBe(true);
    expect(await holds('absent < :v', { ':v': 1 })).toBe(false);
    expect(await holds('absent = :v', { ':v': 1 })).toBe(false);
  });

  it('never orders values of different types', async () => {
    expect(await holds('s > :n', { ':n': 1 })).toBe(false);
    expect(await holds('s <> :n', { ':n': 1 })).toBe(true);
  });

  it('supports BETWEEN and IN', async () => {
    expect(await holds('n BETWEEN :lo AND :hi', { ':lo': 10, ':hi': 20 })).toBe(true);
    expect(await holds('n BETWEEN :lo AND :hi', { ':lo': 11, ':hi': 20 })).toBe(false);
    expect(await holds('s IN (:a, :b)', { ':a': 'apple', ':b': 'banana' })).toBe(true);
    expect(await holds('s IN (:a)', { ':a': 'apple' })).toBe(false);
  });

  it('applies AND before OR, NOT before AND, and parentheses first', async () => {
    const values = { ':yes': 10, ':no': 11 };
    // true OR (true AND false) = true
    expect(await holds('n = :yes OR n = :yes AND n = :no', values)).toBe(true);
    // (true OR true) AND false = false
    expect(await holds('(n = :yes OR n = :yes) AND n = :no', values)).toBe(false);
    // (NOT false) AND true = true
    expect(await holds('NOT n = :no AND n = :yes', values)).toBe(true);
    expect(await holds('not (n = :yes)', { ':yes': 10 })).toBe(false);
  });

  it('checks existence and type', async () => {
    expect(await holds('attribute_exists(n) AND attribute_not_exists(absent)')).toBe(true);
    expect(await holds('attribute_exists(nothing)')).toBe(true);
    expect(await holds('attribute_type(tags, :ss) AND attribute_type(nothing, :null)', { ':ss': 'SS', ':null': 'NULL' })).toBe(true);
    expect(await holds('attribute_type(n, :s)', { ':s': 'S' })).toBe(false);
  });

  it('supports begins_with on strings and binary', async () => {
    expect(await holds('begins_with(s, :p)', { ':p': 'ban' })).toBe(true);
    expect(await holds('begins_with(s, :p)', { ':p': 'nan' })).toBe(false);
    expect(await holds('begins_with(b, :p)', { ':p': new Uint8Array([1, 2]) })).toBe(true);
  });

  it('supports contains on strings, sets and lists', async () => {
    expect(await holds('contains(s, :sub)', { ':sub': 'nan' })).toBe(true);
    expect(await holds('contains(tags, :red)', { ':red': 'red' })).toBe(true);
    expect(await holds('contains(tags, :blue)', { ':blue': 'blue' })).toBe(false);
    expect(await holds('contains(nums, :five)', { ':five': 5 })).toBe(true);
    expect(await holds('contains(letters, :three)', { ':three': 3 })).toBe(true);
  });

  it('supports size on strings, sets, lists and maps', async () => {
    expect(await holds('size(s) = :six', { ':six': 6 })).toBe(true);
    expect(await holds('size(tags) = :two AND size(letters) = :three AND size(info) = :two', { ':two': 2, ':three': 3 })).toBe(true);
    expect(await holds('size(b) = :three', { ':three': 3 })).toBe(true);
  });

  it('follows nested document paths with dots and indexes', async () => {
    expect(await holds('info.nested.deep = :x', { ':x': 'x' })).toBe(true);
    expect(await holds('info.arr[1].v = :two', { ':two': 2 })).toBe(true);
    expect(await holds('letters[0] = :a', { ':a': 'a' })).toBe(true);
    expect(await holds('attribute_not_exists(letters[9])')).toBe(true);
  });

  it('treats a dotted label behind a placeholder as one attribute', async () => {
    expect(await holds('#d = :y', { ':y': 'yes' }, { '#d': 'dotted.name' })).toBe(true);
  });

  it('compares a boolean with = only', async () => {
    expect(await holds('flag = :t', { ':t': true })).toBe(true);
  });

  it('evaluates against an empty item when the item is absent', async () => {
    await expect(doc.send(new UpdateCommand({
      TableName: TABLE, Key: { pk: 'new', sk: 'new' }, ConditionExpression: 'attribute_exists(pk)',
    }))).rejects.toBeInstanceOf(ConditionalCheckFailedException);
  });

  it('accepts keywords in any case', async () => {
    expect(await holds('n between :lo and :hi Or s in (:a)', { ':lo': 1, ':hi': 20, ':a': 'x' })).toBe(true);
  });
});

// ---------------------------------------------------------------------------

describe('update expressions', () => {
  beforeEach(async () => {
    await createTable();
    await doc.send(new PutCommand({
      TableName: TABLE,
      Item: { pk: 'p', sk: 's', tally: 1, label: 'x', letters: [1, 2, 3], info: { a: 1 }, tags: new Set(['a', 'b']) },
    }));
  });

  async function update(expression: string, values?: Record<string, unknown>, extra: Record<string, unknown> = {}): Promise<Record<string, unknown> | undefined> {
    const res = await doc.send(new UpdateCommand({
      TableName: TABLE,
      Key: { pk: 'p', sk: 's' },
      UpdateExpression: expression,
      ExpressionAttributeValues: values,
      ReturnValues: 'ALL_NEW',
      ...extra,
    }));
    return res.Attributes;
  }

  it('SETs top-level and nested attributes', async () => {
    const item = await update('SET a = :a, info.b = :b, #l[0] = :z', { ':a': 'A', ':b': 2, ':z': 0 }, { ExpressionAttributeNames: { '#l': 'letters' } });
    expect(item).toMatchObject({ a: 'A', info: { a: 1, b: 2 }, letters: [0, 2, 3] });
  });

  it('appends when SET names a letters index past the end', async () => {
    expect((await update('SET letters[10] = :v', { ':v': 4 }))?.['letters']).toEqual([1, 2, 3, 4]);
  });

  it('adds and subtracts with + and -, exactly', async () => {
    await doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'p', sk: 's', f: 0.1, tally: 1 } }));
    const item = await update('SET f = f + :f, tally = tally - :one', { ':f': 0.2, ':one': 1 });
    expect(item).toMatchObject({ f: 0.3, tally: 0 });
  });

  it('reads every operand from the item as it was before the update', async () => {
    const item = await update('SET a = tally, tally = :ten', { ':ten': 10 });
    expect(item).toMatchObject({ a: 1, tally: 10 });
  });

  it('supports if_not_exists', async () => {
    const item = await update('SET tally = if_not_exists(tally, :zero) + :one, fresh = if_not_exists(fresh, :zero)', { ':zero': 0, ':one': 1 });
    expect(item).toMatchObject({ tally: 2, fresh: 0 });
  });

  it('supports list_append, including around if_not_exists', async () => {
    const item = await update('SET letters = list_append(letters, :tail), alt = list_append(if_not_exists(alt, :empty), :tail), front = list_append(:head, letters)', {
      ':tail': [9], ':empty': [], ':head': [0],
    });
    expect(item).toMatchObject({ letters: [1, 2, 3, 9], alt: [9], front: [0, 1, 2, 3] });
  });

  it('REMOVEs attributes, nested attributes and letters elements', async () => {
    const item = await update('REMOVE #n, info.a, letters[0], letters[2]', undefined, { ExpressionAttributeNames: { '#n': 'label' } });
    expect(item).toEqual({ pk: 'p', sk: 's', tally: 1, letters: [2], info: {}, tags: new Set(['a', 'b']) });
  });

  it('ADDs to numbers and sets, creating them when absent', async () => {
    const item = await update('ADD #c :five, newCount :five, tags :more, nums :ns', {
      ':five': 5, ':more': new Set(['b', 'c']), ':ns': new Set([1]),
    }, { ExpressionAttributeNames: { '#c': 'tally' } });
    expect(item).toMatchObject({ tally: 6, newCount: 5, tags: new Set(['a', 'b', 'c']), nums: new Set([1]) });
  });

  it('DELETEs from a set and removes the attribute when the set empties', async () => {
    expect((await update('DELETE tags :a', { ':a': new Set(['a']) }))?.['tags']).toEqual(new Set(['b']));
    expect((await update('DELETE tags :b', { ':b': new Set(['b']) }))?.['tags']).toBeUndefined();
  });

  it('combines SET, REMOVE, ADD and DELETE in one expression', async () => {
    const item = await update('SET a = :a REMOVE info ADD #c :one DELETE tags :t', { ':a': 1, ':one': 1, ':t': new Set(['a']) }, {
      ExpressionAttributeNames: { '#c': 'tally' },
    });
    expect(item).toMatchObject({ a: 1, tally: 2, tags: new Set(['b']) });
    expect(item?.['info']).toBeUndefined();
  });

  it('creates the item when it does not exist', async () => {
    const res = await doc.send(new UpdateCommand({
      TableName: TABLE, Key: { pk: 'new', sk: 'one' }, UpdateExpression: 'SET v = :v', ExpressionAttributeValues: { ':v': 1 }, ReturnValues: 'ALL_NEW',
    }));
    expect(res.Attributes).toEqual({ pk: 'new', sk: 'one', v: 1 });
  });

  it('returns ALL_OLD, UPDATED_OLD and UPDATED_NEW', async () => {
    const base = { TableName: TABLE, Key: { pk: 'p', sk: 's' }, UpdateExpression: 'SET info.a = :v, z = :v', ExpressionAttributeValues: { ':v': 7 } };
    expect((await doc.send(new UpdateCommand({ ...base, ReturnValues: 'UPDATED_OLD' }))).Attributes).toEqual({ info: { a: 1 } });
    expect((await doc.send(new UpdateCommand({ ...base, ExpressionAttributeValues: { ':v': 8 }, ReturnValues: 'UPDATED_NEW' }))).Attributes)
      .toEqual({ info: { a: 8 }, z: 8 });
    expect((await doc.send(new UpdateCommand({ ...base, ReturnValues: 'ALL_OLD' }))).Attributes).toMatchObject({ tally: 1, z: 8 });
    expect((await doc.send(new UpdateCommand({ ...base, ReturnValues: 'NONE' }))).Attributes).toBeUndefined();
  });

  it('refuses an update of a key attribute', async () => {
    expect(await validationMessage(update('SET sk = :v', { ':v': 'x' })))
      .toBe('One or more parameter values were invalid: Cannot update attribute sk. This attribute is part of the key');
  });

  it('refuses overlapping paths', async () => {
    expect(await validationMessage(update('SET info = :m, info.a = :v', { ':m': {}, ':v': 1 })))
      .toBe('Invalid UpdateExpression: Two document paths overlap with each other; must remove or rewrite one of these paths; path one: [info], path two: [info, a]');
  });

  it('refuses a SET section used twice', async () => {
    expect(await validationMessage(update('SET a = :v SET b = :v', { ':v': 1 })))
      .toContain('The "SET" section can only be used once in an update expression');
  });

  it('refuses arithmetic on a absent attribute', async () => {
    expect(await validationMessage(update('SET a = absent + :v', { ':v': 1 })))
      .toBe('Invalid UpdateExpression: The provided expression refers to an attribute that does not exist in the item');
  });

  it('refuses ADD of a string', async () => {
    expect(await validationMessage(update('ADD a :s', { ':s': 'x' })))
      .toBe('Invalid UpdateExpression: Incorrect operand type for operator or function; operator: ADD, operand type: STRING');
  });

  it('refuses ADD of a number to a string attribute', async () => {
    expect(await validationMessage(update('ADD #n :one', { ':one': 1 }, { ExpressionAttributeNames: { '#n': 'label' } })))
      .toBe('Invalid UpdateExpression: An operand in the update expression has an incorrect data type');
  });

  it('refuses a nested SET under a absent parent', async () => {
    expect(await validationMessage(update('SET nope.child = :v', { ':v': 1 })))
      .toBe('Invalid UpdateExpression: The document path provided in the update expression is invalid for update');
  });

  it('leaves the item unchanged when the condition fails', async () => {
    await expect(update('SET tally = :v', { ':v': 99, ':c': 5 }, { ConditionExpression: '#c = :c', ExpressionAttributeNames: { '#c': 'tally' } }))
      .rejects.toBeInstanceOf(ConditionalCheckFailedException);
    expect((await doc.send(new GetCommand({ TableName: TABLE, Key: { pk: 'p', sk: 's' } }))).Item?.['tally']).toBe(1);
  });

  it('refuses the legacy AttributeUpdates parameter loudly', async () => {
    expect(await validationMessage(ddb.send(new LowLevelUpdateItemCommand({
      TableName: TABLE, Key: { pk: { S: 'p' }, sk: { S: 's' } }, AttributeUpdates: { a: { Action: 'PUT', Value: { S: 'x' } } },
    })))).toContain('legacy parameter AttributeUpdates');
  });
});

// ---------------------------------------------------------------------------

describe('query', () => {
  beforeEach(async () => {
    await ddb.send(new CreateTableCommand({
      TableName: TABLE,
      BillingMode: 'PAY_PER_REQUEST',
      KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }, { AttributeName: 'sk', KeyType: 'RANGE' }],
      AttributeDefinitions: [
        { AttributeName: 'pk', AttributeType: 'S' },
        { AttributeName: 'sk', AttributeType: 'S' },
        { AttributeName: 'gpk', AttributeType: 'S' },
        { AttributeName: 'gsk', AttributeType: 'N' },
      ],
      GlobalSecondaryIndexes: [
        { IndexName: 'all', KeySchema: [{ AttributeName: 'gpk', KeyType: 'HASH' }, { AttributeName: 'gsk', KeyType: 'RANGE' }], Projection: { ProjectionType: 'ALL' } },
        { IndexName: 'keys', KeySchema: [{ AttributeName: 'gpk', KeyType: 'HASH' }], Projection: { ProjectionType: 'KEYS_ONLY' } },
        {
          IndexName: 'include',
          KeySchema: [{ AttributeName: 'gpk', KeyType: 'HASH' }, { AttributeName: 'gsk', KeyType: 'RANGE' }],
          Projection: { ProjectionType: 'INCLUDE', NonKeyAttributes: ['kept'] },
        },
      ],
    }));
    const items = [
      { pk: 'a', sk: '001', gpk: 'g', gsk: 10, kept: 1, dropped: 1 },
      { pk: 'a', sk: '002', gpk: 'g', gsk: 9, kept: 2, dropped: 2 },
      { pk: 'a', sk: '003', gpk: 'g', gsk: 100, kept: 3, dropped: 3 },
      { pk: 'a', sk: 'b01', kept: 4 }, // not in any index: sparse
      { pk: 'a', sk: 'b02', gpk: 'h', gsk: 1, kept: 5 },
      { pk: 'b', sk: '001', gpk: 'g', gsk: 10, kept: 6 },
    ];
    for (const Item of items) await doc.send(new PutCommand({ TableName: TABLE, Item }));
  });

  const q = (input: Omit<QueryCommandInput, 'TableName'>): Promise<QueryCommandOutput> =>
    doc.send(new QueryCommand({ TableName: TABLE, ...input }));

  it('returns a partition in sort key order, forwards and backwards', async () => {
    const forward = await q({ KeyConditionExpression: 'pk = :a', ExpressionAttributeValues: { ':a': 'a' } });
    expect(forward.Items?.map((i) => i['sk'])).toEqual(['001', '002', '003', 'b01', 'b02']);
    expect(forward.Count).toBe(5);

    const backward = await q({ KeyConditionExpression: 'pk = :a', ExpressionAttributeValues: { ':a': 'a' }, ScanIndexForward: false });
    expect(backward.Items?.map((i) => i['sk'])).toEqual(['b02', 'b01', '003', '002', '001']);
  });

  it.each([
    ['sk = :x', { ':x': '002' }, ['002']],
    ['sk < :x', { ':x': '002' }, ['001']],
    ['sk <= :x', { ':x': '002' }, ['001', '002']],
    ['sk > :x', { ':x': '003' }, ['b01', 'b02']],
    ['sk >= :x', { ':x': '003' }, ['003', 'b01', 'b02']],
    ['sk BETWEEN :x AND :y', { ':x': '002', ':y': 'b01' }, ['002', '003', 'b01']],
    ['begins_with(sk, :x)', { ':x': 'b' }, ['b01', 'b02']],
  ])('applies the sort key condition %s', async (condition, values, expected) => {
    const res = await q({ KeyConditionExpression: `pk = :a AND ${condition}`, ExpressionAttributeValues: { ':a': 'a', ...values } });
    expect(res.Items?.map((i) => i['sk'])).toEqual(expected);
  });

  it('accepts the key conditions in either order and in parentheses', async () => {
    const res = await q({ KeyConditionExpression: '(begins_with(sk, :b)) AND (#p = :a)', ExpressionAttributeNames: { '#p': 'pk' }, ExpressionAttributeValues: { ':a': 'a', ':b': 'b' } });
    expect(res.Items).toHaveLength(2);
  });

  it('applies a FilterExpression after reading, counting both', async () => {
    const res = await q({ KeyConditionExpression: 'pk = :a', FilterExpression: 'kept > :two', ExpressionAttributeValues: { ':a': 'a', ':two': 2 } });
    expect(res.Items?.map((i) => i['kept'])).toEqual([3, 4, 5]);
    expect(res.Count).toBe(3);
    expect(res.ScannedCount).toBe(5);
  });

  it('refuses a FilterExpression on a key attribute', async () => {
    expect(await validationMessage(q({ KeyConditionExpression: 'pk = :a', FilterExpression: 'sk > :x', ExpressionAttributeValues: { ':a': 'a', ':x': '1' } })))
      .toBe('Filter Expression can only contain non-primary key attributes: Primary key attribute: sk');
  });

  it('pages with Limit and LastEvaluatedKey, with Limit counting items read before the filter', async () => {
    const page1 = await q({ KeyConditionExpression: 'pk = :a', FilterExpression: 'kept <> :two', ExpressionAttributeValues: { ':a': 'a', ':two': 2 }, Limit: 2 });
    expect(page1.Items?.map((i) => i['sk'])).toEqual(['001']);
    expect(page1.ScannedCount).toBe(2);
    expect(page1.LastEvaluatedKey).toEqual({ pk: 'a', sk: '002' });

    const page2 = await q({
      KeyConditionExpression: 'pk = :a', FilterExpression: 'kept <> :two', ExpressionAttributeValues: { ':a': 'a', ':two': 2 },
      Limit: 2, ExclusiveStartKey: page1.LastEvaluatedKey,
    });
    expect(page2.Items?.map((i) => i['sk'])).toEqual(['003', 'b01']);
  });

  it('returns a LastEvaluatedKey when Limit lands on the last item, then an empty page', async () => {
    const page1 = await q({ KeyConditionExpression: 'pk = :b', ExpressionAttributeValues: { ':b': 'b' }, Limit: 1 });
    expect(page1.LastEvaluatedKey).toEqual({ pk: 'b', sk: '001' });

    const page2 = await q({ KeyConditionExpression: 'pk = :b', ExpressionAttributeValues: { ':b': 'b' }, Limit: 1, ExclusiveStartKey: page1.LastEvaluatedKey });
    expect(page2.Items).toEqual([]);
    expect(page2.LastEvaluatedKey).toBeUndefined();
  });

  it('pages backwards too', async () => {
    const page1 = await q({ KeyConditionExpression: 'pk = :a', ExpressionAttributeValues: { ':a': 'a' }, ScanIndexForward: false, Limit: 2 });
    const page2 = await q({
      KeyConditionExpression: 'pk = :a', ExpressionAttributeValues: { ':a': 'a' }, ScanIndexForward: false, Limit: 2,
      ExclusiveStartKey: page1.LastEvaluatedKey,
    });
    expect([...page1.Items!, ...page2.Items!].map((i) => i['sk'])).toEqual(['b02', 'b01', '003', '002']);
  });

  it('works with the SDK paginator', async () => {
    const seen: string[] = [];
    for await (const page of paginateQuery({ client: doc, pageSize: 2 }, { TableName: TABLE, KeyConditionExpression: 'pk = :a', ExpressionAttributeValues: { ':a': 'a' } })) {
      seen.push(...(page.Items ?? []).map((i) => i['sk'] as string));
    }
    expect(seen).toEqual(['001', '002', '003', 'b01', 'b02']);
  });

  it('counts with Select COUNT', async () => {
    const res = await q({ KeyConditionExpression: 'pk = :a', ExpressionAttributeValues: { ':a': 'a' }, Select: 'COUNT' });
    expect(res.Count).toBe(5);
    expect(res.Items).toBeUndefined();
  });

  it('projects with ProjectionExpression', async () => {
    const res = await q({ KeyConditionExpression: 'pk = :b', ProjectionExpression: 'kept', ExpressionAttributeValues: { ':b': 'b' } });
    expect(res.Items).toEqual([{ kept: 6 }]);
  });

  it('refuses a key condition without the partition key', async () => {
    expect(await validationMessage(q({ KeyConditionExpression: 'sk = :x', ExpressionAttributeValues: { ':x': '1' } })))
      .toBe('Query condition missed key schema element: pk');
  });

  it('refuses a key condition on a non-key attribute', async () => {
    expect(await validationMessage(q({ KeyConditionExpression: 'pk = :a AND kept = :k', ExpressionAttributeValues: { ':a': 'a', ':k': 1 } })))
      .toContain('Query condition missed key schema element');
  });

  it('refuses OR and <> in a key condition', async () => {
    await validationMessage(q({ KeyConditionExpression: 'pk = :a OR pk = :b', ExpressionAttributeValues: { ':a': 'a', ':b': 'b' } }));
    await validationMessage(q({ KeyConditionExpression: 'pk = :a AND sk <> :x', ExpressionAttributeValues: { ':a': 'a', ':x': '1' } }));
  });

  it('refuses a key condition value of the wrong type', async () => {
    expect(await validationMessage(q({ KeyConditionExpression: 'pk = :a', ExpressionAttributeValues: { ':a': 1 } })))
      .toBe('One or more parameter values were invalid: Condition parameter type does not match schema type');
  });

  it('refuses a Query without a KeyConditionExpression', async () => {
    await validationMessage(ddb.send(new LowLevelQueryCommand({ TableName: TABLE })));
  });

  describe('on a global secondary index', () => {
    it('orders numerically by the index sort key and leaves out items without the index key', async () => {
      const res = await q({ IndexName: 'all', KeyConditionExpression: 'gpk = :g', ExpressionAttributeValues: { ':g': 'g' } });
      expect(res.Items?.map((i) => i['gsk'])).toEqual([9, 10, 10, 100]);
      expect(res.Items?.[0]).toEqual({ pk: 'a', sk: '002', gpk: 'g', gsk: 9, kept: 2, dropped: 2 });
    });

    it('returns only keys from a KEYS_ONLY index', async () => {
      const res = await q({ IndexName: 'keys', KeyConditionExpression: 'gpk = :h', ExpressionAttributeValues: { ':h': 'h' } });
      expect(res.Items).toEqual([{ pk: 'a', sk: 'b02', gpk: 'h' }]);
    });

    it('returns keys and the included attributes from an INCLUDE index', async () => {
      const res = await q({ IndexName: 'include', KeyConditionExpression: 'gpk = :g AND gsk < :ten', ExpressionAttributeValues: { ':g': 'g', ':ten': 10 } });
      expect(res.Items).toEqual([{ pk: 'a', sk: '002', gpk: 'g', gsk: 9, kept: 2 }]);
    });

    it('returns a LastEvaluatedKey with the table and index keys, and continues from it', async () => {
      const page1 = await q({ IndexName: 'all', KeyConditionExpression: 'gpk = :g', ExpressionAttributeValues: { ':g': 'g' }, Limit: 2 });
      expect(page1.LastEvaluatedKey).toEqual({ gpk: 'g', gsk: 10, pk: 'a', sk: '001' });

      const page2 = await q({ IndexName: 'all', KeyConditionExpression: 'gpk = :g', ExpressionAttributeValues: { ':g': 'g' }, ExclusiveStartKey: page1.LastEvaluatedKey });
      expect(page2.Items?.map((i) => [i['pk'], i['gsk']])).toEqual([['b', 10], ['a', 100]]);
    });

    it('refuses an ExclusiveStartKey without the index keys', async () => {
      expect(await validationMessage(q({
        IndexName: 'all', KeyConditionExpression: 'gpk = :g', ExpressionAttributeValues: { ':g': 'g' }, ExclusiveStartKey: { pk: 'a', sk: '001' },
      }))).toContain('The provided starting key is invalid');
    });

    it('refuses a consistent read', async () => {
      expect(await validationMessage(q({ IndexName: 'all', KeyConditionExpression: 'gpk = :g', ExpressionAttributeValues: { ':g': 'g' }, ConsistentRead: true })))
        .toBe('Consistent reads are not supported on global secondary indexes');
    });

    it('refuses Select ALL_ATTRIBUTES on an index that does not project them', async () => {
      expect(await validationMessage(q({ IndexName: 'keys', KeyConditionExpression: 'gpk = :g', ExpressionAttributeValues: { ':g': 'g' }, Select: 'ALL_ATTRIBUTES' })))
        .toContain('Select type ALL_ATTRIBUTES is not supported for global secondary index keys');
    });

    it('refuses an unknown index', async () => {
      expect(await validationMessage(q({ IndexName: 'nope', KeyConditionExpression: 'gpk = :g', ExpressionAttributeValues: { ':g': 'g' } })))
        .toBe('The table does not have the specified index: nope');
    });

    it('refuses an item whose index key has the wrong type', async () => {
      expect(await validationMessage(doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'z', sk: 'z', gsk: 'not a number' } }))))
        .toContain('Type mismatch for Index Key gsk Expected: N Actual: S');
    });

    it('keeps the index in step with updates and deletes', async () => {
      await doc.send(new UpdateCommand({ TableName: TABLE, Key: { pk: 'a', sk: 'b01' }, UpdateExpression: 'SET gpk = :h, gsk = :n', ExpressionAttributeValues: { ':h': 'h', ':n': 0 } }));
      await doc.send(new DeleteCommand({ TableName: TABLE, Key: { pk: 'a', sk: 'b02' } }));

      const res = await q({ IndexName: 'all', KeyConditionExpression: 'gpk = :h', ExpressionAttributeValues: { ':h': 'h' } });
      expect(res.Items?.map((i) => i['sk'])).toEqual(['b01']);
    });
  });
});

// ---------------------------------------------------------------------------

describe('scan', () => {
  beforeEach(async () => {
    await createHashTable();
    for (let i = 0; i < 20; i++) {
      await doc.send(new PutCommand({ TableName: TABLE, Item: { id: `item-${String(i).padStart(2, '0')}`, n: i } }));
    }
  });

  const scan = (input: Omit<ScanCommandInput, 'TableName'> = {}): Promise<ScanCommandOutput> =>
    doc.send(new ScanCommand({ TableName: TABLE, ...input }));

  it('returns every item', async () => {
    const res = await scan();
    expect(res.Count).toBe(20);
    expect(res.LastEvaluatedKey).toBeUndefined();
  });

  it('filters', async () => {
    const res = await scan({ FilterExpression: 'n >= :ten', ExpressionAttributeValues: { ':ten': 10 } });
    expect(res.Count).toBe(10);
    expect(res.ScannedCount).toBe(20);
  });

  it('pages through every item exactly once', async () => {
    const seen: string[] = [];
    let startKey: Record<string, unknown> | undefined;
    do {
      const page = await scan({ Limit: 7, ExclusiveStartKey: startKey });
      seen.push(...page.Items!.map((i) => i['id'] as string));
      startKey = page.LastEvaluatedKey;
    } while (startKey);
    expect(seen.sort()).toEqual(Array.from({ length: 20 }, (_, i) => `item-${String(i).padStart(2, '0')}`));
  });

  it('splits into parallel segments that cover the table without overlap', async () => {
    const segments = await Promise.all([0, 1, 2].map((Segment) => scan({ Segment, TotalSegments: 3 })));
    const ids = segments.flatMap((s) => s.Items!.map((i) => i['id'] as string));
    expect(ids).toHaveLength(20);
    expect(new Set(ids).size).toBe(20);
  });

  it('stops a page at 1 MB of items read, with a LastEvaluatedKey', async () => {
    for (let i = 0; i < 3; i++) {
      await doc.send(new PutCommand({ TableName: TABLE, Item: { id: `big-${i}`, blob: 'x'.repeat(390 * 1024) } }));
    }

    const page = await scan({ ProjectionExpression: 'id' });
    expect(page.Items?.map((i) => i['id'])).toEqual(['big-0', 'big-1', 'big-2']);
    expect(page.LastEvaluatedKey).toEqual({ id: 'big-2' });
    expect((await scan({ ExclusiveStartKey: page.LastEvaluatedKey })).Count).toBe(20);
  });

  it('refuses a Segment without TotalSegments', async () => {
    await validationMessage(scan({ Segment: 0 }));
  });

  it('projects and counts', async () => {
    expect((await scan({ ProjectionExpression: 'n', Limit: 1 })).Items).toEqual([{ n: 0 }]);
    expect((await scan({ Select: 'COUNT' })).Count).toBe(20);
  });
});

// ---------------------------------------------------------------------------

describe('batches', () => {
  beforeEach(async () => {
    await createHashTable('one');
    await createHashTable('two');
  });

  it('writes and deletes in a batch across tables', async () => {
    await doc.send(new PutCommand({ TableName: 'one', Item: { id: 'old' } }));
    const res = await doc.send(new BatchWriteCommand({
      RequestItems: {
        one: [{ PutRequest: { Item: { id: 'a' } } }, { DeleteRequest: { Key: { id: 'old' } } }],
        two: [{ PutRequest: { Item: { id: 'b', v: 1 } } }],
      },
    }));
    expect(res.UnprocessedItems).toEqual({});
    expect(running.simulator.dumpTable('one')).toEqual([{ id: { S: 'a' } }]);
    expect(running.simulator.dumpTable('two')).toEqual([{ id: { S: 'b' }, v: { N: '1' } }]);
  });

  it('refuses more than 25 requests', async () => {
    const requests = Array.from({ length: 26 }, (_, i) => ({ PutRequest: { Item: { id: `i${i}` } } }));
    expect(await validationMessage(doc.send(new BatchWriteCommand({ RequestItems: { one: requests } })))).toContain('less than or equal to 25');
    expect(running.simulator.dumpTable('one')).toEqual([]);
  });

  it('refuses the same key twice in one batch write', async () => {
    expect(await validationMessage(doc.send(new BatchWriteCommand({
      RequestItems: { one: [{ PutRequest: { Item: { id: 'a' } } }, { DeleteRequest: { Key: { id: 'a' } } }] },
    })))).toBe('Provided list of item keys contains duplicates');
  });

  it('writes nothing when one request in the batch is invalid', async () => {
    await validationMessage(doc.send(new BatchWriteCommand({
      RequestItems: { one: [{ PutRequest: { Item: { id: 'a' } } }, { PutRequest: { Item: { nope: 'b' } } }] },
    })));
    expect(running.simulator.dumpTable('one')).toEqual([]);
  });

  it('gets items from several tables, leaving out absent keys', async () => {
    await doc.send(new PutCommand({ TableName: 'one', Item: { id: 'a', v: 1 } }));
    await doc.send(new PutCommand({ TableName: 'two', Item: { id: 'b', v: 2 } }));

    const res = await doc.send(new BatchGetCommand({
      RequestItems: {
        one: { Keys: [{ id: 'a' }, { id: 'absent' }], ProjectionExpression: 'v' },
        two: { Keys: [{ id: 'b' }] },
      },
    }));
    expect(res.Responses).toEqual({ one: [{ v: 1 }], two: [{ id: 'b', v: 2 }] });
    expect(res.UnprocessedKeys).toEqual({});
  });

  it('refuses more than 100 keys in a batch get', async () => {
    const keys = Array.from({ length: 101 }, (_, i) => ({ id: `k${i}` }));
    expect(await validationMessage(doc.send(new BatchGetCommand({ RequestItems: { one: { Keys: keys } } }))))
      .toBe('Too many items requested for the BatchGetItem call');
  });

  it('answers a batch against a absent table with ResourceNotFoundException', async () => {
    await expect(doc.send(new BatchGetCommand({ RequestItems: { ghost: { Keys: [{ id: 'a' }] } } })))
      .rejects.toBeInstanceOf(ResourceNotFoundException);
  });
});

// ---------------------------------------------------------------------------

describe('transactions', () => {
  beforeEach(async () => {
    await createHashTable();
    await doc.send(new PutCommand({ TableName: TABLE, Item: { id: 'acct-1', balance: 100 } }));
    await doc.send(new PutCommand({ TableName: TABLE, Item: { id: 'acct-2', balance: 0 } }));
    await doc.send(new PutCommand({ TableName: TABLE, Item: { id: 'bank', open: true } }));
  });

  const transfer = (amount: number, token?: string): Promise<unknown> => doc.send(new TransactWriteCommand({
    ClientRequestToken: token,
    TransactItems: [
      {
        Update: {
          TableName: TABLE, Key: { id: 'acct-1' },
          UpdateExpression: 'SET balance = balance - :a', ConditionExpression: 'balance >= :a',
          ExpressionAttributeValues: { ':a': amount },
        },
      },
      { Update: { TableName: TABLE, Key: { id: 'acct-2' }, UpdateExpression: 'SET balance = balance + :a', ExpressionAttributeValues: { ':a': amount } } },
      { Put: { TableName: TABLE, Item: { id: `log-${amount}`, amount } } },
      { ConditionCheck: { TableName: TABLE, Key: { id: 'bank' }, ConditionExpression: 'attribute_exists(id)' } },
    ],
  }));

  const balances = async (): Promise<unknown[]> => Promise.all(['acct-1', 'acct-2'].map(async (id) =>
    (await doc.send(new GetCommand({ TableName: TABLE, Key: { id } }))).Item?.['balance']));

  it('applies every write when all conditions hold', async () => {
    await transfer(30);
    expect(await balances()).toEqual([70, 30]);
    expect((await doc.send(new GetCommand({ TableName: TABLE, Key: { id: 'log-30' } }))).Item).toEqual({ id: 'log-30', amount: 30 });
  });

  it('applies nothing and reports a reason per item when a condition fails', async () => {
    const err = await failure(transfer(500));
    expect(err).toBeInstanceOf(TransactionCanceledException);
    expect(err.message).toBe('Transaction cancelled, please refer cancellation reasons for specific reasons [ConditionalCheckFailed, None, None, None]');
    expect((err as TransactionCanceledException).CancellationReasons?.map((r) => r.Code)).toEqual(['ConditionalCheckFailed', 'None', 'None', 'None']);
    expect(await balances()).toEqual([100, 0]);
    expect((await doc.send(new GetCommand({ TableName: TABLE, Key: { id: 'log-500' } }))).Item).toBeUndefined();
  });

  it('includes the item in the reason with ReturnValuesOnConditionCheckFailure', async () => {
    const err = await failure(doc.send(new TransactWriteCommand({
      TransactItems: [{
        ConditionCheck: {
          TableName: TABLE, Key: { id: 'acct-1' }, ConditionExpression: 'balance > :x',
          ExpressionAttributeValues: { ':x': 1000 }, ReturnValuesOnConditionCheckFailure: 'ALL_OLD',
        },
      }],
    })));
    expect((err as TransactionCanceledException).CancellationReasons?.[0]).toEqual({
      // The DocumentClient does not unmarshall items inside exceptions.
      Code: 'ConditionalCheckFailed', Message: 'The conditional request failed', Item: { id: { S: 'acct-1' }, balance: { N: '100' } },
    });
  });

  it('reports a runtime update error as a ValidationError reason', async () => {
    const err = await failure(doc.send(new TransactWriteCommand({
      TransactItems: [
        { Put: { TableName: TABLE, Item: { id: 'new' } } },
        { Update: { TableName: TABLE, Key: { id: 'acct-1' }, UpdateExpression: 'SET x = absent + :one', ExpressionAttributeValues: { ':one': 1 } } },
      ],
    })));
    expect((err as TransactionCanceledException).CancellationReasons?.map((r) => r.Code)).toEqual(['None', 'ValidationError']);
    expect((await doc.send(new GetCommand({ TableName: TABLE, Key: { id: 'new' } }))).Item).toBeUndefined();
  });

  it('refuses two operations on one item', async () => {
    expect(await validationMessage(doc.send(new TransactWriteCommand({
      TransactItems: [
        { Put: { TableName: TABLE, Item: { id: 'acct-1', balance: 1 } } },
        { Delete: { TableName: TABLE, Key: { id: 'acct-1' } } },
      ],
    })))).toBe('Transaction request cannot include multiple operations on one item');
  });

  it('applies a transaction once per ClientRequestToken', async () => {
    await transfer(10, 'token-1');
    await transfer(10, 'token-1');
    expect(await balances()).toEqual([90, 10]);

    const err = await failure(transfer(20, 'token-1'));
    expect(err.name).toBe('IdempotentParameterMismatchException');
  });

  it('deletes inside a transaction', async () => {
    await doc.send(new TransactWriteCommand({ TransactItems: [{ Delete: { TableName: TABLE, Key: { id: 'acct-2' } } }] }));
    expect(running.simulator.dumpTable(TABLE).map((i) => i['id'])).toEqual([{ S: 'acct-1' }, { S: 'bank' }]);
  });

  it('reads several items at once with TransactGetItems', async () => {
    const res = await doc.send(new TransactGetCommand({
      TransactItems: [
        { Get: { TableName: TABLE, Key: { id: 'acct-1' }, ProjectionExpression: 'balance' } },
        { Get: { TableName: TABLE, Key: { id: 'absent' } } },
      ],
    }));
    expect(res.Responses?.map((r) => r.Item)).toEqual([{ balance: 100 }, undefined]);
  });
});

// ---------------------------------------------------------------------------

describe('unsupported input fails loudly', () => {
  beforeEach(createTable);

  it('refuses a real operation the simulator does not implement', async () => {
    const err = await failure(ddb.send(new UpdateTableCommand({ TableName: TABLE, BillingMode: 'PAY_PER_REQUEST' })));
    expect(err.name).toBe('UnknownOperationException');
    expect(err.message).toContain('UpdateTable');
  });

  it('refuses legacy parameters by label', async () => {
    expect(await validationMessage(ddb.send(new PutItemCommand({
      TableName: TABLE, Item: { pk: { S: 'p' }, sk: { S: 's' } }, Expected: { pk: { Exists: false } },
    })))).toContain('legacy parameter Expected');
  });

  it('refuses consumed-capacity reporting rather than returning none', async () => {
    expect(await validationMessage(ddb.send(new PutItemCommand({
      TableName: TABLE, Item: { pk: { S: 'p' }, sk: { S: 's' } }, ReturnConsumedCapacity: 'TOTAL',
    })))).toContain('ReturnConsumedCapacity=TOTAL');
  });

  it('refuses a request without a DynamoDB target with HTTP 400', async () => {
    const res = await fetch(running.url, { method: 'POST', body: '{}' });
    expect(res.status).toBe(400);
    expect((await res.json() as { __type: string }).__type).toBe('com.amazon.coral.service#UnknownOperationException');
  });
});

// ---------------------------------------------------------------------------

describe('test hooks', () => {
  it('lists tables and dumps their items in key order', async () => {
    await createTable();
    await doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'b', sk: '1' } }));
    await doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'a', sk: '2' } }));
    await doc.send(new PutCommand({ TableName: TABLE, Item: { pk: 'a', sk: '1' } }));

    expect(running.simulator.listTables()).toEqual([expect.objectContaining({ name: TABLE, partitionKey: 'pk', sortKey: 'sk', itemCount: 3 })]);
    expect(running.simulator.dumpTable(TABLE).map((i) => [i['pk'], i['sk']])).toEqual([
      [{ S: 'a' }, { S: '1' }], [{ S: 'a' }, { S: '2' }], [{ S: 'b' }, { S: '1' }],
    ]);
  });

  it('empties everything on POST /__local/reset', async () => {
    await createTable();
    const res = await fetch(`${running.url}/__local/reset`, { method: 'POST' });
    expect(res.status).toBe(204);
    expect(running.simulator.listTables()).toEqual([]);
  });
});
