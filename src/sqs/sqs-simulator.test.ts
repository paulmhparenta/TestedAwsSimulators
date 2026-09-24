import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  AddPermissionCommand,
  BatchEntryIdsNotDistinct,
  ChangeMessageVisibilityBatchCommand,
  ChangeMessageVisibilityCommand,
  CreateQueueCommand,
  DeleteMessageBatchCommand,
  DeleteMessageCommand,
  DeleteQueueCommand,
  EmptyBatchRequest,
  GetQueueAttributesCommand,
  GetQueueUrlCommand,
  InvalidAttributeName,
  InvalidAttributeValue,
  InvalidBatchEntryId,
  InvalidMessageContents,
  ListDeadLetterSourceQueuesCommand,
  ListMessageMoveTasksCommand,
  ListQueuesCommand,
  ListQueueTagsCommand,
  MessageNotInflight,
  PurgeQueueCommand,
  PurgeQueueInProgress,
  QueueDeletedRecently,
  QueueDoesNotExist,
  QueueNameExists,
  ReceiptHandleIsInvalid,
  ReceiveMessageCommand,
  ResourceNotFoundException,
  SendMessageBatchCommand,
  SendMessageCommand,
  SetQueueAttributesCommand,
  SQSClient,
  SQSServiceException,
  StartMessageMoveTaskCommand,
  TagQueueCommand,
  TooManyEntriesInBatchRequest,
  UnsupportedOperation,
  UntagQueueCommand,
  type Message,
} from '@aws-sdk/client-sqs';

import { createSqsSimulator, startSqsSimulator, type SqsSimulator } from './sqs-simulator';
import { listen, type RunningSimulator } from '../shared/server';

/**
 * Every case drives the simulator through the real AWS SDK v3 SQS client. The
 * client checks MD5OfBody on every send and receive, so a pass also means the
 * checksums are right.
 */
let running: RunningSimulator & { simulator: SqsSimulator };
let sqs: SQSClient;
let sim: SqsSimulator;

beforeAll(async () => {
  // A frozen clock: simulated time moves only through advanceTime, so a
  // boundary such as "9999ms into a 10s delay" is exact. Long polls still wait
  // in real time.
  const frozen = Date.now();
  running = await startSqsSimulator({ port: 0, now: () => frozen });
  sim = running.simulator;
  sqs = new SQSClient({
    endpoint: running.url,
    region: 'us-east-1',
    credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
  });
});

afterAll(async () => {
  sqs.destroy();
  await running.close();
});

beforeEach(() => {
  sim.reset();
});

async function createQueue(name: string, attributes?: Record<string, string>): Promise<string> {
  const res = await sqs.send(new CreateQueueCommand({ QueueName: name, Attributes: attributes }));
  return res.QueueUrl!;
}

async function send(queueUrl: string, body: string, extra: Partial<ConstructorParameters<typeof SendMessageCommand>[0]> = {}): Promise<string> {
  const res = await sqs.send(new SendMessageCommand({ QueueUrl: queueUrl, MessageBody: body, ...extra }));
  return res.MessageId!;
}

async function receive(queueUrl: string, extra: Partial<ConstructorParameters<typeof ReceiveMessageCommand>[0]> = {}): Promise<Message[]> {
  const res = await sqs.send(new ReceiveMessageCommand({ QueueUrl: queueUrl, ...extra }));
  return res.Messages ?? [];
}

async function attributes(queueUrl: string): Promise<Record<string, string>> {
  const res = await sqs.send(new GetQueueAttributesCommand({ QueueUrl: queueUrl, AttributeNames: ['All'] }));
  return res.Attributes ?? {};
}

async function failure(promise: Promise<unknown>): Promise<SQSServiceException> {
  const err = await promise.then(() => null, (e: unknown) => e);
  if (!(err instanceof SQSServiceException)) throw new Error(`expected an SQSServiceException, got ${String(err)}`);
  return err;
}

const arnOf = (name: string): string => `arn:aws:sqs:us-east-1:000000000000:${name}`;

describe('queues', () => {
  it('creates a queue whose URL points back at the simulator', async () => {
    const url = await createQueue('orders');

    expect(url).toBe(`${running.url}/000000000000/orders`);
    const got = await sqs.send(new GetQueueUrlCommand({ QueueName: 'orders' }));
    expect(got.QueueUrl).toBe(url);
  });

  it('answers GetQueueUrl for a missing queue with QueueDoesNotExist', async () => {
    await expect(sqs.send(new GetQueueUrlCommand({ QueueName: 'nope' }))).rejects.toBeInstanceOf(QueueDoesNotExist);
  });

  it('answers any call on a missing queue URL with QueueDoesNotExist', async () => {
    await expect(send(`${running.url}/000000000000/missing`, 'x')).rejects.toBeInstanceOf(QueueDoesNotExist);
  });

  it('treats a URL for another account as a missing queue', async () => {
    await createQueue('orders');
    await expect(send(`${running.url}/111111111111/orders`, 'x')).rejects.toBeInstanceOf(QueueDoesNotExist);
  });

  it('returns the existing queue when CreateQueue repeats the same attributes', async () => {
    const first = await createQueue('same', { VisibilityTimeout: '45' });
    const second = await createQueue('same', { VisibilityTimeout: '45' });

    expect(second).toBe(first);
  });

  it('refuses CreateQueue with a different attribute value for an existing name', async () => {
    await createQueue('same', { VisibilityTimeout: '45' });

    const err = await failure(createQueue('same', { VisibilityTimeout: '46' }));
    expect(err).toBeInstanceOf(QueueNameExists);
    expect(err.message).toContain('VisibilityTimeout');
  });

  it('refuses an invalid queue name', async () => {
    const err = await failure(createQueue('has space'));
    expect(err.name).toBe('InvalidParameterValue');
  });

  it('refuses FIFO queues loudly rather than creating a standard queue', async () => {
    const err = await failure(createQueue('orders.fifo', { FifoQueue: 'true' }));
    expect(err).toBeInstanceOf(UnsupportedOperation);
    expect(err.message).toContain('FIFO');
  });

  it('lists queues by prefix and pages with MaxResults and NextToken', async () => {
    for (const name of ['a-1', 'a-2', 'a-3', 'b-1']) await createQueue(name);

    const all = await sqs.send(new ListQueuesCommand({}));
    expect(all.QueueUrls).toHaveLength(4);
    expect(all.NextToken).toBeUndefined();

    const page1 = await sqs.send(new ListQueuesCommand({ QueueNamePrefix: 'a-', MaxResults: 2 }));
    expect(page1.QueueUrls?.map((u) => u.split('/').pop())).toEqual(['a-1', 'a-2']);
    expect(page1.NextToken).toBeDefined();
    const page2 = await sqs.send(new ListQueuesCommand({ QueueNamePrefix: 'a-', MaxResults: 2, NextToken: page1.NextToken }));
    expect(page2.QueueUrls?.map((u) => u.split('/').pop())).toEqual(['a-3']);
    expect(page2.NextToken).toBeUndefined();
  });

  it('omits QueueUrls when there are no queues', async () => {
    const res = await sqs.send(new ListQueuesCommand({}));
    expect(res.QueueUrls).toBeUndefined();
  });

  it('deletes a queue, and refuses to recreate it for 60 seconds', async () => {
    const url = await createQueue('temp');
    await sqs.send(new DeleteQueueCommand({ QueueUrl: url }));

    await expect(send(url, 'x')).rejects.toBeInstanceOf(QueueDoesNotExist);
    await expect(createQueue('temp')).rejects.toBeInstanceOf(QueueDeletedRecently);

    sim.advanceTime(60_000);
    expect(await createQueue('temp')).toBe(url);
  });

  it('tags a queue at creation and with TagQueue / UntagQueue', async () => {
    const res = await sqs.send(new CreateQueueCommand({ QueueName: 'tagged', tags: { team: 'core' } }));
    const url = res.QueueUrl!;
    await sqs.send(new TagQueueCommand({ QueueUrl: url, Tags: { env: 'test' } }));
    expect((await sqs.send(new ListQueueTagsCommand({ QueueUrl: url }))).Tags).toEqual({ team: 'core', env: 'test' });

    await sqs.send(new UntagQueueCommand({ QueueUrl: url, TagKeys: ['team'] }));
    expect((await sqs.send(new ListQueueTagsCommand({ QueueUrl: url }))).Tags).toEqual({ env: 'test' });
  });
});

describe('queue attributes', () => {
  it('reports the real defaults', async () => {
    const url = await createQueue('defaults');
    const attrs = await attributes(url);

    expect(attrs).toMatchObject({
      QueueArn: arnOf('defaults'),
      VisibilityTimeout: '30',
      MaximumMessageSize: '1048576',
      MessageRetentionPeriod: '345600',
      DelaySeconds: '0',
      ReceiveMessageWaitTimeSeconds: '0',
      ApproximateNumberOfMessages: '0',
      ApproximateNumberOfMessagesNotVisible: '0',
      ApproximateNumberOfMessagesDelayed: '0',
    });
    expect(attrs['RedrivePolicy']).toBeUndefined();
  });

  it('returns only the attributes asked for', async () => {
    const url = await createQueue('some');
    const res = await sqs.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ['QueueArn', 'VisibilityTimeout'] }));

    expect(res.Attributes).toEqual({ QueueArn: arnOf('some'), VisibilityTimeout: '30' });
  });

  it('counts visible, in-flight and delayed messages', async () => {
    const url = await createQueue('counts');
    await send(url, 'one');
    await send(url, 'two');
    await send(url, 'later', { DelaySeconds: 30 });
    await receive(url);

    const attrs = await attributes(url);
    expect(attrs['ApproximateNumberOfMessages']).toBe('1');
    expect(attrs['ApproximateNumberOfMessagesNotVisible']).toBe('1');
    expect(attrs['ApproximateNumberOfMessagesDelayed']).toBe('1');
  });

  it('refuses an unknown attribute name', async () => {
    const url = await createQueue('names');
    await expect(sqs.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ['Bogus' as never] })))
      .rejects.toBeInstanceOf(InvalidAttributeName);
  });

  it('sets attributes', async () => {
    const url = await createQueue('settable');
    await sqs.send(new SetQueueAttributesCommand({
      QueueUrl: url,
      Attributes: { VisibilityTimeout: '5', DelaySeconds: '2', ReceiveMessageWaitTimeSeconds: '1', MessageRetentionPeriod: '120' },
    }));

    expect(await attributes(url)).toMatchObject({
      VisibilityTimeout: '5', DelaySeconds: '2', ReceiveMessageWaitTimeSeconds: '1', MessageRetentionPeriod: '120',
    });
  });

  it('refuses an out-of-range attribute value and leaves the queue unchanged', async () => {
    const url = await createQueue('ranges');
    await expect(sqs.send(new SetQueueAttributesCommand({
      QueueUrl: url,
      Attributes: { DelaySeconds: '5', VisibilityTimeout: '43201' },
    }))).rejects.toBeInstanceOf(InvalidAttributeValue);

    expect((await attributes(url))['DelaySeconds']).toBe('0');
  });

  it('refuses a read-only attribute on SetQueueAttributes', async () => {
    const url = await createQueue('readonly');
    await expect(sqs.send(new SetQueueAttributesCommand({ QueueUrl: url, Attributes: { QueueArn: 'x' } })))
      .rejects.toBeInstanceOf(InvalidAttributeName);
  });

  it('refuses unsupported attributes loudly', async () => {
    const url = await createQueue('policy');
    const err = await failure(sqs.send(new SetQueueAttributesCommand({ QueueUrl: url, Attributes: { Policy: '{}' } })));
    expect(err).toBeInstanceOf(UnsupportedOperation);
    expect(err.message).toContain('Policy');
  });
});

describe('send and receive', () => {
  it('sends a message with the MD5 of its body and receives it', async () => {
    const url = await createQueue('basic');
    const res = await sqs.send(new SendMessageCommand({ QueueUrl: url, MessageBody: 'héllo wörld' }));

    expect(res.MD5OfMessageBody).toBe(createHash('md5').update('héllo wörld', 'utf8').digest('hex'));
    const [message] = await receive(url);
    expect(message?.Body).toBe('héllo wörld');
    expect(message?.MessageId).toBe(res.MessageId);
    expect(message?.MD5OfBody).toBe(res.MD5OfMessageBody);
  });

  it('round-trips message attributes and returns their MD5', async () => {
    const url = await createQueue('attrs');
    const res = await sqs.send(new SendMessageCommand({
      QueueUrl: url,
      MessageBody: 'x',
      MessageAttributes: {
        kind: { DataType: 'String', StringValue: 'order' },
        count: { DataType: 'Number', StringValue: '3' },
        blob: { DataType: 'Binary', BinaryValue: new Uint8Array([1, 2, 3]) },
        'trace.id': { DataType: 'String.custom', StringValue: 'abc' },
      },
    }));
    expect(res.MD5OfMessageAttributes).toMatch(/^[0-9a-f]{32}$/);

    const [message] = await receive(url, { MessageAttributeNames: ['All'] });
    expect(message?.MessageAttributes?.['kind']).toEqual({ DataType: 'String', StringValue: 'order' });
    expect(message?.MessageAttributes?.['count']).toEqual({ DataType: 'Number', StringValue: '3' });
    expect(Array.from(message?.MessageAttributes?.['blob']?.BinaryValue ?? [])).toEqual([1, 2, 3]);
    expect(message?.MD5OfMessageAttributes).toBe(res.MD5OfMessageAttributes);
  });

  it('computes MD5OfMessageAttributes with the documented SQS algorithm', async () => {
    const url = await createQueue('md5');
    const res = await sqs.send(new SendMessageCommand({
      QueueUrl: url,
      MessageBody: 'x',
      MessageAttributes: { b: { DataType: 'Number', StringValue: '1' }, a: { DataType: 'String', StringValue: 'v' } },
    }));

    const encode = (s: string): Buffer => {
      const data = Buffer.from(s, 'utf8');
      const len = Buffer.alloc(4);
      len.writeUInt32BE(data.length);
      return Buffer.concat([len, data]);
    };
    const expected = createHash('md5').update(Buffer.concat([
      encode('a'), encode('String'), Buffer.from([1]), encode('v'),
      encode('b'), encode('Number'), Buffer.from([1]), encode('1'),
    ])).digest('hex');
    expect(res.MD5OfMessageAttributes).toBe(expected);
  });

  it('returns only the message attributes asked for, by name or prefix', async () => {
    const url = await createQueue('filtered');
    await send(url, 'x', {
      MessageAttributes: {
        'a.one': { DataType: 'String', StringValue: '1' },
        'a.two': { DataType: 'String', StringValue: '2' },
        other: { DataType: 'String', StringValue: '3' },
      },
    });

    const [message] = await receive(url, { MessageAttributeNames: ['a.*'] });
    expect(Object.keys(message?.MessageAttributes ?? {}).sort()).toEqual(['a.one', 'a.two']);
  });

  it('returns no message attributes unless asked', async () => {
    const url = await createQueue('unasked');
    await send(url, 'x', { MessageAttributes: { k: { DataType: 'String', StringValue: 'v' } } });

    const [message] = await receive(url);
    expect(message?.MessageAttributes).toBeUndefined();
    expect(message?.Attributes).toBeUndefined();
  });

  it('returns the system attributes asked for', async () => {
    const url = await createQueue('system');
    await send(url, 'x');
    const before = sim.now();

    const [message] = await receive(url, { MessageSystemAttributeNames: ['All'] });
    expect(message?.Attributes?.ApproximateReceiveCount).toBe('1');
    expect(Number(message?.Attributes?.SentTimestamp)).toBeLessThanOrEqual(before);
    expect(Number(message?.Attributes?.ApproximateFirstReceiveTimestamp)).toBeGreaterThanOrEqual(before);
    expect(message?.Attributes?.SenderId).toBeDefined();
  });

  it('accepts the deprecated AttributeNames too', async () => {
    const url = await createQueue('legacy');
    await send(url, 'x');

    const [message] = await receive(url, { MessageSystemAttributeNames: ['ApproximateReceiveCount'] });
    expect(message?.Attributes).toEqual({ ApproximateReceiveCount: '1' });
  });

  it('delivers up to MaxNumberOfMessages in send order', async () => {
    const url = await createQueue('many');
    for (let i = 0; i < 12; i++) await send(url, `m${i}`);

    const first = await receive(url, { MaxNumberOfMessages: 10 });
    expect(first.map((m) => m.Body)).toEqual(['m0', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9']);
    expect((await receive(url, { MaxNumberOfMessages: 10 })).map((m) => m.Body)).toEqual(['m10', 'm11']);
  });

  it('refuses MaxNumberOfMessages above 10', async () => {
    const url = await createQueue('max');
    const err = await failure(receive(url, { MaxNumberOfMessages: 11 }));
    expect(err.name).toBe('InvalidParameterValue');
    expect(err.message).toContain('MaxNumberOfMessages');
  });

  it('refuses a body with characters SQS does not allow', async () => {
    const url = await createQueue('chars');
    await expect(send(url, 'bad \u0000 char')).rejects.toBeInstanceOf(InvalidMessageContents);
  });

  it('refuses a message larger than MaximumMessageSize', async () => {
    const url = await createQueue('small', { MaximumMessageSize: '1024' });
    const err = await failure(send(url, 'x'.repeat(1025)));
    expect(err.name).toBe('InvalidParameterValue');
    expect(err.message).toContain('shorter than 1024 bytes');
  });

  it('refuses MessageDeduplicationId on a standard queue', async () => {
    const url = await createQueue('dedupe');
    const err = await failure(send(url, 'x', { MessageDeduplicationId: 'd' }));
    expect(err.name).toBe('InvalidParameterValue');
  });

  it('refuses a message attribute with the wrong value field', async () => {
    const url = await createQueue('attr-bad');
    const err = await failure(send(url, 'x', { MessageAttributes: { n: { DataType: 'Number', StringValue: 'abc' } } }));
    expect(err.name).toBe('InvalidParameterValue');
  });
});

describe('delays', () => {
  it('holds a message back for its DelaySeconds', async () => {
    const url = await createQueue('delayed');
    await send(url, 'later', { DelaySeconds: 10 });

    expect(await receive(url)).toEqual([]);
    sim.advanceTime(9_999);
    expect(await receive(url)).toEqual([]);
    sim.advanceTime(1);
    expect((await receive(url)).map((m) => m.Body)).toEqual(['later']);
  });

  it('applies the queue DelaySeconds when the message sets none', async () => {
    const url = await createQueue('queue-delay', { DelaySeconds: '5' });
    await send(url, 'x');

    expect(await receive(url)).toEqual([]);
    sim.advanceTime(5_000);
    expect(await receive(url)).toHaveLength(1);
  });

  it('lets a message DelaySeconds of 0 override the queue delay', async () => {
    const url = await createQueue('override-delay', { DelaySeconds: '5' });
    await send(url, 'now', { DelaySeconds: 0 });
    expect(await receive(url)).toHaveLength(1);
  });

  it('refuses DelaySeconds above 900', async () => {
    const url = await createQueue('too-late');
    const err = await failure(send(url, 'x', { DelaySeconds: 901 }));
    expect(err.name).toBe('InvalidParameterValue');
  });
});

describe('visibility', () => {
  it('hides a received message until its visibility timeout expires', async () => {
    const url = await createQueue('vis', { VisibilityTimeout: '30' });
    await send(url, 'x');
    const [first] = await receive(url);

    expect(await receive(url)).toEqual([]);
    sim.advanceTime(30_000);
    const [again] = await receive(url, { MessageSystemAttributeNames: ['ApproximateReceiveCount'] });
    expect(again?.MessageId).toBe(first?.MessageId);
    expect(again?.ReceiptHandle).not.toBe(first?.ReceiptHandle);
    expect(again?.Attributes?.ApproximateReceiveCount).toBe('2');
  });

  it('uses the VisibilityTimeout given on ReceiveMessage', async () => {
    const url = await createQueue('vis-override');
    await send(url, 'x');
    await receive(url, { VisibilityTimeout: 2 });

    sim.advanceTime(2_000);
    expect(await receive(url)).toHaveLength(1);
  });

  it('keeps ApproximateFirstReceiveTimestamp from the first receive', async () => {
    const url = await createQueue('first-receive');
    await send(url, 'x');
    const [first] = await receive(url, { VisibilityTimeout: 1, MessageSystemAttributeNames: ['All'] });
    sim.advanceTime(5_000);
    const [second] = await receive(url, { MessageSystemAttributeNames: ['All'] });

    expect(second?.Attributes?.ApproximateFirstReceiveTimestamp).toBe(first?.Attributes?.ApproximateFirstReceiveTimestamp);
  });

  it('extends visibility with ChangeMessageVisibility', async () => {
    const url = await createQueue('extend', { VisibilityTimeout: '10' });
    await send(url, 'x');
    const [message] = await receive(url);
    await sqs.send(new ChangeMessageVisibilityCommand({ QueueUrl: url, ReceiptHandle: message!.ReceiptHandle, VisibilityTimeout: 60 }));

    sim.advanceTime(30_000);
    expect(await receive(url)).toEqual([]);
    sim.advanceTime(30_000);
    expect(await receive(url)).toHaveLength(1);
  });

  it('makes a message visible at once with a visibility timeout of 0', async () => {
    const url = await createQueue('release');
    await send(url, 'x');
    const [message] = await receive(url);
    await sqs.send(new ChangeMessageVisibilityCommand({ QueueUrl: url, ReceiptHandle: message!.ReceiptHandle, VisibilityTimeout: 0 }));

    expect(await receive(url)).toHaveLength(1);
  });

  it('refuses ChangeMessageVisibility on a message no longer in flight', async () => {
    const url = await createQueue('expired', { VisibilityTimeout: '1' });
    await send(url, 'x');
    const [message] = await receive(url);
    sim.advanceTime(1_000);

    await expect(sqs.send(new ChangeMessageVisibilityCommand({
      QueueUrl: url, ReceiptHandle: message!.ReceiptHandle, VisibilityTimeout: 10,
    }))).rejects.toBeInstanceOf(MessageNotInflight);
  });

  it('refuses ChangeMessageVisibility with a stale receipt handle', async () => {
    const url = await createQueue('stale-vis', { VisibilityTimeout: '1' });
    await send(url, 'x');
    const [first] = await receive(url);
    sim.advanceTime(1_000);
    await receive(url);

    const err = await failure(sqs.send(new ChangeMessageVisibilityCommand({
      QueueUrl: url, ReceiptHandle: first!.ReceiptHandle, VisibilityTimeout: 10,
    })));
    expect(err.name).toBe('InvalidParameterValue');
  });

  it('refuses a total visibility beyond 12 hours from the receive', async () => {
    const url = await createQueue('ceiling');
    await send(url, 'x');
    const [message] = await receive(url);
    sim.advanceTime(10_000);

    const err = await failure(sqs.send(new ChangeMessageVisibilityCommand({
      QueueUrl: url, ReceiptHandle: message!.ReceiptHandle, VisibilityTimeout: 43_200,
    })));
    expect(err.name).toBe('InvalidParameterValue');
    expect(err.message).toContain('43200');
  });

  it('changes visibility in a batch and reports per-entry failures', async () => {
    const url = await createQueue('vis-batch');
    await send(url, 'a');
    await send(url, 'b');
    const messages = await receive(url, { MaxNumberOfMessages: 2 });

    const res = await sqs.send(new ChangeMessageVisibilityBatchCommand({
      QueueUrl: url,
      Entries: [
        { Id: 'a', ReceiptHandle: messages[0]!.ReceiptHandle, VisibilityTimeout: 0 },
        { Id: 'bad', ReceiptHandle: 'not-a-handle', VisibilityTimeout: 0 },
      ],
    }));
    expect(res.Successful?.map((e) => e.Id)).toEqual(['a']);
    expect(res.Failed).toEqual([expect.objectContaining({ Id: 'bad', Code: 'ReceiptHandleIsInvalid', SenderFault: true })]);
    expect((await receive(url)).map((m) => m.Body)).toEqual(['a']);
  });
});

describe('delete', () => {
  it('deletes a message with its receipt handle', async () => {
    const url = await createQueue('del');
    await send(url, 'x');
    const [message] = await receive(url, { VisibilityTimeout: 1 });
    await sqs.send(new DeleteMessageCommand({ QueueUrl: url, ReceiptHandle: message!.ReceiptHandle }));

    sim.advanceTime(1_000);
    expect(await receive(url)).toEqual([]);
    expect(sim.peekMessages('del')).toEqual([]);
  });

  it('accepts a stale receipt handle but does not delete the message', async () => {
    // "If you use an old ReceiptHandle, the request will succeed, but the
    // message might not be deleted." The simulator never deletes on one.
    const url = await createQueue('stale');
    await send(url, 'x');
    const [first] = await receive(url, { VisibilityTimeout: 1 });
    sim.advanceTime(1_000);
    const [second] = await receive(url, { VisibilityTimeout: 1 });

    await sqs.send(new DeleteMessageCommand({ QueueUrl: url, ReceiptHandle: first!.ReceiptHandle }));
    expect(sim.peekMessages('stale')).toHaveLength(1);

    await sqs.send(new DeleteMessageCommand({ QueueUrl: url, ReceiptHandle: second!.ReceiptHandle }));
    expect(sim.peekMessages('stale')).toHaveLength(0);
  });

  it('accepts a second delete of the same handle', async () => {
    const url = await createQueue('twice');
    await send(url, 'x');
    const [message] = await receive(url);
    await sqs.send(new DeleteMessageCommand({ QueueUrl: url, ReceiptHandle: message!.ReceiptHandle }));
    await sqs.send(new DeleteMessageCommand({ QueueUrl: url, ReceiptHandle: message!.ReceiptHandle }));
  });

  it('refuses a receipt handle it never issued', async () => {
    const url = await createQueue('garbage');
    await expect(sqs.send(new DeleteMessageCommand({ QueueUrl: url, ReceiptHandle: 'garbage' })))
      .rejects.toBeInstanceOf(ReceiptHandleIsInvalid);
  });

  it('refuses a receipt handle from another queue', async () => {
    const a = await createQueue('queue-a');
    const b = await createQueue('queue-b');
    await send(a, 'x');
    const [message] = await receive(a);

    await expect(sqs.send(new DeleteMessageCommand({ QueueUrl: b, ReceiptHandle: message!.ReceiptHandle })))
      .rejects.toBeInstanceOf(ReceiptHandleIsInvalid);
  });

  it('deletes in a batch and reports per-entry failures', async () => {
    const url = await createQueue('del-batch');
    await send(url, 'a');
    await send(url, 'b');
    const messages = await receive(url, { MaxNumberOfMessages: 2 });

    const res = await sqs.send(new DeleteMessageBatchCommand({
      QueueUrl: url,
      Entries: [
        { Id: 'one', ReceiptHandle: messages[0]!.ReceiptHandle },
        { Id: 'two', ReceiptHandle: messages[1]!.ReceiptHandle },
        { Id: 'three', ReceiptHandle: 'bogus' },
      ],
    }));
    expect(res.Successful?.map((e) => e.Id)).toEqual(['one', 'two']);
    expect(res.Failed?.map((e) => e.Code)).toEqual(['ReceiptHandleIsInvalid']);
    expect(sim.peekMessages('del-batch')).toEqual([]);
  });
});

describe('batch send', () => {
  it('sends a batch and reports a bad entry without failing the rest', async () => {
    const url = await createQueue('batch');
    const res = await sqs.send(new SendMessageBatchCommand({
      QueueUrl: url,
      Entries: [
        { Id: 'a', MessageBody: 'first' },
        { Id: 'b', MessageBody: 'second', DelaySeconds: 901 },
        { Id: 'c', MessageBody: 'third', MessageAttributes: { k: { DataType: 'String', StringValue: 'v' } } },
      ],
    }));

    expect(res.Successful?.map((e) => e.Id)).toEqual(['a', 'c']);
    expect(res.Successful?.[1]?.MD5OfMessageAttributes).toMatch(/^[0-9a-f]{32}$/);
    expect(res.Failed).toEqual([expect.objectContaining({ Id: 'b', Code: 'InvalidParameterValue', SenderFault: true })]);
    expect((await receive(url, { MaxNumberOfMessages: 10 })).map((m) => m.Body)).toEqual(['first', 'third']);
  });

  it('refuses an empty batch', async () => {
    const url = await createQueue('empty-batch');
    await expect(sqs.send(new SendMessageBatchCommand({ QueueUrl: url, Entries: [] }))).rejects.toBeInstanceOf(EmptyBatchRequest);
  });

  it('refuses more than 10 entries', async () => {
    const url = await createQueue('big-batch');
    const entries = Array.from({ length: 11 }, (_, i) => ({ Id: `m${i}`, MessageBody: 'x' }));
    await expect(sqs.send(new SendMessageBatchCommand({ QueueUrl: url, Entries: entries })))
      .rejects.toBeInstanceOf(TooManyEntriesInBatchRequest);
  });

  it('refuses repeated entry ids', async () => {
    const url = await createQueue('dup-batch');
    await expect(sqs.send(new SendMessageBatchCommand({
      QueueUrl: url,
      Entries: [{ Id: 'x', MessageBody: '1' }, { Id: 'x', MessageBody: '2' }],
    }))).rejects.toBeInstanceOf(BatchEntryIdsNotDistinct);
  });

  it('refuses an invalid entry id', async () => {
    const url = await createQueue('bad-id');
    await expect(sqs.send(new SendMessageBatchCommand({ QueueUrl: url, Entries: [{ Id: 'has space', MessageBody: '1' }] })))
      .rejects.toBeInstanceOf(InvalidBatchEntryId);
  });
});

describe('long polling', () => {
  it('waits WaitTimeSeconds on an empty queue, then returns nothing', async () => {
    const url = await createQueue('empty-poll');
    const started = Date.now();

    expect(await receive(url, { WaitTimeSeconds: 1 })).toEqual([]);
    expect(Date.now() - started).toBeGreaterThanOrEqual(950);
  });

  it('returns as soon as a message arrives during the wait', async () => {
    const url = await createQueue('arrives');
    const started = Date.now();
    const pending = receive(url, { WaitTimeSeconds: 10 });
    setTimeout(() => { void send(url, 'hello'); }, 100);

    expect((await pending).map((m) => m.Body)).toEqual(['hello']);
    expect(Date.now() - started).toBeLessThan(3_000);
  });

  it('wakes a waiting receive when advanceTime makes a delayed message visible', async () => {
    const url = await createQueue('wake');
    await send(url, 'delayed', { DelaySeconds: 60 });
    const pending = receive(url, { WaitTimeSeconds: 10 });
    setTimeout(() => sim.advanceTime(60_000), 100);

    expect((await pending).map((m) => m.Body)).toEqual(['delayed']);
  });

  it('uses the queue ReceiveMessageWaitTimeSeconds when the request sets none', async () => {
    const url = await createQueue('queue-wait', { ReceiveMessageWaitTimeSeconds: '1' });
    const started = Date.now();

    expect(await receive(url)).toEqual([]);
    expect(Date.now() - started).toBeGreaterThanOrEqual(950);
  });

  it('lets WaitTimeSeconds 0 override the queue wait', async () => {
    const url = await createQueue('no-wait', { ReceiveMessageWaitTimeSeconds: '20' });
    const started = Date.now();

    expect(await receive(url, { WaitTimeSeconds: 0 })).toEqual([]);
    expect(Date.now() - started).toBeLessThan(500);
  });

  it('refuses WaitTimeSeconds above 20', async () => {
    const url = await createQueue('too-long');
    const err = await failure(receive(url, { WaitTimeSeconds: 21 }));
    expect(err.name).toBe('InvalidParameterValue');
  });
});

describe('purge and retention', () => {
  it('purges every message, and refuses a second purge within 60 seconds', async () => {
    const url = await createQueue('purge');
    await send(url, 'a');
    await send(url, 'b');
    await sqs.send(new PurgeQueueCommand({ QueueUrl: url }));

    expect(sim.peekMessages('purge')).toEqual([]);
    await expect(sqs.send(new PurgeQueueCommand({ QueueUrl: url }))).rejects.toBeInstanceOf(PurgeQueueInProgress);
    sim.advanceTime(60_000);
    await sqs.send(new PurgeQueueCommand({ QueueUrl: url }));
  });

  it('drops a message older than the retention period', async () => {
    const url = await createQueue('retention', { MessageRetentionPeriod: '60' });
    await send(url, 'x');

    sim.advanceTime(60_000);
    expect(await receive(url)).toEqual([]);
    expect((await attributes(url))['ApproximateNumberOfMessages']).toBe('0');
  });
});

describe('dead-letter queues', () => {
  async function withDlq(maxReceiveCount: number): Promise<{ source: string; dlq: string }> {
    const dlq = await createQueue('dlq');
    const source = await createQueue('work', {
      VisibilityTimeout: '1',
      RedrivePolicy: JSON.stringify({ deadLetterTargetArn: arnOf('dlq'), maxReceiveCount }),
    });
    return { source, dlq };
  }

  it('reports the RedrivePolicy with a numeric maxReceiveCount', async () => {
    const { source } = await withDlq(3);
    expect(JSON.parse((await attributes(source))['RedrivePolicy']!)).toEqual({ deadLetterTargetArn: arnOf('dlq'), maxReceiveCount: 3 });
  });

  it('delivers a message maxReceiveCount times, then moves it to the DLQ on the next receive', async () => {
    const { source, dlq } = await withDlq(2);
    const id = await send(source, 'poison');

    expect(await receive(source)).toHaveLength(1);
    sim.advanceTime(1_000);
    expect(await receive(source)).toHaveLength(1);
    sim.advanceTime(1_000);
    expect(await receive(source)).toEqual([]);

    const [moved] = await receive(dlq, { MessageSystemAttributeNames: ['All'] });
    expect(moved?.MessageId).toBe(id);
    expect(moved?.Body).toBe('poison');
    expect(moved?.Attributes?.DeadLetterQueueSourceArn).toBe(arnOf('work'));
    // The receive count carries over into the DLQ.
    expect(moved?.Attributes?.ApproximateReceiveCount).toBe('3');
  });

  it('refuses a RedrivePolicy naming a queue that does not exist', async () => {
    await expect(createQueue('orphan', {
      RedrivePolicy: JSON.stringify({ deadLetterTargetArn: arnOf('missing'), maxReceiveCount: 1 }),
    })).rejects.toBeInstanceOf(InvalidAttributeValue);
  });

  it('refuses a maxReceiveCount outside 1 to 1000', async () => {
    await createQueue('dlq');
    await expect(createQueue('bad-count', {
      RedrivePolicy: JSON.stringify({ deadLetterTargetArn: arnOf('dlq'), maxReceiveCount: 0 }),
    })).rejects.toBeInstanceOf(InvalidAttributeValue);
  });

  it('removes the RedrivePolicy when it is set to an empty string', async () => {
    const { source } = await withDlq(1);
    await sqs.send(new SetQueueAttributesCommand({ QueueUrl: source, Attributes: { RedrivePolicy: '' } }));
    expect((await attributes(source))['RedrivePolicy']).toBeUndefined();
  });

  it('enforces a denyAll RedriveAllowPolicy on the DLQ', async () => {
    await createQueue('closed-dlq', { RedriveAllowPolicy: JSON.stringify({ redrivePermission: 'denyAll' }) });
    await expect(createQueue('blocked', {
      RedrivePolicy: JSON.stringify({ deadLetterTargetArn: arnOf('closed-dlq'), maxReceiveCount: 1 }),
    })).rejects.toBeInstanceOf(InvalidAttributeValue);
  });

  it('lists the source queues of a DLQ', async () => {
    const { dlq } = await withDlq(1);
    const res = await sqs.send(new ListDeadLetterSourceQueuesCommand({ QueueUrl: dlq }));
    expect(res.queueUrls).toEqual([`${running.url}/000000000000/work`]);
  });

  async function deadLetter(source: string, body: string): Promise<void> {
    await send(source, body);
    await receive(source);
    sim.advanceTime(1_000);
    await receive(source);
  }

  it('moves DLQ messages back to their source queue with StartMessageMoveTask', async () => {
    const { source } = await withDlq(1);
    await deadLetter(source, 'retry me');
    expect(sim.peekMessages('dlq')).toHaveLength(1);

    const started = await sqs.send(new StartMessageMoveTaskCommand({ SourceArn: arnOf('dlq') }));
    expect(started.TaskHandle).toBeDefined();

    expect(sim.peekMessages('dlq')).toEqual([]);
    const [back] = await receive(source, { MessageSystemAttributeNames: ['ApproximateReceiveCount'] });
    expect(back?.Body).toBe('retry me');
    expect(back?.Attributes?.ApproximateReceiveCount).toBe('1');

    const tasks = await sqs.send(new ListMessageMoveTasksCommand({ SourceArn: arnOf('dlq') }));
    expect(tasks.Results).toEqual([expect.objectContaining({
      Status: 'COMPLETED',
      SourceArn: arnOf('dlq'),
      ApproximateNumberOfMessagesMoved: 1,
      ApproximateNumberOfMessagesToMove: 1,
    })]);
    expect(tasks.Results?.[0]?.TaskHandle).toBeUndefined();
  });

  it('moves DLQ messages to a DestinationArn', async () => {
    const { source } = await withDlq(1);
    const other = await createQueue('other');
    await deadLetter(source, 'elsewhere');

    await sqs.send(new StartMessageMoveTaskCommand({ SourceArn: arnOf('dlq'), DestinationArn: arnOf('other') }));
    expect((await receive(other)).map((m) => m.Body)).toEqual(['elsewhere']);
  });

  it('refuses a move task from a queue that is not a DLQ', async () => {
    await createQueue('plain');
    const err = await failure(sqs.send(new StartMessageMoveTaskCommand({ SourceArn: arnOf('plain') })));
    expect(err.name).toBe('InvalidParameterValue');
  });

  it('refuses a move task from a missing queue', async () => {
    await expect(sqs.send(new StartMessageMoveTaskCommand({ SourceArn: arnOf('ghost') })))
      .rejects.toBeInstanceOf(ResourceNotFoundException);
  });
});

describe('unsupported input fails loudly', () => {
  it('refuses a real SQS operation the simulator does not implement', async () => {
    const url = await createQueue('perm');
    const err = await failure(sqs.send(new AddPermissionCommand({ QueueUrl: url, Label: 'l', AWSAccountIds: ['1'], Actions: ['*'] })));
    expect(err).toBeInstanceOf(UnsupportedOperation);
    expect(err.message).toContain('AddPermission');
  });

  it('refuses the form-encoded query protocol with HTTP 400', async () => {
    const res = await fetch(running.url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'Action=ListQueues',
    });
    expect(res.status).toBe(400);
    expect(res.headers.get('x-amzn-query-error')).toBe('AWS.SimpleQueueService.UnsupportedOperation;Sender');
    expect((await res.json() as { message: string }).message).toContain('query protocol');
  });

  it('refuses an unknown request parameter', async () => {
    const res = await fetch(running.url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-amz-json-1.0', 'x-amz-target': 'AmazonSQS.ListQueues' },
      body: JSON.stringify({ Bogus: 1 }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      __type: 'com.amazonaws.sqs#UnsupportedOperation',
      message: expect.stringContaining('Bogus'),
    });
  });
});

describe('test hooks', () => {
  it('lists queues with their attributes', async () => {
    await createQueue('hook-a');
    await createQueue('hook-b', { DelaySeconds: '3' });

    const queues = sim.listQueues();
    expect(queues.map((q) => q.name)).toEqual(['hook-a', 'hook-b']);
    expect(queues[1]?.attributes['DelaySeconds']).toBe('3');
    expect(queues[1]?.arn).toBe(arnOf('hook-b'));
  });

  it('peeks messages without receiving them', async () => {
    const url = await createQueue('peek');
    await send(url, 'a');
    await send(url, 'b', { DelaySeconds: 10 });
    await receive(url);

    const peeked = sim.peekMessages('peek');
    expect(peeked.map((m) => [m.body, m.state, m.receiveCount])).toEqual([['a', 'in-flight', 1], ['b', 'delayed', 0]]);
    expect(sim.peekMessages('peek')).toHaveLength(2);
  });

  it('empties everything on POST /__local/reset', async () => {
    const url = await createQueue('gone');
    await send(url, 'x');

    const res = await fetch(`${running.url}/__local/reset`, { method: 'POST' });
    expect(res.status).toBe(204);
    expect(sim.listQueues()).toEqual([]);
    await expect(send(url, 'x')).rejects.toBeInstanceOf(QueueDoesNotExist);
  });

  it('takes its time from an injected clock', async () => {
    let clock = Date.UTC(2030, 0, 1);
    const own = createSqsSimulator({ now: () => clock });
    const server = await listen(own.app, 0);
    const client = new SQSClient({ endpoint: server.url, region: 'us-east-1', credentials: { accessKeyId: 't', secretAccessKey: 't' } });
    try {
      const url = (await client.send(new CreateQueueCommand({ QueueName: 'clocked' }))).QueueUrl!;
      await client.send(new SendMessageCommand({ QueueUrl: url, MessageBody: 'x', DelaySeconds: 5 }));
      expect((await client.send(new ReceiveMessageCommand({ QueueUrl: url }))).Messages).toBeUndefined();

      clock += 5_000;
      const res = await client.send(new ReceiveMessageCommand({ QueueUrl: url, MessageSystemAttributeNames: ['SentTimestamp'] }));
      expect(res.Messages?.[0]?.Attributes?.SentTimestamp).toBe(String(Date.UTC(2030, 0, 1)));
    } finally {
      client.destroy();
      await server.close();
    }
  });
});
