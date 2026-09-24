/**
 * In-memory SQS simulator (standard queues) for local development and tests.
 *
 * Speaks the AWS JSON 1.0 protocol that `@aws-sdk/client-sqs` uses:
 *   POST /   X-Amz-Target: AmazonSQS.<Operation>
 *            Content-Type: application/x-amz-json-1.0
 *
 * Errors copy real SQS: a JSON body `{"__type":"com.amazonaws.sqs#<Name>","message":...}`
 * plus the `x-amzn-query-error: <QueryCode>;Sender` header. The SDK builds its
 * exception class (QueueDoesNotExist, ReceiptHandleIsInvalid, ...) from that
 * header, so both have to be right for `instanceof` checks to pass.
 *
 * Queue URLs are `http://<host the client used>/<accountId>/<queueName>`. The
 * SDK sends each request to the host of the QueueUrl it names, so the URL must
 * point back at this server.
 *
 * Time comes from an injectable clock (`now`) plus `advanceTime(ms)`, so a test
 * can expire a visibility timeout or a delay without sleeping. Long polling
 * (`WaitTimeSeconds`) waits in real time, and returns early when a message
 * becomes available, including when `advanceTime` makes one visible.
 *
 * Anything this simulator does not implement (FIFO queues, KMS, queue policies,
 * permissions, the query protocol) is refused with HTTP 400 and a message
 * naming the unsupported thing, never silently ignored.
 */

import express from 'express';
import { createHash, randomUUID } from 'node:crypto';

import { listen, readRawBody, type RunningSimulator } from '../shared/server';

export const SQS_SIMULATOR_DEFAULT_PORT = 38309;
export const SQS_SIMULATOR_DEFAULT_ACCOUNT_ID = '000000000000';
export const SQS_SIMULATOR_DEFAULT_REGION = 'us-east-1';

/** How often a waiting long poll re-checks the queue for time-based changes. */
const LONG_POLL_TICK_MS = 20;

/** Real SQS limits. Each is named in the SQS API reference. */
const MAX_MESSAGE_SIZE = 1_048_576; // 1 MiB, the MaximumMessageSize default and ceiling
const MIN_MESSAGE_SIZE_ATTRIBUTE = 1_024;
const MAX_VISIBILITY_TIMEOUT = 43_200; // 12 hours
const MAX_DELAY_SECONDS = 900;
const MIN_RETENTION = 60;
const MAX_RETENTION = 1_209_600; // 14 days
const DEFAULT_RETENTION = 345_600; // 4 days
const MAX_WAIT_SECONDS = 20;
const MAX_BATCH_ENTRIES = 10;
const MAX_MESSAGE_ATTRIBUTES = 10;
const QUEUE_RECREATE_COOLDOWN_MS = 60_000; // "wait at least 60 seconds" after DeleteQueue
const PURGE_COOLDOWN_MS = 60_000; // "only one PurgeQueue operation ... every 60 seconds"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SqsMessageAttributeValue {
  readonly DataType: string;
  readonly StringValue?: string;
  /** Base64, as the JSON protocol carries it. */
  readonly BinaryValue?: string;
}

export interface SqsSimulatorOptions {
  /** Clock in epoch milliseconds. Default `Date.now`. `advanceTime` adds on top. */
  readonly now?: () => number;
  /** Account id in queue URLs and ARNs. Default `000000000000`. */
  readonly accountId?: string;
  /** Region in queue ARNs. Default `us-east-1`. */
  readonly region?: string;
}

export interface SqsQueueSummary {
  readonly name: string;
  readonly arn: string;
  /** The same map GetQueueAttributes(All) returns. */
  readonly attributes: Readonly<Record<string, string>>;
  readonly tags: Readonly<Record<string, string>>;
}

export type SqsMessageState = 'available' | 'delayed' | 'in-flight';

export interface SqsPeekedMessage {
  readonly messageId: string;
  readonly body: string;
  readonly messageAttributes: Readonly<Record<string, SqsMessageAttributeValue>>;
  readonly state: SqsMessageState;
  readonly receiveCount: number;
  readonly sentTimestamp: number;
  readonly firstReceiveTimestamp: number | null;
  /** Epoch ms at which a delayed or in-flight message becomes available. */
  readonly availableAt: number;
  /** ARN of the queue the message was dead-lettered from, if it was. */
  readonly deadLetterQueueSourceArn: string | null;
}

export interface SqsSimulator {
  readonly app: express.Express;
  /** Deletes every queue, message and move task, and zeroes `advanceTime`. */
  reset(): void;
  listQueues(): readonly SqsQueueSummary[];
  /** Every message in the queue, oldest first, without receiving any. */
  peekMessages(queueName: string): readonly SqsPeekedMessage[];
  /** Moves the simulator clock forward, then wakes any waiting long polls. */
  advanceTime(ms: number): void;
  /** The simulator clock, in epoch ms. */
  now(): number;
}

interface RedrivePolicy {
  readonly deadLetterTargetArn: string;
  readonly maxReceiveCount: number;
}

interface Queue {
  readonly name: string;
  readonly arn: string;
  readonly createdAt: number;
  lastModifiedAt: number;
  visibilityTimeout: number;
  delaySeconds: number;
  messageRetentionPeriod: number;
  maximumMessageSize: number;
  receiveMessageWaitTimeSeconds: number;
  redrivePolicy: RedrivePolicy | null;
  /** Stored verbatim, and enforced when another queue names this one as its DLQ. */
  redriveAllowPolicy: string | null;
  sqsManagedSseEnabled: boolean;
  lastPurgeAt: number | null;
  tags: Record<string, string>;
  messages: StoredMessage[];
}

interface StoredMessage {
  readonly messageId: string;
  readonly body: string;
  readonly md5OfBody: string;
  readonly messageAttributes: Record<string, SqsMessageAttributeValue>;
  readonly md5OfMessageAttributes: string | null;
  readonly awsTraceHeader: string | null;
  readonly messageGroupId: string | null;
  sentTimestamp: number;
  delayedUntil: number;
  inFlightUntil: number;
  /** When the current receive happened; bounds the 12-hour visibility ceiling. */
  receivedAt: number | null;
  receiveCount: number;
  firstReceiveTimestamp: number | null;
  receiptHandle: string | null;
  deadLetterQueueSourceArn: string | null;
}

interface MoveTask {
  readonly taskHandle: string;
  readonly sourceArn: string;
  readonly destinationArn: string | null;
  readonly maxNumberOfMessagesPerSecond: number | null;
  readonly startedTimestamp: number;
  readonly status: 'COMPLETED' | 'FAILED';
  readonly approximateNumberOfMessagesMoved: number;
  readonly approximateNumberOfMessagesToMove: number;
  readonly failureReason: string | null;
}

type Json = Record<string, unknown>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * An SQS error response. `type` is the Smithy shape name in `__type`;
 * `queryCode` is the legacy query-protocol code in `x-amzn-query-error`, which
 * is what the SDK actually uses to choose the exception class.
 */
class SqsError extends Error {
  constructor(
    readonly type: string,
    readonly queryCode: string,
    message: string,
    readonly status = 400,
    readonly fault: 'Sender' | 'Receiver' = 'Sender',
  ) {
    super(message);
  }
}

const errors = {
  queueDoesNotExist: () => new SqsError('QueueDoesNotExist', 'AWS.SimpleQueueService.NonExistentQueue',
    'The specified queue does not exist.'),
  invalidParameterValue: (message: string) => new SqsError('InvalidParameterValueException', 'InvalidParameterValue', message),
  missingParameter: (name: string) => new SqsError('MissingRequiredParameterException', 'MissingParameter',
    `The request must contain the parameter ${name}.`),
  invalidAttributeName: (message: string) => new SqsError('InvalidAttributeName', 'InvalidAttributeName', message),
  invalidAttributeValue: (message: string) => new SqsError('InvalidAttributeValue', 'InvalidAttributeValue', message),
  unsupported: (what: string) => new SqsError('UnsupportedOperation', 'AWS.SimpleQueueService.UnsupportedOperation',
    `${what} is not supported by the tested-aws-simulators SQS simulator.`),
  receiptHandleIsInvalid: (handle: string) => new SqsError('ReceiptHandleIsInvalid', 'ReceiptHandleIsInvalid',
    `The input receipt handle "${handle}" is not a valid receipt handle.`, 404),
  resourceNotFound: (message: string) => new SqsError('ResourceNotFoundException', 'ResourceNotFoundException', message, 404),
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function md5Hex(data: Buffer | string): string {
  return createHash('md5').update(data).digest('hex');
}

/**
 * MD5 of the message attributes, computed the way SQS documents it: attributes
 * sorted by name, each encoded as length-prefixed name, length-prefixed data
 * type, a transport byte (1 string/number, 2 binary) and the length-prefixed
 * value.
 */
function md5OfMessageAttributes(attributes: Record<string, SqsMessageAttributeValue>): string | null {
  const names = Object.keys(attributes).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  if (names.length === 0) return null;
  const parts: Buffer[] = [];
  const lengthPrefixed = (data: Buffer): void => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    parts.push(len, data);
  };
  for (const name of names) {
    const attr = attributes[name]!;
    lengthPrefixed(Buffer.from(name, 'utf8'));
    lengthPrefixed(Buffer.from(attr.DataType, 'utf8'));
    if (attr.BinaryValue !== undefined) {
      parts.push(Buffer.from([2]));
      lengthPrefixed(Buffer.from(attr.BinaryValue, 'base64'));
    } else {
      parts.push(Buffer.from([1]));
      lengthPrefixed(Buffer.from(attr.StringValue ?? '', 'utf8'));
    }
  }
  return md5Hex(Buffer.concat(parts));
}

/**
 * SQS accepts only these characters in a message body or string attribute:
 * #x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF.
 */
function hasOnlyAllowedCharacters(value: string): boolean {
  for (const ch of value) {
    const cp = ch.codePointAt(0)!;
    const ok = cp === 0x9 || cp === 0xa || cp === 0xd
      || (cp >= 0x20 && cp <= 0xd7ff)
      || (cp >= 0xe000 && cp <= 0xfffd)
      || (cp >= 0x10000 && cp <= 0x10ffff);
    if (!ok) return false;
  }
  return true;
}

function messageSize(body: string, attributes: Record<string, SqsMessageAttributeValue>): number {
  let size = Buffer.byteLength(body, 'utf8');
  for (const [name, attr] of Object.entries(attributes)) {
    size += Buffer.byteLength(name, 'utf8') + Buffer.byteLength(attr.DataType, 'utf8');
    size += attr.BinaryValue !== undefined
      ? Buffer.from(attr.BinaryValue, 'base64').length
      : Buffer.byteLength(attr.StringValue ?? '', 'utf8');
  }
  return size;
}

function isPlainObject(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireString(body: Json, name: string): string {
  const value = body[name];
  if (value === undefined || value === null || value === '') throw errors.missingParameter(name);
  if (typeof value !== 'string') throw errors.invalidParameterValue(`Value for parameter ${name} must be a string.`);
  return value;
}

function optionalInteger(body: Json, name: string, min: number, max: number, reason: string): number | undefined {
  const value = body[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw errors.invalidParameterValue(`Value ${String(value)} for parameter ${name} is invalid. Reason: ${reason}`);
  }
  return value;
}

function requireAllowedKeys(op: string, body: Json, allowed: readonly string[], context = ''): void {
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) {
      throw errors.unsupported(`Parameter ${context}${key} on ${op}`);
    }
  }
}

const QUEUE_NAME = /^[A-Za-z0-9_-]{1,80}$/;
const BATCH_ENTRY_ID = /^[A-Za-z0-9_-]{1,80}$/;

/** Every attribute name GetQueueAttributes accepts. */
const READABLE_ATTRIBUTES = [
  'All', 'Policy', 'VisibilityTimeout', 'MaximumMessageSize', 'MessageRetentionPeriod',
  'ApproximateNumberOfMessages', 'ApproximateNumberOfMessagesNotVisible', 'CreatedTimestamp',
  'LastModifiedTimestamp', 'QueueArn', 'ApproximateNumberOfMessagesDelayed', 'DelaySeconds',
  'ReceiveMessageWaitTimeSeconds', 'RedrivePolicy', 'FifoQueue', 'ContentBasedDeduplication',
  'KmsMasterKeyId', 'KmsDataKeyReusePeriodSeconds', 'DeduplicationScope', 'FifoThroughputLimit',
  'RedriveAllowPolicy', 'SqsManagedSseEnabled',
] as const;

/** Settable attributes this simulator implements. */
const SETTABLE_ATTRIBUTES = [
  'VisibilityTimeout', 'MaximumMessageSize', 'MessageRetentionPeriod', 'DelaySeconds',
  'ReceiveMessageWaitTimeSeconds', 'RedrivePolicy', 'RedriveAllowPolicy', 'SqsManagedSseEnabled',
] as const;

/** Real, settable attributes this simulator refuses rather than ignores. */
const UNSUPPORTED_SETTABLE_ATTRIBUTES = [
  'Policy', 'KmsMasterKeyId', 'KmsDataKeyReusePeriodSeconds', 'FifoQueue', 'ContentBasedDeduplication',
  'DeduplicationScope', 'FifoThroughputLimit',
] as const;

const SYSTEM_ATTRIBUTE_NAMES = [
  'All', 'SenderId', 'SentTimestamp', 'ApproximateReceiveCount', 'ApproximateFirstReceiveTimestamp',
  'SequenceNumber', 'MessageDeduplicationId', 'MessageGroupId', 'AWSTraceHeader', 'DeadLetterQueueSourceArn',
] as const;

// ---------------------------------------------------------------------------
// Simulator factory
// ---------------------------------------------------------------------------

export function createSqsSimulator(options: SqsSimulatorOptions = {}): SqsSimulator {
  const baseClock = options.now ?? Date.now;
  const accountId = options.accountId ?? SQS_SIMULATOR_DEFAULT_ACCOUNT_ID;
  const region = options.region ?? SQS_SIMULATOR_DEFAULT_REGION;
  let clockOffset = 0;
  const now = (): number => baseClock() + clockOffset;

  const queues = new Map<string, Queue>();
  /** Queue name → when it was deleted, for QueueDeletedRecently. */
  const deletedAt = new Map<string, number>();
  const moveTasks: MoveTask[] = [];
  const waiters = new Set<() => void>();

  function wakeWaiters(): void {
    for (const wake of [...waiters]) wake();
  }

  const arnFor = (name: string): string => `arn:aws:sqs:${region}:${accountId}:${name}`;
  const urlFor = (host: string, name: string): string => `http://${host}/${accountId}/${name}`;

  function queueByArn(arn: string): Queue | undefined {
    const prefix = `arn:aws:sqs:${region}:${accountId}:`;
    return arn.startsWith(prefix) ? queues.get(arn.slice(prefix.length)) : undefined;
  }

  /**
   * Resolves a QueueUrl. Any host is accepted, because the client may reach the
   * simulator under a different name than the one in the URL, but the account
   * must match, as it must on SQS.
   */
  function queueFromUrl(url: string): Queue {
    let pathname: string;
    try {
      pathname = new URL(url).pathname;
    } catch {
      throw errors.queueDoesNotExist();
    }
    const segments = pathname.split('/').filter(Boolean);
    if (segments.length !== 2 || segments[0] !== accountId) throw errors.queueDoesNotExist();
    const queue = queues.get(segments[1]!);
    if (!queue) throw errors.queueDoesNotExist();
    dropExpired(queue);
    return queue;
  }

  // ── Message state ─────────────────────────────────────────────────────────

  function stateOf(message: StoredMessage, at: number): SqsMessageState {
    if (message.inFlightUntil > at) return 'in-flight';
    if (message.delayedUntil > at) return 'delayed';
    return 'available';
  }

  /** Real SQS deletes messages older than the retention period. */
  function dropExpired(queue: Queue): void {
    const cutoff = now() - queue.messageRetentionPeriod * 1000;
    queue.messages = queue.messages.filter((m) => m.sentTimestamp > cutoff);
  }

  function newReceiptHandle(queue: Queue, message: StoredMessage): string {
    const payload = JSON.stringify({ q: queue.name, m: message.messageId, n: randomUUID() });
    return Buffer.from(payload, 'utf8').toString('base64');
  }

  /** Decodes a receipt handle; a handle this simulator never issued is invalid. */
  function decodeReceiptHandle(queue: Queue, handle: string): { messageId: string } {
    try {
      const decoded = JSON.parse(Buffer.from(handle, 'base64').toString('utf8')) as { q?: unknown; m?: unknown; n?: unknown };
      if (decoded.q === queue.name && typeof decoded.m === 'string' && typeof decoded.n === 'string') {
        return { messageId: decoded.m };
      }
    } catch {
      // fall through
    }
    throw errors.receiptHandleIsInvalid(handle);
  }

  // ── Attributes ────────────────────────────────────────────────────────────

  function queueAttributes(queue: Queue): Record<string, string> {
    const at = now();
    let visible = 0;
    let notVisible = 0;
    let delayed = 0;
    for (const m of queue.messages) {
      const state = stateOf(m, at);
      if (state === 'available') visible += 1;
      else if (state === 'in-flight') notVisible += 1;
      else delayed += 1;
    }
    const attributes: Record<string, string> = {
      QueueArn: queue.arn,
      ApproximateNumberOfMessages: String(visible),
      ApproximateNumberOfMessagesNotVisible: String(notVisible),
      ApproximateNumberOfMessagesDelayed: String(delayed),
      CreatedTimestamp: String(Math.floor(queue.createdAt / 1000)),
      LastModifiedTimestamp: String(Math.floor(queue.lastModifiedAt / 1000)),
      VisibilityTimeout: String(queue.visibilityTimeout),
      MaximumMessageSize: String(queue.maximumMessageSize),
      MessageRetentionPeriod: String(queue.messageRetentionPeriod),
      DelaySeconds: String(queue.delaySeconds),
      ReceiveMessageWaitTimeSeconds: String(queue.receiveMessageWaitTimeSeconds),
      SqsManagedSseEnabled: String(queue.sqsManagedSseEnabled),
    };
    if (queue.redrivePolicy) {
      attributes['RedrivePolicy'] = JSON.stringify(queue.redrivePolicy);
    }
    if (queue.redriveAllowPolicy) {
      attributes['RedriveAllowPolicy'] = queue.redriveAllowPolicy;
    }
    return attributes;
  }

  function integerAttribute(name: string, raw: string, min: number, max: number): number {
    if (!/^-?\d+$/.test(raw.trim())) {
      throw errors.invalidAttributeValue(`Invalid value for the parameter ${name}.`);
    }
    const value = Number(raw);
    if (value < min || value > max) {
      throw errors.invalidAttributeValue(`Invalid value for the parameter ${name}.`);
    }
    return value;
  }

  function parseRedrivePolicy(queueName: string, raw: string): RedrivePolicy | null {
    if (raw === '') return null; // SetQueueAttributes with "" removes the policy.
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw errors.invalidAttributeValue(`Value ${raw} for parameter RedrivePolicy is invalid. Reason: Invalid value for the parameter RedrivePolicy.`);
    }
    if (!isPlainObject(parsed)) {
      throw errors.invalidAttributeValue(`Value ${raw} for parameter RedrivePolicy is invalid. Reason: Redrive policy is not a JSON object.`);
    }
    for (const key of Object.keys(parsed)) {
      if (key !== 'deadLetterTargetArn' && key !== 'maxReceiveCount') {
        throw errors.invalidAttributeValue(`Value ${raw} for parameter RedrivePolicy is invalid. Reason: Only following attributes are supported:[deadLetterTargetArn, maxReceiveCount].`);
      }
    }
    const target = parsed['deadLetterTargetArn'];
    const count = Number(parsed['maxReceiveCount']);
    if (typeof target !== 'string') {
      throw errors.invalidAttributeValue(`Value ${raw} for parameter RedrivePolicy is invalid. Reason: Redrive policy does not contain mandatory attribute: deadLetterTargetArn.`);
    }
    if (parsed['maxReceiveCount'] === undefined) {
      throw errors.invalidAttributeValue(`Value ${raw} for parameter RedrivePolicy is invalid. Reason: Redrive policy does not contain mandatory attribute: maxReceiveCount.`);
    }
    if (!Number.isInteger(count) || count < 1 || count > 1000) {
      throw errors.invalidAttributeValue(`Value ${raw} for parameter RedrivePolicy is invalid. Reason: Invalid value for maxReceiveCount: ${String(parsed['maxReceiveCount'])}, valid values are from 1 to 1000 both inclusive.`);
    }
    const dlq = queueByArn(target);
    if (!dlq) {
      throw errors.invalidAttributeValue(`Value ${raw} for parameter RedrivePolicy is invalid. Reason: Dead letter target does not exist.`);
    }
    if (dlq.redriveAllowPolicy) {
      const allow = JSON.parse(dlq.redriveAllowPolicy) as { redrivePermission?: string; sourceQueueArns?: string[] };
      const sourceArn = arnFor(queueName);
      const allowed = allow.redrivePermission === 'allowAll'
        || (allow.redrivePermission === 'byQueue' && (allow.sourceQueueArns ?? []).includes(sourceArn));
      if (!allowed) {
        throw errors.invalidAttributeValue(`Value ${raw} for parameter RedrivePolicy is invalid. Reason: Queue ${sourceArn} is not allowed to use ${target} as its dead-letter queue.`);
      }
    }
    return { deadLetterTargetArn: target, maxReceiveCount: count };
  }

  function parseRedriveAllowPolicy(raw: string): string | null {
    if (raw === '') return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw errors.invalidAttributeValue('Invalid value for the parameter RedriveAllowPolicy.');
    }
    if (!isPlainObject(parsed)) throw errors.invalidAttributeValue('Invalid value for the parameter RedriveAllowPolicy.');
    const permission = parsed['redrivePermission'];
    if (permission !== 'allowAll' && permission !== 'denyAll' && permission !== 'byQueue') {
      throw errors.invalidAttributeValue('Invalid value for the parameter RedriveAllowPolicy. Reason: redrivePermission must be allowAll, denyAll or byQueue.');
    }
    const sources = parsed['sourceQueueArns'];
    if (permission === 'byQueue') {
      if (!Array.isArray(sources) || sources.length < 1 || sources.length > 10 || !sources.every((s) => typeof s === 'string')) {
        throw errors.invalidAttributeValue('Invalid value for the parameter RedriveAllowPolicy. Reason: sourceQueueArns must list 1 to 10 queue ARNs when redrivePermission is byQueue.');
      }
    } else if (sources !== undefined) {
      throw errors.invalidAttributeValue('Invalid value for the parameter RedriveAllowPolicy. Reason: sourceQueueArns is only allowed when redrivePermission is byQueue.');
    }
    return raw;
  }

  /**
   * Validates a settable-attribute map and returns the changes to apply. Kept
   * separate from applying so a bad attribute leaves the queue untouched.
   */
  function validateAttributes(queueName: string, attributes: unknown): Array<(queue: Queue) => void> {
    if (attributes === undefined) return [];
    if (!isPlainObject(attributes)) throw errors.invalidParameterValue('Attributes must be a map of strings.');
    const changes: Array<(queue: Queue) => void> = [];
    for (const [name, rawValue] of Object.entries(attributes)) {
      if (typeof rawValue !== 'string') throw errors.invalidAttributeValue(`Invalid value for the parameter ${name}.`);
      const value = rawValue;
      if ((UNSUPPORTED_SETTABLE_ATTRIBUTES as readonly string[]).includes(name)) {
        if (name === 'FifoQueue' && value === 'false') continue; // a standard queue, which is what this is
        throw errors.unsupported(`Queue attribute ${name}`);
      }
      if (!(SETTABLE_ATTRIBUTES as readonly string[]).includes(name)) {
        throw errors.invalidAttributeName(`Unknown Attribute ${name}.`);
      }
      switch (name as (typeof SETTABLE_ATTRIBUTES)[number]) {
        case 'VisibilityTimeout': {
          const v = integerAttribute(name, value, 0, MAX_VISIBILITY_TIMEOUT);
          changes.push((q) => { q.visibilityTimeout = v; });
          break;
        }
        case 'MaximumMessageSize': {
          const v = integerAttribute(name, value, MIN_MESSAGE_SIZE_ATTRIBUTE, MAX_MESSAGE_SIZE);
          changes.push((q) => { q.maximumMessageSize = v; });
          break;
        }
        case 'MessageRetentionPeriod': {
          const v = integerAttribute(name, value, MIN_RETENTION, MAX_RETENTION);
          changes.push((q) => { q.messageRetentionPeriod = v; });
          break;
        }
        case 'DelaySeconds': {
          const v = integerAttribute(name, value, 0, MAX_DELAY_SECONDS);
          changes.push((q) => { q.delaySeconds = v; });
          break;
        }
        case 'ReceiveMessageWaitTimeSeconds': {
          const v = integerAttribute(name, value, 0, MAX_WAIT_SECONDS);
          changes.push((q) => { q.receiveMessageWaitTimeSeconds = v; });
          break;
        }
        case 'RedrivePolicy': {
          const v = parseRedrivePolicy(queueName, value);
          changes.push((q) => { q.redrivePolicy = v; });
          break;
        }
        case 'RedriveAllowPolicy': {
          const v = parseRedriveAllowPolicy(value);
          changes.push((q) => { q.redriveAllowPolicy = v; });
          break;
        }
        case 'SqsManagedSseEnabled': {
          if (value !== 'true' && value !== 'false') throw errors.invalidAttributeValue(`Invalid value for the parameter ${name}.`);
          changes.push((q) => { q.sqsManagedSseEnabled = value === 'true'; });
          break;
        }
      }
    }
    return changes;
  }

  function validateTags(tags: unknown): Record<string, string> {
    if (tags === undefined) return {};
    if (!isPlainObject(tags)) throw errors.invalidParameterValue('Tags must be a map of strings.');
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(tags)) {
      if (typeof value !== 'string') throw errors.invalidParameterValue(`Tag ${key} must have a string value.`);
      out[key] = value;
    }
    if (Object.keys(out).length > 50) throw errors.invalidParameterValue('Too many tags added for queue. The maximum is 50.');
    return out;
  }

  // ── Message validation ────────────────────────────────────────────────────

  function validateMessageAttributes(raw: unknown): Record<string, SqsMessageAttributeValue> {
    if (raw === undefined) return {};
    if (!isPlainObject(raw)) throw errors.invalidParameterValue('MessageAttributes must be a map.');
    const names = Object.keys(raw);
    if (names.length > MAX_MESSAGE_ATTRIBUTES) {
      throw errors.invalidParameterValue(`Number of message attributes [${names.length}] exceeds the allowed maximum [${MAX_MESSAGE_ATTRIBUTES}].`);
    }
    const out: Record<string, SqsMessageAttributeValue> = {};
    for (const name of names) {
      const value = raw[name];
      if (!/^[A-Za-z0-9_.-]{1,256}$/.test(name) || name.startsWith('.') || name.endsWith('.') || name.includes('..')) {
        throw errors.invalidParameterValue(`Message attribute name '${name}' is invalid.`);
      }
      if (/^(aws\.|amazon\.)/i.test(name)) {
        throw errors.invalidParameterValue(`Message attribute name '${name}' is reserved for use by AWS.`);
      }
      if (!isPlainObject(value)) throw errors.invalidParameterValue(`The message attribute '${name}' must be an object.`);
      for (const key of Object.keys(value)) {
        if (key === 'StringListValues' || key === 'BinaryListValues') {
          throw errors.unsupported(`Message attribute field ${key} (SQS itself answers "not implemented")`);
        }
        if (key !== 'DataType' && key !== 'StringValue' && key !== 'BinaryValue') {
          throw errors.invalidParameterValue(`The message attribute '${name}' has an unknown field ${key}.`);
        }
      }
      const dataType = value['DataType'];
      if (typeof dataType !== 'string' || !dataType) {
        throw errors.invalidParameterValue(`The message attribute '${name}' must contain a non-empty attribute type.`);
      }
      const baseType = dataType.split('.')[0];
      if (baseType !== 'String' && baseType !== 'Number' && baseType !== 'Binary') {
        throw errors.invalidParameterValue(`The type of message (user) attribute '${name}' is invalid. You must use only the following supported type prefixes: Binary, Number, String.`);
      }
      const stringValue = value['StringValue'];
      const binaryValue = value['BinaryValue'];
      if (baseType === 'Binary') {
        if (typeof binaryValue !== 'string' || binaryValue.length === 0 || stringValue !== undefined) {
          throw errors.invalidParameterValue(`The message attribute '${name}' with type 'Binary' must use field 'Binary'.`);
        }
        out[name] = { DataType: dataType, BinaryValue: binaryValue };
      } else {
        if (typeof stringValue !== 'string' || stringValue.length === 0 || binaryValue !== undefined) {
          throw errors.invalidParameterValue(`The message attribute '${name}' with type '${baseType}' must use field 'String'.`);
        }
        if (baseType === 'Number' && !/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(stringValue)) {
          throw errors.invalidParameterValue(`Can't cast the value of message (user) attribute '${name}' to a number.`);
        }
        if (!hasOnlyAllowedCharacters(stringValue)) {
          throw errors.invalidParameterValue(`Message (user) attribute '${name}' value contains invalid characters.`);
        }
        out[name] = { DataType: dataType, StringValue: stringValue };
      }
    }
    return out;
  }

  interface SendInput {
    body: string;
    delaySeconds: number | undefined;
    attributes: Record<string, SqsMessageAttributeValue>;
    awsTraceHeader: string | null;
    messageGroupId: string | null;
  }

  function validateSendInput(queue: Queue, entry: Json): SendInput {
    if (entry['MessageDeduplicationId'] !== undefined) {
      throw errors.invalidParameterValue('The request include parameter that is not valid for this queue type. Reason: MessageDeduplicationId applies only to FIFO queues.');
    }
    const body = entry['MessageBody'];
    if (body === undefined || body === null || body === '') throw errors.missingParameter('MessageBody');
    if (typeof body !== 'string') throw errors.invalidParameterValue('MessageBody must be a string.');
    if (!hasOnlyAllowedCharacters(body)) {
      throw new SqsError('InvalidMessageContents', 'InvalidMessageContents',
        'Invalid characters found. Valid unicode characters are #x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF');
    }
    const delaySeconds = optionalInteger(entry, 'DelaySeconds', 0, MAX_DELAY_SECONDS, 'DelaySeconds must be >= 0 and <= 900.');
    const attributes = validateMessageAttributes(entry['MessageAttributes']);
    let awsTraceHeader: string | null = null;
    const system = entry['MessageSystemAttributes'];
    if (system !== undefined) {
      if (!isPlainObject(system)) throw errors.invalidParameterValue('MessageSystemAttributes must be a map.');
      for (const [name, value] of Object.entries(system)) {
        if (name !== 'AWSTraceHeader') {
          throw errors.invalidParameterValue(`Message system attribute name '${name}' is invalid.`);
        }
        const v = isPlainObject(value) ? value['StringValue'] : undefined;
        if (!isPlainObject(value) || value['DataType'] !== 'String' || typeof v !== 'string') {
          throw errors.invalidParameterValue("Message system attribute 'AWSTraceHeader' must be of type String.");
        }
        awsTraceHeader = v;
      }
    }
    const group = entry['MessageGroupId'];
    if (group !== undefined && (typeof group !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(group))) {
      throw errors.invalidParameterValue('Value for parameter MessageGroupId is invalid.');
    }
    const size = messageSize(body, attributes);
    if (size > queue.maximumMessageSize) {
      throw errors.invalidParameterValue(`One or more parameters are invalid. Reason: Message must be shorter than ${queue.maximumMessageSize} bytes.`);
    }
    return { body, delaySeconds, attributes, awsTraceHeader, messageGroupId: typeof group === 'string' ? group : null };
  }

  function enqueue(queue: Queue, input: SendInput): StoredMessage {
    const at = now();
    const delay = input.delaySeconds ?? queue.delaySeconds;
    const message: StoredMessage = {
      messageId: randomUUID(),
      body: input.body,
      md5OfBody: md5Hex(Buffer.from(input.body, 'utf8')),
      messageAttributes: input.attributes,
      md5OfMessageAttributes: md5OfMessageAttributes(input.attributes),
      awsTraceHeader: input.awsTraceHeader,
      messageGroupId: input.messageGroupId,
      sentTimestamp: at,
      delayedUntil: at + delay * 1000,
      inFlightUntil: 0,
      receivedAt: null,
      receiveCount: 0,
      firstReceiveTimestamp: null,
      receiptHandle: null,
      deadLetterQueueSourceArn: null,
    };
    queue.messages.push(message);
    wakeWaiters();
    return message;
  }

  function sendResult(message: StoredMessage): Json {
    const result: Json = { MessageId: message.messageId, MD5OfMessageBody: message.md5OfBody };
    if (message.md5OfMessageAttributes) result['MD5OfMessageAttributes'] = message.md5OfMessageAttributes;
    return result;
  }

  // ── Batch validation ──────────────────────────────────────────────────────

  function validateBatchEntries(op: string, entries: unknown, allowed: readonly string[]): Json[] {
    if (entries === undefined || entries === null) throw errors.missingParameter('Entries');
    if (!Array.isArray(entries) || entries.length === 0) {
      throw new SqsError('EmptyBatchRequest', 'AWS.SimpleQueueService.EmptyBatchRequest',
        'There should be at least one SendMessageBatchRequestEntry in the request.'.replace('SendMessageBatch', op));
    }
    if (entries.length > MAX_BATCH_ENTRIES) {
      throw new SqsError('TooManyEntriesInBatchRequest', 'AWS.SimpleQueueService.TooManyEntriesInBatchRequest',
        `Maximum number of entries per request are ${MAX_BATCH_ENTRIES}. You have sent ${entries.length}.`);
    }
    const ids = new Set<string>();
    for (const entry of entries) {
      if (!isPlainObject(entry)) throw errors.invalidParameterValue('Each batch entry must be an object.');
      requireAllowedKeys(op, entry, allowed, 'Entries[].');
      const id = entry['Id'];
      if (typeof id !== 'string' || !BATCH_ENTRY_ID.test(id)) {
        throw new SqsError('InvalidBatchEntryId', 'AWS.SimpleQueueService.InvalidBatchEntryId',
          'A batch entry id can only contain alphanumeric characters, hyphens and underscores. It can be at most 80 letters long.');
      }
      if (ids.has(id)) {
        throw new SqsError('BatchEntryIdsNotDistinct', 'AWS.SimpleQueueService.BatchEntryIdsNotDistinct',
          `Id ${id} repeated.`);
      }
      ids.add(id);
    }
    return entries as Json[];
  }

  function batchFailure(id: string, err: unknown): Json {
    if (err instanceof SqsError) {
      return { Id: id, SenderFault: err.fault === 'Sender', Code: err.queryCode, Message: err.message };
    }
    throw err;
  }

  // ── Receive ───────────────────────────────────────────────────────────────

  function selectMessageAttributes(message: StoredMessage, names: readonly string[]): Record<string, SqsMessageAttributeValue> | undefined {
    if (names.length === 0) return undefined;
    const out: Record<string, SqsMessageAttributeValue> = {};
    for (const [name, value] of Object.entries(message.messageAttributes)) {
      const wanted = names.some((pattern) => {
        if (pattern === 'All' || pattern === '.*') return true;
        if (pattern.endsWith('.*')) return name.startsWith(pattern.slice(0, -1));
        return pattern === name;
      });
      if (wanted) out[name] = value;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }

  function selectSystemAttributes(message: StoredMessage, names: ReadonlySet<string>): Record<string, string> | undefined {
    if (names.size === 0) return undefined;
    const all = names.has('All');
    const want = (name: string): boolean => all || names.has(name);
    const out: Record<string, string> = {};
    if (want('SenderId')) out['SenderId'] = accountId;
    if (want('SentTimestamp')) out['SentTimestamp'] = String(message.sentTimestamp);
    if (want('ApproximateReceiveCount')) out['ApproximateReceiveCount'] = String(message.receiveCount);
    if (want('ApproximateFirstReceiveTimestamp') && message.firstReceiveTimestamp !== null) {
      out['ApproximateFirstReceiveTimestamp'] = String(message.firstReceiveTimestamp);
    }
    if (want('AWSTraceHeader') && message.awsTraceHeader !== null) out['AWSTraceHeader'] = message.awsTraceHeader;
    if (want('MessageGroupId') && message.messageGroupId !== null) out['MessageGroupId'] = message.messageGroupId;
    if (want('DeadLetterQueueSourceArn') && message.deadLetterQueueSourceArn !== null) {
      out['DeadLetterQueueSourceArn'] = message.deadLetterQueueSourceArn;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }

  interface ReceiveRequest {
    max: number;
    visibilityTimeout: number | undefined;
    systemNames: Set<string>;
    messageAttributeNames: string[];
  }

  /**
   * One receive attempt. A message whose receive count has already reached the
   * queue's maxReceiveCount is moved to the dead-letter queue instead of being
   * delivered, which is when real SQS moves it: on the receive that would push
   * ReceiveCount past maxReceiveCount.
   */
  function tryReceive(queue: Queue, request: ReceiveRequest): Json[] {
    dropExpired(queue);
    const at = now();
    const delivered: Json[] = [];
    for (const message of [...queue.messages]) {
      if (delivered.length >= request.max) break;
      if (stateOf(message, at) !== 'available') continue;
      if (queue.redrivePolicy && message.receiveCount >= queue.redrivePolicy.maxReceiveCount) {
        const dlq = queueByArn(queue.redrivePolicy.deadLetterTargetArn);
        if (dlq) {
          queue.messages.splice(queue.messages.indexOf(message), 1);
          message.receiptHandle = null;
          message.inFlightUntil = 0;
          message.delayedUntil = 0;
          message.receivedAt = null;
          message.deadLetterQueueSourceArn = queue.arn;
          dlq.messages.push(message);
          continue;
        }
      }
      message.receiveCount += 1;
      message.firstReceiveTimestamp ??= at;
      message.receiptHandle = newReceiptHandle(queue, message);
      message.receivedAt = at;
      message.inFlightUntil = at + (request.visibilityTimeout ?? queue.visibilityTimeout) * 1000;
      const out: Json = {
        MessageId: message.messageId,
        ReceiptHandle: message.receiptHandle,
        MD5OfBody: message.md5OfBody,
        Body: message.body,
      };
      const system = selectSystemAttributes(message, request.systemNames);
      if (system) out['Attributes'] = system;
      const attributes = selectMessageAttributes(message, request.messageAttributeNames);
      if (attributes) {
        out['MessageAttributes'] = attributes;
        out['MD5OfMessageAttributes'] = md5OfMessageAttributes(attributes);
      }
      delivered.push(out);
    }
    return delivered;
  }

  async function receiveWithWait(queue: Queue, request: ReceiveRequest, waitSeconds: number, req: express.Request): Promise<Json[]> {
    const first = tryReceive(queue, request);
    if (first.length > 0 || waitSeconds === 0) return first;

    const startedReal = Date.now();
    const startedSim = now();
    const deadlineMs = waitSeconds * 1000;
    const res = req.res;
    return new Promise<Json[]>((resolve) => {
      let done = false;
      const finish = (messages: Json[]): void => {
        if (done) return;
        done = true;
        waiters.delete(check);
        clearInterval(timer);
        res?.off('close', onClose);
        resolve(messages);
      };
      const check = (): void => {
        if (done) return;
        if (queues.get(queue.name) !== queue) {
          finish([]); // deleted or reset while waiting
          return;
        }
        const messages = tryReceive(queue, request);
        if (messages.length > 0) {
          finish(messages);
          return;
        }
        if (Date.now() - startedReal >= deadlineMs || now() - startedSim >= deadlineMs) finish([]);
      };
      const onClose = (): void => finish([]);
      const timer = setInterval(check, LONG_POLL_TICK_MS);
      waiters.add(check);
      // The response, not the request: a request emits 'close' as soon as its
      // body has been read, which would end every long poll at once.
      res?.on('close', onClose);
    });
  }

  // ── Visibility ────────────────────────────────────────────────────────────

  function changeVisibility(queue: Queue, receiptHandle: string, visibilityTimeout: number): void {
    const { messageId } = decodeReceiptHandle(queue, receiptHandle);
    const message = queue.messages.find((m) => m.messageId === messageId);
    if (!message || message.receiptHandle !== receiptHandle) {
      throw errors.invalidParameterValue(`Value ${receiptHandle} for parameter ReceiptHandle is invalid. Reason: Message does not exist or is not available for visibility timeout change.`);
    }
    const at = now();
    if (message.inFlightUntil <= at) {
      throw new SqsError('MessageNotInflight', 'AWS.SimpleQueueService.MessageNotInflight', 'Message is not in flight.');
    }
    const receivedAt = message.receivedAt ?? at;
    if (at + visibilityTimeout * 1000 - receivedAt > MAX_VISIBILITY_TIMEOUT * 1000) {
      throw errors.invalidParameterValue(`Value ${visibilityTimeout} for parameter VisibilityTimeout is invalid. Reason: Total VisibilityTimeout for the message is beyond the limit [${MAX_VISIBILITY_TIMEOUT} seconds]`);
    }
    message.inFlightUntil = at + visibilityTimeout * 1000;
    if (visibilityTimeout === 0) wakeWaiters();
  }

  function deleteByHandle(queue: Queue, receiptHandle: string): void {
    const { messageId } = decodeReceiptHandle(queue, receiptHandle);
    // Real SQS: an old receipt handle "will succeed, but the message might not
    // be deleted". The simulator takes the strict reading: only the handle
    // from the most recent receive deletes, and anything else is a silent
    // success, so a consumer that loses its lease sees the message again.
    const index = queue.messages.findIndex((m) => m.messageId === messageId && m.receiptHandle === receiptHandle);
    if (index >= 0) queue.messages.splice(index, 1);
  }

  // ── Operations ────────────────────────────────────────────────────────────

  type Handler = (body: Json, req: express.Request) => Json | Promise<Json>;

  const handlers: Record<string, Handler> = {
    CreateQueue(body, req) {
      requireAllowedKeys('CreateQueue', body, ['QueueName', 'Attributes', 'tags']);
      const name = requireString(body, 'QueueName');
      if (name.endsWith('.fifo')) throw errors.unsupported('FIFO queues (a QueueName ending in .fifo)');
      if (!QUEUE_NAME.test(name)) {
        throw errors.invalidParameterValue('Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length');
      }
      const changes = validateAttributes(name, body['Attributes']);
      const tags = validateTags(body['tags']);
      const existing = queues.get(name);
      if (existing) {
        // Idempotent when every given attribute matches the existing queue.
        const probe: Queue = { ...existing, messages: [] };
        for (const change of changes) change(probe);
        const current = queueAttributes(existing);
        const wanted = queueAttributes(probe);
        for (const key of Object.keys(isPlainObject(body['Attributes']) ? body['Attributes'] : {})) {
          if (current[key] !== wanted[key]) {
            throw new SqsError('QueueNameExists', 'QueueAlreadyExists',
              `A queue already exists with the same name and a different value for attribute ${key}`);
          }
        }
        return { QueueUrl: urlFor(req.headers.host ?? 'localhost', name) };
      }
      const deleted = deletedAt.get(name);
      if (deleted !== undefined && now() - deleted < QUEUE_RECREATE_COOLDOWN_MS) {
        throw new SqsError('QueueDeletedRecently', 'AWS.SimpleQueueService.QueueDeletedRecently',
          'You must wait 60 seconds after deleting a queue before you can create another with the same name.');
      }
      const at = now();
      const queue: Queue = {
        name,
        arn: arnFor(name),
        createdAt: at,
        lastModifiedAt: at,
        visibilityTimeout: 30,
        delaySeconds: 0,
        messageRetentionPeriod: DEFAULT_RETENTION,
        maximumMessageSize: MAX_MESSAGE_SIZE,
        receiveMessageWaitTimeSeconds: 0,
        redrivePolicy: null,
        redriveAllowPolicy: null,
        sqsManagedSseEnabled: true,
        lastPurgeAt: null,
        tags,
        messages: [],
      };
      for (const change of changes) change(queue);
      queues.set(name, queue);
      return { QueueUrl: urlFor(req.headers.host ?? 'localhost', name) };
    },

    GetQueueUrl(body, req) {
      requireAllowedKeys('GetQueueUrl', body, ['QueueName', 'QueueOwnerAWSAccountId']);
      const name = requireString(body, 'QueueName');
      const owner = body['QueueOwnerAWSAccountId'];
      if (owner !== undefined && owner !== accountId) throw errors.queueDoesNotExist();
      if (!queues.has(name)) throw errors.queueDoesNotExist();
      return { QueueUrl: urlFor(req.headers.host ?? 'localhost', name) };
    },

    ListQueues(body, req) {
      requireAllowedKeys('ListQueues', body, ['QueueNamePrefix', 'NextToken', 'MaxResults']);
      const prefix = typeof body['QueueNamePrefix'] === 'string' ? body['QueueNamePrefix'] : '';
      const maxResults = optionalInteger(body, 'MaxResults', 1, 1000, 'MaxResults must be an integer between 1 and 1000.');
      const names = [...queues.keys()].filter((n) => n.startsWith(prefix)).sort();
      let start = 0;
      if (body['NextToken'] !== undefined) {
        if (maxResults === undefined) throw errors.invalidParameterValue('MaxResults is a mandatory parameter when you provide a value for NextToken.');
        const token = String(body['NextToken']);
        const after = Buffer.from(token, 'base64').toString('utf8');
        start = names.findIndex((n) => n > after);
        if (start < 0) start = names.length;
      }
      const page = maxResults === undefined ? names.slice(start, start + 1000) : names.slice(start, start + maxResults);
      const result: Json = {};
      if (page.length > 0) result['QueueUrls'] = page.map((n) => urlFor(req.headers.host ?? 'localhost', n));
      if (maxResults !== undefined && start + page.length < names.length) {
        result['NextToken'] = Buffer.from(page[page.length - 1]!, 'utf8').toString('base64');
      }
      return result;
    },

    DeleteQueue(body) {
      requireAllowedKeys('DeleteQueue', body, ['QueueUrl']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      queues.delete(queue.name);
      deletedAt.set(queue.name, now());
      wakeWaiters();
      return {};
    },

    GetQueueAttributes(body) {
      requireAllowedKeys('GetQueueAttributes', body, ['QueueUrl', 'AttributeNames']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      const names = body['AttributeNames'] === undefined ? [] : body['AttributeNames'];
      if (!Array.isArray(names)) throw errors.invalidParameterValue('AttributeNames must be a list.');
      for (const name of names) {
        if (typeof name !== 'string' || !(READABLE_ATTRIBUTES as readonly string[]).includes(name)) {
          throw errors.invalidAttributeName(`Unknown Attribute ${String(name)}.`);
        }
      }
      const all = queueAttributes(queue);
      const selected: Record<string, string> = {};
      for (const [key, value] of Object.entries(all)) {
        if (names.includes('All') || names.includes(key)) selected[key] = value;
      }
      return Object.keys(selected).length > 0 ? { Attributes: selected } : {};
    },

    SetQueueAttributes(body) {
      requireAllowedKeys('SetQueueAttributes', body, ['QueueUrl', 'Attributes']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      if (body['Attributes'] === undefined) throw errors.missingParameter('Attributes');
      const changes = validateAttributes(queue.name, body['Attributes']);
      for (const change of changes) change(queue);
      queue.lastModifiedAt = now();
      dropExpired(queue);
      return {};
    },

    SendMessage(body) {
      requireAllowedKeys('SendMessage', body, [
        'QueueUrl', 'MessageBody', 'DelaySeconds', 'MessageAttributes', 'MessageSystemAttributes',
        'MessageGroupId', 'MessageDeduplicationId',
      ]);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      const input = validateSendInput(queue, body);
      return sendResult(enqueue(queue, input));
    },

    SendMessageBatch(body) {
      requireAllowedKeys('SendMessageBatch', body, ['QueueUrl', 'Entries']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      const entries = validateBatchEntries('SendMessageBatch', body['Entries'], [
        'Id', 'MessageBody', 'DelaySeconds', 'MessageAttributes', 'MessageSystemAttributes',
        'MessageGroupId', 'MessageDeduplicationId',
      ]);
      let total = 0;
      for (const entry of entries) {
        const b = typeof entry['MessageBody'] === 'string' ? entry['MessageBody'] : '';
        const attrs = isPlainObject(entry['MessageAttributes']) ? entry['MessageAttributes'] as Record<string, SqsMessageAttributeValue> : {};
        try {
          total += messageSize(b, attrs);
        } catch {
          // A malformed entry fails on its own below.
        }
      }
      if (total > queue.maximumMessageSize) {
        throw new SqsError('BatchRequestTooLong', 'AWS.SimpleQueueService.BatchRequestTooLong',
          `Batch requests cannot be longer than ${queue.maximumMessageSize} bytes. You have sent ${total} bytes.`);
      }
      const successful: Json[] = [];
      const failed: Json[] = [];
      for (const entry of entries) {
        const id = entry['Id'] as string;
        try {
          const input = validateSendInput(queue, entry);
          successful.push({ Id: id, ...sendResult(enqueue(queue, input)) });
        } catch (err) {
          failed.push(batchFailure(id, err));
        }
      }
      return { Successful: successful, Failed: failed };
    },

    async ReceiveMessage(body, req) {
      requireAllowedKeys('ReceiveMessage', body, [
        'QueueUrl', 'AttributeNames', 'MessageSystemAttributeNames', 'MessageAttributeNames',
        'MaxNumberOfMessages', 'VisibilityTimeout', 'WaitTimeSeconds', 'ReceiveRequestAttemptId',
      ]);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      if (body['ReceiveRequestAttemptId'] !== undefined) {
        throw errors.unsupported('ReceiveRequestAttemptId (FIFO queues only)');
      }
      const max = optionalInteger(body, 'MaxNumberOfMessages', 1, 10, 'Must be between 1 and 10, if provided.') ?? 1;
      const visibilityTimeout = optionalInteger(body, 'VisibilityTimeout', 0, MAX_VISIBILITY_TIMEOUT,
        'Must be between 0 and 43200, if provided.');
      const wait = optionalInteger(body, 'WaitTimeSeconds', 0, MAX_WAIT_SECONDS, 'Must be >= 0 and <= 20, if provided.')
        ?? queue.receiveMessageWaitTimeSeconds;
      const systemNames = new Set<string>();
      for (const key of ['AttributeNames', 'MessageSystemAttributeNames'] as const) {
        const list = body[key];
        if (list === undefined) continue;
        if (!Array.isArray(list)) throw errors.invalidParameterValue(`${key} must be a list.`);
        for (const name of list) {
          if (typeof name !== 'string' || !(SYSTEM_ATTRIBUTE_NAMES as readonly string[]).includes(name)) {
            throw errors.invalidAttributeName(`Unknown Attribute ${String(name)}.`);
          }
          systemNames.add(name);
        }
      }
      const messageAttributeNames = body['MessageAttributeNames'] ?? [];
      if (!Array.isArray(messageAttributeNames) || !messageAttributeNames.every((n) => typeof n === 'string')) {
        throw errors.invalidParameterValue('MessageAttributeNames must be a list of strings.');
      }
      const messages = await receiveWithWait(queue, {
        max,
        visibilityTimeout,
        systemNames,
        messageAttributeNames: messageAttributeNames as string[],
      }, wait, req);
      return messages.length > 0 ? { Messages: messages } : {};
    },

    DeleteMessage(body) {
      requireAllowedKeys('DeleteMessage', body, ['QueueUrl', 'ReceiptHandle']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      deleteByHandle(queue, requireString(body, 'ReceiptHandle'));
      return {};
    },

    DeleteMessageBatch(body) {
      requireAllowedKeys('DeleteMessageBatch', body, ['QueueUrl', 'Entries']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      const entries = validateBatchEntries('DeleteMessageBatch', body['Entries'], ['Id', 'ReceiptHandle']);
      const successful: Json[] = [];
      const failed: Json[] = [];
      for (const entry of entries) {
        const id = entry['Id'] as string;
        try {
          deleteByHandle(queue, requireString(entry, 'ReceiptHandle'));
          successful.push({ Id: id });
        } catch (err) {
          failed.push(batchFailure(id, err));
        }
      }
      return { Successful: successful, Failed: failed };
    },

    ChangeMessageVisibility(body) {
      requireAllowedKeys('ChangeMessageVisibility', body, ['QueueUrl', 'ReceiptHandle', 'VisibilityTimeout']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      const handle = requireString(body, 'ReceiptHandle');
      if (body['VisibilityTimeout'] === undefined) throw errors.missingParameter('VisibilityTimeout');
      const timeout = optionalInteger(body, 'VisibilityTimeout', 0, MAX_VISIBILITY_TIMEOUT,
        'VisibilityTimeout must be an integer between 0 and 43200.')!;
      changeVisibility(queue, handle, timeout);
      return {};
    },

    ChangeMessageVisibilityBatch(body) {
      requireAllowedKeys('ChangeMessageVisibilityBatch', body, ['QueueUrl', 'Entries']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      const entries = validateBatchEntries('ChangeMessageVisibilityBatch', body['Entries'],
        ['Id', 'ReceiptHandle', 'VisibilityTimeout']);
      const successful: Json[] = [];
      const failed: Json[] = [];
      for (const entry of entries) {
        const id = entry['Id'] as string;
        try {
          const timeout = optionalInteger(entry, 'VisibilityTimeout', 0, MAX_VISIBILITY_TIMEOUT,
            'VisibilityTimeout must be an integer between 0 and 43200.') ?? 0;
          changeVisibility(queue, requireString(entry, 'ReceiptHandle'), timeout);
          successful.push({ Id: id });
        } catch (err) {
          failed.push(batchFailure(id, err));
        }
      }
      return { Successful: successful, Failed: failed };
    },

    PurgeQueue(body) {
      requireAllowedKeys('PurgeQueue', body, ['QueueUrl']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      const at = now();
      if (queue.lastPurgeAt !== null && at - queue.lastPurgeAt < PURGE_COOLDOWN_MS) {
        throw new SqsError('PurgeQueueInProgress', 'AWS.SimpleQueueService.PurgeQueueInProgress',
          `Only one PurgeQueue operation on ${queue.name} is allowed every 60 seconds.`, 403);
      }
      queue.lastPurgeAt = at;
      queue.messages = [];
      return {};
    },

    ListDeadLetterSourceQueues(body, req) {
      requireAllowedKeys('ListDeadLetterSourceQueues', body, ['QueueUrl', 'NextToken', 'MaxResults']);
      const dlq = queueFromUrl(requireString(body, 'QueueUrl'));
      if (body['NextToken'] !== undefined) throw errors.unsupported('NextToken on ListDeadLetterSourceQueues');
      const max = optionalInteger(body, 'MaxResults', 1, 1000, 'MaxResults must be an integer between 1 and 1000.') ?? 1000;
      const sources = [...queues.values()]
        .filter((q) => q.redrivePolicy?.deadLetterTargetArn === dlq.arn)
        .map((q) => q.name)
        .sort()
        .slice(0, max);
      return { queueUrls: sources.map((n) => urlFor(req.headers.host ?? 'localhost', n)) };
    },

    StartMessageMoveTask(body) {
      requireAllowedKeys('StartMessageMoveTask', body, ['SourceArn', 'DestinationArn', 'MaxNumberOfMessagesPerSecond']);
      const sourceArn = requireString(body, 'SourceArn');
      const source = queueByArn(sourceArn);
      if (!source) throw errors.resourceNotFound('The resource that you specified for the SourceArn parameter doesn\'t exist.');
      const rate = optionalInteger(body, 'MaxNumberOfMessagesPerSecond', 1, 500,
        'MaxNumberOfMessagesPerSecond must be between 1 and 500.');
      const isDlq = [...queues.values()].some((q) => q.redrivePolicy?.deadLetterTargetArn === sourceArn);
      if (!isDlq) throw errors.invalidParameterValue('Source queue must be configured as a Dead Letter Queue.');
      const destinationArn = typeof body['DestinationArn'] === 'string' ? body['DestinationArn'] : null;
      const destination = destinationArn === null ? null : queueByArn(destinationArn);
      if (destinationArn !== null && !destination) {
        throw errors.resourceNotFound('The resource that you specified for the DestinationArn parameter doesn\'t exist.');
      }
      dropExpired(source);
      const at = now();
      // The move runs to completion before the response: every message that is
      // not in flight moves. In-flight messages stay in the DLQ.
      const toMove = source.messages.filter((m) => stateOf(m, at) !== 'in-flight');
      let moved = 0;
      let failureReason: string | null = null;
      for (const message of toMove) {
        const target = destination ?? (message.deadLetterQueueSourceArn ? queueByArn(message.deadLetterQueueSourceArn) : undefined);
        if (!target) {
          failureReason = 'CouldNotDetermineMessageSource';
          continue;
        }
        source.messages.splice(source.messages.indexOf(message), 1);
        message.receiveCount = 0;
        message.firstReceiveTimestamp = null;
        message.receiptHandle = null;
        message.receivedAt = null;
        message.inFlightUntil = 0;
        message.delayedUntil = 0;
        message.deadLetterQueueSourceArn = null;
        target.messages.push(message);
        moved += 1;
      }
      const task: MoveTask = {
        taskHandle: Buffer.from(JSON.stringify({ taskId: randomUUID(), sourceArn }), 'utf8').toString('base64'),
        sourceArn,
        destinationArn,
        maxNumberOfMessagesPerSecond: rate ?? null,
        startedTimestamp: at,
        status: failureReason ? 'FAILED' : 'COMPLETED',
        approximateNumberOfMessagesMoved: moved,
        approximateNumberOfMessagesToMove: toMove.length,
        failureReason,
      };
      moveTasks.push(task);
      wakeWaiters();
      return { TaskHandle: task.taskHandle };
    },

    ListMessageMoveTasks(body) {
      requireAllowedKeys('ListMessageMoveTasks', body, ['SourceArn', 'MaxResults']);
      const sourceArn = requireString(body, 'SourceArn');
      if (!queueByArn(sourceArn)) throw errors.resourceNotFound('The resource that you specified for the SourceArn parameter doesn\'t exist.');
      const max = optionalInteger(body, 'MaxResults', 1, 10, 'MaxResults must be between 1 and 10.') ?? 1;
      const results = moveTasks
        .filter((t) => t.sourceArn === sourceArn)
        .slice()
        .reverse()
        .slice(0, max)
        .map((t) => {
          // A TaskHandle is only returned for a RUNNING task, and every task
          // here has already finished.
          const out: Json = {
            Status: t.status,
            SourceArn: t.sourceArn,
            ApproximateNumberOfMessagesMoved: t.approximateNumberOfMessagesMoved,
            ApproximateNumberOfMessagesToMove: t.approximateNumberOfMessagesToMove,
            StartedTimestamp: t.startedTimestamp,
          };
          if (t.destinationArn) out['DestinationArn'] = t.destinationArn;
          if (t.maxNumberOfMessagesPerSecond !== null) out['MaxNumberOfMessagesPerSecond'] = t.maxNumberOfMessagesPerSecond;
          if (t.failureReason) out['FailureReason'] = t.failureReason;
          return out;
        });
      return { Results: results };
    },

    TagQueue(body) {
      requireAllowedKeys('TagQueue', body, ['QueueUrl', 'Tags']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      if (body['Tags'] === undefined) throw errors.missingParameter('Tags');
      const merged = { ...queue.tags, ...validateTags(body['Tags']) };
      queue.tags = validateTags(merged);
      return {};
    },

    UntagQueue(body) {
      requireAllowedKeys('UntagQueue', body, ['QueueUrl', 'TagKeys']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      const keys = body['TagKeys'];
      if (!Array.isArray(keys)) throw errors.missingParameter('TagKeys');
      for (const key of keys) delete queue.tags[String(key)];
      return {};
    },

    ListQueueTags(body) {
      requireAllowedKeys('ListQueueTags', body, ['QueueUrl']);
      const queue = queueFromUrl(requireString(body, 'QueueUrl'));
      return Object.keys(queue.tags).length > 0 ? { Tags: { ...queue.tags } } : {};
    },
  };

  /** Real SQS operations that this simulator refuses by name. */
  const UNSUPPORTED_OPERATIONS = ['AddPermission', 'RemovePermission', 'CancelMessageMoveTask'];

  // ── HTTP ──────────────────────────────────────────────────────────────────

  function sendError(res: express.Response, err: SqsError): void {
    res.status(err.status)
      .setHeader('x-amzn-query-error', `${err.queryCode};${err.fault}`)
      .setHeader('x-amzn-RequestId', randomUUID())
      .type('application/x-amz-json-1.0')
      .send(JSON.stringify({ __type: `com.amazonaws.sqs#${err.type}`, message: err.message }));
  }

  const app = express();

  app.post('/__local/reset', (_req, res) => {
    reset();
    res.status(204).end();
  });

  app.post('{*path}', async (req, res) => {
    try {
      const target = req.headers['x-amz-target'];
      if (typeof target !== 'string' || !target) {
        throw errors.unsupported('The SQS query protocol (form-encoded requests without X-Amz-Target); use AWS SDK v3');
      }
      const [prefix, op] = target.split('.');
      if (prefix !== 'AmazonSQS' || !op) {
        throw new SqsError('UnknownOperationException', 'UnknownOperationException', `Unknown target ${target}.`);
      }
      const raw = (await readRawBody(req)).toString('utf8');
      let body: unknown;
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        throw new SqsError('SerializationException', 'SerializationException', 'The request body is not valid JSON.');
      }
      if (!isPlainObject(body)) throw new SqsError('SerializationException', 'SerializationException', 'The request body must be a JSON object.');
      if (UNSUPPORTED_OPERATIONS.includes(op)) throw errors.unsupported(`Operation ${op}`);
      const handler = handlers[op];
      if (!handler) {
        throw new SqsError('UnknownOperationException', 'UnknownOperationException',
          `Operation ${op} is not a known SQS operation, or is not supported by the tested-aws-simulators SQS simulator.`);
      }
      const result = await handler(body, req);
      res.status(200)
        .setHeader('x-amzn-RequestId', randomUUID())
        .type('application/x-amz-json-1.0')
        .send(JSON.stringify(result));
    } catch (err) {
      if (err instanceof SqsError) {
        sendError(res, err);
        return;
      }
      console.error('[sqs-simulator] Error handling request', err);
      sendError(res, new SqsError('InternalError', 'InternalError', 'Internal simulator error', 500, 'Receiver'));
    }
  });

  app.use((req, res) => {
    sendError(res, new SqsError('UnknownOperationException', 'UnknownOperationException',
      `No SQS route for ${req.method} ${req.path}.`, 404));
  });

  // ── Hooks ─────────────────────────────────────────────────────────────────

  function reset(): void {
    queues.clear();
    deletedAt.clear();
    moveTasks.length = 0;
    clockOffset = 0;
    wakeWaiters();
  }

  function listQueues(): readonly SqsQueueSummary[] {
    return [...queues.values()]
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
      .map((q) => {
        dropExpired(q);
        return { name: q.name, arn: q.arn, attributes: queueAttributes(q), tags: { ...q.tags } };
      });
  }

  function peekMessages(queueName: string): readonly SqsPeekedMessage[] {
    const queue = queues.get(queueName);
    if (!queue) throw new Error(`[sqs-simulator] No queue named ${queueName}`);
    dropExpired(queue);
    const at = now();
    return queue.messages.map((m) => ({
      messageId: m.messageId,
      body: m.body,
      messageAttributes: { ...m.messageAttributes },
      state: stateOf(m, at),
      receiveCount: m.receiveCount,
      sentTimestamp: m.sentTimestamp,
      firstReceiveTimestamp: m.firstReceiveTimestamp,
      availableAt: Math.max(m.delayedUntil, m.inFlightUntil, m.sentTimestamp),
      deadLetterQueueSourceArn: m.deadLetterQueueSourceArn,
    }));
  }

  function advanceTime(ms: number): void {
    if (!Number.isFinite(ms) || ms < 0) throw new Error(`[sqs-simulator] advanceTime needs a non-negative number, got ${ms}`);
    clockOffset += ms;
    wakeWaiters();
  }

  return { app, reset, listQueues, peekMessages, advanceTime, now };
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export interface StartSqsSimulatorOptions extends SqsSimulatorOptions {
  /** Default `SQS_SIMULATOR_PORT` env var, else 38309. Pass 0 for a free port. */
  readonly port?: number;
  readonly host?: string;
}

export async function startSqsSimulator(
  options: StartSqsSimulatorOptions = {},
): Promise<RunningSimulator & { readonly simulator: SqsSimulator }> {
  const port = options.port ?? Number(process.env.SQS_SIMULATOR_PORT ?? SQS_SIMULATOR_DEFAULT_PORT);
  const simulator = createSqsSimulator(options);
  const running = await listen(simulator.app, port, options.host);
  console.log(`SQS simulator listening on ${running.url}`);
  return { ...running, simulator };
}
