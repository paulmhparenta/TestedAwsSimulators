# TestedAwsSimulators

Local simulators for AWS services, for development and end-to-end tests. Each
one is a small Express app that answers the real AWS SDK v3 client, and each one
has a test suite that runs the real SDK against it.

| Simulator | Stands in for | Default port | Protocol |
| --- | --- | --- | --- |
| S3 | Amazon S3 | 38304 | REST, path-style (`forcePathStyle: true`) |
| SES | Amazon SES (v1 API) | 38306 | Query protocol (`@aws-sdk/client-ses`) + JSON `x-amz-target` |
| Cognito | Cognito user pool + hosted UI | 38303 | `AWSCognitoIdentityProviderService` JSON + OAuth2/PKCE |
| Transcribe | AWS Transcribe (in process) | — | A `TranscriptionService` port, not HTTP |
| Sentry | Sentry ingest | 38308 | Envelope + store endpoints |
| OpenRouter | OpenRouter / OpenAI-style chat | 38307 | `/api/v1/chat/completions`, `/embeddings`, `/models` |
| SQS | Amazon SQS (standard queues) | 38309 | AWS JSON 1.0 (`AmazonSQS.*`), in memory |
| DynamoDB | Amazon DynamoDB | 38310 | AWS JSON 1.0 (`DynamoDB_20120810.*`), in memory |

Sentry and OpenRouter are not AWS services. They are here because the same
test setup needs them.

## Why

A simulator is only useful when it refuses what the real service refuses. A
simulator that accepts a bad request makes a test suite green on a path that
fails in production. The rule in every file here: where the simulator and the
real service differ, the simulator is wrong. The comments in the source name the
real behaviour each check copies.

## Install

Install from GitHub:

```bash
npm install --save-dev github:paulmorrishill/TestedAwsSimulators
```

The `prepare` script compiles the TypeScript on install. Node 20 or later.

## Run from the command line

```bash
npx tested-aws-simulators
```

With no arguments the command starts S3, SES, Cognito, Sentry, OpenRouter, SQS
and DynamoDB on their default ports. Name the simulators to start only those:

```bash
npx tested-aws-simulators s3 ses
npx tested-aws-simulators sqs dynamodb
```

| Env var | Effect |
| --- | --- |
| `S3_SIMULATOR_PORT`, `SES_SIMULATOR_PORT`, `COGNITO_EMULATOR_PORT`, `SENTRY_SIMULATOR_PORT`, `OPENROUTER_SIMULATOR_PORT`, `SQS_SIMULATOR_PORT`, `DYNAMODB_SIMULATOR_PORT` | Port for that simulator |
| `COGNITO_EMULATOR_USERS_FILE` | JSON file with an array of `CognitoSeedUser` |
| `COGNITO_EMULATOR_CLIENT_ID` | App client id (default `local-web-client`) |
| `COGNITO_EMULATOR_ISSUER` | `iss` claim (default: the request origin) |
| `COGNITO_EMULATOR_REDIRECT_URI` | Redirect used when `/oauth2/authorize` has none |

## Use in code

Every simulator has two entry points:

- `createXxx(options)` returns `{ app, ...state and test hooks }`. Mount `app`
  on your own server or listen on it yourself.
- `startXxx({ port, ...options })` listens and returns
  `{ server, port, url, close(), simulator }`. Pass `port: 0` for a free port.

Every HTTP server sets a five-minute keep-alive timeout. Node's default of five
seconds races pooled client sockets and resets requests at random. The comment
in [src/shared/server.ts](src/shared/server.ts) gives the measurements.

Every simulator answers `POST /__local/reset`, which clears its state.

### S3

```ts
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { startS3Simulator } from 'tested-aws-simulators';

const s3sim = await startS3Simulator({ port: 0, dataDir: '.local-s3' });
const s3 = new S3Client({
  endpoint: s3sim.url,
  region: 'us-east-1',
  forcePathStyle: true,
  credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
});
await s3.send(new PutObjectCommand({ Bucket: 'b', Key: 'k.txt', Body: 'hello', ContentType: 'text/plain' }));
```

Supports PutObject, GetObject (with `Range`), HeadObject, CopyObject,
DeleteObject, and presigned GET and PUT URLs from `@aws-sdk/s3-request-presigner`.
Objects are files under `dataDir/<bucket>/<key>`, so they survive a restart. The
Content-Type given at PUT time is stored and returned on GET. CORS is open, so a
browser can PUT to a presigned URL.

Not supported: ListObjects, multipart upload, versioning, bucket operations.

### SES

```ts
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { startSesSimulator } from 'tested-aws-simulators';

const sessim = await startSesSimulator({
  port: 0,
  // Optional: run your own bounce/complaint handler on a triggered event.
  onNotification: async (notification) => { /* ... */ },
});
const ses = new SESClient({ endpoint: sessim.url, region: 'us-east-1', credentials: { accessKeyId: 'test', secretAccessKey: 'test' } });

await ses.send(new SendEmailCommand({ /* ... */ }));
sessim.simulator.listEmails();            // summaries, oldest first
sessim.simulator.getEmail(id);            // bodies, headers, attachments
sessim.simulator.getEmailByMessageId(id); // by the MessageId SES returned
```

Supports SendEmail and SendRawEmail. The raw MIME parser reads multipart
bodies, quoted-printable and base64 parts, RFC 2047 subjects, inline `cid:`
images and an ICS calendar part.

- Inbox UI: `GET /emails/`, with the HTML preview rendering inline images.
- Delivery events: `POST /__ses/trigger` with `{ "messageId": "...", "type": "Delivery" | "Bounce" | "Complaint" }`
  builds the SES notification that SNS carries and passes it to `onNotification`.
  `GET /__ses/notifications` lists them.

Not supported: the SES v2 API (`@aws-sdk/client-sesv2`), templates, identities.

### Cognito

```ts
import { startCognitoEmulator } from 'tested-aws-simulators';

const cognito = await startCognitoEmulator({
  port: 38303,
  clientId: 'local-web-client',
  users: [
    { userId: 'admin-001', email: 'admin@example.com', name: 'Ada Admin', groups: ['Admin'], customAttributes: { tenantId: 'a' } },
    { userId: 'user-001', email: 'user@example.com', name: 'Uma User', groups: ['Users'], emailVerified: false },
    { userId: 'gone-001', email: 'gone@example.com', name: 'Gil Gone', groups: ['Users'], enabled: false },
  ],
  // Optional. Fields left out take Cognito's defaults (8, and all four classes required).
  passwordPolicy: { minimumLength: 12, requireSymbols: false },
});
// cognito.jwksUrl → verify tokens exactly as you verify real Cognito tokens
```

Seed users sign in with `Password1!` unless a `password` is given.

Hosted UI: `GET /oauth2/authorize` shows a user picker. Each user button has a
`data-testid` of `local-auth-continue-<primary group>` (first user per group) or
`local-auth-continue-user-<userId>`. `POST /oauth2/token` exchanges the code
(PKCE S256 only) for ID, access and refresh tokens, signed RS256 with the key at
`/.well-known/jwks.json`.

JSON API actions: InitiateAuth (`USER_PASSWORD_AUTH`, `REFRESH_TOKEN_AUTH`),
RespondToAuthChallenge (`NEW_PASSWORD_REQUIRED`), ListUsers (Filter, Limit,
PaginationToken, AttributesToGet), AdminGetUser, AdminCreateUser
(`MessageAction` `SUPPRESS` / `RESEND`, `DesiredDeliveryMediums`),
AdminUpdateUserAttributes, AdminSetUserPassword, AdminDeleteUser,
AdminDisableUser, AdminEnableUser, AdminListGroupsForUser, AdminAddUserToGroup,
AdminRemoveUserFromGroup, AdminUserGlobalSignOut, ForgotPassword,
ConfirmForgotPassword, GetUser, AssociateSoftwareToken, VerifySoftwareToken,
SetUserMFAPreference. Any other action answers `UnknownOperationException` with
its name. Every Admin call takes the user's `sub` or email as `Username`, as on
a pool that signs in by email.

Behaviour copied from real Cognito, each with a test:

- Custom attributes are on the ID token and ListUsers, never on the access token.
- A ListUsers Filter on a custom attribute is refused; a valid Filter is applied.
- AdminCreateUser stores only the attributes it was given: no invented name, and
  status `FORCE_CHANGE_PASSWORD` until a permanent password is set. With no
  `TemporaryPassword` it generates one that meets the policy.
- A `FORCE_CHANGE_PASSWORD` user who signs in gets the `NEW_PASSWORD_REQUIRED`
  challenge and no tokens; RespondToAuthChallenge sets the password and
  confirms the account. On the hosted UI, picking such a user shows a
  new-password form (`data-testid="local-auth-new-password"`) before any code.
- AdminSetUserPassword with `Permanent: true` confirms the account; without it
  the account goes to `FORCE_CHANGE_PASSWORD`, even from `CONFIRMED`.
- The pool's password policy (`passwordPolicy`, default Cognito's) is enforced
  on every password write, refused as `InvalidPasswordException` "Password does
  not conform to policy: …".
- A disabled user reads `Enabled: false` on AdminGetUser and ListUsers, is
  refused by InitiateAuth and the hosted UI with "User is disabled.", and loses
  its refresh tokens and (for Cognito API calls) its access tokens.
  AdminUserGlobalSignOut revokes the same tokens.
- ListUsers filters on `status = "Enabled"` / `"Disabled"` and pages 60 users at a
  time unless `Limit` says fewer; `Limit` above 60 is refused.
- GetUser and the TOTP calls require the `aws.cognito.signin.user.admin` scope.
- ForgotPassword and ConfirmForgotPassword give Cognito's own refusals, check the
  code before the password, and revoke refresh tokens on success.

Invitations: AdminCreateUser without `SUPPRESS` records the invitation Cognito
would send, temporary password included; read it with
`GET /__local/invitation?email=` or `cognito.emulator.getInvitation(email)`.
The emulator stores no phone number, so an invitation by SMS (the AWS default
medium) is refused: send `DesiredDeliveryMediums: ['EMAIL']` or
`MessageAction: 'SUPPRESS'`.

Test hooks: `GET /__local/forgot-password-code?email=`,
`POST /__local/expire-forgot-password-code?email=`, `GET /__local/mfa-state?email=`,
`GET /__local/invitation?email=`.
TOTP: any six-digit code verifies except `000000`, which is refused.

### SQS

```ts
import { SQSClient, CreateQueueCommand, SendMessageCommand, ReceiveMessageCommand } from '@aws-sdk/client-sqs';
import { startSqsSimulator } from 'tested-aws-simulators';

const sqssim = await startSqsSimulator({ port: 0 });
const sqs = new SQSClient({ endpoint: sqssim.url, region: 'us-east-1', credentials: { accessKeyId: 'test', secretAccessKey: 'test' } });

const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: 'jobs' }));
await sqs.send(new SendMessageCommand({ QueueUrl, MessageBody: 'hello', DelaySeconds: 10 }));

sqssim.simulator.advanceTime(10_000);   // no sleeping on delays or visibility timeouts
await sqs.send(new ReceiveMessageCommand({ QueueUrl, WaitTimeSeconds: 5 }));
sqssim.simulator.peekMessages('jobs');  // every message's state, without receiving it
sqssim.simulator.listQueues();          // names, ARNs, attributes, tags
```

Standard queues, held in memory. Queue URLs are
`http://<host>/000000000000/<name>`, where the host is the one the client used,
because the SDK sends each call to the host in its QueueUrl. ARNs are
`arn:aws:sqs:us-east-1:000000000000:<name>`. Pass `accountId` or `region` to
change them.

Operations: CreateQueue, GetQueueUrl, ListQueues (prefix, MaxResults,
NextToken), DeleteQueue, GetQueueAttributes, SetQueueAttributes, SendMessage,
SendMessageBatch, ReceiveMessage, DeleteMessage, DeleteMessageBatch,
ChangeMessageVisibility, ChangeMessageVisibilityBatch, PurgeQueue,
ListDeadLetterSourceQueues, StartMessageMoveTask, ListMessageMoveTasks,
TagQueue, UntagQueue, ListQueueTags.

Queue attributes: VisibilityTimeout, DelaySeconds, MessageRetentionPeriod,
MaximumMessageSize (default 1 MiB), ReceiveMessageWaitTimeSeconds,
RedrivePolicy, RedriveAllowPolicy and SqsManagedSseEnabled. The read-only
ApproximateNumberOf* counts, QueueArn and the timestamps are reported too.

Behaviour copied from real SQS, each with a test:

- Errors carry both `__type` and the `x-amzn-query-error` header, so the SDK
  throws its own classes (`QueueDoesNotExist`, `ReceiptHandleIsInvalid`,
  `MessageNotInflight`, `PurgeQueueInProgress`, `QueueNameExists`, ...).
- `MD5OfMessageBody` and `MD5OfMessageAttributes` use the SQS algorithms. The
  SDK checks the body MD5 on every send and receive.
- Delays, visibility timeouts, the 12-hour visibility ceiling and message
  retention run on the simulator clock. Pass `now: () => number` to inject a
  clock, call `advanceTime(ms)`, or both.
- Long polling waits in real time for up to `WaitTimeSeconds`, or the queue's
  `ReceiveMessageWaitTimeSeconds`. It returns as soon as a message is sent or
  becomes visible, including through `advanceTime`.
- Redrive: a message is delivered `maxReceiveCount` times, and the next receive
  moves it to the dead-letter queue instead of delivering it. The DLQ must
  exist, and its RedriveAllowPolicy is enforced.
- Every receive issues a new receipt handle. Deleting with an old handle
  succeeds but deletes nothing. AWS says the request "will succeed, but the
  message might not be deleted", and the simulator takes the strict reading.
- A deleted queue's name cannot be reused for 60 seconds
  (`QueueDeletedRecently`), and a second PurgeQueue within 60 seconds is refused.
- Batch calls check the entry count, the ids and the total size, and report
  failures per entry in `Failed`.

Test hooks: `reset()` (also `POST /__local/reset`), `listQueues()`,
`peekMessages(queueName)`, `advanceTime(ms)` and `now()`.

These are refused with HTTP 400 and a message naming what is unsupported: FIFO
queues, queue policies, KMS, AddPermission, RemovePermission,
CancelMessageMoveTask, `ReceiveRequestAttemptId`, list-valued message
attributes, the form-encoded query protocol and any request parameter the
simulator does not know.

Known deviations:

- Queues here keep strict send order and never deliver a message twice. Real
  standard queues order on a best-effort basis and deliver at least once, so do
  not rely on either.
- Attribute changes take effect at once. On AWS they take up to 60 seconds, or
  15 minutes for MessageRetentionPeriod. The approximate counts are exact.
- ChangeMessageVisibility with a stale or deleted receipt handle answers
  InvalidParameterValue. On a message that is no longer in flight it answers
  MessageNotInflight.
- A dead-lettered message keeps its MessageId, SentTimestamp and receive count.
- StartMessageMoveTask finishes before it answers. Every DLQ message that is not
  in flight moves, and `MaxNumberOfMessagesPerSecond` is checked but not applied.
  ListMessageMoveTasks shows the task as COMPLETED, or FAILED when a message's
  source queue is gone. Moved messages keep their MessageId and SentTimestamp,
  and their receive count restarts at 0.
- `SenderId` is the account id.

### DynamoDB

```ts
import { DynamoDBClient, CreateTableCommand } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { startDynamoDbSimulator } from 'tested-aws-simulators';

const ddbsim = await startDynamoDbSimulator({ port: 0 });
const ddb = new DynamoDBClient({ endpoint: ddbsim.url, region: 'us-east-1', credentials: { accessKeyId: 'test', secretAccessKey: 'test' } });
const doc = DynamoDBDocumentClient.from(ddb);

await ddb.send(new CreateTableCommand({
  TableName: 'things',
  BillingMode: 'PAY_PER_REQUEST',
  KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }, { AttributeName: 'sk', KeyType: 'RANGE' }],
  AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }, { AttributeName: 'sk', AttributeType: 'S' }],
}));
await doc.send(new PutCommand({ TableName: 'things', Item: { pk: 'a', sk: '1', n: 1 } }));

ddbsim.simulator.dumpTable('things');   // items in wire format, in key order
ddbsim.simulator.listTables();
```

Held in memory. Operations: CreateTable (HASH and RANGE keys, global secondary
indexes with ALL, KEYS_ONLY or INCLUDE projections, PAY_PER_REQUEST or
PROVISIONED), DescribeTable, ListTables, DeleteTable, UpdateTimeToLive,
DescribeTimeToLive, PutItem, GetItem, UpdateItem, DeleteItem, Query, Scan
(including parallel segments), BatchGetItem, BatchWriteItem,
TransactWriteItems and TransactGetItems.

Expressions go through a tokenizer and a recursive descent parser, not regular
expressions:

- Condition and filter: `= <> < <= > >=`, BETWEEN, IN, AND, OR, NOT,
  parentheses, `attribute_exists`, `attribute_not_exists`, `attribute_type`,
  `begins_with`, `contains`, `size`, and document paths such as `a.b[2].c`.
- Key condition: `=` on the partition key, plus at most one sort key condition
  (`= < <= > >=`, BETWEEN or `begins_with`).
- Update: SET (`a = :v`, `a = b + :v`, `a = b - :v`, `if_not_exists`,
  `list_append`, nested paths), REMOVE, ADD (numbers and sets) and DELETE (sets).
- Projection: document paths, including list elements.

Behaviour copied from real DynamoDB, each with a test:

- The error types are DynamoDB's, so `instanceof` works for
  `ConditionalCheckFailedException`, `TransactionCanceledException` (with
  `CancellationReasons`), `ResourceNotFoundException` and
  `ResourceInUseException`. Validation failures are `ValidationException` with
  DynamoDB's messages.
- All 573 reserved words are refused as bare attribute names in expressions.
  Undefined or unused `ExpressionAttributeNames` and `ExpressionAttributeValues`
  are refused too.
- Numbers are exact 38-digit decimals. They compare numerically and are stored
  in canonical form, so `1.50` comes back as `1.5` and `0.1 + 0.2` is `0.3`.
- Strings sort by UTF-8 bytes and binary values by unsigned bytes.
- Keys must be present, of the defined type and not empty. A GSI key attribute
  of the wrong type is refused. An item without the GSI key is left out of the
  index.
- Items over 400 KB are refused. Query and Scan stop after `Limit` items read
  (counted before the filter) or after 1 MB. They return a LastEvaluatedKey
  whenever they stop early, even when no items are left. A LastEvaluatedKey
  from a GSI carries both the table keys and the index keys.
- These are refused: a filter on a key attribute, a consistent read on a GSI,
  and `Select: ALL_ATTRIBUTES` on a GSI that does not project every attribute.
- UpdateItem reads every operand from the item as it was before the update. It
  refuses overlapping paths and updates to key attributes, and creates the item
  if it does not exist. ReturnValues (NONE, ALL_OLD, UPDATED_OLD, ALL_NEW,
  UPDATED_NEW) and ReturnValuesOnConditionCheckFailure are supported.
- TransactWriteItems applies all of its writes or none. It refuses two
  operations on one item and honours ClientRequestToken for ten minutes.

Test hooks: `reset()` (also `POST /__local/reset`), `listTables()` and
`dumpTable(name)`.

These are refused with HTTP 400 and a message naming what is unsupported: local
secondary indexes, streams, PartiQL, and UpdateTable and every other
unimplemented operation (as UnknownOperationException). So are the legacy
`Expected`, `AttributesToGet`, `KeyConditions`, `QueryFilter`, `ScanFilter`,
`AttributeUpdates` and `ConditionalOperator` parameters,
`ReturnConsumedCapacity` or `ReturnItemCollectionMetrics` set to anything but
NONE, and any request parameter the simulator does not know.

Known deviations:

- CreateTable answers CREATING, as DynamoDB does, but the table can be used at
  once. Call the SDK's `waitUntilTableExists` anyway, so the same code works on
  AWS.
- Time to live is recorded and described, but items never expire.
- ItemCount and TableSizeBytes are always current; AWS refreshes them about
  every six hours. Item size follows DynamoDB's documented accounting but is
  approximate for numbers, lists and maps.
- Scan returns items in partition key order, where AWS uses hash order. Never
  rely on Scan order.
- There is no throttling, so UnprocessedItems and UnprocessedKeys are always
  empty.
- `size()` of a string counts UTF-8 bytes. This is not confirmed against AWS for
  non-ASCII text.

### Transcribe

`TranscriptionSimulator` implements a small `TranscriptionService` port (start
job, get status, delete job). It writes a Transcribe-shaped output JSON through
the writer you give it, for example an S3 client pointed at the S3 simulator.
Script the next transcript with `queueScriptedTranscript()` or over HTTP after
`registerTranscriptionSimulatorRoutes(app, simulator)`.

### Sentry

```ts
const sentry = await startSentrySimulator({ port: 0 });
Sentry.init({ dsn: sentry.dsn });
sentry.simulator.getCapturedEvents();
```

Answers the envelope and store endpoints with HTTP 200 and an event id, and
answers CORS preflights so browser SDKs can report. `GET /` lists the captured
events.

### OpenRouter

```ts
const ai = await startOpenRouterSimulator({ port: 0 });
// base URL for an OpenAI-compatible client: ai.baseUrl  (http://localhost:<port>/api/v1)
ai.simulator.queueScriptedResponse('{"title":"scripted"}');
```

With no scripted response the simulator echoes the last user message, or
returns a minimal object for a `json_schema` response format. Streamed responses
copy the framing of a live OpenRouter capture: keep-alive comments, `role` on
every delta, two `stop` events and `[DONE]`. Chunk size and delay are set with
`setStreamConfig()`. Embeddings are deterministic hashes, not real vectors.

## Develop

```bash
npm install
npm test
npm run typecheck
npm run build
```

## Licence

MIT
