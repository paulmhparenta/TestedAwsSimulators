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

With no arguments the command starts S3, SES, Cognito, Sentry and OpenRouter on
their default ports. Name the simulators to start only those:

```bash
npx tested-aws-simulators s3 ses
```

| Env var | Effect |
| --- | --- |
| `S3_SIMULATOR_PORT`, `SES_SIMULATOR_PORT`, `COGNITO_EMULATOR_PORT`, `SENTRY_SIMULATOR_PORT`, `OPENROUTER_SIMULATOR_PORT` | Port for that simulator |
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
  ],
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
ListUsers (with Filter and Limit), AdminGetUser, AdminCreateUser,
AdminUpdateUserAttributes, AdminSetUserPassword, AdminDeleteUser,
AdminListGroupsForUser, AdminAddUserToGroup, AdminRemoveUserFromGroup,
AdminUserGlobalSignOut, ForgotPassword, ConfirmForgotPassword, GetUser,
AssociateSoftwareToken, VerifySoftwareToken, SetUserMFAPreference. Any other
action answers `UnknownOperationException` with its name.

Behaviour copied from real Cognito, each with a test:

- Custom attributes are on the ID token and ListUsers, never on the access token.
- A ListUsers Filter on a custom attribute is refused; a valid Filter is applied.
- AdminCreateUser stores only the attributes it was given: no invented name, and
  status `FORCE_CHANGE_PASSWORD` until a permanent password is set.
- The default password policy is enforced on every password write.
- GetUser and the TOTP calls require the `aws.cognito.signin.user.admin` scope.
- ForgotPassword and ConfirmForgotPassword give Cognito's own refusals, check the
  code before the password, and revoke refresh tokens on success.

Test hooks: `GET /__local/forgot-password-code?email=`,
`POST /__local/expire-forgot-password-code?email=`, `GET /__local/mfa-state?email=`.
TOTP: any six-digit code verifies except `000000`, which is refused.

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
