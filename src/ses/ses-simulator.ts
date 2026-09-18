/**
 * Minimal SES (v1 API) simulator for local development and tests.
 *
 * Implements the subset of the SES API most applications use:
 *   POST /  (Action=SendEmail)    – structured email send
 *   POST /  (Action=SendRawEmail) – raw MIME email send
 *
 * This is the form-encoded query protocol `@aws-sdk/client-ses` sends. The
 * simulator also accepts a JSON body with an `x-amz-target` header:
 *   x-amz-target: AmazonSimpleEmailService.SendEmail
 *   x-amz-target: AmazonSimpleEmailService.SendRawEmail
 *
 * Point the SDK at this server with the SESClient `endpoint` option (or the
 * AWS_ENDPOINT_URL_SES env var). Emails are captured in memory; read them with
 * `listEmails()` / `getEmail()`, or open the inbox UI at `/emails/`.
 *
 * Delivery events: `POST /__ses/trigger { messageId, type }` builds the SES
 * notification (Delivery | Bounce | Complaint) that SNS would carry for that
 * message, records it, and hands it to the `onNotification` callback, so a
 * test can run the same bounce/complaint handler production runs.
 */

import express from 'express';

import { listen, readRawBody, type RunningSimulator } from '../shared/server';
import { extractAddress, parseMimeEmail, type CapturedEmailAttachment } from './mime-parser';
import { createEmailViewerRouter } from './email-viewer';

export type { CapturedEmailAttachment } from './mime-parser';

export const SES_SIMULATOR_DEFAULT_PORT = 38306;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CapturedEmail {
  /** Unique ID assigned by the simulator */
  readonly id: string;
  /** The MessageId the simulator returned to the sender. */
  readonly messageId: string;
  readonly capturedAt: string; // ISO 8601
  readonly from: string;
  readonly to: readonly string[];
  readonly subject: string;
  /** Plain-text body, if present */
  readonly textBody: string | null;
  /** HTML body, if present */
  readonly htmlBody: string | null;
  /** ICS calendar attachment, if present */
  readonly calendarAttachment: CapturedEmailAttachment | null;
  /** Inline image and attachment parts */
  readonly inlineAttachments: readonly CapturedEmailAttachment[];
  /** Raw MIME source (populated for SendRawEmail) */
  readonly rawMime: string | null;
  /** All top-level MIME headers, keys lower-cased (e.g. 'reply-to'). */
  readonly headers: Readonly<Record<string, string>>;
}

export interface CapturedEmailSummary {
  readonly id: string;
  readonly messageId: string;
  readonly capturedAt: string;
  readonly from: string;
  readonly to: readonly string[];
  readonly subject: string;
}

export type SesNotificationType = 'Delivery' | 'Bounce' | 'Complaint';

/**
 * The SES notification JSON — the `Message` string of the SNS record a
 * configuration-set event destination publishes.
 */
export interface SesNotification {
  readonly notificationType: SesNotificationType;
  readonly mail: { readonly messageId: string };
  readonly delivery?: { readonly timestamp: string };
  readonly bounce?: { readonly bounceType: string; readonly bounceSubType: string; readonly timestamp: string };
  readonly complaint?: { readonly complaintFeedbackType: string; readonly timestamp: string };
}

export interface SesSimulatorOptions {
  /**
   * Called for every `POST /__ses/trigger`. Use it to run your own SNS event
   * handler against the notification. A rejection answers HTTP 500.
   */
  readonly onNotification?: (notification: SesNotification) => Promise<void> | void;
}

export interface SesSimulator {
  readonly app: express.Express;
  /** Summaries of every captured email, oldest first. */
  listEmails(): readonly CapturedEmailSummary[];
  getEmail(id: string): CapturedEmail | null;
  getEmailByMessageId(messageId: string): CapturedEmail | null;
  /** Every notification built by `/__ses/trigger`, oldest first. */
  listNotifications(): readonly SesNotification[];
  /** Clears the captured emails and notifications. */
  reset(): void;
}

// ---------------------------------------------------------------------------
// Request body helpers
// ---------------------------------------------------------------------------

/**
 * Parse application/x-www-form-urlencoded body into a flat key→value map.
 * Handles array parameters like Destination.ToAddresses.member.1.
 */
function parseFormBody(raw: string): Record<string, string> {
  const params: Record<string, string> = {};
  for (const pair of raw.split('&')) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    const key = decodeURIComponent(pair.slice(0, eq).replace(/\+/g, ' '));
    const val = decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, ' '));
    params[key] = val;
  }
  return params;
}

function readMemberList(params: Record<string, string>, prefix: string): string[] {
  const values: string[] = [];
  // Prefix.member.1, .member.2, …
  for (let i = 1; ; i++) {
    const addr = params[`${prefix}.member.${i}`];
    if (!addr) break;
    values.push(extractAddress(addr));
  }
  return values;
}

// ---------------------------------------------------------------------------
// JSON protocol bodies
// ---------------------------------------------------------------------------

interface SesJsonSendEmailBody {
  FromEmailAddress?: string;
  Destination?: { ToAddresses?: string[] };
  Content?: {
    Simple?: {
      Subject?: { Data?: string };
      Body?: {
        Text?: { Data?: string };
        Html?: { Data?: string };
      };
    };
  };
}

interface SesJsonSendRawEmailBody {
  Content?: {
    Raw?: { Data?: string }; // base64
  };
}

function xmlError(code: string, message: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${message}</Message></Error>`;
}

// ---------------------------------------------------------------------------
// Simulator factory
// ---------------------------------------------------------------------------

export function createSesSimulator(options: SesSimulatorOptions = {}): SesSimulator {
  const emailStore: CapturedEmail[] = [];
  const notifications: SesNotification[] = [];
  let idCounter = 0;

  function newEmailId(): string {
    idCounter += 1;
    return `ses-sim-${Date.now().toString(36)}-${idCounter.toString(36)}`;
  }

  function newMessageId(): string {
    return `ses-sim-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}@ses-simulator.local`;
  }

  function store(parts: Omit<CapturedEmail, 'id' | 'messageId' | 'capturedAt'>): CapturedEmail {
    const email: CapturedEmail = {
      id: newEmailId(),
      messageId: newMessageId(),
      capturedAt: new Date().toISOString(),
      ...parts,
    };
    emailStore.push(email);
    return email;
  }

  function captureSimple(from: string, to: string[], subject: string, textBody: string | null, htmlBody: string | null): CapturedEmail {
    return store({
      from: extractAddress(from),
      to,
      subject,
      textBody,
      htmlBody,
      calendarAttachment: null,
      inlineAttachments: [],
      rawMime: null,
      headers: {},
    });
  }

  function captureRaw(rawBase64: string): CapturedEmail {
    const rawMime = Buffer.from(rawBase64, 'base64').toString('utf-8');
    return store({ ...parseMimeEmail(rawMime), rawMime });
  }

  function handleSendEmail(params: Record<string, string>): CapturedEmail {
    return captureSimple(
      params['Source'] ?? '',
      readMemberList(params, 'Destination.ToAddresses'),
      params['Message.Subject.Data'] ?? '(no subject)',
      params['Message.Body.Text.Data'] ?? null,
      params['Message.Body.Html.Data'] ?? null,
    );
  }

  function handleSendEmailJson(body: SesJsonSendEmailBody): CapturedEmail {
    return captureSimple(
      body.FromEmailAddress ?? '',
      (body.Destination?.ToAddresses ?? []).map(extractAddress),
      body.Content?.Simple?.Subject?.Data ?? '(no subject)',
      body.Content?.Simple?.Body?.Text?.Data ?? null,
      body.Content?.Simple?.Body?.Html?.Data ?? null,
    );
  }

  function sendResponse(res: express.Response, action: 'SendEmail' | 'SendRawEmail', email: CapturedEmail): void {
    const xml = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      `<${action}Response xmlns="http://ses.amazonaws.com/doc/2010-12-01/">`,
      `  <${action}Result>`,
      `    <MessageId>${email.messageId}</MessageId>`,
      `  </${action}Result>`,
      '  <ResponseMetadata>',
      '    <RequestId>ses-sim-request-id</RequestId>',
      '  </ResponseMetadata>',
      `</${action}Response>`,
    ].join('\n');

    console.log(`[ses-simulator] Captured ${action} id=${email.id} from=${email.from} to=${email.to.join(',')} subject="${email.subject}"`);
    res.status(200).type('application/xml').send(xml);
  }

  function dispatchFormAction(res: express.Response, params: Record<string, string>): boolean {
    const action = params['Action'] ?? '';
    if (action === 'SendEmail') {
      sendResponse(res, 'SendEmail', handleSendEmail(params));
      return true;
    }
    if (action === 'SendRawEmail') {
      sendResponse(res, 'SendRawEmail', captureRaw(params['RawMessage.Data'] ?? ''));
      return true;
    }
    return false;
  }

  function buildNotification(messageId: string, type: SesNotificationType): SesNotification {
    const timestamp = new Date().toISOString();
    if (type === 'Delivery') {
      return { notificationType: 'Delivery', mail: { messageId }, delivery: { timestamp } };
    }
    if (type === 'Bounce') {
      return {
        notificationType: 'Bounce',
        mail: { messageId },
        bounce: { bounceType: 'Permanent', bounceSubType: 'General', timestamp },
      };
    }
    return {
      notificationType: 'Complaint',
      mail: { messageId },
      complaint: { complaintFeedbackType: 'abuse', timestamp },
    };
  }

  function listEmails(): readonly CapturedEmailSummary[] {
    return emailStore.map((e) => ({
      id: e.id,
      messageId: e.messageId,
      capturedAt: e.capturedAt,
      from: e.from,
      to: e.to,
      subject: e.subject,
    }));
  }

  function getEmail(id: string): CapturedEmail | null {
    return emailStore.find((e) => e.id === id) ?? null;
  }

  function reset(): void {
    emailStore.length = 0;
    notifications.length = 0;
  }

  const app = express();

  // ── Inbox UI ───────────────────────────────────────────────────────────────
  app.use('/emails', createEmailViewerRouter({ listEmails, getEmail, clear: reset }, '/emails'));

  // ── Test control ───────────────────────────────────────────────────────────
  app.post('/__local/reset', (_req, res) => {
    reset();
    res.status(204).end();
  });

  app.get('/__ses/notifications', (_req, res) => {
    res.json({ notifications });
  });

  app.post('/__ses/trigger', express.json(), async (req, res) => {
    const body = (req.body ?? {}) as { messageId?: unknown; type?: unknown };
    const type = body.type;
    if (type !== 'Delivery' && type !== 'Bounce' && type !== 'Complaint') {
      res.status(400).json({ error: `Unsupported type: ${String(type)}` });
      return;
    }
    if (typeof body.messageId !== 'string' || !body.messageId) {
      res.status(400).json({ error: 'messageId (string) required' });
      return;
    }
    const notification = buildNotification(body.messageId, type);
    notifications.push(notification);
    try {
      await options.onNotification?.(notification);
      res.json({ ok: true, notification });
    } catch (err) {
      console.error('[ses-simulator] onNotification failed', err);
      res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  // ── SES API ────────────────────────────────────────────────────────────────
  app.post('/', async (req, res) => {
    try {
      const bodyBuf = await readRawBody(req);
      const amzTarget = req.headers['x-amz-target'] ?? '';

      // JSON protocol: uses the x-amz-target header
      if (amzTarget) {
        const target = String(amzTarget);
        let bodyJson: unknown;
        try {
          bodyJson = JSON.parse(bodyBuf.toString('utf-8'));
        } catch {
          res.status(400).type('application/xml').send(xmlError('InvalidRequest', 'Invalid JSON body'));
          return;
        }

        // SendRawEmail first: 'SendRawEmail' does not end with 'SendEmail', but
        // the explicit order keeps the two apart if the matching ever changes.
        if (target.endsWith('.SendRawEmail')) {
          const raw = (bodyJson as SesJsonSendRawEmailBody).Content?.Raw?.Data ?? '';
          sendResponse(res, 'SendRawEmail', captureRaw(raw));
        } else if (target.endsWith('.SendEmail')) {
          sendResponse(res, 'SendEmail', handleSendEmailJson(bodyJson as SesJsonSendEmailBody));
        } else {
          res.status(400).type('application/xml').send(xmlError('InvalidAction', `Unknown target: ${target}`));
        }
        return;
      }

      // Form-encoded query protocol. Tried for any content type, because some
      // clients omit the header.
      const params = parseFormBody(bodyBuf.toString('utf-8'));
      if (!dispatchFormAction(res, params)) {
        const action = params['Action'];
        res.status(400).type('application/xml').send(
          action
            ? xmlError('InvalidAction', `Unknown action: ${action}`)
            : xmlError('InvalidRequest', 'Cannot determine SES action'),
        );
      }
    } catch (err) {
      console.error('[ses-simulator] Error handling request', err);
      res.status(500).type('application/xml').send(xmlError('InternalError', 'Internal simulator error'));
    }
  });

  // Catch-all for unexpected routes
  app.use((req, res) => {
    console.warn(`[ses-simulator] 404 ${req.method} ${req.path}`);
    res.status(404).type('application/xml').send(xmlError('NotFound', 'Not found'));
  });

  return {
    app,
    listEmails,
    getEmail,
    getEmailByMessageId: (messageId) => emailStore.find((e) => e.messageId === messageId) ?? null,
    listNotifications: () => notifications.slice(),
    reset,
  };
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export interface StartSesSimulatorOptions extends SesSimulatorOptions {
  /** Default `SES_SIMULATOR_PORT` env var, else 38306. Pass 0 for a free port. */
  readonly port?: number;
  readonly host?: string;
}

export async function startSesSimulator(
  options: StartSesSimulatorOptions = {},
): Promise<RunningSimulator & { readonly simulator: SesSimulator }> {
  const port = options.port ?? Number(process.env.SES_SIMULATOR_PORT ?? SES_SIMULATOR_DEFAULT_PORT);
  const simulator = createSesSimulator(options);
  const running = await listen(simulator.app, port, options.host);

  console.log(`SES simulator listening on ${running.url}`);
  console.log(`  Inbox: ${running.url}/emails/`);
  return { ...running, simulator };
}
