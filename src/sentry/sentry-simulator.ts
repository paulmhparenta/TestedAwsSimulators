/**
 * Minimal Sentry ingest simulator for local development and tests.
 *
 * Why it exists: pointing local development and test runs at a real Sentry
 * project burns the quota that production errors need. Turning reporting off
 * instead is worse — a path that never runs outside production is a path
 * nobody has tested, and the error reporter is exactly the code that has to
 * work when something breaks. So the SDKs stay switched on and point their DSN
 * at this server.
 *
 * It implements the part of the Sentry ingest API the SDKs use:
 *   POST /api/:projectId/envelope/   – every modern SDK (JS, node, react)
 *   POST /api/:projectId/store/      – the older single-event endpoint
 *   anything else                    – answers 200, so an SDK probing the
 *                                      server never logs an error
 *
 * Both reply the way Sentry does: HTTP 200 with `{"id": "<32 hex chars>"}`.
 *
 * Human view
 *   GET /            – the events this run captured, newest first
 *   GET /events      – the same as JSON
 *
 * Test hooks
 *   simulator.getCapturedEvents()   – every event captured, for assertions
 *   simulator.clear()               – reset the capture array
 *   POST /__local/reset             – the same over HTTP
 *   sentrySimulatorDsn(port)        – the DSN that points an SDK at this server
 */

import express from 'express';
import { randomBytes } from 'node:crypto';

import { escapeHtml, listen, type RunningSimulator } from '../shared/server';

export const SENTRY_SIMULATOR_DEFAULT_PORT = 38308;

/** The public key an SDK sends. Any value works; this one reads clearly in a log. */
export const SENTRY_SIMULATOR_PUBLIC_KEY = 'localsimulatorkey';

/**
 * The headers a browser SDK needs before it may send an envelope.
 *
 * The browser SDK posts with `Content-Type: application/x-sentry-envelope`,
 * which is not a CORS-safelisted content type, so the browser sends an
 * `OPTIONS` preflight first. A server without these headers fails the
 * preflight, and every browser error report is refused with "blocked by CORS
 * policy: No 'Access-Control-Allow-Origin' header". The report never reaches
 * this server, so the run shows a CORS error in place of the error the page
 * was reporting.
 *
 * The real ingest endpoint answers `access-control-allow-origin: *`, because
 * any page on any domain may report to a project it holds the key for.
 */
export const SENTRY_SIMULATOR_ALLOWED_HEADERS = 'Content-Type, X-Sentry-Auth, sentry-trace, baggage';

export interface CapturedSentryEvent {
  /** The id this simulator answered with. */
  eventId: string;
  /** Project id from the DSN path, so one server can serve several projects. */
  projectId: string;
  /** `event`, `transaction`, `session`, … from the envelope item header. */
  itemType: string;
  /** `error`, `warning`, … when the payload carries one. */
  level?: string;
  /** The first line a person would read: the exception or the message. */
  title: string;
  /** The whole payload, for an assertion that needs more than the title. */
  payload: Record<string, unknown>;
  receivedAt: string;
}

export interface SentrySimulator {
  readonly app: express.Express;
  getCapturedEvents(): CapturedSentryEvent[];
  clear(): void;
}

/** The DSN an SDK uses to send here. */
export function sentrySimulatorDsn(port: number = SENTRY_SIMULATOR_DEFAULT_PORT, projectId = '1', host = 'localhost'): string {
  return `http://${SENTRY_SIMULATOR_PUBLIC_KEY}@${host}:${port}/${projectId}`;
}

// ---------------------------------------------------------------------------
// Payload reading
// ---------------------------------------------------------------------------

/** A Sentry event id: 32 hex characters, no dashes. */
function newEventId(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Pull the readable line out of an event payload: the exception type and
 * value, else the message, else the transaction name.
 */
export function describeSentryPayload(payload: Record<string, unknown>): string {
  const exception = payload.exception as { values?: { type?: string; value?: string }[] } | undefined;
  const first = exception?.values?.[0];
  if (first?.type || first?.value) {
    return [first.type, first.value].filter(Boolean).join(': ');
  }
  const message = payload.message as string | { formatted?: string; message?: string } | undefined;
  if (typeof message === 'string') return message;
  if (message?.formatted || message?.message) return (message.formatted ?? message.message) as string;
  if (typeof payload.transaction === 'string') return payload.transaction;
  return '(no title)';
}

/**
 * Split an envelope into its items.
 *
 * The format is newline-delimited JSON: one envelope header, then a pair of
 * lines per item — an item header, then the payload. A payload can hold
 * newlines only when the header gives its length, which the SDKs do not do for
 * events, so splitting on newlines is enough here.
 */
export function parseSentryEnvelope(body: string): { itemType: string; payload: Record<string, unknown> }[] {
  const lines = body.split('\n').filter((line) => line.trim() !== '');
  const items: { itemType: string; payload: Record<string, unknown> }[] = [];
  // Line 0 is the envelope header; items start after it.
  for (let index = 1; index + 1 <= lines.length - 1; index += 2) {
    try {
      const header = JSON.parse(lines[index] as string) as { type?: string };
      const payload = JSON.parse(lines[index + 1] as string) as Record<string, unknown>;
      items.push({ itemType: header.type ?? 'unknown', payload });
    } catch {
      // A malformed item must not stop the rest: the simulator answers 200
      // whatever arrives, because an SDK that cannot report is worse than one
      // whose payload this server could not read.
    }
  }
  return items;
}

// ---------------------------------------------------------------------------
// The app
// ---------------------------------------------------------------------------

export function createSentrySimulator(): SentrySimulator {
  let capturedEvents: CapturedSentryEvent[] = [];

  const getCapturedEvents = (): CapturedSentryEvent[] => capturedEvents.map((event) => ({ ...event }));
  const clear = (): void => {
    capturedEvents = [];
  };

  function capture(projectId: string, itemType: string, payload: Record<string, unknown>): string {
    const eventId = (typeof payload.event_id === 'string' && payload.event_id) || newEventId();
    capturedEvents.push({
      eventId,
      projectId,
      itemType,
      level: typeof payload.level === 'string' ? payload.level : undefined,
      title: describeSentryPayload(payload),
      payload,
      receivedAt: new Date().toISOString(),
    });
    return eventId;
  }

  const app = express();

  // CORS first, and before the body parser: a preflight carries no body and
  // must be answered whatever the route.
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    // The requested headers are reflected when the browser names them. A fixed
    // list would refuse an SDK header this file does not know, which is the
    // failure above again, with a different header name.
    res.setHeader('Access-Control-Allow-Headers', req.header('access-control-request-headers') ?? SENTRY_SIMULATOR_ALLOWED_HEADERS);
    res.setHeader('Access-Control-Max-Age', '86400');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  // Envelopes arrive as text; some SDKs send gzip, which express decompresses
  // before this handler sees it. The type matcher takes everything so a
  // content type this file does not list cannot turn into a 415.
  app.use(express.text({ type: () => true, limit: '20mb' }));

  app.post('/api/:projectId/envelope/', (req, res) => {
    const body = typeof req.body === 'string' ? req.body : '';
    let lastId = newEventId();
    for (const item of parseSentryEnvelope(body)) {
      lastId = capture(req.params.projectId, item.itemType, item.payload);
      console.log(`[sentry-simulator] ${item.itemType}: ${describeSentryPayload(item.payload)}`);
    }
    res.status(200).json({ id: lastId });
  });

  app.post('/api/:projectId/store/', (req, res) => {
    let payload: Record<string, unknown> = {};
    try {
      payload = JSON.parse(typeof req.body === 'string' ? req.body : '{}') as Record<string, unknown>;
    } catch {
      payload = {};
    }
    const eventId = capture(req.params.projectId, 'event', payload);
    console.log(`[sentry-simulator] event: ${describeSentryPayload(payload)}`);
    res.status(200).json({ id: eventId });
  });

  app.post('/__local/reset', (_req, res) => {
    clear();
    res.status(204).end();
  });

  app.get('/events', (_req, res) => {
    res.json({ events: getCapturedEvents().reverse() });
  });

  app.get('/', (_req, res) => {
    const rows = getCapturedEvents()
      .reverse()
      .map((event) => `<tr><td>${event.receivedAt}</td><td>${escapeHtml(event.itemType)}</td>`
        + `<td>${escapeHtml(event.level ?? '')}</td><td>${escapeHtml(event.title)}</td></tr>`)
      .join('');
    res.type('html').send(
      '<!doctype html><meta charset="utf-8"><title>Sentry simulator</title>'
      + '<style>body{font:14px system-ui;margin:24px}table{border-collapse:collapse}'
      + 'td,th{border:1px solid #ddd;padding:6px 10px;text-align:left}</style>'
      + `<h1>Sentry simulator</h1><p>${capturedEvents.length} event(s) captured.</p>`
      + '<table><tr><th>Received</th><th>Type</th><th>Level</th><th>Title</th></tr>'
      + `${rows}</table>`,
    );
  });

  // Anything else answers 200 rather than 404: an SDK that gets an error from
  // its own transport writes a warning into every local run.
  app.use((req, res) => {
    console.log(`[sentry-simulator] ignored ${req.method} ${req.path}`);
    res.status(200).json({ id: newEventId() });
  });

  return { app, getCapturedEvents, clear };
}

export interface StartSentrySimulatorOptions {
  /** Default `SENTRY_SIMULATOR_PORT` env var, else 38308. Pass 0 for a free port. */
  readonly port?: number;
  readonly host?: string;
}

export async function startSentrySimulator(
  options: StartSentrySimulatorOptions = {},
): Promise<RunningSimulator & { readonly simulator: SentrySimulator; readonly dsn: string }> {
  const port = options.port ?? Number(process.env.SENTRY_SIMULATOR_PORT ?? SENTRY_SIMULATOR_DEFAULT_PORT);
  const simulator = createSentrySimulator();
  const running = await listen(simulator.app, port, options.host);
  console.log(`Sentry simulator listening on ${running.url}`);
  return { ...running, simulator, dsn: sentrySimulatorDsn(running.port) };
}
