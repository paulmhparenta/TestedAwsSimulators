import { describe, it, expect, afterEach } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import {
  createSentrySimulator,
  describeSentryPayload,
  parseSentryEnvelope,
  sentrySimulatorDsn,
  startSentrySimulator,
  SENTRY_SIMULATOR_ALLOWED_HEADERS,
  type SentrySimulator,
} from './sentry-simulator';

/**
 * The simulator stands in for Sentry in local, e2e and unit runs. Two things
 * have to hold: an SDK must believe it, and a test must be able to read what
 * was reported.
 *
 * Each case drives the app over a real socket on an ephemeral port: a real
 * request also proves the body parser and the content types an SDK sends.
 */
let server: Server | null = null;
let simulator: SentrySimulator = createSentrySimulator();

const getCapturedSentryEvents = () => simulator.getCapturedEvents();

async function listen(): Promise<string> {
  simulator = createSentrySimulator();
  server = createServer(simulator.app);
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

async function post(baseUrl: string, path: string, body: string, contentType: string): Promise<Response> {
  return fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'content-type': contentType }, body });
}

function envelope(items: { header: Record<string, unknown>; payload: Record<string, unknown> }[]): string {
  const lines = [JSON.stringify({ event_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', sent_at: new Date().toISOString() })];
  for (const item of items) {
    lines.push(JSON.stringify(item.header));
    lines.push(JSON.stringify(item.payload));
  }
  return lines.join('\n') + '\n';
}

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = null;
  }
});

describe('the Sentry simulator', () => {
  it('answers an envelope the way Sentry does: 200 and an event id', async () => {
    const baseUrl = await listen();
    const response = await post(baseUrl, '/api/1/envelope/', envelope([{
      header: { type: 'event' },
      payload: {
        event_id: 'b'.repeat(32),
        level: 'error',
        exception: { values: [{ type: 'TypeError', value: 'x is not a function' }] },
      },
    }]), 'application/x-sentry-envelope');

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ id: 'b'.repeat(32) });
  });

  it('captures the event so a test can assert what was reported', async () => {
    const baseUrl = await listen();
    await post(baseUrl, '/api/1/envelope/', envelope([{
      header: { type: 'event' },
      payload: {
        level: 'error',
        exception: { values: [{ type: 'TypeError', value: 'x is not a function' }] },
      },
    }]), 'application/x-sentry-envelope');

    const captured = getCapturedSentryEvents();
    expect(captured).toHaveLength(1);
    expect(captured[0]).toMatchObject({
      projectId: '1',
      itemType: 'event',
      level: 'error',
      title: 'TypeError: x is not a function',
    });
  });

  it('captures every item in one envelope', async () => {
    const baseUrl = await listen();
    await post(baseUrl, '/api/1/envelope/', envelope([
      { header: { type: 'event' }, payload: { message: 'first' } },
      { header: { type: 'session' }, payload: { status: 'ok' } },
    ]), 'application/x-sentry-envelope');

    expect(getCapturedSentryEvents().map((e) => e.itemType)).toEqual(['event', 'session']);
  });

  it('accepts the older store endpoint', async () => {
    const baseUrl = await listen();
    const response = await post(baseUrl, '/api/7/store/',
      JSON.stringify({ message: 'legacy path', level: 'warning' }), 'application/json');

    expect(response.status).toBe(200);
    expect(((await response.json()) as { id: string }).id).toMatch(/^[0-9a-f]{32}$/);
    expect(getCapturedSentryEvents()[0]).toMatchObject({ projectId: '7', title: 'legacy path' });
  });

  it('answers 200 to anything else, so an SDK never logs a transport error', async () => {
    const baseUrl = await listen();
    const response = await post(baseUrl, '/api/1/security/', '{}', 'application/json');
    expect(response.status).toBe(200);
  });

  it('answers 200 for a malformed envelope rather than failing the caller', async () => {
    const baseUrl = await listen();
    const response = await post(baseUrl, '/api/1/envelope/', 'not an envelope', 'application/x-sentry-envelope');
    expect(response.status).toBe(200);
  });

  it('serves the captured events as JSON', async () => {
    const baseUrl = await listen();
    await post(baseUrl, '/api/1/envelope/', envelope([
      { header: { type: 'event' }, payload: { message: 'one' } },
      { header: { type: 'event' }, payload: { message: 'two' } },
    ]), 'application/x-sentry-envelope');

    const response = await fetch(`${baseUrl}/events`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { events: { title: string }[] };
    // Newest first, so the page and the JSON read the same way.
    expect(body.events.map((event) => event.title)).toEqual(['two', 'one']);
  });
});

/**
 * A browser SDK posts `Content-Type: application/x-sentry-envelope`, which is
 * not CORS-safelisted, so the browser sends an `OPTIONS` preflight first.
 * Without an answer to that preflight the browser refuses the report and the
 * run shows "blocked by CORS policy" in place of the reported error.
 */
describe('the Sentry simulator and a browser caller', () => {
  it('answers the preflight for an envelope post', async () => {
    const baseUrl = await listen();
    const response = await fetch(`${baseUrl}/api/1/envelope/`, {
      method: 'OPTIONS',
      headers: {
        origin: 'http://localhost:5173',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type',
      },
    });

    expect(response.status).toBe(204);
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(response.headers.get('access-control-allow-methods')).toContain('POST');
    expect(response.headers.get('access-control-allow-headers')).toBe('content-type');
  });

  it('allows a header the browser names that this file does not list', async () => {
    const baseUrl = await listen();
    const response = await fetch(`${baseUrl}/api/1/envelope/`, {
      method: 'OPTIONS',
      headers: {
        origin: 'http://localhost:5173',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type, x-some-new-sdk-header',
      },
    });

    expect(response.headers.get('access-control-allow-headers')).toBe('content-type, x-some-new-sdk-header');
  });

  it('names the headers an SDK sends when the browser asks for none', async () => {
    const baseUrl = await listen();
    const response = await fetch(`${baseUrl}/api/1/envelope/`, {
      method: 'OPTIONS',
      headers: { origin: 'http://localhost:5173', 'access-control-request-method': 'POST' },
    });

    expect(response.headers.get('access-control-allow-headers')).toBe(SENTRY_SIMULATOR_ALLOWED_HEADERS);
  });

  it('captures nothing for a preflight', async () => {
    const baseUrl = await listen();
    await fetch(`${baseUrl}/api/1/envelope/`, {
      method: 'OPTIONS',
      headers: { origin: 'http://localhost:5173', 'access-control-request-method': 'POST' },
    });

    expect(getCapturedSentryEvents()).toHaveLength(0);
  });

  it('sends the allow-origin header on the envelope response itself', async () => {
    const baseUrl = await listen();
    const response = await post(
      baseUrl,
      '/api/1/envelope/',
      envelope([{ header: { type: 'event' }, payload: { message: 'from a page' } }]),
      'application/x-sentry-envelope',
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(getCapturedSentryEvents()[0]).toMatchObject({ title: 'from a page' });
  });

  it('sends the allow-origin header on a path it does not route', async () => {
    const baseUrl = await listen();
    const response = await post(baseUrl, '/api/1/security/', '{}', 'application/json');

    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
  });
});

describe('describeSentryPayload', () => {
  it('prefers the exception', () => {
    expect(describeSentryPayload({
      exception: { values: [{ type: 'RangeError', value: 'too big' }] },
      message: 'ignored',
    })).toBe('RangeError: too big');
  });

  it('falls back to a string message', () => {
    expect(describeSentryPayload({ message: 'plain message' })).toBe('plain message');
  });

  it('falls back to a formatted message object', () => {
    expect(describeSentryPayload({ message: { formatted: 'formatted message' } })).toBe('formatted message');
  });

  it('falls back to the transaction name', () => {
    expect(describeSentryPayload({ transaction: 'GET /users' })).toBe('GET /users');
  });

  it('says so when there is nothing to read', () => {
    expect(describeSentryPayload({})).toBe('(no title)');
  });
});

describe('parseSentryEnvelope', () => {
  it('reads header and payload pairs', () => {
    const items = parseSentryEnvelope(envelope([
      { header: { type: 'event' }, payload: { message: 'one' } },
    ]));
    expect(items).toEqual([{ itemType: 'event', payload: { message: 'one' } }]);
  });

  it('returns nothing for an empty body', () => {
    expect(parseSentryEnvelope('')).toEqual([]);
  });

  it('skips an item it cannot read and keeps the rest', () => {
    const body = [
      JSON.stringify({ event_id: 'a'.repeat(32) }),
      '{not json',
      '{also not json',
      JSON.stringify({ type: 'event' }),
      JSON.stringify({ message: 'survivor' }),
    ].join('\n');
    expect(parseSentryEnvelope(body)).toEqual([{ itemType: 'event', payload: { message: 'survivor' } }]);
  });
});

describe('sentrySimulatorDsn', () => {
  it('builds a DSN an SDK accepts', () => {
    expect(sentrySimulatorDsn(38308)).toBe('http://localsimulatorkey@localhost:38308/1');
  });

  it('follows a shifted port, project and host', () => {
    expect(sentrySimulatorDsn(38808, '7', '127.0.0.1')).toBe('http://localsimulatorkey@127.0.0.1:38808/7');
  });
});

describe('startSentrySimulator', () => {
  it('listens, returns a working DSN, and clears on POST /__local/reset', async () => {
    const running = await startSentrySimulator({ port: 0 });
    try {
      expect(running.dsn).toBe(`http://localsimulatorkey@localhost:${running.port}/1`);
      await post(running.url, '/api/1/store/', JSON.stringify({ message: 'kept' }), 'application/json');
      expect(running.simulator.getCapturedEvents()).toHaveLength(1);

      const reset = await fetch(`${running.url}/__local/reset`, { method: 'POST' });
      expect(reset.status).toBe(204);
      expect(running.simulator.getCapturedEvents()).toHaveLength(0);
    } finally {
      await running.close();
    }
  });

  it('serves a readable HTML page of the captured events', async () => {
    const baseUrl = await listen();
    await post(baseUrl, '/api/1/store/', JSON.stringify({ message: '<script>alert(1)</script>' }), 'application/json');

    const html = await (await fetch(`${baseUrl}/`)).text();
    expect(html).toContain('1 event(s) captured.');
    expect(html).toContain('&lt;script&gt;');
    expect(html).not.toContain('<script>alert(1)</script>');
  });
});
