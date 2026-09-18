import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type express from 'express';

/**
 * Keep-alive settings for every simulator's HTTP server.
 *
 * WHY THIS EXISTS. Node closes an idle keep-alive socket after
 * `server.keepAliveTimeout`, which defaults to 5s. Chromium and Node's own
 * `http.Agent` keep a pooled socket far longer, so the SERVER always closes
 * first, and a request written into the last few milliseconds before the FIN
 * races it and is reset.
 *
 * MEASURED, before this was applied: reusing a pooled socket after an idle of
 * 5990ms gave ECONNRESET on 2 of 12 trials and 5995ms on 3 of 12, while 5960ms
 * and 6050ms were 12/12 clean. The window is only a few milliseconds wide, which
 * is why it reads as a random flake rather than a timeout.
 *
 * In a browser the reset surfaces as `TypeError: Failed to fetch` on whichever
 * request happened to land there, after which a test fails on an unrelated
 * step, naming a locator that has nothing to do with the dropped connection.
 *
 * THE FIX IS TO MAKE THE CLIENT CLOSE FIRST. Five minutes is longer than any
 * idle gap inside a test run, so the boundary is never reached. These are local
 * test simulators, so holding idle sockets open costs nothing.
 *
 * `headersTimeout` MUST exceed `keepAliveTimeout`, or Node reintroduces the same
 * race at its own boundary instead of removing it.
 *
 * DO NOT "fix" a recurrence with test retries, longer test timeouts, or a
 * flaky marker. Those hide a dropped connection rather than removing it.
 */
export const LOCAL_KEEP_ALIVE_MS = 5 * 60 * 1000;

/** Applies the settings above. Call once, on every local HTTP server. */
export function applyLocalKeepAlive(server: Server): void {
  server.keepAliveTimeout = LOCAL_KEEP_ALIVE_MS;
  server.headersTimeout = LOCAL_KEEP_ALIVE_MS + 10_000;
}

/** A simulator listening on a real port. */
export interface RunningSimulator {
  readonly server: Server;
  readonly port: number;
  /** `http://localhost:<port>` */
  readonly url: string;
  close(): Promise<void>;
}

/**
 * Listens on `port` (0 picks a free port), applies the keep-alive settings and
 * resolves once the socket is bound.
 */
export async function listen(app: express.Express, port: number, host?: string): Promise<RunningSimulator> {
  const server = createServer(app);
  applyLocalKeepAlive(server);

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    const onListening = (): void => {
      server.off('error', reject);
      resolve();
    };
    if (host) server.listen(port, host, onListening);
    else server.listen(port, onListening);
  });

  const boundPort = (server.address() as AddressInfo).port;
  return {
    server,
    port: boundPort,
    url: `http://localhost:${boundPort}`,
    close: () => new Promise<void>((resolve, reject) => {
      // Idle keep-alive sockets would hold `close` open for five minutes.
      server.closeAllConnections();
      server.close((err) => (err ? reject(err) : resolve()));
    }),
  };
}

/** Collects a raw request body as a Buffer without an express body parser. */
export function readRawBody(req: express.Request): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
