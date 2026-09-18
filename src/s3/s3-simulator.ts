/**
 * Minimal S3 simulator for local development and tests.
 *
 * Implements the subset of the S3 REST API most applications use:
 *   PUT    /{bucket}/{key} – store an object (PutObjectCommand + presigned PUT from a browser)
 *                            and server-side copy when x-amz-copy-source is set (CopyObjectCommand)
 *   GET    /{bucket}/{key} – retrieve an object (GetObjectCommand), with HTTP Range support
 *   HEAD   /{bucket}/{key} – object metadata (HeadObjectCommand)
 *   DELETE /{bucket}/{key} – delete an object (DeleteObjectCommand)
 *
 * The AWS SDK v3 must be pointed at this server via the S3Client `endpoint` option
 * with `forcePathStyle: true` so that the bucket name is part of the path rather
 * than the hostname.
 *
 * Browsers can PUT directly to a presigned URL, so the simulator sets permissive
 * CORS headers on every response.
 *
 * Objects are stored under `{dataDir}/{bucket}/{key}` on disk so they survive
 * process restarts. `reset()` (or `POST /__local/reset`) wipes the directory.
 */

import express from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';

import { listen, readRawBody, type RunningSimulator } from '../shared/server';

export const S3_SIMULATOR_DEFAULT_PORT = 38304;
export const S3_SIMULATOR_DEFAULT_DATA_DIR = '.local-s3';

/**
 * Suffix for the sidecar file holding an object's Content-Type.
 *
 * Real S3 stores the Content-Type given at PUT time and replays it on GET.
 * Without that, every object comes back as `application/octet-stream`, which a
 * browser downloads rather than renders — so an HTML object shown in an
 * `<iframe>` works against real S3 and silently fails locally. The sidecar
 * keeps the type on disk across restarts, the same way the object bodies are
 * stored.
 */
const CONTENT_TYPE_SUFFIX = '.__content-type';

export interface S3SimulatorOptions {
  /** Directory the objects are written to. Default `.local-s3`. */
  readonly dataDir?: string;
}

export interface S3Simulator {
  readonly app: express.Express;
  readonly dataDir: string;
  /** Deletes every stored object. */
  reset(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function xmlError(code: string, message: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${message}</Message></Error>`;
}

function isMissingFile(err: unknown): boolean {
  return (err as NodeJS.ErrnoException)?.code === 'ENOENT';
}

// ---------------------------------------------------------------------------
// Simulator factory
// ---------------------------------------------------------------------------

export function createS3Simulator(options: S3SimulatorOptions = {}): S3Simulator {
  const dataDir = options.dataDir ?? S3_SIMULATOR_DEFAULT_DATA_DIR;

  /**
   * The file for a `bucket/key` path. Keys are URL-decoded so an SDK call, a
   * presigned URL and an `x-amz-copy-source` header all name the same file.
   * A key that resolves outside `dataDir` (`../`) is refused.
   */
  function resolveKeyPath(bucketAndKey: string): string {
    const root = path.resolve(dataDir);
    const resolved = path.resolve(root, bucketAndKey);
    if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
      throw new Error(`Key resolves outside the data directory: ${bucketAndKey}`);
    }
    return resolved;
  }

  function objectPath(reqPath: string): string {
    // reqPath starts with '/', e.g. '/my-bucket/a/b/c.mp4'
    return resolveKeyPath(decodeURIComponent(reqPath.slice(1)));
  }

  async function writeContentType(filePath: string, contentType: string | undefined): Promise<void> {
    if (!contentType) return;
    await fs.writeFile(`${filePath}${CONTENT_TYPE_SUFFIX}`, contentType, 'utf8');
  }

  async function readContentType(filePath: string): Promise<string | null> {
    try {
      const stored = await fs.readFile(`${filePath}${CONTENT_TYPE_SUFFIX}`, 'utf8');
      return stored.trim() || null;
    } catch (err) {
      // A missing sidecar is expected, not a failure: SDK calls that send no
      // Content-Type simply have none stored and fall back to the default.
      // Anything else is a real read error and must not vanish into a silent
      // default.
      if (!isMissingFile(err)) {
        console.error('[s3-simulator] content-type sidecar read error', filePath, err);
      }
      return null;
    }
  }

  async function applyStoredContentType(filePath: string, res: express.Response): Promise<void> {
    const stored = await readContentType(filePath);
    if (stored) res.setHeader('Content-Type', stored);
  }

  const app = express();

  // ── CORS headers on every response ───────────────────────────────────────
  // Required because browsers PUT presigned URLs from a different origin than
  // the simulator.
  app.use((_req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Access-Control-Expose-Headers', 'ETag, Content-Range, Accept-Ranges, Content-Length, Content-Encoding');
    next();
  });

  // ── Preflight ─────────────────────────────────────────────────────────────
  app.options('{*path}', (_req, res) => {
    res.setHeader('Access-Control-Max-Age', '3600');
    res.status(204).send('');
  });

  // ── Test control ──────────────────────────────────────────────────────────
  app.post('/__local/reset', async (_req, res) => {
    await reset();
    res.status(204).send('');
  });

  // ── PUT /{bucket}/{key} ───────────────────────────────────────────────────
  // Used by:
  //   • AWS SDK PutObjectCommand
  //   • Browser fetch() with a presigned URL (direct upload)
  //   • AWS SDK CopyObjectCommand (when the x-amz-copy-source header is present
  //     the body is empty and the destination is populated from the source key
  //     instead of from the request body).
  app.put('{*path}', async (req, res) => {
    const filePath = objectPath(req.path);
    try {
      const copySource = req.headers['x-amz-copy-source'];
      if (copySource) {
        // CopySource looks like "/{bucket}/{key}" or "{bucket}/{key}", possibly
        // URL-encoded. Strip the leading slash and treat the rest as a path
        // beneath dataDir — the same layout used for PUT/GET.
        const raw = Array.isArray(copySource) ? copySource[0] : copySource;
        const decoded = decodeURIComponent((raw ?? '').replace(/^\//, ''));
        const sourcePath = resolveKeyPath(decoded.split('?')[0] ?? '');
        let data: Buffer;
        try {
          data = await fs.readFile(sourcePath);
        } catch (err) {
          if (!isMissingFile(err)) throw err;
          res.status(404).type('application/xml').send(xmlError('NoSuchKey', 'The specified key does not exist.'));
          return;
        }
        await fs.mkdir(path.dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, data);
        // A copy inherits the source object's Content-Type, as it does on S3.
        await writeContentType(filePath, (await readContentType(sourcePath)) ?? undefined);
        // Real S3 returns a CopyObjectResult XML body with ETag and
        // LastModified. The SDK only uses these fields opportunistically, so an
        // ETag is sufficient.
        const etag = `"${data.length}"`;
        res.setHeader('ETag', etag);
        res.status(200).type('application/xml').send(
          `<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult><ETag>${etag}</ETag><LastModified>${new Date().toISOString()}</LastModified></CopyObjectResult>`,
        );
        return;
      }
      const data = await readRawBody(req);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, data);
      await writeContentType(filePath, req.headers['content-type']);
      // S3 returns an ETag on success – some SDK code checks for it.
      res.setHeader('ETag', `"${data.length}"`);
      res.status(200).send('');
    } catch (err) {
      console.error('[s3-simulator] PUT error', req.path, err);
      res.status(500).type('application/xml').send(xmlError('InternalError', 'Internal error.'));
    }
  });

  // ── GET /{bucket}/{key} ───────────────────────────────────────────────────
  // Used by AWS SDK GetObjectCommand and by browser clients that issue HTTP
  // Range requests (for example a PMTiles map reader). Express answers HEAD
  // through this handler too, which is what HeadObjectCommand sends.
  app.get('{*path}', async (req, res) => {
    const filePath = objectPath(req.path);
    // The sidecars are simulator bookkeeping, not objects. Keep them out of the
    // key namespace so a GET can never read one back as if it were content.
    if (req.path.endsWith(CONTENT_TYPE_SUFFIX)) {
      res.status(404).type('application/xml').send(xmlError('NoSuchKey', 'The specified key does not exist.'));
      return;
    }
    try {
      const rangeHeader = req.headers['range'];
      if (rangeHeader) {
        // Parse "bytes=start-end" (end is optional per spec).
        const match = /^bytes=(\d+)-(\d*)$/.exec(rangeHeader);
        if (!match) {
          res.status(416).type('application/xml').send(xmlError('InvalidRange', 'The requested range is not satisfiable.'));
          return;
        }
        const stat = await fs.stat(filePath);
        const total = stat.size;
        const start = parseInt(match[1] || '0', 10);
        const end = match[2] ? parseInt(match[2], 10) : total - 1;
        if (start > end || end >= total) {
          res.setHeader('Content-Range', `bytes */${total}`);
          res.status(416).type('application/xml').send(xmlError('InvalidRange', 'The requested range is not satisfiable.'));
          return;
        }
        const length = end - start + 1;
        const fh = await fs.open(filePath, 'r');
        try {
          const buf = Buffer.allocUnsafe(length);
          await fh.read(buf, 0, length, start);
          res.setHeader('Content-Range', `bytes ${start}-${end}/${total}`);
          res.setHeader('Content-Length', String(length));
          res.setHeader('Accept-Ranges', 'bytes');
          await applyStoredContentType(filePath, res);
          res.status(206).send(buf);
        } finally {
          await fh.close();
        }
        return;
      }

      const data = await fs.readFile(filePath);
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('ETag', `"${data.length}"`);
      await applyStoredContentType(filePath, res);
      res.status(200).send(data);
    } catch {
      // Mimic the XML error body real S3 sends so the SDK throws NoSuchKey.
      res.status(404).type('application/xml').send(xmlError('NoSuchKey', 'The specified key does not exist.'));
    }
  });

  // ── DELETE /{bucket}/{key} ────────────────────────────────────────────────
  // Used by AWS SDK DeleteObjectCommand.
  // S3 returns 204 whether the key existed or not.
  app.delete('{*path}', async (req, res) => {
    const filePath = objectPath(req.path);
    try {
      await fs.unlink(filePath);
    } catch {
      // Ignore – S3 is idempotent on delete.
    }
    try {
      await fs.unlink(`${filePath}${CONTENT_TYPE_SUFFIX}`);
    } catch (err) {
      // The sidecar is optional, so its absence is normal and delete stays
      // idempotent — but a failure to remove one that IS there would leak a
      // stale content type onto the next object at this key.
      if (!isMissingFile(err)) {
        console.error('[s3-simulator] content-type sidecar delete error', filePath, err);
      }
    }
    res.status(204).send('');
  });

  async function reset(): Promise<void> {
    await fs.rm(dataDir, { recursive: true, force: true });
    await fs.mkdir(dataDir, { recursive: true });
  }

  return { app, dataDir, reset };
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export interface StartS3SimulatorOptions extends S3SimulatorOptions {
  /** Default `S3_SIMULATOR_PORT` env var, else 38304. Pass 0 for a free port. */
  readonly port?: number;
  readonly host?: string;
}

export async function startS3Simulator(
  options: StartS3SimulatorOptions = {},
): Promise<RunningSimulator & { readonly simulator: S3Simulator }> {
  const port = options.port ?? Number(process.env.S3_SIMULATOR_PORT ?? S3_SIMULATOR_DEFAULT_PORT);
  const simulator = createS3Simulator(options);

  // Ensure the data directory exists before any requests arrive.
  await fs.mkdir(simulator.dataDir, { recursive: true });

  const running = await listen(simulator.app, port, options.host);
  console.log(`S3 simulator listening on ${running.url}  (data → ${simulator.dataDir}/)`);
  return { ...running, simulator };
}
