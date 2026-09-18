import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  NoSuchKey,
  PutObjectCommand,
  S3Client,
  S3ServiceException,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

import { startS3Simulator, type S3Simulator } from './s3-simulator';
import type { RunningSimulator } from '../shared/server';

/**
 * Every case drives the simulator through the real AWS SDK v3 client, so a
 * pass means the SDK accepts the simulator's responses, not only that the
 * simulator answers.
 */
let running: RunningSimulator & { simulator: S3Simulator };
let s3: S3Client;
let dataDir: string;
const BUCKET = 'test-bucket';

beforeAll(async () => {
  dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tested-aws-simulators-s3-'));
  running = await startS3Simulator({ port: 0, dataDir });
  s3 = new S3Client({
    endpoint: running.url,
    region: 'us-east-1',
    forcePathStyle: true,
    credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
  });
});

afterAll(async () => {
  s3.destroy();
  await running.close();
  await fs.rm(dataDir, { recursive: true, force: true });
});

beforeEach(async () => {
  await running.simulator.reset();
});

async function put(key: string, body: string | Buffer, contentType?: string): Promise<void> {
  await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: key, Body: body, ContentType: contentType }));
}

async function getText(key: string): Promise<{ body: string; contentType?: string }> {
  const res = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: key }));
  return { body: await res.Body!.transformToString(), contentType: res.ContentType };
}

describe('S3 simulator through the AWS SDK', () => {
  it('stores an object and returns the same bytes', async () => {
    await put('docs/hello.txt', 'hello world');

    expect((await getText('docs/hello.txt')).body).toBe('hello world');
  });

  it('replays the Content-Type given at PUT time', async () => {
    await put('pages/index.html', '<p>hi</p>', 'text/html');

    expect((await getText('pages/index.html')).contentType).toBe('text/html');
  });

  it('keeps binary bodies byte for byte', async () => {
    const bytes = Buffer.from([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    await put('bin/data.bin', bytes, 'application/octet-stream');

    const res = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'bin/data.bin' }));
    expect(Buffer.from(await res.Body!.transformToByteArray())).toEqual(bytes);
  });

  it('stores a key with spaces and unicode under the name the SDK sent', async () => {
    await put('folder/a file é.txt', 'spaced');

    expect((await getText('folder/a file é.txt')).body).toBe('spaced');
  });

  it('answers a missing key with NoSuchKey', async () => {
    await expect(s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'nope.txt' }))).rejects.toBeInstanceOf(NoSuchKey);
  });

  it('answers HeadObject with the length and type of a stored object', async () => {
    await put('head/me.json', '{"a":1}', 'application/json');

    const head = await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: 'head/me.json' }));
    expect(head.ContentLength).toBe(7);
    expect(head.ContentType).toBe('application/json');
  });

  it('answers HeadObject for a missing key with a 404', async () => {
    const err = await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: 'missing.json' })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(S3ServiceException);
    expect((err as S3ServiceException).$metadata.httpStatusCode).toBe(404);
  });

  it('serves an HTTP Range request with 206 and Content-Range', async () => {
    await put('range/abc.txt', 'abcdefghij', 'text/plain');

    const res = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'range/abc.txt', Range: 'bytes=2-5' }));
    expect(await res.Body!.transformToString()).toBe('cdef');
    expect(res.ContentRange).toBe('bytes 2-5/10');
    expect(res.$metadata.httpStatusCode).toBe(206);
  });

  it('serves an open-ended range to the last byte', async () => {
    await put('range/open.txt', 'abcdefghij');

    const res = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'range/open.txt', Range: 'bytes=7-' }));
    expect(await res.Body!.transformToString()).toBe('hij');
  });

  it('refuses a range past the end with 416', async () => {
    await put('range/short.txt', 'abc');

    const err = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'range/short.txt', Range: 'bytes=5-9' }))
      .catch((e: unknown) => e);
    expect((err as S3ServiceException).$metadata.httpStatusCode).toBe(416);
  });

  it('copies an object and its Content-Type with CopyObject', async () => {
    await put('copy/source.html', '<b>x</b>', 'text/html');

    await s3.send(new CopyObjectCommand({
      Bucket: BUCKET,
      Key: 'copy/target.html',
      CopySource: `${BUCKET}/copy/source.html`,
    }));

    expect(await getText('copy/target.html')).toEqual({ body: '<b>x</b>', contentType: 'text/html' });
  });

  it('refuses a copy from a missing source with NoSuchKey', async () => {
    await expect(s3.send(new CopyObjectCommand({
      Bucket: BUCKET,
      Key: 'copy/target.txt',
      CopySource: `${BUCKET}/copy/does-not-exist.txt`,
    }))).rejects.toBeInstanceOf(NoSuchKey);
  });

  it('deletes an object, and a second delete still succeeds', async () => {
    await put('del/me.txt', 'bye', 'text/plain');

    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: 'del/me.txt' }));
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: 'del/me.txt' }));

    await expect(s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'del/me.txt' }))).rejects.toBeInstanceOf(NoSuchKey);
  });

  it('does not leak a deleted object\'s Content-Type onto the next object at that key', async () => {
    await put('reuse/key', 'first', 'text/html');
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: 'reuse/key' }));

    // A raw PUT with no Content-Type, as some clients send.
    await fetch(`${running.url}/${BUCKET}/reuse/key`, { method: 'PUT', body: 'second' });

    const res = await fetch(`${running.url}/${BUCKET}/reuse/key`);
    expect(res.headers.get('content-type')).not.toContain('text/html');
  });

  it('accepts a browser PUT to a presigned URL', async () => {
    const url = await getSignedUrl(
      s3,
      new PutObjectCommand({ Bucket: BUCKET, Key: 'presigned/upload.txt', ContentType: 'text/plain' }),
      { expiresIn: 60 },
    );

    const res = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'text/plain' }, body: 'from the browser' });
    expect(res.status).toBe(200);
    expect(await getText('presigned/upload.txt')).toEqual({ body: 'from the browser', contentType: 'text/plain' });
  });

  it('serves a presigned GET URL', async () => {
    await put('presigned/download.txt', 'download me');
    const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket: BUCKET, Key: 'presigned/download.txt' }), { expiresIn: 60 });

    const res = await fetch(url);
    expect(await res.text()).toBe('download me');
  });

  it('answers a CORS preflight for a browser upload', async () => {
    const res = await fetch(`${running.url}/${BUCKET}/any/key`, {
      method: 'OPTIONS',
      headers: { origin: 'http://localhost:5173', 'access-control-request-method': 'PUT' },
    });

    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('access-control-allow-methods')).toContain('PUT');
    expect(res.headers.get('access-control-expose-headers')).toContain('ETag');
  });

  it('never serves a Content-Type sidecar as an object', async () => {
    await put('side/car.txt', 'x', 'text/plain');

    const res = await fetch(`${running.url}/${BUCKET}/side/car.txt.__content-type`);
    expect(res.status).toBe(404);
  });

  it('refuses a key that resolves outside the data directory', async () => {
    // `%2F` survives URL normalisation, so the simulator receives the `..`
    // segments and must refuse them itself.
    const res = await fetch(`${running.url}/${BUCKET}/..%2F..%2Fescape.txt`, { method: 'PUT', body: 'x' });

    expect(res.status).toBe(500);
    await expect(fs.stat(path.join(path.dirname(dataDir), 'escape.txt'))).rejects.toThrow();
  });

  it('writes objects under the data directory, so they survive a restart', async () => {
    await put('disk/persist.txt', 'on disk');

    expect(await fs.readFile(path.join(dataDir, BUCKET, 'disk', 'persist.txt'), 'utf8')).toBe('on disk');
  });

  it('empties the store on POST /__local/reset', async () => {
    await put('reset/me.txt', 'x');

    const res = await fetch(`${running.url}/__local/reset`, { method: 'POST' });
    expect(res.status).toBe(204);
    await expect(s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'reset/me.txt' }))).rejects.toBeInstanceOf(NoSuchKey);
  });
});
