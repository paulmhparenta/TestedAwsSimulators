import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';

import {
  DEFAULT_SIMULATED_TRANSCRIPT,
  TranscriptionSimulator,
  registerTranscriptionSimulatorRoutes,
  type TranscriptOutputWriter,
} from './transcription-simulator';
import { startS3Simulator, type S3Simulator } from '../s3/s3-simulator';
import { listen, type RunningSimulator } from '../shared/server';

class MemoryWriter implements TranscriptOutputWriter {
  public readonly files = new Map<string, { data: Buffer; contentType: string }>();
  public async putFile(key: string, data: Buffer, contentType: string): Promise<void> {
    this.files.set(key, { data, contentType });
  }
  public json(key: string): unknown {
    return JSON.parse(this.files.get(key)!.data.toString('utf8'));
  }
}

const job = (jobName: string, outputKey = `transcripts/${jobName}.json`) => ({
  jobName,
  fileS3Uri: `s3://media/${jobName}.m4a`,
  outputBucket: 'media',
  outputKey,
});

describe('TranscriptionSimulator', () => {
  let writer: MemoryWriter;
  let simulator: TranscriptionSimulator;

  beforeEach(() => {
    writer = new MemoryWriter();
    simulator = new TranscriptionSimulator(writer);
  });

  it('reports IN_PROGRESS for a job it has not seen', async () => {
    expect(await simulator.getJobStatus('unknown')).toEqual({ status: 'IN_PROGRESS' });
  });

  it('writes a Transcribe-shaped output with the default transcript, then reports COMPLETED', async () => {
    await simulator.startTranscription(job('a'));

    expect(await simulator.getJobStatus('a')).toEqual({ status: 'COMPLETED' });
    expect(writer.files.get('transcripts/a.json')?.contentType).toBe('application/json');
    expect(writer.json('transcripts/a.json')).toEqual({ results: { transcripts: [{ transcript: DEFAULT_SIMULATED_TRANSCRIPT }] } });
  });

  it('uses a custom default transcript', async () => {
    const custom = new TranscriptionSimulator(writer, 'custom default');
    await custom.startTranscription(job('a'));

    expect(writer.json('transcripts/a.json')).toEqual({ results: { transcripts: [{ transcript: 'custom default' }] } });
  });

  it('uses scripted transcripts in order, then falls back to the default', async () => {
    simulator.queueScriptedTranscript('first');
    simulator.queueScriptedTranscript('second');

    await simulator.startTranscription(job('a'));
    await simulator.startTranscription(job('b'));
    await simulator.startTranscription(job('c'));

    const transcriptOf = (key: string) => (writer.json(key) as { results: { transcripts: Array<{ transcript: string }> } }).results.transcripts[0]!.transcript;
    expect([transcriptOf('transcripts/a.json'), transcriptOf('transcripts/b.json'), transcriptOf('transcripts/c.json')])
      .toEqual(['first', 'second', DEFAULT_SIMULATED_TRANSCRIPT]);
  });

  it('writes a word-timed document for scripted words', async () => {
    const words = [
      { text: 'hello', startSeconds: 0, endSeconds: 0.4 },
      { text: 'there', startSeconds: 0.5, endSeconds: 0.9 },
    ];
    simulator.queueScriptedWords(words);

    await simulator.startTranscription(job('w'));
    expect(writer.json('transcripts/w.json')).toEqual({ version: 2, fullText: 'hello there', segments: [], words });
  });

  it('uses an explicit fullText for scripted words', async () => {
    simulator.queueScriptedWords([{ text: 'hi', startSeconds: 0, endSeconds: 1 }], 'Hi!');

    await simulator.startTranscription(job('w'));
    expect((writer.json('transcripts/w.json') as { fullText: string }).fullText).toBe('Hi!');
  });

  it('captures every started job', async () => {
    simulator.queueScriptedTranscript('scripted');
    await simulator.startTranscription(job('a'));

    expect(simulator.getCaptured()).toMatchObject([{
      jobName: 'a',
      fileS3Uri: 's3://media/a.m4a',
      outputBucket: 'media',
      outputKey: 'transcripts/a.json',
      transcriptUsed: 'scripted',
    }]);
  });

  it('deleteJob forgets the job and is idempotent', async () => {
    await simulator.startTranscription(job('a'));

    await simulator.deleteJob('a');
    await simulator.deleteJob('a');

    expect(await simulator.getJobStatus('a')).toEqual({ status: 'IN_PROGRESS' });
    expect(simulator.getCaptured()).toHaveLength(0);
  });

  it('clearScripted drops queued transcripts; reset drops everything', async () => {
    simulator.queueScriptedTranscript('dropped');
    simulator.clearScripted();
    await simulator.startTranscription(job('a'));
    expect(simulator.getCaptured()[0]?.transcriptUsed).toBe(DEFAULT_SIMULATED_TRANSCRIPT);

    simulator.reset();
    expect(simulator.getCaptured()).toHaveLength(0);
    expect(await simulator.getJobStatus('a')).toEqual({ status: 'IN_PROGRESS' });
  });
});

describe('TranscriptionSimulator writing to the S3 simulator', () => {
  let s3Running: RunningSimulator & { simulator: S3Simulator };
  let dataDir: string;
  let s3: S3Client;

  beforeAll(async () => {
    dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tested-aws-simulators-transcribe-'));
    s3Running = await startS3Simulator({ port: 0, dataDir });
    s3 = new S3Client({
      endpoint: s3Running.url,
      region: 'us-east-1',
      forcePathStyle: true,
      credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
    });
  });

  afterAll(async () => {
    s3.destroy();
    await s3Running.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  });

  it('produces an output file the SDK reads back', async () => {
    const simulator = new TranscriptionSimulator({
      putFile: async (key, data, contentType) => {
        await s3.send(new PutObjectCommand({ Bucket: 'media', Key: key, Body: data, ContentType: contentType }));
      },
    });
    simulator.queueScriptedTranscript('stored in s3');

    await simulator.startTranscription(job('s3job'));

    const res = await s3.send(new GetObjectCommand({ Bucket: 'media', Key: 'transcripts/s3job.json' }));
    expect(res.ContentType).toBe('application/json');
    expect(JSON.parse(await res.Body!.transformToString())).toEqual({ results: { transcripts: [{ transcript: 'stored in s3' }] } });
  });
});

describe('Transcription simulator HTTP routes', () => {
  let writer: MemoryWriter;
  let simulator: TranscriptionSimulator;
  let running: RunningSimulator;

  beforeAll(async () => {
    writer = new MemoryWriter();
    simulator = new TranscriptionSimulator(writer);
    const app = express();
    app.use(express.json());
    registerTranscriptionSimulatorRoutes(app, simulator);
    running = await listen(app, 0);
  });

  afterAll(async () => {
    await running.close();
  });

  beforeEach(() => {
    simulator.reset();
  });

  const post = (route: string, body: unknown) => fetch(`${running.url}/__local/transcription/${route}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

  it('scripts a transcript', async () => {
    expect((await post('script', { transcript: 'over http' })).status).toBe(204);

    await simulator.startTranscription(job('h'));
    expect(simulator.getCaptured()[0]?.transcriptUsed).toBe('over http');
  });

  it('refuses a script with no transcript', async () => {
    expect((await post('script', {})).status).toBe(400);
  });

  it('scripts words', async () => {
    const res = await post('script-words', { words: [{ text: 'a', startSeconds: 0, endSeconds: 1 }], fullText: 'A' });
    expect(res.status).toBe(204);

    await simulator.startTranscription(job('h'));
    expect((writer.json('transcripts/h.json') as { fullText: string }).fullText).toBe('A');
  });

  it.each([
    ['no words array', {}],
    ['a word that is not an object', { words: ['a'] }],
    ['a word with no timings', { words: [{ text: 'a' }] }],
  ])('refuses script-words with %s', async (_label, body) => {
    expect((await post('script-words', body)).status).toBe(400);
  });

  it('lists captured jobs and clears them', async () => {
    await simulator.startTranscription(job('listed'));

    const captured = (await (await fetch(`${running.url}/__local/transcription/captured`)).json()) as { jobs: Array<{ jobName: string }> };
    expect(captured.jobs.map((j) => j.jobName)).toEqual(['listed']);

    expect((await post('clear', {})).status).toBe(204);
    expect(simulator.getCaptured()).toHaveLength(0);
  });
});
