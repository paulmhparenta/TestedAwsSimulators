/**
 * In-process AWS Transcribe stand-in.
 *
 * This is not an HTTP simulator of the Transcribe API. It is a drop-in
 * implementation of a small `TranscriptionService` port — start a job, poll its
 * status, delete it — that behaves the way Transcribe does from the point of
 * view of code that polls for the output file:
 *
 *  - `startTranscription({ jobName, outputKey, ... })` immediately writes a
 *    Transcribe-shaped output JSON
 *    (`{"results":{"transcripts":[{"transcript":"..."}]}}`) through the
 *    supplied `TranscriptOutputWriter` (for example an S3 client pointed at the
 *    S3 simulator). The transcript comes from the scripted queue if it is not
 *    empty, otherwise from the default placeholder.
 *  - `getJobStatus()` returns `'COMPLETED'` once the output is written, and
 *    `'IN_PROGRESS'` for a job it has not seen.
 *  - `deleteJob()` is idempotent, as Transcribe's DeleteTranscriptionJob is for
 *    a job that is already gone.
 *
 * Test hooks (HTTP), mounted on any Express app with
 * `registerTranscriptionSimulatorRoutes`:
 *
 *   POST /__local/transcription/script        { transcript: string }
 *   POST /__local/transcription/script-words  { words: [{ text, startSeconds, endSeconds }], fullText? }
 *   POST /__local/transcription/clear
 *   GET  /__local/transcription/captured      → { jobs: CapturedTranscriptionJob[] }
 */
import type { Express } from 'express';

export interface StartTranscriptionRequest {
  jobName: string;
  fileS3Uri: string;
  outputBucket: string;
  outputKey: string;
  languageCode?: string;
}

export type TranscriptionJobStatus = 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';

export interface GetJobStatusResponse {
  status: TranscriptionJobStatus;
}

/** The port an application codes against. A real implementation wraps `@aws-sdk/client-transcribe`. */
export interface TranscriptionService {
  startTranscription(request: StartTranscriptionRequest): Promise<void>;
  getJobStatus(jobName: string): Promise<GetJobStatusResponse>;
  /**
   * Idempotent — succeeds when the job is already gone. Transcribe rejects a
   * StartTranscriptionJob with a duplicate jobName, so a reprocess deletes
   * first.
   */
  deleteJob(jobName: string): Promise<void>;
}

/** Where the simulator writes the transcript output. */
export interface TranscriptOutputWriter {
  putFile(key: string, data: Buffer, contentType: string): Promise<void>;
}

export interface CapturedTranscriptionJob {
  jobName: string;
  fileS3Uri: string;
  outputBucket: string;
  outputKey: string;
  capturedAt: string;
  transcriptUsed: string;
}

interface ScriptedEntry {
  body: Buffer;
  describe: string;
}

export interface ScriptedWord {
  text: string;
  startSeconds: number;
  endSeconds: number;
}

export const DEFAULT_SIMULATED_TRANSCRIPT = '[simulated transcript placeholder]';

export class TranscriptionSimulator implements TranscriptionService {
  private readonly scriptedQueue: ScriptedEntry[] = [];
  private readonly captured: CapturedTranscriptionJob[] = [];
  private readonly completedJobs = new Set<string>();

  public constructor(
    private readonly outputWriter: TranscriptOutputWriter,
    private readonly defaultTranscript: string = DEFAULT_SIMULATED_TRANSCRIPT,
  ) {}

  public reset(): void {
    this.scriptedQueue.length = 0;
    this.captured.length = 0;
    this.completedJobs.clear();
  }

  /** The next job's output carries this transcript (FIFO queue). */
  public queueScriptedTranscript(transcript: string): void {
    const body = Buffer.from(JSON.stringify({ results: { transcripts: [{ transcript }] } }), 'utf8');
    this.scriptedQueue.push({ body, describe: transcript });
  }

  /**
   * The next job's output is a word-timed document:
   * `{ version: 2, fullText, segments: [], words }`. Use it when the code under
   * test reads word timings rather than the plain Transcribe shape.
   */
  public queueScriptedWords(words: ScriptedWord[], fullText?: string): void {
    const text = (fullText ?? words.map((w) => w.text).join(' ')).trim();
    const body = Buffer.from(JSON.stringify({ version: 2, fullText: text, segments: [], words }), 'utf8');
    this.scriptedQueue.push({ body, describe: `words[${words.length}]: ${text}` });
  }

  public clearScripted(): void {
    this.scriptedQueue.length = 0;
  }

  public clearCaptured(): void {
    this.captured.length = 0;
  }

  public getCaptured(): readonly CapturedTranscriptionJob[] {
    return this.captured.slice();
  }

  public async startTranscription(request: StartTranscriptionRequest): Promise<void> {
    const next = this.scriptedQueue.shift();
    const body = next?.body ?? Buffer.from(
      JSON.stringify({ results: { transcripts: [{ transcript: this.defaultTranscript }] } }),
      'utf8',
    );
    const describe = next?.describe ?? this.defaultTranscript;
    await this.outputWriter.putFile(request.outputKey, body, 'application/json');
    this.completedJobs.add(request.jobName);
    this.captured.push({
      jobName: request.jobName,
      fileS3Uri: request.fileS3Uri,
      outputBucket: request.outputBucket,
      outputKey: request.outputKey,
      capturedAt: new Date().toISOString(),
      transcriptUsed: describe,
    });
  }

  public async getJobStatus(jobName: string): Promise<GetJobStatusResponse> {
    return { status: this.completedJobs.has(jobName) ? 'COMPLETED' : 'IN_PROGRESS' };
  }

  public async deleteJob(jobName: string): Promise<void> {
    this.completedJobs.delete(jobName);
    const idx = this.captured.findIndex((j) => j.jobName === jobName);
    if (idx >= 0) this.captured.splice(idx, 1);
  }
}

/**
 * Mount the test-only HTTP control routes for the simulator on the supplied
 * Express app. The app must parse JSON bodies (`express.json()`).
 */
export function registerTranscriptionSimulatorRoutes(app: Express, simulator: TranscriptionSimulator): void {
  app.post('/__local/transcription/script', (req, res) => {
    const body = req.body as { transcript?: unknown } | undefined;
    if (typeof body?.transcript !== 'string') {
      res.status(400).json({ error: { message: 'transcript (string) required' } });
      return;
    }
    simulator.queueScriptedTranscript(body.transcript);
    res.status(204).end();
  });

  app.post('/__local/transcription/script-words', (req, res) => {
    const body = req.body as { words?: unknown; fullText?: unknown } | undefined;
    if (!Array.isArray(body?.words)) {
      res.status(400).json({ error: { message: 'words (array) required' } });
      return;
    }
    const words: ScriptedWord[] = [];
    for (const item of body.words) {
      if (!item || typeof item !== 'object') {
        res.status(400).json({ error: { message: 'each word must be an object' } });
        return;
      }
      const w = item as { text?: unknown; startSeconds?: unknown; endSeconds?: unknown };
      if (typeof w.text !== 'string' || typeof w.startSeconds !== 'number' || typeof w.endSeconds !== 'number') {
        res.status(400).json({
          error: { message: 'each word needs text (string), startSeconds, endSeconds (numbers)' },
        });
        return;
      }
      words.push({ text: w.text, startSeconds: w.startSeconds, endSeconds: w.endSeconds });
    }
    const fullText = typeof body.fullText === 'string' ? body.fullText : undefined;
    simulator.queueScriptedWords(words, fullText);
    res.status(204).end();
  });

  app.post('/__local/transcription/clear', (_req, res) => {
    simulator.clearScripted();
    simulator.clearCaptured();
    res.status(204).end();
  });

  app.get('/__local/transcription/captured', (_req, res) => {
    res.status(200).json({ jobs: simulator.getCaptured() });
  });
}
