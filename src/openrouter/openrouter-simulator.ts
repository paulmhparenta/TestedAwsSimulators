/**
 * Minimal OpenRouter (OpenAI-compatible) simulator for local development and tests.
 *
 * Implements the subset of the OpenRouter API most applications use:
 *   POST /api/v1/chat/completions  – chat completion, streamed or not, with an
 *                                    optional response_format = json_object | json_schema
 *   POST /api/v1/embeddings        – deterministic embeddings
 *   GET  /api/v1/models            – list models
 *
 * Point a client at `http://localhost:<port>/api/v1` as its base URL.
 *
 * Test hooks (in process, and over HTTP under /__local/openrouter/*)
 *   queueScriptedResponse(content) – the next chat/completions call returns
 *                                    this exact content (FIFO queue).
 *   getCapturedRequests()          – every chat/completions request, for assertions.
 *   setStreamConfig(config)        – chunk size, delay and keep-alive comments
 *                                    for streamed responses.
 *   reset()                        – clear all of the above.
 *
 * If the queue is empty the simulator answers with a deterministic echo:
 * "Echo: <last user message content>". When response_format is a json_schema
 * the fallback is a minimal JSON object with the schema's required keys.
 */

import express from 'express';

import { listen, type RunningSimulator } from '../shared/server';

export const OPENROUTER_SIMULATOR_DEFAULT_PORT = 38307;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OpenRouterSimulatorMessage {
  role: string;
  content: string;
}

export interface OpenRouterSimulatorJsonObjectResponseFormat {
  type: 'json_object';
}

export interface OpenRouterSimulatorJsonSchemaResponseFormat {
  type: 'json_schema';
  json_schema: {
    name: string;
    strict?: boolean;
    schema: Record<string, unknown>;
  };
}

export interface OpenRouterSimulatorRequest {
  model: string;
  messages: OpenRouterSimulatorMessage[];
  response_format?: OpenRouterSimulatorJsonObjectResponseFormat | OpenRouterSimulatorJsonSchemaResponseFormat;
  stream?: boolean;
}

export interface CapturedAiRequest {
  capturedAt: string;
  request: OpenRouterSimulatorRequest;
}

/**
 * How a streamed response is cut up and paced.
 *
 * A test that asserts progressive rendering needs more than one chunk and a
 * gap between them; a test that only needs the final answer wants no delay at
 * all.
 */
export interface StreamConfig {
  /** Characters per `data:` event. */
  chunkChars: number;
  /** Pause between events. */
  delayMs: number;
  /**
   * Keep-alive comments emitted before the first content event, reproducing
   * what OpenRouter sends while a model is queued. A reader that treats a
   * comment as data fails here and not in production.
   */
  leadingKeepAlives: number;
}

export const DEFAULT_STREAM_CONFIG: StreamConfig = {
  chunkChars: 24,
  delayMs: 0,
  leadingKeepAlives: 1,
};

export interface OpenRouterSimulator {
  readonly app: express.Express;
  queueScriptedResponse(content: string): void;
  getCapturedRequests(): readonly CapturedAiRequest[];
  getStreamConfig(): StreamConfig;
  setStreamConfig(next: Partial<StreamConfig>): void;
  reset(): void;
}

// ---------------------------------------------------------------------------
// Default response synthesis
// ---------------------------------------------------------------------------

function lastUserMessage(messages: OpenRouterSimulatorMessage[]): string {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m && m.role === 'user') return m.content;
  }
  return '';
}

/** Best effort: a minimal value with the top-level required keys of `schema`. */
export function defaultJsonForSchema(schema: Record<string, unknown>): unknown {
  const type = schema['type'];
  if (type === 'object') {
    const props = (schema['properties'] ?? {}) as Record<string, Record<string, unknown>>;
    const required = Array.isArray(schema['required']) ? (schema['required'] as string[]) : Object.keys(props);
    const out: Record<string, unknown> = {};
    for (const key of required) {
      const propSchema = props[key];
      out[key] = propSchema ? defaultJsonForSchema(propSchema) : null;
    }
    return out;
  }
  if (type === 'array') return [];
  if (type === 'string') return '';
  if (type === 'number' || type === 'integer') return 0;
  if (type === 'boolean') return false;
  return null;
}

function buildDefaultContent(req: OpenRouterSimulatorRequest): string {
  const fmt = req.response_format;
  if (fmt?.type === 'json_schema') {
    return JSON.stringify(defaultJsonForSchema(fmt.json_schema.schema));
  }
  if (fmt?.type === 'json_object') {
    return JSON.stringify({ echo: lastUserMessage(req.messages) });
  }
  return `Echo: ${lastUserMessage(req.messages)}`;
}

// ---------------------------------------------------------------------------
// Streamed responses
// ---------------------------------------------------------------------------

/**
 * Splits text into chunks of at most `size` characters WITHOUT splitting a
 * surrogate pair.
 *
 * A naive slice can cut an emoji in half, and each half then decodes as a
 * replacement character. The real API chunks on token boundaries and never
 * produces a lone surrogate, so a simulator that does would fail a reader the
 * real API would not.
 */
export function chunkText(text: string, size: number): string[] {
  const chunks: string[] = [];
  let index = 0;
  while (index < text.length) {
    let end = Math.min(index + size, text.length);
    const lastCode = text.charCodeAt(end - 1);
    const isHighSurrogate = lastCode >= 0xd800 && lastCode <= 0xdbff;
    if (isHighSurrogate && end < text.length) end += 1;
    chunks.push(text.slice(index, end));
    index = end;
  }
  return chunks;
}

const sleep = (ms: number): Promise<void> =>
  ms > 0 ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve();

/**
 * Writes the completion as server-sent events, framed the way OpenRouter
 * frames them.
 *
 * The shape below was taken from a live capture against
 * `https://openrouter.ai/api/v1/chat/completions`, not from the documentation:
 *
 *   - `data: {json}` then a BLANK LINE, per event.
 *   - Every delta carries `role: "assistant"` alongside `content`. There is
 *     NO separate role-only preamble event; the first event carries text.
 *   - The stream ends with TWO `finish_reason: "stop"` events — the second
 *     repeats it and adds `usage` — and then `data: [DONE]`.
 *   - `: OPENROUTER PROCESSING` comments appear while a model is queued. The
 *     simulator sends one by default: a reader that trips over a comment must
 *     fail here and not the first time a model is busy.
 */
async function writeStreamedCompletion(
  res: express.Response,
  body: OpenRouterSimulatorRequest,
  content: string,
  config: StreamConfig,
): Promise<void> {
  const id = `gen-${Date.now()}-sim`;
  const created = Math.floor(Date.now() / 1000);

  res.status(200);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  // Without this, a proxy in front of the simulator may buffer the whole body
  // and deliver it at once — which looks exactly like streaming being broken.
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const writeEvent = (payload: unknown): void => {
    res.write(`data: ${typeof payload === 'string' ? payload : JSON.stringify(payload)}\n\n`);
  };
  const envelope = (choice: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
    id,
    object: 'chat.completion.chunk',
    created,
    model: body.model,
    provider: 'Simulator',
    choices: [choice],
    ...extra,
  });

  for (let i = 0; i < config.leadingKeepAlives; i += 1) {
    res.write(': OPENROUTER PROCESSING\n\n');
  }

  for (const chunk of chunkText(content, Math.max(1, config.chunkChars))) {
    if (res.writableEnded) return;
    await sleep(config.delayMs);
    writeEvent(envelope({
      index: 0,
      delta: { content: chunk, role: 'assistant' },
      finish_reason: null,
      native_finish_reason: null,
    }));
  }

  const finish = {
    index: 0,
    delta: { content: '', role: 'assistant' },
    finish_reason: 'stop',
    native_finish_reason: 'end_turn',
  };
  writeEvent(envelope(finish));
  writeEvent(envelope(finish, {
    service_tier: 'default',
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  }));
  writeEvent('[DONE]');
  res.end();
}

// ---------------------------------------------------------------------------
// Embeddings
// ---------------------------------------------------------------------------

/**
 * A deterministic unit-length vector for a text.
 *
 * NOT an approximation of a real embedding, and not meant to be: it is a hash
 * spread over the dimensions. What it guarantees is what a test needs — the
 * same text always gives the same vector, and different texts give different
 * ones — so a retrieval assertion is reproducible. Whether two texts that MEAN
 * the same thing land near each other is a question only the real model can
 * answer.
 */
export function deterministicEmbedding(text: string, dimensions: number): number[] {
  const vector = new Array<number>(dimensions).fill(0);
  const terms = text.toLowerCase().split(/[^a-z0-9£%]+/).filter(Boolean);

  for (const term of terms) {
    // FNV-1a, so a term always lands on the same dimensions.
    let hash = 0x811c9dc5;
    for (let i = 0; i < term.length; i += 1) {
      hash ^= term.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    const primary = hash % dimensions;
    const secondary = (hash >>> 8) % dimensions;
    vector[primary] = (vector[primary] ?? 0) + 1;
    vector[secondary] = (vector[secondary] ?? 0) + 0.5;
  }

  const magnitude = Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0));
  if (magnitude === 0) {
    // An empty or symbol-only text. Return a fixed unit vector rather than
    // zeros: a zero vector scores 0 against everything, which reads as "no
    // match" when the truth is "nothing to match on".
    vector[0] = 1;
    return vector;
  }
  return vector.map((value) => value / magnitude);
}

// ---------------------------------------------------------------------------
// Simulator app
// ---------------------------------------------------------------------------

export interface OpenRouterSimulatorOptions {
  /** What GET /api/v1/models returns. Default: two free placeholder models. */
  readonly models?: readonly Record<string, unknown>[];
}

const DEFAULT_MODELS: readonly Record<string, unknown>[] = [
  { id: 'openai/gpt-4o-mini', name: 'GPT-4o mini (sim)', context_length: 128000, pricing: { prompt: '0', completion: '0' } },
  { id: 'anthropic/claude-3.5-sonnet', name: 'Claude 3.5 Sonnet (sim)', context_length: 200000, pricing: { prompt: '0', completion: '0' } },
];

export function createOpenRouterSimulator(options: OpenRouterSimulatorOptions = {}): OpenRouterSimulator {
  const capturedRequests: CapturedAiRequest[] = [];
  const scriptedResponses: string[] = [];
  let streamConfig: StreamConfig = { ...DEFAULT_STREAM_CONFIG };

  const getStreamConfig = (): StreamConfig => ({ ...streamConfig });
  const setStreamConfig = (next: Partial<StreamConfig>): void => {
    streamConfig = { ...streamConfig, ...next };
  };
  const reset = (): void => {
    capturedRequests.length = 0;
    scriptedResponses.length = 0;
    streamConfig = { ...DEFAULT_STREAM_CONFIG };
  };

  const app = express();
  app.use(express.json({ limit: '5mb' }));

  app.post('/api/v1/chat/completions', (req, res) => {
    const body = req.body as Partial<OpenRouterSimulatorRequest> | undefined;
    // The real API refuses a request with no model or no messages. Answering
    // it would let a client that builds a broken body pass locally.
    if (!body || typeof body.model !== 'string' || !Array.isArray(body.messages)) {
      res.status(400).json({ error: { code: 400, message: 'model (string) and messages (array) are required' } });
      return;
    }
    const request = body as OpenRouterSimulatorRequest;
    capturedRequests.push({ capturedAt: new Date().toISOString(), request });

    const content = scriptedResponses.shift() ?? buildDefaultContent(request);

    if (request.stream === true) {
      void writeStreamedCompletion(res, request, content, getStreamConfig());
      return;
    }

    res.status(200).json({
      id: `or-sim-${Date.now()}`,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: request.model,
      choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content } }],
      usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
    });
  });

  app.post('/api/v1/embeddings', (req, res) => {
    const body = (req.body ?? {}) as { model?: string; input?: unknown; dimensions?: number };
    const inputs = Array.isArray(body.input)
      ? (body.input as unknown[]).map((value) => String(value))
      : typeof body.input === 'string'
        ? [body.input]
        : null;

    if (!inputs || inputs.length === 0) {
      res.status(400).json({ error: { message: 'input (string or string[]) required' } });
      return;
    }

    const dimensions = Number(body.dimensions ?? 256);
    res.status(200).json({
      object: 'list',
      model: body.model ?? 'openai/text-embedding-3-small',
      data: inputs.map((text, index) => ({
        object: 'embedding',
        index,
        embedding: deterministicEmbedding(text, dimensions),
      })),
      usage: { prompt_tokens: 0, total_tokens: 0 },
    });
  });

  app.get('/api/v1/models', (_req, res) => {
    res.status(200).json({ data: options.models ?? DEFAULT_MODELS });
  });

  // Test-only hooks, on the same port as /api/v1/* so a single server
  // answers both the production-shaped requests and the test control plane.
  app.post('/__local/openrouter/script', (req, res) => {
    const body = req.body as { content?: unknown } | undefined;
    if (typeof body?.content !== 'string') {
      res.status(400).json({ error: { message: 'content (string) required' } });
      return;
    }
    scriptedResponses.push(body.content);
    res.status(204).end();
  });

  app.get('/__local/openrouter/captured', (_req, res) => {
    res.status(200).json({ requests: capturedRequests });
  });

  app.post('/__local/openrouter/stream-config', (req, res) => {
    const body = (req.body ?? {}) as Partial<StreamConfig>;
    const next: Partial<StreamConfig> = {};
    if (typeof body.chunkChars === 'number' && body.chunkChars > 0) next.chunkChars = body.chunkChars;
    if (typeof body.delayMs === 'number' && body.delayMs >= 0) next.delayMs = body.delayMs;
    if (typeof body.leadingKeepAlives === 'number' && body.leadingKeepAlives >= 0) {
      next.leadingKeepAlives = body.leadingKeepAlives;
    }
    setStreamConfig(next);
    res.status(200).json(getStreamConfig());
  });

  const resetRoute: express.RequestHandler = (_req, res) => {
    reset();
    res.status(204).end();
  };
  app.post('/__local/openrouter/clear', resetRoute);
  app.post('/__local/reset', resetRoute);

  app.use((req, res) => {
    console.warn(`[openrouter-simulator] 404 ${req.method} ${req.path}`);
    res.status(404).json({ error: { message: 'Not found' } });
  });

  return {
    app,
    queueScriptedResponse: (content) => {
      scriptedResponses.push(content);
    },
    getCapturedRequests: () => capturedRequests.slice(),
    getStreamConfig,
    setStreamConfig,
    reset,
  };
}

export interface StartOpenRouterSimulatorOptions extends OpenRouterSimulatorOptions {
  /** Default `OPENROUTER_SIMULATOR_PORT` env var, else 38307. Pass 0 for a free port. */
  readonly port?: number;
  readonly host?: string;
}

export async function startOpenRouterSimulator(
  options: StartOpenRouterSimulatorOptions = {},
): Promise<RunningSimulator & { readonly simulator: OpenRouterSimulator; readonly baseUrl: string }> {
  const port = options.port ?? Number(process.env.OPENROUTER_SIMULATOR_PORT ?? OPENROUTER_SIMULATOR_DEFAULT_PORT);
  const simulator = createOpenRouterSimulator(options);
  const running = await listen(simulator.app, port, options.host);
  console.log(`OpenRouter simulator listening on ${running.url}/api/v1`);
  return { ...running, simulator, baseUrl: `${running.url}/api/v1` };
}
