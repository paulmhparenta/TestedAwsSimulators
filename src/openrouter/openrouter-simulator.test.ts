import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  chunkText,
  defaultJsonForSchema,
  deterministicEmbedding,
  startOpenRouterSimulator,
  DEFAULT_STREAM_CONFIG,
  type CapturedAiRequest,
  type OpenRouterSimulator,
} from './openrouter-simulator';
import type { RunningSimulator } from '../shared/server';

let running: RunningSimulator & { simulator: OpenRouterSimulator; baseUrl: string };

beforeAll(async () => {
  running = await startOpenRouterSimulator({ port: 0 });
});

afterAll(async () => {
  await running.close();
});

beforeEach(() => {
  running.simulator.reset();
});

interface Completion {
  model: string;
  choices: Array<{ finish_reason: string; message: { role: string; content: string } }>;
}

async function complete(body: Record<string, unknown>): Promise<Response> {
  return fetch(`${running.baseUrl}/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer test-key' },
    body: JSON.stringify(body),
  });
}

async function completeContent(body: Record<string, unknown>): Promise<string> {
  const res = await complete({ model: 'openai/gpt-4o-mini', ...body });
  expect(res.status).toBe(200);
  return ((await res.json()) as Completion).choices[0]!.message.content;
}

/** Reads an SSE body into its events: comments and `data:` payloads, in order. */
function parseSse(text: string): Array<{ comment?: string; data?: string }> {
  return text
    .split('\n\n')
    .filter((block) => block.length > 0)
    .map((block) => (block.startsWith(':') ? { comment: block.slice(1).trim() } : { data: block.replace(/^data: /, '') }));
}

describe('OpenRouter simulator: chat completions', () => {
  it('echoes the last user message by default, in the OpenAI response shape', async () => {
    const res = await complete({
      model: 'openai/gpt-4o-mini',
      messages: [
        { role: 'system', content: 'be brief' },
        { role: 'user', content: 'first question' },
        { role: 'assistant', content: 'an answer' },
        { role: 'user', content: 'How do I reset my password?' },
      ],
    });
    const body = (await res.json()) as Completion;

    expect(res.status).toBe(200);
    expect(body.model).toBe('openai/gpt-4o-mini');
    expect(body.choices[0]).toMatchObject({ finish_reason: 'stop', message: { role: 'assistant', content: 'Echo: How do I reset my password?' } });
  });

  it('answers a json_schema request with the schema\'s required keys', async () => {
    const content = await completeContent({
      messages: [{ role: 'user', content: 'summarise' }],
      response_format: {
        type: 'json_schema',
        json_schema: {
          name: 'summary',
          schema: {
            type: 'object',
            required: ['title', 'tags', 'score', 'nested'],
            properties: {
              title: { type: 'string' },
              tags: { type: 'array', items: { type: 'string' } },
              score: { type: 'number' },
              nested: { type: 'object', properties: { flag: { type: 'boolean' } } },
              optional: { type: 'string' },
            },
          },
        },
      },
    });

    expect(JSON.parse(content)).toEqual({ title: '', tags: [], score: 0, nested: { flag: false } });
  });

  it('answers a json_object request with valid JSON', async () => {
    const content = await completeContent({ messages: [{ role: 'user', content: 'anything' }], response_format: { type: 'json_object' } });

    expect(JSON.parse(content)).toEqual({ echo: 'anything' });
  });

  it('uses scripted responses in order, then falls back to the echo', async () => {
    running.simulator.queueScriptedResponse('first scripted');
    const scriptRes = await fetch(`${running.url}/__local/openrouter/script`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: 'second scripted' }),
    });
    expect(scriptRes.status).toBe(204);

    const messages = [{ role: 'user', content: 'hi' }];
    expect(await completeContent({ messages })).toBe('first scripted');
    expect(await completeContent({ messages })).toBe('second scripted');
    expect(await completeContent({ messages })).toBe('Echo: hi');
  });

  it('refuses to script a non-string response', async () => {
    const res = await fetch(`${running.url}/__local/openrouter/script`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: 42 }),
    });
    expect(res.status).toBe(400);
  });

  it('captures each request, in process and over HTTP', async () => {
    await completeContent({ messages: [{ role: 'user', content: 'capture me' }] });

    expect(running.simulator.getCapturedRequests()[0]?.request.messages[0]?.content).toBe('capture me');
    const overHttp = (await (await fetch(`${running.url}/__local/openrouter/captured`)).json()) as { requests: CapturedAiRequest[] };
    expect(overHttp.requests).toHaveLength(1);
  });

  it.each([
    ['no model', { messages: [] }],
    ['no messages', { model: 'm' }],
    ['a non-JSON-object body', null],
  ])('refuses a request with %s', async (_label, body) => {
    const res = await complete(body as Record<string, unknown>);
    expect(res.status).toBe(400);
    expect(running.simulator.getCapturedRequests()).toHaveLength(0);
  });

  it('clears scripts, captures and stream config on POST /__local/openrouter/clear', async () => {
    running.simulator.queueScriptedResponse('dropped');
    running.simulator.setStreamConfig({ chunkChars: 1 });
    await completeContent({ messages: [{ role: 'user', content: 'x' }] });
    running.simulator.queueScriptedResponse('also dropped');

    expect((await fetch(`${running.url}/__local/openrouter/clear`, { method: 'POST' })).status).toBe(204);
    expect(running.simulator.getCapturedRequests()).toHaveLength(0);
    expect(running.simulator.getStreamConfig()).toEqual(DEFAULT_STREAM_CONFIG);
    expect(await completeContent({ messages: [{ role: 'user', content: 'y' }] })).toBe('Echo: y');
  });
});

describe('OpenRouter simulator: streaming', () => {
  it('frames a stream the way OpenRouter does: keep-alive, content deltas, two stops, [DONE]', async () => {
    running.simulator.queueScriptedResponse('abcdefghij');
    running.simulator.setStreamConfig({ chunkChars: 4 });

    const res = await complete({ model: 'm', stream: true, messages: [{ role: 'user', content: 'x' }] });
    expect(res.headers.get('content-type')).toContain('text/event-stream');
    const events = parseSse(await res.text());

    expect(events[0]).toEqual({ comment: 'OPENROUTER PROCESSING' });
    const dataEvents = events.slice(1);
    expect(dataEvents.at(-1)).toEqual({ data: '[DONE]' });

    const chunks = dataEvents.slice(0, -1).map((e) => JSON.parse(e.data!) as {
      object: string;
      choices: Array<{ delta: { content: string; role: string }; finish_reason: string | null }>;
      usage?: unknown;
    });
    const contentChunks = chunks.filter((c) => c.choices[0]!.finish_reason === null);
    expect(contentChunks.map((c) => c.choices[0]!.delta.content)).toEqual(['abcd', 'efgh', 'ij']);
    expect(contentChunks.every((c) => c.choices[0]!.delta.role === 'assistant')).toBe(true);
    expect(chunks.every((c) => c.object === 'chat.completion.chunk')).toBe(true);

    const stops = chunks.filter((c) => c.choices[0]!.finish_reason === 'stop');
    expect(stops).toHaveLength(2);
    expect(stops[0]!.usage).toBeUndefined();
    expect(stops[1]!.usage).toBeDefined();
  });

  it('sends no keep-alive when configured with zero', async () => {
    const config = await fetch(`${running.url}/__local/openrouter/stream-config`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ leadingKeepAlives: 0, chunkChars: 100, delayMs: 0 }),
    });
    expect(await config.json()).toEqual({ leadingKeepAlives: 0, chunkChars: 100, delayMs: 0 });

    const res = await complete({ model: 'm', stream: true, messages: [{ role: 'user', content: 'x' }] });
    expect(parseSse(await res.text()).some((e) => e.comment)).toBe(false);
  });

  it('ignores invalid stream-config values', async () => {
    const res = await fetch(`${running.url}/__local/openrouter/stream-config`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chunkChars: 0, delayMs: -1, leadingKeepAlives: 'x' }),
    });
    expect(await res.json()).toEqual(DEFAULT_STREAM_CONFIG);
  });

  it('paces chunks by delayMs', async () => {
    running.simulator.queueScriptedResponse('abc');
    running.simulator.setStreamConfig({ chunkChars: 1, delayMs: 30 });

    const started = Date.now();
    await (await complete({ model: 'm', stream: true, messages: [{ role: 'user', content: 'x' }] })).text();
    expect(Date.now() - started).toBeGreaterThanOrEqual(80);
  });
});

describe('OpenRouter simulator: embeddings and models', () => {
  it('returns one deterministic vector per input', async () => {
    const embed = async (input: unknown) => (await (await fetch(`${running.baseUrl}/embeddings`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input, dimensions: 16 }),
    })).json()) as { data: Array<{ index: number; embedding: number[] }> };

    const first = await embed(['same text', 'other text']);
    const second = await embed('same text');

    expect(first.data.map((d) => d.index)).toEqual([0, 1]);
    expect(first.data[0]!.embedding).toHaveLength(16);
    expect(second.data[0]!.embedding).toEqual(first.data[0]!.embedding);
    expect(first.data[1]!.embedding).not.toEqual(first.data[0]!.embedding);
  });

  it('refuses an embeddings request with no input', async () => {
    const res = await fetch(`${running.baseUrl}/embeddings`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: [] }),
    });
    expect(res.status).toBe(400);
  });

  it('lists models', async () => {
    const body = (await (await fetch(`${running.baseUrl}/models`)).json()) as { data: Array<{ id: string }> };
    expect(body.data.map((m) => m.id)).toContain('openai/gpt-4o-mini');
  });

  it('lists the models passed in the options', async () => {
    const custom = await startOpenRouterSimulator({ port: 0, models: [{ id: 'custom/model' }] });
    try {
      const body = (await (await fetch(`${custom.baseUrl}/models`)).json()) as { data: Array<{ id: string }> };
      expect(body.data).toEqual([{ id: 'custom/model' }]);
    } finally {
      await custom.close();
    }
  });

  it('answers an unknown path with 404', async () => {
    expect((await fetch(`${running.baseUrl}/nope`)).status).toBe(404);
  });
});

describe('OpenRouter simulator helpers', () => {
  it('chunkText never splits a surrogate pair', () => {
    const text = 'ab😀cd😀';
    const chunks = chunkText(text, 3);

    expect(chunks.join('')).toBe(text);
    for (const chunk of chunks) {
      const last = chunk.charCodeAt(chunk.length - 1);
      expect(last >= 0xd800 && last <= 0xdbff).toBe(false);
    }
  });

  it('deterministicEmbedding is unit length, and fixed for an empty text', () => {
    const vector = deterministicEmbedding('some words here', 32);
    expect(Math.sqrt(vector.reduce((s, v) => s + v * v, 0))).toBeCloseTo(1, 10);

    const empty = deterministicEmbedding('!!!', 4);
    expect(empty).toEqual([1, 0, 0, 0]);
  });

  it('defaultJsonForSchema uses every property when required is absent, and null for unknown types', () => {
    expect(defaultJsonForSchema({ type: 'object', properties: { a: { type: 'integer' }, b: {} } })).toEqual({ a: 0, b: null });
  });
});
