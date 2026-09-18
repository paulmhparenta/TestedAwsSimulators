/**
 * A small MIME parser for the raw messages SES SendRawEmail receives.
 *
 * It reads what a test asserts on: the top-level headers, the text and HTML
 * bodies, an ICS calendar part and any inline or attached parts. It is not a
 * general-purpose MIME library.
 */

export interface CapturedEmailAttachment {
  /** Content-ID (without angle brackets), e.g. "abc123@domain" */
  readonly cid: string | null;
  /** Content-Type header value, e.g. "text/calendar; method=REQUEST" */
  readonly contentType: string;
  /** Disposition filename, e.g. "invite.ics" */
  readonly filename: string | null;
  /** Raw decoded bytes of the attachment */
  readonly data: Buffer;
}

/** The part of a captured email that comes from the MIME message itself. */
export interface ParsedEmail {
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
  /** All top-level MIME headers, keys lower-cased (e.g. 'reply-to', 'x-custom-header'). */
  readonly headers: Readonly<Record<string, string>>;
}

interface MimeHeaders {
  [key: string]: string;
}

interface MimePart {
  headers: MimeHeaders;
  body: string;
}

/**
 * Unfold RFC 2822 header continuation lines and split into name/value pairs.
 * Header folding: a line that starts with whitespace continues the previous header.
 */
function parseHeaders(raw: string): MimeHeaders {
  // Unfold first: replace CRLF/LF followed by whitespace with a single space
  const unfolded = raw.replace(/\r?\n([ \t]+)/g, ' ');
  const headers: MimeHeaders = {};
  for (const line of unfolded.split(/\r?\n/)) {
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name) {
      headers[name] = value;
    }
  }
  return headers;
}

/**
 * Extract the primary address from a header value like:
 *   "Display Name <addr@example.com>"  or  "addr@example.com"
 */
export function extractAddress(value: string): string {
  const match = /<([^>]+)>/.exec(value);
  if (match?.[1]) return match[1].trim();
  return value.trim();
}

/**
 * Extract all addresses from a comma-separated list.
 */
function extractAddresses(value: string): string[] {
  return value
    .split(',')
    .map((v) => extractAddress(v.trim()))
    .filter(Boolean);
}

/**
 * Decode base64-encoded content, tolerating line breaks.
 */
function decodeBase64(encoded: string): Buffer {
  const stripped = encoded.replace(/\r?\n/g, '');
  return Buffer.from(stripped, 'base64');
}

/**
 * Split a multipart body into its constituent parts.
 * Returns raw part strings (headers + body separated by blank line).
 */
function splitMultipart(body: string, boundary: string): MimePart[] {
  const parts: MimePart[] = [];
  const delimiter = `--${boundary}`;
  const lines = body.split(/\r?\n/);

  let inPart = false;
  let currentLines: string[] = [];

  for (const line of lines) {
    if (line.startsWith(`${delimiter}--`)) {
      // Closing boundary — save current part if any
      if (inPart && currentLines.length > 0) {
        parts.push(parseMimePart(currentLines.join('\r\n')));
        currentLines = [];
        inPart = false;
      }
      break;
    }

    if (line.startsWith(delimiter)) {
      // Opening or intermediate boundary
      if (inPart && currentLines.length > 0) {
        parts.push(parseMimePart(currentLines.join('\r\n')));
        currentLines = [];
      }
      inPart = true;
      continue;
    }

    if (inPart) {
      currentLines.push(line);
    }
  }

  // Handle case where closing boundary was missing
  if (inPart && currentLines.length > 0) {
    parts.push(parseMimePart(currentLines.join('\r\n')));
  }

  return parts;
}

/**
 * Parse a single MIME part (raw text with headers + blank line + body).
 */
function parseMimePart(raw: string): MimePart {
  // Find the blank line separating headers from body
  const blankLine = raw.search(/\r?\n\r?\n/);
  if (blankLine < 0) {
    return { headers: parseHeaders(raw), body: '' };
  }
  const headerSection = raw.slice(0, blankLine);
  const bodySection = raw.slice(blankLine).replace(/^\r?\n\r?\n?/, '');
  return {
    headers: parseHeaders(headerSection),
    body: bodySection,
  };
}

/**
 * Extract the boundary value from a Content-Type header.
 * e.g.  'multipart/mixed; boundary="abc123"'  →  'abc123'
 */
function extractBoundary(contentType: string): string | null {
  const match = /boundary="?([^";]+)"?/i.exec(contentType);
  return match?.[1]?.trim() ?? null;
}

/**
 * Extract a parameter value from a Content-Type or Content-Disposition header.
 * e.g. extractParam('text/plain; charset=UTF-8', 'charset') → 'UTF-8'
 */
function extractParam(header: string, param: string): string | null {
  const re = new RegExp(`${param}="?([^";]+)"?`, 'i');
  const match = re.exec(header);
  return match?.[1]?.trim() ?? null;
}

/**
 * Parse a raw MIME part's body, returning decoded text or binary.
 */
function decodePartBody(part: MimePart): Buffer {
  const encoding = (part.headers['content-transfer-encoding'] ?? '').toLowerCase().trim();
  if (encoding === 'base64') {
    return decodeBase64(part.body);
  }
  if (encoding === 'quoted-printable') {
    // Minimal QP decode: strip soft line breaks, decode =XX sequences
    const decoded = part.body
      .replace(/=\r?\n/g, '')
      .replace(/=([0-9A-Fa-f]{2})/g, (_m, hex: string) =>
        String.fromCharCode(parseInt(hex, 16)),
      );
    return Buffer.from(decoded, 'latin1');
  }
  // 7bit / 8bit / binary — return as-is
  return Buffer.from(part.body, 'utf-8');
}

/**
 * Parse a raw MIME email string into its addresses, bodies, parts and headers.
 */
export function parseMimeEmail(rawMime: string): ParsedEmail {
  // Split message into headers and body at first blank line
  const blankLine = rawMime.search(/\r?\n\r?\n/);
  const headerSection = blankLine >= 0 ? rawMime.slice(0, blankLine) : rawMime;
  const bodySection = blankLine >= 0 ? rawMime.slice(blankLine).replace(/^\r?\n\r?\n?/, '') : '';

  const topHeaders = parseHeaders(headerSection);

  const fromRaw = topHeaders['from'] ?? '';
  const toRaw = topHeaders['to'] ?? '';
  const subject = decodeRfc2047(topHeaders['subject'] ?? '');
  const from = extractAddress(fromRaw);
  const to = extractAddresses(toRaw);

  const contentType = topHeaders['content-type'] ?? '';

  let textBody: string | null = null;
  let htmlBody: string | null = null;
  let calendarAttachment: CapturedEmailAttachment | null = null;
  const inlineAttachments: CapturedEmailAttachment[] = [];

  if (contentType.toLowerCase().startsWith('multipart/')) {
    const boundary = extractBoundary(contentType);
    if (boundary) {
      const parts = splitMultipart(bodySection, boundary);
      processMultipartParts(parts, contentType, {
        onText: (t) => { textBody = t; },
        onHtml: (h) => { htmlBody = h; },
        onCalendar: (a) => { calendarAttachment = a; },
        onInline: (a) => { inlineAttachments.push(a); },
      });
    }
  } else if (contentType.toLowerCase().startsWith('text/html')) {
    const part: MimePart = { headers: topHeaders, body: bodySection };
    htmlBody = decodePartBody(part).toString('utf-8');
  } else {
    // text/plain or unknown — treat as plain text
    const part: MimePart = { headers: topHeaders, body: bodySection };
    textBody = decodePartBody(part).toString('utf-8');
  }

  return { from, to, subject, textBody, htmlBody, calendarAttachment, inlineAttachments, headers: topHeaders };
}

interface MultipartCallbacks {
  onText: (text: string) => void;
  onHtml: (html: string) => void;
  onCalendar: (attachment: CapturedEmailAttachment) => void;
  onInline: (attachment: CapturedEmailAttachment) => void;
}

/**
 * Recursively process MIME parts, dispatching to the appropriate callback.
 */
function processMultipartParts(
  parts: MimePart[],
  parentContentType: string,
  callbacks: MultipartCallbacks,
): void {
  for (const part of parts) {
    const ct = (part.headers['content-type'] ?? '').toLowerCase();

    if (ct.startsWith('multipart/')) {
      // Recursively handle nested multipart (e.g. multipart/mixed containing multipart/alternative)
      const innerBoundary = extractBoundary(part.headers['content-type'] ?? '');
      if (innerBoundary) {
        const innerParts = splitMultipart(part.body, innerBoundary);
        processMultipartParts(innerParts, ct, callbacks);
      }
    } else if (ct.startsWith('text/plain')) {
      callbacks.onText(decodePartBody(part).toString('utf-8'));
    } else if (ct.startsWith('text/html')) {
      callbacks.onHtml(decodePartBody(part).toString('utf-8'));
    } else if (ct.startsWith('text/calendar')) {
      const filename = extractParam(part.headers['content-disposition'] ?? '', 'filename')
        ?? extractParam(part.headers['content-type'] ?? '', 'name')
        ?? 'invite.ics';
      const cidRaw = part.headers['content-id'] ?? null;
      const cid = cidRaw ? cidRaw.replace(/^<|>$/g, '') : null;
      callbacks.onCalendar({
        cid,
        contentType: part.headers['content-type'] ?? 'text/calendar',
        filename,
        data: decodePartBody(part),
      });
    } else if (ct.length > 0) {
      // Treat everything else with a Content-ID or inline disposition as an inline attachment
      const disposition = (part.headers['content-disposition'] ?? '').toLowerCase();
      const cidRaw = part.headers['content-id'] ?? null;
      const cid = cidRaw ? cidRaw.replace(/^<|>$/g, '') : null;
      const filename = extractParam(part.headers['content-disposition'] ?? '', 'filename')
        ?? extractParam(part.headers['content-type'] ?? '', 'name')
        ?? null;
      if (cid || disposition.startsWith('inline') || disposition.startsWith('attachment')) {
        callbacks.onInline({
          cid,
          contentType: part.headers['content-type'] ?? ct,
          filename,
          data: decodePartBody(part),
        });
      }
    }
  }
}

/**
 * Decode an RFC 2047 encoded-word token like =?UTF-8?B?...?=
 * Only base64 (B) encoding is handled — Q encoding is uncommon in practice here.
 */
function decodeRfc2047(value: string): string {
  return value.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_m, charset: string, encoding: string, encoded: string) => {
    try {
      if (encoding.toUpperCase() === 'B') {
        return Buffer.from(encoded, 'base64').toString('utf-8');
      }
      // Q encoding: underscores are spaces, =XX are hex bytes
      const qDecoded = encoded
        .replace(/_/g, ' ')
        .replace(/=([0-9A-Fa-f]{2})/g, (_h, hex: string) =>
          String.fromCharCode(parseInt(hex, 16)),
        );
      return Buffer.from(qDecoded, 'latin1').toString('utf-8');
    } catch {
      return encoded;
    }
  });
}
