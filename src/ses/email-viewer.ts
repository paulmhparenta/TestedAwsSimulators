/**
 * Inbox viewer for the emails the SES simulator captured.
 *
 * The SES simulator mounts this router at /emails.
 * Provides:
 *   GET  /                  — inline HTML single-page inbox UI
 *   GET  /api/list          — JSON array of email summaries (newest-first)
 *   GET  /api/:id           — full email detail JSON
 *   GET  /api/:id/html      — raw HTML body for iframe rendering
 *   DELETE /api/all         — clears all captured emails
 */

import { Router } from 'express';
import type { CapturedEmail, CapturedEmailSummary } from './ses-simulator';

/** The part of the SES simulator the viewer reads. */
export interface EmailViewerStore {
  listEmails(): readonly CapturedEmailSummary[];
  getEmail(id: string): CapturedEmail | null;
  clear(): void;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface EmailListItem {
  readonly id: string;
  readonly from: string;
  readonly to: readonly string[];
  readonly subject: string;
  /** ISO 8601 timestamp (alias for capturedAt, named per API spec) */
  readonly timestamp: string;
  readonly hasAttachments: boolean;
}

// ---------------------------------------------------------------------------
// HTML inbox UI
// ---------------------------------------------------------------------------

function renderInboxPage(basePath: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Local Email Inbox</title>
    <style>
      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
      :root {
        --bg: #f1f5f9;
        --surface: #ffffff;
        --border: #e2e8f0;
        --header-bg: #1e293b;
        --header-fg: #f8fafc;
        --accent: #3b82f6;
        --accent-hover: #2563eb;
        --muted: #64748b;
        --text: #0f172a;
        --selected-bg: #eff6ff;
        --selected-border: #3b82f6;
        --tag-bg: #dbeafe;
        --tag-fg: #1d4ed8;
        --danger: #ef4444;
        --danger-hover: #dc2626;
      }
      body {
        font-family: system-ui, -apple-system, sans-serif;
        font-size: 14px;
        color: var(--text);
        background: var(--bg);
        height: 100vh;
        display: flex;
        flex-direction: column;
        overflow: hidden;
      }

      /* ── Top bar ── */
      header {
        background: var(--header-bg);
        color: var(--header-fg);
        padding: 0 1rem;
        height: 48px;
        display: flex;
        align-items: center;
        gap: 1rem;
        flex-shrink: 0;
        z-index: 10;
      }
      header h1 {
        font-size: 1rem;
        font-weight: 600;
        letter-spacing: 0.01em;
      }
      #inbox-count {
        background: var(--accent);
        color: #fff;
        font-size: 0.75rem;
        font-weight: 700;
        padding: 1px 7px;
        border-radius: 999px;
        min-width: 20px;
        text-align: center;
      }
      header .spacer { flex: 1; }
      .header-btn {
        appearance: none;
        border: 1px solid rgba(255,255,255,0.2);
        border-radius: 6px;
        padding: 5px 12px;
        background: rgba(255,255,255,0.08);
        color: var(--header-fg);
        font-size: 0.82rem;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 6px;
        transition: background 0.15s;
      }
      .header-btn:hover { background: rgba(255,255,255,0.15); }
      .header-btn.danger { border-color: rgba(239,68,68,0.5); color: #fca5a5; }
      .header-btn.danger:hover { background: rgba(239,68,68,0.15); }
      #auto-refresh-btn.active { border-color: #34d399; color: #6ee7b7; }
      label[for="auto-refresh-toggle"] { display: none; }

      /* ── Filter bar ── */
      .filter-bar {
        background: var(--surface);
        border-bottom: 1px solid var(--border);
        padding: 8px 12px;
        flex-shrink: 0;
      }
      #filter-input {
        width: 100%;
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 6px 10px;
        font-size: 0.87rem;
        color: var(--text);
        outline: none;
        transition: border-color 0.15s;
      }
      #filter-input:focus { border-color: var(--accent); }

      /* ── Main layout ── */
      .main {
        display: flex;
        flex: 1;
        overflow: hidden;
      }

      /* ── Email list panel ── */
      .email-list-panel {
        width: 340px;
        min-width: 220px;
        flex-shrink: 0;
        background: var(--surface);
        border-right: 1px solid var(--border);
        display: flex;
        flex-direction: column;
        overflow: hidden;
      }
      #email-list {
        flex: 1;
        overflow-y: auto;
        list-style: none;
      }
      .email-item {
        padding: 12px 14px;
        border-bottom: 1px solid var(--border);
        cursor: pointer;
        transition: background 0.1s;
        position: relative;
      }
      .email-item:hover { background: var(--bg); }
      .email-item.selected {
        background: var(--selected-bg);
        border-left: 3px solid var(--selected-border);
        padding-left: 11px;
      }
      .email-item-header {
        display: flex;
        align-items: center;
        gap: 6px;
        margin-bottom: 3px;
      }
      .email-from {
        font-weight: 600;
        font-size: 0.85rem;
        flex: 1;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .email-time {
        font-size: 0.75rem;
        color: var(--muted);
        white-space: nowrap;
        flex-shrink: 0;
      }
      .email-subject {
        font-size: 0.83rem;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        margin-bottom: 2px;
      }
      .email-to {
        font-size: 0.75rem;
        color: var(--muted);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .attachment-badge {
        font-size: 0.7rem;
        background: var(--tag-bg);
        color: var(--tag-fg);
        padding: 1px 5px;
        border-radius: 4px;
        flex-shrink: 0;
      }
      .empty-state {
        padding: 2rem 1rem;
        text-align: center;
        color: var(--muted);
        font-size: 0.9rem;
        line-height: 1.5;
      }

      /* ── Email detail panel ── */
      .email-detail-panel {
        flex: 1;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        background: var(--bg);
      }
      .detail-placeholder {
        flex: 1;
        display: flex;
        align-items: center;
        justify-content: center;
        color: var(--muted);
        font-size: 0.95rem;
      }
      .detail-content {
        flex: 1;
        display: flex;
        flex-direction: column;
        overflow: hidden;
      }
      .detail-header {
        background: var(--surface);
        border-bottom: 1px solid var(--border);
        padding: 14px 16px 12px;
        flex-shrink: 0;
      }
      .detail-subject {
        font-size: 1rem;
        font-weight: 600;
        margin-bottom: 8px;
      }
      .detail-meta {
        font-size: 0.82rem;
        color: var(--muted);
        display: flex;
        flex-direction: column;
        gap: 2px;
      }
      .detail-meta span strong { color: var(--text); }

      /* ── Tabs ── */
      .tabs {
        background: var(--surface);
        border-bottom: 1px solid var(--border);
        display: flex;
        flex-shrink: 0;
      }
      .tab-btn {
        appearance: none;
        border: none;
        border-bottom: 2px solid transparent;
        background: transparent;
        padding: 8px 16px;
        font-size: 0.83rem;
        font-weight: 500;
        color: var(--muted);
        cursor: pointer;
        transition: color 0.15s, border-color 0.15s;
        margin-bottom: -1px;
      }
      .tab-btn:hover { color: var(--text); }
      .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

      /* ── Tab panels ── */
      .tab-panels { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
      .tab-panel { display: none; flex: 1; overflow: hidden; flex-direction: column; }
      .tab-panel.active { display: flex; }

      #tab-html iframe {
        flex: 1;
        border: none;
        background: #fff;
      }
      #tab-text pre,
      #tab-headers pre,
      #tab-raw pre {
        flex: 1;
        overflow: auto;
        padding: 16px;
        font-size: 0.8rem;
        font-family: 'SF Mono', 'Cascadia Code', Consolas, monospace;
        line-height: 1.55;
        white-space: pre-wrap;
        word-break: break-word;
        background: var(--surface);
        margin: 0;
        color: var(--text);
      }
    </style>
  </head>
  <body>
    <header>
      <h1>Local Email Inbox</h1>
      <span id="inbox-count">0</span>
      <span class="spacer"></span>
      <button id="auto-refresh-btn" class="header-btn" title="Toggle auto-refresh every 2s">
        Auto-refresh
      </button>
      <button id="clear-btn" class="header-btn danger">Clear All</button>
    </header>

    <div class="filter-bar">
      <input id="filter-input" type="search" placeholder="Filter by from, to, or subject…" autocomplete="off" />
    </div>

    <div class="main">
      <aside class="email-list-panel">
        <ul id="email-list"></ul>
      </aside>

      <section class="email-detail-panel" id="detail-panel">
        <div class="detail-placeholder" id="detail-placeholder">Select an email to preview</div>
        <div class="detail-content" id="detail-content" style="display:none">
          <div class="detail-header">
            <div class="detail-subject" id="detail-subject"></div>
            <div class="detail-meta">
              <span><strong>From:</strong> <span id="detail-from"></span></span>
              <span><strong>To:</strong> <span id="detail-to"></span></span>
              <span><strong>Time:</strong> <span id="detail-time"></span></span>
            </div>
          </div>
          <nav class="tabs">
            <button class="tab-btn active" data-tab="html">HTML Preview</button>
            <button class="tab-btn" data-tab="text">Plain Text</button>
            <button class="tab-btn" data-tab="headers">Headers</button>
            <button class="tab-btn" data-tab="raw">Raw MIME</button>
          </nav>
          <div class="tab-panels">
            <div class="tab-panel active" id="tab-html">
              <iframe id="html-iframe" title="Email HTML preview" sandbox="allow-same-origin"></iframe>
            </div>
            <div class="tab-panel" id="tab-text">
              <pre id="text-body"></pre>
            </div>
            <div class="tab-panel" id="tab-headers">
              <pre id="headers-body"></pre>
            </div>
            <div class="tab-panel" id="tab-raw">
              <pre id="raw-body"></pre>
            </div>
          </div>
        </div>
      </section>
    </div>

    <script>
      (() => {
        const BASE = ${JSON.stringify(basePath)};
        let emails = [];
        let selectedId = null;
        let autoRefresh = false;
        let refreshTimer = null;
        let filterText = '';

        // ── DOM refs ──
        const listEl = document.getElementById('email-list');
        const countBadge = document.getElementById('inbox-count');
        const placeholder = document.getElementById('detail-placeholder');
        const detailContent = document.getElementById('detail-content');
        const detailSubject = document.getElementById('detail-subject');
        const detailFrom = document.getElementById('detail-from');
        const detailTo = document.getElementById('detail-to');
        const detailTime = document.getElementById('detail-time');
        const htmlIframe = document.getElementById('html-iframe');
        const textBody = document.getElementById('text-body');
        const headersBody = document.getElementById('headers-body');
        const rawBody = document.getElementById('raw-body');
        const filterInput = document.getElementById('filter-input');
        const clearBtn = document.getElementById('clear-btn');
        const autoRefreshBtn = document.getElementById('auto-refresh-btn');

        // ── Utilities ──
        function esc(s) {
          return String(s ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
        }

        function formatTime(iso) {
          if (!iso) return '';
          try {
            const d = new Date(iso);
            const now = new Date();
            const sameDay = d.toDateString() === now.toDateString();
            if (sameDay) {
              return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            }
            return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
              d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
          } catch {
            return iso;
          }
        }

        function formatFullTime(iso) {
          if (!iso) return '';
          try {
            return new Date(iso).toLocaleString();
          } catch {
            return iso;
          }
        }

        function matchesFilter(email, filter) {
          if (!filter) return true;
          const q = filter.toLowerCase();
          return (
            (email.from || '').toLowerCase().includes(q) ||
            (email.subject || '').toLowerCase().includes(q) ||
            (email.to || []).some(t => t.toLowerCase().includes(q))
          );
        }

        // ── Fetch & render list ──
        async function loadList() {
          try {
            const res = await fetch(BASE + '/api/list');
            if (!res.ok) return;
            emails = await res.json();
            renderList();
          } catch {
            // ignore fetch errors during dev
          }
        }

        function renderList() {
          const filtered = emails.filter(e => matchesFilter(e, filterText));
          countBadge.textContent = emails.length;

          if (filtered.length === 0) {
            listEl.innerHTML = '<li class="empty-state">' +
              (emails.length === 0
                ? 'No emails yet.<br>Emails captured by the SES simulator will appear here.'
                : 'No emails match your filter.') +
              '</li>';
            return;
          }

          listEl.innerHTML = filtered.map(email => {
            const isSelected = email.id === selectedId;
            const toStr = (email.to || []).join(', ');
            return \`<li class="email-item\${isSelected ? ' selected' : ''}" data-id="\${esc(email.id)}" role="button" tabindex="0">
              <div class="email-item-header">
                <span class="email-from">\${esc(email.from)}</span>
                \${email.hasAttachments ? '<span class="attachment-badge">attach</span>' : ''}
                <span class="email-time">\${esc(formatTime(email.timestamp))}</span>
              </div>
              <div class="email-subject">\${esc(email.subject)}</div>
              <div class="email-to">To: \${esc(toStr)}</div>
            </li>\`;
          }).join('');

          // Rebind click handlers
          listEl.querySelectorAll('.email-item').forEach(item => {
            item.addEventListener('click', () => selectEmail(item.dataset.id));
            item.addEventListener('keydown', (e) => {
              if (e.key === 'Enter' || e.key === ' ') selectEmail(item.dataset.id);
            });
          });
        }

        // ── Select and load email detail ──
        async function selectEmail(id) {
          if (selectedId === id) return;
          selectedId = id;
          renderList(); // update selected highlight

          try {
            const res = await fetch(BASE + '/api/' + encodeURIComponent(id));
            if (!res.ok) {
              showDetail(null);
              return;
            }
            const email = await res.json();
            showDetail(email);
          } catch {
            showDetail(null);
          }
        }

        function showDetail(email) {
          if (!email) {
            placeholder.style.display = '';
            detailContent.style.display = 'none';
            return;
          }

          placeholder.style.display = 'none';
          detailContent.style.display = '';

          detailSubject.textContent = email.subject ?? '(no subject)';
          detailFrom.textContent = email.from ?? '';
          detailTo.textContent = (email.to || []).join(', ');
          detailTime.textContent = formatFullTime(email.capturedAt);

          // HTML tab
          htmlIframe.src = BASE + '/api/' + encodeURIComponent(email.id) + '/html';

          // Plain text tab
          textBody.textContent = email.textBody ?? '(no plain text body)';

          // Headers tab
          const hdrs = email.headers ?? {};
          headersBody.textContent = Object.entries(hdrs)
            .map(([k, v]) => k + ': ' + v)
            .join('\\n') || '(no headers captured)';

          // Raw MIME tab
          rawBody.textContent = email.rawMime ?? '(no raw MIME — sent via SendEmail API)';
        }

        // ── Tab switching ──
        document.querySelectorAll('.tab-btn').forEach(btn => {
          btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('tab-' + tab).classList.add('active');
          });
        });

        // ── Clear all ──
        clearBtn.addEventListener('click', async () => {
          try {
            await fetch(BASE + '/api/all', { method: 'DELETE' });
            emails = [];
            selectedId = null;
            placeholder.style.display = '';
            detailContent.style.display = 'none';
            renderList();
          } catch {
            // ignore
          }
        });

        // ── Auto-refresh toggle ──
        autoRefreshBtn.addEventListener('click', () => {
          autoRefresh = !autoRefresh;
          autoRefreshBtn.classList.toggle('active', autoRefresh);
          autoRefreshBtn.textContent = autoRefresh ? 'Auto-refresh ON' : 'Auto-refresh';
          if (autoRefresh) {
            refreshTimer = setInterval(loadList, 2000);
          } else {
            clearInterval(refreshTimer);
          }
        });

        // ── Filter input ──
        filterInput.addEventListener('input', () => {
          filterText = filterInput.value;
          renderList();
        });

        // ── Initial load ──
        loadList();
      })();
    </script>
  </body>
</html>`;
}

// ---------------------------------------------------------------------------
// Router factory
// ---------------------------------------------------------------------------

export function createEmailViewerRouter(store: EmailViewerStore, basePath: string): Router {
  const router = Router();

  // GET / — serve the inbox HTML UI
  router.get('/', (_req, res) => {
    res.status(200).type('html').send(renderInboxPage(basePath));
  });

  // GET /api/list — email summaries, newest-first
  router.get('/api/list', (_req, res) => {
    const summaries = store.listEmails();
    const items: EmailListItem[] = [...summaries].reverse().map((summary) => {
      const full = store.getEmail(summary.id);
      const hasAttachments =
        full !== null &&
        (full.calendarAttachment !== null || full.inlineAttachments.length > 0);
      return {
        id: summary.id,
        from: summary.from,
        to: summary.to,
        subject: summary.subject,
        timestamp: summary.capturedAt,
        hasAttachments,
      };
    });
    res.json(items);
  });

  // GET /api/all — must come before /api/:id to avoid routing conflict
  // DELETE /api/all — clear all emails
  router.delete('/api/all', (_req, res) => {
    store.clear();
    res.json({ ok: true });
  });

  // GET /api/:id — full email detail
  router.get('/api/:id', (req, res) => {
    const email = store.getEmail(req.params.id);
    if (!email) {
      res.status(404).json({ error: 'Email not found' });
      return;
    }

    // Headers captured from the raw MIME by the SES simulator (keys lower-cased,
    // e.g. 'reply-to', 'list-unsubscribe'). Fall back to synthetic pseudo-headers
    // for legacy SendEmail paths that do not parse raw MIME.
    const headers: Record<string, string> = Object.keys(email.headers).length > 0
      ? { ...email.headers }
      : {
          from: email.from,
          to: email.to.join(', '),
          subject: email.subject,
          date: email.capturedAt,
        };

    res.json({
      id: email.id,
      capturedAt: email.capturedAt,
      from: email.from,
      to: email.to,
      subject: email.subject,
      textBody: email.textBody,
      htmlBody: email.htmlBody,
      rawMime: email.rawMime,
      headers,
      hasAttachments: email.calendarAttachment !== null || email.inlineAttachments.length > 0,
      attachments: {
        calendar: email.calendarAttachment
          ? {
              filename: email.calendarAttachment.filename,
              contentType: email.calendarAttachment.contentType,
              cid: email.calendarAttachment.cid,
            }
          : null,
        inline: email.inlineAttachments.map((a) => ({
          filename: a.filename,
          contentType: a.contentType,
          cid: a.cid,
        })),
      },
    });
  });

  // GET /api/:id/html — raw HTML body for iframe.
  // Rewrites `cid:xxx` image refs to a relative URL served by the inline
  // endpoint below so the iframe can actually render them (browsers don't
  // resolve `cid:` outside a full MIME email client).
  router.get('/api/:id/html', (req, res) => {
    const email = store.getEmail(req.params.id);
    if (!email) {
      res.status(404).type('html').send('<p>Email not found.</p>');
      return;
    }

    if (email.htmlBody) {
      const rewritten = rewriteCidRefsToInlineUrls(email.htmlBody);
      res.status(200).type('html').send(rewritten);
    } else {
      res.status(200).type('html').send(`<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>No HTML body</title>
  <style>body{font-family:system-ui,sans-serif;padding:2rem;color:#64748b;}</style>
  </head>
  <body><p>(This email has no HTML body.)</p></body>
</html>`);
    }
  });

  // GET /api/:id/inline/:cid — serve bytes for an inline attachment so the
  // iframe above can render `cid:` image refs after rewriting.
  router.get('/api/:id/inline/:cid', (req, res) => {
    const email = store.getEmail(req.params.id);
    if (!email) {
      res.status(404).type('text').send('Email not found');
      return;
    }
    const cid = decodeURIComponent(req.params.cid);
    const attachment = email.inlineAttachments.find((a) => a.cid === cid);
    if (!attachment) {
      res.status(404).type('text').send('Inline attachment not found');
      return;
    }
    // Strip any MIME parameters (e.g. "image/png; name=...") — Content-Type
    // header on a binary response only needs the media type.
    const contentType = attachment.contentType.split(';')[0]?.trim() || 'application/octet-stream';
    res.status(200).type(contentType).send(attachment.data);
  });

  return router;
}

/**
 * Replace `cid:<value>` references (typically in `<img src="cid:...">`) with a
 * relative URL that resolves to `/api/:id/inline/:cid` when the iframe is
 * loading the HTML. A sender that embeds images writes `cid:xxx` into the
 * outgoing MIME; this makes those refs loadable in the inbox preview.
 */
function rewriteCidRefsToInlineUrls(html: string): string {
  // cid values are bounded by quotes/whitespace/angle brackets in HTML attrs.
  return html.replace(/cid:([^"'\s>]+)/g, (_, cid: string) => `inline/${encodeURIComponent(cid)}`);
}
