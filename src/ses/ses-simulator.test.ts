import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { SESClient, SendEmailCommand, SendRawEmailCommand } from '@aws-sdk/client-ses';

import { startSesSimulator, type SesNotification, type SesSimulator } from './ses-simulator';
import type { RunningSimulator } from '../shared/server';

let running: RunningSimulator & { simulator: SesSimulator };
let ses: SESClient;
const notificationsSeen: SesNotification[] = [];
let failNextNotification = false;

beforeAll(async () => {
  running = await startSesSimulator({
    port: 0,
    onNotification: (notification) => {
      if (failNextNotification) {
        failNextNotification = false;
        throw new Error('handler refused');
      }
      notificationsSeen.push(notification);
    },
  });
  ses = new SESClient({
    endpoint: running.url,
    region: 'us-east-1',
    credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
  });
});

afterAll(async () => {
  ses.destroy();
  await running.close();
});

beforeEach(() => {
  running.simulator.reset();
  notificationsSeen.length = 0;
});

const PNG_1X1 = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
  'base64',
);

function rawMimeMessage(): string {
  return [
    'From: "Sender Name" <sender@example.com>',
    'To: first@example.com, "Second" <second@example.com>',
    'Subject: =?UTF-8?B?' + Buffer.from('Grüße from the test').toString('base64') + '?=',
    'Reply-To: replies@example.com',
    'X-Custom-Header: custom-value',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="outer"',
    '',
    '--outer',
    'Content-Type: multipart/alternative; boundary="inner"',
    '',
    '--inner',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'Plain body with =3D sign',
    '--inner',
    'Content-Type: text/html; charset=UTF-8',
    '',
    '<p>HTML body <img src="cid:logo@example"></p>',
    '--inner--',
    '--outer',
    'Content-Type: image/png; name="logo.png"',
    'Content-Transfer-Encoding: base64',
    'Content-ID: <logo@example>',
    'Content-Disposition: inline; filename="logo.png"',
    '',
    PNG_1X1.toString('base64'),
    '--outer',
    'Content-Type: text/calendar; method=REQUEST; name="invite.ics"',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from('BEGIN:VCALENDAR\r\nEND:VCALENDAR').toString('base64'),
    '--outer--',
    '',
  ].join('\r\n');
}

describe('SES simulator through the AWS SDK', () => {
  it('captures a SendEmail and returns the MessageId it stored', async () => {
    const result = await ses.send(new SendEmailCommand({
      Source: 'Sender <sender@example.com>',
      Destination: { ToAddresses: ['to@example.com', 'Other <other@example.com>'] },
      Message: {
        Subject: { Data: 'Hello' },
        Body: { Text: { Data: 'text body' }, Html: { Data: '<b>html body</b>' } },
      },
    }));

    const [summary] = running.simulator.listEmails();
    expect(summary).toMatchObject({
      from: 'sender@example.com',
      to: ['to@example.com', 'other@example.com'],
      subject: 'Hello',
      messageId: result.MessageId,
    });
    const email = running.simulator.getEmail(summary!.id)!;
    expect(email.textBody).toBe('text body');
    expect(email.htmlBody).toBe('<b>html body</b>');
    expect(running.simulator.getEmailByMessageId(result.MessageId!)?.id).toBe(summary!.id);
  });

  it('parses a SendRawEmail: addresses, encoded subject, both bodies, headers and parts', async () => {
    const result = await ses.send(new SendRawEmailCommand({ RawMessage: { Data: Buffer.from(rawMimeMessage()) } }));

    const email = running.simulator.getEmailByMessageId(result.MessageId!)!;
    expect(email.from).toBe('sender@example.com');
    expect(email.to).toEqual(['first@example.com', 'second@example.com']);
    expect(email.subject).toBe('Grüße from the test');
    expect(email.textBody).toBe('Plain body with = sign');
    expect(email.htmlBody).toContain('<p>HTML body');
    expect(email.headers['reply-to']).toBe('replies@example.com');
    expect(email.headers['x-custom-header']).toBe('custom-value');
    expect(email.inlineAttachments).toHaveLength(1);
    expect(email.inlineAttachments[0]).toMatchObject({ cid: 'logo@example', filename: 'logo.png' });
    expect(email.inlineAttachments[0]!.data).toEqual(PNG_1X1);
    expect(email.calendarAttachment?.filename).toBe('invite.ics');
    expect(email.calendarAttachment?.data.toString()).toContain('BEGIN:VCALENDAR');
    expect(email.rawMime).toContain('X-Custom-Header');
  });

  it('keeps emails in send order', async () => {
    for (const subject of ['one', 'two', 'three']) {
      await ses.send(new SendEmailCommand({
        Source: 'a@example.com',
        Destination: { ToAddresses: ['b@example.com'] },
        Message: { Subject: { Data: subject }, Body: { Text: { Data: subject } } },
      }));
    }

    expect(running.simulator.listEmails().map((e) => e.subject)).toEqual(['one', 'two', 'three']);
  });
});

describe('SES simulator protocol edges', () => {
  it('accepts the JSON protocol with an x-amz-target header', async () => {
    const res = await fetch(`${running.url}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-amz-json-1.0', 'x-amz-target': 'AmazonSimpleEmailService.SendEmail' },
      body: JSON.stringify({
        FromEmailAddress: 'json@example.com',
        Destination: { ToAddresses: ['to@example.com'] },
        Content: { Simple: { Subject: { Data: 'JSON' }, Body: { Text: { Data: 'json body' } } } },
      }),
    });

    expect(res.status).toBe(200);
    expect(await res.text()).toContain('<MessageId>');
    expect(running.simulator.listEmails()[0]).toMatchObject({ from: 'json@example.com', subject: 'JSON' });
  });

  it('accepts a JSON SendRawEmail', async () => {
    const res = await fetch(`${running.url}/`, {
      method: 'POST',
      headers: { 'x-amz-target': 'AmazonSimpleEmailService.SendRawEmail' },
      body: JSON.stringify({ Content: { Raw: { Data: Buffer.from(rawMimeMessage()).toString('base64') } } }),
    });

    expect(res.status).toBe(200);
    expect(running.simulator.listEmails()[0]?.subject).toBe('Grüße from the test');
  });

  it('refuses an unknown JSON target', async () => {
    const res = await fetch(`${running.url}/`, {
      method: 'POST',
      headers: { 'x-amz-target': 'AmazonSimpleEmailService.DeleteIdentity' },
      body: '{}',
    });

    expect(res.status).toBe(400);
    expect(await res.text()).toContain('InvalidAction');
  });

  it('refuses a JSON body that does not parse', async () => {
    const res = await fetch(`${running.url}/`, {
      method: 'POST',
      headers: { 'x-amz-target': 'AmazonSimpleEmailService.SendEmail' },
      body: '{not json',
    });

    expect(res.status).toBe(400);
    expect(await res.text()).toContain('InvalidRequest');
  });

  it('refuses an unknown query action', async () => {
    const res = await fetch(`${running.url}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'Action=VerifyEmailIdentity&EmailAddress=a%40example.com',
    });

    expect(res.status).toBe(400);
    expect(await res.text()).toContain('Unknown action: VerifyEmailIdentity');
  });

  it('refuses a body with no action', async () => {
    const res = await fetch(`${running.url}/`, { method: 'POST', body: 'nothing=here' });

    expect(res.status).toBe(400);
    expect(await res.text()).toContain('Cannot determine SES action');
  });

  it('answers an unknown path with 404', async () => {
    const res = await fetch(`${running.url}/v2/email/outbound-emails`, { method: 'POST', body: '{}' });
    expect(res.status).toBe(404);
  });

  it('clears the store on POST /__local/reset', async () => {
    await ses.send(new SendEmailCommand({
      Source: 'a@example.com',
      Destination: { ToAddresses: ['b@example.com'] },
      Message: { Subject: { Data: 's' }, Body: { Text: { Data: 't' } } },
    }));

    const res = await fetch(`${running.url}/__local/reset`, { method: 'POST' });
    expect(res.status).toBe(204);
    expect(running.simulator.listEmails()).toHaveLength(0);
  });
});

describe('SES simulator delivery events', () => {
  it.each(['Delivery', 'Bounce', 'Complaint'] as const)('builds a %s notification and hands it to onNotification', async (type) => {
    const res = await fetch(`${running.url}/__ses/trigger`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ messageId: 'msg-1', type }),
    });

    expect(res.status).toBe(200);
    expect(notificationsSeen).toHaveLength(1);
    expect(notificationsSeen[0]).toMatchObject({ notificationType: type, mail: { messageId: 'msg-1' } });
    const detailKey = type.toLowerCase() as 'delivery' | 'bounce' | 'complaint';
    expect(notificationsSeen[0]![detailKey]).toBeDefined();
    expect(running.simulator.listNotifications()).toHaveLength(1);
  });

  it('refuses an unsupported type', async () => {
    const res = await fetch(`${running.url}/__ses/trigger`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ messageId: 'msg-1', type: 'Open' }),
    });

    expect(res.status).toBe(400);
    expect(notificationsSeen).toHaveLength(0);
  });

  it('refuses a trigger with no messageId', async () => {
    const res = await fetch(`${running.url}/__ses/trigger`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'Bounce' }),
    });

    expect(res.status).toBe(400);
  });

  it('answers 500 when the handler throws', async () => {
    failNextNotification = true;
    const res = await fetch(`${running.url}/__ses/trigger`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ messageId: 'msg-1', type: 'Bounce' }),
    });

    expect(res.status).toBe(500);
    expect(((await res.json()) as { error: string }).error).toBe('handler refused');
  });

  it('lists the notifications over HTTP', async () => {
    await fetch(`${running.url}/__ses/trigger`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ messageId: 'msg-2', type: 'Delivery' }),
    });

    const res = await fetch(`${running.url}/__ses/notifications`);
    const body = (await res.json()) as { notifications: SesNotification[] };
    expect(body.notifications.map((n) => n.mail.messageId)).toEqual(['msg-2']);
  });
});

describe('SES simulator inbox viewer', () => {
  async function sendRaw(): Promise<string> {
    const result = await ses.send(new SendRawEmailCommand({ RawMessage: { Data: Buffer.from(rawMimeMessage()) } }));
    return running.simulator.getEmailByMessageId(result.MessageId!)!.id;
  }

  it('serves the inbox page, which calls its own API under /emails', async () => {
    const res = await fetch(`${running.url}/emails/`);
    const html = await res.text();

    expect(res.status).toBe(200);
    expect(html).toContain('const BASE = "/emails";');
  });

  it('lists emails newest first', async () => {
    await ses.send(new SendEmailCommand({
      Source: 'a@example.com',
      Destination: { ToAddresses: ['b@example.com'] },
      Message: { Subject: { Data: 'older' }, Body: { Text: { Data: 't' } } },
    }));
    await sendRaw();

    const list = (await (await fetch(`${running.url}/emails/api/list`)).json()) as Array<{ subject: string; hasAttachments: boolean }>;
    expect(list.map((e) => e.subject)).toEqual(['Grüße from the test', 'older']);
    expect(list.map((e) => e.hasAttachments)).toEqual([true, false]);
  });

  it('returns the detail of one email', async () => {
    const id = await sendRaw();

    const detail = (await (await fetch(`${running.url}/emails/api/${id}`)).json()) as {
      headers: Record<string, string>;
      attachments: { calendar: { filename: string } | null; inline: Array<{ cid: string }> };
    };
    expect(detail.headers['x-custom-header']).toBe('custom-value');
    expect(detail.attachments.calendar?.filename).toBe('invite.ics');
    expect(detail.attachments.inline[0]?.cid).toBe('logo@example');
  });

  it('rewrites cid: image references so the preview can load them', async () => {
    const id = await sendRaw();

    const html = await (await fetch(`${running.url}/emails/api/${id}/html`)).text();
    expect(html).toContain('src="inline/logo%40example"');

    const image = await fetch(`${running.url}/emails/api/${id}/inline/logo%40example`);
    expect(image.headers.get('content-type')).toBe('image/png');
    expect(Buffer.from(await image.arrayBuffer())).toEqual(PNG_1X1);
  });

  it('answers 404 for an unknown email', async () => {
    expect((await fetch(`${running.url}/emails/api/nope`)).status).toBe(404);
    expect((await fetch(`${running.url}/emails/api/nope/html`)).status).toBe(404);
    expect((await fetch(`${running.url}/emails/api/nope/inline/x`)).status).toBe(404);
  });

  it('clears the inbox with DELETE /emails/api/all', async () => {
    await sendRaw();

    const res = await fetch(`${running.url}/emails/api/all`, { method: 'DELETE' });
    expect(res.status).toBe(200);
    expect(running.simulator.listEmails()).toHaveLength(0);
  });
});
