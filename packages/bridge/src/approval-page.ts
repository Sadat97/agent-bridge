// Local approval page. Inline CSS and inline SVG only: no third-party assets,
// no scripts. Forms carry a CSRF token that must match the loopback cookie.

import type { ContactView } from './bridge.ts';
import { qrSvg } from './qr.ts';

export interface PageApproval {
  approval_id: string;
  kind: string;
  status: string;
  summary: string;
  requested_by: string;
  topic_id: string;
  topic_title?: string;
  created_at: string;
  hold: string | null;
  request?: unknown;
  sensitive_paths?: string[];
  contact?: ContactView;
}

const CSS = `
:root { color-scheme: light; }
body { font: 16px/1.45 system-ui, sans-serif; margin: 0 auto; max-width: 46rem; padding: 1.5rem; color: #1b1b1b; background: #f7f6f3; }
h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
h2 { font-size: 1.1rem; margin: 1.5rem 0 0.4rem; }
a { color: #163a70; }
.muted { color: #555; }
.banner { background: #fde8e4; border: 1px solid #b42318; padding: 0.75rem 1rem; margin: 0.75rem 0; }
.card { background: #fff; border: 1px solid #ddd; padding: 1rem; margin: 0.75rem 0; }
.fp { font-family: ui-monospace, monospace; word-break: break-all; }
svg { width: 11rem; height: auto; background: #fff; }
label { display: block; margin: 0.6rem 0 0.2rem; }
input[type=password], input[type=text] { width: 100%; padding: 0.45rem; box-sizing: border-box; font: inherit; }
button { font: inherit; padding: 0.45rem 0.8rem; margin-right: 0.4rem; }
pre { white-space: pre-wrap; word-break: break-word; font: 0.85rem/1.4 ui-monospace, monospace; }
`;

export function renderHome(opts: {
  csrf: string;
  handle: string;
  fingerprint: string;
  qrPayload: string;
  approvals: PageApproval[];
  contacts: ContactView[];
}): string {
  const pending = opts.approvals.filter((item) => item.status === 'pending');
  const changed = opts.contacts.filter((contact) => contact.key_changed);
  const rows = pending
    .map((item) => {
      const hold = item.hold ? ` <span class="muted">${esc(labelHold(item.hold))}</span>` : '';
      return `<li><a href="/approvals/${esc(item.approval_id)}">${esc(item.summary)}</a>${hold}<div class="muted">${esc(item.kind)} · ${esc(item.requested_by)} · ${esc(item.created_at)}</div></li>`;
    })
    .join('');
  const alerts = changed
    .map(
      (contact) =>
        `<div class="banner"><strong>Key changed for ${esc(contact.handle)}.</strong> The pinned fingerprint no longer matches the relay. Do not approve an add until you verify the new fingerprint out of band. Pinned <span class="fp">${esc(contact.fingerprint)}</span>. New <span class="fp">${esc(contact.pending_fingerprint ?? '')}</span>.</div>`,
    )
    .join('');
  const contacts = opts.contacts
    .map((contact) => {
      const state = contact.key_changed ? 'key changed — blocked until re-verified' : contact.verified ? 'verified' : 'unverified';
      const pendingQr =
        contact.key_changed && contact.pending_qr_payload
          ? `<p>New fingerprint</p><p class="fp">${esc(contact.pending_fingerprint ?? '')}</p>${qrSvg(contact.pending_qr_payload)}`
          : '';
      return `<div class="card"><strong>${esc(contact.handle)}</strong> <span class="muted">${esc(state)}</span><p class="fp">${esc(contact.fingerprint)}</p>${qrSvg(contact.qr_payload)}${pendingQr}</div>`;
    })
    .join('');
  return layout(
    'Approvals',
    `${alerts}
     <p class="muted">This page is only on your computer. Approving or denying requires your identity passphrase. Agents cannot do it.</p>
     <h2>Your safety number</h2>
     <p class="fp">${esc(opts.fingerprint)}</p>
     ${qrSvg(opts.qrPayload)}
     <p class="muted">${esc(opts.handle)}</p>
     <h2>Pending</h2>
     ${rows ? `<ul>${rows}</ul>` : '<p class="muted">Nothing is waiting.</p>'}
     <h2>Contacts</h2>
     ${contacts || '<p class="muted">No contacts pinned yet.</p>'}
     <h2>Verify a fingerprint</h2>
     <form method="post" action="/contacts/verify">
       ${csrfField(opts.csrf)}
       <label>Handle <input type="text" name="handle" autocomplete="off" required></label>
       <label>Safety number or QR payload <input type="text" name="fingerprint" autocomplete="off" required></label>
       <label>Identity passphrase <input type="password" name="passphrase" autocomplete="off" required></label>
       <button type="submit">Verify</button>
     </form>
     <h2>Agent tokens</h2>
     <p class="muted">Labels stay hidden until you enter the passphrase. The raw token is not stored.</p>
     <form method="post" action="/tokens/list">
       ${csrfField(opts.csrf)}
       <label>Identity passphrase <input type="password" name="passphrase" autocomplete="off" required></label>
       <button type="submit">Show token labels</button>
     </form>`,
  );
}

export function renderApproval(opts: { csrf: string; approval: PageApproval }): string {
  const item = opts.approval;
  const contact = item.contact;
  const warn =
    contact?.key_changed
      ? `<div class="banner"><strong>Key changed for ${esc(contact.handle)}.</strong> Approving an add is blocked until you verify the new fingerprint. Pinned <span class="fp">${esc(contact.fingerprint)}</span>. New <span class="fp">${esc(contact.pending_fingerprint ?? '')}</span>.</div>`
      : '';
  const contactBlock = contact
    ? `<h2>${esc(contact.handle)} ${contact.verified ? 'verified' : 'unverified'}</h2>
       <p class="fp">${esc(contact.fingerprint)}</p>
       ${qrSvg(contact.qr_payload)}
       ${
         contact.pending_qr_payload
           ? `<p>New fingerprint</p><p class="fp">${esc(contact.pending_fingerprint ?? '')}</p>${qrSvg(contact.pending_qr_payload)}`
           : ''
       }`
    : '';
  const paths =
    item.sensitive_paths && item.sensitive_paths.length > 0
      ? `<p>Sensitive paths: ${item.sensitive_paths.map((path) => `<span class="fp">${esc(path)}</span>`).join(', ')}</p>`
      : '';
  const hold = item.hold ? `<p>Held action: <strong>${esc(labelHold(item.hold))}</strong></p>` : '';
  return layout(
    'Approval',
    `${warn}
     <p><a href="/">All approvals</a></p>
     <div class="card">
       <p><strong>${esc(item.summary)}</strong></p>
       <p class="muted">${esc(item.kind)} · ${esc(item.status)} · ${esc(item.requested_by)} · ${esc(item.created_at)}</p>
       ${item.topic_title ? `<p>Topic: ${esc(item.topic_title)}</p>` : ''}
       ${hold}
       ${paths}
       <pre>${esc(JSON.stringify(item.request ?? {}, null, 2))}</pre>
     </div>
     ${contactBlock}
     <form method="post" action="/approvals/${esc(item.approval_id)}">
       ${csrfField(opts.csrf)}
       <label>Identity passphrase <input type="password" name="passphrase" autocomplete="off" required></label>
       <button type="submit" name="decision" value="approve">Approve</button>
       <button type="submit" name="decision" value="deny">Deny</button>
     </form>`,
  );
}

export function renderTokens(tokens: Array<{ agent_label: string; topic_scope: unknown; revoked: boolean }>): string {
  const rows = tokens
    .map(
      (token) =>
        `<li>${esc(token.agent_label)} <span class="muted">${esc(JSON.stringify(token.topic_scope))}${token.revoked ? ' revoked' : ''}</span></li>`,
    )
    .join('');
  return layout('Agent tokens', `<p><a href="/">Approvals</a></p><ul>${rows}</ul>`);
}

export function renderResult(title: string, body: string): string {
  return layout(title, `<p>${esc(body)}</p><p><a href="/">Back to approvals</a></p>`);
}

export function renderError(message: string): string {
  return layout('Could not do that', `<p>${esc(message)}</p><p><a href="/">Back to approvals</a></p>`);
}

function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${esc(title)} — Agent Bridge</title>
<style>${CSS}</style>
</head>
<body>
<h1>${esc(title)}</h1>
${body}
</body>
</html>`;
}

function csrfField(token: string): string {
  return `<input type="hidden" name="csrf" value="${esc(token)}">`;
}

function labelHold(hold: string): string {
  if (hold === 'spend') return 'spend';
  if (hold === 'external_message') return 'external message';
  if (hold === 'sensitive_path') return 'sensitive path';
  return hold;
}

function esc(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
