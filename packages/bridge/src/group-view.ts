// Human group view. Plain language only: no passphrase field, no composer,
// and no epochs, hashes, tool names, or protocol paths. Yes / No / Edit post
// to the approval route; http.ts still requires the identity passphrase before
// anything is sent. renderExtensionCard is the hook for a future item card
// (an open question, a vote). This view does not invent those types.

/** Read cursor for the person. Not an agent label, so opening a group does not move an agent's cursor. */
export const HUMAN_READ_LABEL = 'human:';

export interface GroupEnvelope {
  seq: number;
  authorHandle: string;
  type: string;
  body: string | null;
  payload: unknown;
  ts: string;
}

export interface GroupApproval {
  approvalId: string;
  kind: string;
  summary: string;
  request: unknown;
  createdAt: string;
}

export interface GroupMember {
  handle: string;
  role: string;
}

export interface GroupKeyChange {
  handle: string;
  at: string | null;
}

export interface GroupRecord {
  topicId: string;
  title: string;
  status: string;
  selfHandle: string;
  doc: unknown;
  envelopes: GroupEnvelope[];
  pending: GroupApproval[];
  members: GroupMember[];
  keyChanged: GroupKeyChange[];
  readSeq: number;
}

export type GroupFilter = 'all' | 'needs';

/** A later item type returns a card here. The string is HTML and must already be escaped. */
export function renderExtensionCard(item: { type: string; payload: unknown }): string | undefined {
  void item;
  return undefined;
}

export interface SummaryField {
  label: string;
  value: string;
  note?: string;
}

export interface TopicSummary {
  label: string;
  line: string;
  fields: SummaryField[];
}

/** One line plus the plain fields of a topic_state document. Skips hashes, epochs, and paths. */
export function summaryFromDoc(doc: unknown, title = ''): TopicSummary {
  const label = /\btrip\b/i.test(title) ? 'Trip' : 'Summary';
  if (!isRecord(doc)) return { label, line: '', fields: [] };
  const fields: SummaryField[] = [];
  for (const [key, value] of Object.entries(doc)) {
    if (skipKey(key)) continue;
    const rendered = renderValue(value, 0);
    if (!rendered?.value) continue;
    fields.push({ label: humanLabel(key), value: rendered.value, ...(rendered.note ? { note: rendered.note } : {}) });
  }
  const line = fields
    .slice(0, 4)
    .map((field) => clip(field.value, 42))
    .join(' · ');
  return { label, line, fields };
}

export function displayName(handle: string): string {
  const local = handle.split('@')[0] ?? handle;
  const first = local.split(/[._\s-]+/).find((part) => part.length > 0) ?? local;
  if (!first) return handle;
  if (first === first.toLowerCase()) return first.charAt(0).toUpperCase() + first.slice(1);
  return first;
}

export function formatListTime(iso: string, now: Date): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  if (sameDay(date, now)) return clock(date);
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (sameDay(date, yesterday)) return 'Yesterday';
  const days = (startOfDay(now).getTime() - startOfDay(date).getTime()) / 86_400_000;
  if (days > 0 && days < 7) return new Intl.DateTimeFormat('en-GB', { weekday: 'short' }).format(date);
  return new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short' }).format(date);
}

export function formatDay(iso: string, now: Date): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  if (sameDay(date, now)) return 'Today';
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (sameDay(date, yesterday)) return 'Yesterday';
  return new Intl.DateTimeFormat('en-GB', { weekday: 'short', day: 'numeric', month: 'short' })
    .format(date)
    .replace(',', '');
}

interface ProjectedRow {
  topicId: string;
  title: string;
  preview: string;
  at: string;
  unread: number;
  needsYou: boolean;
}

function projectRows(records: GroupRecord[]): ProjectedRow[] {
  return records
    .map((record) => {
      const chats = visibleChats(record);
      const last = chats[chats.length - 1];
      const changed = record.keyChanged[0];
      let preview = 'No messages yet.';
      let at = record.envelopes[record.envelopes.length - 1]?.ts ?? '';
      if (last?.body) {
        const mine = last.authorHandle === record.selfHandle;
        const who = mine ? 'You' : `${displayName(last.authorHandle)}'s agent`;
        preview = `${who}: ${collapse(last.body)}`;
        at = last.ts;
      } else if (changed) {
        preview = keyLine(changed.handle);
        at = changed.at ?? at;
      }
      return {
        topicId: record.topicId,
        title: record.title,
        preview,
        at,
        unread: chats.filter((row) => row.seq > record.readSeq).length,
        needsYou: record.pending.length > 0,
      };
    })
    .sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : a.title.localeCompare(b.title)));
}

function previewHtml(preview: string): string {
  const split = preview.indexOf(': ');
  if (split > 0 && split < 40) {
    return `<em>${esc(preview.slice(0, split))}:</em> ${esc(preview.slice(split + 2))}`;
  }
  return esc(preview);
}

function listColumn(rows: ProjectedRow[], selected: string | undefined, filter: GroupFilter, needs: number, now: Date): string {
  const shown = filter === 'needs' ? rows.filter((row) => row.needsYou) : rows;
  const body = shown.length
    ? shown.map((row) => groupRow(row, selected === row.topicId, filter, now)).join('')
    : `<p class="empty">${filter === 'needs' ? 'Nothing needs you.' : 'No groups yet.'}</p>`;
  const needsLabel = needs > 0 ? `Needs you · ${needs}` : 'Needs you';
  return `<section class="col col-list">
    <header class="hdr"><div class="hdr-title">Groups</div></header>
    <div class="filters">
      <a class="pill${filter === 'all' ? ' on' : ''}" href="/groups">All</a>
      <a class="pill need${filter === 'needs' ? ' on' : ''}" href="/groups?filter=needs">${esc(needsLabel)}</a>
    </div>
    <div class="scroll">${body}</div>
    <nav class="tabs">
      <a class="on" href="/groups">Groups</a>
      <a href="/">Approvals</a>
      <a href="/#contacts">Contacts</a>
    </nav>
  </section>`;
}

function groupRow(row: ProjectedRow, selected: boolean, filter: GroupFilter, now: Date): string {
  const href = `/groups/${encodeURIComponent(row.topicId)}${filter === 'needs' ? '?filter=needs' : ''}`;
  const time = row.at ? formatListTime(row.at, now) : '';
  return `<a class="row${selected ? ' sel' : ''}" href="${href}">
    ${groupAvatar('sz48')}
    <span class="m">
      <span class="l1"><b>${esc(row.title)}</b><time>${esc(time)}</time></span>
      <span class="l2">${previewHtml(row.preview)}</span>
      <span class="l3">
        ${row.needsYou ? `<span class="pill need">Needs you</span>` : ''}
        <span class="sp"></span>
        ${row.unread > 0 ? `<span class="badge">${row.unread}</span>` : ''}
      </span>
    </span>
  </a>`;
}

function timelinePieces(
  record: GroupRecord,
  now: Date,
  extensionCard: (item: { type: string; payload: unknown }) => string | undefined,
): string[] {
  type Item = { at: string; seq: number; html: string };
  const items: Item[] = [];
  for (const row of record.envelopes) {
    const chat = chatText(row);
    if (chat) {
      items.push({ at: row.ts, seq: row.seq, html: bubble(record, row, chat, now) });
      continue;
    }
    if (row.type === 'leave') {
      items.push({
        at: row.ts,
        seq: row.seq,
        html: `<div class="sys">${esc(`${displayName(row.authorHandle)} left this group.`)}</div>`,
      });
      continue;
    }
    if (hiddenType(row.type)) continue;
    const card = extensionCard({ type: row.type, payload: row.payload });
    if (card) items.push({ at: row.ts, seq: row.seq, html: card });
  }
  for (const change of record.keyChanged) {
    items.push({
      at: change.at ?? '',
      seq: Number.MAX_SAFE_INTEGER,
      html: `<div class="warn"><p>${esc(keyLine(change.handle))}</p><a class="btn sm pri" href="/contacts/${encodeURIComponent(change.handle)}/verify">Check</a></div>`,
    });
  }
  items.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.seq - b.seq));
  const out: string[] = [];
  let day = '';
  for (const item of items) {
    const label = item.at ? formatDay(item.at, now) : '';
    if (label && label !== day) {
      day = label;
      out.push(`<div class="day">${esc(label)}</div>`);
    }
    out.push(item.html);
  }
  return out;
}

function approvalCards(record: GroupRecord, csrf: string): string {
  return record.pending.map((approval) => approvalCard(record.topicId, approval, csrf)).join('');
}

function approvalCard(topicId: string, approval: GroupApproval, csrf: string): string {
  const card = cardCopy(approval);
  const action = `/groups/${encodeURIComponent(topicId)}/approvals/${encodeURIComponent(approval.approvalId)}`;
  const draft = card.draft ? `<div class="draft">${esc(card.draft)}</div>` : '';
  const note = card.note ? `<p class="sub">${esc(card.note)}</p>` : '';
  const edit = card.canEdit
    ? `<details class="edit">
        <summary class="btn ghost sm">Edit</summary>
        <form method="post" action="${action}">
          ${csrfField(csrf)}
          <input type="hidden" name="decision" value="edit">
          <label class="edit-label">Wording<textarea name="body" rows="4">${esc(card.draft)}</textarea></label>
          <button class="btn sm" type="submit">Save</button>
        </form>
      </details>`
    : '';
  return `<div class="card need">
    <div class="k">Needs you</div>
    <div class="ttl">${esc(card.title)}</div>
    ${draft}
    ${note}
    <form method="post" action="${action}" class="btns">
      ${csrfField(csrf)}
      <button class="btn pri" type="submit" name="decision" value="approve">Yes</button>
      <button class="btn" type="submit" name="decision" value="deny">No</button>
    </form>
    ${edit}
  </div>`;
}

function cardCopy(approval: GroupApproval): { title: string; draft: string; note?: string; canEdit: boolean } {
  const request = isRecord(approval.request) ? approval.request : {};
  if (approval.kind === 'request') {
    const body = typeof request.body === 'string' && request.body.trim() ? request.body.trim() : approval.summary;
    return {
      title: 'Your agent wants to send this',
      draft: isNoiseText(body) ? approval.summary : body,
      note: plainConsequence(request),
      canEdit: true,
    };
  }
  if (approval.kind === 'state_change') {
    return {
      title: 'Your agent wants to update the shared notes',
      draft: isNoiseText(approval.summary) ? '' : approval.summary,
      note: 'This changes something you asked to confirm.',
      canEdit: false,
    };
  }
  if (approval.kind === 'invite') {
    const handle = typeof request.handle === 'string' ? request.handle : '';
    return { title: `Your agent wants to invite ${handle ? displayName(handle) : 'someone'}`, draft: '', canEdit: false };
  }
  if (approval.kind === 'remove') {
    const handle = typeof request.handle === 'string' ? request.handle : '';
    return { title: `Your agent wants to remove ${handle ? displayName(handle) : 'someone'}`, draft: '', canEdit: false };
  }
  if (approval.kind === 'join') {
    return {
      title: 'You were added to this group',
      draft: isNoiseText(approval.summary) ? '' : approval.summary,
      canEdit: false,
    };
  }
  return { title: 'Your agent is waiting for you', draft: '', canEdit: false };
}

function plainConsequence(request: Record<string, unknown>): string | undefined {
  const payload = isRecord(request.payload) ? request.payload : {};
  const kind = typeof payload.kind === 'string' ? payload.kind : '';
  if (kind === 'spend') {
    const amount = payload.amount;
    if (typeof amount === 'number' && Number.isFinite(amount)) return `This spends ${amount}.`;
    if (typeof amount === 'string' && amount.trim() && !isNoiseText(amount) && amount.length < 40) {
      return `This spends ${amount.trim()}.`;
    }
    return 'This spends money.';
  }
  if (kind === 'external_message') {
    const to = typeof payload.to === 'string' ? payload.to.trim() : '';
    if (to && !isNoiseText(to) && to.length < 80) return `This contacts someone outside the group: ${to}.`;
    return 'This contacts someone outside the group.';
  }
  return undefined;
}

function bubble(record: GroupRecord, row: GroupEnvelope, text: string, now: Date): string {
  const mine = row.authorHandle === record.selfHandle;
  const name = displayName(row.authorHandle);
  return `<div class="msg${mine ? ' mine' : ''}">
    <div class="bub">
      <div class="who">${esc(name)} <span class="tag">agent</span></div>
      <div class="body">${esc(text)}</div>
      <div class="meta">${esc(row.ts ? formatListTime(row.ts, now) : '')}</div>
    </div>
  </div>`;
}

function startedLine(record: GroupRecord): string {
  if (record.members.length === 0) return '';
  const owner = record.members.find((member) => member.role === 'owner') ?? record.members[0];
  if (!owner) return '';
  const others = record.members.filter((member) => member.handle !== owner.handle).map((member) => displayName(member.handle));
  const who = displayName(owner.handle);
  const text = others.length === 0 ? `${who} started this group` : `${who} started this group with ${joinNames(others)}`;
  return `<div class="sys">${esc(text)}</div>`;
}

function joinNames(names: string[]): string {
  if (names.length <= 1) return names[0] ?? '';
  if (names.length === 2) return `${names[0]} and ${names[1]}`;
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

function memberLine(record: GroupRecord): string {
  const names = record.members.map((member) => displayName(member.handle));
  if (names.length === 0) return record.status === 'closed' ? 'Closed' : '';
  const line = joinNames(names);
  return record.status === 'closed' ? `${line} · closed` : line;
}

function fieldsHtml(fields: SummaryField[]): string {
  if (fields.length === 0) return '';
  return `<div class="sec">${fields
    .map(
      (field) =>
        `<div class="fld"><div class="fn">${esc(field.label)}</div><div class="fv">${esc(field.value)}</div>${field.note ? `<div class="fs">${esc(field.note)}</div>` : ''}</div>`,
    )
    .join('')}</div>`;
}

function visibleChats(record: GroupRecord): GroupEnvelope[] {
  return record.envelopes.filter((row) => chatText(row) !== undefined);
}

function chatText(row: GroupEnvelope): string | undefined {
  if (!CHAT_TYPES.has(row.type)) return undefined;
  const body = row.body?.trim() ?? '';
  if (!body || isNoiseText(body)) return undefined;
  return body;
}

const CHAT_TYPES = new Set(['update', 'question', 'request', 'answer']);
const HIDDEN_TYPES = new Set([
  'state_snapshot',
  'state_patch',
  'snapshot_request',
  'invite_proposal',
  'removal_proposal',
  'system',
]);

function hiddenType(type: string): boolean {
  return HIDDEN_TYPES.has(type);
}

const TOOL_NAMES = [
  'list_topics',
  'create_topic',
  'list_members',
  'invite_member',
  'remove_member',
  'read_messages',
  'post_message',
  'get_state',
  'propose_state_change',
  'list_approvals',
  'self_update',
  'self-update',
];

export function isNoiseText(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed) return true;
  const lower = trimmed.toLowerCase();
  if (lower === 'discarded draft' || lower === 'state snapshot' || lower === 'state updated') return true;
  if (/sha256:[0-9a-f]/i.test(trimmed)) return true;
  if (/\bepoch\b/i.test(trimmed)) return true;
  if (/\/_meta(\/|$)/.test(trimmed)) return true;
  if (/(^|\s)\/[a-z0-9_*]+(?:\/[a-z0-9_*]+)+/i.test(trimmed)) return true;
  if (TOOL_NAMES.some((name) => lower.includes(name))) return true;
  return false;
}

function keyLine(handle: string): string {
  return `${displayName(handle)}'s agent changed devices — check it's really them.`;
}

const SKIP_KEYS = new Set([
  'hash',
  'doc_hash',
  'epoch',
  'version',
  'sig',
  'signature',
  'approval',
  'patch',
  'base_hash',
  'base_version',
  'payload',
  'credential',
  'seq',
  'message_id',
]);

function skipKey(key: string): boolean {
  const lower = key.toLowerCase();
  return key.startsWith('_') || SKIP_KEYS.has(lower) || lower.includes('hash') || lower === 'epoch';
}

function renderValue(value: unknown, depth: number): { value: string; note?: string } | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'string') {
    const text = value.trim();
    if (!text || looksTechnical(text)) return undefined;
    return { value: text };
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return undefined;
    return { value: String(value) };
  }
  if (typeof value === 'boolean') return { value: value ? 'Yes' : 'No' };
  if (Array.isArray(value)) {
    const parts = value
      .map((item) => renderValue(item, depth + 1)?.value)
      .filter((item): item is string => item !== undefined && item.length > 0);
    if (parts.length === 0) return undefined;
    return { value: parts.join(', ') };
  }
  if (!isRecord(value) || depth >= 2) return undefined;
  let note: string | undefined;
  const parts: string[] = [];
  for (const [key, inner] of Object.entries(value)) {
    if (skipKey(key)) continue;
    const rendered = renderValue(inner, depth + 1);
    if (!rendered?.value) continue;
    if (key === 'status' || key === 'note' || key === 'state') {
      note = rendered.value;
      continue;
    }
    parts.push(rendered.value);
  }
  if (parts.length === 0 && !note) return undefined;
  return { value: parts.join(', ') || note || '', ...(parts.length > 0 && note ? { note } : {}) };
}

function looksTechnical(text: string): boolean {
  if (isNoiseText(text)) return true;
  if (/^[0-9a-f]{32,}$/i.test(text)) return true;
  if (text.length > 180) return true;
  return false;
}

function humanLabel(key: string): string {
  const spaced = key
    .replaceAll(/[_-]+/g, ' ')
    .replaceAll(/([a-z0-9])([A-Z])/g, '$1 $2')
    .trim();
  return spaced
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
}

function collapse(text: string): string {
  return clip(text.replaceAll(/\s+/g, ' ').trim(), 160);
}

function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
}

function page(opts: { title: string; view: 'list' | 'topic'; body: string }): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${esc(opts.title)} — Agent Bridge</title>
<style>${CSS}</style>
</head>
<body data-view="${opts.view}">
${opts.body}
</body>
</html>`;
}

function csrfField(csrf: string): string {
  return `<input type="hidden" name="csrf" value="${esc(csrf)}">`;
}

const icon = {
  back: `<svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M15 5l-7 7 7 7"/></svg>`,
  pin: `<svg class="ic pin" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 4h6l-1 6 3 3H7l3-3-1-6zM12 13v7"/></svg>`,
  chev: `<svg class="ic chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>`,
  people: `<svg class="ic people" viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="9" r="3"/><circle cx="17" cy="10" r="2.4"/><path d="M3.5 19c.6-3 2.8-4.5 5.5-4.5s4.9 1.5 5.5 4.5M15.5 14.8c2.4-.3 4.2.9 5 3.2"/></svg>`,
};

function groupAvatar(size: string): string {
  return `<span class="av grp ${size}" aria-hidden="true">${icon.people}</span>`;
}

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

function startOfDay(date: Date): Date {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate());
}

function clock(date: Date): string {
  return new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
    .format(date)
    .replace(/[\u202f\u00a0]/g, ' ');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function esc(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const CSS = `
:root {
  color-scheme: dark;
  --bg: #10131a;
  --panel: #171b24;
  --lift: #1d2330;
  --line: #2a3140;
  --text: #eef1f6;
  --muted: #9aa3b2;
  --faint: #6e7787;
  --me: #8b96ff;
  --me-bg: #262c5a;
  --need: #e8b86a;
  --sans: system-ui, "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--bg); color: var(--text); font: 16px/1.45 var(--sans); }
a { color: inherit; text-decoration: none; }
button, summary { font: inherit; color: inherit; }
.shell { min-height: 100vh; }
.col { min-width: 0; }
.col-list { background: #12161e; display: flex; flex-direction: column; min-height: 100vh; }
.shell.topic .col-list, .shell.topic .col-notes, .shell.list .col-thread { display: none; }
.hdr { display: flex; align-items: center; gap: 10px; padding: 12px 16px; background: var(--panel); border-bottom: 1px solid var(--line); }
.hdr-title { font-size: 26px; font-weight: 700; letter-spacing: -0.02em; }
.hdr .t { flex: 1; min-width: 0; }
.hdr .t b, .row .l1 b { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.hdr .t b { font-size: 17px; }
.hdr .t span { display: block; color: var(--muted); font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.iconbtn { width: 36px; height: 36px; display: grid; place-items: center; color: var(--muted); }
.ic { width: 22px; height: 22px; stroke: currentColor; fill: none; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.ic.pin { width: 16px; height: 16px; }
.ic.chev { width: 18px; height: 18px; color: var(--faint); }
.ic.people { stroke: #fff; }
.av { display: grid; place-items: center; flex: none; }
.av.grp { border-radius: 16px; background: linear-gradient(135deg, #5a68e0, #2a9d9c); color: #fff; }
.av.sz40 { width: 40px; height: 40px; }
.av.sz48 { width: 48px; height: 48px; }
.filters { display: flex; gap: 8px; padding: 12px 16px; }
.pill { display: inline-flex; align-items: center; padding: 5px 12px; border-radius: 999px; font-size: 13px; font-weight: 650; color: var(--muted); background: var(--lift); border: 1px solid var(--line); }
.pill.on { background: #2a3160; border-color: #3d4a99; color: #d4d9ff; }
.pill.need { background: #2a2414; border-color: #5c4a22; color: var(--need); }
.row { display: flex; gap: 12px; padding: 13px 16px; align-items: flex-start; border-bottom: 1px solid #1a1f29; }
.row.sel { background: #1a2033; }
.row .m { flex: 1; min-width: 0; }
.row .l1 { display: flex; justify-content: space-between; gap: 10px; align-items: baseline; }
.row .l1 b { font-size: 16.5px; font-weight: 650; }
.row .l1 time { color: var(--faint); font-size: 13px; flex: none; }
.row .l2 { color: var(--muted); font-size: 15px; margin-top: 4px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.row .l2 em { font-style: normal; color: #c5ccd8; }
.row .l3 { margin-top: 8px; display: flex; gap: 8px; align-items: center; }
.sp { flex: 1; }
.badge { min-width: 22px; height: 22px; padding: 0 7px; border-radius: 11px; background: var(--me); color: #10131a; font: 700 12px var(--sans); display: inline-grid; place-items: center; }
.tabs { display: flex; border-top: 1px solid var(--line); background: var(--panel); margin-top: auto; }
.tabs a { flex: 1; text-align: center; padding: 12px 8px 16px; color: var(--faint); font-size: 13px; }
.tabs a.on { color: #d4d9ff; }
.pin { border-bottom: 1px solid var(--line); background: #151922; }
.pinbar { display: flex; gap: 10px; align-items: flex-start; padding: 11px 16px; cursor: pointer; list-style: none; }
.pinbar::-webkit-details-marker { display: none; }
.pin-line { flex: 1; min-width: 0; color: var(--muted); font-size: 13.5px; line-height: 1.4; }
.pin-line b { color: var(--text); }
.scroll { min-height: 0; }
.chat { padding: 12px 14px 28px; display: flex; flex-direction: column; gap: 10px; }
.day { align-self: center; font-size: 12.5px; color: var(--muted); background: var(--panel); padding: 4px 12px; border-radius: 999px; }
.sys { align-self: center; max-width: 34rem; text-align: center; color: var(--faint); font-size: 13px; }
.msg { display: flex; max-width: 100%; }
.msg.mine { justify-content: flex-end; }
.bub { max-width: 34rem; border-radius: 18px; padding: 10px 14px 8px; background: var(--lift); }
.msg.mine .bub { background: var(--me-bg); }
.who { font-size: 13px; font-weight: 650; margin-bottom: 3px; color: #c5d0ea; }
.tag { font-weight: 550; font-size: 11.5px; color: var(--faint); }
.body { font-size: 16px; line-height: 1.4; white-space: pre-wrap; overflow-wrap: anywhere; }
.meta { text-align: right; color: var(--faint); font-size: 12px; margin-top: 4px; }
.warn { background: #241e14; border-radius: 16px; padding: 12px 14px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.warn p { flex: 1; min-width: 160px; margin: 0; color: #f0d7a4; }
.card { border-radius: 18px; padding: 14px; background: var(--panel); display: grid; gap: 8px; max-width: 36rem; }
.card.need { background: #241e14; }
.card .k { font-size: 13px; font-weight: 650; color: var(--need); }
.card .ttl { font-size: 17px; font-weight: 650; }
.card .sub { margin: 0; color: var(--muted); font-size: 14.5px; }
.draft { background: #1a160f; border-radius: 12px; padding: 12px 14px; color: #f3ead8; white-space: pre-wrap; overflow-wrap: anywhere; }
.btns { display: flex; gap: 8px; flex-wrap: wrap; }
.btn { padding: 8px 16px; border-radius: 12px; font-weight: 650; font-size: 15px; border: 1px solid var(--line); background: var(--lift); color: var(--text); cursor: pointer; }
.btn.pri { background: var(--need); border-color: var(--need); color: #1a1408; }
.btn.ghost { background: transparent; }
.btn.sm { padding: 7px 14px; font-size: 14px; }
.edit { display: grid; }
.edit summary { width: fit-content; list-style: none; }
.edit summary::-webkit-details-marker { display: none; }
.edit-label { display: grid; gap: 6px; color: var(--muted); font-size: 13px; margin-top: 8px; }
textarea { width: 100%; box-sizing: border-box; font: inherit; color: var(--text); background: #1a160f; border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; }
.sec { padding: 8px 16px 16px; }
.fld { padding: 14px 0; border-bottom: 1px solid #1a1f29; }
.fld:last-child { border-bottom: 0; }
.fn { color: var(--muted); font-size: 13px; }
.fv { font-size: 17px; font-weight: 650; }
.fs { color: var(--muted); font-size: 14px; margin-top: 2px; }
.empty { color: var(--muted); padding: 24px 16px; }
.col-notes { background: #12161e; }
@media (min-width: 960px) {
  html, body { height: 100%; }
  .shell { height: 100vh; min-height: 0; overflow: hidden; }
  .shell.topic { display: grid; grid-template-columns: 340px minmax(0, 1fr) 320px; }
  .shell.list { display: grid; grid-template-columns: 340px minmax(0, 1fr); }
  .shell.topic .col-list, .shell.topic .col-thread, .shell.topic .col-notes, .shell.list .col-list, .shell.list .col-thread { display: flex; flex-direction: column; min-height: 0; }
  .col-list { border-right: 1px solid var(--line); min-height: 0; }
  .col-notes { border-left: 1px solid var(--line); }
  .scroll { flex: 1; overflow: auto; }
  .back, .pin .chev, .pin .mobile-fields { display: none; }
  .pinbar { cursor: default; }
  .chat { padding: 16px 28px 20px; }
  .bub { max-width: 70%; }
  .empty-thread { align-items: center; justify-content: center; }
}
`;

function renderListBody(
  records: GroupRecord[],
  filter: GroupFilter,
  now: Date,
  selected?: string,
): { needs: number; column: string } {
  const rows = projectRows(records);
  const needs = rows.filter((row) => row.needsYou).length;
  return { needs, column: listColumn(rows, selected, filter, needs, now) };
}

export function renderGroupsPage(opts: {
  records: GroupRecord[];
  filter: GroupFilter;
  now: Date;
}): string {
  const view = renderListBody(opts.records, opts.filter, opts.now);
  return page({
    title: 'Groups',
    view: 'list',
    body: `<div class="shell list">
      ${view.column}
      <section class="col col-thread empty-thread"><p class="empty">Choose a group.</p></section>
    </div>`,
  });
}

export function renderTopicPage(opts: {
  records: GroupRecord[];
  topicId: string;
  filter: GroupFilter;
  now: Date;
  csrf: string;
  extensionCard?: (item: { type: string; payload: unknown }) => string | undefined;
}): string | undefined {
  const record = opts.records.find((item) => item.topicId === opts.topicId);
  if (!record) return undefined;
  const summary = summaryFromDoc(record.doc, record.title);
  const fields = fieldsHtml(summary.fields);
  const pieces = timelinePieces(record, opts.now, opts.extensionCard ?? renderExtensionCard);
  const view = renderListBody(opts.records, opts.filter, opts.now, record.topicId);
  const names = memberLine(record);
  const pinText = summary.fields.length > 0 ? ` · ${summary.line}` : ' · Nothing else is written down yet.';
  const needsPill = record.pending.length > 0 ? `<span class="pill need">Needs you</span>` : '';
  return page({
      title: record.title,
      view: 'topic',
      body: `<div class="shell topic">
        ${view.column}
        <section class="col col-thread">
          <header class="hdr">
            <a class="iconbtn back" href="/groups${opts.filter === 'needs' ? '?filter=needs' : ''}" aria-label="Groups">${icon.back}</a>
            ${groupAvatar('sz40')}
            <div class="t"><b>${esc(record.title)}</b><span>${esc(names)}</span></div>
            ${needsPill}
          </header>
          <details class="pin">
            <summary class="pinbar">
              ${icon.pin}
              <span class="pin-line"><b>${esc(summary.label)}</b>${esc(pinText)}</span>
              ${icon.chev}
            </summary>
            <div class="mobile-fields">${fields}</div>
          </details>
          <div class="scroll">
            <div class="chat">
              ${startedLine(record)}
              ${record.status === 'halted' ? `<div class="sys">This group is paused.</div>` : ''}
              ${record.status === 'pending_join' ? `<div class="sys">You have not joined this group yet.</div>` : ''}
              ${pieces.join('') || (record.pending.length === 0 ? `<div class="sys">No messages yet.</div>` : '')}
              ${approvalCards(record, opts.csrf)}
            </div>
          </div>
        </section>
        <aside class="col col-notes">
          <header class="hdr"><div class="t"><b>${esc(summary.label)}</b><span>${esc(record.title)}</span></div></header>
          <div class="scroll">${fields || `<p class="empty">Nothing else is written down yet.</p>`}</div>
        </aside>
      </div>`,
  });
}
