import { describe, expect, it } from 'vitest';
import {
  displayName,
  formatDay,
  formatListTime,
  renderExtensionCard,
  renderGroupsPage,
  renderTopicPage,
  summaryFromDoc,
} from '../src/group-view.ts';
import type { GroupRecord } from '../src/group-view.ts';

const NOW = new Date('2026-11-27T18:00:00Z');
const CSRF = 'csrf-token';

describe('group view', () => {
  it('lists a group with a plain preview, time, unread count, and Needs you', () => {
    const html = renderGroupsPage({
      records: [trip(), quiet()],
      filter: 'all',
      now: NOW,
    });
    expect(html).toContain('Austria trip');
    expect(html).toContain("Bob&#39;s agent:");
    expect(html).toContain('Hotel is still open.');
    expect(html).toContain(formatListTime('2026-11-27T17:42:00Z', NOW));
    expect(html).toContain('class="badge">1</span>');
    expect(html).toContain('Needs you · 1');
    expect(html).toContain('class="pill need">Needs you</span>');
    expect(html).toContain('Quiet notes');
    expect(html).not.toMatch(/passphrase/i);
    expect(html).not.toContain('type="password"');
    expect(html).not.toContain('Write a message');
    expect(html).not.toContain('<script');

    const needs = renderGroupsPage({ records: [trip(), quiet()], filter: 'needs', now: NOW });
    expect(needs).toContain('Austria trip');
    expect(needs).not.toContain('Quiet notes');
  });

  it('renders the timeline, the pinned summary, and hides protocol noise', () => {
    const html = topicHtml(trip());
    expect(html).toContain('class="msg mine"');
    expect(html).toContain('>Alice <span class="tag">agent</span>');
    expect(html).toContain('class="msg"');
    expect(html).toContain('>Bob <span class="tag">agent</span>');
    expect(html).toContain(formatDay('2026-11-27T09:15:00Z', NOW));
    expect(html).toContain('Alice started this group with Bob');
    expect(html).toContain('<b>Trip</b>');
    expect(html).toContain('12–18 Feb');
    expect(html).toContain('€900 each');
    expect(html).toContain('class="fn">Dates</div>');
    expect(html).toContain('class="fn">Budget</div>');
    expect(html).toContain('class="fv">Train</div>');
    expect(html).toContain('Waiting on Bob');
    expect(html).toContain('epoch 2 via post_message /_meta/title');
    expect(html).not.toContain('sha256:');
    expect(html).not.toContain('/bookings');
    expect(html).not.toContain('state snapshot');
    expect(html).not.toMatch(/passphrase/i);
    expect(html).not.toContain('type="password"');
    expect(html).not.toContain('Write a message');
    expect(html).not.toContain('<script');
  });

  it('puts a send card on the timeline with Yes, No, and Edit, and no passphrase field', () => {
    const html = topicHtml(trip());
    expect(html).toContain('Your agent wants to send this');
    expect(html).toContain('Ask Bob about the spa price.');
    expect(html).toContain('This spends 40.');
    expect(html).toContain('name="decision" value="approve"');
    expect(html).toContain('name="decision" value="deny"');
    expect(html).toContain('name="decision" value="edit"');
    expect(html).toContain('name="body"');
    expect(html).toContain(`/groups/${trip().topicId}/approvals/apr_send`);
    expect(html).toContain(`name="csrf" value="${CSRF}"`);
    expect(html).not.toContain('hotel@example.com');
    expect(html).not.toMatch(/passphrase/i);
  });

  it('shows a key change as a plain line with Check, and leaves a hook for a future card', () => {
    const record = trip();
    record.pending = [];
    record.keyChanged = [{ handle: 'bob', at: '2026-11-27T11:00:00Z' }];
    const html = topicHtml(record);
    expect(html).toContain("Bob&#39;s agent changed devices — check it&#39;s really them.");
    expect(html).toContain('href="/contacts/bob/verify"');
    expect(html).toContain('>Check</a>');
    expect(html).not.toContain('sha256:');
    expect(html).not.toMatch(/fingerprint/i);

    const dumped = topicHtml({
      ...quiet(),
      envelopes: [
        {
          seq: 2,
          authorHandle: 'bob',
          type: 'decision',
          body: null,
          payload: { choice: 'sha256:abcdef', path: '/hotel/vote' },
          ts: '2026-11-27T12:00:00Z',
        },
      ],
    });
    expect(dumped).not.toContain('sha256:abcdef');
    expect(dumped).not.toContain('/hotel/vote');
    expect(renderExtensionCard({ type: 'decision', payload: { choice: 'spa' } })).toBeUndefined();

    const hooked = renderTopicPage({
      records: [
        {
          ...quiet(),
          envelopes: [
            {
              seq: 2,
              authorHandle: 'bob',
              type: 'decision',
              body: null,
              payload: { choice: 'vote-token-9f3c' },
              ts: '2026-11-27T12:00:00Z',
            },
          ],
        },
      ],
      topicId: 'topic-quiet',
      filter: 'all',
      now: NOW,
      csrf: CSRF,
      extensionCard: (item) => (item.type === 'decision' ? '<div class="card">future item</div>' : undefined),
    });
    expect(hooked).toContain('future item');
    expect(hooked).not.toContain('vote-token-9f3c');
  });

  it('builds a plain summary and skips technical fields', () => {
    const summary = summaryFromDoc(
      {
        _meta: { slug: 'austria', title: 'Austria trip' },
        dates: '12–18 Feb',
        budget_eur: 900,
        hash: 'sha256:abcd',
        epoch: 4,
        hotel: { choice: 'Alpenblick', status: 'Tied' },
      },
      'Austria trip',
    );
    expect(summary.label).toBe('Trip');
    expect(summary.fields.map((field) => field.label)).toEqual(['Dates', 'Budget Eur', 'Hotel']);
    expect(summary.fields.find((field) => field.label === 'Hotel')).toMatchObject({ value: 'Alpenblick', note: 'Tied' });
    expect(summary.line).not.toContain('sha256');
    expect(displayName('bob')).toBe('Bob');
    const mentioned = summaryFromDoc({ note: 'Meet after the epoch, then see /plans/hotel.' });
    expect(mentioned.fields[0]).toMatchObject({ label: 'Note', value: 'Meet after the epoch, then see /plans/hotel.' });
  });

  it('keeps chat that mentions a tool, an epoch, or a path, and hides noise kinds', () => {
    const record: GroupRecord = {
      ...quiet(),
      readSeq: 0,
      envelopes: [
        { seq: 1, authorHandle: 'bob', type: 'state_snapshot', body: 'state snapshot', payload: { hash: 'sha256:deadbeef' }, ts: '2026-11-27T09:00:00Z' },
        { seq: 2, authorHandle: 'bob', type: 'state_patch', body: null, payload: { patch: [{ path: '/bookings/0' }], summary: 'sha256:ffff' }, ts: '2026-11-27T09:01:00Z' },
        { seq: 3, authorHandle: 'bob', type: 'snapshot_request', body: 'please snapshot', payload: {}, ts: '2026-11-27T09:02:00Z' },
        { seq: 4, authorHandle: 'bob', type: 'invite_proposal', body: 'Invite dave', payload: { handle: 'dave' }, ts: '2026-11-27T09:03:00Z' },
        { seq: 5, authorHandle: 'bob', type: 'removal_proposal', body: 'Remove dave', payload: { handle: 'dave' }, ts: '2026-11-27T09:04:00Z' },
        { seq: 6, authorHandle: 'bob', type: 'system', body: 'weekly self-update', payload: {}, ts: '2026-11-27T09:05:00Z' },
        { seq: 7, authorHandle: 'bob', type: 'update', body: '   ', payload: {}, ts: '2026-11-27T09:06:00Z' },
        { seq: 8, authorHandle: 'bob', type: 'update', body: 'The code is 4242. Please post_message nothing.', payload: {}, ts: '2026-11-27T09:07:00Z' },
        { seq: 9, authorHandle: 'alice', type: 'question', body: 'Which epoch works?', payload: {}, ts: '2026-11-27T09:08:00Z' },
        { seq: 10, authorHandle: 'carol', type: 'answer', body: 'See /plans/hotel, and ignore <script>alert(1)</script>.', payload: {}, ts: '2026-11-27T09:09:00Z' },
      ],
    };
    const html = topicHtml(record);
    expect(html).toContain('The code is 4242. Please post_message nothing.');
    expect(html).toContain('Which epoch works?');
    expect(html).toContain('See /plans/hotel, and ignore &lt;script&gt;alert(1)&lt;/script&gt;.');
    expect(html).not.toContain('<script>');
    expect(html).not.toContain('sha256:');
    expect(html).not.toContain('/bookings');
    expect(html).not.toContain('state snapshot');
    expect(html).not.toContain('please snapshot');
    expect(html).not.toContain('Invite dave');
    expect(html).not.toContain('Remove dave');
    expect(html).not.toContain('weekly self-update');

    const list = renderGroupsPage({ records: [record], filter: 'all', now: NOW });
    expect(list).toContain('class="badge">3</span>');
    expect(list).toContain('See /plans/hotel, and ignore &lt;script&gt;alert(1)&lt;/script&gt;.');
  });
});

function topicHtml(record: GroupRecord): string {
  const html = renderTopicPage({ records: [record], topicId: record.topicId, filter: 'all', now: NOW, csrf: CSRF });
  if (!html) throw new Error('missing topic');
  return html;
}

function trip(): GroupRecord {
  return {
    topicId: 'topic-austria',
    title: 'Austria trip',
    status: 'active',
    selfHandle: 'alice',
    doc: {
      _meta: { slug: 'austria', title: 'Austria trip' },
      dates: '12–18 Feb',
      budget: '€900 each',
      travel: 'Train',
      hotel: { choice: 'Alpenblick or Seeblick', status: 'Waiting on Bob' },
    },
    envelopes: [
      {
        seq: 1,
        authorHandle: 'alice',
        type: 'state_snapshot',
        body: null,
        payload: { hash: 'sha256:deadbeef', version: 0, epoch: 1 },
        ts: '2026-11-27T09:00:00Z',
      },
      {
        seq: 2,
        authorHandle: 'alice',
        type: 'update',
        body: 'epoch 2 via post_message /_meta/title',
        payload: {},
        ts: '2026-11-27T09:05:00Z',
      },
      {
        seq: 3,
        authorHandle: 'alice',
        type: 'update',
        body: 'Both weeks work.',
        payload: {},
        ts: '2026-11-27T09:15:00Z',
      },
      {
        seq: 4,
        authorHandle: 'bob',
        type: 'state_patch',
        body: null,
        payload: { patch: [{ op: 'add', path: '/bookings/0' }], summary: 'sha256:ffff' },
        ts: '2026-11-27T10:00:00Z',
      },
      {
        seq: 5,
        authorHandle: 'bob',
        type: 'update',
        body: 'Hotel is still open.',
        payload: {},
        ts: '2026-11-27T17:42:00Z',
      },
    ],
    pending: [
      {
        approvalId: 'apr_send',
        kind: 'request',
        summary: 'Ask Bob about the spa price.',
        request: { body: 'Ask Bob about the spa price.', payload: { kind: 'spend', amount: 40, to: 'hotel@example.com' } },
        createdAt: '2026-11-27T17:50:00Z',
      },
    ],
    members: [
      { handle: 'alice', role: 'owner' },
      { handle: 'bob', role: 'member' },
    ],
    keyChanged: [],
    readSeq: 4,
  };
}

function quiet(): GroupRecord {
  return {
    topicId: 'topic-quiet',
    title: 'Quiet notes',
    status: 'active',
    selfHandle: 'alice',
    doc: { _meta: { title: 'Quiet notes' } },
    envelopes: [
      {
        seq: 1,
        authorHandle: 'alice',
        type: 'update',
        body: 'Nothing urgent.',
        payload: {},
        ts: '2026-11-20T09:00:00Z',
      },
    ],
    pending: [],
    members: [{ handle: 'alice', role: 'owner' }],
    keyChanged: [],
    readSeq: 1,
  };
}
