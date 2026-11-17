import { describe, expect, it } from 'vitest';
import { DEFAULT_POLICY, patchNeedsApproval, pathIsSensitive, requestNeedsApproval } from '../src/policy.ts';

describe('approval policy', () => {
  it('requires approval for spend and external messages, and an agent can only add one', () => {
    expect(requestNeedsApproval(DEFAULT_POLICY, { kind: 'spend' }, false)).toBe(true);
    expect(requestNeedsApproval(DEFAULT_POLICY, { kind: 'note' }, false)).toBe(false);
    expect(requestNeedsApproval(DEFAULT_POLICY, { kind: 'note' }, true)).toBe(true);
  });

  it('matches sensitive state paths, including an ancestor write', () => {
    expect(pathIsSensitive(DEFAULT_POLICY, '/_meta/slug')).toBe(true);
    expect(pathIsSensitive(DEFAULT_POLICY, '/_meta')).toBe(true);
    expect(pathIsSensitive(DEFAULT_POLICY, '/bookings/0/confirmation')).toBe(true);
    expect(pathIsSensitive(DEFAULT_POLICY, '/bookings')).toBe(true);
    expect(pathIsSensitive(DEFAULT_POLICY, '/')).toBe(true);
    expect(pathIsSensitive(DEFAULT_POLICY, '/notes/0')).toBe(false);
    expect(pathIsSensitive(DEFAULT_POLICY, '/spend/amount')).toBe(true);
    expect(
      patchNeedsApproval(DEFAULT_POLICY, [{ op: 'replace', path: '/notes/0', value: 1 }], false),
    ).toBe(false);
    expect(
      patchNeedsApproval(DEFAULT_POLICY, [{ op: 'replace', path: '/notes/0', value: 1 }], true),
    ).toBe(true);
  });

  it('requires approval for descendants of a sensitive path, and for copy or move from one', () => {
    const child = '/bookings/0/confirmation/status';
    const paid = '/bookings/0/confirmation/paid';
    expect(pathIsSensitive(DEFAULT_POLICY, child)).toBe(true);
    expect(pathIsSensitive(DEFAULT_POLICY, paid)).toBe(true);
    expect(pathIsSensitive(DEFAULT_POLICY, '/bookings/0')).toBe(true);
    expect(pathIsSensitive(DEFAULT_POLICY, '/notes/1')).toBe(false);
    for (const op of ['add', 'replace', 'remove', 'test'] as const) {
      expect(patchNeedsApproval(DEFAULT_POLICY, [{ op, path: child, value: 'x' }], false)).toBe(true);
    }
    expect(
      patchNeedsApproval(DEFAULT_POLICY, [{ op: 'copy', from: child, path: '/notes/0' }], false),
    ).toBe(true);
    expect(
      patchNeedsApproval(DEFAULT_POLICY, [{ op: 'move', from: paid, path: '/notes/0' }], false),
    ).toBe(true);
    expect(
      patchNeedsApproval(DEFAULT_POLICY, [{ op: 'copy', from: '/notes/0', path: '/notes/1' }], false),
    ).toBe(false);
  });
});
