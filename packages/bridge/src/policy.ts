// The person's approval policy (DESIGN.md section 6.1). Agents can only add an
// approval for one call; they cannot remove one the file requires.

import { readFileSync } from 'node:fs';
import type { PatchOp } from './json.ts';

export interface Policy {
  requests_needing_approval: string[];
  state_paths_needing_approval: string[];
  approval_expiry_hours: number;
}

export const DEFAULT_POLICY: Policy = {
  requests_needing_approval: ['spend', 'external_message'],
  state_paths_needing_approval: ['/bookings/*/confirmation', '/spend/**', '/_meta/**'],
  approval_expiry_hours: 72,
};

export function loadPolicy(path: string): Policy {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return DEFAULT_POLICY;
  }
  if (!isPolicy(parsed)) return DEFAULT_POLICY;
  return parsed;
}

export function requestNeedsApproval(policy: Policy, payload: Record<string, unknown>, force: boolean): boolean {
  if (force) return true;
  const kind = payload.kind;
  return typeof kind === 'string' && policy.requests_needing_approval.includes(kind);
}

export function patchNeedsApproval(policy: Policy, patch: PatchOp[], force: boolean): boolean {
  if (force) return true;
  for (const op of patch) {
    if (pathIsSensitive(policy, op.path)) return true;
    if (op.from !== undefined && pathIsSensitive(policy, op.from)) return true;
  }
  return false;
}

/** True when a write at `path` would change a value the policy marks sensitive. */
export function pathIsSensitive(policy: Policy, path: string): boolean {
  return policy.state_paths_needing_approval.some((pattern) => pointerAffects(pattern, path));
}

function pointerAffects(pattern: string, path: string): boolean {
  const wanted = segments(pattern);
  const given = segments(path);
  if (pointerMatch(pattern, path)) return true;
  // Replacing an ancestor rewrites the sensitive child. `/` rewrites everything.
  if (coversAncestor(wanted, given)) return true;
  // A child of a sensitive path is the same value. `/bookings/*/confirmation/status`
  // is under `/bookings/*/confirmation`.
  return coversDescendant(wanted, given);
}

function coversAncestor(wanted: string[], given: string[]): boolean {
  const concrete = wanted.filter((segment) => segment !== '**');
  if (given.length >= concrete.length) return false;
  for (let i = 0; i < given.length; i++) {
    const segment = concrete[i];
    if (segment !== undefined && segment !== '*' && segment !== given[i]) return false;
  }
  return true;
}

/** The pattern matches a proper prefix of `path`. `*` is one segment. */
function coversDescendant(wanted: string[], given: string[]): boolean {
  let wi = 0;
  let gi = 0;
  while (wi < wanted.length) {
    const segment = wanted[wi]!;
    // A trailing ** already matches every longer path in pointerMatch.
    if (segment === '**') return false;
    if (gi >= given.length) return false;
    if (segment !== '*' && segment !== given[gi]) return false;
    wi += 1;
    gi += 1;
  }
  return gi < given.length;
}

function pointerMatch(pattern: string, path: string): boolean {
  return matchSegments(segments(pattern), segments(path));
}

function matchSegments(pattern: string[], path: string[]): boolean {
  if (pattern.length === 0) return path.length === 0;
  const [head, ...rest] = pattern;
  if (head === '**') {
    if (rest.length === 0) return true;
    for (let i = 0; i <= path.length; i++) {
      if (matchSegments(rest, path.slice(i))) return true;
    }
    return false;
  }
  if (path.length === 0) return false;
  if (head !== '*' && head !== path[0]) return false;
  return matchSegments(rest, path.slice(1));
}

function segments(pointer: string): string[] {
  if (pointer === '' || pointer === '/') return [];
  if (!pointer.startsWith('/')) return [pointer];
  return pointer
    .slice(1)
    .split('/')
    .map((segment) => segment.replaceAll('~1', '/').replaceAll('~0', '~'));
}

function isPolicy(value: unknown): value is Policy {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    stringArray(record.requests_needing_approval) &&
    stringArray(record.state_paths_needing_approval) &&
    typeof record.approval_expiry_hours === 'number' &&
    record.approval_expiry_hours > 0
  );
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}
