// Shared-state bytes: RFC 6902 JSON Patch and RFC 8785 canonical JSON.
// Canonical form sorts object keys by UTF-16 code unit and uses JSON number
// formatting, which matches RFC 8785 for the finite numbers JSON.parse yields.

import { createHash } from 'node:crypto';
import { utf8 } from '@agent-bridge/protocol';

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export interface PatchOp {
  op: 'add' | 'remove' | 'replace' | 'move' | 'copy' | 'test';
  path: string;
  from?: string;
  value?: unknown;
}

export function canonicalize(value: unknown): string {
  return JSON.stringify(order(value)) ?? 'null';
}

export function hashBytes(value: unknown): Uint8Array {
  return new Uint8Array(createHash('sha256').update(utf8(canonicalize(value))).digest());
}

export function hashLabel(bytes: Uint8Array): string {
  return `sha256:${Buffer.from(bytes).toString('hex')}`;
}

export function parseHashLabel(label: string): Uint8Array | undefined {
  if (!label.startsWith('sha256:')) return undefined;
  const hex = label.slice('sha256:'.length);
  if (hex.length !== 64 || !/^[0-9a-f]+$/.test(hex)) return undefined;
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/** Apply a patch to a deep copy. The input document is not modified. */
export function applyPatch(doc: unknown, patch: PatchOp[]): { ok: true; doc: unknown } | { ok: false; message: string } {
  let current = cloneJson(doc);
  for (const op of patch) {
    const step = applyOne(current, op);
    if (!step.ok) return step;
    current = step.doc;
  }
  return { ok: true, doc: current };
}

export function pointerValue(doc: unknown, pointer: string): { ok: true; value: unknown } | { ok: false; message: string } {
  return read(doc, pointer);
}

export function isPatch(value: unknown): value is PatchOp[] {
  if (!Array.isArray(value)) return false;
  return value.every((op) => {
    if (typeof op !== 'object' || op === null) return false;
    const record = op as Record<string, unknown>;
    if (typeof record.op !== 'string' || typeof record.path !== 'string') return false;
    if (!['add', 'remove', 'replace', 'move', 'copy', 'test'].includes(record.op)) return false;
    if (record.from !== undefined && typeof record.from !== 'string') return false;
    return true;
  });
}

function applyOne(doc: unknown, op: PatchOp): { ok: true; doc: unknown } | { ok: false; message: string } {
  if (op.op === 'add' || op.op === 'replace' || op.op === 'test') {
    if (op.value === undefined || !isJson(op.value)) return fail('patch value is not JSON');
  }
  if ((op.op === 'move' || op.op === 'copy') && op.from === undefined) return fail('patch is missing from');
  if (op.op === 'test') {
    const found = read(doc, op.path);
    if (!found.ok) return found;
    return jsonEqual(found.value, op.value) ? { ok: true, doc } : fail('test op failed');
  }
  if (op.op === 'remove') return removeAt(doc, op.path);
  if (op.op === 'replace') return replaceAt(doc, op.path, op.value);
  if (op.op === 'copy') {
    const found = read(doc, op.from!);
    if (!found.ok) return found;
    return addAt(doc, op.path, cloneJson(found.value));
  }
  if (op.op === 'move') {
    if (op.path.startsWith(op.from!) && (op.path.length === op.from!.length || op.path[op.from!.length] === '/')) {
      return fail('cannot move a value into itself');
    }
    const found = read(doc, op.from!);
    if (!found.ok) return found;
    const removed = removeAt(doc, op.from!);
    if (!removed.ok) return removed;
    return addAt(removed.doc, op.path, found.value);
  }
  return addAt(doc, op.path, op.value);
}

function addAt(doc: unknown, pointer: string, value: unknown): { ok: true; doc: unknown } | { ok: false; message: string } {
  if (pointer === '') return { ok: true, doc: cloneJson(value) };
  const tokens = tokensOf(pointer);
  if (!tokens) return fail('patch path is not a JSON pointer');
  const parent = parentOf(doc, tokens);
  if (!parent.ok) return parent;
  const key = tokens[tokens.length - 1]!;
  if (Array.isArray(parent.value)) {
    if (key === '-') {
      parent.value.push(cloneJson(value) as Json);
      return { ok: true, doc };
    }
    const index = arrayIndex(key, parent.value.length);
    if (index === undefined) return fail('patch path is not an array index');
    parent.value.splice(index, 0, cloneJson(value) as Json);
    return { ok: true, doc };
  }
  parent.value[key] = cloneJson(value) as Json;
  return { ok: true, doc };
}

function removeAt(doc: unknown, pointer: string): { ok: true; doc: unknown } | { ok: false; message: string } {
  if (pointer === '') return fail('cannot remove the whole document');
  const tokens = tokensOf(pointer);
  if (!tokens) return fail('patch path is not a JSON pointer');
  const parent = parentOf(doc, tokens);
  if (!parent.ok) return parent;
  const key = tokens[tokens.length - 1]!;
  if (Array.isArray(parent.value)) {
    const index = arrayIndex(key, parent.value.length - 1);
    if (index === undefined || parent.value[index] === undefined) return fail('patch path does not exist');
    parent.value.splice(index, 1);
    return { ok: true, doc };
  }
  if (!Object.hasOwn(parent.value, key)) return fail('patch path does not exist');
  delete parent.value[key];
  return { ok: true, doc };
}

function replaceAt(doc: unknown, pointer: string, value: unknown): { ok: true; doc: unknown } | { ok: false; message: string } {
  if (pointer === '') return { ok: true, doc: cloneJson(value) };
  const tokens = tokensOf(pointer);
  if (!tokens) return fail('patch path is not a JSON pointer');
  const parent = parentOf(doc, tokens);
  if (!parent.ok) return parent;
  const key = tokens[tokens.length - 1]!;
  if (Array.isArray(parent.value)) {
    const index = arrayIndex(key, parent.value.length - 1);
    if (index === undefined) return fail('patch path does not exist');
    parent.value[index] = cloneJson(value) as Json;
    return { ok: true, doc };
  }
  if (!Object.hasOwn(parent.value, key)) return fail('patch path does not exist');
  parent.value[key] = cloneJson(value) as Json;
  return { ok: true, doc };
}

function read(doc: unknown, pointer: string): { ok: true; value: unknown } | { ok: false; message: string } {
  if (pointer === '') return { ok: true, value: doc };
  const tokens = tokensOf(pointer);
  if (!tokens) return fail('patch path is not a JSON pointer');
  let current = doc;
  for (const token of tokens) {
    if (Array.isArray(current)) {
      const index = arrayIndex(token, current.length - 1);
      if (index === undefined || current[index] === undefined) return fail('patch path does not exist');
      current = current[index];
    } else if (isObject(current) && Object.hasOwn(current, token)) {
      current = current[token];
    } else {
      return fail('patch path does not exist');
    }
  }
  return { ok: true, value: current };
}

function parentOf(
  doc: unknown,
  tokens: string[],
): { ok: true; value: Json[] | { [key: string]: Json } } | { ok: false; message: string } {
  const parentPointer = tokens.length === 1 ? '' : `/${tokens.slice(0, -1).map(escapeToken).join('/')}`;
  const found = read(doc, parentPointer);
  if (!found.ok) return found;
  if (!Array.isArray(found.value) && !isObject(found.value)) return fail('patch path does not exist');
  return { ok: true, value: found.value };
}

function tokensOf(pointer: string): string[] | undefined {
  if (!pointer.startsWith('/')) return undefined;
  return pointer
    .slice(1)
    .split('/')
    .map((token) => token.replaceAll('~1', '/').replaceAll('~0', '~'));
}

function escapeToken(token: string): string {
  return token.replaceAll('~', '~0').replaceAll('/', '~1');
}

function arrayIndex(token: string, max: number): number | undefined {
  if (!/^(0|[1-9][0-9]*)$/.test(token)) return undefined;
  const index = Number(token);
  if (!Number.isSafeInteger(index) || index > max) return undefined;
  return index;
}

function fail(message: string): { ok: false; message: string } {
  return { ok: false, message };
}

function order(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(order);
  if (isObject(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) out[key] = order(value[key]);
    return out;
  }
  return value;
}

function cloneJson(value: unknown): unknown {
  return JSON.parse(canonicalize(value));
}

function jsonEqual(left: unknown, right: unknown): boolean {
  return canonicalize(left) === canonicalize(right);
}

function isObject(value: unknown): value is { [key: string]: Json } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isJson(value: unknown): boolean {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJson);
  if (isObject(value)) return Object.values(value).every(isJson);
  return false;
}
