import { describe, expect, it } from 'vitest';
import { applyPatch, canonicalize, hashBytes, hashLabel } from '../src/json.ts';

describe('shared state bytes', () => {
  it('canonicalizes object keys and hashes the document', () => {
    expect(canonicalize({ b: 1, a: { d: true, c: null } })).toBe('{"a":{"c":null,"d":true},"b":1}');
    const hash = hashBytes({ a: 1 });
    expect(hashLabel(hash)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(hashBytes({ a: 1 })).toEqual(hashBytes({ a: 1 }));
  });

  it('applies add, remove, replace, move, copy, and test', () => {
    const doc = { trains: [{ id: 'a' }], note: 'x' };
    const applied = applyPatch(doc, [
      { op: 'add', path: '/trains/-', value: { id: 'b' } },
      { op: 'replace', path: '/note', value: 'y' },
      { op: 'copy', from: '/note', path: '/copy' },
      { op: 'move', from: '/copy', path: '/moved' },
      { op: 'test', path: '/moved', value: 'y' },
      { op: 'remove', path: '/moved' },
    ]);
    expect(applied).toEqual({ ok: true, doc: { trains: [{ id: 'a' }, { id: 'b' }], note: 'y' } });
    expect(doc).toEqual({ trains: [{ id: 'a' }], note: 'x' });
  });

  it('rejects a path that is not there and a failed test', () => {
    expect(applyPatch({ a: 1 }, [{ op: 'remove', path: '/missing' }])).toMatchObject({ ok: false });
    expect(applyPatch({ a: 1 }, [{ op: 'test', path: '/a', value: 2 }])).toMatchObject({ ok: false, message: 'test op failed' });
  });
});
