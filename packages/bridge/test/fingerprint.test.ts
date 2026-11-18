import { describe, expect, it } from 'vitest';
import { renderApproval, renderHome } from '../src/approval-page.ts';
import {
  fingerprint,
  fingerprintDigits,
  fingerprintQrPayload,
  parseFingerprint,
} from '../src/fingerprint.ts';
import { qrSvg, qrTerminal } from '../src/qr.ts';

const ZERO = new Uint8Array(32);

describe('safety number', () => {
  it('shows SHA-256 as 12 groups of 5 digits and a QR payload', () => {
    expect(fingerprint(ZERO)).toBe('04632 05093 53513 27310 65824 23493 72732 01522 02237 09631 47919 91810');
    const digits = fingerprintDigits(ZERO);
    expect(digits).toHaveLength(60);
    expect(fingerprint(ZERO).split(' ')).toEqual(digits.match(/.{5}/g));
    expect(fingerprintQrPayload(ZERO)).toBe(`agbfp:v1:${digits}`);
  });

  it('accepts grouped digits, raw digits, and the QR payload', () => {
    const digits = fingerprintDigits(ZERO);
    expect(parseFingerprint(fingerprint(ZERO))).toBe(digits);
    expect(parseFingerprint(digits)).toBe(digits);
    expect(parseFingerprint(`  ${fingerprintQrPayload(ZERO)}  `)).toBe(digits);
    expect(parseFingerprint('agbfp:v1:123')).toBeUndefined();
    expect(parseFingerprint(`${digits}1`)).toBeUndefined();
    expect(parseFingerprint('not a fingerprint')).toBeUndefined();
  });

  it('prints a terminal QR and an SVG with no external references', () => {
    const payload = fingerprintQrPayload(ZERO);
    const terminal = qrTerminal(payload);
    expect(terminal).toMatch(/[▀▄█]/);
    const svg = qrSvg(payload);
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg.replaceAll('xmlns="http://www.w3.org/2000/svg"', '')).not.toMatch(/<script|https?:\/\//);
    const page = renderHome({
      csrf: 'csrf-token',
      handle: 'ada',
      fingerprint: fingerprint(ZERO),
      qrPayload: payload,
      approvals: [],
      contacts: [],
    });
    expect(page).toContain(fingerprint(ZERO));
    expect(page).toContain('<svg');
    expect(page.replaceAll('xmlns="http://www.w3.org/2000/svg"', '')).not.toMatch(/<script|https?:\/\//);
    const dirty = renderApproval({
      csrf: 'csrf-token',
      approval: {
        approval_id: 'apr_1',
        kind: 'request',
        status: 'pending',
        summary: '<script>alert(1)</script>',
        requested_by: 'ada/cli',
        topic_id: 'topic',
        created_at: '2026-11-18T00:00:00.000Z',
        hold: 'spend',
        request: { body: '<b>no</b>' },
      },
    });
    expect(dirty).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(dirty).not.toContain('<script>');
    expect(dirty).toContain('name="csrf" value="csrf-token"');
    expect(dirty).toContain('value="deny"');
  });
});
