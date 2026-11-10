import { describe, expect, it } from 'vitest';
import {
  analyzeTiming,
  buildClaimRows,
  formatDuration,
  inspectJwt,
} from '../jwt';

function toBase64Url(obj: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  let bin = '';
  for (const b of bytes) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

describe('inspectJwt', () => {
  it('handles empty input cleanly', () => {
    const res = inspectJwt('   ');
    expect(res.isEmpty).toBe(true);
    expect(res.isValidStructure).toBe(false);
  });

  it('strips Bearer prefix and parses valid UTF-8 header & payload', () => {
    const header = toBase64Url({ alg: 'HS256', typ: 'JWT' });
    const payload = toBase64Url({ sub: '42', name: 'Çağrı Şen', exp: 1900000000 });
    const token = `Bearer ${header}.${payload}.fakesig123`;

    const res = inspectJwt(token);
    expect(res.bearerPrefixStripped).toBe(true);
    expect(res.isValidStructure).toBe(true);
    expect(res.header).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(res.payload).toEqual({ sub: '42', name: 'Çağrı Şen', exp: 1900000000 });
  });

  it('rejects non-3-part tokens', () => {
    const res = inspectJwt('abc.def');
    expect(res.tokenFormat).toBe('invalid');
    expect(res.isValidStructure).toBe(false);
    expect(res.checks[0]?.status).toBe('fail');
  });

  it('detects 5-part JWE tokens and decodes JWE header', () => {
    const jweHeader = toBase64Url({ alg: 'RSA-OAEP-256', enc: 'A256GCM', kid: 'enc-1' });
    const res = inspectJwt(`${jweHeader}.encKey.iv.ciphertext.tag`);
    expect(res.tokenFormat).toBe('jwe');
    expect(res.isValidStructure).toBe(false);
    expect(res.header).toEqual({ alg: 'RSA-OAEP-256', enc: 'A256GCM', kid: 'enc-1' });
    expect(res.payload).toBeNull();
    expect(res.checks.some((c) => c.id === 'structure-jwe' && c.status === 'warn')).toBe(true);
  });

  it('warns on alg=none and empty signature', () => {
    const header = toBase64Url({ alg: 'none', typ: 'JWT' });
    const payload = toBase64Url({ sub: '1' });
    const res = inspectJwt(`${header}.${payload}.`);

    const algCheck = res.checks.find((c) => c.id === 'header-alg');
    const sigCheck = res.checks.find((c) => c.id === 'signature-present');
    expect(algCheck?.status).toBe('warn');
    expect(sigCheck?.status).toBe('warn');
  });

  it('fails when header contains invalid Base64URL characters', () => {
    const payload = toBase64Url({ sub: '1' });
    const res = inspectJwt(`invalid+chars=.${payload}.sig`);
    expect(res.isValidStructure).toBe(false);
    expect(res.errors.some((e) => e.includes('Header'))).toBe(true);
  });
});

describe('analyzeTiming & formatDuration', () => {
  it('formats durations across days, hours, minutes, seconds', () => {
    expect(formatDuration(90061)).toBe('1g 01s 01d 01sn');
    expect(formatDuration(45)).toBe('45sn');
  });

  it('detects active valid token and computes lifespan progress', () => {
    const nowMs = 1_700_000_500 * 1000;
    const timing = analyzeTiming(
      { iat: 1_700_000_000, exp: 1_700_001_000 },
      nowMs,
    );
    expect(timing.status).toBe('valid');
    expect(timing.remainingSeconds).toBe(500);
    expect(timing.lifespanProgressPercent).toBe(50);
  });

  it('detects expired token', () => {
    const nowMs = 1_700_002_000 * 1000;
    const timing = analyzeTiming({ exp: 1_700_001_000 }, nowMs);
    expect(timing.status).toBe('expired');
    expect(timing.remainingSeconds).toBe(-1000);
  });

  it('detects not-yet-valid token via nbf', () => {
    const nowMs = 1_700_000_000 * 1000;
    const timing = analyzeTiming(
      { nbf: 1_700_000_300, exp: 1_700_001_000 },
      nowMs,
    );
    expect(timing.status).toBe('not_yet_valid');
    expect(timing.nbfRemainingSeconds).toBe(300);
  });
});

describe('buildClaimRows', () => {
  it('maps standard and custom claims', () => {
    const rows = buildClaimRows({
      iss: 'https://auth.example.com',
      exp: 1_700_001_000,
      tenant_tier: 'pro',
    });

    const issRow = rows.find((r) => r.key === 'iss');
    const customRow = rows.find((r) => r.key === 'tenant_tier');
    expect(issRow?.isStandard).toBe(true);
    expect(customRow?.isStandard).toBe(false);
    expect(customRow?.category).toBe('custom');
  });
});
