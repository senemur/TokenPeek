import { describe, expect, it } from 'vitest';
import { exportJWK, exportSPKI, generateKeyPair, SignJWT } from 'jose';
import {
  createSampleTokens,
  DEMO_HMAC_SECRET,
  verifyJwtSignature,
} from '../verify';

describe('verifyJwtSignature', () => {
  it('verifies valid HS256 sample token even if expired (signature integrity check)', async () => {
    const bundle = await createSampleTokens();

    const validRes = await verifyJwtSignature({
      token: bundle.validToken,
      headerAlg: 'HS256',
      keyMode: 'hmac',
      expectedAlgorithm: 'HS256',
      secret: DEMO_HMAC_SECRET,
      secretEncoding: 'utf8',
      publicKeyInput: '',
    });
    expect(validRes.status).toBe('valid');

    const expiredSigRes = await verifyJwtSignature({
      token: bundle.expiredToken,
      headerAlg: 'HS256',
      keyMode: 'hmac',
      expectedAlgorithm: 'HS256',
      secret: DEMO_HMAC_SECRET,
      secretEncoding: 'utf8',
      publicKeyInput: '',
    });
    expect(expiredSigRes.status).toBe('valid');
  });

  it('rejects tampered signature', async () => {
    const bundle = await createSampleTokens();
    const res = await verifyJwtSignature({
      token: bundle.tamperedToken,
      headerAlg: 'HS256',
      keyMode: 'hmac',
      expectedAlgorithm: 'HS256',
      secret: DEMO_HMAC_SECRET,
      secretEncoding: 'utf8',
      publicKeyInput: '',
    });
    expect(res.status).toBe('invalid');
  });

  it('rejects alg=none explicitly', async () => {
    const res = await verifyJwtSignature({
      token: 'a.b.',
      headerAlg: 'none',
      keyMode: 'hmac',
      expectedAlgorithm: 'auto',
      secret: 'secret',
      secretEncoding: 'utf8',
      publicKeyInput: '',
    });
    expect(res.status).toBe('invalid');
    expect(res.message).toContain('alg="none"');
  });

  it('blocks algorithm confusion when pasting PEM public key into HMAC mode', async () => {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    const spkiPem = await exportSPKI(publicKey);
    const rsToken = await new SignJWT({ sub: '123' })
      .setProtectedHeader({ alg: 'RS256' })
      .sign(privateKey);

    const confusionAttempt = await verifyJwtSignature({
      token: rsToken,
      headerAlg: 'RS256',
      keyMode: 'hmac',
      expectedAlgorithm: 'auto',
      secret: spkiPem,
      secretEncoding: 'utf8',
      publicKeyInput: '',
    });
    expect(confusionAttempt.status).toBe('error');
    expect(confusionAttempt.message).toContain('Algoritma karışıklığı');

    const validAsymmetric = await verifyJwtSignature({
      token: rsToken,
      headerAlg: 'RS256',
      keyMode: 'publicKey',
      expectedAlgorithm: 'RS256',
      secret: '',
      secretEncoding: 'utf8',
      publicKeyInput: spkiPem,
    });
    expect(validAsymmetric.status).toBe('valid');
  });

  it('verifies ES256 token with JWK public key and rejects private JWK', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256', {
      extractable: true,
    });
    const pubJwk = await exportJWK(publicKey);
    const privJwk = await exportJWK(privateKey);

    const esToken = await new SignJWT({ sub: 'alice' })
      .setProtectedHeader({ alg: 'ES256' })
      .sign(privateKey);

    const privAttempt = await verifyJwtSignature({
      token: esToken,
      headerAlg: 'ES256',
      keyMode: 'publicKey',
      expectedAlgorithm: 'ES256',
      secret: '',
      secretEncoding: 'utf8',
      publicKeyInput: JSON.stringify(privJwk),
    });
    expect(privAttempt.status).toBe('error');
    expect(privAttempt.message).toContain('private key');

    const pubSuccess = await verifyJwtSignature({
      token: esToken,
      headerAlg: 'ES256',
      keyMode: 'publicKey',
      expectedAlgorithm: 'ES256',
      secret: '',
      secretEncoding: 'utf8',
      publicKeyInput: JSON.stringify(pubJwk),
    });
    expect(pubSuccess.status).toBe('valid');
  });
});
