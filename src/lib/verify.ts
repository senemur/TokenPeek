import { compactVerify, importJWK, importSPKI, SignJWT, errors as joseErrors } from 'jose';
import type { JWK } from 'jose';

export const HMAC_ALGORITHMS = ['HS256', 'HS384', 'HS512'] as const;
export const ASYMMETRIC_ALGORITHMS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
] as const;

export type HmacAlgorithm = (typeof HMAC_ALGORITHMS)[number];
export type AsymmetricAlgorithm = (typeof ASYMMETRIC_ALGORITHMS)[number];
export type SupportedAlgorithm = HmacAlgorithm | AsymmetricAlgorithm;

export type KeyMode = 'hmac' | 'publicKey';
export type SecretEncoding = 'utf8' | 'base64';

export interface VerifySignatureOptions {
  token: string;
  headerAlg: string | null;
  keyMode: KeyMode;
  expectedAlgorithm: SupportedAlgorithm | 'auto';
  secret: string;
  secretEncoding: SecretEncoding;
  publicKeyInput: string;
}

export interface VerifySignatureResult {
  status: 'valid' | 'invalid' | 'error';
  algorithmUsed: SupportedAlgorithm | null;
  message: string;
  securityNote?: string;
}

export const DEMO_HMAC_SECRET = 'tokenpeek-local-demo-secret-key-256';

export function isHmacAlgorithm(alg: string): alg is HmacAlgorithm {
  return (HMAC_ALGORITHMS as readonly string[]).includes(alg);
}

export function isAsymmetricAlgorithm(alg: string): alg is AsymmetricAlgorithm {
  return (ASYMMETRIC_ALGORITHMS as readonly string[]).includes(alg);
}

export function isSupportedAlgorithm(alg: string): alg is SupportedAlgorithm {
  return isHmacAlgorithm(alg) || isAsymmetricAlgorithm(alg);
}

function bytesToOctJwk(bytes: Uint8Array): JWK {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  const k = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return { kty: 'oct', k };
}

function decodeBase64OrBase64Url(input: string): Uint8Array {
  const cleaned = input.trim().replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned)) {
    throw new Error('Geçersiz Base64 / Base64URL secret formatı.');
  }
  const padded = cleaned.padEnd(cleaned.length + ((4 - (cleaned.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function assertJwkMatchesAlgorithm(jwk: JWK, alg: AsymmetricAlgorithm): void {
  if ('d' in jwk && jwk.d) {
    throw new Error(
      'Güvenlik uyarısı: JWK içinde private key bileşeni ("d") tespit edildi. Doğrulama için yalnızca public key paylaşın.',
    );
  }
  if (jwk.kty === 'oct') {
    throw new Error(
      'Algoritma karışıklığı engellendi: Simetrik ("oct") JWK asimetrik doğrulama modunda kullanılamaz.',
    );
  }
  if ((alg.startsWith('RS') || alg.startsWith('PS')) && jwk.kty !== 'RSA') {
    throw new Error(`${alg} için RSA tipinde JWK bekleniyordu (gelen: ${String(jwk.kty)}).`);
  }
  if (alg.startsWith('ES') && jwk.kty !== 'EC') {
    throw new Error(`${alg} için EC tipinde JWK bekleniyordu (gelen: ${String(jwk.kty)}).`);
  }
  if (alg === 'EdDSA' && jwk.kty !== 'OKP') {
    throw new Error(`EdDSA için OKP tipinde JWK bekleniyordu (gelen: ${String(jwk.kty)}).`);
  }
}

async function resolvePublicKey(
  rawInput: string,
  alg: AsymmetricAlgorithm,
): Promise<CryptoKey | Uint8Array> {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new Error('Lütfen SPKI PEM (-----BEGIN PUBLIC KEY-----) veya JWK formatında public key girin.');
  }

  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(trimmed)) {
    throw new Error(
      'Güvenlik uyarısı: Private key algılandı. İmza doğrulaması için yalnızca Public Key girilmelidir.',
    );
  }

  if (trimmed.startsWith('{')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new Error('Public Key JWK geçerli bir JSON nesnesi değil.');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('Public Key JWK geçerli bir JSON nesnesi olmalıdır.');
    }
    const jwk = parsed as JWK;
    assertJwkMatchesAlgorithm(jwk, alg);
    const imported = await importJWK(jwk, alg);
    return imported as CryptoKey | Uint8Array;
  }

  if (!trimmed.includes('-----BEGIN PUBLIC KEY-----')) {
    throw new Error(
      'Desteklenen formatlar: SPKI PEM ("-----BEGIN PUBLIC KEY-----") veya JWK JSON.',
    );
  }

  return importSPKI(trimmed, alg);
}

/**
 * Verifies a JWT JWS signature strictly client-side with algorithm-confusion guards.
 */
export async function verifyJwtSignature(
  options: VerifySignatureOptions,
): Promise<VerifySignatureResult> {
  const {
    token,
    headerAlg,
    keyMode,
    expectedAlgorithm,
    secret,
    secretEncoding,
    publicKeyInput,
  } = options;

  if (!headerAlg) {
    return {
      status: 'error',
      algorithmUsed: null,
      message: 'Token header içinde "alg" alanı bulunamadığı için imza doğrulanamıyor.',
    };
  }

  if (headerAlg.toLowerCase() === 'none') {
    return {
      status: 'invalid',
      algorithmUsed: null,
      message: 'alg="none" güvenlik politikası gereği reddedildi.',
      securityNote:
        'İmzasız (alg: none) tokenlar kimlik doğrulama için asla güvenilir kabul edilmemelidir.',
    };
  }

  if (!isSupportedAlgorithm(headerAlg)) {
    return {
      status: 'error',
      algorithmUsed: null,
      message: `Desteklenmeyen algoritma: ${headerAlg}.`,
    };
  }

  if (expectedAlgorithm !== 'auto' && expectedAlgorithm !== headerAlg) {
    return {
      status: 'invalid',
      algorithmUsed: null,
      message: `Algoritma uyuşmazlığı: Beklenen algoritma "${expectedAlgorithm}", ancak token header "${headerAlg}" belirtiyor.`,
      securityNote:
        'Beklenen algoritmayı sabitlemek (algorithm pinning), saldırganların alg başlığını değiştirerek doğrulamayı atlatmasını önler.',
    };
  }

  if (keyMode === 'hmac' && !isHmacAlgorithm(headerAlg)) {
    return {
      status: 'error',
      algorithmUsed: null,
      message: `Algoritma karışıklığı engellendi: Token "${headerAlg}" (asimetrik) kullanıyor; doğrulama için Public Key sekmesini kullanın.`,
      securityNote:
        'Asimetrik algoritmalı tokenları HMAC secret ile doğrulamaya çalışmak CVE-2015-9235 benzeri risklere yol açar.',
    };
  }

  if (keyMode === 'publicKey' && !isAsymmetricAlgorithm(headerAlg)) {
    return {
      status: 'error',
      algorithmUsed: null,
      message: `Algoritma karışıklığı engellendi: Token "${headerAlg}" (simetrik HMAC) kullanıyor; doğrulama için HMAC Secret sekmesini kullanın.`,
    };
  }

  try {
    let key: CryptoKey | JWK;

    if (keyMode === 'hmac') {
      const trimmedSecret = secret.trim();
      if (!trimmedSecret) {
        return {
          status: 'error',
          algorithmUsed: null,
          message: 'Doğrulama için lütfen HMAC secret değerini girin.',
        };
      }
      if (/-----BEGIN [A-Z ]*KEY-----/.test(trimmedSecret)) {
        return {
          status: 'error',
          algorithmUsed: null,
          message:
            'Güvenlik engeli: HMAC secret alanına PEM anahtarı girildi. Public Key doğrulaması için Asimetrik sekmesini seçin.',
        };
      }

      const secretBytes =
        secretEncoding === 'base64'
          ? decodeBase64OrBase64Url(trimmedSecret)
          : new TextEncoder().encode(secret);
      key = bytesToOctJwk(secretBytes);
    } else {
      key = (await resolvePublicKey(publicKeyInput, headerAlg as AsymmetricAlgorithm)) as CryptoKey;
    }

    await compactVerify(token, key, {
      algorithms: [headerAlg],
    });

    return {
      status: 'valid',
      algorithmUsed: headerAlg,
      message: `İmza kriptografik olarak doğrulandı (${headerAlg}).`,
    };
  } catch (err) {
    if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
      return {
        status: 'invalid',
        algorithmUsed: headerAlg,
        message: 'İmza geçersiz: Anahtar yanlış veya token içeriği değiştirilmiş.',
      };
    }

    if (err instanceof joseErrors.JWSInvalid) {
      return {
        status: 'invalid',
        algorithmUsed: headerAlg,
        message: 'JWS yapısı veya imza biçimi geçersiz.',
      };
    }

    const detail = err instanceof Error ? err.message : 'Doğrulama sırasında beklenmeyen hata oluştu.';
    return {
      status: 'error',
      algorithmUsed: headerAlg,
      message: detail,
    };
  }
}

export interface DemoTokenBundle {
  validToken: string;
  expiredToken: string;
  tamperedToken: string;
  secret: string;
}

/**
 * Generates local signed demo JWTs directly in browser memory using Web Crypto.
 */
export async function createSampleTokens(): Promise<DemoTokenBundle> {
  const secretKey = bytesToOctJwk(new TextEncoder().encode(DEMO_HMAC_SECRET));
  const nowSec = Math.floor(Date.now() / 1000);

  const validToken = await new SignJWT({
    sub: 'usr_98412',
    name: 'Deniz Yılmaz',
    email: 'deniz@example.dev',
    roles: ['backend-dev', 'admin'],
    scope: 'read:orders write:orders',
    azp: 'tokenpeek-web',
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT', kid: 'demo-key-2026' })
    .setIssuer('https://auth.tokenpeek.local')
    .setAudience('https://api.tokenpeek.local')
    .setIssuedAt(nowSec - 300)
    .setNotBefore(nowSec - 60)
    .setExpirationTime(nowSec + 3600)
    .setJti('jti_demo_active_01')
    .sign(secretKey);

  const expiredToken = await new SignJWT({
    sub: 'usr_98412',
    name: 'Deniz Yılmaz',
    roles: ['backend-dev'],
    scope: 'read:orders',
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT', kid: 'demo-key-2026' })
    .setIssuer('https://auth.tokenpeek.local')
    .setAudience('https://api.tokenpeek.local')
    .setIssuedAt(nowSec - 7200)
    .setExpirationTime(nowSec - 900)
    .setJti('jti_demo_expired_02')
    .sign(secretKey);

  const parts = validToken.split('.');
  const flippedChar = parts[2].startsWith('A') ? 'B' : 'A';
  const tamperedToken = `${parts[0]}.${parts[1]}.${flippedChar}${parts[2].slice(1)}`;

  return {
    validToken,
    expiredToken,
    tamperedToken,
    secret: DEMO_HMAC_SECRET,
  };
}
