export type ValidationStatus = 'pass' | 'warn' | 'fail';

export interface ValidationCheck {
  id: string;
  label: string;
  status: ValidationStatus;
  detail: string;
}

export interface JwtSegments {
  headerRaw: string;
  payloadRaw: string;
  signatureRaw: string;
}

export type JwtFormatKind = 'empty' | 'jws' | 'jwe' | 'invalid';

export interface JwtInspectionResult {
  isEmpty: boolean;
  tokenFormat: JwtFormatKind;
  isValidStructure: boolean;
  bearerPrefixStripped: boolean;
  normalizedToken: string;
  segments: JwtSegments | null;
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  checks: ValidationCheck[];
  errors: string[];
}

export type TokenTimingStatus =
  | 'valid'
  | 'expired'
  | 'not_yet_valid'
  | 'no_expiration';

export interface TokenTimingAnalysis {
  status: TokenTimingStatus;
  expTimestamp: number | null;
  nbfTimestamp: number | null;
  iatTimestamp: number | null;
  expIso: string | null;
  expLocal: string | null;
  nbfLocal: string | null;
  iatLocal: string | null;
  remainingSeconds: number | null;
  nbfRemainingSeconds: number | null;
  lifespanProgressPercent: number | null;
  invalidTimestampClaims: string[];
}

export interface ClaimRow {
  key: string;
  title: string;
  description: string;
  category: 'standard' | 'identity' | 'authorization' | 'custom';
  rawValue: string;
  formattedValue: string;
  isStandard: boolean;
}

const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;
const BASE64URL_OPTIONAL_REGEX = /^[A-Za-z0-9_-]*$/;

interface ClaimMetadata {
  title: string;
  description: string;
  category: 'standard' | 'identity' | 'authorization';
  isTimestamp?: boolean;
}

export const CLAIM_DEFINITIONS: Record<string, ClaimMetadata> = {
  iss: {
    title: 'Issuer',
    description: 'Token\'ı üreten ve imzalayan yetkili servis/sistem.',
    category: 'standard',
  },
  sub: {
    title: 'Subject',
    description: 'Token\'ın temsil ettiği kullanıcı veya varlık kimliği.',
    category: 'standard',
  },
  aud: {
    title: 'Audience',
    description: 'Token\'ın hedeflendiği alıcı servis veya API.',
    category: 'standard',
  },
  exp: {
    title: 'Expiration Time',
    description: 'Token\'ın geçerliliğinin sona erdiği Unix zaman damgası.',
    category: 'standard',
    isTimestamp: true,
  },
  nbf: {
    title: 'Not Before',
    description: 'Token\'ın bu zamandan önce kabul edilmemesi gerektiğini belirtir.',
    category: 'standard',
    isTimestamp: true,
  },
  iat: {
    title: 'Issued At',
    description: 'Token\'ın oluşturulduğu Unix zaman damgası.',
    category: 'standard',
    isTimestamp: true,
  },
  jti: {
    title: 'JWT ID',
    description: 'Replay saldırılarını önlemek için kullanılan benzersiz token kimliği.',
    category: 'standard',
  },
  azp: {
    title: 'Authorized Party',
    description: 'Token\'ı talep eden istemci (client_id).',
    category: 'authorization',
  },
  scope: {
    title: 'Scope',
    description: 'OAuth 2.0 / OIDC kapsamında verilen yetki alanları.',
    category: 'authorization',
  },
  scp: {
    title: 'Scopes',
    description: 'Yetki kapsamları listesi.',
    category: 'authorization',
  },
  roles: {
    title: 'Roles',
    description: 'Kullanıcıya veya servise atanmış roller.',
    category: 'authorization',
  },
  permissions: {
    title: 'Permissions',
    description: 'İzin verilen ayrıntılı erişim hakları.',
    category: 'authorization',
  },
  email: {
    title: 'Email',
    description: 'Kullanıcının e-posta adresi.',
    category: 'identity',
  },
  email_verified: {
    title: 'Email Verified',
    description: 'E-posta adresinin doğrulanıp doğrulanmadığı.',
    category: 'identity',
  },
  name: {
    title: 'Full Name',
    description: 'Kullanıcının tam adı.',
    category: 'identity',
  },
  given_name: {
    title: 'Given Name',
    description: 'Kullanıcının adı.',
    category: 'identity',
  },
  family_name: {
    title: 'Family Name',
    description: 'Kullanıcının soyadı.',
    category: 'identity',
  },
  preferred_username: {
    title: 'Preferred Username',
    description: 'Tercih edilen kullanıcı adı.',
    category: 'identity',
  },
  auth_time: {
    title: 'Auth Time',
    description: 'Son kimlik doğrulama zamanı (Unix timestamp).',
    category: 'identity',
    isTimestamp: true,
  },
  nonce: {
    title: 'Nonce',
    description: 'OIDC akışında CSRF/replay koruması için tek kullanımlık değer.',
    category: 'standard',
  },
  sid: {
    title: 'Session ID',
    description: 'Kimlik doğrulama oturum kimliği.',
    category: 'identity',
  },
  tid: {
    title: 'Tenant ID',
    description: 'Çok kiracılı (multi-tenant) sistemdeki kiracı kimliği.',
    category: 'authorization',
  },
};

/**
 * Decodes an unpadded Base64URL string into strict UTF-8 text.
 */
export function decodeBase64UrlToUtf8(segment: string): string {
  if (!BASE64URL_REGEX.test(segment)) {
    throw new Error('Segment geçersiz Base64URL karakterleri içeriyor.');
  }
  if (segment.length % 4 === 1) {
    throw new Error('Base64URL uzunluğu geçersiz (mod 4 == 1 olamaz).');
  }

  const base64 = segment.replace(/-/g, '+').replace(/_/g, '/');
  const paddingLength = (4 - (base64.length % 4)) % 4;
  const padded = base64 + '='.repeat(paddingLength);

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  const decoder = new TextDecoder('utf-8', { fatal: true });
  return decoder.decode(bytes);
}

function decodeJsonObjectSegment(
  segment: string,
  segmentName: 'Header' | 'Payload',
): { data: Record<string, unknown> | null; error: string | null } {
  if (!segment) {
    return { data: null, error: `${segmentName} bölümü boş olamaz.` };
  }

  try {
    const utf8 = decodeBase64UrlToUtf8(segment);
    const parsed: unknown = JSON.parse(utf8);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return {
        data: null,
        error: `${segmentName} geçerli bir JSON nesnesi ({...}) olmalıdır.`,
      };
    }
    return { data: parsed as Record<string, unknown>, error: null };
  } catch (err) {
    const reason =
      err instanceof Error ? err.message : 'Bilinmeyen çözümleme hatası.';
    return {
      data: null,
      error: `${segmentName} çözümlenemedi: ${reason}`,
    };
  }
}

/**
 * Parses and validates a JWT string strictly inside the browser.
 */
export function inspectJwt(rawInput: string): JwtInspectionResult {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return {
      isEmpty: true,
      tokenFormat: 'empty',
      isValidStructure: false,
      bearerPrefixStripped: false,
      normalizedToken: '',
      segments: null,
      header: null,
      payload: null,
      checks: [],
      errors: [],
    };
  }

  const bearerMatch = /^Bearer\s+(.+)$/i.exec(trimmed);
  const bearerPrefixStripped = Boolean(bearerMatch);
  const normalizedToken = (bearerMatch ? bearerMatch[1] : trimmed).trim();

  const parts = normalizedToken.split('.');
  const checks: ValidationCheck[] = [];
  const errors: string[] = [];

  if (parts.length === 5) {
    const jweHeaderDecoded = decodeJsonObjectSegment(parts[0], 'Header');
    const detail =
      'Bu token 5 bölümden (JWE: Header.EncryptedKey.IV.Ciphertext.Tag) oluşuyor. İçerik şifrelenmiş olduğu için payload tarayıcıda çözümlenemez; yalnızca korumalı JWE Header görüntülenebilir.';
    checks.push({
      id: 'structure-jwe',
      label: 'JWE (Şifreli JWT) Tespit Edildi',
      status: 'warn',
      detail,
    });
    if (jweHeaderDecoded.error) {
      checks.push({
        id: 'header-encoding',
        label: 'JWE Header Base64URL & JSON',
        status: 'fail',
        detail: jweHeaderDecoded.error,
      });
      errors.push(jweHeaderDecoded.error);
    } else if (jweHeaderDecoded.data) {
      checks.push({
        id: 'header-encoding',
        label: 'JWE Header Base64URL & JSON',
        status: 'pass',
        detail: `JWE Header çözümlendi (alg: ${String(jweHeaderDecoded.data.alg ?? 'yok')}, enc: ${String(jweHeaderDecoded.data.enc ?? 'yok')}).`,
      });
    }

    return {
      isEmpty: false,
      tokenFormat: 'jwe',
      isValidStructure: false,
      bearerPrefixStripped,
      normalizedToken,
      segments: null,
      header: jweHeaderDecoded.data,
      payload: null,
      checks,
      errors,
    };
  }

  if (parts.length !== 3) {
    const detail = `JWT 3 bölümden (header.payload.signature) oluşmalıdır; şu an ${parts.length} bölüm bulundu.`;
    checks.push({
      id: 'structure',
      label: '3 Parçalı JWS Yapısı',
      status: 'fail',
      detail,
    });
    errors.push(detail);

    return {
      isEmpty: false,
      tokenFormat: 'invalid',
      isValidStructure: false,
      bearerPrefixStripped,
      normalizedToken,
      segments: null,
      header: null,
      payload: null,
      checks,
      errors,
    };
  }

  checks.push({
    id: 'structure',
    label: '3 Parçalı JWS Yapısı',
    status: 'pass',
    detail: 'Header, Payload ve Signature noktalarla ayrılmış 3 bölüm halinde.',
  });

  const [headerRaw, payloadRaw, signatureRaw] = parts;
  const segments: JwtSegments = { headerRaw, payloadRaw, signatureRaw };

  const headerDecoded = decodeJsonObjectSegment(headerRaw, 'Header');
  if (headerDecoded.error) {
    checks.push({
      id: 'header-encoding',
      label: 'Header Base64URL & JSON',
      status: 'fail',
      detail: headerDecoded.error,
    });
    errors.push(headerDecoded.error);
  } else {
    checks.push({
      id: 'header-encoding',
      label: 'Header Base64URL & JSON',
      status: 'pass',
      detail: 'Header geçerli Base64URL ve UTF-8 JSON nesnesi.',
    });
  }

  const headerObj = headerDecoded.data;
  if (headerObj) {
    const alg = headerObj.alg;
    if (typeof alg !== 'string' || !alg.trim()) {
      checks.push({
        id: 'header-alg',
        label: 'Algoritma (alg) Header',
        status: 'fail',
        detail: 'Header içinde geçerli bir "alg" alanı bulunamadı.',
      });
      errors.push('Header içinde "alg" alanı eksik veya geçersiz.');
    } else if (alg.toLowerCase() === 'none') {
      checks.push({
        id: 'header-alg',
        label: 'Algoritma (alg) Header',
        status: 'warn',
        detail: 'Güvenlik uyarısı: alg="none" imzasız token belirtir; üretim ortamında reddedilmelidir.',
      });
    } else {
      checks.push({
        id: 'header-alg',
        label: 'Algoritma (alg) Header',
        status: 'pass',
        detail: `Algoritma tanımlı: ${alg}`,
      });
    }
  }

  const payloadDecoded = decodeJsonObjectSegment(payloadRaw, 'Payload');
  if (payloadDecoded.error) {
    checks.push({
      id: 'payload-encoding',
      label: 'Payload Base64URL & JSON',
      status: 'fail',
      detail: payloadDecoded.error,
    });
    errors.push(payloadDecoded.error);
  } else {
    checks.push({
      id: 'payload-encoding',
      label: 'Payload Base64URL & JSON',
      status: 'pass',
      detail: 'Payload geçerli Base64URL ve UTF-8 JSON nesnesi.',
    });
  }

  if (!signatureRaw) {
    checks.push({
      id: 'signature-present',
      label: 'İmza Segmenti',
      status: 'warn',
      detail: 'İmza segmenti boş. Bu token kriptografik olarak imzalanmamış.',
    });
  } else if (!BASE64URL_OPTIONAL_REGEX.test(signatureRaw)) {
    const sigErr = 'İmza segmenti geçersiz Base64URL karakterleri içeriyor.';
    checks.push({
      id: 'signature-present',
      label: 'İmza Segmenti',
      status: 'fail',
      detail: sigErr,
    });
    errors.push(sigErr);
  } else {
    checks.push({
      id: 'signature-present',
      label: 'İmza Segmenti',
      status: 'pass',
      detail: `İmza segmenti mevcut (${signatureRaw.length} karakter Base64URL).`,
    });
  }

  const isValidStructure =
    errors.length === 0 && headerObj !== null && payloadDecoded.data !== null;

  return {
    isEmpty: false,
    tokenFormat: isValidStructure ? 'jws' : 'invalid',
    isValidStructure,
    bearerPrefixStripped,
    normalizedToken,
    segments,
    header: headerObj,
    payload: payloadDecoded.data,
    checks,
    errors,
  };
}

export function formatUnixTimestampLocal(unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  if (Number.isNaN(date.getTime())) {
    return 'Geçersiz tarih';
  }
  return new Intl.DateTimeFormat('tr-TR', {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(date);
}

/**
 * Formats an absolute duration in seconds into a readable Turkish countdown.
 */
export function formatDuration(totalSecondsInput: number): string {
  const absSeconds = Math.max(0, Math.floor(Math.abs(totalSecondsInput)));
  const days = Math.floor(absSeconds / 86400);
  const hours = Math.floor((absSeconds % 86400) / 3600);
  const minutes = Math.floor((absSeconds % 3600) / 60);
  const seconds = absSeconds % 60;

  const parts: string[] = [];
  if (days > 0) parts.push(`${days}g`);
  if (hours > 0 || days > 0) parts.push(`${String(hours).padStart(2, '0')}s`);
  if (minutes > 0 || hours > 0 || days > 0) {
    parts.push(`${String(minutes).padStart(2, '0')}d`);
  }
  parts.push(`${String(seconds).padStart(2, '0')}sn`);
  return parts.join(' ');
}

function readTimestampClaim(
  payload: Record<string, unknown>,
  key: 'exp' | 'nbf' | 'iat',
  invalidOut: string[],
): number | null {
  if (!(key in payload) || payload[key] === undefined || payload[key] === null) {
    return null;
  }
  const value = payload[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    invalidOut.push(key);
    return null;
  }
  return value;
}

export function analyzeTiming(
  payload: Record<string, unknown>,
  nowMs: number = Date.now(),
): TokenTimingAnalysis {
  const nowSec = nowMs / 1000;
  const invalidTimestampClaims: string[] = [];

  const expTimestamp = readTimestampClaim(payload, 'exp', invalidTimestampClaims);
  const nbfTimestamp = readTimestampClaim(payload, 'nbf', invalidTimestampClaims);
  const iatTimestamp = readTimestampClaim(payload, 'iat', invalidTimestampClaims);

  const remainingSeconds =
    expTimestamp !== null ? expTimestamp - nowSec : null;
  const nbfRemainingSeconds =
    nbfTimestamp !== null ? nbfTimestamp - nowSec : null;

  let status: TokenTimingStatus = 'no_expiration';
  if (nbfRemainingSeconds !== null && nbfRemainingSeconds > 0) {
    status = 'not_yet_valid';
  } else if (remainingSeconds !== null) {
    status = remainingSeconds <= 0 ? 'expired' : 'valid';
  }

  let lifespanProgressPercent: number | null = null;
  if (
    iatTimestamp !== null &&
    expTimestamp !== null &&
    expTimestamp > iatTimestamp
  ) {
    const total = expTimestamp - iatTimestamp;
    const elapsed = nowSec - iatTimestamp;
    const ratio = Math.min(1, Math.max(0, elapsed / total));
    lifespanProgressPercent = Math.round(ratio * 1000) / 10;
  }

  return {
    status,
    expTimestamp,
    nbfTimestamp,
    iatTimestamp,
    expIso:
      expTimestamp !== null
        ? new Date(expTimestamp * 1000).toISOString()
        : null,
    expLocal:
      expTimestamp !== null ? formatUnixTimestampLocal(expTimestamp) : null,
    nbfLocal:
      nbfTimestamp !== null ? formatUnixTimestampLocal(nbfTimestamp) : null,
    iatLocal:
      iatTimestamp !== null ? formatUnixTimestampLocal(iatTimestamp) : null,
    remainingSeconds,
    nbfRemainingSeconds,
    lifespanProgressPercent,
    invalidTimestampClaims,
  };
}

function stringifyClaimValue(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return JSON.stringify(value);
}

function formatClaimValue(key: string, value: unknown): string {
  const meta = CLAIM_DEFINITIONS[key];
  if (meta?.isTimestamp && typeof value === 'number' && Number.isFinite(value)) {
    return `${formatUnixTimestampLocal(value)} (${new Date(value * 1000).toISOString()})`;
  }
  if (Array.isArray(value)) {
    return value.map((item) => stringifyClaimValue(item)).join(', ');
  }
  if (typeof value === 'boolean') {
    return value ? 'Evet (true)' : 'Hayır (false)';
  }
  if (typeof value === 'object' && value !== null) {
    return JSON.stringify(value);
  }
  return stringifyClaimValue(value);
}

export function buildClaimRows(payload: Record<string, unknown>): ClaimRow[] {
  return Object.entries(payload).map(([key, value]) => {
    const meta = CLAIM_DEFINITIONS[key];
    return {
      key,
      title: meta?.title ?? 'Özel Claim',
      description:
        meta?.description ?? 'Uygulamaya özel (custom) payload claim alanı.',
      category: meta?.category ?? 'custom',
      rawValue: stringifyClaimValue(value),
      formattedValue: formatClaimValue(key, value),
      isStandard: Boolean(meta),
    };
  });
}
