import { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Eye,
  EyeOff,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import {
  ASYMMETRIC_ALGORITHMS,
  DEMO_HMAC_SECRET,
  HMAC_ALGORITHMS,
  isAsymmetricAlgorithm,
  isHmacAlgorithm,
  verifyJwtSignature,
  type KeyMode,
  type SecretEncoding,
  type SupportedAlgorithm,
  type VerifySignatureResult,
} from '../lib/verify';

interface SignatureVerifierProps {
  token: string;
  headerAlg: string | null;
  secret: string;
  onSecretChange: (value: string) => void;
  publicKeyInput: string;
  onPublicKeyChange: (value: string) => void;
}

export function SignatureVerifier({
  token,
  headerAlg,
  secret,
  onSecretChange,
  publicKeyInput,
  onPublicKeyChange,
}: SignatureVerifierProps) {
  const [keyMode, setKeyMode] = useState<KeyMode>('hmac');
  const [expectedAlg, setExpectedAlg] = useState<SupportedAlgorithm | 'auto'>('auto');
  const [secretEncoding, setSecretEncoding] = useState<SecretEncoding>('utf8');
  const [showSecret, setShowSecret] = useState(false);
  const [result, setResult] = useState<VerifySignatureResult | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  // Sync suggested tab when a token with asymmetric/symmetric alg is pasted
  useEffect(() => {
    if (headerAlg && isAsymmetricAlgorithm(headerAlg)) {
      setKeyMode('publicKey');
    } else if (headerAlg && isHmacAlgorithm(headerAlg)) {
      setKeyMode('hmac');
    }
    setResult(null);
  }, [token, headerAlg]);

  const algorithmOptions =
    keyMode === 'hmac' ? HMAC_ALGORITHMS : ASYMMETRIC_ALGORITHMS;

  async function handleVerify() {
    if (!token) return;
    setIsVerifying(true);
    try {
      const res = await verifyJwtSignature({
        token,
        headerAlg,
        keyMode,
        expectedAlgorithm: expectedAlg,
        secret,
        secretEncoding,
        publicKeyInput,
      });
      setResult(res);
    } finally {
      setIsVerifying(false);
    }
  }

  return (
    <section className="card" aria-label="Güvenli İmza Doğrulama">
      <div className="card-header" style={{ flexWrap: 'wrap' }}>
        <h2 className="card-title">
          <ShieldCheck size={17} color="#34d399" />
          Güvenli İmza Doğrulama
        </h2>
        <div className="tab-group" role="tablist" aria-label="Anahtar Türü">
          <button
            type="button"
            role="tab"
            aria-selected={keyMode === 'hmac'}
            className={`tab-btn ${keyMode === 'hmac' ? 'active' : ''}`}
            onClick={() => {
              setKeyMode('hmac');
              setExpectedAlg('auto');
              setResult(null);
            }}
          >
            HMAC Secret (HS*)
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={keyMode === 'publicKey'}
            className={`tab-btn ${keyMode === 'publicKey' ? 'active' : ''}`}
            onClick={() => {
              setKeyMode('publicKey');
              setExpectedAlg('auto');
              setResult(null);
            }}
          >
            Public Key (RS*/ES*/EdDSA)
          </button>
        </div>
      </div>

      <div className="field-group">
        <label htmlFor="expected-alg" className="field-label">
          <span>Beklenen Algoritma (Algorithm Pinning)</span>
          <span className="muted" style={{ fontSize: '0.74rem' }}>
            Header alg: <strong>{headerAlg ?? 'Yok'}</strong>
          </span>
        </label>
        <select
          id="expected-alg"
          className="field-select"
          value={expectedAlg}
          onChange={(e) => {
            setExpectedAlg(e.target.value as SupportedAlgorithm | 'auto');
            setResult(null);
          }}
        >
          <option value="auto">
            Seçili moda göre header alg ile eşleştir (Güvenli izin listesi)
          </option>
          {algorithmOptions.map((alg) => (
            <option key={alg} value={alg}>
              Yalnızca {alg} kabul et (Strict Pinning)
            </option>
          ))}
        </select>
      </div>

      {keyMode === 'hmac' ? (
        <div className="field-group">
          <div className="field-label">
            <label htmlFor="hmac-secret">HMAC Secret Anahtarı</label>
            <div className="btn-row">
              <button
                type="button"
                className="btn"
                style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                onClick={() => onSecretChange(DEMO_HMAC_SECRET)}
              >
                Demo Secret Doldur
              </button>
              <button
                type="button"
                className="btn"
                style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                onClick={() =>
                  setSecretEncoding((prev) => (prev === 'utf8' ? 'base64' : 'utf8'))
                }
              >
                Format: {secretEncoding === 'utf8' ? 'UTF-8' : 'Base64 / Base64URL'}
              </button>
            </div>
          </div>

          <div className="input-with-action">
            <input
              id="hmac-secret"
              type={showSecret ? 'text' : 'password'}
              className="field-input mono"
              value={secret}
              onChange={(e) => {
                onSecretChange(e.target.value);
                setResult(null);
              }}
              placeholder="Secret key yalnızca tarayıcı belleğinde tutulur..."
              autoComplete="off"
              spellCheck={false}
            />
            <button
              type="button"
              className="btn"
              onClick={() => setShowSecret((prev) => !prev)}
              aria-label={showSecret ? 'Secret gizle' : 'Secret göster'}
            >
              {showSecret ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </div>
        </div>
      ) : (
        <div className="field-group">
          <label htmlFor="public-key" className="field-label">
            <span>Public Key (SPKI PEM veya JWK JSON)</span>
          </label>
          <textarea
            id="public-key"
            className="token-textarea mono"
            style={{ minHeight: 112 }}
            value={publicKeyInput}
            onChange={(e) => {
              onPublicKeyChange(e.target.value);
              setResult(null);
            }}
            placeholder={
              '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----\n\nveya {"kty":"RSA","n":"...","e":"AQAB"}'
            }
            spellCheck={false}
          />
        </div>
      )}

      <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 10 }}>
        <button
          type="button"
          className="btn btn-primary"
          onClick={handleVerify}
          disabled={!token || isVerifying}
        >
          <ShieldCheck size={15} />
          {isVerifying ? 'Doğrulanıyor...' : 'İmzayı Tarayıcıda Doğrula'}
        </button>
      </div>

      {result && (
        <div
          className={`verify-result ${
            result.status === 'valid'
              ? 'check-pass'
              : result.status === 'invalid'
                ? 'check-fail'
                : 'check-warn'
          }`}
          role="status"
        >
          {result.status === 'valid' && (
            <CheckCircle2 size={18} color="#22c55e" style={{ flexShrink: 0, marginTop: 2 }} />
          )}
          {result.status === 'invalid' && (
            <XCircle size={18} color="#ef4444" style={{ flexShrink: 0, marginTop: 2 }} />
          )}
          {result.status === 'error' && (
            <ShieldAlert size={18} color="#f59e0b" style={{ flexShrink: 0, marginTop: 2 }} />
          )}
          <div>
            <div style={{ fontWeight: 600 }}>{result.message}</div>
            {result.securityNote && (
              <div className="muted" style={{ marginTop: 4, fontSize: '0.78rem' }}>
                {result.securityNote}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="security-callout">
        <strong>Güvenlik Modeli:</strong> Doğrulama Web Crypto API (<code>jose</code>) ile tamamen
        tarayıcınızda çalışır. <code>alg="none"</code> reddedilir, private key girişi engellenir
        ve simetrik/asimetrik anahtar tipleri ayrı tutularak algoritma karışıklığı (algorithm
        confusion) saldırıları önlenir.
      </div>
    </section>
  );
}
