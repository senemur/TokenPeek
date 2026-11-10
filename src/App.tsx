import { useEffect, useMemo, useState } from 'react';
import { Clock, FileSearch, Lock, ShieldCheck } from 'lucide-react';
import logoImg from './assets/tokenpeek-logo.png';
import { ClaimsTable } from './components/ClaimsTable';
import { ExpirationBanner } from './components/ExpirationBanner';
import { JsonPanel } from './components/JsonPanel';
import { SignatureVerifier } from './components/SignatureVerifier';
import { TokenInput } from './components/TokenInput';
import { inspectJwt } from './lib/jwt';
import { createAsymmetricSampleToken, createSampleTokens } from './lib/verify';

export function App() {
  const [rawToken, setRawToken] = useState('');
  const [secret, setSecret] = useState('');
  const [publicKeyInput, setPublicKeyInput] = useState('');

  useEffect(() => {
    let active = true;
    createSampleTokens().then((bundle) => {
      if (!active) return;
      setRawToken(bundle.validToken);
      setSecret(bundle.secret);
    });
    return () => {
      active = false;
    };
  }, []);

  const inspection = useMemo(() => inspectJwt(rawToken), [rawToken]);

  async function handleLoadSample(kind: 'valid' | 'expired' | 'tampered' | 'rs256') {
    if (kind === 'rs256') {
      const rsBundle = await createAsymmetricSampleToken();
      setSecret('');
      setPublicKeyInput(rsBundle.jwksJson);
      setRawToken(rsBundle.token);
      return;
    }

    const bundle = await createSampleTokens();
    setSecret(bundle.secret);
    setPublicKeyInput('');
    if (kind === 'valid') setRawToken(bundle.validToken);
    if (kind === 'expired') setRawToken(bundle.expiredToken);
    if (kind === 'tampered') setRawToken(bundle.tamperedToken);
  }

  function handleClear() {
    setRawToken('');
    setSecret('');
    setPublicKeyInput('');
  }

  const headerAlg =
    inspection.header && typeof inspection.header.alg === 'string'
      ? inspection.header.alg
      : null;
  const headerKid =
    inspection.header && typeof inspection.header.kid === 'string'
      ? inspection.header.kid
      : null;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <img
            src={logoImg}
            alt="TokenPeek Logo"
            className="brand-logo"
          />
          <div>
            <h1>TokenPeek</h1>
            <p>Tarayıcı içi JWT (JSON Web Token) inceleme ve güvenli imza doğrulama aracı</p>
          </div>
        </div>

        <div
          className="privacy-pill"
          title="Hiçbir token veya anahtar sunucuya gönderilmez, tarayıcı deposunda saklanmaz."
        >
          <Lock size={14} />
          %100 Tarayıcıda İşlenir — Sunucuya Veri Gönderilmez
        </div>
      </header>

      <section className="intro-card" aria-label="TokenPeek Ne İşe Yarar?">
        <div className="intro-header">
          <h2 className="card-title">TokenPeek Ne Yapar?</h2>
          <span className="badge badge-info">Backend & API Debug Aracı</span>
        </div>
        <p className="intro-summary">
          API isteklerinde kullandığınız JWT token&apos;ları harici bir sunucuya göndermeden kendi
          tarayıcınızda çözümleyip doğrulamanızı sağlar.
        </p>

        <div className="intro-steps">
          <div className="intro-step">
            <div className="intro-step-title">
              <FileSearch size={15} color="#38bdf8" />
              1. Yapıştır &amp; Çözümle
            </div>
            <p className="intro-step-desc">
              Header, Payload ve tüm Claim alanlarını okunabilir JSON ve aranabilir tablo halinde
              görüntüleyin; format hatalarını anında yakalayın.
            </p>
          </div>

          <div className="intro-step">
            <div className="intro-step-title">
              <Clock size={15} color="#c084fc" />
              2. Süre &amp; Geçerliliği İzle
            </div>
            <p className="intro-step-desc">
              Token&apos;ın ne zaman üretildiğini (<code>iat</code>), ne zaman süresinin dolacağını (
              <code>exp</code>) ve kalan zamanı canlı geri sayımla takip edin.
            </p>
          </div>

          <div className="intro-step">
            <div className="intro-step-title">
              <ShieldCheck size={15} color="#34d399" />
              3. İmzayı Güvenle Doğrula
            </div>
            <p className="intro-step-desc">
              Token&apos;ın yolda değiştirilmediğini doğrulamak için HMAC secret veya Public Key
              (PEM / JWKS) ile tarayıcı içinde kriptografik kontrol yapın.
            </p>
          </div>
        </div>
      </section>

      <main className="main-grid">
        <div className="stack">
          <TokenInput
            rawToken={rawToken}
            onChange={setRawToken}
            inspection={inspection}
            onLoadSample={handleLoadSample}
            onClear={handleClear}
          />

          {inspection.normalizedToken && inspection.tokenFormat === 'jws' && (
            <SignatureVerifier
              token={inspection.normalizedToken}
              headerAlg={headerAlg}
              headerKid={headerKid}
              payload={inspection.payload}
              secret={secret}
              onSecretChange={setSecret}
              publicKeyInput={publicKeyInput}
              onPublicKeyChange={setPublicKeyInput}
            />
          )}

          {inspection.tokenFormat === 'jwe' && (
            <section className="card" aria-label="JWE Bilgilendirmesi">
              <h2 className="card-title" style={{ marginBottom: 8 }}>
                <Lock size={17} color="#f59e0b" />
                JWE (Şifreli Token) Algılandı
              </h2>
              <p className="muted" style={{ margin: 0 }}>
                Bu token JWS yerine 5 bölümlü <strong>JWE</strong> formatındadır. İçerik şifreli
                olduğu için yalnızca JWE Header incelenebilir; imza doğrulaması ve payload çözümlemesi
                uygulanmaz.
              </p>
            </section>
          )}
        </div>

        <div className="stack">
          {inspection.isEmpty ? (
            <section className="card empty-state">
              <ShieldCheck size={34} color="#38bdf8" style={{ marginBottom: 10 }} />
              <h2 style={{ margin: '0 0 6px', fontSize: '1.05rem' }}>
                İncelemek için bir JWT token yapıştırın
              </h2>
              <p className="muted" style={{ maxWidth: 420, margin: '0 auto' }}>
                Token yalnızca tarayıcı belleğinde çözümlenir. <code>Bearer ...</code> önekiyle
                yapıştırılan Authorization header değerleri otomatik olarak temizlenir.
              </p>
            </section>
          ) : (
            <>
              {inspection.payload && <ExpirationBanner payload={inspection.payload} />}

              <div className="json-grid">
                {inspection.header && (
                  <JsonPanel
                    title="Header (JOSE)"
                    accentColor="var(--header-color)"
                    data={inspection.header}
                  />
                )}
                {inspection.payload && (
                  <JsonPanel
                    title="Payload (Claims)"
                    accentColor="var(--payload-color)"
                    data={inspection.payload}
                  />
                )}
              </div>

              {inspection.payload && <ClaimsTable payload={inspection.payload} />}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
