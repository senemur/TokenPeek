import { useEffect, useState } from 'react';
import { Clock, AlertCircle, CheckCircle2, HelpCircle } from 'lucide-react';
import { analyzeTiming, formatDuration } from '../lib/jwt';

interface ExpirationBannerProps {
  payload: Record<string, unknown>;
}

export function ExpirationBanner({ payload }: ExpirationBannerProps) {
  const [nowMs, setNowMs] = useState(() => Date.now());

  useEffect(() => {
    const id = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);
    return () => window.clearInterval(id);
  }, []);

  const timing = analyzeTiming(payload, nowMs);

  const badgeConfig = {
    valid: { label: 'Süre Geçerli', className: 'badge-valid', Icon: CheckCircle2 },
    expired: { label: 'Süresi Dolmuş', className: 'badge-expired', Icon: AlertCircle },
    not_yet_valid: { label: 'Henüz Aktif Değil (nbf)', className: 'badge-warn', Icon: Clock },
    no_expiration: { label: 'Expiration (exp) Yok', className: 'badge-info', Icon: HelpCircle },
  }[timing.status];

  const StatusIcon = badgeConfig.Icon;

  let countdownText = 'exp claim tanımlı değil';
  let countdownColor = 'var(--text-secondary)';

  if (timing.status === 'not_yet_valid' && timing.nbfRemainingSeconds !== null) {
    countdownText = `${formatDuration(timing.nbfRemainingSeconds)} sonra aktifleşecek`;
    countdownColor = 'var(--warning)';
  } else if (timing.remainingSeconds !== null) {
    if (timing.remainingSeconds > 0) {
      countdownText = `${formatDuration(timing.remainingSeconds)} kaldı`;
      countdownColor =
        timing.remainingSeconds < 300 ? 'var(--warning)' : 'var(--signature-color)';
    } else {
      countdownText = `${formatDuration(Math.abs(timing.remainingSeconds))} önce doldu`;
      countdownColor = 'var(--danger)';
    }
  }

  return (
    <section className="card" aria-label="Token Süre ve Expiration Analizi">
      <div className="card-header">
        <h2 className="card-title">
          <Clock size={17} color="#34d399" />
          Expiration & Zaman Analizi
        </h2>
        <span className={`badge ${badgeConfig.className}`}>
          <StatusIcon size={13} />
          {badgeConfig.label}
        </span>
      </div>

      <div className="countdown-value" style={{ color: countdownColor }}>
        {countdownText}
      </div>

      {timing.invalidTimestampClaims.length > 0 && (
        <div className="check-item check-warn" style={{ marginBottom: 10 }}>
          <AlertCircle size={15} color="#f59e0b" />
          <div className="check-detail">
            Geçersiz sayısal zaman damgası formatı:{' '}
            <strong>{timing.invalidTimestampClaims.join(', ')}</strong> (Unix saniye beklenir).
          </div>
        </div>
      )}

      {timing.lifespanProgressPercent !== null && (
        <div>
          <div className="field-label">
            <span>Token Yaşam Döngüsü (iat → exp)</span>
            <span>%{timing.lifespanProgressPercent}</span>
          </div>
          <div className="progress-track">
            <div
              className="progress-fill"
              style={{
                width: `${timing.lifespanProgressPercent}%`,
                background:
                  timing.status === 'expired'
                    ? 'var(--danger)'
                    : 'linear-gradient(90deg, #38bdf8, #34d399)',
              }}
            />
          </div>
        </div>
      )}

      <div className="meta-grid">
        <div className="meta-box">
          <div className="meta-label">Expiration (exp)</div>
          <div className="meta-value">{timing.expLocal ?? 'Tanımlı değil'}</div>
          {timing.expIso && (
            <div className="muted" style={{ fontSize: '0.73rem', marginTop: 2 }}>
              {timing.expIso}
            </div>
          )}
        </div>
        <div className="meta-box">
          <div className="meta-label">Issued At (iat)</div>
          <div className="meta-value">{timing.iatLocal ?? 'Tanımlı değil'}</div>
        </div>
        <div className="meta-box">
          <div className="meta-label">Not Before (nbf)</div>
          <div className="meta-value">{timing.nbfLocal ?? 'Tanımlı değil'}</div>
        </div>
      </div>
    </section>
  );
}
