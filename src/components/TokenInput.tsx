import {
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  Sparkles,
  Trash2,
  XCircle,
} from 'lucide-react';
import type { JwtInspectionResult } from '../lib/jwt';

interface TokenInputProps {
  rawToken: string;
  onChange: (value: string) => void;
  inspection: JwtInspectionResult;
  onLoadSample: (kind: 'valid' | 'expired' | 'tampered') => void;
  onClear: () => void;
}

export function TokenInput({
  rawToken,
  onChange,
  inspection,
  onLoadSample,
  onClear,
}: TokenInputProps) {
  return (
    <section className="card" aria-label="JWT Girişi ve Format Doğrulama">
      <div className="card-header">
        <h2 className="card-title">
          <KeyRound size={17} color="#38bdf8" />
          Encoded JWT Token
        </h2>
        <div className="btn-row">
          <button
            type="button"
            className="btn"
            onClick={() => onLoadSample('valid')}
            title="Tarayıcı içinde geçerli örnek token üret"
          >
            <Sparkles size={14} />
            Örnek Geçerli
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => onLoadSample('expired')}
          >
            Süresi Dolmuş
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => onLoadSample('tampered')}
          >
            Bozuk İmza
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={onClear}
            disabled={!rawToken}
            title="Token ve anahtarları bellekten temizle"
          >
            <Trash2 size={14} />
            Temizle
          </button>
        </div>
      </div>

      <textarea
        id="jwt-input"
        className="token-textarea mono"
        value={rawToken}
        onChange={(e) => onChange(e.target.value)}
        placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0..."
        spellCheck={false}
        autoComplete="off"
        aria-label="JWT token yapıştırın"
      />

      {inspection.bearerPrefixStripped && (
        <div style={{ marginTop: 8 }}>
          <span className="badge badge-info">
            "Bearer " öneki otomatik olarak temizlendi
          </span>
        </div>
      )}

      {inspection.segments && (
        <>
          <div className="segment-preview" aria-label="Renklendirilmiş JWT bölümleri">
            <span className="seg-header">{inspection.segments.headerRaw}</span>
            <span className="seg-dot">.</span>
            <span className="seg-payload">{inspection.segments.payloadRaw}</span>
            <span className="seg-dot">.</span>
            <span className="seg-signature">
              {inspection.segments.signatureRaw || '(boş)'}
            </span>
          </div>
          <div className="legend-row">
            <span className="legend-item">
              <span className="dot" style={{ background: 'var(--header-color)' }} />
              Header
            </span>
            <span className="legend-item">
              <span className="dot" style={{ background: 'var(--payload-color)' }} />
              Payload
            </span>
            <span className="legend-item">
              <span className="dot" style={{ background: 'var(--signature-color)' }} />
              Signature
            </span>
          </div>
        </>
      )}

      {inspection.checks.length > 0 && (
        <div className="check-list" aria-label="Format doğrulama kontrolleri">
          {inspection.checks.map((check) => (
            <div key={check.id} className={`check-item check-${check.status}`}>
              {check.status === 'pass' && (
                <CheckCircle2 size={16} color="#22c55e" style={{ flexShrink: 0, marginTop: 2 }} />
              )}
              {check.status === 'warn' && (
                <AlertTriangle size={16} color="#f59e0b" style={{ flexShrink: 0, marginTop: 2 }} />
              )}
              {check.status === 'fail' && (
                <XCircle size={16} color="#ef4444" style={{ flexShrink: 0, marginTop: 2 }} />
              )}
              <div>
                <div className="check-title">{check.label}</div>
                <div className="check-detail">{check.detail}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
