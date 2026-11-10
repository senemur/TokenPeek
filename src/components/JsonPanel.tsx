import { useState } from 'react';
import { Check, Copy } from 'lucide-react';

interface JsonPanelProps {
  title: string;
  accentColor: string;
  data: Record<string, unknown>;
}

export function JsonPanel({ title, accentColor, data }: JsonPanelProps) {
  const [copied, setCopied] = useState(false);
  const formatted = JSON.stringify(data, null, 2);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(formatted);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard API may be unavailable in restricted contexts
    }
  }

  return (
    <section className="card">
      <div className="card-header">
        <h3 className="card-title">
          <span className="dot" style={{ background: accentColor, width: 10, height: 10 }} />
          {title}
        </h3>
        <button type="button" className="btn" onClick={handleCopy}>
          {copied ? <Check size={14} color="#22c55e" /> : <Copy size={14} />}
          {copied ? 'Kopyalandı' : 'JSON Kopyala'}
        </button>
      </div>
      <pre className="json-pre" style={{ color: accentColor }}>
        {formatted}
      </pre>
    </section>
  );
}
