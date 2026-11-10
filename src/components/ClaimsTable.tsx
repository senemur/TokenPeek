import { useMemo, useState } from 'react';
import { Search, Table2 } from 'lucide-react';
import { buildClaimRows } from '../lib/jwt';

interface ClaimsTableProps {
  payload: Record<string, unknown>;
}

const CATEGORY_LABELS = {
  standard: 'Standart',
  identity: 'Kimlik',
  authorization: 'Yetki',
  custom: 'Özel',
} as const;

export function ClaimsTable({ payload }: ClaimsTableProps) {
  const [query, setQuery] = useState('');
  const rows = useMemo(() => buildClaimRows(payload), [payload]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(
      (row) =>
        row.key.toLowerCase().includes(q) ||
        row.title.toLowerCase().includes(q) ||
        row.rawValue.toLowerCase().includes(q) ||
        row.formattedValue.toLowerCase().includes(q),
    );
  }, [query, rows]);

  return (
    <section className="card" aria-label="Payload Claim Tablosu">
      <div className="card-header" style={{ flexWrap: 'wrap' }}>
        <h2 className="card-title">
          <Table2 size={17} color="#c084fc" />
          Claim Tablosu ({rows.length})
        </h2>
        <div style={{ position: 'relative', minWidth: 220 }}>
          <Search
            size={14}
            color="#64748b"
            style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }}
          />
          <input
            type="search"
            className="field-input"
            style={{ paddingLeft: 30 }}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Claim veya değer ara..."
            aria-label="Claim tablosunda ara"
          />
        </div>
      </div>

      <div className="table-wrap">
        <table className="claims-table">
          <thead>
            <tr>
              <th>Claim</th>
              <th>Açıklama</th>
              <th>Ham Değer</th>
              <th>Okunabilir Değer</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={4} className="muted" style={{ textAlign: 'center', padding: 20 }}>
                  Eşleşen claim bulunamadı.
                </td>
              </tr>
            ) : (
              filtered.map((row) => (
                <tr key={row.key}>
                  <td>
                    <div className="claim-key">{row.key}</div>
                    <span className="muted" style={{ fontSize: '0.73rem' }}>
                      {CATEGORY_LABELS[row.category]}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontWeight: 500 }}>{row.title}</div>
                    <div className="muted" style={{ fontSize: '0.76rem' }}>
                      {row.description}
                    </div>
                  </td>
                  <td className="claim-raw">{row.rawValue}</td>
                  <td>{row.formattedValue}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
