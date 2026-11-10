import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import App from '../../App';

function toBase64Url(obj: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  let bin = '';
  for (const b of bytes) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

afterEach(() => {
  cleanup();
});

describe('App UI integration', () => {
  it('loads initial valid HS256 demo token and displays sections', async () => {
    render(<App />);

    expect(
      await screen.findByText('Süre Geçerli', {}, { timeout: 4000 }),
    ).toBeInTheDocument();
    expect(screen.getByText('Header (JOSE)')).toBeInTheDocument();
    expect(screen.getByText('Payload (Claims)')).toBeInTheDocument();
    expect(screen.getByText(/Claim Tablosu/)).toBeInTheDocument();
  });

  it('switches to expired and tampered tokens and verifies signature failure', async () => {
    render(<App />);
    await screen.findByText('Süre Geçerli');

    fireEvent.click(screen.getByRole('button', { name: 'Süresi Dolmuş' }));
    expect(await screen.findByText('Süresi Dolmuş', { selector: 'span.badge' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Bozuk İmza' }));
    await screen.findByText('Süre Geçerli', { selector: 'span.badge' });

    fireEvent.click(
      screen.getByRole('button', { name: /İmzayı Tarayıcıda Doğrula/i }),
    );
    expect(
      await screen.findByText(/İmza geçersiz/i),
    ).toBeInTheDocument();
  });

  it('generates RS256 sample with JWKS and verifies signature in browser', async () => {
    render(<App />);
    await screen.findByText('Süre Geçerli');

    fireEvent.click(screen.getByRole('button', { name: 'Örnek RS256' }));

    await waitFor(() => {
      expect(screen.getByText(/Header kid:/)).toBeInTheDocument();
    });

    fireEvent.click(
      screen.getByRole('button', { name: /İmzayı Tarayıcıda Doğrula/i }),
    );

    expect(
      await screen.findByText(/İmza kriptografik olarak doğrulandı \(RS256\)/),
    ).toBeInTheDocument();
    expect(screen.getByText(/JWKS üzerinden eşleşen anahtar/)).toBeInTheDocument();
  });

  it('strips Bearer prefix, filters claims table, and clears memory', async () => {
    render(<App />);
    await screen.findByText('Süre Geçerli');

    const tokenBox = screen.getByLabelText('JWT token yapıştırın');
    const customToken = `Bearer ${toBase64Url({ alg: 'HS256', typ: 'JWT' })}.${toBase64Url({
      sub: 'backend-user-77',
      custom_role: 'auditor',
    })}.abc123`;

    fireEvent.change(tokenBox, { target: { value: customToken } });
    expect(
      screen.getByText(/"Bearer " öneki otomatik olarak temizlendi/),
    ).toBeInTheDocument();

    const searchInput = screen.getByLabelText('Claim tablosunda ara');
    fireEvent.change(searchInput, { target: { value: 'custom_role' } });
    expect(screen.getAllByText('auditor').length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText('backend-user-77')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Temizle/i }));
    expect(
      screen.getByText('İncelemek için bir JWT token yapıştırın'),
    ).toBeInTheDocument();
  });
});
