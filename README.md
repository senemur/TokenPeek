# TokenPeek — İstemci Taraflı JWT İnceleme Aracı

Backend geliştiricilerin JWT (JSON Web Token) içeriklerini **hiçbir sunucuya veri göndermeden**, doğrudan tarayıcı içinde güvenli bir şekilde incelemesini ve doğrulamasını sağlayan geliştirici aracı.

## Özellikler

- **%100 Tarayıcı İçi İşlem (Zero Network):** Yapıştırılan token'lar, secret değerler ve public key'ler yalnızca tarayıcı belleğinde işlenir; harici bir API'ye gönderilmez ve `localStorage` / `sessionStorage` içinde saklanmaz.
- **Header & Payload Görüntüleme:** Renk kodlu JWT segment önizlemesi (`Header.Payload.Signature`) ve tek tıkla kopyalanabilir JSON görünümü.
- **JWE (5 Parçalı Şifreli Token) Tespiti:** 5 bölümden oluşan şifreli JWE token'ları algılar ve korumalı JWE Header alanını görüntüler.
- **Expiration & Canlı Geri Sayım:** `exp`, `iat` ve `nbf` zaman damgalarını yerel tarih + ISO-8601 formatında gösterir; sürenin dolmasına kalan (veya dolmasının üzerinden geçen) süreyi saniye bazında canlı hesaplar.
- **Claim Tablosu:** RFC 7519 ve yaygın OIDC/yetkilendirme claim'lerini açıklamaları, ham değerleri ve okunabilir biçimleriyle aranabilir tablo halinde sunar.
- **Format Doğrulama:** 3 parçalı JWS yapısı, katı Base64URL karakter kontrolü, UTF-8 JSON doğrulaması ve `alg` başlığı güvenlik kontrolleri.
- **Güvenli İmza & Policy Doğrulama (`jose` / Web Crypto API):**
  - Simetrik (`HS256`, `HS384`, `HS512`) ve Asimetrik (`RS256/384/512`, `PS256/384/512`, `ES256/384/512`, `EdDSA`) desteği
  - **JWKS (`{ "keys": [...] }`) Desteği:** Token header'daki `kid` değerine göre JWKS içinden otomatik anahtar seçimi
  - **Claim Policy Assertions:** İsteğe bağlı beklenen `iss` (Issuer) ve `aud` (Audience) doğrulaması
  - **Yerleşik Demo Üretici:** Tarayıcı belleğinde tek tıkla geçerli `HS256`, `RS256` (JWKS ile), süresi dolmuş ve bozuk imzalı test token'ları üretme
  - `alg="none"` reddi, Algorithm Pinning, private key engeli ve simetrik/asimetrik anahtar karışıklığı koruması

## Teknoloji Yığını

- **React 19** + **TypeScript** + **Vite**
- **jose** (Tarayıcı içi Web Crypto API tabanlı JWS doğrulama ve örnek token üretimi)
- **Vitest** + **Testing Library** + **ESLint**

## Kurulum ve Çalıştırma

```bash
npm install
npm run dev
```

### Lint, Test ve Derleme

```bash
npm run lint
npm test
npm run build
```

## GitHub Actions & GitHub Pages

- **CI ([ci.yml](.github/workflows/ci.yml)):** `main` dalına yapılan her push ve pull request üzerinde `npm run lint`, `npm test` ve `npm run build` adımlarını çalıştırır.
- **GitHub Pages ([pages.yml](.github/workflows/pages.yml)):** Repo ayarlarından **Settings → Pages → Source: GitHub Actions** seçildikten sonra **Actions → Deploy to GitHub Pages → Run workflow** ile canlı demo yayınlanabilir.

## Güvenlik Notu (Production Dağıtımı)

Uygulamayı statik olarak yayınlarken aşağıdaki HTTP Content-Security-Policy başlığını ekleyerek ağ çıkışını tamamen kilitleyebilirsiniz:

```text
Content-Security-Policy: default-src 'self'; connect-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
```

## Lisans

[MIT](LICENSE)
