# TokenPeek — İstemci Taraflı JWT İnceleme Aracı

Backend geliştiricilerin JWT (JSON Web Token) içeriklerini **hiçbir sunucuya veri göndermeden**, doğrudan tarayıcı içinde güvenli bir şekilde incelemesini ve doğrulamasını sağlayan geliştirici aracı.

## Özellikler

- **%100 Tarayıcı İçi İşlem (Zero Network):** Yapıştırılan token'lar, secret değerler ve public key'ler yalnızca tarayıcı belleğinde işlenir; harici bir API'ye gönderilmez ve `localStorage` / `sessionStorage` içinde saklanmaz.
- **Header & Payload Görüntüleme:** Renk kodlu JWT segment önizlemesi (`Header.Payload.Signature`) ve tek tıkla kopyalanabilir JSON görünümü.
- **Expiration & Canlı Geri Sayım:** `exp`, `iat` ve `nbf` zaman damgalarını yerel tarih + ISO-8601 formatında gösterir; sürenin dolmasına kalan (veya dolmasının üzerinden geçen) süreyi saniye bazında canlı hesaplar.
- **Claim Tablosu:** RFC 7519 ve yaygın OIDC/yetkilendirme claim'lerini açıklamaları, ham değerleri ve okunabilir biçimleriyle aranabilir tablo halinde sunar.
- **Format Doğrulama:** 3 parçalı JWS yapısı, katı Base64URL karakter kontrolü, UTF-8 JSON doğrulaması ve `alg` başlığı güvenlik kontrolleri.
- **Güvenli İmza Doğrulama (`jose` / Web Crypto API):**
  - Simetrik (`HS256`, `HS384`, `HS512`) ve Asimetrik (`RS256/384/512`, `PS256/384/512`, `ES256/384/512`, `EdDSA`) desteği
  - `alg="none"` reddi
  - Algorithm Pinning (beklenen algoritmayı sabitleme)
  - Simetrik secret ve asimetrik public key (SPKI PEM / JWK) ayrımı ile algoritma karışıklığı (algorithm confusion) koruması
  - Private key yapıştırılmasını engelleyen güvenlik uyarısı

## Teknoloji Yığını

- **React 19** + **TypeScript** + **Vite**
- **jose** (Tarayıcı içi Web Crypto API tabanlı JWS doğrulama ve örnek token üretimi)
- **Vitest** + **Testing Library**

## Kurulum ve Çalıştırma

```bash
npm install
npm run dev
```

### Test ve Derleme

```bash
npm test
npm run build
```

## Güvenlik Notu (Production Dağıtımı)

Uygulamayı statik olarak yayınlarken aşağıdaki HTTP Content-Security-Policy başlığını ekleyerek ağ çıkışını tamamen kilitleyebilirsiniz:

```text
Content-Security-Policy: default-src 'self'; connect-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
```

## Lisans

[MIT](LICENSE)
