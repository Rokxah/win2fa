<p align="center">
  <img src="assets/icon.png" width="112" alt="Win2FA">
</p>

<h1 align="center">Win2FA</h1>

<p align="center">İki adımlı doğrulama (2FA) kodların, Windows'un sistem tepsisinde.</p>

<p align="center">
  <a href="https://github.com/Rokxah/win2fa/releases/latest"><b>⬇︎ Win2FA'yı indir</b></a>
  &nbsp;·&nbsp; Windows 10 (2004+) / 11 · x64 · Ücretsiz, açık kaynak
  &nbsp;·&nbsp; <a href="#english">English</a>
</p>

---

Telefonu cebinden çıkarıp doğru hesabı bulmak, kodu bakarak yazmak yok.
Saatin yanındaki kilide tıkla ya da **Ctrl+Alt+2**'ye bas, servisin adını yaz, **Enter**'a bas:
kod panoya kopyalanır, yapıştırırsın.

## Özellikler

- **Tepsiden tek tıkla kod.** Sık kullandıkların en üstte, gerisi alfabetik.
- **Anında arama.** Türkçe karakterlerle de çalışır ("gokhan" yazınca "Gökhan" bulunur).
- **Klavyeyle kullanım.** Her yerden Ctrl+Alt+2, ↑↓ ile seç, Enter ile kopyala, F2 ile düzenle.
- **Google Authenticator'dan aktarma.** Telefondaki "Hesapları dışa aktar" QR kodlarını kameraya göster. Birden çok QR varsa ilerlemeyi görürsün. Kamera yoksa QR'ın ekran görüntüsünü ya da fotoğrafını da yükleyebilirsin.
- **Ekrandaki QR'ı okuma.** Bir sitede 2FA kurarken ekrandaki QR kodu tek tıkla eklenir.
- **Ana şifre ve Windows Hello.** Panel her açılışta ana şifre ya da parmak izi / yüz tanıma / Windows PIN ister.
- **Pano koruması.** Kopyalanan kod Windows pano geçmişine ve bulut eşitlemeye alınmaz, 30 saniye sonra silinir.
- **İnternete bağlanmaz.** Hiçbir veri bilgisayarından çıkmaz.

## Kurulum

1. [Son sürüm sayfasından](https://github.com/Rokxah/win2fa/releases/latest) `Win2FA.exe` dosyasını indir.
2. İstediğin bir klasöre koy ve çalıştır. Kurulum ya da .NET gerekmez.
3. İlk açılışta bir ana şifre belirle. Tepsi menüsünden "Windows açılışında başlat"ı açabilirsin.

> Uygulama henüz kod imzalı değil. Windows SmartScreen "Windows bilgisayarınızı korudu" uyarısı gösterebilir:
> **Ek bilgi → Yine de çalıştır**. İstersen sürüm sayfasındaki SHA-256 değerini
> `Get-FileHash Win2FA.exe` çıktısıyla karşılaştırabilirsin.

## Güvenlik

Hesaplar `%APPDATA%\Win2FA\accounts.dat` dosyasında üç katmanla korunur:

1. **Ana şifre:** PBKDF2-SHA256 (600.000 tur) ile türetilen anahtarla **AES-256-GCM** şifreleme.
2. **Windows Hello (isteğe bağlı):** Kasa anahtarının bir kopyası, Hello'nun TPM'de duran anahtarıyla yapılan imzadan türetilen anahtarla şifrelenir. Parmak izi / yüz / PIN doğrulaması olmadan bu kopya açılmaz.
3. **Windows DPAPI:** Dosya ayrıca senin Windows kullanıcı hesabına bağlı olarak şifrelenir.

Panel her kapandığında, Windows kilitlendiğinde ve 5 dakika işlem yapılmadığında kasa kilitlenir, anahtarlar bellekten silinir.

⚠️ **Ana şifreni unutursan hesaplar Win2FA'da açılamaz.** Telefondaki Google Authenticator'ı silme, hesapların orada da dursun.

## Derleme

.NET 10 SDK gerekir.

```
cd src/Win2FA
dotnet publish -c Release -o ../../dist
```

Çekirdek testleri (RFC 6238 vektörleri, Google aktarma biçimi, şifreli depo): `cd tests/CoreTest && dotnet run`

---

<a id="english"></a>
## English

**Win2FA** puts your two-factor (TOTP) codes in the Windows system tray. Press **Ctrl+Alt+2**, type the service name and hit **Enter**: the code is copied to the clipboard (hidden from clipboard history, cleared after 30 s).

- Import from Google Authenticator by showing its export QR codes to your webcam, or from a screenshot.
- Read a 2FA QR code straight from the screen while setting up a new account.
- Vault encrypted with AES-256-GCM using a key derived from your master password (PBKDF2, 600k rounds), optionally unlockable with Windows Hello, wrapped in Windows DPAPI. Locks every time the panel closes.
- Works fully offline. The interface is in Turkish.

Download the latest `Win2FA.exe` from [Releases](https://github.com/Rokxah/win2fa/releases/latest). Windows 10 2004+ / 11, x64. No installer, no .NET runtime required.

## Lisans / License

MIT © 2026 GB Projects
