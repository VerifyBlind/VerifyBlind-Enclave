# VerifyBlind — Enclave

**Bu, VerifyBlind'in AWS Nitro Enclave'inin herkese açık kaynak kodudur.** Kimlik numaranız (TCKN) ve
biyometrik verileriniz yalnızca bu enclave'in *içinde* işlenir; ne işletim sistemi, ne sunucu yöneticisi,
ne de VerifyBlind ekibi içeriğini göremez. Enclave'in **ölçümü (PCR0)** her sürümde burada yayınlanır ve
AWS donanımı tarafından imzalanır.

**This is the public source code of VerifyBlind's AWS Nitro Enclave.** Your national ID number and
biometric data are processed *only inside* this enclave — not the host OS, not a server admin, not the
VerifyBlind team can see its contents. The enclave's **measurement (PCR0)** is published here on every
release and signed by AWS hardware.

🌐 [verifyblind.com](https://verifyblind.com) · 📦 [Releases](https://github.com/VerifyBlind/VerifyBlind-Enclave/releases) · 🤖 [Android](https://github.com/VerifyBlind/VerifyBlind-Android) · 🍎 [iOS](https://github.com/VerifyBlind/VerifyBlind-iOS)

**[🇹🇷 Türkçe](#türkçe) · [🇬🇧 English](#english)**

---

## Türkçe

### Bu repo nedir?

VerifyBlind **sıfır-bilgi (zero-knowledge)** bir kimlik doğrulama sistemidir. Hassas işlem (NFC kimlik
okuma, yüz eşleştirme, canlılık) bir **AWS Nitro Enclave** içinde yapılır — donanımla izole edilmiş,
disk/SSH/operatör erişimi olmayan bir hesaplama ortamı. Bu enclave'in çalıştırdığı kodun tam olarak ne
olduğu, kriptografik olarak **kanıtlanabilir** olmalıdır. Bu repo o kodu açık eder.

> Bu repo, özel geliştirme monorepo'sunun **salt-okunur kaynak aynasıdır**.

### PCR0 nedir?

PCR0, enclave imajının (EIF) içeriğinin kriptografik **özetidir** (parmak izi). Enclave her başladığında
AWS Nitro donanımı, çalışan imajın PCR0'ını ölçer ve AWS'nin kök sertifikasıyla imzalanmış bir
**attestation belgesi** üretir. Tek bir bit bile değişse PCR0 tamamen değişir.

Her [Release](https://github.com/VerifyBlind/VerifyBlind-Enclave/releases) şu dosyaları yayınlar:
`enclave.eif` (imaj), `pcr0.txt` (beklenen PCR0), `expected_pcr.json` (PCR0 + commit + nitro-cli sürümü)
ve `nitro_cli_version.txt`.

### Nasıl doğrulanır?

Güven iki bağımsız ayakta kapanır:

1. **Kaynak açık + build yeniden-üretilebilir.** [`.github/workflows/deploy-enclave.yml`](.github/workflows/deploy-enclave.yml)
   her sürümde imajı **iki kez** (cache kapalı) derler ve aynı PCR0'ı ürettiğini doğrular; yani bu
   commit'ten herkes aynı PCR0'a ulaşır. Bir denetçi, repo'yu bu commit'te klonlayıp aynı iş akışını
   (ya da kendi Nitro ortamında `nitro-cli build-enclave`) çalıştırarak release'teki `pcr0.txt` değerine
   ulaştığını teyit edebilir. Böylece "yayınlanan PCR0 gerçekten bu açık koddan geliyor" kanıtlanır.

2. **Canlı enclave kriptografik olarak zorlanır (otomatik).** Mobil uygulama her el sıkışmada (handshake)
   sunucudan AWS Nitro **attestation belgesini** alır, AWS kök sertifikasına kadar zinciri doğrular,
   içinden PCR0'ı çıkarır ve o PCR0 için sunulan **VerifyBlind geliştirici imzasını**, uygulamaya gömülü
   geliştirici genel anahtarıyla doğrular. İmzası olmayan bir PCR0 reddedilir. Yani sunucuda farklı/kurcalanmış
   bir enclave çalışsaydı uygulamanız bunu reddederdi — bu kontrolü sizin için uygulama yapar. Partnerler de
   aynı kontrolü yapabilir: doğrulama sonucuyla birlikte attestation belgesi ve PCR0 imzası gelir,
   geliştirici genel anahtarı `https://api.verifyblind.com/api/public/developer-key` adresindedir.

Kısacası: bu repo + release'teki PCR0, *yayınlanan kodun* parmak izini doğrulamanızı sağlar; AWS Nitro
attestation ise *canlı sunucunun* o parmak izini taşıdığını garanti eder.

### Bileşenler
- `Program.cs`, `Services/`, `Controllers/` — enclave uygulaması (handshake, register, login)
- `Models/` — ONNX ML modelleri (yüz hizalama, yüz embedding, pasif canlılık); Dockerfile'da SHA256 ile pinlenir
- `Certificates/` — NFC için CSCA + CRL sertifikaları; `Certificates/Escrow/` kurtarma açık anahtarı
- `Dockerfile.enclave` — deterministik imaj tarifi

### Kimlik sırrının kurtarma kopyası
`user_id`, `nsbd_id` ve `doc_id` kodlarını üreten sır AWS KMS ile sarılı durur ve yalnız bu enclave
açabilir. AWS hesabı kaybolursa kodların değişmemesi için `POST /api/Enclave/escrow/identity-secret`
ucu sırrı **yalnız** `Certificates/Escrow/identity-escrow-recipient.pem` dosyasındaki açık anahtara
(RSA-OAEP-SHA256) şifreleyip verir. Anahtar istekle gelmez, imajın içindedir; bu yüzden PCR0'ın
kapsamındadır ve sunucu onu değiştiremez. Özel yarısı yalnız kurucuda, çevrimdışıdır. Bilet imzalama
sırrının kopyası üretilmez.

---

## English

### What is this repo?

VerifyBlind is a **zero-knowledge** identity verification system. The sensitive processing (NFC ID
reading, face matching, liveness) runs inside an **AWS Nitro Enclave** — a hardware-isolated compute
environment with no disk, no SSH, no operator access. What code that enclave runs must be
cryptographically **provable**. This repo is that code, in the open.

> This repo is a **read-only source mirror** of the private development monorepo.

### What is PCR0?

PCR0 is a cryptographic **digest** (fingerprint) of the enclave image (EIF) contents. Every time the
enclave boots, AWS Nitro hardware measures the running image's PCR0 and produces an **attestation
document** signed by AWS's root certificate. Change a single bit and PCR0 changes completely.

Every [Release](https://github.com/VerifyBlind/VerifyBlind-Enclave/releases) publishes: `enclave.eif`
(the image), `pcr0.txt` (expected PCR0), `expected_pcr.json` (PCR0 + commit + nitro-cli version) and
`nitro_cli_version.txt`.

### How to verify

Trust closes through two independent legs:

1. **Source is public + build is reproducible.** [`.github/workflows/deploy-enclave.yml`](.github/workflows/deploy-enclave.yml)
   builds the image **twice** (cache disabled) on every release and verifies it produces the same PCR0 —
   i.e. anyone building from this commit gets the same PCR0. An auditor can clone the repo at that commit
   and re-run the same workflow (or `nitro-cli build-enclave` in their own Nitro environment) and confirm
   it reaches the release's `pcr0.txt`. That proves the published PCR0 really comes from this open source.

2. **The live enclave is cryptographically enforced (automatic).** On every handshake the mobile app
   fetches the AWS Nitro **attestation document** from the server, verifies the chain up to AWS's root
   certificate, extracts PCR0, and verifies the **VerifyBlind developer signature** supplied for that PCR0
   with the developer public key embedded in the app. A PCR0 without such a signature is rejected. So if a
   different/tampered enclave were running on the server, your app would refuse it — the app performs this
   check for you. Partners can run the same check: the attestation document and the PCR0 signature come with
   each verification result, and the developer public key is at
   `https://api.verifyblind.com/api/public/developer-key`.

In short: this repo + the release PCR0 let you verify the fingerprint of the *published code*; AWS Nitro
attestation guarantees the *live server* carries that fingerprint.

### Components
- `Program.cs`, `Services/`, `Controllers/` — the enclave application (handshake, register, login)
- `Models/` — ONNX ML models (face alignment, face embedding, passive liveness); pinned by SHA256 in the Dockerfile
- `Certificates/` — CSCA + CRL certificates for NFC; `Certificates/Escrow/` holds the recovery public key
- `Dockerfile.enclave` — the deterministic image recipe

### Recovery copy of the identity secret
The secret behind `user_id`, `nsbd_id` and `doc_id` is wrapped by AWS KMS and only this enclave can
unwrap it. So that the codes survive the loss of the AWS account, `POST /api/Enclave/escrow/identity-secret`
encrypts the secret **only** to the public key in `Certificates/Escrow/identity-escrow-recipient.pem`
(RSA-OAEP-SHA256). The key does not come with the request; it is part of the image, so it is covered by
PCR0 and the server cannot swap it. Only the founder holds the private half, offline. No copy of the
ticket signing secret is produced.
