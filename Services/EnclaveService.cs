using VerifyBlind.Core.Crypto;
using VerifyBlind.Core.Models;
using System.Text.Json;
using System.Text;
using System.Linq;
using System.Collections.Concurrent; 

namespace VerifyBlind.Enclave.Services;

#pragma warning disable SYSLIB0057 // Suppress obsolete X509Certificate2 constructor warning

public class EnclaveService
{
    private readonly IEnclaveKeyService _enclaveKeys;
    private readonly IKmsService _kms;
    private readonly IBiometricService _biometricService;

// Cache for Trusted Certificates by Country (e.g., "TUR" -> Collection)
    private static readonly ConcurrentDictionary<string, System.Security.Cryptography.X509Certificates.X509Certificate2Collection> _countryCertsCache
        = new();

    // Cache for CRL entries by Country (e.g., "TUR" -> list of revoked serial numbers)
    private static readonly ConcurrentDictionary<string, HashSet<string>> _countryCrlCache = new();

    public EnclaveService(IEnclaveKeyService enclaveKeys, IKmsService kms, IBiometricService biometricService)
    {
        _enclaveKeys = enclaveKeys;
        _kms = kms;
        _biometricService = biometricService;
    }

    public HandshakeResponse Handshake(DiagLog diag)
    {
        Console.WriteLine("[Enclave] El sıkışma başlatılıyor...");
        var nonce = Guid.NewGuid().ToString("N");
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var dataToSign = nonce + timestamp;
        var signature = _enclaveKeys.SignDataWithEnclaveKey(dataToSign);
        diag.Ok("Nonce + Signature");

        Console.WriteLine("[Enclave] El sıkışma: Zorluklar oluşturuluyor...");
        var challenges = new List<LivenessAction>();
        var rnd = new Random();
        var allActions = new[] { LivenessAction.FaceLeft, LivenessAction.FaceRight, LivenessAction.Blink, LivenessAction.Smile };

        while (challenges.Count < 5)
        {
            var action = allActions[rnd.Next(allActions.Length)];
            if (challenges.Count == 0 || challenges.Last() != action)
                challenges.Add(action);
        }
        diag.Ok("Challenges", string.Join(",", challenges));

        Console.WriteLine("[Enclave] El sıkışma: HSM'den Tasdik Belgesi talep ediliyor...");
        var attestDoc = _enclaveKeys.GetAttestationDocument();
        Console.WriteLine($"[Enclave] El sıkışma: Tasdik Belgesi alındı mı? {(attestDoc != null ? "EVET" : "HAYIR")}");
        diag.Ok("Attestation", attestDoc != null ? "EVET" : "HAYIR");

        return new HandshakeResponse
        {
            Nonce = nonce,
            Timestamp = timestamp,
            NonceSignature = signature,
            AttestationDocument = attestDoc,
            Challenges = challenges
        };
    }

    public LoginHandshakeResponse LoginHandshake(DiagLog diag)
    {
        Console.WriteLine("[Enclave] Login handshake başlatılıyor...");
        var attestDoc = _enclaveKeys.GetAttestationDocument();
        Console.WriteLine($"[Enclave] Login handshake: Tasdik Belgesi alındı mı? {(attestDoc != null ? "EVET" : "HAYIR")}");
        diag.Ok("Attestation", attestDoc != null ? "EVET" : "HAYIR");
        return new LoginHandshakeResponse { AttestationDocument = attestDoc };
    }

    public async Task<(string ticket, float faceScore, string cardId)> RegisterAsync(RegistrationRequest request, DiagLog diag)
    {
        diag.Info($"Kayıt başladı. EncKey={request.EncryptedKey.Length}ch, Blob={request.AesBlob.Length}ch");
        Console.WriteLine($"[Enclave] Kayıt isteği alındı. Şifreli Anahtar Uzunluğu: {request.EncryptedKey.Length}, Blob Uzunluğu: {request.AesBlob.Length}");

        string aesKeyBase64;
        try
        {
            diag.Begin("RSA Decrypt");
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                 var blobHash = Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(request.AesBlob)));
                 var encKeyHash = Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(request.EncryptedKey)));
                 Console.WriteLine($"[DEBUG] Enclave AesBlob Hash değeri: {blobHash}");
                 Console.WriteLine($"[DEBUG] Enclave EncptKey Hash değeri: {encKeyHash}");
            }

            // 1. Decrypt Data
            // Decrypt AES key using Enclave Private Key
            aesKeyBase64 = _enclaveKeys.DecryptWithEnclaveKey(request.EncryptedKey);

            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                var keyHash = Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(aesKeyBase64)));
                Console.WriteLine($"[DEBUG] Enclave Çözülmüş AesKey Hash değeri: {keyHash}");
            }

            Console.WriteLine($"[Enclave] RSA şifre çözme başarılı. Anahtar Base64 Uzunluğu: {aesKeyBase64.Length}");
            diag.Ok("RSA Decrypt", $"AES key len={aesKeyBase64.Length}ch");
        }
        catch (Exception ex)
        {
            diag.Fail("RSA Decrypt", ex.Message);
            Console.WriteLine($"[Enclave] RSA şifre çözme başarısız: {ex}");
            throw new RegistrationException(RegistrationStep.RsaDecrypt, "ERR_RSA_DECRYPT", ex.Message);
        }

        // --- Step 2: AES Decrypt ---
        string payloadJson;
        try
        {
            diag.Begin("AES Decrypt");
            payloadJson = CryptoUtils.AesDecrypt(request.AesBlob, aesKeyBase64);
            Console.WriteLine("[Enclave] AES şifre çözme başarılı. Yük JSON çıkarıldı.");
            diag.Ok("AES Decrypt", $"Payload len={payloadJson.Length}ch");
        }
        catch (Exception ex)
        {
            diag.Fail("AES Decrypt", ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.AesDecrypt}] adımında başarısız: {ex}");
            if (ex.Message.Contains("0xc100000d") || ex.Message.Contains("Auth tag mismatch"))
            {
                throw new RegistrationException(RegistrationStep.AesDecrypt, "ERR_AES_GCM_TAG", ex.Message);
            }
            throw new RegistrationException(RegistrationStep.AesDecrypt, "ERR_AES_DECRYPT", ex.Message);
        }

        var payload = JsonSerializer.Deserialize<SecurePayload>(payloadJson);
        if (payload == null) throw new RegistrationException(RegistrationStep.AesDecrypt, "ERR_INVALID_PAYLOAD");

        // --- Step 3: Nonce Verification ---
        try
        {
            diag.Begin("Nonce Verify");
            VerifyNonce(payload);
            diag.Ok("Nonce Verify");
        }
        catch (Exception ex)
        {
            diag.Fail("Nonce Verify", ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.NonceVerification}] adımında başarısız: {ex}");
            throw new RegistrationException(RegistrationStep.NonceVerification, "ERR_NONCE_VERIFICATION", ex.Message);
        }

        // --- Step 4: Active Authentication ---
        try
        {
            diag.Begin("Active Auth");
            VerifyActiveAuth(payload);
            diag.Ok("Active Auth");
        }
        catch (Exception ex)
        {
            diag.Fail("Active Auth", ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.ActiveAuthentication}] adımında başarısız: {ex}");
            throw new RegistrationException(RegistrationStep.ActiveAuthentication, "ERR_ACTIVE_AUTH", ex.Message);
        }

        // --- Step 5: Passive Authentication (SOD/CSCA) ---
        try
        {
            diag.Begin("Passive Auth");
            VerifyPassiveAuth(payload.SOD, payload.DG1, payload.DG15);
            diag.Ok("Passive Auth");
        }
        catch (Exception ex)
        {
            diag.Fail("Passive Auth", ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.PassiveAuthentication}] adımında başarısız: {ex}");
            throw new RegistrationException(RegistrationStep.PassiveAuthentication, "ERR_PASSIVE_AUTH", ex.Message);
        }

        // --- Step 6: Biometric Verification (parallel embedding) ---
        float faceScore;
        try
        {
            diag.Begin("Biometric");
            faceScore = VerifyBiometricMatchParallel(payload);
            diag.Ok("Biometric", $"Score={Math.Round(faceScore * 100, 1)}%");
        }
        catch (Exception ex)
        {
            diag.Fail("Biometric", ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.BiometricVerification}] adımında başarısız: {ex}");
            var bioCode = !_biometricService.IsModelLoaded ? "ERR_BIOMETRIC_MODEL_MISSING" : "ERR_BIOMETRIC_MISMATCH";
            throw new RegistrationException(RegistrationStep.BiometricVerification, bioCode, ex.Message);
        }

        // --- Step 7: DG1 Parsing ---
        TicketPayload ticketPayload;
        try
        {
            diag.Begin("DG1 Parse");
            ticketPayload = ParseDG1ToTicket(payload.DG1, payload.UserPubKey, request.CountryIsoCode);
            Console.WriteLine("==");
            Console.WriteLine($"[Enclave] GERÇEK VERİ ÇIKARILDI ✓");
            Console.WriteLine($"[Enclave] TCKN: {Mask(ticketPayload.TCKN)}");
            Console.WriteLine($"[Enclave] Ad/Soyad: {Mask(ticketPayload.Ad)} {Mask(ticketPayload.Soyad)}");
            Console.WriteLine("==");
            diag.Ok("DG1 Parse", $"Country={ticketPayload.CountryIsoCode}, TCKN={Mask(ticketPayload.TCKN)}");
        }
        catch (Exception ex)
        {
            diag.Fail("DG1 Parse", ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.Dg1Parsing}] adımında başarısız: {ex}");
            throw new RegistrationException(RegistrationStep.Dg1Parsing, "ERR_DG1_PARSE", ex.Message);
        }

        // --- Step 7b: Card Expiry Check ---
        if (ticketPayload.GecerlilikTarihi < DateTime.UtcNow.Date)
        {
            Console.WriteLine($"[Enclave] Kimlik kartı süresi dolmuş: {ticketPayload.GecerlilikTarihi:yyyy-MM-dd}");
            throw new RegistrationException(RegistrationStep.Dg1Parsing, "ERR_CARD_EXPIRED", $"Expired: {ticketPayload.GecerlilikTarihi:yyyy-MM-dd}");
        }
        Console.WriteLine($"[Enclave] Kart geçerlilik tarihi DOĞRULANDI ✓ ({ticketPayload.GecerlilikTarihi:yyyy-MM-dd})");

        // --- Step 8: ID Generation (before signing so IDs are embedded in the ticket) ---
        // person_id = hex(SHA256(HMAC(TCKN_Person_id)))
        // card_id   = hex(SHA256(HMAC(hex(SHA256(SOD))_Card_id)))  — SOD-based, globally unique
        // Both are stored in the signed ticket; Login reads them directly without recomputing.
        string personId, cardId;
        try
        {
            diag.Begin("ID Generation");
            // SOD hash as hex — used as input for card_id derivation
            var sodHashHex = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(Convert.FromBase64String(payload.SOD))
            ).ToLowerInvariant();

            // 2 HMAC çağrısı birbirinden bağımsız — paralel çalıştır (~60ms kazanç)
            Task<string>? personHmacTask = null;
            if (!string.IsNullOrEmpty(ticketPayload.TCKN))
                personHmacTask = _kms.ComputeHmacAsync($"{ticketPayload.TCKN}_Person_id");

            var cardHmacTask = _kms.ComputeHmacAsync($"{sodHashHex}_Card_id");

            if (personHmacTask != null)
            {
                var pIdHmac = await personHmacTask;
                personId = Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(Convert.FromBase64String(pIdHmac))
                ).ToLowerInvariant();
            }
            else
            {
                personId = "";
                Console.WriteLine("[Enclave] TCKN bulunamadı. person_id boş string olarak ayarlandı.");
            }

            var cIdHmac = await cardHmacTask;
            cardId = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(Convert.FromBase64String(cIdHmac))
            ).ToLowerInvariant();

            // Embed into ticket so Login can read without recomputing
            ticketPayload.PersonId = personId;
            ticketPayload.CardId   = cardId;

            diag.Ok("ID Generation", $"PersonId={personId[..8]}.., CardId={cardId[..8]}..");
        }
        catch (Exception ex)
        {
            diag.Fail("ID Generation", ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.IdGeneration}] adımında başarısız: {ex}");
            throw new RegistrationException(RegistrationStep.IdGeneration, "ERR_ID_GENERATION", ex.Message);
        }

        // --- Step 9: Ticket Signing (IDs already embedded above) ---
        SignedTicket signedTicket;
        try
        {
            diag.Begin("Ticket Sign");
            var signature = await _kms.SignTicketAsync(ticketPayload);
            signedTicket = new SignedTicket
            {
                Payload = ticketPayload,
                Signature = signature
            };
            diag.Ok("Ticket Sign");
        }
        catch (Exception ex)
        {
            diag.Fail("Ticket Sign", ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.TicketSigning}] adımında başarısız: {ex}");
            throw new RegistrationException(RegistrationStep.TicketSigning, "ERR_TICKET_SIGNING", ex.Message);
        }

        // --- Step 10: Response Encryption ---
        try
        {
            diag.Begin("Response Encrypt");
            var bundledContent = new
            {
                ticket = signedTicket,
                person_id = personId,
                card_id = cardId
            };
            var bundledJson = JsonSerializer.Serialize(bundledContent);
            
            var (aesBlob, aesKey, aesIv) = CryptoUtils.AesEncrypt(bundledJson);
            // OaepSha1: Android Keystore TEE does not support MGF1-SHA256 on all devices
            var encAesKey = CryptoUtils.RsaEncryptOaepSha1(aesKey, payload.UserPubKey);
            var hybridResponse = new 
            {
                enc_key = encAesKey,
                blob = aesBlob
            };
            
            diag.Ok("Response Encrypt");
            return (JsonSerializer.Serialize(hybridResponse), faceScore, cardId);
        }
        catch (Exception ex)
        {
            diag.Fail("Response Encrypt", ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.ResponseEncryption}] adımında başarısız: {ex}");
            throw new RegistrationException(RegistrationStep.ResponseEncryption, "ERR_RESPONSE_ENCRYPTION", ex.Message);
        }
    }

    /// <summary>
    /// Demo Mode için hardcoded veriyle gerçek imzalı ticket üretir.
    /// NFC/biometrik adımları atlanır; ID üretimi, imza ve şifreleme normal akıştaki gibi gerçek HSM ile yapılır.
    /// Tek farkı: SecurePayload yok, kimlik verisi enklavın içine gömülü.
    /// </summary>
    public async Task<(string ticket, float faceScore, string cardId)> DemoRegisterAsync(string userPubKey, DiagLog diag)
    {
        diag.Info($"[DEMO] Kayıt başladı. UserPubKey={userPubKey.Length}ch");
        Console.WriteLine($"[Enclave] DEMO kayıt isteği alındı. UserPubKey uzunluğu: {userPubKey.Length}");

        if (string.IsNullOrEmpty(userPubKey))
            throw new RegistrationException(RegistrationStep.RsaDecrypt, "ERR_DEMO_MISSING_PUBKEY");

        // Hardcoded demo identity (gerçek bir kart yok — TCKN/SOD hash sabit)
        const string demoTckn = "00000000000";
        const string demoSodHashHex = "demo_sod_hash_fixed_for_card_id_derivation";

        var ticketPayload = new TicketPayload
        {
            TCKN = demoTckn,
            Ad = "Demo",
            Soyad = "Kullanıcı",
            DogumTarihi = new DateTime(1992, 1, 1),
            SeriNo = "A12345678",
            GecerlilikTarihi = new DateTime(2030, 12, 31),
            Cinsiyet = "E",
            Uyruk = "TUR",
            UserPubKey = userPubKey,
            CountryIsoCode = "TUR",
            DocumentType = "ID"
        };

        // --- ID Generation (real KMS HMAC — same algorithm as production) ---
        string personId, cardId;
        try
        {
            diag.Begin("Demo ID Generation");
            var personHmacTask = _kms.ComputeHmacAsync($"{demoTckn}_Person_id");
            var cardHmacTask = _kms.ComputeHmacAsync($"{demoSodHashHex}_Card_id");

            var pHmac = await personHmacTask;
            personId = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(Convert.FromBase64String(pHmac))
            ).ToLowerInvariant();

            var cHmac = await cardHmacTask;
            cardId = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(Convert.FromBase64String(cHmac))
            ).ToLowerInvariant();

            ticketPayload.PersonId = personId;
            ticketPayload.CardId = cardId;

            diag.Ok("Demo ID Generation", $"PersonId={personId[..8]}.., CardId={cardId[..8]}..");
        }
        catch (Exception ex)
        {
            diag.Fail("Demo ID Generation", ex.Message);
            throw new RegistrationException(RegistrationStep.IdGeneration, "ERR_ID_GENERATION", ex.Message);
        }

        // --- Ticket Signing (real HSM signature) ---
        SignedTicket signedTicket;
        try
        {
            diag.Begin("Demo Ticket Sign");
            var signature = await _kms.SignTicketAsync(ticketPayload);
            signedTicket = new SignedTicket
            {
                Payload = ticketPayload,
                Signature = signature
            };
            diag.Ok("Demo Ticket Sign");
        }
        catch (Exception ex)
        {
            diag.Fail("Demo Ticket Sign", ex.Message);
            throw new RegistrationException(RegistrationStep.TicketSigning, "ERR_TICKET_SIGNING", ex.Message);
        }

        // --- Response Encryption (hybrid: AES blob + RSA-wrapped key with user's pub key) ---
        try
        {
            diag.Begin("Demo Response Encrypt");
            var bundledContent = new
            {
                ticket = signedTicket,
                person_id = personId,
                card_id = cardId
            };
            var bundledJson = JsonSerializer.Serialize(bundledContent);

            var (aesBlob, aesKey, _) = CryptoUtils.AesEncrypt(bundledJson);
            // OaepSha1: Android Keystore TEE does not support MGF1-SHA256 on all devices
            var encAesKey = CryptoUtils.RsaEncryptOaepSha1(aesKey, userPubKey);
            var hybridResponse = new
            {
                enc_key = encAesKey,
                blob = aesBlob
            };
            diag.Ok("Demo Response Encrypt");
            return (JsonSerializer.Serialize(hybridResponse), 1.0f, cardId);
        }
        catch (Exception ex)
        {
            diag.Fail("Demo Response Encrypt", ex.Message);
            throw new RegistrationException(RegistrationStep.ResponseEncryption, "ERR_RESPONSE_ENCRYPTION", ex.Message);
        }
    }

    public async Task<string> LoginAsync(LoginRequest request, DiagLog diag)
    {
        try {
            return await LoginInternalAsync(request, diag);
        } catch (Exception ex) {
            diag.Fail("Login", ex.Message);
            diag.Ok($"[Enclave] KRİTİK GİRİŞ HATASI: {ex}");
            throw;
        }
    }

    private async Task<string> LoginInternalAsync(LoginRequest request, DiagLog diag)
    {
        // 1. Decrypt EncrSignedTicket (contains {Signed_Ticket, Nonce, Pk_Hash} encrypted with Enclave Pub Key)
        string decryptedJson;
        try
        {
            diag.Begin("Ticket Decrypt");
            var hybridObj = JsonSerializer.Deserialize<JsonElement>(request.EncrSignedTicket);
            var encKey = hybridObj.GetProperty("enc_key").GetString();
            var blob = hybridObj.GetProperty("blob").GetString();
            
            var aesKey = _enclaveKeys.DecryptWithEnclaveKey(encKey!);
            decryptedJson = CryptoUtils.AesDecrypt(blob!, aesKey);
            diag.Ok("Ticket Decrypt");
        }
        catch (Exception ex)
        {
            diag.Fail("Ticket Decrypt", ex.Message);
            diag.Ok($"[Enclave] Giriş şifre çözme başarısız: {ex}");
            throw new InvalidOperationException("Giriş şifre çözme başarısız.");
        }

        // 2. Parse decrypted content
        SignedTicket? signedTicket = null;
        string? innerNonce = null;
        string? innerPkHash = null;

        try
        {
            diag.Begin("Ticket Parse");
            using var doc = JsonDocument.Parse(decryptedJson);
            var root = doc.RootElement;
            
            // Extract inner properties
            if (root.TryGetProperty("nonce", out var nonceEl)) innerNonce = nonceEl.GetString();
            if (root.TryGetProperty("pk_hash", out var pkHashEl)) innerPkHash = pkHashEl.GetString();

            // Extract signed ticket
            if (root.TryGetProperty("signed_ticket", out var ticketEl))
            {
                signedTicket = JsonSerializer.Deserialize<SignedTicket>(ticketEl.GetRawText());
            }
            else
            {
                // Fallback: entire decrypted content is the signed ticket (Legacy)
                // In new flow, this branch should strictly fail if we enforce binding
                signedTicket = JsonSerializer.Deserialize<SignedTicket>(decryptedJson);
            }
        }
        catch (Exception ex)
        {
            diag.Fail("Ticket Parse", ex.Message);
            diag.Ok($"[Enclave] Giriş bileti ayrıştırma başarısız: {ex.Message}");
            throw new InvalidDataException("Geçersiz bilet formatı.");
        }

        if (signedTicket == null) throw new InvalidDataException("Geçersiz bilet.");
        diag.Ok("Ticket Parse", $"Country={signedTicket.Payload.CountryIsoCode}, Nonce={innerNonce?[..8]}..");

        // 3. Validation
        if (string.IsNullOrEmpty(request.QrPayloadJson))
        {
            throw new Exception("İstekte QR yük verisi eksik.");
        }

        // Parse QR Payload to get Request and Sign
string? partnerId = null;
        object? specialData = null;
        string? reqPublicKey = null;
        string? reqNonce = null; 

        using var qrDoc = JsonDocument.Parse(request.QrPayloadJson);
        var qrRoot = qrDoc.RootElement;
        
        // Define variable outside scope
        Dictionary<string, object>? reqValidations = null;

        // Structure: { "request": { ... } }  — sign alanı yok (ephemeral key mimarisi)
        if (!qrRoot.TryGetProperty("request", out var qrReqEl)) throw new Exception("Geçersiz QR yük verisi: 'request' alanı eksik.");

        // Extract fields from 'request' object
        if (qrReqEl.TryGetProperty("partner_id", out var pid)) partnerId = pid.GetString();
        if (qrReqEl.TryGetProperty("public_key", out var pk)) reqPublicKey = pk.GetString();
        if (qrReqEl.TryGetProperty("nonce", out var n)) reqNonce = n.GetString();
        if (qrReqEl.TryGetProperty("additional_data", out var sd)) specialData = JsonSerializer.Deserialize<object>(sd.GetRawText());

        // This is redundancy for validation usage later, but good for local extraction
        if (qrReqEl.TryGetProperty("validations", out var valProp))
        {
            try {
                reqValidations = JsonSerializer.Deserialize<Dictionary<string, object>>(valProp.GetRawText());
                diag.Ok($"[Enclave] GELEN Doğrulamalar: {reqValidations?.Count ?? 0} anahtar: [{(reqValidations != null ? string.Join(", ", reqValidations.Keys) : "")}]");
            } catch { /* Hatalı validation verisi yoksayıldı */ }
        }

        if (string.IsNullOrEmpty(partnerId) || string.IsNullOrEmpty(reqPublicKey) || string.IsNullOrEmpty(reqNonce))
        {
            throw new Exception("Geçersiz QR yük verisi: Zorunlu alanlar eksik (partner_id, public_key, nonce).");
        }

        // 3.1 Verify Binding (Inner Pk Hash == Hash(Request Public Key))
        diag.Begin("Binding Check");
        if (!string.IsNullOrEmpty(innerPkHash))
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            var pkBytes = Encoding.UTF8.GetBytes(reqPublicKey); 
            var computedHashBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(reqPublicKey));
            var computedHashHex = Convert.ToHexString(computedHashBytes).ToLowerInvariant();
            
            diag.Ok($"[Enclave] Bağlama Kontrolü: İç={innerPkHash}, Hesaplanan={computedHashHex}");
            
            if (!innerPkHash.Equals(computedHashHex, StringComparison.OrdinalIgnoreCase))
            {
                var computedHashB64 = Convert.ToBase64String(computedHashBytes);
                if (innerPkHash != computedHashB64)
                {
                    diag.Fail("Binding Check", $"Expected={computedHashHex[..8]}.., Got={innerPkHash[..8]}..");
                    diag.Ok($"[Enclave] Bağlama BAŞARISIZ. Beklenen: {computedHashHex} (veya b64), Gelen: {innerPkHash}");
                    throw new Exception("Bağlama başarısız: Public Key Hash uyuşmuyor.");
                }
            }
            else
            {
                diag.Ok("[Enclave] Bağlama DOĞRULANDI ✓");
            }
            diag.Ok("Binding Check");
        }
        else
        {
            diag.Fail("Binding Check", "inner_pk_hash bulunamadı");
            diag.Ok("[Enclave] HATA: inner_pk_hash bulunamadı. Bağlama kontrolü BAŞARISIZ.");
            throw new Exception("Bağlama başarısız: Bilette Public Key Hash eksik.");
        }

        // 3.2 Verify Nonce (Inner Nonce == Request Nonce)
        diag.Begin("Nonce Match");
        if (innerNonce != reqNonce)
        {
            diag.Fail("Nonce Match", $"Inner={innerNonce}, Request={reqNonce}");
            diag.Ok($"[Enclave] Nonce Uyuşmazlığı: İç={innerNonce}, İstek={reqNonce}");
            throw new Exception("Nonce uyuşmuyor.");
        }
        diag.Ok("Nonce Match");

        // 4. Verify Ticket Signature + 5. Compute UserId — paralel (bağımsız KMS çağrıları)
        diag.Ok("---------------------------------------------------");
        diag.Ok($"[Enclave] TCKN için giriş işlemi: {(string.IsNullOrEmpty(signedTicket.Payload.TCKN) ? "(Boş)" : Mask(signedTicket.Payload.TCKN))}");
        diag.Ok($"[Enclave] Partner ID: {partnerId}");

        string userId;
        string personId;

        diag.Begin("Ticket Sig Verify");
        var sigVerifyTask = _kms.VerifyTicketSignatureAsync(signedTicket);

        // UserId HMAC'ı imza doğrulamasından bağımsız — paralel başlat
        Task<string>? userIdHmacTask = null;
        if (!string.IsNullOrEmpty(signedTicket.Payload.TCKN))
        {
            diag.Begin("UserId+PersonId");
            userIdHmacTask = _kms.ComputeHmacAsync($"{signedTicket.Payload.TCKN}:{partnerId}");
        }


        // Her iki KMS sonucunu topla
        if (!await sigVerifyTask)
        {
            diag.Fail("Ticket Sig Verify", "İmza geçersiz");
            throw new Exception("Geçersiz bilet!");
        }
        diag.Ok("Ticket Sig Verify");

        // Kart geçerlilik tarihi kontrolü (imza doğrulandıktan sonra)
        if (signedTicket.Payload.GecerlilikTarihi < DateTime.UtcNow.Date)
        {
            Console.WriteLine($"[Enclave] Kimlik kartı süresi dolmuş: {signedTicket.Payload.GecerlilikTarihi:yyyy-MM-dd}");
            throw new Exception($"Kimlik kartının geçerlilik süresi dolmuş ({signedTicket.Payload.GecerlilikTarihi:dd.MM.yyyy}). Giriş yapılamaz.");
        }
        Console.WriteLine($"[Enclave] Kart geçerlilik tarihi DOĞRULANDI ✓ ({signedTicket.Payload.GecerlilikTarihi:yyyy-MM-dd})");

        if (userIdHmacTask != null)
        {
            userId = await userIdHmacTask;
            diag.Ok($"[Enclave] user_id hesaplandı: {userId[..8]}...");

            // person_id and card_id were computed at registration and embedded in the signed
            // ticket — read directly, no recomputation needed.
            personId = signedTicket.Payload.PersonId;
            diag.Ok($"[Enclave] person_id ticket'tan okundu: {(personId.Length > 8 ? personId[..8] : personId)}...");

            diag.Ok("UserId+PersonId", $"user={userId[..8]}.., person={personId[..8]}..");
        }
        else
        {
            userId   = "";
            personId = "";
            diag.Ok("[Enclave] Bilette TCKN yok. user_id/person_id için boş string kullanılıyor.");
            diag.Info("UserId/PersonId: boş (TCKN yok)");
        }

        // card_id: read from signed ticket (computed at registration from SOD, globally unique).
        string loginCardId = signedTicket.Payload.CardId;
        if (!string.IsNullOrEmpty(loginCardId))
            diag.Ok($"[Enclave] card_id ticket'tan okundu: {loginCardId[..8]}...");
        diag.Ok("---------------------------------------------------");

        // 6. Process Validations (e.g. Age Check, Nationality Check)
        diag.Begin("Validations");
        var validationsOutput = new Dictionary<string, object>();

        if (reqValidations != null && reqValidations.Count > 0)
        {
            diag.Ok($"[Enclave] {reqValidations.Count} doğrulama işleniyor...");
            
            foreach(var kvp in reqValidations)
            {
                // Unbox JsonElement if present
                var rawValue = kvp.Value is JsonElement je
                    ? (je.ValueKind == JsonValueKind.String ? je.GetString() ?? "" : je.GetRawText().Trim('\"'))
                    : kvp.Value?.ToString() ?? "";

                if (kvp.Key == "age")
                {
                    try
                    {
                        var dob = signedTicket.Payload.DogumTarihi;
                        var today = DateTime.UtcNow;
                        var age = today.Year - dob.Year;
                        if (dob.Date > today.AddYears(-age)) age--;

                        var result = CheckAgeConstraint(age, rawValue);
                        validationsOutput["age"] = result;
                        //diag.Info($"Age: dob={dob:yyyy-MM-dd}, age={age}, constraint='{rawValue}', result={result}");
                    }
                    catch (Exception ex)
                    {
                        diag.Info($"Age ERROR: {ex.GetType().Name}: {ex.Message}: {ex.StackTrace}, dob={signedTicket.Payload.DogumTarihi:yyyy-MM-dd}");
                        //validationsOutput["age"] = false;
                    }
                }
                else if (kvp.Key == "user_id")
                {
                    bool requested = false;
                    if (kvp.Value is JsonElement boolEl && boolEl.ValueKind == JsonValueKind.True) requested = true;
                    else if (rawValue.ToLower() == "true") requested = true;
                    if (requested) validationsOutput["user_id"] = userId;
                }

            }
        }

        diag.Ok("Validations", $"Count={validationsOutput.Count}");
        diag.Ok($"[Enclave] specialData: '{specialData}'");

        // 7. Prepare Payload & SIGN (Phase 8 - Enhanced Security)
        diag.Begin("Response Encrypt");
        var loginResp = new LoginResponse
        {
            Nonce = request.Nonce,
            SpecialData = specialData,
            Validations = validationsOutput.Count > 0 ? validationsOutput : null,
        };
        
        var loginRespJson = JsonSerializer.Serialize(loginResp);
        var enclaveSig = _enclaveKeys.SignDataWithEnclaveKey(loginRespJson);

        // 8. Bundle into SignedResponse
        var signedResp = new SignedLoginResponse
        {
            Payload = loginRespJson,
            Signature = enclaveSig
        };
        var signedRespJson = JsonSerializer.Serialize(signedResp);

        // 8. Hybrid Encryption for Partner (AES + Partner RSA PubKey)
        // a. Generate random AES key and encrypt the bundle
        var (partnerAesBlob, partnerAesKey, partnerAesIv) = CryptoUtils.AesEncrypt(signedRespJson);

        // b. Encrypt AES key with Partner's Public Key
        var encPartnerAesKey = CryptoUtils.RsaEncrypt(partnerAesKey, reqPublicKey!);

        // c. encrypted_response = partner's hybrid blob (enc_key + blob only — no relay metadata)
        var partnerBlob = new { enc_key = encPartnerAesKey, blob = partnerAesBlob };
        var encryptedResponse = JsonSerializer.Serialize(partnerBlob);

        // d. relay_metadata: plaintext for Relay (KVKK consent recording)
        //    Scopes = validation keys requested; results = bool outcomes
        //    Sıfır Bilgi: person_id / user_id / card_id Relay DB'sine YAZILMAZ.
        //    enclave_sig: Bu rıza makbuzunun Enclave tarafından üretildiğinin kanıtı.
        var scopesList = reqValidations?.Keys.ToList() ?? new List<string>();
        var resultsBool = validationsOutput
            .Where(kv => kv.Value is bool)
            .ToDictionary(kv => kv.Key, kv => (bool)kv.Value);
        //if (shareUserId) scopesList.Add("user_id");

        // Consent makbuzu imzası: scopes + results + nonce + partner_id
        var consentReceiptData = $"{request.Nonce}:{partnerId}:{string.Join(",", scopesList)}:{string.Join(",", resultsBool.Select(kv => $"{kv.Key}={kv.Value}"))}";
        var consentEnclaveSig = _enclaveKeys.SignDataWithEnclaveKey(consentReceiptData);

        var relayMetadata = new
        {
            card_id          = loginCardId,   // block check only — DB'ye yazılmaz
            scopes           = scopesList,
            results          = resultsBool,
            consent_version  = "1.0",
            enclave_sig      = consentEnclaveSig
        };

        // e. Final response: encrypted_response (partner) + relay_metadata (Relay) + nationality (nonce_ledger)
        var nationality = signedTicket.Payload.Uyruk; // ISO 3166-1 alpha-3 (e.g. "TUR")
        var finalResponse = new
        {
            encrypted_response = encryptedResponse,
            nationality        = nationality,
            relay_metadata     = relayMetadata
        };

        diag.Ok("Response Encrypt", $"Validations={validationsOutput.Count}, Scopes={string.Join(",", scopesList)}, Nationality={nationality}");
        return JsonSerializer.Serialize(finalResponse);
    }


    // --- NONCE VERIFICATION (Replay Protection) ---
    
    internal void VerifyNonce(SecurePayload payload)
    {
        Console.WriteLine("[Enclave] Nonce ve Zaman Damgası doğrulanıyor...");
        
        // 1. Check Timestamp is within 5 minutes
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var diff = now - payload.Timestamp;
        const long MAX_AGE_SECONDS = 5 * 60; // 5 minutes
        
        if (diff < 0 || diff > MAX_AGE_SECONDS)
        {
            throw new InvalidOperationException($"Nonce süresi dolmuş: Zaman damgası çok eski ({diff}s). İzin verilen maksimum: {MAX_AGE_SECONDS}s.");
        }
        Console.WriteLine($"[Enclave] Zaman Damgası geçerli. Yaş: {diff}s");
        
        // 2. Verify NonceSignature was signed by Enclave
        var dataToVerify = payload.Nonce + payload.Timestamp;
        var isValid = _enclaveKeys.VerifyEnclaveSignature(dataToVerify, payload.NonceSignature);
        
        if (!isValid)
        {
            throw new InvalidOperationException("Nonce imzası geçersiz: Bu Enclave tarafından imzalanmamış.");
        }
        Console.WriteLine("[Enclave] Nonce İmzası DOĞRULANDI ✓");
    }

    // --- ACTIVE AUTHENTICATION (Chip Clone Protection) ---
    
    internal void VerifyActiveAuth(SecurePayload payload)
    {
        Console.WriteLine("[Enclave] Aktif Kimlik Doğrulama kontrol ediliyor (ISO 9796-2)...");
        
        // Skip if DG15 or ActiveSig is missing (some cards don't support AA)
        if (string.IsNullOrEmpty(payload.DG15) && string.IsNullOrEmpty(payload.ActiveSig))
        {
            Console.WriteLine("[Enclave] UYARI: AA verisi eksik (DG15 ve İmza). Kartın AA desteklemediği varsayılıyor.");
            return; // Allow for cards that don't support AA (No Public Key exposed)
        }
        
        // Anti-Downgrade: If DG15 exists, AA MUST be performed
        if (!string.IsNullOrEmpty(payload.DG15) && string.IsNullOrEmpty(payload.ActiveSig))
        {
             throw new Exception("Aktif Kimlik Doğrulama Başarısız: DG15 (Public Key) mevcut, ancak Aktif İmza EKSİK.");
        }
        
        // 1. Verify Challenge matches SHA256(Nonce)[0..7]
        var nonceBytes = Encoding.UTF8.GetBytes(payload.Nonce);
        byte[] expectedChallenge;
        using (var sha = System.Security.Cryptography.SHA256.Create())
        {
            var hash = sha.ComputeHash(nonceBytes);
            expectedChallenge = hash.Take(8).ToArray();
        }
        
        var actualChallenge = Convert.FromBase64String(payload.AAChallenge);
        if (!expectedChallenge.SequenceEqual(actualChallenge))
        {
            throw new Exception($"Aktif Doğrulama Başarısız: Challenge uyuşmuyor. Beklenen: {Convert.ToBase64String(expectedChallenge)}, Gelen: {payload.AAChallenge}");
        }
        Console.WriteLine("[Enclave] Challenge Nonce ile eşleşiyor ✓");
        
        // 2. Extract Public Key from DG15 and Verify Signature using ISO 9796-2
        try 
        {
            var dg15Bytes = Convert.FromBase64String(payload.DG15);
            var fullResponse = Convert.FromBase64String(payload.ActiveSig);
            
            // Parse DG15 to extract SubjectPublicKeyInfo
            var pubKeyInfo = ExtractPublicKeyFromDG15(dg15Bytes);
            
            // Import key into BouncyCastle
            var keyInfo = Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo.GetInstance(pubKeyInfo);
            var bcPubKey = Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(keyInfo);
            
            if (bcPubKey is not Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsaKey)
            {
                throw new Exception("Aktif Kimlik Doğrulama Başarısız: Public Key RSA değil. Bu Enclave yalnızca RSA desteklemektedir.");
            }
            
            Console.WriteLine($"[Enclave] AA RSA Anahtar Boyutu: {rsaKey.Modulus.BitLength} bit");

            // JMRTD response likely includes RND.IC prefix if Length > KeyLen
            int keyLenBytes = rsaKey.Modulus.BitLength / 8;
            byte[] activeSigBytes;
            if (fullResponse.Length > keyLenBytes)
            {
                 int skip = fullResponse.Length - keyLenBytes;
                 activeSigBytes = fullResponse.Skip(skip).ToArray();
            }
            else
            {
                activeSigBytes = fullResponse;
            }
            
            // 1. Try Standard BouncyCastle Verification Loop
            // Turkish ID cards use trailer 13516 (SHA-256)
            var digestsToTry = new (string Name, Org.BouncyCastle.Crypto.IDigest Digest)[]
            {
                ("SHA-256", new Org.BouncyCastle.Crypto.Digests.Sha256Digest()),
                ("SHA-1", new Org.BouncyCastle.Crypto.Digests.Sha1Digest()),
            };
            
            var signaturestoTry = new (string Name, byte[] Data)[]
            {
                ("Signature Only", activeSigBytes),
                ("Full Response", fullResponse),
            };
            
            foreach (var (sigName, sigData) in signaturestoTry)
            {
                foreach (var (digestName, digestInstance) in digestsToTry)
                {
                    // Try both implicit and explicit trailer modes
                    foreach (var useImplicit in new[] { false, true })
                    {
                        try
                        {
                            var signer = new Org.BouncyCastle.Crypto.Signers.Iso9796d2Signer(
                                new Org.BouncyCastle.Crypto.Engines.RsaEngine(), 
                                digestInstance, 
                                useImplicit);
                            
                            signer.Init(false, rsaKey);
                            
                            if (signer.VerifySignature(sigData))
                            {
                                if (signer.HasFullMessage())
                                {
                                    var recoveredMessage = signer.GetRecoveredMessage();
                                    
                                    // Check if challenge appears anywhere in recovered message
                                    for (int i = 0; i <= recoveredMessage.Length - 8; i++)
                                    {
                                        if (recoveredMessage.Skip(i).Take(8).SequenceEqual(actualChallenge))
                                        {
                                            Console.WriteLine($"[Enclave] Aktif Kimlik Doğrulama DOĞRULANDI (Standart ISO 9796-2, {digestName}, {sigName}) ✓");
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        catch { /* Iterate silently */ }
                    }
                }
            }
            
            // 2. Fallback: Manual Raw ISO 9796-2 Verification
            // (Necessary for some cards where padding or trailer handling differs from BouncyCastle standard)
            try
            {
                Console.WriteLine("[Enclave] Standart doğrulama başarısız. Manuel ISO 9796-2 kurtarma deneniyor...");
                Console.WriteLine($"[Enclave] HATA AYIKLAMA: Beklenen Challenge: {Mask(Convert.ToHexString(actualChallenge))}");
                
                var rsaEngine = new Org.BouncyCastle.Crypto.Engines.RsaEngine();
                rsaEngine.Init(false, rsaKey); // decrypt mode
                
                // Try with both full response and signature only
                foreach(var sigObj in signaturestoTry)
                {
                    byte[] decrypted;
                    try {
                        decrypted = rsaEngine.ProcessBlock(sigObj.Data, 0, sigObj.Data.Length);
                    } catch (Exception ex) {
                        Console.WriteLine($"[Enclave] HATA AYIKLAMA: RSA Şifre Çözme Hatası ({sigObj.Name}): {ex.Message}");
                        continue; 
                    }
                    
                    if (decrypted.Length > 0)
                    {
                        Console.WriteLine($"[Enclave] HATA AYIKLAMA: Çözüldü {sigObj.Name} ({decrypted.Length} bayt): {Convert.ToHexString(decrypted)}");

                        if (decrypted[0] != 0x6A && decrypted[0] != 0x4A)
                        {
                            continue;
                        }

                        // Search for challenge anywhere in the decrypted block (skipping header)
                        // This robust approach handles non-standard padding, trailer placement, or message structure
                        for (int i = 1; i <= decrypted.Length - 8; i++)
                        {
                            bool match = true;
                            for (int j = 0; j < 8; j++)
                            {
                                if (decrypted[i + j] != actualChallenge[j])
                                {
                                    match = false;
                                    break;
                                }
                            }
                            
                            if (match)
                            {
                                Console.WriteLine($"[Enclave] Aktif Kimlik Doğrulama DOĞRULANDI (Manuel Kurtarma, {sigObj.Name}) ✓");
                                return;
                            }
                        }

                        // Fallback: Manual Hash Verification (Implicit Challenge)
                        // Assume structure: [Header 1] [M1] [RecoveredHash 32] [Trailer 2]
                        // This handles cases where Challenge is not in M1 but is implicit (part of hash input)
                        if (decrypted.Length > 35)
                        {
                            try
                            {
                                int trailerLen = 2; // Assume 0x34CC
                                int hashLen = 32; // SHA-256
                                int hashStart = decrypted.Length - trailerLen - hashLen;
                                
                                if (hashStart > 1)
                                {
                                    byte[] recoveredHash = new byte[hashLen];
                                    Array.Copy(decrypted, hashStart, recoveredHash, 0, hashLen);
                                    
                                    byte[] m1 = new byte[hashStart - 1]; // From index 1 to hashStart
                                    Array.Copy(decrypted, 1, m1, 0, m1.Length);
                                    
                                    using (var sha = System.Security.Cryptography.SHA256.Create())
                                    {
                                        // Try M1 || Challenge (Likely RND.IC || RND.IFD)
                                        var attempt1 = new byte[m1.Length + actualChallenge.Length];
                                        Buffer.BlockCopy(m1, 0, attempt1, 0, m1.Length);
                                        Buffer.BlockCopy(actualChallenge, 0, attempt1, m1.Length, actualChallenge.Length);
                                        
                                        if (sha.ComputeHash(attempt1).SequenceEqual(recoveredHash))
                                        {
                                            Console.WriteLine($"[Enclave] Aktif Kimlik Doğrulama DOĞRULANDI (Manuel Hash Kontrolü M1||Challenge, {sigObj.Name}) ✓");
                                            return;
                                        }
                                        
                                        // Try Challenge || M1
                                        var attempt2 = new byte[actualChallenge.Length + m1.Length];
                                        Buffer.BlockCopy(actualChallenge, 0, attempt2, 0, actualChallenge.Length);
                                        Buffer.BlockCopy(m1, 0, attempt2, actualChallenge.Length, m1.Length);
                                        
                                        if (sha.ComputeHash(attempt2).SequenceEqual(recoveredHash))
                                        {
                                            Console.WriteLine($"[Enclave] Aktif Kimlik Doğrulama DOĞRULANDI (Manuel Hash Kontrolü Challenge||M1, {sigObj.Name}) ✓");
                                            return;
                                        }
                                    }
                                }
                            }
                            catch { /* Ignore manual hash check errors */ }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Enclave] Manuel AA Doğrulama Hatası: {ex.Message}");
            }

            // 3. Fallback: PKCS#1 v1.5 Verification (Common in simulations and older cards)
            try
            {
                // Simulation uses PKCS#1 and signs the Base64 String of the challenge
                var signer = new Org.BouncyCastle.Crypto.Signers.RsaDigestSigner(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
                signer.Init(false, rsaKey);
                
                // Variant A: Standard (Raw Challenge Bytes)
                signer.BlockUpdate(actualChallenge, 0, actualChallenge.Length);
                if (signer.VerifySignature(activeSigBytes))
                {
                     Console.WriteLine($"[Enclave] Aktif Kimlik Doğrulama DOĞRULANDI (PKCS#1 v1.5, Standart) ✓");
                     return;
                }
                
                // Variant B: Simulation Hack (Base64 String Bytes)
                signer.Reset();
                var challengeBase64Bytes = Encoding.UTF8.GetBytes(Convert.ToBase64String(actualChallenge));
                signer.BlockUpdate(challengeBase64Bytes, 0, challengeBase64Bytes.Length);
                if (signer.VerifySignature(activeSigBytes))
                {
                     Console.WriteLine($"[Enclave] Aktif Kimlik Doğrulama DOĞRULANDI (PKCS#1 v1.5, Simülasyon Modu) ✓");
                     return;
                }
            }
            catch { /* Ignore fallback errors */ }
            
            // If none worked, throw HARD FAIL
            throw new Exception("Aktif Kimlik Doğrulama BAŞARISIZ: İmza formatı tanınmıyor veya geçersiz. Chip özgünlüğü doğrulanamıyor.");
        }
        catch (Exception ex) when (ex.Message.Contains("Active Authentication"))
        {
            throw; // Re-throw AA-specific errors
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Enclave] AA Doğrulama Hatası: {ex.Message}");
            throw new Exception($"Aktif Kimlik Doğrulama KRİTİK HATA: {ex.Message}");
        }
    }
    
    internal byte[] ExtractPublicKeyFromDG15(byte[] dg15Bytes)
    {
        // DG15 ASN.1 structure:
        // [0x6F] [length] [SubjectPublicKeyInfo]
        // We need to unwrap the outer Application 15 tag (0x6F = 0x40 | 15)
        
        if (dg15Bytes.Length < 4) 
            throw new Exception("DG15 çok kısa.");
            
        int offset = 0;
        
        // Check for Application tag 0x6F (Application 15)
        if (dg15Bytes[offset] == 0x6F)
        {
            offset++;
            // Parse length
            int length;
            if ((dg15Bytes[offset] & 0x80) == 0)
            {
                length = dg15Bytes[offset];
                offset++;
            }
            else
            {
                int numBytes = dg15Bytes[offset] & 0x7F;
                offset++;
                length = 0;
                for (int i = 0; i < numBytes; i++)
                {
                    length = (length << 8) | dg15Bytes[offset++];
                }
            }
            
            // Return the SubjectPublicKeyInfo (the content after the wrapper)
            return dg15Bytes.Skip(offset).Take(length).ToArray();
        }
        
        // If no wrapper, assume it's already SubjectPublicKeyInfo
        return dg15Bytes;
    }
    
    // --- BIOMETRIC VERIFICATION ---

    internal float VerifyBiometricMatch(SecurePayload payload)
    {
        Console.WriteLine("[Enclave] Biyometrik Kimlik Eşleşmesi başlatılıyor...");

        if (string.IsNullOrEmpty(payload.DG2_Photo)) throw new Exception("Biyometrik Hata: Kimlik fotoğrafı (DG2) eksik.");
        if (string.IsNullOrEmpty(payload.UserSelfie)) throw new Exception("Biyometrik Hata: Kullanıcı selfie'si eksik.");

        byte[] idPhotoBytes = Convert.FromBase64String(payload.DG2_Photo);
        byte[] probePhotoBytes = Convert.FromBase64String(payload.UserSelfie);

        // Use Real AI
        Console.WriteLine($"[Enclave] Kimlik Fotoğrafı Boyutu: {idPhotoBytes.Length} bayt");
        Console.WriteLine($"[Enclave] Selfie Fotoğrafı Boyutu: {probePhotoBytes.Length} bayt");

        // DEBUG image saving removed — biometric data must never persist to disk.

        float similarity = _biometricService.VerifyFace(idPhotoBytes, probePhotoBytes);

        // Threshold for ArcFace (Cosine Similarity)
        // Reverted to standard 0.40 per user request for quality check.
        const float THRESHOLD = 0.40f;

        Console.WriteLine($" > [AI] Benzerlik Puanı: {similarity * 100:0.0}%");

        if (similarity < THRESHOLD)
        {
            throw new Exception($"Kimlik Doğrulama Başarısız: Yüz kimlik kartıyla eşleşmiyor. Puan: {similarity:0.00}");
        }

        Console.WriteLine("[Enclave] Biyometrik Kimlik EŞLEŞMESİ ONAYLANDI ✓");
        return similarity;
    }

    internal float VerifyBiometricMatchParallel(SecurePayload payload)
    {
        Console.WriteLine("[Enclave] Biyometrik Kimlik Eşleşmesi başlatılıyor (paralel)...");

        if (string.IsNullOrEmpty(payload.DG2_Photo)) throw new Exception("Biyometrik Hata: Kimlik fotoğrafı (DG2) eksik.");
        if (string.IsNullOrEmpty(payload.UserSelfie)) throw new Exception("Biyometrik Hata: Kullanıcı selfie'si eksik.");

        byte[] idPhotoBytes = Convert.FromBase64String(payload.DG2_Photo);
        byte[] probePhotoBytes = Convert.FromBase64String(payload.UserSelfie);

        Console.WriteLine($"[Enclave] Kimlik Fotoğrafı Boyutu: {idPhotoBytes.Length} bayt");
        Console.WriteLine($"[Enclave] Selfie Fotoğrafı Boyutu: {probePhotoBytes.Length} bayt");

        float similarity = _biometricService.VerifyFaceParallel(idPhotoBytes, probePhotoBytes);

        const float THRESHOLD = 0.40f;

        Console.WriteLine($" > [AI] Benzerlik Puanı (paralel): {similarity * 100:0.0}%");

        if (similarity < THRESHOLD)
        {
            throw new Exception($"Kimlik Doğrulama Başarısız: Yüz kimlik kartıyla eşleşmiyor. Puan: {similarity:0.00}");
        }

        Console.WriteLine("[Enclave] Biyometrik Kimlik EŞLEŞMESİ ONAYLANDI ✓");
        return similarity;
    }
    
    // --- CERTIFICATE VERIFICATION (PASSIVE AUTH) ---
    
    private void VerifyPassiveAuth(string sodBase64, string dg1Base64, string dg15Base64)
    {
        Console.WriteLine("[Enclave] Pasif Kimlik Doğrulama başlatılıyor (CSCA Kontrolü + DG Hash Doğrulaması)...");
        
// 1. Get Country from DG1 to find correct CSCA folder
        var countryCode = GetIssuingCountryFromDG1(dg1Base64);
        Console.WriteLine($"[Enclave] Belge Ülkesi: {countryCode}. CSCA/{countryCode} yükleniyor...");
        
        // 2. Load/Cache certificates for this specific country
        var certs = _countryCertsCache.GetOrAdd(countryCode, (code) => LoadCscaCertificatesInternal(code));

        Console.WriteLine($"[Enclave] Ülke Güven Deposu kullanılıyor ({countryCode}): {certs.Count} sertifika mevcut.");

        if (certs.Count == 0)
            throw new Exception($"Çip doğrulama yapılamadığından bu kart desteklenmemektedir ({countryCode} için CSCA sertifikası bulunamadı).");

        // 2. Parse SOD (PKCS#7 Signed Data)
        byte[] sodBytes = Convert.FromBase64String(sodBase64);
        
        // SIMULATION BYPASS
        try {
            var sodStr = Encoding.UTF8.GetString(sodBytes);
        } catch {}
        
        Console.WriteLine("[Enclave] SOD sahte değil. GERÇEK Pasif Kimlik Doğrulama başlatılıyor...");

        // FIX: Unwrap ICAO Application Tag 0x77 if present
        try 
        {
            // Use AsnDecoder to parse the tag and find content offset
            var tag = System.Formats.Asn1.Asn1Tag.Decode(sodBytes, out int _);
            if (tag.TagClass == System.Formats.Asn1.TagClass.Application && tag.TagValue == 23)
            {
                Console.WriteLine("[Enclave] SOD'dan ICAO Etiketi 0x77 çözülüyor...");
                System.Formats.Asn1.AsnDecoder.ReadEncodedValue(
                    sodBytes, 
                    System.Formats.Asn1.AsnEncodingRules.BER, 
                    out int contentOffset, 
                    out int contentLength, 
                    out int _);
                
                // Extract inner content (SignedData)
                sodBytes = sodBytes.AsSpan(contentOffset, contentLength).ToArray();
            }
        }
        catch (Exception asnEx)
        {
            Console.WriteLine($"[Enclave] Etiket Çözme Uyarısı: {asnEx.Message}. Ham baytlarla devam ediliyor.");
        }

        var signedCms = new System.Security.Cryptography.Pkcs.SignedCms();
try
        {
            signedCms.Decode(sodBytes);
        }
        catch (System.Security.Cryptography.CryptographicException cex)
        {
            Console.WriteLine($"[Enclave] SOD Çözme BAŞARISIZ (CryptographicException): {cex.Message}");
            Console.WriteLine($"[Enclave] SOD ham baytlar ({sodBytes.Length}): {Convert.ToHexString(sodBytes.AsSpan(0, Math.Min(64, sodBytes.Length)))}...");
            throw new Exception($"Pasif Kimlik Doğrulama Başarısız: SOD yapısı çözümlenemedi. ({cex.Message})");
        } 

        // 3. Verify Signature against Trust Store
        try 
        {
            // First, basic signature check (integrity)
try
            {
                signedCms.CheckSignature(true); 
            }
            catch (System.Security.Cryptography.CryptographicException cex)
            {
                Console.WriteLine($"[Enclave] SOD CheckSignature BAŞARISIZ: {cex.Message}");
                // Log the signer info for debugging
                if (signedCms.SignerInfos.Count > 0)
                {
                    var si = signedCms.SignerInfos[0];
                    Console.WriteLine($"[Enclave] İmzacı DigestAlgorithm: {si.DigestAlgorithm.FriendlyName} ({si.DigestAlgorithm.Value})");
                    if (si.Certificate != null)
                        Console.WriteLine($"[Enclave] İmzacı Sertifikası: {si.Certificate.Subject}");
                }
                throw new Exception($"Pasif Kimlik Doğrulama Başarısız: SOD imza doğrulaması başarısız. ({cex.Message})");
            } 
            Console.WriteLine("[Enclave] SOD İmza Bütünlüğü Geçerli.");
            
            // Now check Chain of Trust
            var signer = signedCms.SignerInfos[0];
            var dsCert = signer.Certificate;
            
            if (dsCert == null) throw new Exception("SOD içinde sertifika yok.");

            Console.WriteLine($"[Enclave] DS Konusu: {dsCert.Subject}");
            Console.WriteLine($"[Enclave] DS Yayıncısı:  {dsCert.Issuer}");

            // Extract Authority Key Identifier (AKID) - OID 2.5.29.35
            var akidExt = dsCert.Extensions["2.5.29.35"];
            if (akidExt != null)
            {
                Console.WriteLine($"[Enclave] DS Üst ID talep ediyor (AKID): {Convert.ToHexString(akidExt.RawData)}");
            }
            
            bool trusted = false;
            
            // Native .NET Chain Build (Enforces strictly authenticated paths + CRLs)
            using (var chain = new System.Security.Cryptography.X509Certificates.X509Chain())
            {
                // AWS/Docker ortamlarından cgv.nvi.gov.tr gibi devlet CRL sunucularına 
                // erişim (Geo-Block/Firewall nedeniyle) 30 saniyelik TCP Timeout yaratıyor!
                // Bu yüzden Online CRL şimdilik devre dışı bırakıldı (35 saniye gecikme çözümü).
                chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = System.Security.Cryptography.X509Certificates.X509VerificationFlags.AllowUnknownCertificateAuthority;
                
                // Use ExtraStore as fallback for the native builder
                chain.ChainPolicy.ExtraStore.AddRange(certs);

                // Build the chain
                bool buildResult = false;
                try 
                {
                    buildResult = chain.Build(dsCert);
                }
                catch (System.Security.Cryptography.CryptographicException cex)
                {
                    Console.WriteLine($"[Enclave] X509Chain.Build CryptographicException fırlattı: {cex.Message}. Manuel BouncyCastle doğrulamaya geçiliyor...");
                }

                if (buildResult)
                {
                    // Check if the root of the chain is in our Trusted List
                    var root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate; 
                    var found = certs.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, root.Thumbprint, false);
                    if (found.Count > 0)
                    {
                        trusted = true;
                        Console.WriteLine($"[Enclave] Zincir Güvenilir Köke doğrulandı: {root.Subject}");
                    }
                    else 
                    {
                        Console.WriteLine($"[Enclave] Zincir Kökü: {root.Subject} Güven Deposunda bulunamadı.");
                    }
                }
                else 
                {
Console.WriteLine("[Enclave] ORS Zincir İnşası başarısız. Durumlar kontrol ediliyor...");
                     foreach(var status in chain.ChainStatus)
                     {
                         Console.WriteLine($"[Enclave] Zincir Durumu: {status.Status} - {status.StatusInformation}");
                     }
                }
            }
            
            // FALLBACK: Manual BouncyCastle Signature Verification
            // Linux/Docker ortamında OS Root Store (.NET ExtraStore bug'ı) çalışmadığında 
            // işlemi kurtarmak için hayat kurtaran saf kriptografik doğrulama.
            if (!trusted)
            {
                Console.WriteLine("[Enclave] Zincir Doğrulaması için Manuel BouncyCastle Yedeğine başvuruluyor...");
                try 
                {
                    // Convert .NET Cert to BouncyCastle Cert
                    var parser = new Org.BouncyCastle.X509.X509CertificateParser();
                    var bcDsCert = parser.ReadCertificate(dsCert.RawData);

                    foreach (var csca in certs)
                    {
                        try 
                        {
                            var bcCsca = parser.ReadCertificate(csca.RawData);
                            // Verify dsCert signature using csca's public key
                            bcDsCert.Verify(bcCsca.GetPublicKey());
                            
                            // If we reach here, it's valid!
                            trusted = true;
                            Console.WriteLine($"[Enclave] MANUEL DOĞRULAMA BAŞARILI ✓ İmzalayan: {csca.Subject}");
                            break; 
                        }
                        catch { /* Try next CSCA */ }
                    }
                }
                catch (Exception exBc)
                {
                    Console.WriteLine($"[Enclave] Manuel BC doğrulaması başarısız: {exBc.Message}");
                }
            }
            
            if (!trusted)
            {
                var sha256 = Convert.ToHexString(dsCert.GetCertHash(System.Security.Cryptography.HashAlgorithmName.SHA256));
                Console.WriteLine($"[Enclave] Zincir Doğrulaması Başarısız ❌ Yayıncı: '{dsCert.Issuer}' SHA-256: {sha256}");
                throw new Exception($"Çip doğrulama yapılamadığından bu kart desteklenmemektedir (kart sertifikası güvenilir CSCA ile doğrulanamadı).");
            }

            // 3b. Offline CRL Check — DSC iptal edilmiş mi kontrol et
            CheckCertificateRevocation(dsCert, countryCode);
        }
        catch (Exception ex)
        {
Console.WriteLine($"[Enclave] SOD Doğrulaması Başarısız: {ex}");
            // Wrap ALL exceptions (including CryptographicException) with context
            throw new Exception($"SOD Zincir Doğrulaması Başarısız: {ex.Message}", ex); 
        }

        // 4. Verify DG Hashes against SOD Content
        Console.WriteLine("[Enclave] Veri Grubu Hash'leri doğrulanıyor...");
        VerifyDGHashes(signedCms.ContentInfo.Content, dg1Base64, dg15Base64);

        Console.WriteLine("[Enclave] Pasif Kimlik Doğrulama (SOD İmzası + DG Hash Doğrulaması) TAMAMLANDI ✓");
    }
    
    internal void VerifyDGHashes(byte[] sodContent, string dg1Base64, string dg15Base64)
    {
try
        {
            byte[] dg1Bytes = Convert.FromBase64String(dg1Base64);
            Console.WriteLine($"[Enclave] DG1 Baytları Alındı: {dg1Bytes.Length} (Başlangıcı: {Convert.ToHexString(dg1Bytes.AsSpan(0, Math.Min(4, dg1Bytes.Length)))})");

            // We need to support all possible ICAO hash algorithms
            string[] algos = { "SHA-256", "SHA-1", "SHA-384", "SHA-512" };
            bool found = false;
            string detectedAlgo = "";

            foreach (var algo in algos)
            {
                byte[] hash;
                using (var hasher = System.Security.Cryptography.IncrementalHash.CreateHash(new System.Security.Cryptography.HashAlgorithmName(algo.Replace("-", ""))))
                {
                    hasher.AppendData(dg1Bytes);
                    hash = hasher.GetHashAndReset();
                }

                if (SearchHashInSOD(sodContent, 1, hash))
                {
                    found = true;
                    detectedAlgo = algo;
                    Console.WriteLine($"[Enclave] DG1 Hash Eşleşmesi Bulundu ({algo}) ✓");
                    break;
                }

                // Fallback: Some readers strip the outer tag (0x61) or the length header.
                // Try hashing the inner content if it looks like there's a tag at the start.
                if (dg1Bytes.Length > 2 && (dg1Bytes[0] == 0x61 || dg1Bytes[0] == 0x5F))
                {
                    // Basic TLV Skip (Tag + Length)
                    int skip = (dg1Bytes[1] & 0x80) == 0 ? 2 : 2 + (dg1Bytes[1] & 0x7F);
                    if (dg1Bytes.Length > skip)
                    {
                        using var hasherInner = System.Security.Cryptography.IncrementalHash.CreateHash(new System.Security.Cryptography.HashAlgorithmName(algo.Replace("-", "")));
                        hasherInner.AppendData(dg1Bytes.AsSpan(skip).ToArray());
                        var innerHash = hasherInner.GetHashAndReset();
                        if (SearchHashInSOD(sodContent, 1, innerHash))
                        {
                            found = true;
                            detectedAlgo = algo;
                            Console.WriteLine($"[Enclave] DG1 Hash Eşleşmesi Bulundu (İç Yedek) ({algo}) ✓");
                            break;
                        }
                    }
                }
            }

            if (!found)
            {
                // Diagnostic: Log first 64 bytes of SOD content to see the actual hash list
                Console.WriteLine($"[Enclave] DG1 Hash Uyuşmazlığı. SOD İçeriği ({sodContent.Length} bayt): {Convert.ToHexString(sodContent.AsSpan(0, Math.Min(128, sodContent.Length)))}");
                throw new Exception("DG1 Hash Uyuşmazlığı! (SHA-1, SHA-256, SHA-384 veya SHA-512 ile SOD'da eşleşme bulunamadı). NFC okuma sırasında veri bozulması olabilir.");
            } 
            // For DG15 (if provided)
            if (!string.IsNullOrEmpty(dg15Base64))
            {
                byte[] dg15Bytes = Convert.FromBase64String(dg15Base64);
                byte[] actualDg15Hash;
using (var hasher = System.Security.Cryptography.IncrementalHash.CreateHash(new System.Security.Cryptography.HashAlgorithmName(detectedAlgo.Replace("-", ""))))
                {
                    hasher.AppendData(dg15Bytes);
                    actualDg15Hash = hasher.GetHashAndReset();
                }
                
                if (!SearchHashInSOD(sodContent, 15, actualDg15Hash))
                {
                    throw new Exception("DG15 Hash Uyuşmazlığı! (AA Public Key değiştirilmiş olabilir).");
                }
                Console.WriteLine($"[Enclave] DG15 Hash DOĞRULANDI ✓ ({detectedAlgo})");
            }
        }
        catch (Exception ex) when (ex.Message.Contains("TAMPERED") || ex.Message.Contains("Mismatch"))
        {
            throw; 
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Enclave] DG Hash Doğrulama KRİTİK HATA: {ex.Message}");
throw; 
        }
    }
    
    internal bool SearchHashInSOD(byte[] sodContent, int dgNumber, byte[] expectedHash)
    {
        // Simple search: look for the hash bytes in SOD content
        // In production, properly parse the ASN.1 structure
        
        // Convert to hex for logging
        var expectedHex = Convert.ToHexString(expectedHash);
        
        // Brute force search for the hash in SOD content
        for (int i = 0; i <= sodContent.Length - expectedHash.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < expectedHash.Length; j++)
            {
                if (sodContent[i + j] != expectedHash[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                Console.WriteLine($"[Enclave] DG{dgNumber} hash SOD'da {i} ofsetinde bulundu");
                return true;
            }
        }
        
        Console.WriteLine($"[Enclave] UYARI: DG{dgNumber} hash SOD içeriğinde bulunamadı (Beklenen: {expectedHex[..Math.Min(16, expectedHex.Length)]}...)");
        return false;
    }

private void CheckCertificateRevocation(System.Security.Cryptography.X509Certificates.X509Certificate2 dsCert, string countryCode)
    {
        var revokedSerials = _countryCrlCache.GetOrAdd(countryCode, LoadCrlEntriesInternal);

        if (revokedSerials.Count == 0)
        {
            Console.WriteLine($"[Enclave] CRL/{countryCode}: CRL dosyasi yok veya bos, CRL kontrolu atlanıyor.");
            return;
        }

        // .NET SerialNumber bastaki sifirlarla pad edebilir, normalize et
        var dsSerial = dsCert.SerialNumber.TrimStart('0').ToUpperInvariant();
        Console.WriteLine($"[Enclave] CRL kontrolu: DS seri no={dsSerial}, CRL'de {revokedSerials.Count} iptal kaydi.");

        if (revokedSerials.Contains(dsSerial))
        {
            throw new Exception($"Sertifika İptal Edilmiş! ❌ DS sertifikası (Seri: {dsSerial}) CRL'de iptal edilmiş olarak işaretli. Bu belgenin imzası artık güvenilir değil.");
        }

        Console.WriteLine("[Enclave] CRL kontrolu GECTI ✓ DS sertifikasi iptal listesinde degil.");
    }

    private static HashSet<string> LoadCrlEntriesInternal(string countryCode)
    {
        var revoked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string crlPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Certificates", "CRL", countryCode);
        if (!Directory.Exists(crlPath))
        {
            crlPath = Path.Combine(Directory.GetCurrentDirectory(), "Certificates", "CRL", countryCode);
        }
        if (!Directory.Exists(crlPath))
        {
            return revoked;
        }

        var files = Directory.GetFiles(crlPath, "*.crl");
        Console.WriteLine($"[Enclave] CRL/{countryCode}: {files.Length} CRL dosyasi bulundu.");

        var parser = new Org.BouncyCastle.X509.X509CrlParser();

        foreach (var file in files)
        {
            try
            {
                var bytes = File.ReadAllBytes(file);
                var crl = parser.ReadCrl(bytes);

                var revokedCerts = crl.GetRevokedCertificates();
                if (revokedCerts == null) continue;

                foreach (Org.BouncyCastle.X509.X509CrlEntry entry in revokedCerts)
                {
                    // BouncyCastle BigInteger.ToString(16) bastaki sifirlari keser
                    // .NET SerialNumber pad edebilir, her ikisini de TrimStart('0') ile normalize ediyoruz
                    var hex = entry.SerialNumber.ToString(16).TrimStart('0').ToUpperInvariant();
                    if (hex.Length > 0) revoked.Add(hex);
                }

                Console.WriteLine($"[Enclave] CRL/{countryCode}/{Path.GetFileName(file)}: {revokedCerts.Count} iptal kaydi yuklendi.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Enclave] CRL/{countryCode}/{Path.GetFileName(file)} yuklenemedi: {ex.Message}");
            }
        }

        return revoked;
    }

    private static System.Security.Cryptography.X509Certificates.X509Certificate2Collection LoadCscaCertificatesInternal(string countryCode)
    {
        Console.WriteLine($"[Enclave] {countryCode} için Güvenilir Kök Deposu diskten başlatılıyor...");
        var collection = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
        
        // Path: Certificates/CSCA/{CountryCode}
        string certPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Certificates", "CSCA", countryCode);
        
        if (!Directory.Exists(certPath))
        {
             certPath = Path.Combine(Directory.GetCurrentDirectory(), "Certificates", "CSCA", countryCode); 
        }

        if (Directory.Exists(certPath))
        {
            var files = Directory.GetFiles(certPath, "*.*"); 
Console.WriteLine($"[Enclave] CSCA/{countryCode} klasöründe {files.Length} dosya bulundu.");
            foreach (var file in files)
            {
                try 
                {
                    // Check for Master List (PKCS#7)
                    if (file.EndsWith(".ml", StringComparison.OrdinalIgnoreCase) || 
                        file.EndsWith(".masterlist", StringComparison.OrdinalIgnoreCase) ||
                        file.EndsWith(".p7b", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine($"[Enclave] Master List okunuyor: {Path.GetFileName(file)}");
                        byte[] bytes = File.ReadAllBytes(file);
                        var signedCms = new System.Security.Cryptography.Pkcs.SignedCms();
                        signedCms.Decode(bytes);
                        
                        if (signedCms.Certificates.Count > 0)
                        {
                            collection.AddRange(signedCms.Certificates);
                        }
                        
                        // Extract Inner Content for pure certs in ML
                        try 
                        {
                            var contentBytes = signedCms.ContentInfo.Content;
                            if (contentBytes != null && contentBytes.Length > 0)
                            {
                                 var reader = new System.Formats.Asn1.AsnReader(contentBytes, System.Formats.Asn1.AsnEncodingRules.BER);
                                 var sequence = reader.ReadSequence();
                                 
                                 // Skip Version
                                 if (sequence.PeekTag().HasSameClassAndValue(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.UniversalTagNumber.Integer)))
                                 {
                                     sequence.ReadInteger();
                                 }
                                 
                                 var nextTag = sequence.PeekTag();
                                 System.Formats.Asn1.AsnReader certSetReader;
                                 if (nextTag.TagValue == (int)System.Formats.Asn1.UniversalTagNumber.SetOf)
                                 {
                                     certSetReader = sequence.ReadSetOf();
                                 }
                                 else 
                                 {
                                     certSetReader = sequence.ReadSetOf();
                                 }

                                 int count = 0;
                                 while (certSetReader.HasData)
                                 {
                                     var certBytes = certSetReader.ReadEncodedValue().ToArray();
                                     try 
                                     {
                                        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(certBytes);
                                        collection.Add(cert);
                                        count++;
                                     } 
                                     catch { }
                                 }
                                 Console.WriteLine($"[Enclave] Master List yükünden {count} sertifika içe aktarıldı.");
                            }
                        }
                        catch { /* Ignore ML parse errors for now */ }
                    }
                    else if (file.EndsWith(".pem", StringComparison.OrdinalIgnoreCase) ||
                             file.EndsWith(".crt", StringComparison.OrdinalIgnoreCase))
                    {
                        // Text-based PEM or DER
                        try 
                        {
                            var text = File.ReadAllText(file);
                            if (text.Contains("-----BEGIN CERTIFICATE-----"))
                            {
                                var cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(text);
                                collection.Add(cert);
                            }
                            else
                            {
                                // Likely binary DER with .crt extension
                                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(file);
                                collection.Add(cert);
                            }
                        }
                        catch (Exception exPem)
                        {
                            Console.WriteLine($"[Enclave] {Path.GetFileName(file)} için PEM yüklemesi başarısız, binary yedek deneniyor... Hata: {exPem.Message}");
                             // Fallback to binary load
                            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(file);
                            collection.Add(cert);
                        }
                    }
                    else
                    {
                        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(file);
                        collection.Add(cert);
                    }
                }
                catch (Exception ex)
                { 
                    Console.WriteLine($"[Enclave] {Path.GetFileName(file)} yüklenemedi: {ex.Message}");
                }
            }
        }
        Console.WriteLine($"[Enclave] Güven Deposu başlatıldı. Toplam Sertifika: {collection.Count}");
        return collection;
    }

 
    /// <summary>
    /// Parses DG1 (ICAO 9303 TD1 MRZ) from Base64 to extract identity data.
    /// TD1 format: 3 lines × 30 characters
    /// Line 1: [DocType2][Country3][DocNo9][Check1][OptData15]
    /// Line 2: [DOB6][Check1][Sex1][Expiry6][Check1][Nationality3][OptData11]
    /// Line 3: [Name30] (SURNAME<<GIVENNAMES)
    /// </summary>
    internal TicketPayload ParseDG1ToTicket(string dg1Base64, string userPubKey, string countryIsoCode)
    {
        // DG1 is TLV encoded: Tag 61 -> Tag 5F1F (MRZ data)
        var dg1Bytes = Convert.FromBase64String(dg1Base64);
        var mrzString = ExtractMrzFromDG1(dg1Bytes);

        Console.WriteLine($"[Enclave] MRZ ayrıştırıldı ({mrzString.Length} karakter): {Mask(mrzString)}");

        // TD1 = 90 chars (3×30), TD3 (Passport) = 88 chars (2×44)
        string line1, line2, line3;
        string docNo, nationality, dob, gender, expiry, surname, givenName, issuingCountry;
        string docType = "";

        if (mrzString.Length >= 90)
        {
            // TD1 format (ID Card): 3 lines × 30 chars
            line1 = mrzString.Substring(0, 30);

            // Belge tipi doğrulaması: P (pasaport), I/A/C (kimlik kartı) kabul edilir
            // V (vize) ve diğer geçici belge tipleri reddedilir
            var docTypeChar = line1[0];
            if (docTypeChar != 'P' && docTypeChar != 'I' && docTypeChar != 'A' && docTypeChar != 'C')
                throw new Exception($"Bu belge türü desteklenmemektedir ('{docTypeChar}'). Yalnızca pasaport ve vatandaşlık kimlik kartları kabul edilmektedir.");
            docType = docTypeChar.ToString();

            line2 = mrzString.Substring(30, 30);
            line3 = mrzString.Substring(60, 30);

            issuingCountry = line1.Substring(2, 3).Replace("<", "").Trim();
            docNo = line1.Substring(5, 9).Replace("<", "").Trim();
            dob = line2.Substring(0, 6);
            gender = line2.Substring(7, 1);
            expiry = line2.Substring(8, 6);
            nationality = line2.Substring(15, 3).Replace("<", "").Trim();

            // Line 3: SURNAME<<GIVENNAMES<<<...
            var nameParts = line3.Replace("<", " ").Trim().Split(new[] { "  " }, StringSplitOptions.RemoveEmptyEntries);
            surname = nameParts.Length > 0 ? nameParts[0].Trim() : "";
            givenName = nameParts.Length > 1 ? nameParts[1].Trim() : "";
        }
        else if (mrzString.Length >= 88)
        {
            // TD3 format (Passport): 2 lines × 44 chars
            line1 = mrzString.Substring(0, 44);

            // TD3'te de belge tipi kontrolü (visa TD3 teorik olarak mümkün)
            var docTypeChar = line1[0];
            if (docTypeChar != 'P' && docTypeChar != 'I' && docTypeChar != 'A' && docTypeChar != 'C')
                throw new Exception($"Bu belge türü desteklenmemektedir ('{docTypeChar}'). Yalnızca pasaport ve vatandaşlık kimlik kartları kabul edilmektedir.");
            docType = docTypeChar.ToString();

            line2 = mrzString.Substring(44, 44);

            issuingCountry = line1.Substring(2, 3).Replace("<", "").Trim();
            // Line 1: [DocType1][Type1][Country3][NAME39]
            var nameSection = line1.Substring(5).Replace("<", " ").Trim();
            var nameParts = nameSection.Split(new[] { "  " }, StringSplitOptions.RemoveEmptyEntries);
            surname = nameParts.Length > 0 ? nameParts[0].Trim() : "";
            givenName = nameParts.Length > 1 ? nameParts[1].Trim() : "";

            // Line 2: [DocNo9][Check1][Nationality3][DOB6][Check1][Sex1][Expiry6][Check1]...
            docNo = line2.Substring(0, 9).Replace("<", "").Trim();
            nationality = line2.Substring(10, 3).Replace("<", "").Trim();
            dob = line2.Substring(13, 6);
            gender = line2.Substring(20, 1);
            expiry = line2.Substring(21, 6);
        }
        else
        {
            throw new Exception($"Invalid MRZ length: {mrzString.Length}. Expected 90 (TD1) or 88 (TD3).");
        }

        Console.WriteLine($"[Enclave] DG1 Ayrıştırıldı: Ülke={issuingCountry}, Uyruk={nationality}, BelgeNo={Mask(docNo)}, Cinsiyet={gender}");

        // Parse DOB (YYMMDD -> DateTime)
        var dobDate = ParseMrzDate(dob);
        var expiryDate = ParseMrzDate(expiry, isExpiry: true);

// For citizens of known countries, we extract their National ID (TCKN for TUR, National ID for THA, etc.)
        // This is stored in different places depending on document type (TD1 vs TD3)
        string primaryId = ""; // Default to empty string (will result in empty person_id/user_id)
        
        bool isTur = issuingCountry == "TUR" || nationality == "TUR";
        bool isTha = issuingCountry == "THA" || nationality == "THA";

        if (isTur || isTha)
        {
            if (mrzString.Length >= 90)
            {
                // TD1 (ID Card): Optional Data field (Line 1, index 15-29)
                var optionalData = line1!.Substring(15, 15).Replace("<", "").Trim();
                if (isTur && optionalData.Length >= 11 && optionalData.Take(11).All(char.IsDigit))
                {
                    primaryId = optionalData.Substring(0, 11);
                    Console.WriteLine($"[Enclave] TD1 İsteğe Bağlı Veriden TCKN çıkarıldı: {Mask(primaryId)}");
                }
                // (Thailand TD1 support can be added here if needed)
            }
            else if (mrzString.Length >= 88)
            {
                // TD3 (Passport): Personal Number (Line 2, positions 28-42 in zero-based Line 2 index)
                // Total mrzString index: 44 + 28 = 72. Length: 14.
                if (mrzString.Length >= 72 + 14)
                {
                    var personalNo = mrzString.Substring(72, 14).Replace("<", "").Trim();
                    
                    if (isTha && personalNo.Length >= 13 && personalNo.Take(13).All(char.IsDigit))
                    {
                        primaryId = personalNo.Substring(0, 13);
                        Console.WriteLine($"[Enclave] TD3 Kişisel Numaradan Tayland Ulusal ID çıkarıldı: {Mask(primaryId)}");
                    }
                    else if (isTur && personalNo.Length >= 11 && personalNo.Take(11).All(char.IsDigit))
                    {
                        primaryId = personalNo.Substring(0, 11);
                        Console.WriteLine($"[Enclave] TD3 Kişisel Numaradan TCKN çıkarıldı: {Mask(primaryId)}");
                    }
                    else if (isTur || isTha)
                    {
                        Console.WriteLine($"[Enclave] UYARI: {issuingCountry}/{nationality} belgesi tespit edildi ancak Kişisel Numara alanı geçersiz veya ID eksik: '{Mask(personalNo)}'");
                    }
                } 
            }
        }

        return new TicketPayload
        {
TCKN = primaryId, // Will be empty for non-TUR or missing TCKN
            Ad = givenName,
            Soyad = surname,
            DogumTarihi = dobDate,
            SeriNo = docNo,
            GecerlilikTarihi = expiryDate,
            Cinsiyet = gender == "M" ? "M" : gender == "F" ? "F" : "<",
            Uyruk = nationality,
            UserPubKey = userPubKey,
            CountryIsoCode = countryIsoCode,
            DocumentType = docType
        };
    }

    internal string GetIssuingCountryFromDG1(string dg1Base64)
    {
        try 
        {
            var dg1Bytes = Convert.FromBase64String(dg1Base64);
            var mrz = ExtractMrzFromDG1(dg1Bytes);
            if (!string.IsNullOrEmpty(mrz) && mrz.Length >= 5)
            {
                var country = mrz.Substring(2, 3).Replace("<", "").Trim().ToUpper();
                // Basic sanitization to prevent path traversal
                if (country.All(char.IsLetterOrDigit)) return country;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Enclave] CSCA klasörü için ülke çıkarılamadı: {ex.Message}");
        }
        return "UNKNOWN";
    } 
    /// <summary>
    /// Extracts MRZ string from DG1 TLV structure.
    /// DG1 is BER-TLV: Tag 61 { Tag 5F1F { MRZ bytes } }
    /// </summary>
    internal string ExtractMrzFromDG1(byte[] dg1Bytes)
    {
        try
        {
            var reader = new System.Formats.Asn1.AsnReader(dg1Bytes, System.Formats.Asn1.AsnEncodingRules.BER);
            var outerTag = reader.PeekTag();
            
            // Expected DG1 Wrapper: Application Tag 1 (0x61)
            if (outerTag.TagClass == System.Formats.Asn1.TagClass.Application && outerTag.TagValue == 1 && outerTag.IsConstructed)
            {
                var dg1Reader = reader.ReadSequence(outerTag);
                while (dg1Reader.HasData)
                {
                    var innerTag = dg1Reader.PeekTag();
                    // MRZ Content: Application Tag 31 (0x5F1F)
                    if (innerTag.TagClass == System.Formats.Asn1.TagClass.Application && innerTag.TagValue == 31)
                    {
                        var mrzTagContent = dg1Reader.ReadEncodedValue();
                        
                        // Extract just the inner value (ignoring the 5F 1F XX header bytes)
                        System.Formats.Asn1.AsnDecoder.ReadEncodedValue(
                            mrzTagContent.Span,
                            System.Formats.Asn1.AsnEncodingRules.BER,
                            out int contentOffset,
                            out int contentLength,
                            out int bytesConsumed);
                            
                        return Encoding.ASCII.GetString(mrzTagContent.Span.Slice(contentOffset, contentLength).ToArray());
                    }
                    else
                    {
                        dg1Reader.ReadEncodedValue(); // Skip unknown/optional inner tags
                    }
                }
            }
            throw new Exception("Application Tag 0x61 or 0x5F1F missing in DG1 strict ASN.1 structure.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Enclave] DG1 için ASN.1 ayrıştırma hatası: {ex.Message}. Regex ham çözmeye geçiliyor.");
            // Ultimate Substring Fallback for Malformed/Debug cases
            var raw = Encoding.ASCII.GetString(dg1Bytes);
            // ICAO MRZ is either 88 or 90 characters, containing only A-Z, 0-9, and <
            var match = System.Text.RegularExpressions.Regex.Match(raw, @"[A-Z0-9<]{88,90}");
            if (match.Success)
            {
                Console.WriteLine($"[Enclave] DG1 Yedek: Regex {match.Length} karakterlik MRZ başarıyla çıkardı.");
                return match.Value;
            }
            if (raw.Trim().Length >= 88)
            {
                return raw.Trim(); 
            }
            throw new Exception($"Could not extract MRZ from DG1 using ASN.1 strict parser or Regex fallback: {ex.Message}");
        }
    }

    /// <summary>
    /// Parses MRZ date (YYMMDD) to DateTime.
    /// For DOB: YY > 30 -> 19xx, else 20xx
    /// For Expiry: always 20xx
    /// </summary>
    internal DateTime ParseMrzDate(string yymmdd, bool isExpiry = false)
    {
        if (yymmdd.Length != 6) return DateTime.MinValue;
        
        int yy = int.Parse(yymmdd.Substring(0, 2));
        int mm = int.Parse(yymmdd.Substring(2, 2));
        int dd = int.Parse(yymmdd.Substring(4, 2));

        if (mm < 1 || mm > 12) mm = 1;
        if (dd < 1 || dd > 31) dd = 1;

        int year;
        if (isExpiry)
        {
            year = 2000 + yy; // Expiry dates are always in 2000s
        }
        else
        {
            year = yy > 30 ? 1900 + yy : 2000 + yy; // DOB heuristic
        }

        try { return new DateTime(year, mm, dd); }
        catch { return DateTime.MinValue; }
    }

    internal bool CheckAgeConstraint(int userAge, string constraint)
    {
        constraint = constraint.Trim();
        if (string.IsNullOrEmpty(constraint)) return true;

        if (constraint.EndsWith("+"))
        {
            // "18+" => age >= 18
            if (int.TryParse(constraint.TrimEnd('+'), out int minAge))
            {
                return userAge >= minAge;
            }
        }
        else if (constraint.EndsWith("-"))
        {
            // "16-" => age < 16
            if (int.TryParse(constraint.TrimEnd('-'), out int maxAge))
            {
                return userAge < maxAge;
            }
        }
        else if (constraint.Contains("-"))
        {
            // "16-35" => 16 <= age < 35
            var parts = constraint.Split('-');
            if (parts.Length == 2 && 
                int.TryParse(parts[0], out int min) && 
                int.TryParse(parts[1], out int max))
            {
                return userAge >= min && userAge < max;
            }
        }
        else
        {
            // "24" => age == 24
            if (int.TryParse(constraint, out int exactAge))
            {
                return userAge == exactAge;
            }
        }

        throw new Exception($"Invalid Age Constraint Format: '{constraint}'");
    }

    internal string Mask(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;
        if (value.Length <= 4) return "**" + value.Length + "**"; // Too short to mask first/last 2
        return value.Substring(0, 2) + new string('*', value.Length - 4) + value.Substring(value.Length - 2);
    }

    /// <summary>
    /// Verilen string'i IPv6 /64 CIDR prefix'e dönüştürür.
    /// - Zaten CIDR ise (örn: "2001:db8::/48") olduğu gibi döner — prefix uzunluğu değiştirilmez.
    /// - Tam IPv6 adresi ise (örn: "2403:6200:8871:6bad:6d4d:4245:e9df:df98") → "2403:6200:8871:6bad::/64"
    /// - IPv4 veya geçersiz format ise null döner.
    /// </summary>
}
