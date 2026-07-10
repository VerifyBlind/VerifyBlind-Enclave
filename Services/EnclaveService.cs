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
    private readonly IAntiSpoofService _antiSpoof;
    // Ticket'lar enclave-içi simetrik MAC ile imzalanır/doğrulanır (Ticket Forgery fix).
    private readonly ITicketMacService _ticketMac;

    public EnclaveService(IEnclaveKeyService enclaveKeys, IKmsService kms, IBiometricService biometricService,
        ITicketMacService ticketMac, IAntiSpoofService antiSpoof)
    {
        _enclaveKeys = enclaveKeys;
        _kms = kms;
        _biometricService = biometricService;
        _ticketMac = ticketMac;
        _antiSpoof = antiSpoof;
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
            var passiveAuthSummary = PassiveAuth.Verify(payload.SOD, payload.DG1, payload.DG2, payload.DG15);
            diag.Ok("Passive Auth", passiveAuthSummary);
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
            throw new RegistrationException(RegistrationStep.BiometricVerification, bioCode, ex.Message)
            {
                FaceScore = (ex as BiometricMismatchException)?.Score
            };
        }

        // --- Step 7: Anti-Spoof (passive liveness) — FAIL-CLOSED (bkz. EnforceAntiSpoof) ---
        EnforceAntiSpoof(payload, diag);

        // --- Step 8: DG1 Parsing ---
        TicketPayload ticketPayload;
        try
        {
            diag.Begin("DG1 Parse");
            ticketPayload = MrzParser.ParseDG1ToTicket(payload.DG1, payload.UserPubKey, request.CountryIsoCode);
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
            // İmzalama zamanı — MAC bunu kapsar (kurcalanamaz). Login'de iptal kurallarına karşı kontrol edilir.
            ticketPayload.SignedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            // Referans yüz fotosu — self-custody ticket'a gömülür; MAC kapsar. Relay'e/partnere gitmez.
            // İleride enclave-içi yüz karşılaştırma için referans (step-up + biyometrik karşılaştırma).
            // SOD-doğrulanmış HAM DG2'den çıkarılır (telefonun DG2_Photo alanına GÜVENİLMEZ) → gelecekteki
            // karşılaştırmalar da doğrulanmış referansa dayanır. Bu noktada PassiveAuth DG2'yi doğrulamış olur.
            ticketPayload.FaceRefJpegB64 = Convert.ToBase64String(
                Dg2FaceExtractor.ExtractFaceImage(Convert.FromBase64String(payload.DG2)));
            await _ticketMac.EnsureSecretLoadedAsync(request.TicketSecretWrapped);
            var signature = _ticketMac.ComputeMac(ticketPayload);
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
    /// Demo kartın sabit TCKN sentinel'i. Gerçek bir TCKN asla tümü-sıfır olmaz, bu yüzden
    /// login sırasında demo kartı güvenle ayırt etmek için kullanılır (kimlik kodlarını TEST önekiyle işaretlemek üzere).
    /// </summary>
    internal const string DemoTckn = "00000000000";

    /// <summary>
    /// Demo Mode için hardcoded veriyle gerçek imzalı ticket üretir.
    /// NFC/biometrik adımları atlanır; ID üretimi, imza ve şifreleme normal akıştaki gibi gerçek HSM ile yapılır.
    /// Tek farkı: SecurePayload yok, kimlik verisi enklavın içine gömülü.
    /// </summary>
    public async Task<(string ticket, float faceScore, string cardId)> DemoRegisterAsync(string userPubKey, string? ticketSecretWrapped, DiagLog diag)
    {
        diag.Info($"[DEMO] Kayıt başladı. UserPubKey={userPubKey.Length}ch");
        Console.WriteLine($"[Enclave] DEMO kayıt isteği alındı. UserPubKey uzunluğu: {userPubKey.Length}");

        if (string.IsNullOrEmpty(userPubKey))
            throw new RegistrationException(RegistrationStep.RsaDecrypt, "ERR_DEMO_MISSING_PUBKEY");

        // Hardcoded demo identity (gerçek bir kart yok — TCKN/SOD hash sabit)
        const string demoTckn = DemoTckn;
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
            ticketPayload.SignedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            await _ticketMac.EnsureSecretLoadedAsync(ticketSecretWrapped);
            var signature = _ticketMac.ComputeMac(ticketPayload);
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
        await _ticketMac.EnsureSecretLoadedAsync(request.TicketSecretWrapped);
        Task<bool> sigVerifyTask = Task.FromResult(_ticketMac.VerifyMac(signedTicket));

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

        // 4.1 Holder-of-Key kanıtı (Güvenlik incelemesi Y-4)
        // SignedTicket, Enclave'in PUBLIC anahtarıyla şifrelidir; özel anahtar gerektirmez. Bu nedenle
        // sızan bir SignedTicket (bulut yedeği / cihaz kopyası) bütünlük geçen herhangi bir uygulamada
        // bearer-token gibi kullanılabilir → kurbanı herhangi bir partnere doğrulayabilir.
        // Bunu engellemek için cihaz, ticket içindeki UserPubKey'in ÖZEL eşiyle (Android Keystore /
        // iOS Keychain — donanım-destekli, biyometrik-kapılı, dışa aktarılamaz) bu login'e özgü
        // "VBLOK1|{nonce}|{pk_hash}|{ts}" mesajını imzalar. UserPubKey, MAC-doğrulanmış ticket
        // payload'ının parçası olduğundan bu noktada güvenilirdir.
        diag.Begin("Holder-of-Key");
        {
            var userPubKey = signedTicket.Payload.UserPubKey;
            if (string.IsNullOrEmpty(userPubKey))
            {
                diag.Fail("Holder-of-Key", "Bilette UserPubKey yok");
                throw new Exception("Holder-of-key doğrulaması başarısız: bilette kullanıcı anahtarı yok.");
            }
            if (string.IsNullOrEmpty(request.UserSignature))
            {
                diag.Fail("Holder-of-Key", "İstekte user_signature yok");
                throw new Exception("Holder-of-key doğrulaması başarısız: imza eksik (uygulamayı güncelleyin).");
            }

            // Zaman damgası tazeliği. Nonce zaten tek-kullanım + 15dk TTL ile replay'i engeller; bu
            // pencere yalnızca cihaz-saati suistimalini sınırlar. Pencere QR TTL'sinden geniş tutulur
            // ki meşru bir login (nonce ≤15dk yaşar) zaman damgası yüzünden ASLA kırılmasın.
            const long SkewFutureSec = 300;  // +5 dk (ileri saat toleransı)
            const long SkewPastSec   = 900;  // -15 dk (QR TTL ile hizalı)
            var nowSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (request.UserSigTimestamp > nowSec + SkewFutureSec ||
                request.UserSigTimestamp < nowSec - SkewPastSec)
            {
                diag.Fail("Holder-of-Key", $"timestamp pencere dışı: ts={request.UserSigTimestamp}, now={nowSec}");
                throw new Exception("Holder-of-key doğrulaması başarısız: zaman damgası geçersiz.");
            }

            // Kanonik mesaj — mobil imzalayıcıyla BYTE-BYTE aynı olmalı (reqNonce==innerNonce==cihaz nonce,
            // innerPkHash==cihaz pk_hash; ikisi de yukarıdaki binding/nonce kontrolleriyle doğrulandı).
            var hokMessage = $"VBLOK1|{reqNonce}|{innerPkHash}|{request.UserSigTimestamp}";
            if (!CryptoUtils.VerifySignature(hokMessage, request.UserSignature, userPubKey))
            {
                diag.Fail("Holder-of-Key", "İmza UserPubKey ile doğrulanamadı");
                throw new Exception("Holder-of-key doğrulaması başarısız: imza geçersiz.");
            }
            diag.Ok("Holder-of-Key");
        }

        // Kart geçerlilik tarihi kontrolü (imza doğrulandıktan sonra)
        if (signedTicket.Payload.GecerlilikTarihi < DateTime.UtcNow.Date)
        {
            Console.WriteLine($"[Enclave] Kimlik kartı süresi dolmuş: {signedTicket.Payload.GecerlilikTarihi:yyyy-MM-dd}");
            throw new Exception($"Kimlik kartının geçerlilik süresi dolmuş ({signedTicket.Payload.GecerlilikTarihi:dd.MM.yyyy}). Giriş yapılamaz.");
        }
        Console.WriteLine($"[Enclave] Kart geçerlilik tarihi DOĞRULANDI ✓ ({signedTicket.Payload.GecerlilikTarihi:yyyy-MM-dd})");

        // Ticket-iptal kuralları (admin-yönetimli, relay'den iletilir) — SignedAtUnix etkin bir kurala
        // düşerse reddet. Kural yok/boş → kabul. now ENCLAVE saatiyle (güvenlik kontrolü enclave-side).
        diag.Begin("Revocation Check");
        var nowUnixRevoke = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (RevocationPolicy.IsRevoked(signedTicket.Payload.SignedAtUnix, nowUnixRevoke, request.RevocationRules))
        {
            diag.Fail("Revocation Check", $"SignedAt={signedTicket.Payload.SignedAtUnix} bir iptal kuralına düşüyor");
            throw new TicketRevokedException("Bu kimlik kaydı iptal edildi. Lütfen kimliğinizi yeniden ekleyin.");
        }
        diag.Ok("Revocation Check");

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
                    if (requested)
                    {
                        // Demo kart (sabit TCKN) ile giriş → partner'ın test verisini gerçek doğrulamalardan
                        // ayırt edebilmesi için üç kimlik kodunun başına "TEST_" öneki eklenir (ilk 5 karakter TEST_).
                        bool isDemo = signedTicket.Payload.TCKN == DemoTckn;
                        string Mark(string code) => isDemo && !string.IsNullOrEmpty(code) ? "TEST_" + code : code;

                        // Tek "user_id" isteği = üç partner-scoped kimlik kodu birden (AYRI string alanlar).
                        // Amaç: ulusal-no şema değişimi (kaldırma/ekleme) ve kart yenileme boyunca partner'ın
                        // aynı kişiyi takip edebilmesi — kodlar değişimden ÖNCE saklanmış olmalı, bu yüzden
                        // opt-in değil bundle. user_id string kalır (mevcut partner kırılmaz). TCKN yoksa "".
                        validationsOutput["user_id"] = Mark(userId);

                        // nsbd_id: biyografik kişi kovası (kart yenilemede sabit, olasılıksal ipucu).
                        var nsbd = await IdentityCodes.BuildNsbdIdAsync(_kms, signedTicket.Payload, partnerId ?? "");
                        if (nsbd != null) validationsOutput["nsbd_id"] = Mark(nsbd);

                        // doc_id: partner-scoped card_id (aynı belge ⟹ aynı kişi, sert sinyal).
                        var doc = await IdentityCodes.BuildDocIdAsync(
                            _kms, loginCardId, signedTicket.Payload.DocumentType, partnerId ?? "");
                        if (doc != null) validationsOutput["doc_id"] = Mark(doc);
                    }
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
        // KVKK şeffaflık: "user_id" istendiğinde nsbd_id/doc_id de fiilen paylaşılır. İstenen anahtarlar
        // değil, GERÇEKTEN üretilen kimlik kodlarını da consent kapsamına yaz (değerler değil, adlar).
        foreach (var bundledKey in new[] { "nsbd_id", "doc_id" })
            if (validationsOutput.ContainsKey(bundledKey) && !scopesList.Contains(bundledKey))
                scopesList.Add(bundledKey);
        var resultsBool = validationsOutput
            .Where(kv => kv.Value is bool)
            .ToDictionary(kv => kv.Key, kv => (bool)kv.Value);

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

    // --- PASSIVE LIVENESS (Anti-Spoof) — FAIL-CLOSED ---
    // Güvenlik denetimi #1: eski kod, crop çözme/çıkarım sırasındaki HER istisnayı genel bir
    // catch ile yutup ("devam edilecek") kaydı canlılık kontrolsüz tamamlıyordu; model yüklü
    // değilse de bloğu sessizce atlıyordu. İkisi de fail-OPEN'dı. Artık:
    //   • model yüklü değil → REDDET (biyometrik adımla simetrik; startup/readiness backstop)
    //   • crop boş / bozuk base64 / çözülemeyen JPEG / çıkarım hatası → REDDET
    //   • P(live) eşiğin altında → REDDET
    internal void EnforceAntiSpoof(SecurePayload payload, DiagLog diag)
    {
        diag.Begin("AntiSpoof");

        if (!_antiSpoof.IsModelLoaded)
        {
            diag.Fail("AntiSpoof", "model yüklü değil");
            throw new RegistrationException(RegistrationStep.BiometricVerification, "ERR_ANTISPOOFING_MODEL_MISSING",
                "Pasif canlılık modeli yüklü değil — kayıt güvenli şekilde tamamlanamaz.");
        }

        if (string.IsNullOrEmpty(payload.AntiSpoofCrop))
            throw new RegistrationException(RegistrationStep.BiometricVerification, "ERR_ANTISPOOFING",
                "Anti-spoof crop eksik — pasif canlılık doğrulaması atlanamaz.");

        float pLive;
        try
        {
            byte[] cropBytes = Convert.FromBase64String(payload.AntiSpoofCrop);
            float[] probs = _antiSpoof.Predict(cropBytes);
            // Live = indeks 1 (etiketli referansla doğrulandı: ham-BGR girdide real→idx1≈0.99, fake→≈0.00).
            pLive = probs.Length > 1 ? probs[1] : 0f;
            string breakdown = probs.Length >= 3 ? $" [c0={probs[0]:P1} c1={probs[1]:P1} c2={probs[2]:P1}]" : "";
            diag.Ok("AntiSpoof", $"P(live)={Math.Round(pLive * 100, 1)}%{breakdown}");
        }
        catch (Exception ex)
        {
            // Bozuk base64 / çözülemeyen JPEG / çıkarım hatası → FAIL-CLOSED (eskiden yutuluyordu).
            diag.Fail("AntiSpoof", ex.Message);
            Console.WriteLine($"[Enclave] Anti-spoof girdi/çıkarım hatası — kayıt REDDEDİLDİ: {ex.Message}");
            throw new RegistrationException(RegistrationStep.BiometricVerification, "ERR_ANTISPOOFING",
                "Pasif canlılık doğrulaması yapılamadı (geçersiz veya işlenemeyen anti-spoof verisi).");
        }

        if (pLive < AntiSpoofService.LiveThreshold)
            throw new RegistrationException(RegistrationStep.BiometricVerification, "ERR_ANTISPOOFING",
                $"Canlı yüz tespit edilemedi (P={pLive:F3}).");
    }

    // --- ACTIVE AUTHENTICATION (Chip Clone Protection) ---

    internal void VerifyActiveAuth(SecurePayload payload)
    {
        Console.WriteLine("[Enclave] Aktif Kimlik Doğrulama kontrol ediliyor (ISO 9796-2)...");
        
        // AA ZORUNLU: VerifyBlind yalnızca çip-doğrulamalı (Active Authentication destekli)
        // belgeleri kabul eder. DG15 (public key) VEYA Aktif İmza eksikse → REDDET.
        // Eski "desteklemeyen kart için atla" davranışı bir downgrade açığıydı: saldırgan
        // DG15'i hiç göndermeyerek klon-korumasını atlayabiliyordu (2026-06-09 kapatıldı).
        if (string.IsNullOrEmpty(payload.DG15) || string.IsNullOrEmpty(payload.ActiveSig))
        {
            Console.WriteLine("[Enclave] AA verisi eksik (DG15 ve/veya Aktif İmza). Çip doğrulaması yapılamıyor — RED.");
            throw new Exception("Aktif Kimlik Doğrulama Başarısız: Bu belge çip doğrulamasını (Active Authentication) desteklemiyor ya da NFC okuması eksik.");
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
                
                // (KALDIRILDI) Variant B "Simülasyon Modu" — challenge'ın base64 string'i üzerinden
                // PKCS#1 doğrulaması yalnızca yazılım simülatörü içindi ve üretimde sahte-kart
                // kabul yolu oluşturuyordu (2026-06-09 silindi). Gerçek kartlar buna ihtiyaç duymaz.
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

    internal float VerifyBiometricMatchParallel(SecurePayload payload)
    {
        Console.WriteLine("[Enclave] Biyometrik Kimlik Eşleşmesi başlatılıyor (paralel)...");

        if (string.IsNullOrEmpty(payload.DG2)) throw new Exception("Biyometrik Hata: Kimlik veri grubu (DG2) eksik.");
        if (string.IsNullOrEmpty(payload.UserSelfie)) throw new Exception("Biyometrik Hata: Kullanıcı selfie'si eksik.");

        // Kimlik fotoğrafı, Passive Authentication'ın SOD/CSCA'ya karşı doğruladığı HAM DG2'den
        // çıkarılır — telefonun ayrı gönderdiği (hiçbir şeye bağlı OLMAYAN) yeniden-kodlanmış görüntüye
        // GÜVENİLMEZ. Çağrı sırası şartı: bu metot register akışında PassiveAuth'tan SONRA çalışır,
        // dolayısıyla payload.DG2 bu noktada kriptografik olarak doğrulanmıştır. Çıkarım başarısızsa
        // fail-closed (Dg2FaceExtractor fırlatır) — asla istemci görüntüsüne geri düşülmez.
        byte[] idPhotoBytes = Dg2FaceExtractor.ExtractFaceImage(Convert.FromBase64String(payload.DG2));
        byte[] probePhotoBytes = Convert.FromBase64String(payload.UserSelfie);

        Console.WriteLine($"[Enclave] Kimlik Fotoğrafı Boyutu: {idPhotoBytes.Length} bayt");
        Console.WriteLine($"[Enclave] Selfie Fotoğrafı Boyutu: {probePhotoBytes.Length} bayt");

        float similarity = _biometricService.VerifyFaceParallel(idPhotoBytes, probePhotoBytes);

        // ArcFace (w600k_r50) kosinüs eşiği — YuNet 5-nokta HİZALI boru hattı için kalibre edildi
        // (FaceAligner; eski 0.40 hizalamasız center-crop içindi, hizalı dağılımda çok yüksek kalırdı).
        // LFW held-out: 0.20'de FAR ~%0.16 / FRR ~%1.3. Cross-domain (DG2 chip ↔ canlı selfie) genuine
        // skorları daha düşük → muhafazakâr başlangıç; canlı histogram (biometric_face_score_percent,
        // BiometricScoreDriftLow alert) gerçek dağılımı gösterince ince ayar. Bkz
        // tools/biometric/yunet_frr_ref.py + CalibrationLfwTests (LFW_DIR gated).
        const float THRESHOLD = 0.20f;

        Console.WriteLine($" > [AI] Benzerlik Puanı (paralel): {similarity * 100:0.0}%");

        if (similarity < THRESHOLD)
        {
            throw new BiometricMismatchException(similarity, $"Kimlik Doğrulama Başarısız: Yüz kimlik kartıyla eşleşmiyor. Puan: {similarity:0.00}");
        }

        Console.WriteLine("[Enclave] Biyometrik Kimlik EŞLEŞMESİ ONAYLANDI ✓");
        return similarity;
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

    internal static string Mask(string value)
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
