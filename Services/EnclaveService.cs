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
    // Canlı benzerlik akışı — YALNIZ streaming içindir. Register buraya ASLA bakmaz (K4).
    private readonly FlowEmbeddingCache _flowEmbeddings;

    /// <summary>
    /// ArcFace (w600k_r50) kosinüs eşiği — YuNet 5-nokta hizalı boru hattı için kalibre edildi.
    /// Gerekçe ve kalibrasyon notları için bkz. <see cref="VerifyBiometricMatchParallel"/>.
    ///
    /// Streaming ve final register AYNI sayıyı kullanır: streaming "geçti" deyip register'ın
    /// aynı kareyi reddetmesi kullanıcıyı açıklanamaz bir duvara çarptırırdı.
    /// </summary>
    public const float BiometricThreshold = 0.20f;

    public EnclaveService(IEnclaveKeyService enclaveKeys, IKmsService kms, IBiometricService biometricService,
        ITicketMacService ticketMac, IAntiSpoofService antiSpoof, FlowEmbeddingCache flowEmbeddings)
    {
        _enclaveKeys = enclaveKeys;
        _kms = kms;
        _biometricService = biometricService;
        _ticketMac = ticketMac;
        _antiSpoof = antiSpoof;
        _flowEmbeddings = flowEmbeddings;
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
        diag.Ok("AttestationKarar", _enclaveKeys.LastRenewalDecision);

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
        diag.Ok("AttestationKarar", _enclaveKeys.LastRenewalDecision);
        return new LoginHandshakeResponse { AttestationDocument = attestDoc };
    }

    /// <returns>
    /// Ticket, kazanan adayın benzerlik skoru, kart numarası ve HER adayın sonucu.
    /// Aday sonuçları relay tarafından ölçüm tablosuna yazılır — kazanan da kaybeden de
    /// (cihazın "en iyi" hükmü ile enclave'in hükmü arasındaki sapmanın etiketli örneği).
    /// </returns>
    public async Task<(string ticket, float faceScore, string cardId, List<CandidateOutcome> candidates)> RegisterAsync(RegistrationRequest request, DiagLog diag)
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
            // Süre aşımı AYRI kodla gider: relay onu beklenen kullanıcı durumu sayıp Sentry'ye
            // event üretmeyen seviyede loglar (bkz. VerifyController.Register). Nonce imzasının
            // geçersizliği ve ileri cihaz saati ERR_NONCE_VERIFICATION olarak kalır ve uyarı üretir.
            // Yaş/pencere YAPISAL tanı alanına yazılır: kişiye bağlanamaz, "15 dk yetiyor mu"
            // sorusunu tek olaydan yanıtlar.
            if (ex is NonceExpiredException expired)
            {
                throw new RegistrationException(RegistrationStep.NonceVerification, "ERR_NONCE_EXPIRED", ex.Message)
                {
                    Diagnostic = $"nonce-expired age={expired.AgeSeconds}s max={expired.MaxAgeSeconds}s"
                };
            }
            throw new RegistrationException(RegistrationStep.NonceVerification, "ERR_NONCE_VERIFICATION", ex.Message);
        }

        // --- Step 4: Active Authentication ---
        try
        {
            diag.Begin("Active Auth");
            var aaProfile = VerifyActiveAuth(payload);
            diag.Ok("Active Auth", aaProfile);
        }
        catch (Exception ex)
        {
            // Yapısal profil hem diag satırına hem de relay üzerinden Sentry'ye gider; kartı tekrar
            // isteyemeyeceğimiz için tek denemede teşhis edilebilir olması şart.
            var aaProfile = (ex as ActiveAuthException)?.Profile;
            diag.Fail("Active Auth", aaProfile != null ? $"{ex.Message} [{aaProfile}]" : ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.ActiveAuthentication}] adımında başarısız: {ex}");
            throw new RegistrationException(RegistrationStep.ActiveAuthentication, "ERR_ACTIVE_AUTH", ex.Message)
            {
                Diagnostic = aaProfile
            };
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
            var paProfile = (ex as PassiveAuthException)?.Profile;
            diag.Fail("Passive Auth", paProfile != null ? $"{ex.Message} [{paProfile}]" : ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.PassiveAuthentication}] adımında başarısız: {ex}");
            throw new RegistrationException(RegistrationStep.PassiveAuthentication, "ERR_PASSIVE_AUTH", ex.Message)
            {
                Diagnostic = paProfile
            };
        }

        // --- Step 5.5: Document Policy (yalnızca TC kimlik kartı) ---
        // KONUM GEREKÇESİ: Passive Auth'tan SONRA çünkü DG1'e ancak SOD'a karşı doğrulandıktan
        // sonra güvenilebilir — aksi halde değiştirilmiş bir istemci ülke alanına "TUR" yazıp
        // kapıyı geçerdi. Biyometrikten ÖNCE çünkü desteklenmeyen belge için ONNX maliyeti
        // ödenmesin. Mobil taraf (DocumentSupport) aynı kuralı kullanıcıya erken mesaj için
        // uygular; burası otoritedir.
        try
        {
            diag.Begin("Document Policy");
            var polFields = MrzParser.ExtractPolicyFieldsFromDG1(payload.DG1);
            if (polFields == null)
            {
                // DG1 hiç çözülemedi. Fail-closed kalıyoruz (kayıt reddedilir) ama bunu "belge
                // desteklenmiyor" diye RAPORLAMIYORUZ: okunamayan DG1 geçerli bir TC kimliğinde de
                // olabilir (NFC/aktarım arızası). Kullanıcıya "belgeniz TC değil" demek hem yanlış
                // hem çıkmaz; ERR_DG1_PARSE "kart okunamadı, tekrar deneyin" mesajına eşlenir.
                diag.Fail("Document Policy", "DG1 okunamadı — politika alanları çıkarılamadı");
                Console.WriteLine("[Enclave] Belge politikası: DG1 okunamadı → ERR_DG1_PARSE (fail-closed red).");
                throw new RegistrationException(
                    RegistrationStep.DocumentPolicy, VerifyBlind.Core.EnclaveErrorCodes.Dg1Parse,
                    "DG1 okunamadı: politika alanları (ülke/belge kodu) çıkarılamadı.");
            }

            var (polCountry, polDocCode, polDob) = polFields.Value;
            var verdict = DocumentPolicy.Evaluate(polCountry, polDocCode);
            if (verdict != DocumentPolicy.Verdict.Accepted)
            {
                var polCode = DocumentPolicy.ErrorCodeFor(verdict)!;
                diag.Fail("Document Policy", $"{verdict} (ülke={polCountry}, kod={polDocCode})");
                Console.WriteLine($"[Enclave] Belge politikası reddi: {verdict} — ülke={polCountry}, belgeKodu={polDocCode}");
                throw new RegistrationException(
                    RegistrationStep.DocumentPolicy, polCode,
                    $"Desteklenmeyen belge (ülke={polCountry}, kod={polDocCode}).")
                {
                    // Relay bunu Sentry'ye yapısal alan olarak basar (ZK-güvenli ISO kodu).
                    IssuingCountry = string.IsNullOrEmpty(polCountry) ? "UNKNOWN" : polCountry
                };
            }
            // Yaş kapısı: belge TC kimlik kartı olarak KABUL EDİLDİKTEN sonra. Mobil taraf aynı
            // kuralı erken mesaj için uygular ama değiştirilmiş bir istemci onu atlayabilir;
            // otorite burasıdır. Doğum tarihi ASLA loglanmaz — yalnız verdict.
            var ageVerdict = AgePolicy.Evaluate(polDob);
            if (ageVerdict == AgePolicy.Verdict.Unparseable)
            {
                // DG1 çözüldü ama doğum tarihi alanı okunamadı → "yaşınız küçük" demek YANLIŞ
                // teşhis olurdu. Fail-closed kalıyoruz ama kullanıcıya "kart okunamadı" denir.
                diag.Fail("Document Policy", "Doğum tarihi MRZ'den çözülemedi");
                Console.WriteLine("[Enclave] Yaş politikası: doğum tarihi çözülemedi → ERR_DG1_PARSE (fail-closed red).");
                throw new RegistrationException(
                    RegistrationStep.DocumentPolicy, VerifyBlind.Core.EnclaveErrorCodes.Dg1Parse,
                    "DG1 okundu ancak doğum tarihi alanı çözülemedi.");
            }
            if (ageVerdict == AgePolicy.Verdict.BelowMinimumAge)
            {
                diag.Fail("Document Policy", $"Asgari yaş ({AgePolicy.MinimumAge}) karşılanmıyor");
                Console.WriteLine($"[Enclave] Yaş politikası reddi: kullanıcı {AgePolicy.MinimumAge} yaşını doldurmamış.");
                throw new RegistrationException(
                    RegistrationStep.DocumentPolicy, VerifyBlind.Core.EnclaveErrorCodes.AgeBelowMinimum,
                    $"Kullanıcı asgari yaşı ({AgePolicy.MinimumAge}) doldurmamış.");
            }

            diag.Ok("Document Policy", $"Country={polCountry}, DocCode={polDocCode}");
        }
        catch (RegistrationException) { throw; }
        catch (Exception ex)
        {
            diag.Fail("Document Policy", ex.Message);
            Console.WriteLine($"[Enclave] [{RegistrationStep.DocumentPolicy}] adımında başarısız: {ex}");
            // Beklenmedik bir hata, belgenin desteklenmediğinin KANITI değildir — bu adımda
            // patlayan her şey teşhis olarak "kart okunamadı"dır (ERR_UNSUPPORTED_DOC_TYPE
            // kullanıcıya "pasaportunuz kabul edilmiyor" derdi; iç arızada bu yanlış ve çıkmaz).
            throw new RegistrationException(RegistrationStep.DocumentPolicy, VerifyBlind.Core.EnclaveErrorCodes.Dg1Parse, ex.Message);
        }

        // --- Step 6+7: Biyometrik eşleşme + pasif canlılık (aday aday, TAM KAPI) ---
        // Adaylar sırayla TAM kapıdan geçirilir ve ilk GEÇEN kazanır. Enclave streaming'de neyi
        // onayladığını BİLMEZ ve önbelleğe GÜVENMEZ (K4) — burada her şey baştan hesaplanır.
        var (faceScore, candidateOutcomes) = EvaluateCandidates(payload, diag);

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
            // detail'e geçerlilik tarihini YAZMA. detail, RegistrationException.Message üzerinden
            // enclave'in HTTP hata gövdesine, oradan da relay'in Sentry event'ine gider — yani
            // çipten okunan bir alan enclave güven sınırının dışına, üçüncü taraf bir SaaS'a çıkar.
            // Kod (ERR_CARD_EXPIRED) teşhis için zaten yeterli; tarih hiçbir şey eklemiyor.
            // (Yukarıdaki Console satırı enclave stdout'unda kalır — prod EIF'te erişilemez.)
            throw new RegistrationException(RegistrationStep.Dg1Parsing, "ERR_CARD_EXPIRED");
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
            // TCKN formatı burada da doğrulanır (login yoluyla aynı kapı). Bugün MrzParser TCKN'yi
            // ya boş ya geçerli bıraktığı için "boş mu" kontrolüyle denk; ama o invariant'a bağlı
            // kalmamak için açıkça IsValidTckn kullanılır — TicketPayload başka bir yoldan
            // üretilirse (test, gelecekteki bir akış) iki uç ayrışmasın.
            Task<string>? personHmacTask = null;
            if (IdentityCodes.IsValidTckn(ticketPayload.TCKN))
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
                Console.WriteLine("[Enclave] Geçerli TCKN yok → person_id üretilmedi (boş bırakıldı).");
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
            return (JsonSerializer.Serialize(hybridResponse), faceScore, cardId, candidateOutcomes);
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
    /// Login'de user_id (ve diğer kimlik kodları) türetilebilir mi? Gerçek kartlar TCKN format
    /// kapısından (<see cref="IdentityCodes.IsValidTckn"/>) geçmek zorundadır; demo kart sentinel'i
    /// (<see cref="DemoTckn"/>) bilinçli olarak muaftır — çıktı zaten "TEST_" ile işaretlenir.
    ///
    /// <para><b>Neden ayrı bir kapı:</b> demo sentinel tümü-sıfırdır ve <c>IsValidTckn</c> "gerçek
    /// TCKN 0 ile başlayamaz" kuralı yüzünden onu (doğru biçimde) reddeder. O kurala dokunmadan
    /// (gerçek çöp TCKN'ler elenmeye devam etsin) demo'yu burada muaf tutuyoruz. Yalnız login
    /// yolu bu muafiyete ihtiyaç duyar: gerçek register asla demo sentinel taşımaz (demo kaydın
    /// kendi ayrı hardcoded yolu vardır).</para>
    /// </summary>
    internal static bool DerivesIdentityCodes(string? tckn) =>
        IdentityCodes.IsValidTckn(tckn) || tckn == DemoTckn;

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
            Soyad = "User",
            DogumTarihi = new DateTime(1992, 1, 1),
            SeriNo = "A12345678",
            GecerlilikTarihi = new DateTime(2030, 12, 31),
            Cinsiyet = "E",
            Uyruk = "TUR",
            UserPubKey = userPubKey,
            CountryIsoCode = "TUR",
            DocumentType = "I"
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
            // Ham istisna dökümü (mesaj + stack) diag'a YAZILMAZ: relay diag satırlarını
            // Information seviyesinde loglar ve serbest metin kimlik verisi taşıyabilir. Tür adı
            // yapısaldır ve teşhis için yeterlidir.
            diag.Fail("Login", ex.GetType().Name);
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
            diag.Fail("Ticket Decrypt", ex.GetType().Name);
            throw new InvalidOperationException("Giriş şifre çözme başarısız.");
        }

        // 2. Parse decrypted content
        SignedTicket? signedTicket = null;
        string? innerNonce = null;
        string? innerPkHash = null;
        // Canlı yüz karesi zarfın İÇİNDEDİR (gövdede düz alan DEĞİL): relay biyometrik görüntüyü
        // görmez ve kare bu login'in nonce'una bağlanmış olur. Kayıt akışı da biyometriyi aynı
        // sebeple aes_blob içinde taşıyor.
        LoginFaceProof? faceProof = null;

        try
        {
            diag.Begin("Ticket Parse");
            using var doc = JsonDocument.Parse(decryptedJson);
            var root = doc.RootElement;
            
            // Extract inner properties
            if (root.TryGetProperty("nonce", out var nonceEl)) innerNonce = nonceEl.GetString();
            if (root.TryGetProperty("pk_hash", out var pkHashEl)) innerPkHash = pkHashEl.GetString();
            if (root.TryGetProperty("face_proof", out var fpEl) && fpEl.ValueKind == JsonValueKind.Object)
                faceProof = JsonSerializer.Deserialize<LoginFaceProof>(fpEl.GetRawText());

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
            diag.Fail("Ticket Parse", ex.GetType().Name);
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
                // Anahtar ADLARI sabit sözleşme alanlarıdır (değerler DEĞİL) → yapısal, PII'sız.
            diag.Info($"Validations: {reqValidations?.Count ?? 0} [{(reqValidations != null ? string.Join(",", reqValidations.Keys) : "")}]");
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
            
            // ⚠️ Kullanıcı açık anahtarının hash'i KALICI bir cihaz/kişi tanımlayıcısıdır: loglara
            // açık yazılırsa farklı oturumlardaki satırlar aynı kişiye bağlanabilir hale gelir
            // (ZK duruşuyla çelişir). Yalnız ilk 8 karakter — eşleşme/uyuşmazlık teşhisine yeter.
            diag.Info($"Binding: inner={Mask8(innerPkHash)} computed={Mask8(computedHashHex)}");
            
            if (!innerPkHash.Equals(computedHashHex, StringComparison.OrdinalIgnoreCase))
            {
                var computedHashB64 = Convert.ToBase64String(computedHashBytes);
                if (innerPkHash != computedHashB64)
                {
                    diag.Fail("Binding Check", $"expected={Mask8(computedHashHex)} got={Mask8(innerPkHash)}");
                    throw new Exception("Bağlama başarısız: Public Key Hash uyuşmuyor.");
                }
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
            diag.Info($"Nonce mismatch: inner={Mask8(innerNonce)} req={Mask8(reqNonce)}");
            throw new Exception("Nonce uyuşmuyor.");
        }
        diag.Ok("Nonce Match");

        // 4. Verify Ticket Signature + 5. Compute UserId — paralel (bağımsız KMS çağrıları)
        diag.Ok("---------------------------------------------------");
        diag.Ok($"[Enclave] TCKN için giriş işlemi: {(string.IsNullOrEmpty(signedTicket.Payload.TCKN) ? "(Boş)" : Mask(signedTicket.Payload.TCKN))}");
        diag.Info($"Partner: {partnerId}");

        string userId;
        string personId;

        diag.Begin("Ticket Sig Verify");
        await _ticketMac.EnsureSecretLoadedAsync(request.TicketSecretWrapped);
        Task<bool> sigVerifyTask = Task.FromResult(_ticketMac.VerifyMac(signedTicket));

        // UserId HMAC'ı imza doğrulamasından bağımsız — paralel başlat.
        // TCKN formatı BURADA doğrulanır (yalnız "boş mu" değil): geçersizse kod hiç üretilmez ve
        // user_id partner cevabından DÜŞER — eskiden boş string dönüyordu, bu da TCKN'siz tüm
        // kullanıcıları partner tarafında aynı kimliğe çakıştırıyordu. Demo kart sentinel'i muaf
        // tutulur (bkz. DerivesIdentityCodes) → demo login "TEST_" önekli user_id üretmeye devam eder.
        Task<string>? userIdHmacTask = null;
        if (DerivesIdentityCodes(signedTicket.Payload.TCKN))
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
            // Mesaja geçerlilik tarihini YAZMA: bu metin login hata gövdesine (error alanı) girer ve
            // relay onu Sentry'ye + verification_logs'a basar → çipten okunan bir alan enclave güven
            // sınırının dışına çıkar. Kullanıcıya zaten bu metin DEĞİL, relay'in resx'i gösterilir
            // (error_code=ERR_CARD_EXPIRED → EnclaveErrorCardExpired), yani tarih kimseye lazım değil.
            throw new CardExpiredException("Kimlik kartının geçerlilik süresi dolmuş. Giriş yapılamaz.");
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

        // 5.5 CANLI YÜZ KAPISI — giriş anında kişinin kendisi orada mı?
        //
        // Buraya kadarki her kontrol TELEFONUN meşru olduğunu kanıtlar (bilet, bağlama, nonce,
        // MAC, holder-of-key). Hiçbiri telefonu TUTAN kişiyi kanıtlamaz: cihaz anahtarı
        // AUTH_DEVICE_CREDENTIAL ile de açılır, yani PIN'i bilen aile ferdi kart sahibi adına
        // doğrulanabilirdi. Bu kapı kayıt anında SOD-doğrulanmış DG2'den çıkarılıp bilete mühürlenen
        // yüz referansını giriş anındaki canlı kareyle karşılaştırarak o boşluğu kapatır.
        //
        // Konum gerekçesi: ucuz kapılar (binding/nonce/MAC/HoK/kart vadesi/iptal) GEÇİLDİKTEN sonra
        // → geçersiz bir bilet için ONNX maliyeti ödenmez; validation işlemeden ÖNCE
        // → reddedilecek bir giriş için kimlik kodu türetilip KMS çağrılmaz.
        //
        // FAIL-CLOSED: kural "referans varsa zorunlu, yoksa yalnız demo bileti muaf" biçiminde
        // yazılır — "demo ise atla" biçiminde DEĞİL. İkincisinde varsayılan davranış atlamak olurdu
        // ve ileride FaceRef'i boş bırakan bir yol kontrolü SESSİZCE kaldırırdı. Burada varsayılan
        // reddetmektir; boşluk gürültülü şekilde ortaya çıkar.
        //
        // ⚠️ Karar demo BUTONUNUN kapısına (sürüm eşleşmesi) ASLA dayandırılmaz: o yalnız
        // yapılandırmadır ve zayıftır. Hem FaceRefJpegB64 hem TCKN, MAC ile mühürlü bilet
        // payload'ının içindedir → "bu demo bir bilettir" istemci beyanı değil, enclave'in
        // mühürden okuduğu otoriter olgudur.
        EnforceLoginFaceProof(signedTicket.Payload, faceProof, diag);

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
            // Boş string burada yalnız DAHİLİ bir işaretçidir — partner cevabına ASLA konmaz
            // (aşağıda user_id yalnız üretilebildiyse validationsOutput'a yazılır).
            diag.Ok("[Enclave] Bilette geçerli TCKN yok → user_id/person_id üretilmedi.");
            diag.Info("UserId/PersonId: üretilmedi (geçersiz/eksik TCKN)");
        }

        // card_id: read from signed ticket (computed at registration from SOD, globally unique).
        string loginCardId = signedTicket.Payload.CardId;
        if (!string.IsNullOrEmpty(loginCardId))
            diag.Ok($"[Enclave] card_id ticket'tan okundu: {loginCardId[..8]}...");
        diag.Ok("---------------------------------------------------");

        // 6. Process Validations (e.g. Age Check, Nationality Check)
        diag.Begin("Validations");
        var validationsOutput = new Dictionary<string, object>();
        // Partner istedi ama türetilemedi → alan cevaptan düşer, adı buraya yazılır. relay_metadata
        // ile relay'e taşınır; relay bunu Sentry'ye basar (enclave'in ağ erişimi yok, sinyal ancak
        // relay üzerinden çıkabilir). Yalnız kod ADLARI — kişisel veri değil.
        var missingIdentityCodes = new List<string>();

        if (reqValidations != null && reqValidations.Count > 0)
        {
            diag.Info($"Validations processing: {reqValidations.Count}");
            
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
                        // opt-in değil bundle.
                        //
                        // SÖZLEŞME: bir kod türetilemiyorsa ALAN HİÇ DÖNMEZ (boş string DEĞİL).
                        // Boş string dönmek, kodu türetilemeyen tüm kullanıcıları partner tarafında
                        // aynı kimliğe çakıştırıyordu. Doğrulama başarılı kalır; eksik alanlar
                        // relay_metadata üzerinden Sentry'ye sinyallenir.
                        if (!string.IsNullOrEmpty(userId)) validationsOutput["user_id"] = Mark(userId);
                        else missingIdentityCodes.Add("user_id");

                        // nsbd_id: biyografik kişi kovası (kart yenilemede sabit, olasılıksal ipucu).
                        var nsbd = await IdentityCodes.BuildNsbdIdAsync(_kms, signedTicket.Payload, partnerId ?? "");
                        if (nsbd != null) validationsOutput["nsbd_id"] = Mark(nsbd);
                        else missingIdentityCodes.Add("nsbd_id");

                        // doc_id: partner-scoped card_id (aynı belge ⟹ aynı kişi, sert sinyal).
                        var doc = await IdentityCodes.BuildDocIdAsync(
                            _kms, loginCardId, signedTicket.Payload.DocumentType, partnerId ?? "");
                        if (doc != null) validationsOutput["doc_id"] = Mark(doc);
                        else missingIdentityCodes.Add("doc_id");
                    }
                }

            }
        }

        diag.Ok("Validations", $"Count={validationsOutput.Count}");
        // İÇERİK YAZILMAZ: `additional_data` partnerin serbestçe doldurduğu bir alandır (sipariş no,
        // müşteri referansı, hatta kişisel veri olabilir) ve bizim denetimimizde değildir. Yalnız
        // varlığı loglanır — teşhis için gereken de bu.
        diag.Info($"SpecialData: {(specialData == null ? "yok" : "var")}");

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
        // Aynı doğruluk kuralı ters yönde: istendi ama TÜRETİLEMEDİ ise kapsamda görünmemeli —
        // rıza makbuzu paylaşılmamış bir veriyi paylaşılmış gibi göstermez.
        if (!validationsOutput.ContainsKey("user_id"))
            scopesList.Remove("user_id");
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
            enclave_sig      = consentEnclaveSig,
            // Operasyonel sinyal (DB'ye YAZILMAZ, yalnız relay log/Sentry): partner'ın istediği
            // ama türetilemeyen kimlik kodlarının ADLARI. Boş dizi = her şey yolunda.
            identity_codes_missing = missingIdentityCodes
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
        
        // 1. Zaman damgası tazeliği.
        // Bu pencere kayıt akışının TAMAMINI kapsamak zorunda: nonce handshake'te üretilir ve AA
        // challenge'ı ondan türetildiği için (SHA-256(nonce)[0..7]) MRZ girişi + NFC okuma + liveness
        // bitene kadar yaşamalı; yenilenmesi NFC'nin baştan okunması demektir. Eski 5 dk gerçek
        // kullanıcılarda yetmiyordu — ilk kez deneyen bir kullanıcı 5 dk 34 sn'de bitirip 34 saniyeyle
        // reddedildi (2026-08-21). 15 dk, sistemdeki diğer nonce/QR TTL'leriyle (900s) hizalıdır.
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var diff = now - payload.Timestamp;
        const long MAX_AGE_SECONDS = 15 * 60; // 15 dakika
        
        // Süre aşımı ile ileri-saat AYRI durumlardır ve ayrı raporlanırlar: birincisi kullanıcının
        // akışı 15 dk'da bitirememesidir (beklenen davranış, izlenecek bir arıza yok), ikincisi
        // cihaz saatinin ileri olmasıdır (gerçek anomali — bkz. enclave saat kayması vakaları).
        // Tek kodda birleştirildikleri sürece ikisi de Sentry'de aynı uyarıyı üretiyordu.
        if (diff > MAX_AGE_SECONDS)
        {
            throw new NonceExpiredException(diff, MAX_AGE_SECONDS);
        }
        if (diff < 0)
        {
            throw new InvalidOperationException($"Nonce zaman damgası gelecekte: cihaz saati {-diff}s ileri.");
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
    /// <summary>MiniFASNetV2 çıktısı — 3-sınıf softmax + P(live). Ölçüm satırına yazılır.</summary>
    internal readonly record struct AntiSpoofResult(float PLive, float C0, float C1, float C2);

    /// <param name="crop">
    /// Değerlendirilecek adayın KENDİ 2,7× kırpması. Benzerliğin geldiği kareyle AYNI kareden
    /// olmalıdır (K6) — çağıran taraf bunu garanti eder.
    /// </param>
    /// <param name="label">Teşhis satırındaki aday etiketi (çok adaylı akışta hangisi olduğu).</param>
    /// <param name="payload">
    /// Kayıt akışının yükü — YALNIZ <paramref name="crop"/> verilmediğinde okunur. Giriş yolunda
    /// SecurePayload YOKTUR (referans ticket'tan gelir, K4) → null geçilir, crop zorunlu olur.
    /// </param>
    internal AntiSpoofResult EnforceAntiSpoof(SecurePayload? payload, DiagLog diag, string? crop = null, string? label = null)
    {
        var step = label is null ? "AntiSpoof" : $"AntiSpoof {label}";
        crop ??= payload?.AntiSpoofCrop;

        diag.Begin(step);

        if (!_antiSpoof.IsModelLoaded)
        {
            diag.Fail(step, "model yüklü değil");
            throw new RegistrationException(RegistrationStep.BiometricVerification, "ERR_ANTISPOOFING_MODEL_MISSING",
                "Pasif canlılık modeli yüklü değil — kayıt güvenli şekilde tamamlanamaz.");
        }

        if (string.IsNullOrEmpty(crop))
            throw new RegistrationException(RegistrationStep.BiometricVerification, "ERR_ANTISPOOFING",
                "Anti-spoof crop eksik — pasif canlılık doğrulaması atlanamaz.");

        float pLive, c0 = 0f, c1 = 0f, c2 = 0f;
        try
        {
            byte[] cropBytes = Convert.FromBase64String(crop);
            float[] probs = _antiSpoof.Predict(cropBytes);
            // Live = indeks 1 (etiketli referansla doğrulandı: ham-BGR girdide real→idx1≈0.99, fake→≈0.00).
            pLive = probs.Length > 1 ? probs[1] : 0f;
            c0 = probs.Length > 0 ? probs[0] : 0f;
            c1 = probs.Length > 1 ? probs[1] : 0f;
            c2 = probs.Length > 2 ? probs[2] : 0f;
            string breakdown = probs.Length >= 3 ? $" [c0={probs[0]:P1} c1={probs[1]:P1} c2={probs[2]:P1}]" : "";
            diag.Ok(step, $"P(live)={Math.Round(pLive * 100, 1)}%{breakdown}");
        }
        catch (Exception ex)
        {
            // Bozuk base64 / çözülemeyen JPEG / çıkarım hatası → FAIL-CLOSED (eskiden yutuluyordu).
            diag.Fail(step, ex.Message);
            Console.WriteLine($"[Enclave] Anti-spoof girdi/çıkarım hatası — kayıt REDDEDİLDİ: {ex.Message}");
            throw new RegistrationException(RegistrationStep.BiometricVerification, "ERR_ANTISPOOFING",
                "Pasif canlılık doğrulaması yapılamadı (geçersiz veya işlenemeyen anti-spoof verisi).");
        }

        if (pLive < AntiSpoofService.LiveThreshold)
            throw new RegistrationException(RegistrationStep.BiometricVerification, "ERR_ANTISPOOFING",
                $"Canlı yüz tespit edilemedi (P={pLive:F3}).")
            {
                PLive = pLive, C0 = c0, C1 = c1, C2 = c2,
            };

        return new AntiSpoofResult(pLive, c0, c1, c2);
    }


    // ── GİRİŞ: CANLI YÜZ KAPISI ───────────────────────────────────────────────

    /// <summary>
    /// Giriş anında canlı yüz kanıtını zorlar: bilete mühürlü yüz referansı ile gelen selfie'nin
    /// benzerliği + AYNI karenin pasif canlılık kontrolü. Kayıt yolundaki kapının giriş karşılığıdır
    /// ve ondan HİÇBİR eşik farkı taşımaz (<see cref="BiometricThreshold"/> / 0.55 ortaktır).
    ///
    /// Atlama yolu YALNIZ demo biletleri içindir ve bir istemci beyanına değil, MAC ile mühürlenmiş
    /// payload'a dayanır: <see cref="DemoRegisterAsync"/> gerçek çip görmediği için FaceRefJpegB64'ü
    /// hiç set etmez, dolayısıyla demo biletlerin referansı YAPISAL olarak boştur.
    ///
    /// 🔴 K6: selfie ile anti-spoof kırpması AYNI KAREDEN gelmek zorundadır — benzerlik bir kareden,
    /// canlılık başkasından alınırsa (fotoğraf tut + kendi yüzünü göster) gerçek bir açık doğar.
    /// Enclave bunu doğrulayamaz; garantiyi istemci verir ve tek gövdede tek kare taşıyan kontrat
    /// (<see cref="LoginFaceProof"/>) bunu yapısal olarak dayatır.
    ///
    /// 🔴 K4: referans BİLETTEN okunur, FlowEmbeddingCache'ten DEĞİL — giriş yolu durumsuzdur.
    /// </summary>
    internal void EnforceLoginFaceProof(TicketPayload ticket, LoginFaceProof? proof, DiagLog diag)
    {
        var hasFaceRef = !string.IsNullOrEmpty(ticket.FaceRefJpegB64);

        if (!hasFaceRef)
        {
            // Referans yok. TEK meşru sebep demo bilettir; gerçek TCKN taşıyan referanssız bir bilet
            // ya eski bir kayıttan ya da bir hatadan gelir → kontrol sessizce kalkmasın diye REDDET.
            if (ticket.TCKN == DemoTckn)
            {
                diag.Ok("Login Face", "atlandı (demo bileti — yüz referansı yapısal olarak yok)");
                return;
            }

            diag.Fail("Login Face", "bilette yüz referansı yok (demo değil)");
            throw new LoginFaceMismatchException(
                "Bu kimlik kaydı canlı yüz doğrulamasını desteklemiyor. Lütfen kimliğinizi yeniden ekleyin.");
        }

        if (proof == null || string.IsNullOrEmpty(proof.UserSelfie))
        {
            // Bilet referans taşıyor ama istek kare getirmedi → eski istemci veya kapıyı atlama denemesi.
            diag.Fail("Login Face", "face_proof eksik (bilette referans VAR)");
            throw new LoginFaceMismatchException(
                "Giriş için canlı yüz doğrulaması gerekiyor. Lütfen uygulamayı güncelleyin ve tekrar deneyin.");
        }

        // Cihaz ölçüleri DOĞRULANMAZ — yalnız teşhis satırına düşer (uç kimlik doğrulaması istemez,
        // gövdeden gelen sayıya güvenilmez). Cihaz skoru enclave skoruyla KIYASLANAMAZ: farklı model.
        if (proof.DeviceMetrics?.DeviceMatchScore is int dms)
            diag.Info($"Login Device: match={dms}% (doğrulanmadı, yalnız ölçüm)");

        float score;
        diag.Begin("Biometric Login");
        try
        {
            var refBytes = Convert.FromBase64String(ticket.FaceRefJpegB64);
            var probeBytes = Convert.FromBase64String(proof.UserSelfie);

            // Referans, kayıt anında SOD-doğrulanmış DG2'den ÇIKARILMIŞ yüz görüntüsüdür
            // (bkz. RegisterAsync — Dg2FaceExtractor sonucu bilete yazılır) → tekrar çıkarma YOK.
            score = _biometricService.VerifyFaceParallel(refBytes, probeBytes);
        }
        catch (Exception ex)
        {
            // Bozuk base64 / çözülemeyen görüntü / çıkarım hatası → FAIL-CLOSED.
            diag.Fail("Biometric Login", ex.GetType().Name);
            var reason = !_biometricService.IsModelLoaded
                ? "Biyometrik model yüklü değil — giriş güvenli şekilde tamamlanamaz."
                : "Canlı yüz doğrulaması yapılamadı (geçersiz veya işlenemeyen görüntü verisi).";
            throw new LoginFaceMismatchException(reason);
        }

        // Biçim register'daki "Biometric: Score=..%" satırıyla AYNI: bu satırlar relay loguna düşüyor
        // ve şu an giriş kapısının TEK ölçüm kaynağı — biçimi değiştirmek mevcut sorguları kırar.
        diag.Ok("Biometric Login", $"Score={Math.Round(score * 100, 1)}%");

        if (score < BiometricThreshold)
        {
            // Skor mesaja YAZILMAZ: bu metin relay üzerinden Sentry'ye ve verification_logs'a gider.
            Console.WriteLine($"[Enclave] Giriş yüz eşleşmesi BAŞARISIZ: {score:0.00} < {BiometricThreshold:0.00}");
            throw new LoginFaceMismatchException(
                "Yüzünüz bu kimliği ekleyen kişiyle eşleşmedi. Doğrulamayı yalnız kimliğin sahibi tamamlayabilir.");
        }

        // Pasif canlılık — AYNI karenin kırpmasıyla, kayıt yolundaki fail-closed davranışın AYNISI
        // (model yok / kırpma bozuk / çıkarım patladı / P(live) düşük → REDDET; sessiz geçme YOK).
        // Girişte JEST YOKTUR: giriş ~2 saniyede bitmeli, yoksa 2FA/step-up kullanım alanı ölür.
        // payload=null: giriş yolunda SecurePayload yoktur, crop doğrudan verilir.
        EnforceAntiSpoof(null, diag, proof.AntiSpoofCrop, "Login");
    }

    // --- ACTIVE AUTHENTICATION (Chip Clone Protection) ---

    /// <summary>
    /// ICAO Active Authentication doğrulaması. Başarıda kartın AA profilini döner (yapısal, PII'sız
    /// — bkz. <see cref="RegistrationException.Diagnostic"/>); başarısızlıkta aynı profili taşıyan
    /// <see cref="ActiveAuthException"/> fırlatır.
    ///
    /// Profil ŞART: üretim enclave'i debug modda değil, `Console.WriteLine` hiçbir yerde görünmüyor.
    /// Bir kart AA'dan geçemezse elimizdeki tek kanıt bu satır olacak ve kartı tekrar isteyemeyeceğiz.
    /// Profil hangi ISO 9796-2 varyantının kullanıldığını TEK denemede belli eder: anahtar algoritması
    /// ve bit uzunluğu, imza/DG uzunlukları, çözülen bloğun başlık ve trailer baytları. Bunların
    /// hiçbiri kartı ya da kişiyi tanımlamaz — açık anahtarın veya imzanın KENDİSİ karta özgü ve
    /// ilişkilendirilebilir olurdu, o yüzden ASLA yazılmaz.
    /// </summary>
    internal string VerifyActiveAuth(SecurePayload payload)
    {
        Console.WriteLine("[Enclave] Aktif Kimlik Doğrulama kontrol ediliyor (ISO 9796-2)...");
        
        // AA ZORUNLU: VerifyBlind yalnızca çip-doğrulamalı (Active Authentication destekli)
        // belgeleri kabul eder. DG15 (public key) VEYA Aktif İmza eksikse → REDDET.
        // Eski "desteklemeyen kart için atla" davranışı bir downgrade açığıydı: saldırgan
        // DG15'i hiç göndermeyerek klon-korumasını atlayabiliyordu (2026-06-09 kapatıldı).
        if (string.IsNullOrEmpty(payload.DG15) || string.IsNullOrEmpty(payload.ActiveSig))
        {
            Console.WriteLine("[Enclave] AA verisi eksik (DG15 ve/veya Aktif İmza). Çip doğrulaması yapılamıyor — RED.");
            throw new ActiveAuthException("Aktif Kimlik Doğrulama Başarısız: Bu belge çip doğrulamasını (Active Authentication) desteklemiyor ya da NFC okuması eksik.")
            {
                Profile = $"missing,dg15:{payload.DG15?.Length ?? 0}ch,sig:{payload.ActiveSig?.Length ?? 0}ch"
            };
        }
        
        // Anti-Downgrade: If DG15 exists, AA MUST be performed
        if (!string.IsNullOrEmpty(payload.DG15) && string.IsNullOrEmpty(payload.ActiveSig))
        {
             throw new ActiveAuthException("Aktif Kimlik Doğrulama Başarısız: DG15 (Public Key) mevcut, ancak Aktif İmza EKSİK.")
             {
                 Profile = "missing,sig:0ch"
             };
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
            // Challenge nonce'tan türer; uzunluk dışında hiçbir şey loglanmaz (nonce oturuma özgüdür).
            throw new ActiveAuthException("Aktif Doğrulama Başarısız: Challenge nonce ile uyuşmuyor.")
            {
                Profile = $"challenge-mismatch,got:{actualChallenge.Length}B,want:{expectedChallenge.Length}B"
            };
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
            
            // Algoritma OID'i düşük kardinaliteli bir kuşak göstergesidir (kişiye bağlanamaz) ve
            // kart EC anahtara geçerse tek bakışta anlaşılmasını sağlar.
            var algOid = keyInfo.Algorithm.Algorithm.Id;

            if (bcPubKey is not Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsaKey)
            {
                throw new ActiveAuthException($"Aktif Kimlik Doğrulama Başarısız: Public Key RSA değil ({bcPubKey.GetType().Name}). Bu Enclave yalnızca RSA desteklemektedir.")
                {
                    Profile = $"alg:{algOid},key:{bcPubKey.GetType().Name},dg15:{dg15Bytes.Length}B,sig:{fullResponse.Length}B"
                };
            }

            Console.WriteLine($"[Enclave] AA RSA Anahtar Boyutu: {rsaKey.Modulus.BitLength} bit");
            var profile = $"alg:RSA,bits:{rsaKey.Modulus.BitLength},dg15:{dg15Bytes.Length}B,sig:{fullResponse.Length}B";

            // Çipin INTERNAL AUTHENTICATE yanıtı tam modül uzunluğundadır; bazı okuyucular başa ek
            // bayt koyabilir → sondaki keyLen baytı alınır. (BitLength 8'in katı olmayabilir; yukarı
            // yuvarlanmazsa geçerli bir imzanın İLK baytı kırpılır ve doğrulama sessizce çöker.)
            int keyLenBytes = (rsaKey.Modulus.BitLength + 7) / 8;
            byte[] activeSigBytes = fullResponse.Length > keyLenBytes
                ? fullResponse.Skip(fullResponse.Length - keyLenBytes).ToArray()
                : fullResponse;

            // ICAO Doc 9303 Part 11 §6.1 — Active Authentication, ISO 9796-2 Şema 1 (kısmi kurtarma):
            //     F = 6A || M1 || Hash(M1 ‖ challenge) || Trailer
            // M1 çipin rastgelesidir (RND.ICC); challenge M1'İN İÇİNDE YER ALMAZ, yalnızca hash
            // girdisidir. Doğrulama bu yüzden "kurtarılan M1'in ardına challenge'ı ekle" şeklinde
            // yapılmalıdır (UpdateWithRecoveredMessage + BlockUpdate). İmzayı tek başına
            // VerifySignature'a vermek GEÇERLİ kart imzalarını da reddeder.
            //
            // Hash + trailer kartın kuşağına göre değişir (0xBC = örtük tek bayt; 0x33CC/0x34CC =
            // açık iki bayt). Tümü denenir: 2026-08-21'e kadar yalnızca SHA-256 + açık trailer
            // kabul ediliyordu, diğer TC kimlik kuşakları "İmza formatı tanınmıyor" ile REDDEDİLDİ
            // (Sentry VERIFYBLIND-API-E — istemci aynı imzayı DG15 ile yerelde doğrulamıştı).
            foreach (var digestName in new[] { "SHA-1", "SHA-256", "SHA-224", "SHA-384", "SHA-512" })
            {
                foreach (var implicitTrailer in new[] { true, false })
                {
                    try
                    {
                        var signer = new Org.BouncyCastle.Crypto.Signers.Iso9796d2Signer(
                            new Org.BouncyCastle.Crypto.Engines.RsaEngine(),
                            Org.BouncyCastle.Security.DigestUtilities.GetDigest(digestName),
                            implicitTrailer);
                        signer.Init(false, rsaKey);
                        signer.UpdateWithRecoveredMessage(activeSigBytes);              // M1 = RND.ICC
                        signer.BlockUpdate(actualChallenge, 0, actualChallenge.Length); // M2 = challenge
                        if (signer.VerifySignature(activeSigBytes))
                        {
                            var trailerName = implicitTrailer ? "implicit" : "explicit";
                            Console.WriteLine($"[Enclave] Aktif Kimlik Doğrulama DOĞRULANDI " +
                                $"(ISO 9796-2, {digestName}, {trailerName} trailer) ✓");
                            // Başarıda da profil dönülür: hangi varyantların sahada GERÇEKTEN
                            // kullanıldığını bilmek, bir sonraki hatayı teşhis etmenin temeli.
                            return $"{profile},match:iso9796-2/{digestName}/{trailerName}";
                        }
                    }
                    catch { /* bu hash/trailer bileşimi değil — sıradakini dene */ }
                }
            }

            // (KALDIRILDI 2026-08-21) "Manuel kurtarma" geri düşüşleri:
            //   • çözülen bloğun İÇİNDE challenge arama — hash'i HİÇ doğrulamıyordu ve gerçek AA
            //     imzalarında challenge zaten blokta bulunmaz (yalnız hash girdisidir),
            //   • trailer=2 bayt + hash=32 bayt VARSAYAN elle hash kontrolü — SHA-256/açık-trailer
            //     dışındaki her geçerli kartı reddediyordu (bu hatanın kaynağı).
            // İkisi de yukarıdaki standart doğrulamanın eksik/kusurlu kopyalarıydı.

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
                     return $"{profile},match:pkcs1/SHA-256";
                }
                
                // (KALDIRILDI) Variant B "Simülasyon Modu" — challenge'ın base64 string'i üzerinden
                // PKCS#1 doğrulaması yalnızca yazılım simülatörü içindi ve üretimde sahte-kart
                // kabul yolu oluşturuyordu (2026-06-09 silindi). Gerçek kartlar buna ihtiyaç duymaz.
            }
            catch { /* Ignore fallback errors */ }

            // Hiçbir varyant tutmadı. TEŞHİS AMAÇLI ham RSA çözümü: bloğun başlık ve trailer baytları
            // hangi şemanın kullanıldığını söyler (0x6A/0x4A = ISO 9796-2 başlığı; 0xBC = örtük
            // trailer, 0x33CC/0x34CC/... = açık trailer + hash kimliği). Bu bir KABUL YOLU DEĞİLDİR —
            // yalnız profile yazılır; blok içeriği (M1 rastgelesi, hash) hiçbir zaman loglanmaz.
            var blockInfo = "blk:n/a";
            try
            {
                var rawEngine = new Org.BouncyCastle.Crypto.Engines.RsaEngine();
                rawEngine.Init(false, rsaKey);
                var decrypted = rawEngine.ProcessBlock(activeSigBytes, 0, activeSigBytes.Length);
                blockInfo = decrypted.Length >= 3
                    ? $"blk:{decrypted.Length}B,hdr:{decrypted[0]:X2},tr:{decrypted[^2]:X2}{decrypted[^1]:X2}"
                    : $"blk:{decrypted.Length}B";
            }
            catch (Exception rawEx)
            {
                blockInfo = $"blk:err/{rawEx.GetType().Name}";
            }

            throw new ActiveAuthException("Aktif Kimlik Doğrulama BAŞARISIZ: İmza formatı tanınmıyor veya geçersiz. Chip özgünlüğü doğrulanamıyor.")
            {
                Profile = $"{profile},{blockInfo},match:none"
            };
        }
        catch (ActiveAuthException)
        {
            throw; // AA'ya özgü hatalar profilleriyle birlikte yukarı çıkar
        }
        catch (Exception ex)
        {
            // Beklenmeyen hata (DG15 ayrıştırılamadı, base64 bozuk, anahtar içe aktarılamadı...).
            // İstisna TÜRÜ yapısaldır ve teşhis için kritiktir; mesajı serbest metin olduğu için
            // profile GİRMEZ (yalnız TechnicalDetail'e, o da Sentry'ye çıkmaz).
            Console.WriteLine($"[Enclave] AA Doğrulama Hatası: {ex.Message}");
            throw new ActiveAuthException($"Aktif Kimlik Doğrulama KRİTİK HATA: {ex.Message}")
            {
                Profile = $"parse-error:{ex.GetType().Name}"
            };
        }
    }
    
    /// <summary>
    /// Tanımlayıcı hash/anahtar değerlerini loga yazarken ilk 8 karaktere indirger.
    /// Teşhis için (eşleşiyor mu / uyuşmuyor mu) yeter; oturumlar arası ilişkilendirmeye yetmez.
    /// </summary>
    private static string Mask8(string? value) =>
        string.IsNullOrEmpty(value) ? "-" : (value.Length <= 8 ? value : value[..8] + "..");

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
    
    // --- ADAY DEĞERLENDİRME (final register) ---

    /// <summary>
    /// Yükteki adayları sırayla TAM kapıdan geçirir; ilk GEÇEN kazanır.
    ///
    /// <para><b>Sıra (K5):</b> önce istemcinin en iyi seçtiği kare (rank 1), sonra enclave'in
    /// streaming'de onayladığı kare (rank 2). Gerekçe VERİ KALİTESİ: hep sınırdaki kareyi
    /// değerlendirirsek loglar "herkes kıl payı geçiyor" gibi görünür ve eşik kararlarını bozuk
    /// bir dağılıma bakarak veririz.</para>
    ///
    /// <para><b>Tam kapı (K6):</b> her aday KENDİ selfie'si ve KENDİ 2,7× kırpmasıyla bir bütün
    /// olarak değerlendirilir. Benzerliği bir adaydan, canlılığı başkasından almak gerçek bir
    /// açıktır: saldırgan gerçek yüzü benzerliğe, canlı kırpmayı anti-spoof'a verirdi.</para>
    ///
    /// <para><b>Kontrol kaldırılmadı (K3):</b> geçen aday hem benzerliği hem canlılığı KENDİ
    /// geçer; ikisi de bugünkü eşikler ve bugünkü fail-closed davranışla uygulanır. Hiçbir aday
    /// geçemezse akış bugünkü gibi reddedilir.</para>
    ///
    /// <para>Aday listesi boşsa eski tek-fotoğraf yolu çalışır (geriye dönük uyumlu: streaming
    /// göndermeyen eski istemciler aynen kayıt olur).</para>
    /// </summary>
    /// <returns>Kazanan adayın benzerlik skoru + HER adayın sonucu (ölçüm satırları için).</returns>
    internal (float faceScore, List<CandidateOutcome> outcomes) EvaluateCandidates(SecurePayload payload, DiagLog diag)
    {
        var candidates = BuildCandidateList(payload);
        var outcomes = new List<CandidateOutcome>(candidates.Count);

        // Son başarısızlık saklanır: hiçbir aday geçmezse kullanıcıya dönecek hata budur.
        // 1. aday reddi 2. adayın da reddiyle sonuçlanırsa kullanıcı yine tek ve net bir hata
        // görür — "iki fotoğraf denendi" ayrıntısı ona bir şey söylemez.
        RegistrationException? lastFailure = null;

        for (int i = 0; i < candidates.Count; i++)
        {
            var candidate = candidates[i];
            var label = $"Aday {candidate.Rank}";

            float score;
            try
            {
                diag.Begin($"Biometric {label}");
                score = VerifyBiometricMatchParallel(payload, candidate.UserSelfie);
                diag.Ok($"Biometric {label}", $"Score={Math.Round(score * 100, 1)}%");
            }
            catch (Exception ex)
            {
                diag.Fail($"Biometric {label}", ex.Message);
                Console.WriteLine($"[Enclave] [{RegistrationStep.BiometricVerification}] {label} başarısız: {ex.Message}");
                var bioCode = !_biometricService.IsModelLoaded ? "ERR_BIOMETRIC_MODEL_MISSING" : "ERR_BIOMETRIC_MISMATCH";
                var rejectScore = (ex as BiometricMismatchException)?.Score;
                outcomes.Add(new CandidateOutcome
                {
                    Rank = candidate.Rank,
                    MatchScore = rejectScore.HasValue ? Math.Round(rejectScore.Value, 4) : 0,
                    Outcome = FrameOutcomes.FailSimilarity,
                });
                lastFailure = new RegistrationException(RegistrationStep.BiometricVerification, bioCode, ex.Message)
                {
                    FaceScore = rejectScore
                };
                continue;
            }

            // Canlılık AYNI adayın kırpmasıyla — fail-closed davranış aynen korunur.
            AntiSpoofResult live;
            try
            {
                live = EnforceAntiSpoof(payload, diag, candidate.AntiSpoofCrop, label);
            }
            catch (RegistrationException ex)
            {
                outcomes.Add(new CandidateOutcome
                {
                    Rank = candidate.Rank,
                    MatchScore = Math.Round(score, 4),
                    PLive = Math.Round(ex.PLive ?? 0, 4),
                    C0 = Math.Round(ex.C0 ?? 0, 4),
                    C1 = Math.Round(ex.C1 ?? 0, 4),
                    C2 = Math.Round(ex.C2 ?? 0, 4),
                    Outcome = FrameOutcomes.FailLiveness,
                });
                lastFailure = ex;
                continue;
            }

            // Bu aday HER İKİ kapıyı da KENDİ geçti → kazanan.
            outcomes.Add(new CandidateOutcome
            {
                Rank = candidate.Rank,
                MatchScore = Math.Round(score, 4),
                PLive = Math.Round(live.PLive, 4),
                C0 = Math.Round(live.C0, 4),
                C1 = Math.Round(live.C1, 4),
                C2 = Math.Round(live.C2, 4),
                Outcome = FrameOutcomes.Pass,
            });

            // ⚠️ Kalan adaylar DEĞERLENDİRİLMEZ ama ölçüm kaybı yok: sıra gereği kalan aday
            // sınırdaki karedir ve zaten streaming satırlarında kare kare kayıtlıdır.
            if (i < candidates.Count - 1)
                diag.Info($"{label} geçti — kalan aday değerlendirilmedi.");

            return (score, outcomes);
        }

        // Hiçbir aday geçemedi → bugünkü davranış: reddet. Aday sonuçları istisnayla TAŞINIR:
        // reddedilen kareler ölçümün asıl konusudur, red yolunda düşürülemezler.
        if (lastFailure is not null)
            throw new RegistrationException(lastFailure.Step, lastFailure.ErrorCode, lastFailure.TechnicalDetail)
            {
                FaceScore = lastFailure.FaceScore,
                PLive = lastFailure.PLive,
                C0 = lastFailure.C0,
                C1 = lastFailure.C1,
                C2 = lastFailure.C2,
                IssuingCountry = lastFailure.IssuingCountry,
                Diagnostic = lastFailure.Diagnostic,
                CandidateOutcomes = outcomes,
            };

        throw new RegistrationException(
            RegistrationStep.BiometricVerification, "ERR_BIOMETRIC_MISMATCH", "Değerlendirilebilir aday yok.")
        {
            CandidateOutcomes = outcomes,
        };
    }

    /// <summary>
    /// Yükten aday listesini kurar: en fazla İKİ aday, rank sırasına göre.
    ///
    /// Aday yoksa eski tek-fotoğraf alanlarından (<see cref="SecurePayload.UserSelfie"/> +
    /// <see cref="SecurePayload.AntiSpoofCrop"/>) tek adaylık liste üretilir — streaming
    /// göndermeyen istemciler için davranış birebir aynı kalır.
    ///
    /// ⚠️ TAVAN İKİ: uç kimlik doğrulaması istemez ve her aday iki ONNX çıkarımı demektir;
    /// sınırsız aday, register'ı ucuz bir CPU tüketim yüzeyine çevirirdi.
    /// </summary>
    internal static List<RegistrationCandidate> BuildCandidateList(SecurePayload payload)
    {
        const int maxCandidates = 2;

        if (payload.Candidates is { Count: > 0 })
        {
            var list = payload.Candidates
                .Where(c => !string.IsNullOrEmpty(c.UserSelfie))
                .OrderBy(c => c.Rank)
                .Take(maxCandidates)
                .ToList();

            if (list.Count > 0) return list;
        }

        return
        [
            new RegistrationCandidate
            {
                Rank = 1,
                UserSelfie = payload.UserSelfie,
                AntiSpoofCrop = payload.AntiSpoofCrop,
            }
        ];
    }

    // --- CANLI BENZERLİK AKIŞI (streaming) ---
    //
    // ⚠️ Bu bölüm ÖLÇÜM içindir ve register akışını HİÇBİR şekilde etkilemez. Register durumsuz
    // kalır: buradaki önbelleğe bakmaz, buradaki "geçti" kararına güvenmez. Streaming tamamen
    // kapatılsa kayıt aynen çalışır (K4).

    /// <summary>
    /// Akış başı hazırlık: DG2'den ArcFace gömme vektörünü hesaplayıp akış numarasıyla RAM'de
    /// önbelleğe alır. Sonraki karelerde DG2 bir daha gönderilmez.
    ///
    /// ⚠️ Burada PASSIVE AUTH YAPILMAZ ve YAPILMASI GEREKMEZ: bu yol yalnız bir SAYI üretir,
    /// hiçbir ticket imzalamaz. Doğrulanmamış bir DG2 gönderen istemci yalnız kendi kendine
    /// yanlış bir benzerlik skoru gösterir; final register DG2'yi SOD'a karşı bugünkü gibi
    /// yeniden doğrular ve o kapıdan geçemez.
    /// </summary>
    public void StreamingPrepare(StreamingPrepareRequest request, DiagLog diag)
    {
        if (!Guid.TryParse(request.FlowId, out _))
            throw new InvalidOperationException("Geçersiz akış numarası.");

        var aesKeyBase64 = _enclaveKeys.DecryptWithEnclaveKey(request.EncryptedKey);
        var payloadJson = CryptoUtils.AesDecrypt(request.AesBlob, aesKeyBase64);
        var payload = JsonSerializer.Deserialize<StreamingPreparePayload>(payloadJson)
            ?? throw new InvalidOperationException("Prepare yükü çözülemedi.");

        if (string.IsNullOrEmpty(payload.DG2))
            throw new InvalidOperationException("DG2 eksik.");

        // Register ile AYNI boru hattı: ham DG2'den gömülü JPEG çıkarılır, YuNet ile hizalanır.
        // Aynı olması şart — farklı bir çıkarma yolu, streaming'in "geçti" dediği kareyi
        // register'ın reddetmesine yol açardı.
        var faceBytes = Dg2FaceExtractor.ExtractFaceImage(Convert.FromBase64String(payload.DG2));
        var embedding = _biometricService.ComputeEmbedding(faceBytes);

        _flowEmbeddings.Store(request.FlowId, embedding);
        diag.Ok("StreamingPrepare", $"embedding={embedding.Length}d, önbellek={_flowEmbeddings.Count}");
    }

    /// <summary>
    /// Tek kare değerlendirmesi: benzerlik (selfie ↔ önbellekteki DG2 gömmesi) + canlılık
    /// (aynı karenin 2,7× kırpması). İkisi de AYNI kareden gelir (K6).
    ///
    /// Register'dan farkı: burada hiçbir şey reddedilmez, yalnız ÖLÇÜLÜR. Anti-spoof düşse bile
    /// istisna fırlatılmaz — sonuç <c>fail_liveness</c> olarak döner ve satır yazılır. Kare kare
    /// P(live) yörüngesi, 24 Ağustos'taki %46,2 anomalisinin hangi koşulda oluştuğunu
    /// gösterebilecek TEK veri.
    /// </summary>
    public StreamingCheckResponse StreamingCheck(StreamingCheckRequest request, DiagLog diag)
    {
        if (!Guid.TryParse(request.FlowId, out _))
            throw new InvalidOperationException("Geçersiz akış numarası.");

        var chipEmbedding = _flowEmbeddings.Get(request.FlowId)
            ?? throw new InvalidOperationException("Akış referansı yok ya da süresi doldu (prepare gerekli).");

        var aesKeyBase64 = _enclaveKeys.DecryptWithEnclaveKey(request.EncryptedKey);
        var payloadJson = CryptoUtils.AesDecrypt(request.AesBlob, aesKeyBase64);
        var payload = JsonSerializer.Deserialize<StreamingCheckPayload>(payloadJson)
            ?? throw new InvalidOperationException("Kare yükü çözülemedi.");

        if (string.IsNullOrEmpty(payload.UserSelfie))
            throw new InvalidOperationException("Selfie eksik.");

        var selfieEmbedding = _biometricService.ComputeEmbedding(Convert.FromBase64String(payload.UserSelfie));
        var similarity = _biometricService.CosineSimilarity(chipEmbedding, selfieEmbedding);
        var similarityPassed = similarity >= BiometricThreshold;

        // Canlılık ölçümü — register'dan farklı olarak FIRLATMAZ. Girdi bozuksa ya da model
        // yüklü değilse P(live)=0 ile "ölçülemedi" kaydedilir; streaming bir kapı değil bir
        // ölçüm aracıdır ve telemetri asla akışı bozmaz.
        float pLive = 0f, c0 = 0f, c1 = 0f, c2 = 0f;
        try
        {
            if (_antiSpoof.IsModelLoaded && !string.IsNullOrEmpty(payload.AntiSpoofCrop))
            {
                var probs = _antiSpoof.Predict(Convert.FromBase64String(payload.AntiSpoofCrop));
                c0 = probs.Length > 0 ? probs[0] : 0f;
                c1 = probs.Length > 1 ? probs[1] : 0f;
                c2 = probs.Length > 2 ? probs[2] : 0f;
                pLive = c1;
            }
        }
        catch (Exception ex)
        {
            diag.Info($"StreamingCheck anti-spoof ölçülemedi: {ex.GetType().Name}");
        }

        var livePassed = pLive >= AntiSpoofService.LiveThreshold;

        // Sonuç sırası benzerlik önce: "yüz tutmadı" ile "canlı değil" bambaşka iki düzeltme ve
        // ikisi aynı anda düştüğünde önce sorulan soru benzerliktir.
        var outcome = !similarityPassed ? FrameOutcomes.FailSimilarity
                    : !livePassed       ? FrameOutcomes.FailLiveness
                                        : FrameOutcomes.Pass;

        diag.Ok("StreamingCheck",
            $"seq={request.Seq} match={similarity * 100:0.0}% P(live)={pLive * 100:0.0}% → {outcome}");

        return new StreamingCheckResponse
        {
            // ⚠️ Cihaza YALNIZ benzerlik kararı bildirilir. Anti-spoof kararı submit kapısına
            // GİRMEZ: register'daki canlılık kontrolü fail-closed ve orada zaten uygulanıyor;
            // burada uygulamak, ölçmek için eklediğimiz yolu ikinci bir kapıya çevirirdi.
            SimilarityPassed = similarityPassed,
            MatchScore = Math.Round(similarity, 4),
            PLive = Math.Round(pLive, 4),
            C0 = Math.Round(c0, 4),
            C1 = Math.Round(c1, 4),
            C2 = Math.Round(c2, 4),
            Outcome = outcome,
        };
    }

    /// <summary>Akış bitti — gömme vektörünü RAM'den hemen sil (TTL'i bekleme).</summary>
    public void StreamingRelease(string flowId) => _flowEmbeddings.Remove(flowId);

    // --- BIOMETRIC VERIFICATION ---

    /// <param name="selfieBase64">
    /// Değerlendirilecek adayın KENDİ selfie'si. Verilmezse yükün tek-fotoğraf alanı kullanılır
    /// (streaming göndermeyen istemciler).
    /// </param>
    internal float VerifyBiometricMatchParallel(SecurePayload payload, string? selfieBase64 = null)
    {
        Console.WriteLine("[Enclave] Biyometrik Kimlik Eşleşmesi başlatılıyor (paralel)...");

        selfieBase64 ??= payload.UserSelfie;

        if (string.IsNullOrEmpty(payload.DG2)) throw new Exception("Biyometrik Hata: Kimlik veri grubu (DG2) eksik.");
        if (string.IsNullOrEmpty(selfieBase64)) throw new Exception("Biyometrik Hata: Kullanıcı selfie'si eksik.");

        // Kimlik fotoğrafı, Passive Authentication'ın SOD/CSCA'ya karşı doğruladığı HAM DG2'den
        // çıkarılır — telefonun ayrı gönderdiği (hiçbir şeye bağlı OLMAYAN) yeniden-kodlanmış görüntüye
        // GÜVENİLMEZ. Çağrı sırası şartı: bu metot register akışında PassiveAuth'tan SONRA çalışır,
        // dolayısıyla payload.DG2 bu noktada kriptografik olarak doğrulanmıştır. Çıkarım başarısızsa
        // fail-closed (Dg2FaceExtractor fırlatır) — asla istemci görüntüsüne geri düşülmez.
        byte[] idPhotoBytes = Dg2FaceExtractor.ExtractFaceImage(Convert.FromBase64String(payload.DG2));
        byte[] probePhotoBytes = Convert.FromBase64String(selfieBase64);

        Console.WriteLine($"[Enclave] Kimlik Fotoğrafı Boyutu: {idPhotoBytes.Length} bayt");
        Console.WriteLine($"[Enclave] Selfie Fotoğrafı Boyutu: {probePhotoBytes.Length} bayt");

        float similarity = _biometricService.VerifyFaceParallel(idPhotoBytes, probePhotoBytes);

        // ArcFace (w600k_r50) kosinüs eşiği — YuNet 5-nokta HİZALI boru hattı için kalibre edildi
        // (FaceAligner; eski 0.40 hizalamasız center-crop içindi, hizalı dağılımda çok yüksek kalırdı).
        // LFW held-out: 0.20'de FAR ~%0.16 / FRR ~%1.3. Cross-domain (DG2 chip ↔ canlı selfie) genuine
        // skorları daha düşük → muhafazakâr başlangıç; canlı histogram (biometric_face_score_percent,
        // BiometricScoreDriftLow alert) gerçek dağılımı gösterince ince ayar. Bkz
        // tools/biometric/yunet_frr_ref.py + CalibrationLfwTests (LFW_DIR gated).
        const float THRESHOLD = BiometricThreshold;

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
