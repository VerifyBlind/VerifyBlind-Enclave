using System.Security.Cryptography;
using System.Text;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using Moq;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

public class EnclaveServiceTests
{
    private readonly Mock<IEnclaveKeyService> _enclaveKeys = new();
    private readonly Mock<IKmsService> _kms = new();
    private readonly Mock<IBiometricService> _biometrics = new();
    private readonly EnclaveService _service;

    public EnclaveServiceTests()
    {
        // Setup realistic defaults
        _enclaveKeys.Setup(k => k.GetEnclavePublicKey()).Returns("fake-pub-key");
        _enclaveKeys.Setup(k => k.SignDataWithEnclaveKey(It.IsAny<string>())).Returns("fake-sig");
        _enclaveKeys.Setup(k => k.GetAttestationDocument()).Returns("fake-attestation");

        _service = new EnclaveService(_enclaveKeys.Object, _kms.Object, _biometrics.Object);
    }

    // ── Handshake ─────────────────────────────────────────────────────────────

    [Fact]
    public void Handshake_ReturnsNonceAndChallenges()
    {
        var diag = new DiagLog();
        var response = _service.Handshake(diag);

        Assert.NotNull(response);
        Assert.NotEmpty(response.Nonce);
        Assert.NotEmpty(response.NonceSignature);
        Assert.NotNull(response.Challenges);
        Assert.Equal(5, response.Challenges.Count);
    }

    [Fact]
    public void Handshake_NonceIsUniqueEachCall()
    {
        var diag = new DiagLog();
        var r1 = _service.Handshake(diag);
        var r2 = _service.Handshake(diag);

        Assert.NotEqual(r1.Nonce, r2.Nonce);
    }

    [Fact]
    public void Handshake_SignsNonceWithEnclaveKey()
    {
        var diag = new DiagLog();
        _service.Handshake(diag);

        _enclaveKeys.Verify(k => k.SignDataWithEnclaveKey(It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public void Handshake_FetchesAttestationDocument()
    {
        var diag = new DiagLog();
        var response = _service.Handshake(diag);

        _enclaveKeys.Verify(k => k.GetAttestationDocument(), Times.Once);
        Assert.Equal("fake-attestation", response.AttestationDocument);
    }

    [Fact]
    public void Handshake_ChallengesHaveNoConsecutiveDuplicates()
    {
        var diag = new DiagLog();
        var response = _service.Handshake(diag);

        for (int i = 1; i < response.Challenges.Count; i++)
            Assert.NotEqual(response.Challenges[i - 1], response.Challenges[i]);
    }

    // ── Login Handshake ───────────────────────────────────────────────────────

    [Fact]
    public void LoginHandshake_ReturnsAttestationDocument()
    {
        var diag = new DiagLog();
        var response = _service.LoginHandshake(diag);

        Assert.NotNull(response);
        Assert.Equal("fake-attestation", response.AttestationDocument);
        _enclaveKeys.Verify(k => k.GetAttestationDocument(), Times.Once);
    }

    // ── RegisterAsync helpers ─────────────────────────────────────────────────

    /// <summary>Builds an AES-encrypted RegistrationRequest with the given SecurePayload fields.</summary>
    private RegistrationRequest BuildRequest(
        string nonce, long timestamp, string nonceSignature,
        string dg1 = "", string dg15 = "", string activeSig = "",
        string sod = "", string dg2 = "", string userPubKey = "")
    {
        var payload = new VerifyBlind.Core.Models.SecurePayload
        {
            Nonce = nonce,
            Timestamp = timestamp,
            NonceSignature = nonceSignature,
            DG1 = dg1,
            DG15 = dg15,
            ActiveSig = activeSig,
            SOD = sod,
            UserPubKey = userPubKey
        };
        var json = System.Text.Json.JsonSerializer.Serialize(payload);
        var (aesCipher, aesKey, _) = VerifyBlind.Core.Crypto.CryptoUtils.AesEncrypt(json);
        _enclaveKeys.Setup(k => k.DecryptWithEnclaveKey(It.IsAny<string>())).Returns(aesKey);

        return new RegistrationRequest { EncryptedKey = "enc", AesBlob = aesCipher };
    }

    // ── RegisterAsync — error paths ───────────────────────────────────────────

    [Fact]
    public async Task RegisterAsync_RsaDecryptFails_ThrowsRegistrationExceptionStep1()
    {
        _enclaveKeys.Setup(k => k.DecryptWithEnclaveKey(It.IsAny<string>()))
            .Throws(new InvalidOperationException("Key not available"));

        var request = new RegistrationRequest { EncryptedKey = "bad", AesBlob = "bad" };
        var ex = await Assert.ThrowsAsync<RegistrationException>(() =>
            _service.RegisterAsync(request, new DiagLog()));

        Assert.Equal(RegistrationStep.RsaDecrypt, ex.Step);
    }

    [Fact]
    public async Task RegisterAsync_AesDecryptFails_ThrowsRegistrationExceptionStep2()
    {
        // RSA decrypt succeeds but returns a key that won't work for AES
        _enclaveKeys.Setup(k => k.DecryptWithEnclaveKey(It.IsAny<string>()))
            .Returns("not-a-valid-aes-key");

        var request = new RegistrationRequest { EncryptedKey = "enc", AesBlob = "bad-aes-blob" };
        var ex = await Assert.ThrowsAsync<RegistrationException>(() =>
            _service.RegisterAsync(request, new DiagLog()));

        Assert.Equal(RegistrationStep.AesDecrypt, ex.Step);
    }

    [Fact]
    public async Task RegisterAsync_DiagLogRecordsSteps()
    {
        _enclaveKeys.Setup(k => k.DecryptWithEnclaveKey(It.IsAny<string>()))
            .Throws(new InvalidOperationException("fail"));

        var diag = new DiagLog();
        try { await _service.RegisterAsync(new RegistrationRequest { EncryptedKey = "k", AesBlob = "b" }, diag); }
        catch { }

        Assert.NotEmpty(diag.Entries);
    }

    [Fact]
    public async Task RegisterAsync_NonceExpired_ThrowsNonceVerification()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var request = BuildRequest(
            nonce: "test-nonce",
            timestamp: now - 700, // 11+ minutes ago — expired
            nonceSignature: "sig");

        var ex = await Assert.ThrowsAsync<RegistrationException>(() =>
            _service.RegisterAsync(request, new DiagLog()));

        Assert.Equal(RegistrationStep.NonceVerification, ex.Step);
    }

    [Fact]
    public async Task RegisterAsync_NonceSignatureInvalid_ThrowsNonceVerification()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _enclaveKeys.Setup(k => k.VerifyEnclaveSignature(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(false);

        var request = BuildRequest(
            nonce: "test-nonce",
            timestamp: now,
            nonceSignature: "bad-sig");

        var ex = await Assert.ThrowsAsync<RegistrationException>(() =>
            _service.RegisterAsync(request, new DiagLog()));

        Assert.Equal(RegistrationStep.NonceVerification, ex.Step);
    }

    [Fact]
    public async Task RegisterAsync_Dg15PresentButActiveSignatureMissing_ThrowsActiveAuth()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _enclaveKeys.Setup(k => k.VerifyEnclaveSignature(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(true);

        var request = BuildRequest(
            nonce: "test-nonce",
            timestamp: now,
            nonceSignature: "valid-sig",
            dg15: Convert.ToBase64String(new byte[] { 0x01, 0x02 }), // DG15 present
            activeSig: ""); // ActiveSig missing

        var ex = await Assert.ThrowsAsync<RegistrationException>(() =>
            _service.RegisterAsync(request, new DiagLog()));

        Assert.Equal(RegistrationStep.ActiveAuthentication, ex.Step);
    }

    [Fact]
    public async Task RegisterAsync_NoDg15AndNoActiveSig_PassesActiveAuthAndFailsPassiveAuth()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _enclaveKeys.Setup(k => k.VerifyEnclaveSignature(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(true);

        // AA skipped (no DG15), but SOD is invalid → PassiveAuth fails
        var request = BuildRequest(
            nonce: "test-nonce",
            timestamp: now,
            nonceSignature: "valid-sig",
            dg15: "",
            activeSig: "",
            sod: Convert.ToBase64String(new byte[] { 0xFF, 0xFE }), // invalid SOD bytes
            dg1: "");

        var ex = await Assert.ThrowsAsync<RegistrationException>(() =>
            _service.RegisterAsync(request, new DiagLog()));

        Assert.Equal(RegistrationStep.PassiveAuthentication, ex.Step);
    }

    // ── LoginAsync — error paths ──────────────────────────────────────────────

    [Fact]
    public async Task LoginAsync_InvalidEncrSignedTicketJson_Throws()
    {
        var request = new LoginRequest
        {
            EncrSignedTicket = "not-valid-json",
            Nonce = Guid.NewGuid().ToString()
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.LoginAsync(request, new DiagLog()));

        Assert.NotNull(ex);
    }

    [Fact]
    public async Task LoginAsync_DecryptFails_ThrowsGirisHatasi()
    {
        _enclaveKeys.Setup(k => k.DecryptWithEnclaveKey(It.IsAny<string>()))
            .Throws(new Exception("decrypt error"));

        // Valid JSON structure but DecryptWithEnclaveKey will throw
        var encPayload = System.Text.Json.JsonSerializer.Serialize(new { enc_key = "ek", blob = "bb" });
        var request = new LoginRequest
        {
            EncrSignedTicket = encPayload,
            Nonce = Guid.NewGuid().ToString()
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.LoginAsync(request, new DiagLog()));

        Assert.Contains("şifre çözme", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LoginAsync_MissingQrPayload_Throws()
    {
        // Create a valid hybrid encrypted ticket that decrypts to a valid SignedTicket
        // Use real crypto so DecryptWithEnclaveKey returns a usable key
        var (privateKey, publicKey) = VerifyBlind.Core.Crypto.CryptoUtils.GenerateRsaKeyPair();
        var (aesCipher, aesKey, _) = VerifyBlind.Core.Crypto.CryptoUtils.AesEncrypt(
            System.Text.Json.JsonSerializer.Serialize(new
            {
                signed_ticket = new { payload = new { }, signature = "" },
                nonce = "test-nonce",
                pk_hash = "hash"
            }));

        var encKey = VerifyBlind.Core.Crypto.CryptoUtils.RsaEncrypt(aesKey, publicKey);
        _enclaveKeys.Setup(k => k.DecryptWithEnclaveKey(It.IsAny<string>()))
            .Returns(aesKey);

        var encPayload = System.Text.Json.JsonSerializer.Serialize(new { enc_key = encKey, blob = aesCipher });
        var request = new LoginRequest
        {
            EncrSignedTicket = encPayload,
            Nonce = "test-nonce",
            QrPayloadJson = null // missing QR payload
        };

        var ex = await Assert.ThrowsAsync<Exception>(() =>
            _service.LoginAsync(request, new DiagLog()));

        Assert.NotNull(ex);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a BER-TLV DG1 byte array (Tag 0x61 wrapping Tag 0x5F1F wrapping MRZ ASCII bytes)
    /// and returns it Base64-encoded.
    /// </summary>
    private static string BuildDG1Base64(string mrzString)
    {
        byte[] mrzBytes = Encoding.ASCII.GetBytes(mrzString);
        // Inner: 5F 1F [len] [mrzBytes]
        var inner = new List<byte> { 0x5F, 0x1F, (byte)mrzBytes.Length };
        inner.AddRange(mrzBytes);
        // Outer: 61 [len] [inner]
        var outer = new List<byte> { 0x61, (byte)inner.Count };
        outer.AddRange(inner);
        return Convert.ToBase64String(outer.ToArray());
    }

    /// <summary>
    /// Fictional Turkish ID card MRZ (TD1, 3×30 chars).
    /// Person: AHMET YILMAZ — DOB 1990-01-01, TCKN 12345678901 (fictional).
    /// Line 1: DocType=I<, Country=TUR, DocNo=123456789, OptData=12345678901+pad
    /// Line 2: DOB=900101, Gender=M, Expiry=301231, Nationality=TUR
    /// Line 3: YILMAZ<<AHMET
    /// </summary>
    private const string FakeTurkishTD1Mrz =
        "I<TUR123456789012345678901<<<<" +  // 30 chars — TCKN at pos 15-25
        "9001011M3012311TUR00000000<<<0" +  // 30 chars
        "YILMAZ<<AHMET<<<<<<<<<<<<<<<<<";   // 30 chars

    // ── ParseMrzDate ──────────────────────────────────────────────────────────

    [Fact]
    public void ParseMrzDate_DobOlderThan30_Returns19xxDate()
    {
        // yy=85 > 30 → 1985
        var result = _service.ParseMrzDate("850615");
        Assert.Equal(new DateTime(1985, 6, 15), result);
    }

    [Fact]
    public void ParseMrzDate_DobYoungerThan30_Returns20xxDate()
    {
        // yy=05 ≤ 30 → 2005
        var result = _service.ParseMrzDate("050322");
        Assert.Equal(new DateTime(2005, 3, 22), result);
    }

    [Fact]
    public void ParseMrzDate_ExpiryDate_Always20xx()
    {
        // isExpiry=true, yy=30 → always 2030
        var result = _service.ParseMrzDate("301231", isExpiry: true);
        Assert.Equal(new DateTime(2030, 12, 31), result);
    }

    [Fact]
    public void ParseMrzDate_WrongLength_ReturnsMinValue()
    {
        var result = _service.ParseMrzDate("9001");
        Assert.Equal(DateTime.MinValue, result);
    }

    [Fact]
    public void ParseMrzDate_InvalidMonth_ClampsTo1()
    {
        // mm=99 → clamped to 1
        var result = _service.ParseMrzDate("859901");
        Assert.Equal(new DateTime(1985, 1, 1), result);
    }

    // ── CheckAgeConstraint ────────────────────────────────────────────────────

    [Fact] public void CheckAgeConstraint_PlusFormat_AgeAboveMin_ReturnsTrue()
        => Assert.True(_service.CheckAgeConstraint(18, "18+"));

    [Fact] public void CheckAgeConstraint_PlusFormat_AgeBelowMin_ReturnsFalse()
        => Assert.False(_service.CheckAgeConstraint(17, "18+"));

    [Fact] public void CheckAgeConstraint_MinusFormat_AgeBelowMax_ReturnsTrue()
        => Assert.True(_service.CheckAgeConstraint(15, "16-"));

    [Fact] public void CheckAgeConstraint_MinusFormat_AgeAtMax_ReturnsFalse()
        => Assert.False(_service.CheckAgeConstraint(16, "16-"));

    [Fact] public void CheckAgeConstraint_RangeFormat_AgeInRange_ReturnsTrue()
        => Assert.True(_service.CheckAgeConstraint(25, "18-65"));

    [Fact] public void CheckAgeConstraint_RangeFormat_AgeBelowRange_ReturnsFalse()
        => Assert.False(_service.CheckAgeConstraint(17, "18-65"));

    [Fact] public void CheckAgeConstraint_ExactFormat_ExactMatch_ReturnsTrue()
        => Assert.True(_service.CheckAgeConstraint(24, "24"));

    [Fact] public void CheckAgeConstraint_ExactFormat_NoMatch_ReturnsFalse()
        => Assert.False(_service.CheckAgeConstraint(25, "24"));

    [Fact] public void CheckAgeConstraint_EmptyConstraint_ReturnsTrue()
        => Assert.True(_service.CheckAgeConstraint(99, ""));

    [Fact]
    public void CheckAgeConstraint_InvalidFormat_Throws()
    {
        var ex = Assert.Throws<Exception>(() => _service.CheckAgeConstraint(25, "invalid!!"));
        Assert.Contains("Invalid Age Constraint", ex.Message);
    }

    // ── Mask ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Mask_NullOrEmpty_ReturnsValue()
    {
        Assert.Equal("", _service.Mask(""));
        Assert.Null(_service.Mask(null!));
    }

    [Fact]
    public void Mask_ShortString_ReturnsStarNotation()
    {
        // Length 3 ≤ 4 → "**3**"
        var result = _service.Mask("ABC");
        Assert.StartsWith("**", result);
    }

    [Fact]
    public void Mask_NormalString_MasksMiddle()
    {
        // "ABCDEF" → "AB**EF"
        var result = _service.Mask("ABCDEF");
        Assert.StartsWith("AB", result);
        Assert.EndsWith("EF", result);
        Assert.Contains("**", result);
    }

    // ── SearchHashInSOD ───────────────────────────────────────────────────────

    [Fact]
    public void SearchHashInSOD_HashPresent_ReturnsTrue()
    {
        var hash = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        // SOD content contains this hash somewhere
        var sodContent = new byte[] { 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x03, 0x04 };
        Assert.True(_service.SearchHashInSOD(sodContent, 1, hash));
    }

    [Fact]
    public void SearchHashInSOD_HashAbsent_ReturnsFalse()
    {
        // Use SHA256-length hash (32 bytes = 64 hex chars) to avoid Substring(0,16) bug in log line
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes("not-in-content"));
        var sodContent = new byte[64]; // all zeros — hash won't match
        Assert.False(_service.SearchHashInSOD(sodContent, 1, hash));
    }

    // ── ExtractMrzFromDG1 ─────────────────────────────────────────────────────

    [Fact]
    public void ExtractMrzFromDG1_ValidTlvStructure_ReturnsMrz()
    {
        var dg1Bytes = Convert.FromBase64String(BuildDG1Base64(FakeTurkishTD1Mrz));
        var mrz = _service.ExtractMrzFromDG1(dg1Bytes);
        Assert.Equal(FakeTurkishTD1Mrz, mrz);
    }

    [Fact]
    public void ExtractMrzFromDG1_RawAsciiWithoutTlv_FallsBackToRegex()
    {
        // Raw MRZ bytes without ASN.1 wrapper → fallback regex extracts it
        var mrzBytes = Encoding.ASCII.GetBytes(FakeTurkishTD1Mrz);
        var mrz = _service.ExtractMrzFromDG1(mrzBytes);
        Assert.Equal(90, mrz.Length);
    }

    // ── GetIssuingCountryFromDG1 ──────────────────────────────────────────────

    [Fact]
    public void GetIssuingCountryFromDG1_ValidTurkishDG1_ReturnsTUR()
    {
        var dg1Base64 = BuildDG1Base64(FakeTurkishTD1Mrz);
        var country = _service.GetIssuingCountryFromDG1(dg1Base64);
        Assert.Equal("TUR", country);
    }

    [Fact]
    public void GetIssuingCountryFromDG1_InvalidBase64_ReturnsUnknown()
    {
        var country = _service.GetIssuingCountryFromDG1("not-valid-base64!!!");
        Assert.Equal("UNKNOWN", country);
    }

    // ── ParseDG1ToTicket ──────────────────────────────────────────────────────

    [Fact]
    public void ParseDG1ToTicket_TD1_TurkishCard_ExtractsAllFields()
    {
        var dg1Base64 = BuildDG1Base64(FakeTurkishTD1Mrz);
        var ticket = _service.ParseDG1ToTicket(dg1Base64, "pubkey", "TUR");

        Assert.Equal("12345678901", ticket.TCKN);
        Assert.Equal("AHMET", ticket.Ad);
        Assert.Equal("YILMAZ", ticket.Soyad);
        Assert.Equal(new DateTime(1990, 1, 1), ticket.DogumTarihi);
        Assert.Equal("M", ticket.Cinsiyet);
        Assert.Equal("TUR", ticket.Uyruk);
        Assert.Equal("pubkey", ticket.UserPubKey);
        Assert.Equal("TUR", ticket.CountryIsoCode);
    }

    [Fact]
    public void ParseDG1ToTicket_TD1_NonTurkish_NoTckn()
    {
        // German TD1 — country DEU, nationality DEU
        const string germanMrz =
            "I<DEU123456789012345678901<<<<" +
            "9001011M3012311DEU00000000<<<0" +
            "MUSTERMANN<<ERIKA<<<<<<<<<<<<<";

        var dg1Base64 = BuildDG1Base64(germanMrz);
        var ticket = _service.ParseDG1ToTicket(dg1Base64, "pk", "DEU");

        Assert.Equal("", ticket.TCKN); // no TCKN for non-TUR
        Assert.Equal("ERIKA", ticket.Ad);
        Assert.Equal("MUSTERMANN", ticket.Soyad);
    }

    [Fact]
    public void ParseDG1ToTicket_TD3_TurkishPassport_ExtractsTckn()
    {
        // TD3 = 2×44 chars. Personal number field (pos 72-85 in full MRZ) holds TCKN.
        // Line 1 (44): P<TUR + SURNAME<<GIVENNAME padded to 44 chars
        // Line 2 (44): DocNo9+Chk+Nat3+DOB6+Chk+Sex1+Exp6+Chk+PersonNo14+PersChk+Composite
        const string td3Line1 = "P<TURYILMAZ<<AHMET<<<<<<<<<<<<<<<<<<<<<<<<<<"; // P<TUR(5)+YILMAZ(6)+<<(2)+AHMET(5)+26×< = 44
        const string td3Line2 = "1234567890TUR9001011M3012316123456789017<<00"; // 44 chars

        var mrzString = td3Line1 + td3Line2;
        Assert.Equal(88, mrzString.Length);

        var dg1Base64 = BuildDG1Base64(mrzString);
        var ticket = _service.ParseDG1ToTicket(dg1Base64, "pk", "TUR");

        // Personal number at mrzString pos 72 (= td3Line2 pos 28): "12345678901 7<<" → TCKN = "12345678901"
        Assert.Equal("12345678901", ticket.TCKN);
    }

    [Fact]
    public void ParseDG1ToTicket_InvalidMrzLength_Throws()
    {
        // MRZ of 50 chars → neither TD1 nor TD3
        var shortMrz = new string('A', 50);
        var dg1Base64 = BuildDG1Base64(shortMrz);

        Assert.Throws<Exception>(() => _service.ParseDG1ToTicket(dg1Base64, "pk", "TUR"));
    }

    // ── VerifyNonce ───────────────────────────────────────────────────────────

    [Fact]
    public void VerifyNonce_ValidFreshNonce_DoesNotThrow()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _enclaveKeys.Setup(k => k.VerifyEnclaveSignature(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(true);

        var payload = new SecurePayload { Nonce = "test", Timestamp = now - 10, NonceSignature = "sig" };
        _service.VerifyNonce(payload); // must not throw
    }

    [Fact]
    public void VerifyNonce_ExpiredTimestamp_Throws()
    {
        var old = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 400; // 400s ago > 300s limit
        var payload = new SecurePayload { Nonce = "n", Timestamp = old, NonceSignature = "sig" };

        Assert.Throws<InvalidOperationException>(() => _service.VerifyNonce(payload));
    }

    [Fact]
    public void VerifyNonce_FutureTimestamp_Throws()
    {
        var future = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60; // 60s in future
        var payload = new SecurePayload { Nonce = "n", Timestamp = future, NonceSignature = "sig" };

        Assert.Throws<InvalidOperationException>(() => _service.VerifyNonce(payload));
    }

    [Fact]
    public void VerifyNonce_InvalidSignature_Throws()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _enclaveKeys.Setup(k => k.VerifyEnclaveSignature(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(false);

        var payload = new SecurePayload { Nonce = "n", Timestamp = now, NonceSignature = "bad" };
        Assert.Throws<InvalidOperationException>(() => _service.VerifyNonce(payload));
    }

    // ── VerifyActiveAuth ──────────────────────────────────────────────────────

    [Fact]
    public void VerifyActiveAuth_BothDg15AndActiveSigMissing_ReturnsWithoutThrow()
    {
        // Cards that don't support Active Authentication — code allows this
        var payload = new SecurePayload { DG15 = "", ActiveSig = "", Nonce = "n" };
        _service.VerifyActiveAuth(payload); // must not throw
    }

    [Fact]
    public void VerifyActiveAuth_Dg15PresentButActiveSigMissing_Throws()
    {
        var payload = new SecurePayload
        {
            DG15 = Convert.ToBase64String(new byte[] { 0x01, 0x02 }),
            ActiveSig = "",
            Nonce = "n"
        };
        Assert.Throws<Exception>(() => _service.VerifyActiveAuth(payload));
    }

    [Fact]
    public void VerifyActiveAuth_WrongChallenge_Throws()
    {
        // ActiveSig present, but AAChallenge doesn't match SHA256(Nonce)[0..7]
        using var rsa = RSA.Create(1024);
        var spkiBytes = rsa.ExportSubjectPublicKeyInfo();

        var payload = new SecurePayload
        {
            Nonce = "test-nonce-12345",
            DG15 = Convert.ToBase64String(spkiBytes),
            ActiveSig = Convert.ToBase64String(new byte[128]),
            AAChallenge = Convert.ToBase64String(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
            // wrong challenge — doesn't match SHA256("test-nonce-12345")[0..7]
        };

        Assert.Throws<Exception>(() => _service.VerifyActiveAuth(payload));
    }

    [Fact]
    public void VerifyActiveAuth_ValidPkcs1Signature_DoesNotThrow()
    {
        // Generate an RSA key pair, sign the challenge, and verify
        using var rsa = RSA.Create(1024);
        var spkiBytes = rsa.ExportSubjectPublicKeyInfo();

        var nonce = "test-nonce-for-aa";
        var nonceHash = SHA256.HashData(Encoding.UTF8.GetBytes(nonce));
        var challenge = nonceHash.Take(8).ToArray();

        // Sign with PKCS#1 v1.5 SHA-256 — matches BouncyCastle RsaDigestSigner(Sha256Digest)
        var sig = rsa.SignData(challenge, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var payload = new SecurePayload
        {
            Nonce = nonce,
            DG15 = Convert.ToBase64String(spkiBytes),
            ActiveSig = Convert.ToBase64String(sig),
            AAChallenge = Convert.ToBase64String(challenge)
        };

        _service.VerifyActiveAuth(payload); // must not throw
    }

    // ── VerifyBiometricMatchParallel ──────────────────────────────────────────

    [Fact]
    public void VerifyBiometricMatchParallel_MissingDg2Photo_Throws()
    {
        var payload = new SecurePayload { DG2_Photo = "", UserSelfie = "abc" };
        Assert.Throws<Exception>(() => _service.VerifyBiometricMatchParallel(payload));
    }

    [Fact]
    public void VerifyBiometricMatchParallel_MissingSelfie_Throws()
    {
        var payload = new SecurePayload
        {
            DG2_Photo = Convert.ToBase64String(new byte[100]),
            UserSelfie = ""
        };
        Assert.Throws<Exception>(() => _service.VerifyBiometricMatchParallel(payload));
    }

    [Fact]
    public void VerifyBiometricMatchParallel_ScoreAboveThreshold_ReturnsScore()
    {
        _biometrics.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
            .Returns(0.85f);

        var payload = new SecurePayload
        {
            DG2_Photo = Convert.ToBase64String(new byte[100]),
            UserSelfie = Convert.ToBase64String(new byte[100])
        };

        var score = _service.VerifyBiometricMatchParallel(payload);
        Assert.Equal(0.85f, score);
    }

    [Fact]
    public void VerifyBiometricMatchParallel_ScoreBelowThreshold_Throws()
    {
        _biometrics.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
            .Returns(0.20f); // below 0.40 threshold

        var payload = new SecurePayload
        {
            DG2_Photo = Convert.ToBase64String(new byte[100]),
            UserSelfie = Convert.ToBase64String(new byte[100])
        };

        Assert.Throws<Exception>(() => _service.VerifyBiometricMatchParallel(payload));
    }

    // ── VerifyDGHashes ────────────────────────────────────────────────────────

    [Fact]
    public void VerifyDGHashes_HashFoundInSodContent_DoesNotThrow()
    {
        var dg1Bytes = Convert.FromBase64String(BuildDG1Base64(FakeTurkishTD1Mrz));
        var dg1Hash = SHA256.HashData(dg1Bytes);

        // SOD content that contains the DG1 hash (brute-force search will find it)
        var sodContent = new byte[] { 0x00, 0x01, 0x02 }
            .Concat(dg1Hash)
            .Concat(new byte[] { 0xFF })
            .ToArray();

        _service.VerifyDGHashes(sodContent, BuildDG1Base64(FakeTurkishTD1Mrz), null!);
    }

    [Fact]
    public void VerifyDGHashes_HashNotInSodContent_Throws()
    {
        var dg1Base64 = BuildDG1Base64(FakeTurkishTD1Mrz);

        // SOD content with wrong bytes — hash won't match
        var sodContent = new byte[64]; // all zeros

        Assert.Throws<Exception>(() => _service.VerifyDGHashes(sodContent, dg1Base64, null!));
    }

    // ── DiagLog ───────────────────────────────────────────────────────────────

    [Fact]
    public void DiagLog_OkAndFail_RecordEntries()
    {
        var diag = new DiagLog();
        diag.Ok("Step1");
        diag.Fail("Step2", "error message");
        diag.Info("Some info");

        Assert.Equal(3, diag.Entries.Count);
    }

    [Fact]
    public void DiagLog_TotalMs_IsNonNegative()
    {
        var diag = new DiagLog();
        diag.Begin("SomeStep");
        diag.Ok("SomeStep");

        Assert.True(diag.TotalMs >= 0);
    }

    // ── Handshake (additional) ────────────────────────────────────────────────

    [Fact]
    public void Handshake_AllChallengesAreValidLivenessActions()
    {
        var response = _service.Handshake(new DiagLog());
        var allowed = new[]
        {
            LivenessAction.FaceLeft, LivenessAction.FaceRight, LivenessAction.Blink, LivenessAction.Smile
        };

        Assert.All(response.Challenges, c => Assert.Contains(c, allowed));
        Assert.DoesNotContain(LivenessAction.None, response.Challenges);
    }

    [Fact]
    public void Handshake_TimestampIsCurrent()
    {
        var before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var response = _service.Handshake(new DiagLog());
        var after = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        Assert.InRange(response.Timestamp, before, after);
    }

    // ── ParseMrzDate (additional boundaries) ──────────────────────────────────

    [Fact]
    public void ParseMrzDate_DobYearExactly30_Returns2030()  // yy=30 is NOT > 30 → 2000s
        => Assert.Equal(new DateTime(2030, 5, 1), _service.ParseMrzDate("300501"));

    [Fact]
    public void ParseMrzDate_DobYearExactly31_Returns1931()  // yy=31 IS > 30 → 1900s
        => Assert.Equal(new DateTime(1931, 5, 1), _service.ParseMrzDate("310501"));

    [Fact]
    public void ParseMrzDate_InvalidDay_ClampsTo1()
        => Assert.Equal(new DateTime(1985, 6, 1), _service.ParseMrzDate("850632"));

    [Fact]
    public void ParseMrzDate_NonNumericInput_ThrowsFormatException()
    {
        // HARDENING NOTE: ParseMrzDate guards length and clamps month/day, but a non-numeric
        // field still throws FormatException from int.Parse rather than returning MinValue.
        // This test pins current behaviour — making it resilient would be a deliberate change.
        Assert.Throws<FormatException>(() => _service.ParseMrzDate("ABCDEF"));
    }

    // ── CheckAgeConstraint (additional boundaries) ────────────────────────────

    [Fact] public void CheckAgeConstraint_RangeFormat_AgeAtLowerBound_ReturnsTrue()
        => Assert.True(_service.CheckAgeConstraint(18, "18-65"));

    [Fact] public void CheckAgeConstraint_RangeFormat_AgeAtUpperBound_ReturnsFalse()  // upper bound exclusive
        => Assert.False(_service.CheckAgeConstraint(65, "18-65"));

    [Fact] public void CheckAgeConstraint_RangeFormat_AgeJustUnderUpperBound_ReturnsTrue()
        => Assert.True(_service.CheckAgeConstraint(64, "18-65"));

    [Fact] public void CheckAgeConstraint_PlusFormat_AgeExactlyAtMin_ReturnsTrue()
        => Assert.True(_service.CheckAgeConstraint(18, "18+"));

    [Fact] public void CheckAgeConstraint_LeadingTrailingWhitespace_IsTrimmed()
        => Assert.True(_service.CheckAgeConstraint(20, "  18+  "));

    [Fact] public void CheckAgeConstraint_MalformedRange_Throws()
        => Assert.Throws<Exception>(() => _service.CheckAgeConstraint(20, "18-25-30"));

    // ── Mask (additional) ─────────────────────────────────────────────────────

    [Fact]
    public void Mask_ExactlyFourChars_ReturnsStarNotation()
        => Assert.Equal("**4**", _service.Mask("ABCD"));

    [Fact]
    public void Mask_FiveChars_KeepsFirstTwoAndLastTwo()
        => Assert.Equal("AB*DE", _service.Mask("ABCDE"));

    [Fact]
    public void Mask_TcknLengthValue_OnlyExposesFourDigits()
    {
        // An 11-digit TCKN must never have its middle digits exposed in logs.
        var masked = _service.Mask("12345678901");
        Assert.Equal("12*******01", masked);
        Assert.DoesNotContain("345678", masked);
    }

    // ── ExtractMrzFromDG1 / GetIssuingCountryFromDG1 (additional) ──────────────

    [Fact]
    public void ExtractMrzFromDG1_EmptyBytes_Throws()
        => Assert.ThrowsAny<Exception>(() => _service.ExtractMrzFromDG1(Array.Empty<byte>()));

    [Fact]
    public void ExtractMrzFromDG1_GarbageBytes_Throws()
        => Assert.ThrowsAny<Exception>(() => _service.ExtractMrzFromDG1(new byte[] { 0x01, 0x02, 0x03 }));

    [Fact]
    public void GetIssuingCountryFromDG1_GermanCard_ReturnsDEU()
    {
        var germanMrz = FakeTurkishTD1Mrz.Replace("TUR", "DEU");
        Assert.Equal("DEU", _service.GetIssuingCountryFromDG1(BuildDG1Base64(germanMrz)));
    }

    // ── ParseDG1ToTicket (additional) ─────────────────────────────────────────

    [Fact]
    public void ParseDG1ToTicket_UnsupportedDocType_Throws()
    {
        // 'V' = visa — only P / I / A / C are accepted document types.
        var visaMrz = "V" + FakeTurkishTD1Mrz.Substring(1);
        Assert.Throws<Exception>(() => _service.ParseDG1ToTicket(BuildDG1Base64(visaMrz), "pk", "TUR"));
    }

    [Fact]
    public void ParseDG1ToTicket_FemaleGender_MappedToF()
    {
        // Same card, line 2 gender byte M → F.
        var femaleMrz = FakeTurkishTD1Mrz.Substring(0, 30)
            + "9001011F3012311TUR00000000<<<0"
            + FakeTurkishTD1Mrz.Substring(60);
        var ticket = _service.ParseDG1ToTicket(BuildDG1Base64(femaleMrz), "pk", "TUR");
        Assert.Equal("F", ticket.Cinsiyet);
    }

    [Fact]
    public void ParseDG1ToTicket_ExpiryDateParsedFromMrz()
    {
        var ticket = _service.ParseDG1ToTicket(BuildDG1Base64(FakeTurkishTD1Mrz), "pk", "TUR");
        Assert.Equal(new DateTime(2030, 12, 31), ticket.GecerlilikTarihi);
    }

    [Fact]
    public void ParseDG1ToTicket_NonTurkishCard_LeavesTcknEmpty()
    {
        // Even though the optional-data field is numeric, a non-TUR/THA card must not yield a TCKN.
        var frenchMrz = FakeTurkishTD1Mrz.Replace("TUR", "FRA");
        var ticket = _service.ParseDG1ToTicket(BuildDG1Base64(frenchMrz), "pk", "FRA");
        Assert.Equal("", ticket.TCKN);
        Assert.Equal("FRA", ticket.Uyruk);
    }

    // ── VerifyDGHashes — DG15 path ────────────────────────────────────────────

    [Fact]
    public void VerifyDGHashes_Dg15PresentAndHashFound_DoesNotThrow()
    {
        var dg1Base64 = BuildDG1Base64(FakeTurkishTD1Mrz);
        var dg15Bytes = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
        var dg15Base64 = Convert.ToBase64String(dg15Bytes);

        var dg1Hash = SHA256.HashData(Convert.FromBase64String(dg1Base64));
        var dg15Hash = SHA256.HashData(dg15Bytes);

        // SOD content embeds BOTH hashes (the brute-force scan finds them).
        var sodContent = new byte[] { 0x00 }
            .Concat(dg1Hash).Concat(new byte[] { 0xFF })
            .Concat(dg15Hash).Concat(new byte[] { 0xFF })
            .ToArray();

        _service.VerifyDGHashes(sodContent, dg1Base64, dg15Base64); // must not throw
    }

    [Fact]
    public void VerifyDGHashes_Dg15HashMissing_Throws()
    {
        var dg1Base64 = BuildDG1Base64(FakeTurkishTD1Mrz);
        var dg1Hash = SHA256.HashData(Convert.FromBase64String(dg1Base64));

        // DG1 hash present, DG15 hash absent → DG15 tampering must be rejected.
        var sodContent = new byte[] { 0x00 }.Concat(dg1Hash).Concat(new byte[64]).ToArray();

        Assert.Throws<Exception>(() =>
            _service.VerifyDGHashes(sodContent, dg1Base64, Convert.ToBase64String(new byte[] { 0x11, 0x22 })));
    }

    // ── SearchHashInSOD (additional offsets) ──────────────────────────────────

    [Fact]
    public void SearchHashInSOD_HashAtOffsetZero_ReturnsTrue()
    {
        var hash = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var sodContent = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00 };
        Assert.True(_service.SearchHashInSOD(sodContent, 1, hash));
    }

    [Fact]
    public void SearchHashInSOD_HashAtVeryEnd_ReturnsTrue()
    {
        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("tail"));
        var sodContent = new byte[16].Concat(hash).ToArray();
        Assert.True(_service.SearchHashInSOD(sodContent, 1, hash));
    }

    [Fact]
    public void SearchHashInSOD_ContentShorterThanHash_ReturnsFalse()
    {
        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("x")); // 32 bytes
        Assert.False(_service.SearchHashInSOD(new byte[8], 1, hash));
    }

    // ── LoginAsync — QR payload, binding & nonce validation (security-critical) ─

    /// <summary>
    /// Builds a hybrid-encrypted login request whose inner ticket carries <paramref name="innerNonce"/>
    /// and a pk_hash, paired with a QR payload carrying <paramref name="qrNonce"/>. DecryptWithEnclaveKey
    /// is mocked to return the real AES key so the Enclave can decrypt the blob and reach the
    /// binding / nonce-match checks. innerNonce must be at least 8 chars (the service logs nonce[..8]).
    /// </summary>
    private LoginRequest BuildLoginRequest(
        string innerNonce, string qrNonce,
        string? pkHashOverride = null,
        string partnerId = "partner-1",
        bool includeRequestObject = true)
    {
        var (_, reqPublicKey) = VerifyBlind.Core.Crypto.CryptoUtils.GenerateRsaKeyPair();
        var pkHash = pkHashOverride ?? Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(reqPublicKey))).ToLowerInvariant();

        var inner = System.Text.Json.JsonSerializer.Serialize(new
        {
            signed_ticket = new SignedTicket
            {
                Payload = new TicketPayload { CountryIsoCode = "TUR", GecerlilikTarihi = new DateTime(2030, 1, 1) },
                Signature = "sig"
            },
            nonce = innerNonce,
            pk_hash = pkHash
        });
        var (aesCipher, aesKey, _) = VerifyBlind.Core.Crypto.CryptoUtils.AesEncrypt(inner);
        _enclaveKeys.Setup(k => k.DecryptWithEnclaveKey(It.IsAny<string>())).Returns(aesKey);

        var encPayload = System.Text.Json.JsonSerializer.Serialize(new { enc_key = "ek", blob = aesCipher });

        var qr = includeRequestObject
            ? System.Text.Json.JsonSerializer.Serialize(new
              {
                  request = new { partner_id = partnerId, public_key = reqPublicKey, nonce = qrNonce }
              })
            : System.Text.Json.JsonSerializer.Serialize(new { foo = "no request object here" });

        return new LoginRequest
        {
            EncrSignedTicket = encPayload,
            Nonce = Guid.NewGuid().ToString(),
            QrPayloadJson = qr
        };
    }

    [Fact]
    public async Task LoginAsync_QrPayloadMissingRequestObject_Throws()
    {
        var request = BuildLoginRequest("shared-nonce-123", "shared-nonce-123", includeRequestObject: false);
        var ex = await Assert.ThrowsAsync<Exception>(() => _service.LoginAsync(request, new DiagLog()));
        Assert.Contains("request", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LoginAsync_QrPayloadMissingPartnerId_Throws()
    {
        var request = BuildLoginRequest("shared-nonce-123", "shared-nonce-123", partnerId: "");
        var ex = await Assert.ThrowsAsync<Exception>(() => _service.LoginAsync(request, new DiagLog()));
        Assert.Contains("Zorunlu alanlar", ex.Message);
    }

    [Fact]
    public async Task LoginAsync_BindingMismatch_PkHashDoesNotMatchPublicKey_Throws()
    {
        // pk_hash signed into the ticket must equal SHA256(QR request public key). A mismatch
        // means the ticket was not bound to this partner's key — a relay / replay attempt.
        var request = BuildLoginRequest("shared-nonce-123", "shared-nonce-123",
            pkHashOverride: "deadbeefdeadbeefdeadbeefdeadbeef");
        var ex = await Assert.ThrowsAsync<Exception>(() => _service.LoginAsync(request, new DiagLog()));
        Assert.Contains("Bağlama", ex.Message);
    }

    [Fact]
    public async Task LoginAsync_BindingMissing_EmptyPkHash_Throws()
    {
        var request = BuildLoginRequest("shared-nonce-123", "shared-nonce-123", pkHashOverride: "");
        var ex = await Assert.ThrowsAsync<Exception>(() => _service.LoginAsync(request, new DiagLog()));
        Assert.Contains("Bağlama", ex.Message);
    }

    [Fact]
    public async Task LoginAsync_NonceMismatch_InnerNonceDiffersFromQrNonce_Throws()
    {
        // The nonce signed into the ticket must equal the nonce in the QR request.
        var request = BuildLoginRequest(innerNonce: "ticket-nonce-aaa", qrNonce: "qr-nonce-bbbbbbb");
        var ex = await Assert.ThrowsAsync<Exception>(() => _service.LoginAsync(request, new DiagLog()));
        Assert.Contains("Nonce uyuşmuyor", ex.Message);
    }

    [Fact]
    public async Task LoginAsync_ValidBindingAndNonce_ReachesTicketSignatureVerification()
    {
        // With binding + nonce OK the flow advances to ticket signature verification.
        // Mock KMS to reject the signature → proves the binding/nonce gates were passed.
        _kms.Setup(k => k.VerifyTicketSignatureAsync(It.IsAny<SignedTicket>())).ReturnsAsync(false);
        var request = BuildLoginRequest("matching-nonce-1", "matching-nonce-1");

        var ex = await Assert.ThrowsAsync<Exception>(() => _service.LoginAsync(request, new DiagLog()));
        Assert.Contains("Geçersiz bilet", ex.Message);
    }
}
