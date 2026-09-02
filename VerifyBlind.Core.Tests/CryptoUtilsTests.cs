using VerifyBlind.Core.Crypto;
using System.Security.Cryptography;
using System.Text;

namespace VerifyBlind.Core.Tests;

public class CryptoUtilsTests
{
    #region RSA Key Generation

    [Fact]
    public void GenerateRsaKeyPair_ReturnsValidKeyPair()
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();

        Assert.False(string.IsNullOrEmpty(privateKey));
        Assert.False(string.IsNullOrEmpty(publicKey));

        // Verify keys are valid Base64
        var privBytes = Convert.FromBase64String(privateKey);
        var pubBytes = Convert.FromBase64String(publicKey);
        Assert.True(privBytes.Length > 0);
        Assert.True(pubBytes.Length > 0);
    }

    [Fact]
    public void GenerateRsaKeyPair_KeysAreImportable()
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();

        using var rsaPriv = RSA.Create();
        rsaPriv.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
        Assert.Equal(2048, rsaPriv.KeySize);

        using var rsaPub = RSA.Create();
        rsaPub.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
        Assert.Equal(2048, rsaPub.KeySize);
    }

    [Fact]
    public void GenerateRsaKeyPair_EachCallProducesUniqueKeys()
    {
        var (priv1, pub1) = CryptoUtils.GenerateRsaKeyPair();
        var (priv2, pub2) = CryptoUtils.GenerateRsaKeyPair();

        Assert.NotEqual(priv1, priv2);
        Assert.NotEqual(pub1, pub2);
    }

    #endregion

    #region RSA Encrypt/Decrypt (OAEP-SHA256)

    [Fact]
    public void RsaEncryptDecrypt_RoundTrip_Success()
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var plainText = "Merhaba VerifyBlind!";

        var encrypted = CryptoUtils.RsaEncrypt(plainText, publicKey);
        var decrypted = CryptoUtils.RsaDecrypt(encrypted, privateKey);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void RsaEncrypt_ProducesDifferentCiphertextEachTime()
    {
        var (_, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var plainText = "Test data";

        var enc1 = CryptoUtils.RsaEncrypt(plainText, publicKey);
        var enc2 = CryptoUtils.RsaEncrypt(plainText, publicKey);

        // OAEP is probabilistic — same plaintext gives different ciphertext
        Assert.NotEqual(enc1, enc2);
    }

    [Fact]
    public void RsaDecrypt_WithWrongKey_Throws()
    {
        var (_, publicKey1) = CryptoUtils.GenerateRsaKeyPair();
        var (privateKey2, _) = CryptoUtils.GenerateRsaKeyPair();

        var encrypted = CryptoUtils.RsaEncrypt("secret", publicKey1);

        Assert.ThrowsAny<CryptographicException>(() =>
            CryptoUtils.RsaDecrypt(encrypted, privateKey2));
    }

    [Theory]
    [InlineData("")]
    [InlineData("A")]
    [InlineData("Türkçe karakterler: ğüşıöç")]
    [InlineData("Special chars: !@#$%^&*()")]
    public void RsaEncryptDecrypt_VariousInputs(string plainText)
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();

        var encrypted = CryptoUtils.RsaEncrypt(plainText, publicKey);
        var decrypted = CryptoUtils.RsaDecrypt(encrypted, privateKey);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void RsaEncryptDecrypt_MaxSizePayload()
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        // RSA-2048 OAEP-SHA256: max = 256 - 2*32 - 2 = 190 bytes
        var plainText = new string('X', 190);

        var encrypted = CryptoUtils.RsaEncrypt(plainText, publicKey);
        var decrypted = CryptoUtils.RsaDecrypt(encrypted, privateKey);

        Assert.Equal(plainText, decrypted);
    }

    #endregion

    #region RSA Encrypt OAEP-SHA1 (Android Keystore compat)

    [Fact]
    public void RsaEncryptOaepSha1_CanDecryptWithSha1Padding()
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var plainText = "Android Keystore data";

        var encrypted = CryptoUtils.RsaEncryptOaepSha1(plainText, publicKey);

        // Decrypt with SHA1 padding manually since RsaDecrypt uses SHA256
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
        var decryptedBytes = rsa.Decrypt(Convert.FromBase64String(encrypted), RSAEncryptionPadding.OaepSHA1);
        var decrypted = Encoding.UTF8.GetString(decryptedBytes);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void RsaEncryptOaepSha1_CannotDecryptWithSha256()
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var encrypted = CryptoUtils.RsaEncryptOaepSha1("test", publicKey);

        // SHA256 decrypt should fail on SHA1-encrypted data
        Assert.ThrowsAny<CryptographicException>(() =>
            CryptoUtils.RsaDecrypt(encrypted, privateKey));
    }

    #endregion

    #region AES-GCM Encrypt/Decrypt

    [Fact]
    public void AesEncryptDecrypt_RoundTrip_Success()
    {
        var plainText = "Hassas veri: TCKN korumalı";

        var (cipherText, key, iv) = CryptoUtils.AesEncrypt(plainText);
        var decrypted = CryptoUtils.AesDecrypt(cipherText, key);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void AesEncrypt_ProducesDifferentOutputEachTime()
    {
        var plainText = "Same input";

        var (ct1, k1, _) = CryptoUtils.AesEncrypt(plainText);
        var (ct2, k2, _) = CryptoUtils.AesEncrypt(plainText);

        Assert.NotEqual(ct1, ct2);
        Assert.NotEqual(k1, k2);
    }

    [Fact]
    public void AesDecrypt_WithWrongKey_Throws()
    {
        var (cipherText, _, _) = CryptoUtils.AesEncrypt("secret");
        var (_, wrongKey, _) = CryptoUtils.AesEncrypt("other");

        Assert.ThrowsAny<Exception>(() =>
            CryptoUtils.AesDecrypt(cipherText, wrongKey));
    }

    [Fact]
    public void AesDecrypt_TamperedCiphertext_Throws()
    {
        var (cipherText, key, _) = CryptoUtils.AesEncrypt("integrity test");

        var bytes = Convert.FromBase64String(cipherText);
        bytes[15] ^= 0xFF; // Tamper with ciphertext
        var tampered = Convert.ToBase64String(bytes);

        Assert.ThrowsAny<Exception>(() =>
            CryptoUtils.AesDecrypt(tampered, key));
    }

    [Theory]
    [InlineData("")]
    [InlineData("A")]
    [InlineData("Uzun bir metin: " + "ABCDEFGHIJ")]
    public void AesEncryptDecrypt_VariousInputs(string plainText)
    {
        var (cipherText, key, _) = CryptoUtils.AesEncrypt(plainText);
        var decrypted = CryptoUtils.AesDecrypt(cipherText, key);

        Assert.Equal(plainText, decrypted);
    }

    #endregion

    #region RSA-PSS Sign/Verify

    [Fact]
    public void SignAndVerify_RoundTrip_Success()
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var data = "İmzalanacak veri";

        var signature = CryptoUtils.SignData(data, privateKey);
        var isValid = CryptoUtils.VerifySignature(data, signature, publicKey);

        Assert.True(isValid);
    }

    [Fact]
    public void VerifySignature_WrongData_ReturnsFalse()
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();

        var signature = CryptoUtils.SignData("original", privateKey);
        var isValid = CryptoUtils.VerifySignature("tampered", signature, publicKey);

        Assert.False(isValid);
    }

    [Fact]
    public void VerifySignature_WrongKey_ReturnsFalse()
    {
        var (privateKey1, _) = CryptoUtils.GenerateRsaKeyPair();
        var (_, publicKey2) = CryptoUtils.GenerateRsaKeyPair();

        var signature = CryptoUtils.SignData("data", privateKey1);
        var isValid = CryptoUtils.VerifySignature("data", signature, publicKey2);

        Assert.False(isValid);
    }

    [Fact]
    public void VerifySignature_TamperedSignature_ReturnsFalse()
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();

        var signature = CryptoUtils.SignData("data", privateKey);
        var sigBytes = Convert.FromBase64String(signature);
        sigBytes[0] ^= 0xFF;
        var tampered = Convert.ToBase64String(sigBytes);

        var isValid = CryptoUtils.VerifySignature("data", tampered, publicKey);
        Assert.False(isValid);
    }

    [Fact]
    public void SignData_ProducesDifferentSignaturesEachTime()
    {
        var (privateKey, _) = CryptoUtils.GenerateRsaKeyPair();
        var data = "deterministic?";

        var sig1 = CryptoUtils.SignData(data, privateKey);
        var sig2 = CryptoUtils.SignData(data, privateKey);

        // PSS is probabilistic
        Assert.NotEqual(sig1, sig2);
    }

    #endregion

    #region ImportPublicKey

    [Fact]
    public void ImportPublicKey_SpkiBase64_Success()
    {
        var (_, publicKey) = CryptoUtils.GenerateRsaKeyPair();

        using var rsa = RSA.Create();
        var result = CryptoUtils.ImportPublicKey(rsa, publicKey);

        Assert.True(result);
        Assert.Equal(2048, rsa.KeySize);
    }

    [Fact]
    public void ImportPublicKey_PemFormat_Success()
    {
        var (_, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var keyBytes = Convert.FromBase64String(publicKey);

        // Convert to PEM
        var pem = "-----BEGIN PUBLIC KEY-----\n" +
                  Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks) +
                  "\n-----END PUBLIC KEY-----";

        using var rsa = RSA.Create();
        var result = CryptoUtils.ImportPublicKey(rsa, pem);

        Assert.True(result);
    }

    [Fact]
    public void ImportPublicKey_InvalidKey_ReturnsFalse()
    {
        using var rsa = RSA.Create();
        var result = CryptoUtils.ImportPublicKey(rsa, "not-a-valid-key!!!");

        Assert.False(result);
    }

    #endregion

    #region GetPublicKeyHash

    [Fact]
    public void GetPublicKeyHash_ReturnsConsistentHash()
    {
        var (_, publicKey) = CryptoUtils.GenerateRsaKeyPair();

        var hash1 = CryptoUtils.GetPublicKeyHash(publicKey);
        var hash2 = CryptoUtils.GetPublicKeyHash(publicKey);

        Assert.Equal(hash1, hash2);
        Assert.Equal(64, hash1.Length); // SHA256 = 32 bytes = 64 hex chars
    }

    [Fact]
    public void GetPublicKeyHash_DifferentKeys_DifferentHashes()
    {
        var (_, pub1) = CryptoUtils.GenerateRsaKeyPair();
        var (_, pub2) = CryptoUtils.GenerateRsaKeyPair();

        Assert.NotEqual(CryptoUtils.GetPublicKeyHash(pub1), CryptoUtils.GetPublicKeyHash(pub2));
    }

    [Fact]
    public void GetPublicKeyHash_PemFormat_StripsHeaders()
    {
        var (_, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var keyBytes = Convert.FromBase64String(publicKey);
        var pem = "-----BEGIN PUBLIC KEY-----\n" +
                  Convert.ToBase64String(keyBytes) +
                  "\n-----END PUBLIC KEY-----";

        var hashRaw = CryptoUtils.GetPublicKeyHash(publicKey);
        var hashPem = CryptoUtils.GetPublicKeyHash(pem);

        Assert.Equal(hashRaw, hashPem);
    }

    [Fact]
    public void GetPublicKeyHash_InvalidInput_ReturnsEmpty()
    {
        var hash = CryptoUtils.GetPublicKeyHash("not-base64!!!");
        Assert.Equal(string.Empty, hash);
    }

    #endregion

    #region Hybrid Encryption (RSA + AES round-trip)

    [Fact]
    public void HybridEncryption_FullRoundTrip()
    {
        // This simulates the actual flow: AES encrypts payload, RSA wraps AES key
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var payload = "{\"tckn\":\"12345678901\",\"ad\":\"Ali\",\"soyad\":\"Yılmaz\"}";

        // Encrypt
        var (aesCipher, aesKey, _) = CryptoUtils.AesEncrypt(payload);
        var wrappedKey = CryptoUtils.RsaEncrypt(aesKey, publicKey);

        // Decrypt
        var unwrappedKey = CryptoUtils.RsaDecrypt(wrappedKey, privateKey);
        var decrypted = CryptoUtils.AesDecrypt(aesCipher, unwrappedKey);

        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void HybridEncryption_SignedTicket_FullFlow()
    {
        // Simulates: Enclave signs ticket, partner verifies
        var (enclavePriv, enclavePub) = CryptoUtils.GenerateRsaKeyPair();
        var (partnerPriv, partnerPub) = CryptoUtils.GenerateRsaKeyPair();

        var ticketJson = "{\"UserId\":\"abc123\",\"Ad\":\"Mehmet\"}";

        // Enclave signs
        var signature = CryptoUtils.SignData(ticketJson, enclavePriv);

        // Enclave encrypts for partner
        var (aesCipher, aesKey, _) = CryptoUtils.AesEncrypt(ticketJson + "|" + signature);
        var wrappedKey = CryptoUtils.RsaEncrypt(aesKey, partnerPub);

        // Partner decrypts
        var unwrappedKey = CryptoUtils.RsaDecrypt(wrappedKey, partnerPriv);
        var decrypted = CryptoUtils.AesDecrypt(aesCipher, unwrappedKey);
        var parts = decrypted.Split('|');

        // Partner verifies signature
        Assert.True(CryptoUtils.VerifySignature(parts[0], parts[1], enclavePub));
        Assert.Equal(ticketJson, parts[0]);
    }

    #endregion

    #region Error Handling & Malformed Input

    [Fact]
    public void RsaEncrypt_InvalidPublicKey_Throws()
        => Assert.ThrowsAny<Exception>(() => CryptoUtils.RsaEncrypt("data", "not-a-valid-key!!!"));

    [Fact]
    public void RsaDecrypt_NonBase64CipherText_Throws()
    {
        var (privateKey, _) = CryptoUtils.GenerateRsaKeyPair();
        Assert.ThrowsAny<Exception>(() => CryptoUtils.RsaDecrypt("not-base64!!!", privateKey));
    }

    [Fact]
    public void RsaDecrypt_InvalidPrivateKey_Throws()
    {
        var (_, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var encrypted = CryptoUtils.RsaEncrypt("data", publicKey);
        Assert.ThrowsAny<Exception>(() => CryptoUtils.RsaDecrypt(encrypted, "not-base64!!!"));
    }

    [Fact]
    public void SignData_InvalidPrivateKey_Throws()
        => Assert.ThrowsAny<Exception>(() => CryptoUtils.SignData("data", "not-base64!!!"));

    [Fact]
    public void VerifySignature_NonBase64Signature_ReturnsFalseNeverThrows()
    {
        var (_, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        // VerifySignature must swallow all errors and return false — never throw to the caller.
        Assert.False(CryptoUtils.VerifySignature("data", "not-base64!!!", publicKey));
    }

    [Fact]
    public void VerifySignature_InvalidPublicKey_ReturnsFalse()
    {
        var (privateKey, _) = CryptoUtils.GenerateRsaKeyPair();
        var signature = CryptoUtils.SignData("data", privateKey);
        Assert.False(CryptoUtils.VerifySignature("data", signature, "not-a-valid-key!!!"));
    }

    [Fact]
    public void VerifySignature_EmptySignature_ReturnsFalse()
    {
        var (_, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        Assert.False(CryptoUtils.VerifySignature("data", "", publicKey));
    }

    [Fact]
    public void AesDecrypt_NonBase64_Throws()
    {
        var (_, key, _) = CryptoUtils.AesEncrypt("x");
        Assert.ThrowsAny<Exception>(() => CryptoUtils.AesDecrypt("not-base64!!!", key));
    }

    [Fact]
    public void AesDecrypt_BlobShorterThanNoncePlusTag_Throws()
    {
        var (_, key, _) = CryptoUtils.AesEncrypt("x");
        // A 10-byte blob cannot hold a 12-byte GCM nonce + 16-byte auth tag.
        var tooShort = Convert.ToBase64String(new byte[10]);
        Assert.ThrowsAny<Exception>(() => CryptoUtils.AesDecrypt(tooShort, key));
    }

    [Fact]
    public void AesDecrypt_TamperedAuthTag_Throws()
    {
        var (cipherText, key, _) = CryptoUtils.AesEncrypt("auth tag integrity");
        var bytes = Convert.FromBase64String(cipherText);
        bytes[^1] ^= 0xFF; // flip last byte — part of the 16-byte GCM auth tag
        Assert.ThrowsAny<Exception>(() => CryptoUtils.AesDecrypt(Convert.ToBase64String(bytes), key));
    }

    [Fact]
    public void AesDecrypt_TamperedNonce_Throws()
    {
        var (cipherText, key, _) = CryptoUtils.AesEncrypt("nonce integrity");
        var bytes = Convert.FromBase64String(cipherText);
        bytes[0] ^= 0xFF; // flip first byte — part of the 12-byte GCM nonce
        Assert.ThrowsAny<Exception>(() => CryptoUtils.AesDecrypt(Convert.ToBase64String(bytes), key));
    }

    #endregion

    #region AES Structure & Large Payloads

    [Fact]
    public void AesEncrypt_IvIsFirst12BytesOfBlob()
    {
        var (cipherText, _, iv) = CryptoUtils.AesEncrypt("nonce placement");
        var combined = Convert.FromBase64String(cipherText);
        var ivBytes = Convert.FromBase64String(iv);
        Assert.Equal(12, ivBytes.Length); // GCM standard nonce size
        Assert.Equal(ivBytes, combined.Take(12).ToArray());
    }

    [Fact]
    public void AesEncryptDecrypt_LargePayload_RoundTrips()
    {
        var plainText = new string('Z', 100_000);
        var (cipherText, key, _) = CryptoUtils.AesEncrypt(plainText);
        Assert.Equal(plainText, CryptoUtils.AesDecrypt(cipherText, key));
    }

    #endregion

    #region ImportPublicKey — Format Variants

    [Fact]
    public void ImportPublicKey_Pkcs1Format_Success()
    {
        using var source = RSA.Create(2048);
        var pkcs1Base64 = Convert.ToBase64String(source.ExportRSAPublicKey());

        using var rsa = RSA.Create();
        Assert.True(CryptoUtils.ImportPublicKey(rsa, pkcs1Base64));
        Assert.Equal(2048, rsa.KeySize);
    }

    [Fact]
    public void ImportPublicKey_EmptyString_ReturnsFalse()
    {
        using var rsa = RSA.Create();
        Assert.False(CryptoUtils.ImportPublicKey(rsa, ""));
    }

    [Fact]
    public void ImportPublicKey_PrivateKeyInsteadOfPublic_ReturnsFalse()
    {
        var (privateKey, _) = CryptoUtils.GenerateRsaKeyPair();
        using var rsa = RSA.Create();
        // A PKCS#8 private key is neither valid SPKI nor PKCS#1 public key material.
        Assert.False(CryptoUtils.ImportPublicKey(rsa, privateKey));
    }

    #endregion

    #region GetPublicKeyHash — Correctness

    [Fact]
    public void GetPublicKeyHash_MatchesManualSha256OfKeyBytes()
    {
        var (_, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var expected = Convert.ToHexString(
            SHA256.HashData(Convert.FromBase64String(publicKey))).ToLowerInvariant();
        Assert.Equal(expected, CryptoUtils.GetPublicKeyHash(publicKey));
    }

    [Fact]
    public void GetPublicKeyHash_WhitespacePaddedKey_SameAsTrimmed()
    {
        var (_, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        Assert.Equal(
            CryptoUtils.GetPublicKeyHash(publicKey),
            CryptoUtils.GetPublicKeyHash("  \n" + publicKey + "\r\n  "));
    }

    #endregion

    #region OAEP-SHA256 vs OAEP-SHA1 Incompatibility

    [Fact]
    public void RsaEncrypt_Sha256Ciphertext_NotDecryptableWithSha1Padding()
    {
        var (privateKey, publicKey) = CryptoUtils.GenerateRsaKeyPair();
        var sha256Cipher = CryptoUtils.RsaEncrypt("payload", publicKey);

        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
        // OAEP padding is hash-bound: SHA-256 ciphertext must fail SHA-1 unwrapping.
        Assert.ThrowsAny<CryptographicException>(() =>
            rsa.Decrypt(Convert.FromBase64String(sha256Cipher), RSAEncryptionPadding.OaepSHA1));
    }

    #endregion
}
