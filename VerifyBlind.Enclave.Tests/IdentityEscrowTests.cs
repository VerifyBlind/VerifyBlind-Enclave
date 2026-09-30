using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Moq;
using VerifyBlind.Enclave.Services;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Kimlik-HMAC sırrının çevrimdışı kurtarma dosyası. Dosya yalnız alıcı özel anahtarıyla açılmalı,
/// açılınca AYNI sır ve AYNI parmak izi çıkmalı; kurtarma betiği (tools/escrow-open.ps1) bu biçime
/// dayanıyor.
/// </summary>
public class IdentityEscrowTests
{
    private static readonly byte[] DevSecret =
        SHA256.HashData(Encoding.UTF8.GetBytes("verifyblind-identity-hmac-dev-secret-v1"));

    private static IdentityHmacService DevService()
    {
        var env = new Mock<IHostEnvironment>();
        env.SetupGet(e => e.EnvironmentName).Returns(Environments.Development);
        return new IdentityHmacService(
            Mock.Of<IKmsService>(), Mock.Of<IEnclaveKeyService>(),
            new ConfigurationBuilder().Build(), env.Object);
    }

    [Fact]
    public async Task Escrow_OpensWithRecipientPrivateKey_ToTheSameSecret()
    {
        var svc = DevService();
        await svc.EnsureSecretLoadedAsync(null);
        using var recipient = RSA.Create(3072);

        var file = svc.CreateEscrow(recipient, "abc123");

        var plain = recipient.Decrypt(Convert.FromBase64String(file.Ciphertext), RSAEncryptionPadding.OaepSHA256);
        using var doc = JsonDocument.Parse(plain);
        Assert.Equal(1, doc.RootElement.GetProperty("v").GetInt32());
        Assert.Equal("identity-hmac", doc.RootElement.GetProperty("purpose").GetString());
        Assert.Equal("vb-idhmac-v1\n", doc.RootElement.GetProperty("label").GetString());
        Assert.Equal(DevSecret, Convert.FromBase64String(doc.RootElement.GetProperty("secret").GetString()!));

        Assert.Equal(IdentityEscrow.Fingerprint(DevSecret), file.SecretFingerprint);
        Assert.Equal("abc123", file.RecipientKeySha256);
        Assert.Equal("verifyblind-identity-escrow", file.Format);
        Assert.Equal("RSA-OAEP-SHA256", file.Algorithm);
    }

    /// <summary>Kurtarılan sır aynı user_id'yi üretmeli — asıl amaç bu.</summary>
    [Fact]
    public async Task RecoveredSecret_ComputesTheSameHmacAsTheService()
    {
        var svc = DevService();
        await svc.EnsureSecretLoadedAsync(null);
        using var recipient = RSA.Create(3072);
        var file = svc.CreateEscrow(recipient, "x");

        var plain = recipient.Decrypt(Convert.FromBase64String(file.Ciphertext), RSAEncryptionPadding.OaepSHA256);
        using var doc = JsonDocument.Parse(plain);
        var secret = Convert.FromBase64String(doc.RootElement.GetProperty("secret").GetString()!);
        var label = Encoding.UTF8.GetBytes(doc.RootElement.GetProperty("label").GetString()!);

        using var hmac = new HMACSHA256(secret);
        var data = Encoding.UTF8.GetBytes("10000000146:partner-1");
        var recovered = Convert.ToBase64String(hmac.ComputeHash(label.Concat(data).ToArray()));

        Assert.Equal(svc.ComputeHmac("10000000146:partner-1"), recovered);
    }

    /// <summary>Parmak izi sabit: etiket ya da hesap değişirse kurtarma betiği eski dosyaları doğrulayamaz.</summary>
    [Fact]
    public void Fingerprint_IsStableForTheDevSecret()
    {
        using var hmac = new HMACSHA256(DevSecret);
        var expected = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes("vb-idhmac-escrow-check-v1"))).ToLowerInvariant();
        Assert.Equal(expected, IdentityEscrow.Fingerprint(DevSecret));
        Assert.Equal(64, expected.Length);
    }

    [Fact]
    public void CreateEscrow_BeforeSecretLoaded_Throws()
    {
        using var recipient = RSA.Create(3072);
        Assert.Throws<InvalidOperationException>(() => DevService().CreateEscrow(recipient, "x"));
    }

    [Fact]
    public void LoadRecipient_MissingFile_IsNotConfigured()
    {
        var dir = Directory.CreateTempSubdirectory("vb-escrow-").FullName;
        try
        {
            Assert.Throws<EscrowNotConfiguredException>(() => IdentityEscrow.LoadRecipient(dir));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void LoadRecipient_ShortKey_IsRejected()
    {
        var dir = WriteRecipient(2048, out _);
        try
        {
            Assert.Throws<InvalidOperationException>(() => IdentityEscrow.LoadRecipient(dir));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void LoadRecipient_ValidKey_ReturnsSpkiHash()
    {
        var dir = WriteRecipient(3072, out var spki);
        try
        {
            var (key, sha) = IdentityEscrow.LoadRecipient(dir);
            using (key)
            {
                Assert.Equal(3072, key.KeySize);
                Assert.Equal(Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant(), sha);
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    private static string WriteRecipient(int bits, out byte[] spki)
    {
        var dir = Directory.CreateTempSubdirectory("vb-escrow-").FullName;
        var escrowDir = Path.Combine(dir, "Certificates", "Escrow");
        Directory.CreateDirectory(escrowDir);
        using var rsa = RSA.Create(bits);
        spki = rsa.ExportSubjectPublicKeyInfo();
        File.WriteAllText(Path.Combine(escrowDir, "identity-escrow-recipient.pem"), rsa.ExportSubjectPublicKeyInfoPem());
        return dir;
    }
}
