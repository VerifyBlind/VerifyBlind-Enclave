using System.Security.Cryptography;
using System.Text;

namespace VerifyBlind.Core.Crypto;

public static class CryptoUtils
{
    // RSA Key Generation
    public static (string PrivateKey, string PublicKey) GenerateRsaKeyPair()
    {
        using var rsa = RSA.Create(2048);
        // Use PKCS#8 for Private Key (Standard Cross-Platform), SPKI (X.509) for Public Key 
        return (Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()), Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()));
    }

    // RSA Encryption (OAEP-SHA256 — for Enclave key operations, SHA-256/MGF1-SHA256)
    public static string RsaEncrypt(string data, string publicKeyBase64)
    {
        using var rsa = RSA.Create();
        // Import SPKI (Standard X.509)
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        // OAEP-SHA256: resistant to Bleichenbacher padding oracle attacks (replaces PKCS#1 v1.5)
        var encryptedBytes = rsa.Encrypt(dataBytes, RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(encryptedBytes);
    }

    // RSA Encryption (OAEP-SHA1 — for Android Keystore-backed user keys)
    // Android Keystore hardware TEE does not support MGF1-SHA256 on all devices/API levels.
    // OAEP-SHA1 is still secure against Bleichenbacher attacks on RSA-2048.
    public static string RsaEncryptOaepSha1(string data, string publicKeyBase64)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var encryptedBytes = rsa.Encrypt(dataBytes, RSAEncryptionPadding.OaepSHA1);
        return Convert.ToBase64String(encryptedBytes);
    }

    // RSA Decryption
    public static string RsaDecrypt(string cipherText, string privateKeyBase64)
    {
        using var rsa = RSA.Create();
        // Import PKCS#8 Private Key
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyBase64), out _);
        var cipherBytes = Convert.FromBase64String(cipherText);
        // OAEP-SHA256: matches encryption padding
        var decryptedBytes = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(decryptedBytes);
    }
    // AES-GCM Encryption (Simplified)
    public static (string CipherText, string Key, string Iv) AesEncrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();
        
        var key = aes.Key;
        var nonce = new byte[12]; // GCM standard nonce size
        RandomNumberGenerator.Fill(nonce);

        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[16]; // Auth tag

        using var aesGcm = new AesGcm(key, 16); // Standard constructor with tag size
        aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

        // We bundle nonce + ciphertext + tag
        var combined = new byte[nonce.Length + cipherBytes.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, combined, 0, nonce.Length);
        Buffer.BlockCopy(cipherBytes, 0, combined, nonce.Length, cipherBytes.Length);
        Buffer.BlockCopy(tag, 0, combined, nonce.Length + cipherBytes.Length, tag.Length);

        return (Convert.ToBase64String(combined), Convert.ToBase64String(key), Convert.ToBase64String(nonce));
    }
    
    // AES-GCM Decryption
    public static string AesDecrypt(string combinedCipherText, string keyBase64)
    {
        var combined = Convert.FromBase64String(combinedCipherText);
        var key = Convert.FromBase64String(keyBase64);

        var nonce = new byte[12];
        var tag = new byte[16];
        var cipherBytes = new byte[combined.Length - nonce.Length - tag.Length];

        Buffer.BlockCopy(combined, 0, nonce, 0, nonce.Length);
        Buffer.BlockCopy(combined, nonce.Length, cipherBytes, 0, cipherBytes.Length);
        Buffer.BlockCopy(combined, nonce.Length + cipherBytes.Length, tag, 0, tag.Length);

        using var aesGcm = new AesGcm(key, 16);
        var plainBytes = new byte[cipherBytes.Length];
        aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }

    // Signature 
    public static string SignData(string data, string privateKeyBase64)
    {
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyBase64), out _);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        // PSS: probabilistic padding, secure against forgery attacks (replaces PKCS#1 v1.5 signatures)
        var signatureBytes = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return Convert.ToBase64String(signatureBytes);
    }

    public static bool VerifySignature(string data, string signature, string publicKeyBase64)
    {
        try
        {
            using var rsa = RSA.Create();
            if (!ImportPublicKey(rsa, publicKeyBase64))
                return false;

            var dataBytes = Encoding.UTF8.GetBytes(data);
            var signatureBytes = Convert.FromBase64String(signature);
            return rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch
        {
             return false;
        }
    }

    public static bool ImportPublicKey(RSA rsa, string publicKeyPem)
    {
        bool keyLoaded = false;
        string originalKey = publicKeyPem.Trim();

        // Attempt 1: Raw Base64 as SPKI
        if (!keyLoaded && !originalKey.StartsWith("-----"))
        {
            try {
                var keyBytes = Convert.FromBase64String(originalKey);
                rsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
                keyLoaded = true;
            } catch {}
        }

        // Attempt 2: Raw Base64 as PKCS#1
        if (!keyLoaded && !originalKey.StartsWith("-----"))
        {
            try {
                var keyBytes = Convert.FromBase64String(originalKey);
                rsa.ImportRSAPublicKey(keyBytes, out _);
                keyLoaded = true;
            } catch {}
        }

        // Attempt 3: PEM
        if (!keyLoaded && originalKey.StartsWith("-----"))
        {
            try {
                rsa.ImportFromPem(originalKey);
                keyLoaded = true;
            } catch {}
        }

        return keyLoaded;
    }


    public static string GetPublicKeyHash(string publicKeyBase64)
    {
        try {
            // Clean up PEM if present
            var cleanKey = publicKeyBase64
                .Replace("-----BEGIN PUBLIC KEY-----", "")
                .Replace("-----END PUBLIC KEY-----", "")
                .Replace("\n", "")
                .Replace("\r", "")
                .Trim();

            var keyBytes = Convert.FromBase64String(cleanKey);
            var hashBytes = SHA256.HashData(keyBytes);
            return Convert.ToHexString(hashBytes).ToLower();
        }
        catch {
            return string.Empty;
        }
    }
}
