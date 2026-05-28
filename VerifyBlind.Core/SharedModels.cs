using System.Text.Json;
using System.Text.Json.Serialization;

namespace VerifyBlind.Core.Models;

// Handshake
public class HandshakeRequest
{
    [JsonPropertyName("integrity_token")]
    public string IntegrityToken { get; set; } = string.Empty;

    [JsonPropertyName("fcm_token")]
    public string? FcmToken { get; set; }

    [JsonPropertyName("platform")]
    public string? Platform { get; set; }
}


public enum LivenessAction
{
    None = 0,
    FaceLeft = 1,
    FaceRight = 2,
    Blink = 3,
    Smile = 4
}

public class HandshakeResponse
{
 
    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;
    
    [JsonPropertyName("timestamp")]
    public long Timestamp { get; set; }
    
    [JsonPropertyName("nonce_signature")]
    public string NonceSignature { get; set; } = string.Empty;
    
[JsonPropertyName("attestation_document")]
    public string? AttestationDocument { get; set; } // Base64 encoded AWS Nitro Attestation Document 
    [JsonPropertyName("challenges")]
    public List<LivenessAction> Challenges { get; set; } = new();
}

public class LoginHandshakeResponse
{
    [JsonPropertyName("attestation_document")]
    public string? AttestationDocument { get; set; }
}

// Registration Payload (Encrypted part from Phone)
public class SecurePayload
{
    public string SOD { get; set; } = string.Empty;
    public string DG1 { get; set; } = string.Empty;
    public string DG15 { get; set; } = string.Empty; // AA Public Key (Base64)
    public string ActiveSig { get; set; } = string.Empty;
    public string AAChallenge { get; set; } = string.Empty; // Challenge used for AA (Base64)
    public string UserPubKey { get; set; } = string.Empty;
    
    // Nonce Verification (from Handshake)
    public string Nonce { get; set; } = string.Empty;
    public long Timestamp { get; set; }
    public string NonceSignature { get; set; } = string.Empty;
    
    // Biometric Data (Base64 encoded)
    public string DG2_Photo { get; set; } = string.Empty; // Chip Photo
    public string LivenessVideo { get; set; } = string.Empty; // Base64 (MP4/WebM)
    public string ZoomVideo { get; set; } = string.Empty;     // Base64 (MP4/WebM)
    
    // Best Frame from Liveness (JPEG) for Face Match
    public string UserSelfie { get; set; } = string.Empty;    // Base64 (JPEG)
    
    // Play Integrity API Token
    public string IntegrityToken { get; set; } = string.Empty;
}

// Registration Request (Phone -> Relay -> Enclave)
public class RegistrationRequest
{
    [JsonPropertyName("encrypted_key")]
    public string EncryptedKey { get; set; } = string.Empty; // RSA Encrypted AES Key

    [JsonPropertyName("aes_blob")]
    public string AesBlob { get; set; } = string.Empty; // AES GCM Encrypted SecurePayload

    [JsonPropertyName("country_iso_code")]
    public string CountryIsoCode { get; set; } = string.Empty;
}

// Demo Registration Request (Phone -> Relay -> Enclave)
// NFC/biometric verisi olmadan, enklavda hardcoded demo veriyle gerçek imzalı ticket üretir.
public class DemoRegisterRequest
{
    [JsonPropertyName("user_pub_key")]
    public string UserPubKey { get; set; } = string.Empty;

    [JsonPropertyName("app_version")]
    public string AppVersion { get; set; } = string.Empty;
}

// Ticket
public class TicketPayload
{
    public string TCKN { get; set; } = string.Empty;
    public string Ad { get; set; } = string.Empty;
    public string Soyad { get; set; } = string.Empty;
    public DateTime DogumTarihi { get; set; }
    public string SeriNo { get; set; } = string.Empty;
    public DateTime GecerlilikTarihi { get; set; }
    public string Cinsiyet { get; set; } = string.Empty; // M/F
    public string Uyruk { get; set; } = string.Empty; // Nationality
    public string UserPubKey { get; set; } = string.Empty;
    public string CountryIsoCode { get; set; } = string.Empty;
    /// <summary>
    /// Computed once at registration by the Enclave, signed into the ticket.
    /// Login reads directly — no recomputation needed.
    /// PersonId = hex(SHA256(HMAC(TCKN_Person_id)))
    /// </summary>
    public string PersonId { get; set; } = string.Empty;
    /// <summary>
    /// Computed once at registration by the Enclave, signed into the ticket.
    /// Login reads directly — no recomputation needed.
    /// CardId = hex(SHA256(HMAC(hex(SHA256(SOD))_Card_id)))
    /// </summary>
    public string CardId { get; set; } = string.Empty;
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DocumentType { get; set; } // MRZ line1[0]: P/I/A/C
}

public class SignedTicket
{
    public TicketPayload Payload { get; set; } = new();
    public string Signature { get; set; } = string.Empty; // Enclave HSM Signature
}

// --- Partner Request Models (Signed) ---

public class PartnerRequest
{
    [JsonPropertyName("request")]
    public JsonElement Request { get; set; }

    [JsonPropertyName("sign")]
    public string Sign { get; set; } = string.Empty;
}

public class PartnerRequestData
{
    [JsonPropertyName("partner_id")]
    public string PartnerId { get; set; } = string.Empty;

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("public_key")]
    public string PublicKey { get; set; } = string.Empty;

    [JsonPropertyName("callback_url")]
    public string? CallbackUrl { get; set; }

    [JsonPropertyName("additional_data")]
    public object? SpecialData { get; set; }

    [JsonPropertyName("validations")]
    public Dictionary<string, object>? Validations { get; set; }
}

public class LoginRequest
{
    // --- Fields from Mobile (3 fields) ---
    [JsonPropertyName("encr_signed_ticket")]
    public string EncrSignedTicket { get; set; } = string.Empty; // RSA Encrypted {Signed_Ticket, Nonce}

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty; // API-generated GUID from QR

    [JsonPropertyName("integrity_token")]
    public string IntegrityToken { get; set; } = string.Empty; // Play Integrity Token

    // --- Fields set by API before Enclave relay (serialized to Enclave) ---
    // [JsonPropertyName("partner_id")] - REMOVED (Extracted from QrPayloadJson)
    // public string? PartnerId { get; set; }

    [JsonPropertyName("partner_public_key")]
    public string? PartnerPublicKey { get; set; }

    [JsonPropertyName("qr_payload_json")]
    public string? QrPayloadJson { get; set; } // Raw QR payload JSON from Redis

    /// <summary>Relay API tarafından set edilir. Mobil istemcinin IPv4 adresi (ip4 validation için).</summary>
    [JsonPropertyName("client_ipv4")]
    public string? ClientIpV4 { get; set; }

    /// <summary>Relay API tarafından set edilir. Mobil istemcinin IPv6 adresi (ip6 validation için).</summary>
    [JsonPropertyName("client_ipv6")]
    public string? ClientIpV6 { get; set; }

    // --- Internal API-only fields (not sent to Enclave) ---
    [JsonIgnore]
    public string? CallbackUrl { get; set; }
}

public class LoginResponse
{
    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("validations")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, object>? Validations { get; set; }

    [JsonPropertyName("additional_data")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? SpecialData { get; set; }
}
public class SignedLoginResponse
{
    [JsonPropertyName("payload")]
    public string Payload { get; set; } = string.Empty; // JSON of LoginResponse

    [JsonPropertyName("signature")]
    public string Signature { get; set; } = string.Empty; // RSA signature (Base64)
}
