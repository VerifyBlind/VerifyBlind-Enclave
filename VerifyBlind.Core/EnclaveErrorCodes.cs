namespace VerifyBlind.Core;

/// <summary>
/// Enclave'in HTTP yanıtlarında kullandığı hata kodu sabitleri.
/// EnclaveClient._enclaveErrorCodeMap bu sabitlerden kurulur; SharedResources.resx
/// her kod için bir lokalizasyon anahtarı içermelidir.
/// </summary>
public static class EnclaveErrorCodes
{
    public const string RsaDecrypt            = "ERR_RSA_DECRYPT";
    public const string AesGcmTag             = "ERR_AES_GCM_TAG";
    public const string AesDecrypt            = "ERR_AES_DECRYPT";
    public const string InvalidPayload        = "ERR_INVALID_PAYLOAD";
    public const string NonceVerification     = "ERR_NONCE_VERIFICATION";
    public const string ActiveAuth            = "ERR_ACTIVE_AUTH";
    public const string PassiveAuth           = "ERR_PASSIVE_AUTH";
    public const string UnsupportedCountry    = "ERR_UNSUPPORTED_COUNTRY";
    public const string UnsupportedDocType    = "ERR_UNSUPPORTED_DOC_TYPE";
    public const string BiometricMismatch     = "ERR_BIOMETRIC_MISMATCH";
    public const string BiometricModelMissing = "ERR_BIOMETRIC_MODEL_MISSING";
    public const string Dg1Parse              = "ERR_DG1_PARSE";
    public const string CardExpired           = "ERR_CARD_EXPIRED";
    public const string IdGeneration          = "ERR_ID_GENERATION";
    public const string TicketSigning         = "ERR_TICKET_SIGNING";
    public const string ResponseEncryption    = "ERR_RESPONSE_ENCRYPTION";
    public const string DemoMissingPubkey     = "ERR_DEMO_MISSING_PUBKEY";
    public const string Antispoofing          = "ERR_ANTISPOOFING";
    public const string TicketRevoked         = "ERR_TICKET_REVOKED";
}
