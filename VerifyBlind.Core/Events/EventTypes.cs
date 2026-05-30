namespace VerifyBlind.Core.Events;

/// <summary>
/// Sistemde yayımlanan tüm domain event tiplerinin sabit tanımları.
/// Magic string kullanımını önler, typo riskini ortadan kaldırır.
/// </summary>
public static class EventTypes
{
    // ── Handshake ─────────────────────────────────────────────────────────────
    public const string HandshakeInitiated     = "HANDSHAKE_INITIATED";
    public const string HandshakeIntegrityFail = "HANDSHAKE_INTEGRITY_FAIL";

    // ── Login / Verification ──────────────────────────────────────────────────
    public const string LoginIntegrityFail     = "LOGIN_INTEGRITY_FAIL";
    public const string LoginReplayAttempt     = "LOGIN_REPLAY_ATTEMPT";
    public const string LoginReceived          = "LOGIN_RECEIVED";
    public const string LoginEnclaveSuccess    = "LOGIN_ENCLAVE_SUCCESS";
    public const string LoginEnclaveFailed     = "LOGIN_ENCLAVE_FAILED";
    public const string PopResultStored        = "POP_RESULT_STORED";
    public const string PopCancelledByUser     = "POP_CANCELLED_BY_USER";
    public const string CallbackAttempted      = "CALLBACK_ATTEMPTED";
    public const string CallbackSuccess        = "CALLBACK_SUCCESS";
    public const string CallbackFailed         = "CALLBACK_FAILED";

    // ── Revoke ────────────────────────────────────────────────────────────────
    public const string RevokeRequested        = "REVOKE_REQUESTED";
    public const string RevokeIntegrityFail    = "REVOKE_INTEGRITY_FAIL";
    public const string RevokeSuccess          = "REVOKE_SUCCESS";
    public const string RevokeFailed           = "REVOKE_FAILED";

    // ── Partner / QR ─────────────────────────────────────────────────────────
    public const string QrGenerated            = "QR_GENERATED";
    public const string QrDuplicateNonce       = "QR_DUPLICATE_NONCE";
    public const string SignatureVerifyFail    = "SIGNATURE_VERIFY_FAIL";
    public const string CacheRefreshed         = "CACHE_REFRESHED";

    // ── KVKK / Veri Koruma ───────────────────────────────────────────────────
    public const string ConsentGranted           = "CONSENT_GRANTED";
    public const string ConsentWithdrawn         = "CONSENT_WITHDRAWN";
    public const string DataAccessRequested      = "DATA_ACCESS_REQUESTED";
    public const string ErasureRequested         = "ERASURE_REQUESTED";
    public const string ErasureCompleted         = "ERASURE_COMPLETED";
    public const string DataExportRequested      = "DATA_EXPORT_REQUESTED";
    public const string RetentionPurgeCompleted  = "RETENTION_PURGE_COMPLETED";
    public const string BreachDetected           = "BREACH_DETECTED";
    public const string BreachReported           = "BREACH_REPORTED";

    // ── Aggregate Types ───────────────────────────────────────────────────────
    public static class Aggregate
    {
        public const string Verification = "Verification";
        public const string Partner      = "Partner";
        public const string System       = "System";
        public const string Kvkk         = "Kvkk";
    }
}
