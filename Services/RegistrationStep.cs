namespace VerifyBlind.Enclave.Services;

/// <summary>
/// RegisterAsync akışındaki her bir doğrulama/işlem adımını temsil eder.
/// </summary>
public enum RegistrationStep
{
    RsaDecrypt,
    AesDecrypt,
    NonceVerification,
    ActiveAuthentication,
    PassiveAuthentication,
    BiometricVerification,
    Dg1Parsing,
    TicketSigning,
    IdGeneration,
    ResponseEncryption
}
