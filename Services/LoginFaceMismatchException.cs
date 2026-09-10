using VerifyBlind.Core;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Girişte canlı yüz kapısı reddettiğinde fırlatılır: selfie ticket'taki yüz referansıyla
/// eşleşmedi, VEYA ticket referans taşıdığı halde istek face_proof getirmedi (fail-closed).
/// EnclaveController login catch'i bunu yakalayıp yanıta
/// error_code=<see cref="EnclaveErrorCodes.LoginFaceMismatch"/> ekler; relay resx ile lokalize eder.
///
/// ⚠️ Mesaja skor veya çipten okunan HİÇBİR alan yazılmaz: bu metin login hata gövdesine girer ve
/// relay onu Sentry'ye + verification_logs'a basar. Skor yalnız DiagLog satırındadır.
/// </summary>
public sealed class LoginFaceMismatchException : Exception
{
    public string ErrorCode => EnclaveErrorCodes.LoginFaceMismatch;

    public LoginFaceMismatchException(string message) : base(message) { }
}
