namespace VerifyBlind.Enclave.Services;

/// <summary>
/// RegisterAsync akışında belirli bir adımda oluşan hatayı temsil eder.
/// Message → JSON {"code":"ERR_XXX","step":"...","detail":"..."} döner.
/// API katmanı code'u SharedResources üzerinden lokalize eder.
/// </summary>
public class RegistrationException : Exception
{
    public RegistrationStep Step { get; }
    public string ErrorCode { get; }
    public string? TechnicalDetail { get; }
    /// <summary>Biyometrik red durumunda skoru taşır (relay metriği için, ZK-güvenli skaler). Diğer hatalarda null.</summary>
    public float? FaceScore { get; init; }

    public RegistrationException(RegistrationStep step, string errorCode, string? technicalDetail = null)
        : base(errorCode)
    {
        Step = step;
        ErrorCode = errorCode;
        TechnicalDetail = technicalDetail;
    }

    public override string Message =>
        System.Text.Json.JsonSerializer.Serialize(new
        {
            code   = ErrorCode,
            step   = Step.ToString(),
            detail = TechnicalDetail
        });
}

/// <summary>
/// Biyometrik eşik-altı reddi. Skoru taşır → red skoru relay metriğine (ZK-güvenli skaler) yansıtılabilir.
/// </summary>
public class BiometricMismatchException : Exception
{
    public float Score { get; }
    public BiometricMismatchException(float score, string message) : base(message) => Score = score;
}
