using VerifyBlind.Core;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Login'de ticket'taki kart geçerlilik tarihi geçmişse fırlatılır. EnclaveController login catch'i
/// bunu yakalayıp yanıta error_code=<see cref="EnclaveErrorCodes.CardExpired"/> (ERR_CARD_EXPIRED) ekler;
/// relay bunu resx ile lokalize eder (register'daki ERR_CARD_EXPIRED ile aynı mesaj), mobil böylece
/// "yeniden kayıt" yönlendirmesi yapabilir. (Register yolu zaten RegistrationException ile aynı kodu üretir.)
/// </summary>
public sealed class CardExpiredException : Exception
{
    public string ErrorCode => EnclaveErrorCodes.CardExpired;

    public CardExpiredException(string message) : base(message) { }
}
