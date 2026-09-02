using VerifyBlind.Core;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Login'de ticket'ın IssuedAtUnix'i etkin bir iptal kuralıyla (RevocationPolicy) eşleştiğinde fırlatılır.
/// EnclaveController login catch'i bunu yakalayıp yanıta error_code=<see cref="EnclaveErrorCodes.TicketRevoked"/>
/// (ERR_TICKET_REVOKED) ekler; mobil bu kodu görünce saklı ticket'ı silip yeniden-kayıt akışını tetikler.
/// </summary>
public sealed class TicketRevokedException : Exception
{
    public string ErrorCode => EnclaveErrorCodes.TicketRevoked;

    public TicketRevokedException(string message) : base(message) { }
}
