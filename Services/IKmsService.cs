using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services;

public interface IKmsService
{
    Task<string> ComputeHmacAsync(string data);
    Task<string> SignTicketAsync(TicketPayload ticket);
    Task<bool> VerifyTicketSignatureAsync(SignedTicket signedTicket);
}
