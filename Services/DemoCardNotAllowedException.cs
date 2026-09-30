using VerifyBlind.Core;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Demo bileti, test olarak işaretli olmayan bir partnere doğrulama için kullanıldı.
/// Demo kart gerçek bir kişiyi kanıtlamaz; gerçek partnerde "doğrulandı" sonucu üretmemeli.
/// </summary>
public sealed class DemoCardNotAllowedException : Exception
{
    public string ErrorCode => EnclaveErrorCodes.DemoCardTestOnly;

    public DemoCardNotAllowedException(string message) : base(message) { }
}
