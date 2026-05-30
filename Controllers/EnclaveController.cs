using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using Microsoft.AspNetCore.Mvc;

namespace VerifyBlind.Enclave.Controllers;

[ApiController]
[Route("api/[controller]")]
public class EnclaveController : ControllerBase
{
    private readonly EnclaveService _service;
    private readonly IEnclaveKeyService _keyService;

    public EnclaveController(EnclaveService service, IEnclaveKeyService keyService)
    {
        _service = service;
        _keyService = keyService;
    }

    /// <summary>
    /// GET /api/Enclave/public-key
    /// Enclave'in imzalama public key'ini base64 SPKI formatında döner.
    /// Relay tarafından /api/public/enclave-key endpoint'i için kullanılır.
    /// </summary>
    [HttpGet("public-key")]
    public IActionResult GetPublicKey()
    {
        return Ok(new { public_key = _keyService.GetEnclavePublicKey() });
    }

    [HttpPost("handshake")]
    public IActionResult Handshake()
    {
        var diag = new VerifyBlind.Enclave.Services.DiagLog();
        try
        {
            var result = _service.Handshake(diag);
            return Ok(new
            {
                nonce = result.Nonce,
                timestamp = result.Timestamp,
                nonce_signature = result.NonceSignature,
                attestation_document = result.AttestationDocument,
                enclave_pub_key = _keyService.GetEnclavePublicKey(),
                challenges = result.Challenges,
                enclave_diag = diag.Entries
            });
        }
        catch (Exception ex)
        {
            diag.Fail("Handshake", ex.Message);
            Console.WriteLine($"[Enclave Controller] HANDSHAKE ERROR: {ex}");
            return BadRequest(new { error = ex.Message, enclave_diag = diag.Entries });
        }
    }

    [HttpPost("login-handshake")]
    public IActionResult LoginHandshake()
    {
        var diag = new VerifyBlind.Enclave.Services.DiagLog();
        try
        {
            var result = _service.LoginHandshake(diag);
            return Ok(new
            {
                attestation_document = result.AttestationDocument,
                enclave_pub_key = _keyService.GetEnclavePublicKey(),
                enclave_diag = diag.Entries
            });
        }
        catch (Exception ex)
        {
            diag.Fail("LoginHandshake", ex.Message);
            Console.WriteLine($"[Enclave Controller] LOGIN-HANDSHAKE ERROR: {ex}");
            return BadRequest(new { error = ex.Message, enclave_diag = diag.Entries });
        }
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegistrationRequest request)
    {
        var diag = new VerifyBlind.Enclave.Services.DiagLog();
        try
        {
            var result = await _service.RegisterAsync(request, diag);
            diag.Info($"Toplam Enclave süresi: {diag.TotalMs}ms");
            return Ok(new
            {
                encrypted_ticket = result.ticket,
                face_similarity_score = Math.Round(result.faceScore * 100, 1),
                relay_card_id = result.cardId,         // plaintext for relay block check only
                enclave_diag = diag.Entries
            });
        }
        catch (Exception ex)
        {
            diag.Info($"Toplam Enclave süresi: {diag.TotalMs}ms");
            Console.WriteLine($"[Enclave Controller] REGISTER ERROR ({ex.GetType().Name}): {ex}");
            // RegistrationException → kullanıcı verisi hatası (400), beklenmedik hatalar → sunucu hatası (500)
            var statusCode = ex is RegistrationException ? 400 : 500;
            return StatusCode(statusCode, new { error = ex.Message, enclave_diag = diag.Entries });
        }
    }

    [HttpPost("demo-register")]
    public async Task<IActionResult> DemoRegister([FromBody] DemoRegisterRequest request)
    {
        var diag = new VerifyBlind.Enclave.Services.DiagLog();
        try
        {
            var result = await _service.DemoRegisterAsync(request.UserPubKey, diag);
            diag.Info($"Toplam Enclave süresi: {diag.TotalMs}ms");
            return Ok(new
            {
                encrypted_ticket = result.ticket,
                face_similarity_score = Math.Round(result.faceScore * 100, 1),
                relay_card_id = result.cardId,
                enclave_diag = diag.Entries
            });
        }
        catch (Exception ex)
        {
            diag.Info($"Toplam Enclave süresi: {diag.TotalMs}ms");
            Console.WriteLine($"[Enclave Controller] DEMO REGISTER ERROR ({ex.GetType().Name}): {ex}");
            var statusCode = ex is RegistrationException ? 400 : 500;
            return StatusCode(statusCode, new { error = ex.Message, enclave_diag = diag.Entries });
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var diag = new VerifyBlind.Enclave.Services.DiagLog();
        try
        {
            var result = await _service.LoginAsync(request, diag);
            diag.Info($"Toplam Enclave süresi: {diag.TotalMs}ms");

            // Inject enclave_diag into the service result JSON and return as-is.
            // Do NOT wrap result under an "encrypted_response" key — result is already
            // the complete JSON object with encrypted_response, nationality, relay_metadata.
            try
            {
                var node = System.Text.Json.Nodes.JsonNode.Parse(result)!;
                node["enclave_diag"] = System.Text.Json.Nodes.JsonNode.Parse(
                    System.Text.Json.JsonSerializer.Serialize(diag.Entries));
                return Content(node.ToJsonString(), "application/json");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Enclave Controller] Result Parse Warning: {ex.Message}");
                return Content(result, "application/json");
            }
        }
        catch (Exception ex)
        {
            diag.Info($"Toplam Enclave süresi: {diag.TotalMs}ms");
            Console.WriteLine($"[Enclave Controller] LOGIN CRITICAL ERROR ({ex.GetType().Name}): {ex}");
            // InvalidOperationException / InvalidDataException: bilet/kriptografi hatası (istemci verisi) → 400
            // Exception (doğrudan throw): doğrulama hatası (nonce, bağlama, imza) → 400
            // Beklenmedik diğer hatalar (KMS bağlantısı vb.): → 500
            var statusCode = (ex is InvalidOperationException || ex is InvalidDataException || ex.GetType() == typeof(Exception)) ? 400 : 500;
            return StatusCode(statusCode, new { error = ex.Message, enclave_diag = diag.Entries });
        }
    }
}
