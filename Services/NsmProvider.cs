using System.Runtime.InteropServices;
using System.Text;
using System.Linq;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Communicates with the AWS Nitro Security Module (/dev/nsm) to obtain hardware-backed
/// Attestation Documents (COSE_Sign1 / CBOR format).
/// </summary>
public interface INsmProvider
{
    byte[] GetAttestationDocument(byte[] userData, byte[]? nonce = null, byte[]? publicKey = null);
    bool IsHardwareAvailable { get; }
}

public class NsmProvider : INsmProvider
{
    private const string NsmDevicePath = "/dev/nsm";
    
    // Formula: _IOWR(0x0a, 0, 32 bytes) -> 0xC0200A00
    private const uint NSM_IOCTL_REQUEST = 0xC0200A00; 
    
    public bool IsHardwareAvailable => 
        RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && File.Exists(NsmDevicePath);

    [DllImport("libc", SetLastError = true)]
    private static extern int open(string path, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, uint request, ref NsmIoctlArgs args);

    [StructLayout(LayoutKind.Sequential)]
    private struct NsmIoctlArgs
    {
        public IntPtr Request;
        public UIntPtr RequestLen;
        public IntPtr Response;
        public UIntPtr ResponseLen;
    }

    public byte[] GetAttestationDocument(byte[] userData, byte[]? nonce = null, byte[]? publicKey = null)
    {
        if (!IsHardwareAvailable)
        {
            Console.WriteLine("[NSM] /dev/nsm bulunamadı → Nitro Enclave dışı ortam, simülasyon modu (SADECE GELİŞTİRME).");
            return BuildMockAttestationDocument(userData);
        }

        try
        {
            return RequestAttestationFromHardware(userData, nonce, publicKey);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[NSM] Hardware attestation failed: {ex.Message}. Mock Attestation is DISABLED.");
            throw;
        }
    }

    private static byte[] BuildMockAttestationDocument(byte[] userData)
    {
        // Lokal geliştirme için minimal geçerli CBOR yapısı.
        // Relay'deki AttestationVerifier bu belgeyi PCR0 doğrulaması için kullanır;
        using var ms = new System.IO.MemoryStream();
        ms.WriteByte(0xA1); // map(1)
        WriteCborText(ms, "document");
        var inner = BuildMockInnerDocument(userData);
        WriteCborBytes(ms, inner);
        return ms.ToArray();
    }

    private static byte[] BuildMockInnerDocument(byte[] userData)
    {
        using var ms = new System.IO.MemoryStream();
        ms.WriteByte(0xA2); // map(2)
        WriteCborText(ms, "user_data");
        WriteCborBytes(ms, userData);
        WriteCborText(ms, "pcr0");
        WriteCborBytes(ms, new byte[48]); // 48 sıfır bayt — mock PCR0
        return ms.ToArray();
    }

    private byte[] RequestAttestationFromHardware(byte[] userData, byte[]? nonce, byte[]? publicKey)
    {
        Console.WriteLine($"[NSM] Requesting hardware document (userData len: {userData.Length})");
        var requestCbor = BuildCborAttestationRequest(userData, nonce, publicKey);

        int fd = open(NsmDevicePath, 2); // O_RDWR = 2
        if (fd < 0)
        {
            int err = Marshal.GetLastWin32Error();
            Console.WriteLine($"[NSM ERROR] Cannot open {NsmDevicePath}. fd: {fd}, errno: {err}");
            throw new IOException($"Cannot open {NsmDevicePath}: errno={err}");
        }

        const int REQ_BUF_SIZE = 0x1000;  // 4KB
        const int RESP_BUF_SIZE = 0x4000; // 16KB (Increased)

        IntPtr reqBuf = Marshal.AllocHGlobal(REQ_BUF_SIZE);
        IntPtr respBuf = Marshal.AllocHGlobal(RESP_BUF_SIZE);
        try
        {
            // Zero-initialize response buffer
            for (int i = 0; i < RESP_BUF_SIZE; i++)
                Marshal.WriteByte(respBuf, i, 0);

            // Copy request CBOR into the request buffer
            int copyLen = Math.Min(requestCbor.Length, REQ_BUF_SIZE);
            Marshal.Copy(requestCbor, 0, reqBuf, copyLen);

            var args = new NsmIoctlArgs
            {
                Request = reqBuf,
                RequestLen = (UIntPtr)copyLen,
                Response = respBuf,
                ResponseLen = (UIntPtr)RESP_BUF_SIZE
            };

            Console.WriteLine($"[NSM] Executing ioctl on fd {fd} with 0x{NSM_IOCTL_REQUEST:X} command...");
            int result = ioctl(fd, NSM_IOCTL_REQUEST, ref args);
            
            if (result != 0)
            {
                int errno = Marshal.GetLastWin32Error();
                Console.WriteLine($"[NSM ERROR] ioctl failed. result: {result}, errno: {errno}");
                throw new IOException($"ioctl failed: errno={errno}, result={result}");
            }

            // Read response bytes back
            int actualRespLen = (int)args.ResponseLen;
            var responseBytes = new byte[actualRespLen];
            Marshal.Copy(args.Response, responseBytes, 0, actualRespLen);

            var document = ExtractDocumentFromCborResponse(responseBytes);
            Console.WriteLine($"[NSM] ✓ Hardware Attestation Document successfully obtained. Size: {document.Length} bytes.");
            return document;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[NSM] RequestAttestationFromHardware ERROR: {ex.Message}");
            throw;
        }
        finally
        {
            if (reqBuf != IntPtr.Zero) Marshal.FreeHGlobal(reqBuf);
            if (respBuf != IntPtr.Zero) Marshal.FreeHGlobal(respBuf);
            close(fd);
        }
    }

    private static byte[] BuildCborAttestationRequest(byte[] userData, byte[]? nonce, byte[]? publicKey)
    {
        using var ms = new System.IO.MemoryStream();
        ms.WriteByte(0xA1); // map(1)
        WriteCborText(ms, "Attestation"); // Fix: Use "Attestation" instead of "AttestationRequest"
        
        int innerFields = 1 + (nonce != null ? 1 : 0) + (publicKey != null ? 1 : 0);
        ms.WriteByte((byte)(0xA0 | innerFields)); // map(n)
        
        WriteCborText(ms, "user_data");
        WriteCborBytes(ms, userData);
        
        if (nonce != null) {
            WriteCborText(ms, "nonce");
            WriteCborBytes(ms, nonce);
        }
        if (publicKey != null) {
            WriteCborText(ms, "public_key");
            WriteCborBytes(ms, publicKey);
        }
        
        return ms.ToArray();
    }

    private static void WriteCborText(System.IO.Stream s, string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        WriteCborHeader(s, 3, (uint)bytes.Length); // Major 3: text string
        s.Write(bytes, 0, bytes.Length);
    }

    private static void WriteCborBytes(System.IO.Stream s, byte[] bytes)
    {
        WriteCborHeader(s, 2, (uint)bytes.Length); // Major 2: byte string
        s.Write(bytes, 0, bytes.Length);
    }

    private static void WriteCborHeader(System.IO.Stream s, int major, uint len)
    {
        int majorBits = (major & 0x7) << 5;
        if (len < 24) s.WriteByte((byte)(majorBits | len));
        else if (len < 256) { s.WriteByte((byte)(majorBits | 24)); s.WriteByte((byte)len); }
        else if (len < 65536) { 
            s.WriteByte((byte)(majorBits | 25)); 
            s.WriteByte((byte)(len >> 8)); s.WriteByte((byte)len); 
        }
        else {
            s.WriteByte((byte)(majorBits | 26));
            s.WriteByte((byte)(len >> 24)); s.WriteByte((byte)(len >> 16));
            s.WriteByte((byte)(len >> 8)); s.WriteByte((byte)len);
        }
    }

    private byte[] ExtractDocumentFromCborResponse(byte[] responseCbor)
    {
        // Simple scan for "document" key (64 6F 63 75 6D 65 6E 74)
        byte[] docKey = { 0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74 };
        
        for (int i = 0; i < responseCbor.Length - 12; i++)
        {
            // Manual byte comparison for performance and reliability
            bool match = true;
            for (int k = 0; k < docKey.Length; k++) {
                if (responseCbor[i + k] != docKey[k]) {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                int start = i + docKey.Length;
                // Next byte should be CBOR bstr header (0x40 - 0x5B)
                byte header = responseCbor[start];
                if (header >= 0x40 && header <= 0x5B)
                {
                    int headerLen;
                    long dataLen = ReadCborLength(responseCbor, start, out headerLen);
                    
                    Console.WriteLine($"[NSM] Key 'document' found at index {i}. Data length: {dataLen}, Header length: {headerLen}");
                    
                    if (start + headerLen + dataLen > responseCbor.Length)
                        throw new InvalidDataException("CBOR response truncated or invalid length");

                    byte[] doc = new byte[dataLen];
                    Array.Copy(responseCbor, start + headerLen, doc, 0, (int)dataLen);
                    return doc;
                }
            }
        }
        throw new InvalidDataException("Attestation document not found in NSM response. Raw hex was logged.");
    }

    private long ReadCborLength(byte[] data, int pos, out int headerLen)
    {
        int info = data[pos] & 0x1F;
        if (info < 24) { headerLen = 1; return info; }
        if (info == 24) { headerLen = 2; return data[pos + 1]; }
        if (info == 25) { headerLen = 3; return (data[pos + 1] << 8) | data[pos + 2]; }
        if (info == 26) { headerLen = 5; return ((long)data[pos + 1] << 24) | (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4]; }
        throw new NotSupportedException("Extended CBOR lengths not supported");
    }


}
