using System;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Sentetik DG2 EF fixture'ları — ICAO 9303 / ISO 19794-5 (CBEFF) yapısını taklit eder. PII YOK
/// (gerçek pasaport/kimlik DG2'si kullanılmaz). Hem <see cref="Dg2FaceExtractorTests"/> hem de
/// biyometri kaynağını ham DG2'den alan EnclaveService testleri tarafından paylaşılır.
/// </summary>
internal static class Dg2TestFixtures
{
    /// <summary>
    /// JPEG-biçimli minimal baytlar: SOI (FF D8 FF) ... EOI (FF D9). Extractor decode ETMEZ, yalnız
    /// işaretlere göre dilimler → render edilebilir olması gerekmez.
    /// </summary>
    internal static readonly byte[] ValidJpeg =
    {
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05,
        0xFF, 0xD9
    };

    /// <summary>İçinde <see cref="ValidJpeg"/> gömülü, iyi biçimli bir DG2 EF.</summary>
    internal static byte[] ValidDg2 => BuildDg2(ValidJpeg);

    /// <summary>
    /// Gerçekçi DG2 EF kurar:
    ///   75 { 7F61 { 02 01 &lt;count&gt; 7F60 { A1{BHT} 5F2E { ISO19794-5 kaydı + görüntü } } } }
    /// </summary>
    internal static byte[] BuildDg2(byte[] image)
    {
        // ISO 19794-5 yüz kaydı: "FAC\0" + "010\0" + uzunluk(4) + yüz sayısı(2) + FIB(20) + ImageInfo(12) + görüntü.
        var isoRecord = Concat(
            new byte[] { 0x46, 0x41, 0x43, 0x00, 0x30, 0x31, 0x30, 0x00 }, // 'F''A''C'0  '0''1''0'0
            new byte[] { 0x00, 0x00, 0x00, 0x40 },                          // record length (placeholder)
            new byte[] { 0x00, 0x01 },                                      // number of faces = 1
            new byte[20],                                                   // Facial Information Block
            new byte[12],                                                   // Image Information Block
            image);

        var bdb = Tlv(0x5F2E, isoRecord);                                          // Biometric Data Block
        var bht = new byte[] { 0xA1, 0x03, 0x80, 0x01, 0x02 };                     // küçük Biometric Header Template
        var bit = Tlv(0x7F60, Concat(bht, bdb));                                   // Biometric Information Template
        var bigt = Tlv(0x7F61, Concat(new byte[] { 0x02, 0x01, 0x01 }, bit));      // count=1 + BIT
        return Tlv(0x75, bigt);                                                     // DG2 EF
    }

    /// <summary>BER-TLV kodlar: etiket (1-2 bayt, big-endian) + uzunluk (kısa/uzun biçim) + içerik.</summary>
    private static byte[] Tlv(int tag, byte[] content)
    {
        var tagBytes = tag <= 0xFF
            ? new[] { (byte)tag }
            : new[] { (byte)(tag >> 8), (byte)(tag & 0xFF) };

        byte[] lenBytes;
        if (content.Length < 0x80)
            lenBytes = new[] { (byte)content.Length };
        else if (content.Length < 0x100)
            lenBytes = new byte[] { 0x81, (byte)content.Length };
        else
            lenBytes = new byte[] { 0x82, (byte)(content.Length >> 8), (byte)(content.Length & 0xFF) };

        return Concat(tagBytes, lenBytes, content);
    }

    internal static byte[] Concat(params byte[][] arrays)
    {
        var total = 0;
        foreach (var a in arrays) total += a.Length;
        var result = new byte[total];
        var offset = 0;
        foreach (var a in arrays)
        {
            Buffer.BlockCopy(a, 0, result, offset, a.Length);
            offset += a.Length;
        }
        return result;
    }
}
