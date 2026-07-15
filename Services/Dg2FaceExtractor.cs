namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Biyometrik yüz görüntüsünü SOD-doğrulanmış HAM DG2 EF'sinden çıkarır.
///
/// <para>Güvenlik gerekçesi: biyometrik eşleştirme, telefonun ayrı gönderdiği (ve hiçbir şeye
/// kriptografik bağlı OLMAYAN) yeniden-kodlanmış yüz görüntüsüne değil, Passive Authentication'ın
/// SOD/CSCA hash zincirine karşı doğruladığı ham DG2 baytlarına dayanmalıdır. Aksi halde kötü
/// niyetli/değiştirilmiş bir istemci gerçek DG2'yi (hash geçer) gönderip BAŞKASININ yüzünü
/// biyometriye verebilirdi. Bu sınıf, yüzü doğrulanmış kaynaktan çıkararak o boşluğu kapatır.</para>
///
/// <para>ÇAĞRI SIRASI ŞARTI: yalnızca DG2 hash'i SOD'a karşı doğrulandıktan (PassiveAuth) SONRA
/// çağrılmalı; bu sınıf doğrulama yapmaz, doğrulanmış baytlardan görüntüyü çıkarır.</para>
///
/// <para>Çıkarılan baytlar, jMRTD'nin telefonda <c>imageInputStream</c> ile döndürdüğü gömülü JPEG
/// ile birebir aynıdır → enclave-tarafı YuNet 5-nokta hizalama + ArcFace boru hattının girdisi
/// (BiometricService) değişmeden kalır.</para>
///
/// <para>MVP kapsamı: Türk kimlik kartı DG2'si JPEG'dir. Yabancı pasaportlardaki JPEG2000 (JP2) DG2
/// bu sınıfta DESTEKLENMEZ — JP2 bulunursa açık bir hata ile fail-closed (asla istemci görüntüsüne
/// geri düşmez).</para>
/// </summary>
public static class Dg2FaceExtractor
{
    /// <summary>DG2'den yüz görüntüsü çıkarılamadığında fırlatılır (fail-closed).</summary>
    public sealed class Dg2FaceExtractionException : Exception
    {
        public Dg2FaceExtractionException(string message) : base(message) { }
    }

    /// <summary>
    /// Ham DG2 EF baytlarından gömülü JPEG yüz görüntüsünü döndürür (SOI..EOI dahil).
    /// Bulunamazsa <see cref="Dg2FaceExtractionException"/> fırlatır.
    /// </summary>
    public static byte[] ExtractFaceImage(byte[] dg2Raw)
    {
        if (dg2Raw == null || dg2Raw.Length == 0)
            throw new Dg2FaceExtractionException("DG2 boş — yüz görüntüsü çıkarılamıyor.");

        var jpeg = TryExtractJpeg(dg2Raw);
        if (jpeg == null)
            throw new Dg2FaceExtractionException(
                "DG2 içinde JPEG yüz görüntüsü bulunamadı (yalnız JPEG DG2 destekleniyor; JP2/JPEG2000 bu sürümde desteklenmez).");

        return jpeg;
    }

    /// <summary>
    /// İlk JPEG SOI (FF D8 FF) işaretinden son EOI (FF D9) işaretine kadar olan baytları döndürür.
    /// Tek-yüz DG2'sinde tek görüntü vardır; DG2 zaten SOD-doğrulanmış olduğundan tüm EF üzerinde
    /// taramak güvenlidir. JPEG yoksa null döner.
    /// </summary>
    private static byte[]? TryExtractJpeg(byte[] data)
    {
        int soi = IndexOf(data, 0xFF, 0xD8, 0xFF, start: 0);
        if (soi < 0) return null;

        int eoi = LastIndexOf(data, 0xFF, 0xD9, minStart: soi + 3);
        if (eoi < 0) return null;

        int end = eoi + 2; // EOI dahil
        var slice = new byte[end - soi];
        Buffer.BlockCopy(data, soi, slice, 0, slice.Length);
        return slice;
    }

    private static int IndexOf(byte[] data, byte b0, byte b1, byte b2, int start)
    {
        for (int i = start; i <= data.Length - 3; i++)
            if (data[i] == b0 && data[i + 1] == b1 && data[i + 2] == b2)
                return i;
        return -1;
    }

    private static int LastIndexOf(byte[] data, byte b0, byte b1, int minStart)
    {
        for (int i = data.Length - 2; i >= minStart; i--)
            if (data[i] == b0 && data[i + 1] == b1)
                return i;
        return -1;
    }
}
