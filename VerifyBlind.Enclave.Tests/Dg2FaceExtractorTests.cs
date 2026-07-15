using System;
using VerifyBlind.Enclave.Services;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Dg2FaceExtractor birim testleri.
///
/// Amaç: biyometrik yüz görüntüsünü SOD-doğrulanmış HAM DG2 EF'sinden çıkarmak (telefonun ayrı
/// gönderdiği DG2_Photo'ya GÜVENMEDEN). Çıkarılan baytlar, jMRTD'nin telefonda ürettiği gömülü
/// JPEG ile birebir aynı olmalı → enclave-tarafı YuNet 5-nokta hizalama + ArcFace boru hattının
/// girdisi değişmez.
///
/// PII yok: gerçek DG2 yerine ICAO 9303 / ISO 19794-5 yapısını taklit eden SENTETİK fixture'lar
/// kullanılır (bkz <see cref="Dg2TestFixtures"/>).
/// </summary>
public class Dg2FaceExtractorTests
{
    [Fact]
    public void ExtractFaceImage_WellFormedDg2_ReturnsEmbeddedJpegExactly()
    {
        var dg2 = Dg2TestFixtures.BuildDg2(Dg2TestFixtures.ValidJpeg);

        var face = Dg2FaceExtractor.ExtractFaceImage(dg2);

        Assert.Equal(Dg2TestFixtures.ValidJpeg, face);
    }

    [Fact]
    public void ExtractFaceImage_EmptyInput_ThrowsFailClosed()
    {
        Assert.Throws<Dg2FaceExtractor.Dg2FaceExtractionException>(
            () => Dg2FaceExtractor.ExtractFaceImage(Array.Empty<byte>()));
    }

    [Fact]
    public void ExtractFaceImage_NoJpegPresent_ThrowsFailClosed()
    {
        // Geçerli görünümlü ama JPEG İÇERMEYEN DG2 (ör. JP2 imzalı blok). Asla istemci görüntüsüne
        // geri düşmemeli — açık hata ile reddetmeli.
        var jp2 = new byte[] { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A };
        var dg2 = Dg2TestFixtures.BuildDg2(jp2);

        Assert.Throws<Dg2FaceExtractor.Dg2FaceExtractionException>(
            () => Dg2FaceExtractor.ExtractFaceImage(dg2));
    }

    [Fact]
    public void ExtractFaceImage_SoiWithoutEoi_ThrowsFailClosed()
    {
        // SOI (FF D8 FF) var ama EOI (FF D9) yok → eksik/bozuk JPEG → reddet.
        var truncated = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x01, 0x02, 0x03 };
        var dg2 = Dg2TestFixtures.BuildDg2(truncated);

        Assert.Throws<Dg2FaceExtractor.Dg2FaceExtractionException>(
            () => Dg2FaceExtractor.ExtractFaceImage(dg2));
    }
}
