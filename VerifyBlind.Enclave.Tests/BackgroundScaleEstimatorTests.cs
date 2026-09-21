using System;
using System.Collections.Generic;
using System.Linq;
using VerifyBlind.Enclave.Services;
using VerifyBlind.Enclave.Services.Vision;
using Xunit;

namespace VerifyBlind.Enclave.Tests
{
    /// <summary>
    /// ORB hattının UÇTAN UCA doğrulaması: bilinen bir ölçek geri bulunabiliyor mu.
    ///
    /// <para>Sahne yordamsal olarak üretiliyor — dünya koordinatlarında dağılmış diskler,
    /// istenen yakınlıkta doğrudan çiziliyor. Bir görüntüyü büyütüp ara değer üretmek yerine
    /// böyle yapmanın sebebi: ara değer bulanıklığı ölçümün kendi hatasına karışır ve testin
    /// neyi ölçtüğü belirsizleşir. Burada kare çiftleri ARASINDA hiçbir yapay bozulma yok,
    /// yalnız gerçek ölçek farkı var.</para>
    ///
    /// <para>Tekrar eden desen (sinüs, tuğla) bilerek kullanılmıyor: oran testi onları zaten
    /// reddeder ve test yanlış sebepten düşerdi.</para>
    /// </summary>
    public class BackgroundScaleEstimatorTests
    {
        private const int W = 240, H = 320;
        private static readonly Blob[] BgBlobs = MakeBlobs(0xB6_1105, 420, 200);
        private static readonly Blob[] FaceBlobs = MakeBlobs(0xFACE_01, 60, 34);

        /// <summary>
        /// Sabit tohumlu sekil kumesi. Diskler DEGIL: hepsi ayni yaricapta daireler birbirinin
        /// aynisidir ve tanimlayici onlari gercekten ayirt edemez - ilk surumde esles,melerin
        /// %84'u yanlis cikti. Farkli en-boy oranli, iki tonlu dikdortgenler her noktaya kendine
        /// ozgu bir kose imzasi verir; gercek bir odanin (kitap sirti, cerceve, priz) yaptigi da budur.
        /// </summary>
        private readonly record struct Blob(double X, double Y, double W, double H, byte V1, byte V2);

        private static Blob[] MakeBlobs(uint seed, int count, int spread)
        {
            uint s = seed;
            uint Next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }

            var blobs = new Blob[count];
            for (int i = 0; i < count; i++)
                blobs[i] = new Blob(
                    (int)(Next() % (uint)(2 * spread)) - spread,
                    (int)(Next() % (uint)(2 * spread)) - spread,
                    3 + Next() % 11,
                    3 + Next() % 11,
                    (byte)(25 + Next() % 205),
                    (byte)(25 + Next() % 205));
            return blobs;
        }

        /// <summary>
        /// Sahneyi verilen yakınlıkta çizer. Arka plan ve yüz AYRI ölçeklerle çizilebilir —
        /// gerçek yüz ile düz ekran arasındaki tek fark tam olarak budur.
        /// </summary>
        private static byte[] Render(double bgScale, double faceScale, bool withFace = true)
        {
            var img = new byte[W * H];

            // Konuma gore degisen yumusak zemin. Duz bir zemin uzerinde ayni yaricapli diskler
            // birbirinin AYNISI olur; oran testi onlari hakli olarak reddeder ve test kendi
            // kurdugu belirsizligi olcer. Gercek bir odada (kitaplik, mobilya, kapi pervazi)
            // her bolgenin kendi baglami vardir - zemin onu temsil ediyor.
            for (int y = 0; y < H; y++)
                for (int x = 0; x < W; x++)
                {
                    double wx = (x - W / 2.0) / bgScale, wy = (y - H / 2.0) / bgScale;
                    double v = 110 + 38 * Math.Sin(wx / 53.0) + 32 * Math.Cos(wy / 41.0)
                                   + 24 * Math.Sin((wx + wy) / 71.0);
                    img[y * W + x] = (byte)Math.Clamp(v, 0, 255);
                }

            void Draw(Blob[] blobs, double scale)
            {
                foreach (var b in blobs)
                {
                    double cx = W / 2.0 + b.X * scale;
                    double cy = H / 2.0 + b.Y * scale;
                    double hw = b.W * scale / 2, hh = b.H * scale / 2;

                    int x0 = (int)Math.Max(0, cx - hw), x1 = (int)Math.Min(W - 1, cx + hw);
                    int y0 = (int)Math.Max(0, cy - hh), y1 = (int)Math.Min(H - 1, cy + hh);

                    for (int y = y0; y <= y1; y++)
                        for (int x = x0; x <= x1; x++)
                            img[y * W + x] = x < cx ? b.V1 : b.V2;
                }
            }

            Draw(BgBlobs, bgScale);
            if (withFace) Draw(FaceBlobs, faceScale);
            return img;
        }

        /// <summary>Yüz kutusu, yüz disklerinin kapladığı merkez bölge.</summary>
        private static Rect FaceRect(double faceScale)
        {
            int half = (int)(40 * faceScale);
            return new Rect(W / 2 - half, H / 2 - (int)(half * 1.25), 2 * half, (int)(2.5 * half));
        }

        private static BackgroundScale? Estimate(double bgA, double faceA, double bgB, double faceB) =>
            BackgroundScaleEstimator.Estimate(
                Render(bgA, faceA), W, H, FaceRect(faceA),
                Render(bgB, faceB), W, H, FaceRect(faceB));

        // ── Ölçek geri bulunuyor mu ───────────────────────────────────────────

        [Fact]
        public void AyniKareOlcekBir()
        {
            var r = Estimate(1.0, 1.0, 1.0, 1.0);

            Assert.NotNull(r);
            Assert.InRange(r!.Value.Scale, 0.98, 1.02);
        }

        /// <summary>
        /// Hattın varlık sebebi. Bilinen bir ölçek farkı geri bulunamıyorsa B oranı da
        /// hesaplanamaz ve bütün tasarım dayanaksız kalır.
        /// </summary>
        [Theory]
        [InlineData(1.15)]
        [InlineData(1.30)]
        [InlineData(1.50)]
        public void BilinenArkaPlanOlcegiGeriBulunur(double factor)
        {
            var r = Estimate(1.0, 1.0, factor, factor);

            Assert.NotNull(r);
            double error = Math.Abs(r!.Value.Scale - factor) / factor;
            Assert.True(error < 0.04,
                $"beklenen {factor:F2}, ölçülen {r.Value.Scale:F3} (%{error * 100:F1} sapma, " +
                $"{r.Value.Inliers}/{r.Value.Matches} uyumlu)");
        }

        // ── Asıl ayrım: düz yüzey mi, gerçek yüz mü ───────────────────────────

        /// <summary>
        /// DÜZ YÜZEY: yüz ve arka plan aynı düzlemde, aynı oranda büyür. Oran 1'e çıkmalı —
        /// bu bir ölçüm değil fizik sabitidir, ekranı eğmek/kaydırmak değiştiremez.
        /// </summary>
        [Fact]
        public void DuzYuzeydeOranBireYakin()
        {
            const double zoom = 1.4;
            var bg = Estimate(1.0, 1.0, zoom, zoom);
            Assert.NotNull(bg);

            double? ratio = BackgroundScaleEstimator.ParallaxRatio(zoom, bg);

            Assert.NotNull(ratio);
            Assert.InRange(ratio!.Value, 0.96, 1.04);
        }

        /// <summary>
        /// GERÇEK YÜZ: yüz 2,0 kat büyürken arka plan yalnız 1,4 kat büyür (daha uzakta olduğu
        /// için). Oran 1,43 — sahada ölçülen 1,38-1,59 bandının içinde.
        /// </summary>
        [Fact]
        public void GercekYuzdeOranBandaDuser()
        {
            var bg = Estimate(1.0, 1.0, 1.4, 2.0);
            Assert.NotNull(bg);

            double? ratio = BackgroundScaleEstimator.ParallaxRatio(2.0, bg);

            Assert.NotNull(ratio);
            Assert.InRange(ratio!.Value, 1.30, 1.60);
        }

        // ── Sözleşmeler ───────────────────────────────────────────────────────

        /// <summary>
        /// Dokusuz arka planda ölçüm İMKÂNSIZ ve bu bir red sebebi değil. Düz duvarın önündeki
        /// meşru kullanıcı burada düşerse giriş yapamaz hâle gelir.
        /// </summary>
        [Fact]
        public void DokusuzArkaPlandaOlculemez()
        {
            var flat = new byte[W * H];
            Array.Fill(flat, (byte)120);

            Assert.Null(BackgroundScaleEstimator.Estimate(flat, W, H, null, flat, W, H, null));
        }

        [Fact]
        public void YuzBolgesindekiNoktalarKullanilmaz()
        {
            var face = FaceRect(1.0);
            var features = OrbExtractor.Extract(Render(1.0, 1.0), W, H, face);

            Assert.NotEmpty(features);
            Assert.DoesNotContain(features, f => face.Contains((int)f.X, (int)f.Y));
        }

        [Fact]
        public void OlcumBelirlenir()
        {
            var a = Estimate(1.0, 1.0, 1.3, 1.3);
            var b = Estimate(1.0, 1.0, 1.3, 1.3);

            Assert.Equal(a!.Value.Scale, b!.Value.Scale);
            Assert.Equal(a.Value.Inliers, b.Value.Inliers);
        }

        // ── En geniş çift + göreli derinlik ────────────────────────────────────

        /// <summary>
        /// Fizik: yüz N, arka plan yüzden g geride. N = 100, 80, 60 ve g = 200 seçildi, yani
        /// kareler arası ölçekler UYDURMA DEĞİL, tek bir sahneden türetildi:
        /// <code>
        /// yüz ölçeği (0→2) = 100/60   = 1,667
        /// arka plan (0→2)  = 300/260  = 1,154
        /// B                = 1,667/1,154 = 1,445
        /// g/N (yakın uçta) = 200/60   = 3,33
        /// </code>
        /// </summary>
        private static (List<GrayImage?> gray, List<Rect> boxes, List<double> ied) Sequence()
        {
            double[] bg = { 1.0, 300.0 / 280.0, 300.0 / 260.0 };
            double[] face = { 1.0, 100.0 / 80.0, 100.0 / 60.0 };

            var gray = new List<GrayImage?>();
            var boxes = new List<Rect>();
            for (int k = 0; k < 3; k++)
            {
                gray.Add(new GrayImage(Render(bg[k], face[k]), W, H));
                boxes.Add(FaceRect(face[k]));
            }
            return (gray, boxes, new List<double> { 60, 75, 100 });
        }

        /// <summary>
        /// 🔴 Bu testin varlık sebebi: B, kıyaslanan çiftin yüz ölçeğini aşamaz. Ardışık
        /// çiftlerle ölçmek sinyali tavana dayayıp kırpıyordu (sahada 1,19-1,21, tavan 1,27).
        /// En geniş çift kullanılınca aynı sahne belirgin biçimde daha yüksek B veriyor.
        /// </summary>
        [Fact]
        public void EnGenisCiftKullanilir()
        {
            var (gray, boxes, ied) = Sequence();

            var r = PlanarityMeasurementService.MeasureParallax(gray, boxes, ied);

            Assert.NotNull(r.Ratio);
            // Ardışık çift 1,167 verirdi; en geniş çift 1,445 vermeli.
            Assert.True(r.Ratio!.Value > 1.30,
                $"en geniş çift kullanılmamış görünüyor: B={r.Ratio.Value:F3} (beklenen ~1,445)");
            Assert.InRange(r.Ratio.Value, 1.30, 1.60);
            Assert.True(r.Inliers > 0, "uyum sayısı raporlanmıyor");
        }

        /// <summary>
        /// P = (B−1)/(s−1): düz yüzeyde 0, sonsuz uzak arka planda 1. Bu sahnede arka plan
        /// yüzden 200, yakın bakış mesafesi 60 birim → P = g/(sN+g) = 200/(1,667·60+200) = 0,667.
        /// </summary>
        [Fact]
        public void NormalizePayFizikleUyusur()
        {
            var (gray, boxes, ied) = Sequence();

            var r = PlanarityMeasurementService.MeasureParallax(gray, boxes, ied);

            Assert.NotNull(r.P);
            Assert.InRange(r.P!.Value, 0.50, 0.82);
        }

        /// <summary>
        /// 🔴 Kullanılan çiftin ölçeği AYRICA raporlanmalı. `ied_ratio`'yu körlemesine s sanmak
        /// sahada yanlış sonuca götürdü: 2,72 açıklıklı bir koşuda en geniş çift tutmamıştı ve
        /// gerçek s 1,91'di; körlemesine hesap P'yi neredeyse yarıya düşürüyordu.
        /// </summary>
        [Fact]
        public void KullanilanOlcekRaporlanir()
        {
            var (gray, boxes, ied) = Sequence();

            var r = PlanarityMeasurementService.MeasureParallax(gray, boxes, ied);

            Assert.NotNull(r.Span);
            Assert.InRange(r.Span!.Value, 1.0, 100.0 / 60.0 + 0.01);
        }

        /// <summary>Düz yüzey: yüz ve arka plan aynı oranda büyür → B ≈ 1, derinlik ≈ 0.</summary>
        [Fact]
        public void DuzYuzeydeDerinlikSifir()
        {
            double[] scales = { 1.0, 1.25, 1.667 };
            var gray = new List<GrayImage?>();
            var boxes = new List<Rect>();
            for (int k = 0; k < 3; k++)
            {
                gray.Add(new GrayImage(Render(scales[k], scales[k]), W, H));
                boxes.Add(FaceRect(scales[k]));
            }

            var r = PlanarityMeasurementService.MeasureParallax(gray, boxes, new List<double> { 60, 75, 100 });

            Assert.NotNull(r.Ratio);
            Assert.InRange(r.Ratio!.Value, 0.94, 1.06);
            Assert.InRange(r.P!.Value, -0.2, 0.2);
        }

        /// <summary>
        /// Halka: öznitelikler yüzün çevresindeki bantta aranır, kadrajın uzak kenarlarında
        /// değil. Saldırganın ekranının DIŞINDA kalan gerçek odayı ölçüme sokmayan şey bu.
        /// </summary>
        [Fact]
        public void HalkaDisindakiNoktalarKullanilmaz()
        {
            var face = FaceRect(1.0);
            var ring = BackgroundScaleEstimator.RingAround(face);
            Assert.NotNull(ring);

            var features = OrbExtractor.Extract(Render(1.0, 1.0), W, H, face, include: ring);

            Assert.NotEmpty(features);
            Assert.DoesNotContain(features, f => !ring!.Value.Contains((int)f.X, (int)f.Y));
        }

        // ── Kapı ──────────────────────────────────────────────────────────────

        /// <summary>
        /// 🔴 Eşiğin iki tarafını da sabitler. Ölçüm ya da eşik kayarsa bu test düşer.
        ///
        /// <para>Saha kalibrasyonu (2026-09-22): desteklenen meşru 0,402-0,832, ekran
        /// düzenekleri −0,022 ve 0,063, eşik 0,30.</para>
        /// </summary>
        [Fact]
        public void EsikDuzYuzeyiElerMesruyuGecirir()
        {
            double[] scales = { 1.0, 1.25, 1.667 };
            var flatGray = new List<GrayImage?>();
            var flatBoxes = new List<Rect>();
            for (int k = 0; k < 3; k++)
            {
                flatGray.Add(new GrayImage(Render(scales[k], scales[k]), W, H));
                flatBoxes.Add(FaceRect(scales[k]));
            }
            var ied = new List<double> { 60, 75, 100 };

            var flat = PlanarityMeasurementService.MeasureParallax(flatGray, flatBoxes, ied);
            var real = PlanarityMeasurementService.MeasureParallax(
                Sequence().gray, Sequence().boxes, Sequence().ied);

            Assert.NotNull(flat.P);
            Assert.NotNull(real.P);
            Assert.True(flat.P!.Value < PlanarityMeasurementService.MinParallaxP,
                $"düz yüzey eşiği geçiyor: P={flat.P.Value:F3} ≥ {PlanarityMeasurementService.MinParallaxP}");
            Assert.True(real.P!.Value > PlanarityMeasurementService.MinParallaxP,
                $"gerçek sahne eşiğe takılıyor: P={real.P.Value:F3} < {PlanarityMeasurementService.MinParallaxP}");
        }
    }
}
