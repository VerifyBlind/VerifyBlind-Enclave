using System;
using System.Linq;
using VerifyBlind.Enclave.Services.Vision;
using Xunit;

namespace VerifyBlind.Enclave.Tests
{
    /// <summary>
    /// FAST-9 köşe bulucunun SENTETİK doğrulaması.
    ///
    /// <para>Fotoğraf kullanılmıyor: her girdi burada üretiliyor, beklenen çıktı geometriden
    /// biliniyor. Parallaks deneyindeki 40 fotoğraf ve Python referansı bulunamadı, ama bu
    /// aşama için gerekli de değil — köşe bulucunun doğruluğu "bilinen köşeyi buluyor mu,
    /// bilinen kenarı elemiyor mu" sorusudur ve ikisi de sentetik olarak sorulabilir.</para>
    ///
    /// <para>Saha doğrulaması ayrı ve daha sonra: gerçek yüzde B ≈ 1,38-1,59, dört düz düzenekte
    /// (monitör/TV fotoğrafı, telefon ekranı, monitörde canlı kamera) B ≈ 1,00.</para>
    /// </summary>
    public class FastDetectorTests
    {
        private const int Bg = 30;
        private const int Fg = 200;

        private static byte[] Blank(int w, int h, byte value = Bg)
        {
            var img = new byte[w * h];
            Array.Fill(img, value);
            return img;
        }

        /// <summary>Koyu zemine parlak bir kare basar; köşeleri [x0,x1) × [y0,y1) sınırındadır.</summary>
        private static byte[] WithSquare(int w, int h, int x0, int y0, int x1, int y1)
        {
            var img = Blank(w, h);
            for (int y = y0; y < y1; y++)
                for (int x = x0; x < x1; x++)
                    img[y * w + x] = Fg;
            return img;
        }

        /// <summary>Kare görüntüyü saat yönünde 90° döndürür.</summary>
        private static byte[] Rotate90(byte[] src, int n)
        {
            var dst = new byte[n * n];
            for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                    dst[y * n + x] = src[(n - 1 - x) * n + y];
            return dst;
        }

        private static bool HasPointNear(System.Collections.Generic.List<KeyPoint> pts, int x, int y, int tol) =>
            pts.Any(p => Math.Abs(p.X - x) <= tol && Math.Abs(p.Y - y) <= tol);

        // ── Köşe bulma ────────────────────────────────────────────────────────

        [Fact]
        public void DuzYuzeydeKoseYok()
        {
            var pts = FastDetector.Detect(Blank(120, 120), 120, 120);
            Assert.Empty(pts);
        }

        [Fact]
        public void KareninDortKosesiBulunur()
        {
            var img = WithSquare(120, 120, 40, 40, 80, 80);
            var pts = FastDetector.Detect(img, 120, 120);

            Assert.True(HasPointNear(pts, 40, 40, 4), "sol üst köşe bulunamadı");
            Assert.True(HasPointNear(pts, 79, 40, 4), "sağ üst köşe bulunamadı");
            Assert.True(HasPointNear(pts, 40, 79, 4), "sol alt köşe bulunamadı");
            Assert.True(HasPointNear(pts, 79, 79, 4), "sağ alt köşe bulunamadı");
        }

        /// <summary>
        /// FAST'ın varlık sebebi: kenar köşe DEĞİLDİR. Düz bir kenarda çember ikiye bölünür
        /// (8+8), dokuz ardışık nokta oluşmaz. Bu koşul kalkarsa bütün kenarlar nokta üretir
        /// ve eşleştirme kullanılamaz hâle gelir.
        /// </summary>
        [Fact]
        public void DuzKenarKoseSayilmaz()
        {
            var img = WithSquare(120, 120, 40, 40, 80, 80);
            var pts = FastDetector.Detect(img, 120, 120);

            Assert.False(HasPointNear(pts, 60, 40, 2), "üst kenarın ortası köşe sayılmış");
            Assert.False(HasPointNear(pts, 40, 60, 2), "sol kenarın ortası köşe sayılmış");
        }

        /// <summary>
        /// Bastırma olmadan tek bir köşe, 3×3 komşuluğuyla birlikte dokuz kez raporlanır.
        /// Dört köşeli bir karede toplam nokta sayısının küçük kalması bunu sabitliyor.
        /// </summary>
        [Fact]
        public void BastirmaKopyalariAtar()
        {
            var img = WithSquare(120, 120, 40, 40, 80, 80);
            var pts = FastDetector.Detect(img, 120, 120);

            Assert.InRange(pts.Count, 4, 16);
        }

        [Fact]
        public void DislananBolgeTaranmaz()
        {
            var img = WithSquare(120, 120, 40, 40, 80, 80);
            var exclude = new Rect(30, 30, 30, 30);   // sol üst köşeyi içine alır

            var pts = FastDetector.Detect(img, 120, 120, exclude: exclude);

            Assert.False(HasPointNear(pts, 40, 40, 4), "dışlanan bölgede nokta üretildi");
            Assert.True(HasPointNear(pts, 79, 79, 4), "dışlama fazlasını yedi");
        }

        [Fact]
        public void TavanEnGucluleriBirakir()
        {
            var img = WithSquare(120, 120, 40, 40, 80, 80);

            var all = FastDetector.Detect(img, 120, 120);
            var capped = FastDetector.Detect(img, 120, 120, maxPoints: 2);

            Assert.Equal(2, capped.Count);
            Assert.All(capped, p => Assert.Contains(all, q => q.X == p.X && q.Y == p.Y));
            Assert.True(capped[0].Score >= capped[1].Score, "tavan skora göre sıralamıyor");
        }

        [Fact]
        public void KenaraCokYakinNoktaUretilmez()
        {
            // Yönelim yaması 15 yarıçaplı; bu görüntüde hiçbir noktaya yer yok.
            var img = WithSquare(20, 20, 5, 5, 15, 15);
            Assert.Empty(FastDetector.Detect(img, 20, 20));
        }

        // ── Yönelim ───────────────────────────────────────────────────────────
        //
        // Yönelim, tanımlayıcının döndürülerek okunmasını sağlayan şey. Yanlışsa aynı desen
        // kamera eğildiğinde farklı bit üretir ve eşleştirme sessizce çöker — bu yüzden
        // dört yönde ayrı ayrı sabitleniyor.

        /// <summary>Merkezin bir yanı parlak, diğeri koyu olan dairesel yama.</summary>
        private static byte[] HalfBright(int n, Func<int, int, bool> brightWhen)
        {
            var img = Blank(n, n);
            for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                    if (brightWhen(x - n / 2, y - n / 2))
                        img[y * n + x] = Fg;
            return img;
        }

        [Theory]
        [InlineData("sağ", 0.0)]
        [InlineData("alt", Math.PI / 2)]
        [InlineData("sol", Math.PI)]
        [InlineData("üst", -Math.PI / 2)]
        public void YonelimParlakTarafiGosterir(string yon, double beklenen)
        {
            const int n = 41;
            Func<int, int, bool> test = yon switch
            {
                "sağ" => (dx, _) => dx > 0,
                "alt" => (_, dy) => dy > 0,
                "sol" => (dx, _) => dx < 0,
                _ => (_, dy) => dy < 0,
            };

            double angle = FastDetector.Orientation(HalfBright(n, test), n, n, n / 2, n / 2);

            // π ile -π aynı yön; kıyaslama sarmalı hesaba katmalı.
            double diff = Math.Atan2(Math.Sin(angle - beklenen), Math.Cos(angle - beklenen));
            Assert.True(Math.Abs(diff) < 0.05, $"{yon}: beklenen {beklenen:F2}, ölçülen {angle:F2}");
        }

        /// <summary>
        /// Asıl şart bu: görüntü dönerse yönelim onunla birlikte dönmeli. Mutlak açının doğru
        /// olması yetmez — tanımlayıcının işine yarayan şey bu eş-değişimdir.
        /// </summary>
        [Fact]
        public void YonelimGoruntuyleBirlikteDoner()
        {
            const int n = 41;
            var img = HalfBright(n, (dx, _) => dx > 0);
            var rotated = Rotate90(img, n);

            double before = FastDetector.Orientation(img, n, n, n / 2, n / 2);
            double after = FastDetector.Orientation(rotated, n, n, n / 2, n / 2);

            double delta = Math.Atan2(Math.Sin(after - before), Math.Cos(after - before));
            Assert.True(Math.Abs(delta - Math.PI / 2) < 0.05,
                $"90° dönmede yönelim {delta:F2} rad kaydı, beklenen {Math.PI / 2:F2}");
        }
    }
}
