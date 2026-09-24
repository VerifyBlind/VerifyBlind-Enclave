using System;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using VerifyBlind.Enclave.Services.FaceAlignment;

namespace VerifyBlind.Enclave.Services.Stance
{
    /// <summary>
    /// OLAY ÖZELLİKLERİ — göz kırpma, gülümseme, ağız açma'nın enclave tarafı ölçüsü.
    ///
    /// <para><b>Neden model değil:</b> enclave'de yalnız YuNet'in beş noktası var (göz
    /// merkezleri, burun, ağız köşeleri); göz kapağı ya da dudak konturu yok. Yeni bir model
    /// eklemek hem PCR0'ı hem saldırı yüzeyini değiştirir ve kullanıcının kararı. Burada önce
    /// ÖLÇÜYORUZ: hizalanmış 112×112 karede basit piksel istatistikleri olayı ayırt ediyor mu?
    /// Ediyorsa model gerekmez; etmiyorsa model kararına veriyle gideriz.</para>
    ///
    /// <para>⚠️ Her ölçü aynı duraktaki NÖTR kareye GÖRE yorumlanır, mutlak değil: ışık, cilt
    /// tonu, gözlük kareden kareye değil kişiden kişiye değişir; aynı durağın iki karesi aynı
    /// ışıkta, aynı ölçekte.</para>
    ///
    /// <para>Bölgeler ArcFace kanonik şablonundan türetildi: gözler (38,3 / 73,5 ; 51,6), ağız
    /// köşeleri (41,5 / 70,7 ; 92,3). Hizalama beş noktaya benzerlik dönüşümüyle oturtulduğu
    /// için bölgeler her karede yüzün aynı yerine düşer.</para>
    /// </summary>
    public static class EventFeatures
    {
        private const int Size = FaceAligner.OutputSize;

        /// <summary>Göz yaması yarı-genişliği / yarı-yüksekliği (px, 112 uzayında).</summary>
        private const int EyeHalfW = 9;
        private const int EyeHalfH = 5;

        /// <summary>
        /// Karenin hizalanmış 112×112 parlaklık görüntüsü; çözülemezse null.
        /// </summary>
        public static byte[]? AlignedLuma(byte[] imageBytes, float[] landmarks)
        {
            try
            {
                using var source = Image.Load<Rgb24>(imageBytes);
                using var aligned = FaceAligner.AlignWith(source, landmarks);
                var luma = new byte[Size * Size];
                aligned.ProcessPixelRows(acc =>
                {
                    for (int y = 0; y < Size; y++)
                    {
                        var row = acc.GetRowSpan(y);
                        for (int x = 0; x < Size; x++)
                        {
                            var p = row[x];
                            luma[y * Size + x] = (byte)((p.R * 299 + p.G * 587 + p.B * 114) / 1000);
                        }
                    }
                });
                return luma;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// GÖZ KONTRASTI — iki göz yamasındaki parlaklık standart sapmasının ortalaması.
        ///
        /// <para>Açık göz: koyu iris/göz bebeği + açık sklera → yüksek sapma. Kapalı göz: göz
        /// kapağı derisi tekdüze → düşük sapma (kirpik çizgisi kalır, sıfıra inmez).</para>
        /// </summary>
        public static double EyeContrast(byte[] luma)
        {
            var dst = FaceAligner.CanonicalLandmarks;
            double left = PatchStd(luma, (int)Math.Round(dst[0]), (int)Math.Round(dst[1]), EyeHalfW, EyeHalfH);
            double right = PatchStd(luma, (int)Math.Round(dst[2]), (int)Math.Round(dst[3]), EyeHalfW, EyeHalfH);
            return (left + right) / 2.0;
        }

        /// <summary>
        /// AĞIZ İÇİ KOYULUĞU — ağız bölgesinde, yanak/burun cildinin medyanının yarısından koyu
        /// piksellerin oranı.
        ///
        /// <para>Açık ağızda boşluk koyu görünür. Referans aynı karenin kendi cildi: ışık
        /// değişse de oran bozulmaz.</para>
        /// </summary>
        public static double MouthDarkFraction(byte[] luma)
        {
            var dst = FaceAligner.CanonicalLandmarks;
            int mx0 = (int)Math.Round(dst[6]) + 4, mx1 = (int)Math.Round(dst[8]) - 4;
            int my0 = (int)Math.Round(dst[7]) - 6, my1 = (int)Math.Round(dst[7]) + 12;

            // Cilt referansı: burnun iki yanındaki yanaklar (gözlerin altı, ağzın üstü).
            var skin = new List<byte>(256);
            for (int y = 64; y < 80; y++)
            {
                for (int x = 28; x < 40; x++) skin.Add(luma[y * Size + x]);
                for (int x = 72; x < 84; x++) skin.Add(luma[y * Size + x]);
            }
            skin.Sort();
            double reference = skin[skin.Count / 2];
            if (reference < 1) return 0;

            int dark = 0, total = 0;
            for (int y = Math.Max(0, my0); y < Math.Min(Size, my1); y++)
                for (int x = Math.Max(0, mx0); x < Math.Min(Size, mx1); x++)
                {
                    total++;
                    if (luma[y * Size + x] < reference * 0.5) dark++;
                }
            return total == 0 ? 0 : (double)dark / total;
        }

        /// <summary>
        /// AĞIZ GENİŞLİĞİ — ağız köşeleri arası / göz merkezleri arası, HAM noktalardan.
        ///
        /// <para>Hizalanmış kareden değil ham noktalardan: hizalama beş noktaya en küçük kareler
        /// oturtması; gülümsemede köşeler dışa kayınca dönüşüm onları kısmen şablona geri çeker
        /// ve sinyal ezilir.</para>
        /// </summary>
        public static double? MouthWidthRatio(float[] landmarks)
        {
            if (landmarks is not { Length: 10 }) return null;
            double eye = Distance(landmarks[0], landmarks[1], landmarks[2], landmarks[3]);
            double mouth = Distance(landmarks[6], landmarks[7], landmarks[8], landmarks[9]);
            return eye < 1e-6 ? null : mouth / eye;
        }

        private static double Distance(float x0, float y0, float x1, float y1)
        {
            double dx = x1 - x0, dy = y1 - y0;
            return Math.Sqrt(dx * dx + dy * dy);
        }

        private static double PatchStd(byte[] luma, int cx, int cy, int hw, int hh)
        {
            double sum = 0, sumSq = 0;
            int n = 0;
            for (int y = Math.Max(0, cy - hh); y <= Math.Min(Size - 1, cy + hh); y++)
                for (int x = Math.Max(0, cx - hw); x <= Math.Min(Size - 1, cx + hw); x++)
                {
                    double v = luma[y * Size + x];
                    sum += v;
                    sumSq += v * v;
                    n++;
                }
            if (n == 0) return 0;
            double mean = sum / n;
            return Math.Sqrt(Math.Max(0, sumSq / n - mean * mean));
        }
    }
}
