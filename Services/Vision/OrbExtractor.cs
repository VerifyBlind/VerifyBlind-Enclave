using System;
using System.Collections.Generic;

namespace VerifyBlind.Enclave.Services.Vision
{
    /// <summary>
    /// Bir öznitelik: KAYNAK görüntü koordinatlarında konum, yönelim, bulunduğu piramit ölçeği
    /// ve 256 bitlik imza.
    /// </summary>
    /// <param name="X">Kaynak (0. kademe) görüntüsündeki sütun.</param>
    /// <param name="Y">Kaynak görüntüsündeki satır.</param>
    /// <param name="Scale">Bulunduğu kademenin küçültme oranı — 1,0 tam çözünürlük.</param>
    public readonly record struct Feature(double X, double Y, double Angle, double Scale, byte[] Descriptor);

    /// <summary>
    /// ORB ÖZNİTELİK ÇIKARICI — piramit + FAST + rBRIEF.
    ///
    /// <para><b>Piramit neden şart:</b> BRIEF ölçek değişmez DEĞİLDİR. Bizim durumumuz ise tam
    /// olarak ölçekler arası: uzak ve yakın kare arasında arka plan ~1,2-1,5 kat büyüyor. Tek
    /// çözünürlükte çalışan bir çıkarıcı bu iki kareyi hiç eşleştiremez — ölçüm sessizce sıfır
    /// eşleşmeyle biter ve "arka planda doku yoktu" gibi görünür. Görüntü kademe kademe
    /// küçültülünce uzak karenin bir kademesi ile yakın karenin başka bir kademesi aynı fiziksel
    /// deseni AYNI piksel boyutunda görür ve imzalar tutar.</para>
    ///
    /// <para><b>Kademeler arası oran 1,2:</b> ORB'un varsayılanı. Daha büyük adım kademe sayısını
    /// azaltır ama iki kademe arasına düşen ölçekler eşleşmez hâle gelir; daha küçük adım
    /// maliyeti arttırır. Altı kademe 1 ile 2,99 arasını tarar, beklediğimiz 1,5'lik aralığı
    /// rahatça kapsar.</para>
    ///
    /// <para><b>Küçültme ALAN ORTALAMASIYLA:</b> en yakın komşuyla küçültmek örtüşme (aliasing)
    /// üretir, örtüşme de tanımlayıcıyı kare kare oynatır. Bu, eşleştirmeyi sessizce bozan ve
    /// sonradan bulunması zor bir hata sınıfıdır.</para>
    /// </summary>
    public static class OrbExtractor
    {
        /// <summary>Ardışık kademeler arası küçültme oranı.</summary>
        public const double LevelFactor = 1.2;

        /// <summary>Kademe sayısı (0. kademe tam çözünürlük).</summary>
        public const int Levels = 6;

        /// <summary>Bir kademenin taranabilmesi için gereken en küçük kenar.</summary>
        private const int MinSide = 2 * FastDetector.OrientationRadius + 8;

        /// <summary>
        /// Görüntüdeki öznitelikleri tüm kademelerde çıkarır.
        /// </summary>
        /// <param name="exclude">
        /// KAYNAK koordinatlarında dışlanacak dikdörtgen — yüz bölgesi. Ölçülen şey ARKA PLANIN
        /// ölçeği; yüzün kendi noktaları payı paydaya karıştırır ve B oranını 1'e doğru çeker,
        /// yani saldırıyı meşru gibi gösterir. Dışlama isteğe bağlı değil, ölçümün tanımının
        /// parçası.
        /// </param>
        /// <param name="maxPerLevel">Kademe başına en güçlü kaç nokta tutulacak.</param>
        public static List<Feature> Extract(
            byte[] gray,
            int width,
            int height,
            Rect? exclude = null,
            int maxPerLevel = 150,
            int threshold = 20)
        {
            ArgumentNullException.ThrowIfNull(gray);
            var features = new List<Feature>(maxPerLevel * Levels);

            for (int level = 0; level < Levels; level++)
            {
                double scale = Math.Pow(LevelFactor, level);
                int lw = (int)(width / scale);
                int lh = (int)(height / scale);
                if (lw < MinSide || lh < MinSide) break;

                byte[] img = level == 0 ? gray : Downscale(gray, width, height, lw, lh);

                // 🔴 Dışlama kademeye taşınırken DIŞA doğru büyütülür, kırpılmaz.
                //
                // Kademede bulunan nokta kaynak koordinatlarına geri çarpıldığı için, aşağı
                // yuvarlanmış bir kenar yüzün içine düşen noktayı serbest bırakır: test tam
                // olarak bunu yakaladı. Ayrıca yarıçap kadar pay bırakılıyor — tanımlayıcı
                // noktanın çevresindeki yamayı okuyor, yüze değen bir yama yüz bilgisi taşır
                // ve paydayı paya yaklaştırarak oranı 1'e, yani saldırı lehine çeker.
                Rect? levelExclude = null;
                if (exclude is { } r)
                {
                    int pad = FastDetector.OrientationRadius;
                    int lx0 = (int)Math.Floor(r.X / scale) - pad;
                    int ly0 = (int)Math.Floor(r.Y / scale) - pad;
                    int lx1 = (int)Math.Ceiling((r.X + r.Width) / scale) + pad;
                    int ly1 = (int)Math.Ceiling((r.Y + r.Height) / scale) + pad;
                    levelExclude = new Rect(lx0, ly0, lx1 - lx0, ly1 - ly0);
                }

                var keyPoints = FastDetector.Detect(img, lw, lh, threshold, levelExclude, maxPerLevel);

                foreach (var kp in keyPoints)
                {
                    var descriptor = BriefDescriptor.Describe(img, lw, lh, kp);
                    if (descriptor is null) continue;

                    // Konum KAYNAK koordinatlarına taşınır: RANSAC iki görüntüyü kendi tam
                    // çözünürlüklerinde kıyaslar, kademe yalnız eşleştirmeyi mümkün kılan ara adım.
                    features.Add(new Feature(kp.X * scale, kp.Y * scale, kp.Angle, scale, descriptor));
                }
            }

            return features;
        }

        /// <summary>
        /// Alan ortalamasıyla küçültme. Her hedef piksel, kaynaktaki karşılık gelen dikdörtgenin
        /// ortalamasıdır — örtüşmeyi bastırır, tanımlayıcıyı kararlı tutar.
        /// </summary>
        internal static byte[] Downscale(byte[] src, int sw, int sh, int dw, int dh)
        {
            var dst = new byte[dw * dh];
            double fx = (double)sw / dw;
            double fy = (double)sh / dh;

            for (int y = 0; y < dh; y++)
            {
                int y0 = (int)(y * fy);
                int y1 = Math.Min(sh, Math.Max(y0 + 1, (int)((y + 1) * fy)));

                for (int x = 0; x < dw; x++)
                {
                    int x0 = (int)(x * fx);
                    int x1 = Math.Min(sw, Math.Max(x0 + 1, (int)((x + 1) * fx)));

                    int sum = 0, count = 0;
                    for (int yy = y0; yy < y1; yy++)
                    {
                        int rowBase = yy * sw;
                        for (int xx = x0; xx < x1; xx++)
                        {
                            sum += src[rowBase + xx];
                            count++;
                        }
                    }

                    dst[y * dw + x] = (byte)(sum / count);
                }
            }

            return dst;
        }
    }
}
