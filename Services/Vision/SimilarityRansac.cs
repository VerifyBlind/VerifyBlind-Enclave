using System;
using System.Collections.Generic;
using VerifyBlind.Enclave.Services.FaceAlignment;

namespace VerifyBlind.Enclave.Services.Vision
{
    /// <summary>Bir nokta eşleşmesi: A karesindeki konum → B karesindeki konum.</summary>
    /// <param name="Scale">
    /// Noktanın bulunduğu en kaba piramit kademesinin oranı. Uyum toleransı bununla ÇARPILIR.
    ///
    /// <para>🔴 Sabit piksel toleransı yanlış: 5. kademede bulunan bir nokta kaynak
    /// koordinatlarına 2,5 ile çarpılarak taşınıyor, dolayısıyla oradaki 1 piksellik konum
    /// belirsizliği kaynakta 2,5 piksele karşılık geliyor. Sabit 4 piksel eşiğiyle kaba
    /// kademelerin doğru eşleşmeleri toptan aykırı sayılıyordu — yüz kutusunun büyük olduğu
    /// yakın karede geriye zaten az nokta kaldığı için ölçüm tamamen düşüyordu.</para>
    /// </param>
    public readonly record struct PointPair(double Ax, double Ay, double Bx, double By, double Scale = 1.0);

    /// <summary>Uydurulan benzerlik dönüşümünün sonucu.</summary>
    /// <param name="Scale">B'nin A'ya göre ölçeği — ARKA PLAN ÖLÇEĞİ budur.</param>
    /// <param name="Rotation">Dönme açısı (radyan).</param>
    /// <param name="Inliers">Modele uyan eşleşme sayısı.</param>
    /// <param name="Total">Değerlendirilen toplam eşleşme sayısı.</param>
    public readonly record struct SimilarityFit(double Scale, double Rotation, int Inliers, int Total);

    /// <summary>
    /// RANSAC İLE BENZERLİK KESTİRİMİ — ORB'un son ve belirleyici aşaması.
    ///
    /// <para><b>Neden RANSAC, neden en-küçük-kareler değil:</b> eşleşmelerin bir kısmı YANLIŞTIR
    /// ve en-küçük-kareler tek bir yanlış eşleşmeden bile ciddi biçimde sapar. Denenen beş ucuz
    /// yöntemin hepsi de bu yüzden çökmüştü: hepsi bütün verinin doğru olduğunu varsayıyordu.
    /// ORB'u çalıştıran şey tanımlayıcı değil, hareketi BİLMEDEN uydurup aykırıları atabilmesi.</para>
    ///
    /// <para><b>Model neden benzerlik (4 serbestlik):</b> ölçek + dönme + öteleme. Telefon
    /// uzaklaşıp yaklaşırken arka plan kabaca bu dönüşümü yaşar. Tam homografi (8 serbestlik)
    /// daha genel ama daha çok nokta ister ve gürültüde ölçeği öteleme/eğrilikle takas ederek
    /// tam da ölçmek istediğimiz sayıyı bulanıklaştırır.</para>
    ///
    /// <para>🔴 <b>Örnekleme deterministik.</b> Sabit tohumlu üreteç kullanılıyor: aynı girdi her
    /// koşuda aynı sonucu vermeli. Rastgele tohum, aynı akışın iki kez farklı karar vermesi
    /// demektir — hem ayıklanamaz hem de "aynı kaynak → aynı davranış" iddiasını bozar.</para>
    /// </summary>
    public static class SimilarityRansac
    {
        /// <summary>Modele uyum sayılan en büyük yeniden izdüşüm hatası (piksel).</summary>
        public const double InlierPixels = 4.0;

        /// <summary>Sonucun anlamlı sayılması için gereken en az uyumlu eşleşme.</summary>
        public const int MinInliers = 12;

        private const int Iterations = 300;

        /// <summary>
        /// Eşleşmelerden sağlam bir benzerlik dönüşümü kestirir.
        /// </summary>
        /// <returns>
        /// Yeterli uyum bulunamazsa <c>null</c> — "ölçemedik" demektir, "sahte" DEĞİL.
        /// Bu ayrım ölçüm kapıya döndüğünde de korunmalı: dokusuz duvarın önündeki meşru
        /// kullanıcı ölçülemez, reddedilmemeli.
        /// </returns>
        public static SimilarityFit? Estimate(IReadOnlyList<PointPair> pairs)
        {
            ArgumentNullException.ThrowIfNull(pairs);
            if (pairs.Count < MinInliers) return null;

            uint state = 0x5EED_A17E;
            uint Next()
            {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                return state;
            }

            var src = new float[4];
            var dst = new float[4];
            int bestInliers = 0;
            float[]? bestModel = null;

            for (int iter = 0; iter < Iterations; iter++)
            {
                int i = (int)(Next() % (uint)pairs.Count);
                int j = (int)(Next() % (uint)pairs.Count);
                if (i == j) continue;

                var p = pairs[i];
                var q = pairs[j];

                // İki nokta çakışıksa dönüşüm tanımsız — Umeyama burada istisna atar.
                if (Math.Abs(p.Ax - q.Ax) < 1e-6 && Math.Abs(p.Ay - q.Ay) < 1e-6) continue;

                src[0] = (float)p.Ax; src[1] = (float)p.Ay;
                src[2] = (float)q.Ax; src[3] = (float)q.Ay;
                dst[0] = (float)p.Bx; dst[1] = (float)p.By;
                dst[2] = (float)q.Bx; dst[3] = (float)q.By;

                float[] model;
                try { model = Umeyama.SimilarityTransform(src, dst); }
                catch (ArgumentException) { continue; }

                int inliers = CountInliers(pairs, model);
                if (inliers > bestInliers)
                {
                    bestInliers = inliers;
                    bestModel = model;
                }
            }

            if (bestModel is null || bestInliers < MinInliers) return null;

            // Uyumluların tamamıyla yeniden uydur: iki noktadan çıkan model gürültülüdür,
            // asıl sayıyı uyumlu kümenin tamamı verir.
            var inlierSrc = new List<float>(bestInliers * 2);
            var inlierDst = new List<float>(bestInliers * 2);
            foreach (var pair in pairs)
            {
                if (!IsInlier(pair, bestModel)) continue;
                inlierSrc.Add((float)pair.Ax); inlierSrc.Add((float)pair.Ay);
                inlierDst.Add((float)pair.Bx); inlierDst.Add((float)pair.By);
            }

            float[] refined;
            try { refined = Umeyama.SimilarityTransform([.. inlierSrc], [.. inlierDst]); }
            catch (ArgumentException) { refined = bestModel; }

            double a = refined[0], b = refined[3];
            double scale = Math.Sqrt(a * a + b * b);
            if (scale <= 0 || double.IsNaN(scale)) return null;

            return new SimilarityFit(scale, Math.Atan2(b, a), bestInliers, pairs.Count);
        }

        private static int CountInliers(IReadOnlyList<PointPair> pairs, float[] model)
        {
            int count = 0;
            foreach (var pair in pairs)
                if (IsInlier(pair, model)) count++;
            return count;
        }

        private static bool IsInlier(PointPair p, float[] m)
        {
            double px = m[0] * p.Ax + m[1] * p.Ay + m[2];
            double py = m[3] * p.Ax + m[4] * p.Ay + m[5];
            double dx = px - p.Bx, dy = py - p.By;
            double tol = InlierPixels * Math.Max(1.0, p.Scale);
            return dx * dx + dy * dy <= tol * tol;
        }
    }
}
