using System;
using System.Collections.Generic;

namespace VerifyBlind.Enclave.Services.Vision
{
    /// <summary>Arka plan ölçeği kestirimi ve ne kadar veriye dayandığı.</summary>
    /// <param name="Scale">B karesinin A karesine göre arka plan ölçeği.</param>
    /// <param name="Inliers">Modele uyan eşleşme sayısı — güvenin ölçüsü.</param>
    /// <param name="Matches">Uydurma öncesi toplam eşleşme sayısı.</param>
    public readonly record struct BackgroundScale(double Scale, int Inliers, int Matches);

    /// <summary>
    /// ARKA PLAN ÖLÇEĞİ — parallaks oranının PAYDASI.
    ///
    /// <para><b>Ölçülen fikir:</b> telefon uzaklaşıp yaklaşırken yüz ve arka plan farklı
    /// derinlikte oldukları için farklı oranda büyür. Düz bir yüzeyde (ekran, baskı) ikisi AYNI
    /// düzlemdedir ve aynı oranda büyür:
    /// <code>
    /// B = yüz ölçeği / arka plan ölçeği
    ///   düz yüzey  → 1,00   (fizik sabiti, ölçüm değil)
    ///   gerçek yüz → 1,38 - 1,59
    /// </code>
    /// Bu sınıf paydayı üretir; payı (yüz ölçeği) çağıran kendi ölçer.</para>
    ///
    /// <para><b>Yüz DIŞLANIR.</b> Dışlanmazsa yüzün kendi noktaları paydaya karışır, payda paya
    /// yaklaşır ve oran 1'e çekilir — yani saldırıyı meşru gösterir. Dışlama bir eniyileme değil,
    /// ölçümün tanımının parçası.</para>
    ///
    /// <para>⚠️ <c>null</c> dönüşü "ölçemedik" demektir, "sahte" DEĞİL. Dokusuz bir duvarın
    /// önündeki meşru kullanıcı ölçülemez ve reddedilmemelidir; bu sözleşme kapı açıldığında da
    /// korunmalı.</para>
    /// </summary>
    public static class BackgroundScaleEstimator
    {
        /// <summary>
        /// İki karenin arka planı arasındaki ölçek değişimini kestirir.
        /// </summary>
        /// <param name="faceA">A karesindeki yüz kutusu (dışlanır); bilinmiyorsa null.</param>
        /// <param name="faceB">B karesindeki yüz kutusu (dışlanır); bilinmiyorsa null.</param>
        public static BackgroundScale? Estimate(
            byte[] grayA, int widthA, int heightA, Rect? faceA,
            byte[] grayB, int widthB, int heightB, Rect? faceB)
        {
            var a = OrbExtractor.Extract(grayA, widthA, heightA, faceA);
            var b = OrbExtractor.Extract(grayB, widthB, heightB, faceB);

            var matches = FeatureMatcher.Match(a, b);
            if (matches.Count < SimilarityRansac.MinInliers) return null;

            var pairs = new List<PointPair>(matches.Count);
            foreach (var m in matches)
                pairs.Add(new PointPair(
                    a[m.A].X, a[m.A].Y, b[m.B].X, b[m.B].Y,
                    Math.Max(a[m.A].Scale, b[m.B].Scale)));

            var fit = SimilarityRansac.Estimate(pairs);
            if (fit is not { } f) return null;

            return new BackgroundScale(f.Scale, f.Inliers, matches.Count);
        }

        /// <summary>
        /// Parallaks oranı: <paramref name="faceScale"/> / arka plan ölçeği.
        ///
        /// <para>Yüz ölçeği çağıranın kendi ölçümüdür (enclave'de göz-arası mesafe oranı);
        /// istemcinin beyanı DEĞİL. İki sayının da aynı kare çiftinden gelmesi şarttır, yoksa
        /// oran iki farklı hareketi kıyaslar ve anlamsızdır.</para>
        /// </summary>
        public static double? ParallaxRatio(double faceScale, BackgroundScale? background)
        {
            if (background is not { } bg) return null;
            if (bg.Scale <= 0 || faceScale <= 0) return null;
            return faceScale / bg.Scale;
        }
    }
}
