using System;
using System.Collections.Generic;

namespace VerifyBlind.Enclave.Services.Vision
{
    /// <summary>İki öznitelik listesi arasında bir eşleşme.</summary>
    public readonly record struct FeatureMatch(int A, int B, int Distance);

    /// <summary>
    /// ÖZNİTELİK EŞLEŞTİRİCİ — kaba kuvvet Hamming + oran testi + çapraz kontrol.
    ///
    /// <para><b>Neden kaba kuvvet:</b> kare başına birkaç yüz öznitelik var; ağaç/karma yapıları
    /// bu boyutta kazandırmaz, ama kod karmaşıklığı ve belirlenirlik riski getirir. Enclave'de
    /// sade ve deterministik olan kazanır.</para>
    ///
    /// <para><b>Oran testi (Lowe):</b> en iyi eşleşme, ikinci en iyiden belirgin biçimde yakın
    /// değilse eşleşme atılır. Tekrar eden dokularda (tuğla, perde kıvrımı, çit) bir nokta
    /// onlarca yere benzer; bu testsiz eşleşmelerin çoğu rastgele olur ve RANSAC'a çöp gider.</para>
    ///
    /// <para><b>Çapraz kontrol:</b> A'nın en iyisi B ise, B'nin de en iyisi A olmalı. Tek yönlü
    /// eşleştirmede bir karedeki tek bir güçlü nokta, öbür karedeki onlarca noktanın "en iyisi"
    /// olarak seçilebilir ve sahte bir yığılma üretir.</para>
    ///
    /// <para>⚠️ Bu aşama hâlâ yanlış eşleşme üretir — görevi onları AZALTMAK. Yanlışları atmak
    /// RANSAC'ın işi; ikisi birlikte çalışır.</para>
    /// </summary>
    public static class FeatureMatcher
    {
        /// <summary>En iyi / ikinci en iyi uzaklık oranı üst sınırı.</summary>
        public const double RatioThreshold = 0.8;

        /// <summary>
        /// Kabul edilen en büyük Hamming uzaklığı (256 bit üzerinden). Bunun üstü, ilgisiz iki
        /// yamanın rastgele benzerliği sayılır.
        ///
        /// <para>Değer 55-90 arasında taranıp ölçüldü: sentetik sahnede sonucu HİÇ değiştirmiyor,
        /// çünkü hayatta kalan yanlış eşleşmeler zaten çok yakın (gerçekten belirsiz yamalar).
        /// Yani bu sayı ayarlanarak kazanılacak bir şey yok; 64 ilkesel bir üst sınır olarak
        /// duruyor (bitlerin dörtte biri), veriye uydurulmuş bir değer değil.</para>
        /// </summary>
        public const int MaxDistance = 64;

        public static List<FeatureMatch> Match(IReadOnlyList<Feature> a, IReadOnlyList<Feature> b)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);

            var result = new List<FeatureMatch>();
            if (a.Count == 0 || b.Count == 0) return result;

            // B tarafının en iyileri, çapraz kontrol için aynı taramada biriktirilir.
            var bestForB = new int[b.Count];
            var bestDistB = new int[b.Count];
            Array.Fill(bestForB, -1);
            Array.Fill(bestDistB, int.MaxValue);

            var bestForA = new int[a.Count];
            var bestDistA = new int[a.Count];
            var secondDistA = new int[a.Count];
            Array.Fill(bestForA, -1);
            Array.Fill(bestDistA, int.MaxValue);
            Array.Fill(secondDistA, int.MaxValue);

            for (int i = 0; i < a.Count; i++)
            {
                ReadOnlySpan<byte> da = a[i].Descriptor;

                for (int j = 0; j < b.Count; j++)
                {
                    int d = BriefDescriptor.Hamming(da, b[j].Descriptor);

                    if (d < bestDistA[i])
                    {
                        secondDistA[i] = bestDistA[i];
                        bestDistA[i] = d;
                        bestForA[i] = j;
                    }
                    else if (d < secondDistA[i])
                    {
                        secondDistA[i] = d;
                    }

                    if (d < bestDistB[j])
                    {
                        bestDistB[j] = d;
                        bestForB[j] = i;
                    }
                }
            }

            for (int i = 0; i < a.Count; i++)
            {
                int j = bestForA[i];
                if (j < 0) continue;
                if (bestDistA[i] > MaxDistance) continue;

                // İkinci en iyi yoksa oran testi uygulanamaz; tek aday varsa uzaklık sınırı yeter.
                if (secondDistA[i] != int.MaxValue &&
                    bestDistA[i] > RatioThreshold * secondDistA[i]) continue;

                if (bestForB[j] != i) continue;   // çapraz kontrol

                result.Add(new FeatureMatch(i, j, bestDistA[i]));
            }

            return result;
        }
    }
}
