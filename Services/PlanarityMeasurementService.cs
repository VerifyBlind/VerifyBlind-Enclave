using System;
using System.Collections.Generic;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services.FaceAlignment;

namespace VerifyBlind.Enclave.Services
{
    /// <summary>
    /// Parallaks kanıtını ÖLÇER — karar vermez.
    ///
    /// <para><b>Ölçülecek sinyal:</b> yüz ve arka plan farklı derinlikte olduğu için telefon
    /// uzaklaşıp yaklaşırken farklı oranda büyür. Düz yüzeyde ikisi aynı düzlemdedir ve aynı
    /// oranda büyür — oran <b>1,00</b> olur. Fotoğraf ölçümünde ekran 0,997-1,025 (iki farklı
    /// cihazda), gerçek yüz 1,38-1,59 verdi.</para>
    ///
    /// <para>🔴 <b>BU SÜRÜM SİNYALİ HENÜZ HESAPLAMIYOR.</b> Arka planın ölçeğini çıkarmak
    /// gerçek özellik eşleştirmesi (ORB) gerektiriyor ve o henüz yazılmadı. Beş ucuz alternatif
    /// denendi, beşi de çöktü: hepsi bir hareket modeli VARSAYIYOR, oysa düzlemsel sahnenin
    /// gerçek hareketi parametreleri bilinmeyen bir homografi. ORB'u çalıştıran şey tanımlayıcı
    /// değil, hareketi bilmeden eşleştirip RANSAC ile aykırıları ATMASI.</para>
    ///
    /// <para>Şimdilik toplanan: kaç karede yüz bulunabildi, yüzün gerçek açıklığı (istemcinin
    /// bildirdiğine GÜVENMEDEN, YuNet ile), istemcinin arka plan doku ölçümü. Bunlar eşik ve
    /// kullanılabilirlik kararlarının yarısı — sinyal gelince öbür yarısı tamamlanır.</para>
    ///
    /// <para>⚠️ Hiçbir kaydı reddetmez. "Ölçemedik" ile "sahte" ayrı şeylerdir ve kapı
    /// açıldığında da ayrı kalmalı: ölçülemeyen akışı reddetmek, düz duvarın önündeki meşru
    /// kullanıcıyı giriş yapamaz hale getirir.</para>
    /// </summary>
    public interface IPlanarityMeasurementService
    {
        PlanarityOutcome Measure(ParallaxProof? proof);
    }

    /// <inheritdoc cref="IPlanarityMeasurementService"/>
    public class PlanarityMeasurementService : IPlanarityMeasurementService
    {
        /// <summary>
        /// İşlenecek EN FAZLA kare. Her kare bir YuNet çıkarımıdır; sınırsız kare register'ı
        /// ucuz bir CPU tüketim yüzeyine çevirirdi (aday listesindeki "tavan iki" ile aynı gerekçe).
        /// </summary>
        public const int MaxFrames = 8;

        /// <summary>Parallaks için en az bu kadar ölçülebilir kare gerekir (uzak + yakın).</summary>
        public const int MinFrames = 2;

        /// <summary>Tek karenin çözülmüş en büyük boyutu — şişirilmiş yük koruması.</summary>
        private const int MaxFrameBytes = 400_000;

        /// <summary>
        /// İstemcinin bildirdiği doku bu değerin altındaysa ölçüm "dokusuz" sayılır.
        /// ⚠️ İstemciden gelir ve DOĞRULANMAZ; yalnız etiketleme içindir, karar değil.
        ///
        /// <para><b>18 → 14 (2026-09-19), ilk gerçek dağılımdan.</b> Çıplak duvar 10,8-13,6;
        /// mutfak/perde/tablolu duvar/gece penceresi 14,2-16,1; kitaplık ve koridor 18,1-19,3.
        /// 18 eşiği yedi meşru sahnenin beşini "dokusuz" etiketliyordu. Değer istemcideki
        /// <c>MIN_BACKGROUND_TEXTURE</c> ile AYNI olmak zorunda: farklı olurlarsa kullanıcı
        /// uyarı almadan geçer ama satır <c>no_texture</c> yazılır (ya da tersi).</para>
        /// </summary>
        private const double MinBackgroundTexture = 14.0;

        private readonly IBiometricService _biometric;

        public PlanarityMeasurementService(IBiometricService biometric) => _biometric = biometric;

        public PlanarityOutcome Measure(ParallaxProof? proof)
        {
            if (proof == null)
                return new PlanarityOutcome { Status = PlanarityStatuses.NoProof };

            var outcome = new PlanarityOutcome
            {
                BgTexture = proof.BgTexture,
                ElapsedMs = proof.ElapsedMs,
            };

            // 🔴 Kare YOKSA bile doku ve süre KAYDEDİLİR. Eskiden boş kare listesi daha ilk
            // satırda boş bir sonuçla dönüyordu ve o akışın arka plan dokusu — eşiği kalibre
            // etmek için gereken tek sayı — kayboluyordu. Sahada tam bu oldu: dokusuz arka
            // plan yüzünden hiç kare toplanamayan akıştan geriye sadece "no_proof" kaldı,
            // dokunun KAÇ olduğu ise hiç öğrenilemedi. Ölçemediğimiz akış, neden
            // ölçemediğimizi anlatan akıştır.
            if (proof.Frames.Count == 0)
            {
                outcome.Status = PlanarityStatuses.NoProof;
                Console.WriteLine(
                    $"[Parallax] durum=no_proof kare=0 " +
                    $"doku={proof.BgTexture?.ToString("F1") ?? "-"} süre={proof.ElapsedMs}ms");
                return outcome;
            }

            // Yüzü kendi YuNet'imizle bul — istemcinin bildirdiği genişliklere GÜVENMİYORUZ.
            var interocular = new List<double>();
            int processed = 0;
            foreach (string b64 in proof.Frames)
            {
                if (processed >= MaxFrames) break;
                if (string.IsNullOrEmpty(b64)) continue;

                byte[] bytes;
                try { bytes = Convert.FromBase64String(b64); }
                catch (FormatException) { continue; }
                if (bytes.Length == 0 || bytes.Length > MaxFrameBytes) continue;

                processed++;
                float[]? lm;
                try { lm = _biometric.DetectLandmarks(bytes); }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Parallax] Kare atlandı: {ex.GetType().Name}");
                    continue;
                }
                double? d = lm is null ? null : PlanarityProbe.Interocular(lm);
                if (d is > 0) interocular.Add(d.Value);
            }

            outcome.FarMeasured = interocular.Count;

            if (interocular.Count == 0)
            {
                outcome.Status = PlanarityStatuses.NoFaceFar;
                return outcome;
            }

            // Kareler en uzaktan en yakına SIRALI geliyor → açıklık = son / ilk.
            // Bunu istemciden almıyoruz: açıklık sinyalin anlamını belirleyen sayı ve
            // istemcinin beyanı doğrulanamaz.
            double span = interocular[^1] / interocular[0];
            outcome.IedRatio = Math.Round(span, 4);

            if (interocular.Count < MinFrames)
                outcome.Status = PlanarityStatuses.NotEnoughFrames;
            else if (proof.BgTexture is { } t && t < MinBackgroundTexture)
                // Doku yoksa arka plan ölçeği çıkarılamaz — ama bu bir RED sebebi değil.
                outcome.Status = PlanarityStatuses.NoTexture;
            else if (span < 1.2)
                // Kullanıcı yeterince yaklaşmadı → sinyalin anlamı yok.
                outcome.Status = PlanarityStatuses.NotApproached;
            else
                outcome.Status = PlanarityStatuses.Measured;

            // 🔴 outcome.Delta BİLEREK null: asıl sinyal ORB gelince hesaplanacak.
            Console.WriteLine(
                $"[Parallax] durum={outcome.Status} kare={outcome.FarMeasured}/{proof.Frames.Count} " +
                $"açıklık={span:F2} doku={proof.BgTexture?.ToString("F1") ?? "-"} " +
                $"tam={proof.Complete}");

            return outcome;
        }
    }
}
