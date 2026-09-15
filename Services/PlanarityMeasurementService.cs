using System;
using System.Collections.Generic;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services.FaceAlignment;

namespace VerifyBlind.Enclave.Services
{
    /// <summary>
    /// Yakınlaştırma kanıtını ÖLÇER — karar vermez.
    ///
    /// <para>Kullanıcı telefonu yüzüne yaklaştırır; istemci uzak ve yakın pencerelerden kare
    /// kümesi toplar; burada her karenin 5 YuNet noktası çıkarılıp <see cref="PlanarityProbe"/>
    /// ile düzlem-dışılık sinyali hesaplanır. Düz yüzey (monitör, baskı) ~0 üretir, gerçek yüz
    /// belirgin bir sayı üretir.</para>
    ///
    /// <para>⚠️ <b>Şimdilik yalnız ÖLÇÜM.</b> Hiçbir kaydı reddetmez. Eşik canlı veriyle
    /// kalibre edilecek; kapı ancak meşru kullanıcı dağılımı görüldükten sonra açılır. Bu,
    /// ölçüm hattını önce kurup sonra karar verme kalıbının aynısıdır.</para>
    /// </summary>
    public interface IPlanarityMeasurementService
    {
        PlanarityOutcome Measure(ZoomProof? proof);
    }

    /// <inheritdoc cref="IPlanarityMeasurementService"/>
    public class PlanarityMeasurementService : IPlanarityMeasurementService
    {
        /// <summary>
        /// Pencere başına işlenecek EN FAZLA kare. Her kare bir YuNet çıkarımıdır; sınırsız
        /// kare, register'ı ucuz bir CPU tüketim yüzeyine çevirirdi (aday listesindeki
        /// "tavan iki" kuralıyla aynı gerekçe).
        /// </summary>
        public const int MaxFramesPerWindow = 12;

        /// <summary>
        /// Pencere başına EN AZ kare. Sentetik ölçüm tek kare çiftinin gerçekçi nokta
        /// titremesinde yetmediğini gösterdi (1,5 px'te %60); bunun altında ölçümü "yapıldı"
        /// saymak yanıltıcı olur.
        /// </summary>
        public const int MinFramesPerWindow = 3;

        /// <summary>Tek karenin çözülmüş en büyük boyutu — şişirilmiş yük koruması.</summary>
        private const int MaxFrameBytes = 200_000;

        private readonly IBiometricService _biometric;

        public PlanarityMeasurementService(IBiometricService biometric) => _biometric = biometric;

        public PlanarityOutcome Measure(ZoomProof? proof)
        {
            if (proof == null ||
                (proof.FarFrames.Count == 0 && proof.NearFrames.Count == 0))
            {
                // Eski istemci ya da adımı atlayan akış — ölçüm yok, hata da yok.
                return new PlanarityOutcome { Status = PlanarityStatuses.NoProof };
            }

            List<float[]> far = DetectWindow(proof.FarFrames);
            List<float[]> near = DetectWindow(proof.NearFrames);

            var outcome = new PlanarityOutcome
            {
                FarMeasured = far.Count,
                NearMeasured = near.Count,
            };

            if (far.Count == 0)
            {
                outcome.Status = PlanarityStatuses.NoFaceFar;
                return outcome;
            }

            if (near.Count == 0)
            {
                outcome.Status = PlanarityStatuses.NoFaceNear;
                return outcome;
            }

            // Kısmi ölçüm de kaydedilir: "kaç kare ölçülebildi" kalibrasyonun kendisi için veri.
            // Ama az kareyle çıkan sayıya "ölçüldü" demeyiz — eşik çalışmasını kirletirdi.
            if (far.Count < MinFramesPerWindow || near.Count < MinFramesPerWindow)
                outcome.Status = PlanarityStatuses.NotEnoughFrames;
            else
                outcome.Status = PlanarityStatuses.Measured;

            var farOffset = PlanarityProbe.MedianOffset(far);
            var nearOffset = PlanarityProbe.MedianOffset(near);

            outcome.FarResidual = farOffset?.Magnitude;
            outcome.NearResidual = nearOffset?.Magnitude;
            outcome.Delta = PlanarityProbe.Delta(far, near);

            double? farIed = PlanarityProbe.MedianInterocular(far);
            double? nearIed = PlanarityProbe.MedianInterocular(near);
            if (farIed is > 0 && nearIed is > 0)
                outcome.IedRatio = Math.Round(nearIed.Value / farIed.Value, 4);

            if (outcome.Delta.HasValue) outcome.Delta = Math.Round(outcome.Delta.Value, 5);
            if (outcome.FarResidual.HasValue) outcome.FarResidual = Math.Round(outcome.FarResidual.Value, 5);
            if (outcome.NearResidual.HasValue) outcome.NearResidual = Math.Round(outcome.NearResidual.Value, 5);

            Console.WriteLine(
                $"[Planarity] durum={outcome.Status} uzak={outcome.FarMeasured} yakın={outcome.NearMeasured} " +
                $"delta={outcome.Delta?.ToString("F5") ?? "-"} ied_oran={outcome.IedRatio?.ToString("F2") ?? "-"}");

            return outcome;
        }

        /// <summary>
        /// Bir pencerenin karelerini çözüp noktalarını çıkarır. Çözülemeyen/yüz bulunamayan
        /// kareler SESSİZCE atlanır — pencerede yeterli kare kalıp kalmadığını çağıran yorumlar.
        /// </summary>
        private List<float[]> DetectWindow(List<string> frames)
        {
            var result = new List<float[]>(Math.Min(frames.Count, MaxFramesPerWindow));

            int processed = 0;
            foreach (string b64 in frames)
            {
                if (processed >= MaxFramesPerWindow) break;
                if (string.IsNullOrEmpty(b64)) continue;

                byte[] bytes;
                try
                {
                    bytes = Convert.FromBase64String(b64);
                }
                catch (FormatException)
                {
                    continue;   // bozuk kare — ölçümden düşer, akışı durdurmaz
                }

                if (bytes.Length == 0 || bytes.Length > MaxFrameBytes) continue;

                processed++;

                // Ölçüm kaydı ASLA düşürmez. Gerçek uygulama zaten yutuyor; buradaki kalkan
                // sözleşmeyi koda bağlar: bu yol bir karar yolu değil, bir gözlem yoludur.
                float[]? lm;
                try
                {
                    lm = _biometric.DetectLandmarks(bytes);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Planarity] Kare atlandı (ölçüm kaydı etkilemez): {ex.Message}");
                    continue;
                }

                if (lm != null) result.Add(lm);
            }

            return result;
        }
    }
}
