using System;
using System.IO;
using System.Linq;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

namespace VerifyBlind.Enclave.Services
{
    public interface IAntiSpoofService
    {
        bool IsModelLoaded { get; }

        /// <summary>
        /// Returns the 3-class softmax. Live = index 1 (etiketli referansla doğrulandı:
        /// ham-BGR [0,255] girdide real→idx1≈0.99, fake→idx1≈0.00).
        /// Values below threshold indicate a spoof attempt.
        /// </summary>
        float[] Predict(byte[] cropJpeg);

        /// <summary>
        /// İKİNCİ ÖLÇEK (MiniFASNetV1SE, 4,0× kırpma) — <b>YALNIZ ÖLÇÜM, KAPI DEĞİL.</b>
        ///
        /// <para><b>Neden kapı değil:</b> üretici bu iki modeli topluluk olarak tasarlamış ve
        /// tek ölçek çalıştırmak yanlış yapılandırma gibi görünüyordu. Ölçüm tersini söyledi:
        /// 32 fotoğraflık gerçek yüz/ekran karşılaştırmasında 4,0 modeli EKRANLARA daha yüksek
        /// "canlı" puanı veriyor ve ikisinin ortalaması 2,7'nin tek başınadan KÖTÜ ayırıyor
        /// (0,264 ↔ 0,317). Bu yüzden skorlanıyor ama karara girmiyor.</para>
        ///
        /// <para>Model yoksa ya da kırpma boşsa <c>null</c> — çağıran bunu "ölçülemedi" diye
        /// kaydeder, "sahte" diye DEĞİL.</para>
        /// </summary>
        float[]? PredictSecondary(byte[] crop40Jpeg);
    }

    /// <summary>
    /// Silent-Face MiniFASNetV2 passive anti-spoof.
    /// Input: 80×80 JPEG of a 2.7× enlarged face bbox crop (sent from mobile).
    /// Model: [1,3,80,80] BGR float32 (mean=[104,117,123], scale=1/255) → 3-class softmax [fake1, real, fake2].
    /// P(live) = output[1].
    /// </summary>
    public class AntiSpoofService : IAntiSpoofService
    {
        private InferenceSession? _session;
        private string _inputName = "input";
        private bool _isLoaded;

        // İkinci ölçek (4,0×) — ölçüm amaçlı, yüklenemezse akış etkilenmez.
        private InferenceSession? _session40;
        private string _inputName40 = "input";
        private bool _isLoaded40;

        public bool IsModelLoaded => _isLoaded;

        // Minimum live probability to pass. Below this → spoof rejected.
        public const float LiveThreshold = 0.55f;

        public AntiSpoofService()
        {
            var baseDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Models");
            LoadModel(Path.Combine(baseDir, "minifasnet_v2.onnx"));

            // İkinci ölçek ÖLÇÜM içindir: yüklenemezse sessizce atlanır ve canlılık kapısı
            // bugünkü gibi çalışmaya devam eder. Kapıya girmeyen bir modelin yokluğu kaydı
            // düşürmemeli.
            try
            {
                var p40 = Path.Combine(baseDir, "minifasnet_v1se_40.onnx");
                if (File.Exists(p40))
                {
                    _session40 = new InferenceSession(p40, new Microsoft.ML.OnnxRuntime.SessionOptions());
                    _inputName40 = _session40.InputMetadata.Keys.First();
                    _isLoaded40 = true;
                    Console.WriteLine($"[AntiSpoofService] MiniFASNetV1SE 4,0 yüklendi (ÖLÇÜM, girdi: {_inputName40})");
                }
                else
                {
                    Console.WriteLine("[AntiSpoofService] 4,0 modeli yok — ikinci ölçek ölçümü atlanacak.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AntiSpoofService] 4,0 modeli yüklenemedi (ölçüm atlanacak): {ex.Message}");
            }
        }

        private void LoadModel(string modelPath)
        {
            try
            {
                if (!File.Exists(modelPath))
                {
                    Console.WriteLine($"[AntiSpoofService] Model bulunamadı: {modelPath}");
                    return;
                }

                var options = new Microsoft.ML.OnnxRuntime.SessionOptions();
                _session = new InferenceSession(modelPath, options);
                _inputName = _session.InputMetadata.Keys.First();
                _isLoaded = true;
                Console.WriteLine($"[AntiSpoofService] MiniFASNetV2 yüklendi (girdi: {_inputName})");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AntiSpoofService] Model yükleme hatası: {ex.Message}");
            }
        }

        public float[] Predict(byte[] cropJpeg)
        {
            if (!_isLoaded || _session == null)
                throw new InvalidOperationException("Anti-spoof modeli yüklenmedi (minifasnet_v2.onnx).");

            try
            {
                var input = BuildTensor(cropJpeg);
                var inputs = new[] { NamedOnnxValue.CreateFromTensor(_inputName, input) };

                using var results = _session.Run(inputs);
                var outputTensor = results.First().AsTensor<float>();
                var scores = outputTensor.ToArray();

                // 3-class softmax. Live = index 1 (etiketli referansla doğrulandı).
                // Apply softmax in case model emits raw logits.
                var softmax = Softmax(scores);
                Console.WriteLine($"[AntiSpoofService] softmax=[{string.Join(", ", softmax.Select(s => s.ToString("F3")))}]");
                return softmax;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AntiSpoofService] Inference hatası: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc cref="IAntiSpoofService.PredictSecondary"/>
        public float[]? PredictSecondary(byte[] crop40Jpeg)
        {
            if (!_isLoaded40 || _session40 == null || crop40Jpeg.Length == 0) return null;

            try
            {
                // AYNI ön-işleme: ham BGR 0-255. İki model de aynı üreticiden, aynı kuralla
                // eğitilmiş; birine /255 verip ötekine vermemek sessiz bir çöp üretirdi.
                var input = BuildTensor(crop40Jpeg);
                using var results = _session40.Run(
                    new[] { NamedOnnxValue.CreateFromTensor(_inputName40, input) });
                var softmax = Softmax(results.First().AsTensor<float>().ToArray());
                Console.WriteLine($"[AntiSpoofService] 4,0 softmax=[{string.Join(", ", softmax.Select(s => s.ToString("F3")))}] (ölçüm)");
                return softmax;
            }
            catch (Exception ex)
            {
                // Ölçüm yolu ASLA kaydı düşürmez.
                Console.WriteLine($"[AntiSpoofService] 4,0 çıkarım hatası (ölçüm atlandı): {ex.Message}");
                return null;
            }
        }

        private static DenseTensor<float> BuildTensor(byte[] jpeg)
        {
            using var image = Image.Load<Rgb24>(jpeg);
            image.Mutate(x => x.Resize(80, 80));

            var tensor = new DenseTensor<float>(new[] { 1, 3, 80, 80 });

            // Channel layout: [B=0, G=1, R=2] — BGR.
            // Normalization: HAM [0,255] (bölme YOK, mean YOK). Etiketli referans
            //   görüntülerle yerelde doğrulandı (minivision sample F1/F2/T1): yalnız ham-BGR
            //   girdi gerçek/sahte ayrımı veriyor (real idx1≈0.99 / fake idx1≈0.00);
            //   /255 veya mean çıkarma modeli tek sınıfa saturate ediyor.
            image.ProcessPixelRows(accessor =>
            {
                for (int y = 0; y < 80; y++)
                {
                    var row = accessor.GetRowSpan(y);
                    for (int x = 0; x < 80; x++)
                    {
                        var p = row[x];
                        tensor[0, 0, y, x] = p.B;
                        tensor[0, 1, y, x] = p.G;
                        tensor[0, 2, y, x] = p.R;
                    }
                }
            });

            return tensor;
        }

        private static float[] Softmax(float[] logits)
        {
            if (logits.Length == 0) return logits;
            float max = logits.Max();
            var exp = logits.Select(x => (float)Math.Exp(x - max)).ToArray();
            float sum = exp.Sum();
            return exp.Select(x => x / sum).ToArray();
        }
    }
}
