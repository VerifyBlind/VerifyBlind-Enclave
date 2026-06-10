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
        /// Returns the 3-class softmax. Model card (garciafido/minifasnet-v2) order: [live, print, replay].
        /// Index 0 = P(live); values below threshold indicate a spoof attempt.
        /// </summary>
        float[] Predict(byte[] cropJpeg);
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

        public bool IsModelLoaded => _isLoaded;

        // Minimum live probability to pass. Below this → spoof rejected.
        public const float LiveThreshold = 0.55f;

        public AntiSpoofService()
        {
            var modelPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Models", "minifasnet_v2.onnx");
            LoadModel(modelPath);
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

                // 3-class softmax. Model card (garciafido/minifasnet-v2) order: [live, print, replay].
                // Caller reads index 0 as P(live). Apply softmax in case model emits raw logits.
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

        private static DenseTensor<float> BuildTensor(byte[] jpeg)
        {
            using var image = Image.Load<Rgb24>(jpeg);
            image.Mutate(x => x.Resize(80, 80));

            var tensor = new DenseTensor<float>(new[] { 1, 3, 80, 80 });

            // Channel layout: [B=0, G=1, R=2] — BGR, per model card.
            // Normalization: pixel / 255 → [0,1] (ToTensor). Mean çıkarma YOK
            //   (model kartı + orijinal minivision ToTensor; eski 104/117/123 mean çıkarması HATALIYDI).
            image.ProcessPixelRows(accessor =>
            {
                for (int y = 0; y < 80; y++)
                {
                    var row = accessor.GetRowSpan(y);
                    for (int x = 0; x < 80; x++)
                    {
                        var p = row[x];
                        tensor[0, 0, y, x] = p.B / 255f;
                        tensor[0, 1, y, x] = p.G / 255f;
                        tensor[0, 2, y, x] = p.R / 255f;
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
