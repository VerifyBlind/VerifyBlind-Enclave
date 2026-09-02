using System.Collections.Generic;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using VerifyBlind.Enclave.Services.FaceAlignment;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>FaceAligner saf-matematik yardımcıları: 2x3 afin tersleme + bilinear warp.</summary>
public class FaceAlignerWarpTests
{
    [Fact]
    public void InvertAffine_MatchesGolden()
    {
        float[] m = { 0.897557f, 0.014061f, -58.177151f, -0.014061f, 0.897557f, -46.540564f };
        float[] golden = { 1.113862f, -0.01745f, 63.989204f, 0.01745f, 1.113862f, 52.854934f };

        float[] inv = FaceAligner.InvertAffine(m);

        for (int i = 0; i < 6; i++)
            Assert.True(System.Math.Abs(golden[i] - inv[i]) < 1e-3f, $"inv[{i}]: {golden[i]} vs {inv[i]}");
    }

    [Fact]
    public void InvertAffine_ComposesToIdentity()
    {
        float[] m = { 0.897557f, 0.014061f, -58.177151f, -0.014061f, 0.897557f, -46.540564f };
        float[] inv = FaceAligner.InvertAffine(m);
        // M(inv(p)) == p for a sample point
        float px = 70f, py = 90f;
        float sx = inv[0] * px + inv[1] * py + inv[2];
        float sy = inv[3] * px + inv[4] * py + inv[5];
        float bx = m[0] * sx + m[1] * sy + m[2];
        float by = m[3] * sx + m[4] * sy + m[5];
        Assert.Equal(px, bx, 2);
        Assert.Equal(py, by, 2);
    }

    [Fact]
    public void WarpAffineBilinear_Identity_ReproducesSource()
    {
        using var src = new Image<Rgb24>(8, 8);
        src.ProcessPixelRows(acc =>
        {
            for (int y = 0; y < 8; y++)
            {
                var row = acc.GetRowSpan(y);
                for (int x = 0; x < 8; x++)
                    row[x] = new Rgb24((byte)(x * 30), (byte)(y * 30), 0);
            }
        });
        float[] identityInv = { 1f, 0f, 0f, 0f, 1f, 0f };

        using Image<Rgb24> warped = FaceAligner.WarpAffineBilinear(src, identityInv, 8, 8);

        warped.ProcessPixelRows(acc =>
        {
            for (int y = 0; y < 8; y++)
            {
                var row = acc.GetRowSpan(y);
                for (int x = 0; x < 8; x++)
                {
                    Assert.Equal((byte)(x * 30), row[x].R);
                    Assert.Equal((byte)(y * 30), row[x].G);
                }
            }
        });
    }

    [Fact]
    public void WarpAffineBilinear_OutOfBounds_PadsZero()
    {
        using var src = new Image<Rgb24>(4, 4);
        src.Mutate(c => c.BackgroundColor(Color.White));
        // inv maps output (0,0) to source (100,100) → dışarıda → siyah (0).
        float[] inv = { 1f, 0f, 100f, 0f, 1f, 100f };

        using Image<Rgb24> warped = FaceAligner.WarpAffineBilinear(src, inv, 4, 4);

        warped.ProcessPixelRows(acc =>
        {
            var row = acc.GetRowSpan(0);
            Assert.Equal(0, row[0].R);
            Assert.Equal(0, row[0].G);
            Assert.Equal(0, row[0].B);
        });
    }
}

/// <summary>
/// YuNet 3-stride decode (cls/obj/bbox/kps → 5-landmark yüz) + NMS birim testleri.
/// Modelden bağımsız: sentetik çıktı dizileriyle decode mantığını pinler. Decode formülü
/// OpenCV FaceDetectorYN ile aynı: score=√(cls·obj), cx=(c+dx)·s, w=exp(dw)·s, kps=(c+dkx)·s.
/// </summary>
public class YunetDecoderTests
{
    // stride=8, inputSize=640 → cols=rows=80. Tek hücreyi (c=10,r=20) aktive et.
    private const int InputSize = 640;

    private static (float[] cls, float[] obj, float[] bbox, float[] kps) MakeStride8WithFace()
    {
        int cols = InputSize / 8;          // 80
        int n = cols * cols;               // 6400
        var cls = new float[n];
        var obj = new float[n];
        var bbox = new float[n * 4];
        var kps = new float[n * 10];

        int c = 10, r = 20;
        int idx = r * cols + c;            // 1610
        cls[idx] = 0.81f;                  // √(0.81·1.0) = 0.9
        obj[idx] = 1.0f;
        bbox[idx * 4 + 0] = 0.5f;          // cx=(10+0.5)*8=84
        bbox[idx * 4 + 1] = 0.5f;          // cy=(20+0.5)*8=164
        bbox[idx * 4 + 2] = 0.0f;          // w=exp(0)*8=8
        bbox[idx * 4 + 3] = 0.0f;          // h=8 → x=80,y=160
        // 5 landmark: point0=(0.25,0.25), point1=(0.75,0.10), kalanlar 0.5
        kps[idx * 10 + 0] = 0.25f; kps[idx * 10 + 1] = 0.25f;   // (82,162)
        kps[idx * 10 + 2] = 0.75f; kps[idx * 10 + 3] = 0.10f;   // (86,160.8)
        for (int k = 2; k < 5; k++) { kps[idx * 10 + 2 * k] = 0.5f; kps[idx * 10 + 2 * k + 1] = 0.5f; }
        return (cls, obj, bbox, kps);
    }

    [Fact]
    public void DecodeStride_SingleActivation_DecodesBoxAndLandmarks()
    {
        var (cls, obj, bbox, kps) = MakeStride8WithFace();

        List<FaceDetection> dets = YunetDecoder.DecodeStride(cls, obj, bbox, kps, 8, InputSize, 0.6f);

        var d = Assert.Single(dets);
        Assert.Equal(0.9f, d.Score, 3);
        Assert.Equal(80f, d.X, 3);
        Assert.Equal(160f, d.Y, 3);
        Assert.Equal(8f, d.W, 3);
        Assert.Equal(8f, d.H, 3);
        Assert.Equal(10, d.Landmarks.Length);
        Assert.Equal(82f, d.Landmarks[0], 3);     // kp0 x
        Assert.Equal(162f, d.Landmarks[1], 3);    // kp0 y
        Assert.Equal(86f, d.Landmarks[2], 3);     // kp1 x
        Assert.Equal(160.8f, d.Landmarks[3], 2);  // kp1 y
    }

    [Fact]
    public void DecodeStride_BelowScoreThreshold_IsFiltered()
    {
        int cols = InputSize / 8;
        int n = cols * cols;
        var cls = new float[n];
        var obj = new float[n];
        int idx = 21 * cols + 11;
        cls[idx] = 0.25f; obj[idx] = 0.25f;       // √(0.0625)=0.25 < 0.6

        List<FaceDetection> dets = YunetDecoder.DecodeStride(cls, obj, new float[n * 4], new float[n * 10], 8, InputSize, 0.6f);

        Assert.Empty(dets);
    }

    [Fact]
    public void Nms_OverlappingBoxes_KeepsHigherScore()
    {
        var high = new FaceDetection { Score = 0.95f, X = 100, Y = 100, W = 50, H = 50, Landmarks = new float[10] };
        var low = new FaceDetection { Score = 0.70f, X = 105, Y = 105, W = 50, H = 50, Landmarks = new float[10] }; // ~%70 IoU
        var far = new FaceDetection { Score = 0.80f, X = 300, Y = 300, W = 50, H = 50, Landmarks = new float[10] };

        List<FaceDetection> kept = YunetDecoder.Nms(new List<FaceDetection> { low, high, far }, 0.3f);

        Assert.Equal(2, kept.Count);
        Assert.Contains(high, kept);   // çakışan çiftten yüksek skorlu kalır
        Assert.Contains(far, kept);    // çakışmayan kalır
        Assert.DoesNotContain(low, kept);
    }

    [Fact]
    public void SelectBestFace_PicksLargestAreaAfterNms()
    {
        var small = new FaceDetection { Score = 0.99f, X = 0, Y = 0, W = 20, H = 20, Landmarks = new float[10] };
        var big = new FaceDetection { Score = 0.85f, X = 200, Y = 200, W = 120, H = 120, Landmarks = new float[10] };

        FaceDetection? best = YunetDecoder.SelectBestFace(new List<FaceDetection> { small, big }, 0.3f);

        Assert.NotNull(best);
        Assert.Equal(big, best);       // en yüksek skor değil, en büyük alan (referansla aynı)
    }

    [Fact]
    public void SelectBestFace_Empty_ReturnsNull()
    {
        Assert.Null(YunetDecoder.SelectBestFace(new List<FaceDetection>(), 0.3f));
    }
}

/// <summary>
/// Yüz-hizalama (YuNet decode + Umeyama similarity) birim testleri.
/// Golden değerler `tools/biometric/yunet_frr_ref.py` ile DOĞRULANMIŞ numpy referansından
/// üretildi (LFW'de EER ~%1.56 / FAR≤%0.1'de FRR ~%1.70 — center-crop %46'dan).
/// Bu testler enclave C# portunun referans algoritmayla AYNI olduğunu pinler.
/// </summary>
public class UmeyamaTests
{
    // ArcFace kanonik 5-nokta şablonu (w600k_r50'nin eğitildiği 112x112 hizalama).
    private static readonly float[] ArcfaceDst =
    {
        38.2946f, 51.6963f, 73.5318f, 51.5014f, 56.0252f, 71.7366f,
        41.5493f, 92.3655f, 70.7299f, 92.2041f
    };

    private static void AssertMatrix(float[] expected, float[] actual, float tol)
    {
        Assert.Equal(6, actual.Length);
        for (int i = 0; i < 6; i++)
            Assert.True(System.Math.Abs(expected[i] - actual[i]) < tol,
                $"M[{i}]: beklenen {expected[i]}, gelen {actual[i]} (tol {tol})");
    }

    [Fact]
    public void SimilarityTransform_RealLandmarks_MatchesGolden()
    {
        // Gerçek bir LFW yüzünden tespit edilen 5 landmark (orijinal koordinat).
        float[] src =
        {
            102.4f, 112.2f, 146.3f, 114.0f, 127.9f, 135.4f, 106.5f, 153.8f, 142.6f, 154.2f
        };
        // numpy Umeyama (SVD) golden — kapalı-form C# ile birebir eşleşmeli.
        float[] golden =
        {
            0.897557f, 0.014061f, -58.177151f, -0.014061f, 0.897557f, -46.540564f
        };

        float[] m = Umeyama.SimilarityTransform(src, ArcfaceDst);

        AssertMatrix(golden, m, 1e-3f);
    }

    [Fact]
    public void SimilarityTransform_SrcEqualsDst_IsIdentity()
    {
        float[] golden = { 1f, 0f, 0f, 0f, 1f, 0f };

        float[] m = Umeyama.SimilarityTransform(ArcfaceDst, ArcfaceDst);

        AssertMatrix(golden, m, 1e-4f);
    }

    [Fact]
    public void SimilarityTransform_ScaledAndShifted_RecoversInverse()
    {
        // src = dst*2 + (10,20)  =>  M src + t = dst  =>  scale 0.5, t = (-5,-10)
        float[] src = new float[10];
        for (int i = 0; i < 5; i++)
        {
            src[2 * i] = ArcfaceDst[2 * i] * 2f + 10f;
            src[2 * i + 1] = ArcfaceDst[2 * i + 1] * 2f + 20f;
        }
        float[] golden = { 0.5f, 0f, -5f, 0f, 0.5f, -10f };

        float[] m = Umeyama.SimilarityTransform(src, ArcfaceDst);

        AssertMatrix(golden, m, 1e-4f);
    }

    [Fact]
    public void SimilarityTransform_MapsSourceOntoDestination()
    {
        // Bağımsız doğrulama: M, src noktalarını dst'ye yakın taşımalı (similarity LS).
        float[] src =
        {
            102.4f, 112.2f, 146.3f, 114.0f, 127.9f, 135.4f, 106.5f, 153.8f, 142.6f, 154.2f
        };
        float[] m = Umeyama.SimilarityTransform(src, ArcfaceDst);

        // Ortalama yeniden-yansıtma hatası küçük olmalı (gerçek yüz ~birkaç px).
        float err = 0f;
        for (int i = 0; i < 5; i++)
        {
            float x = m[0] * src[2 * i] + m[1] * src[2 * i + 1] + m[2];
            float y = m[3] * src[2 * i] + m[4] * src[2 * i + 1] + m[5];
            err += System.MathF.Sqrt((x - ArcfaceDst[2 * i]) * (x - ArcfaceDst[2 * i]) +
                                      (y - ArcfaceDst[2 * i + 1]) * (y - ArcfaceDst[2 * i + 1]));
        }
        err /= 5f;
        Assert.True(err < 3.0f, $"ortalama yeniden-yansıtma hatası {err:0.00}px çok büyük");
    }
}
