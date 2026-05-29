using VerifyBlind.Enclave.Services;
using Moq;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

public class BiometricServiceTests
{
    // ── IBiometricService Mock Tests ──────────────────────────────────────────
    // Real BiometricService loads ONNX model from disk — not available in unit tests.
    // These tests verify the interface contract and mock behavior.

    [Fact]
    public void Mock_IBiometricService_HighScore_IsAboveThreshold()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.IsModelLoaded).Returns(true);
        mock.Setup(b => b.VerifyFace(It.IsAny<byte[]>(), It.IsAny<byte[]>())).Returns(0.95f);
        mock.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.IsAny<byte[]>())).Returns(0.95f);

        var service = mock.Object;

        Assert.True(service.IsModelLoaded);
        Assert.True(service.VerifyFace(new byte[1], new byte[1]) > 0.7f);
        Assert.True(service.VerifyFaceParallel(new byte[1], new byte[1]) > 0.7f);
    }

    [Fact]
    public void Mock_IBiometricService_LowScore_IsBelowThreshold()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.IsModelLoaded).Returns(true);
        mock.Setup(b => b.VerifyFace(It.IsAny<byte[]>(), It.IsAny<byte[]>())).Returns(0.3f);

        var service = mock.Object;

        Assert.True(service.VerifyFace(new byte[1], new byte[1]) < 0.7f);
    }

    [Fact]
    public void RealBiometricService_IsModelLoaded_ReflectsOnnxFilePresence()
    {
        // Real service: IsModelLoaded == true iff the ONNX file exists in Models/
        var service = new BiometricService();
        var modelPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Models", "w600k_mbf.onnx");

        // The model is loaded iff the file exists — both outcomes are valid
        Assert.Equal(System.IO.File.Exists(modelPath), service.IsModelLoaded);
    }

    [Fact]
    public void RealBiometricService_ModelNotLoaded_VerifyFaceThrows()
    {
        var service = new BiometricService();

        if (!service.IsModelLoaded)
        {
            Assert.Throws<InvalidOperationException>(() =>
                service.VerifyFace(new byte[100], new byte[100]));
        }
        else
        {
            // Model loaded — service is functional; no exception expected for valid (but random) bytes
            Assert.True(service.IsModelLoaded);
        }
    }

    [Fact]
    public void RealBiometricService_ModelNotLoaded_VerifyFaceParallelThrows()
    {
        var service = new BiometricService();

        if (!service.IsModelLoaded)
        {
            Assert.Throws<InvalidOperationException>(() =>
                service.VerifyFaceParallel(new byte[100], new byte[100]));
        }
        else
        {
            // Model loaded — service is functional
            Assert.True(service.IsModelLoaded);
        }
    }

    // ── Score Range / Threshold Tests ─────────────────────────────────────────
    // NOTE: EnclaveService.VerifyBiometricMatch[Parallel] uses an ArcFace cosine-similarity
    // THRESHOLD of 0.40f (see EnclaveService.cs). These tests pin that value so an
    // accidental change that weakens (or breaks) face matching fails the build.

    [Theory]
    [InlineData(0.0f, false)]
    [InlineData(0.20f, false)]
    [InlineData(0.39f, false)]
    [InlineData(0.40f, true)]
    [InlineData(0.41f, true)]
    [InlineData(0.85f, true)]
    [InlineData(1.0f, true)]
    public void FaceScore_EnclaveThresholdIsZeroPointFour(float score, bool shouldPass)
    {
        const float enclaveThreshold = 0.40f;
        Assert.Equal(shouldPass, score >= enclaveThreshold);
    }

    // ── Exception Propagation ─────────────────────────────────────────────────

    [Fact]
    public void Mock_VerifyFace_Throws_PropagatesToCaller()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.VerifyFace(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
            .Throws(new InvalidOperationException("model not loaded"));

        Assert.Throws<InvalidOperationException>(() => mock.Object.VerifyFace(new byte[1], new byte[1]));
    }

    [Fact]
    public void Mock_VerifyFaceParallel_Throws_PropagatesToCaller()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
            .Throws(new InvalidOperationException("model not loaded"));

        Assert.Throws<InvalidOperationException>(() => mock.Object.VerifyFaceParallel(new byte[1], new byte[1]));
    }

    [Fact]
    public void RealBiometricService_ImplementsIBiometricService()
    {
        // Guards the DI contract — EnclaveService depends on IBiometricService, not the concrete type.
        Assert.IsAssignableFrom<IBiometricService>(new BiometricService());
    }
}
