ONNX models in this directory are tracked via Git LFS (see .gitattributes: Models/*.onnx).
They MUST be in the repo: the GitHub Actions workflow (deploy-enclave.yml) checks out with
lfs:true and bakes them into the enclave Docker image / EIF. The Nitro Enclave is isolated
and cannot fetch models at runtime. Dockerfile.enclave pins each model's SHA256 — if you
replace a model file, update the hash there too (PCR0 will change, as expected).

Face recognition: w600k_r50.onnx
  ArcFace R50 (buffalo_l). Replaced w600k_mbf.onnx (MobileFaceNet) — stronger model;
  biometrics run ONLY at register. Threshold is calibrated separately (mbf logs do NOT
  transfer to r50, different score scale). Used by BiometricService.cs.

Anti-spoof (passive liveness): minifasnet_v2.onnx
  Silent-Face MiniFASNetV2 (scale 2.7, 80x80 BGR input, 3-class softmax [fake1, live, fake2]).
  Source: huggingface.co/garciafido/minifasnet-v2-anti-spoofing-onnx
  Used by AntiSpoofService.cs (passive-liveness check).
