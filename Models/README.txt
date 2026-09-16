ONNX models in this directory are tracked via Git LFS (see .gitattributes: Models/*.onnx).
They MUST be in the repo: the GitHub Actions workflow (deploy-enclave.yml) checks out with
lfs:true and bakes them into the enclave Docker image / EIF. The Nitro Enclave is isolated
and cannot fetch models at runtime. Dockerfile.enclave pins each model's SHA256 — if you
replace a model file, update the hash there too (PCR0 will change, as expected).

Face recognition: w600k_r50.onnx
  ArcFace R50 (buffalo_l). Replaced w600k_mbf.onnx (MobileFaceNet) — stronger model;
  biometrics run ONLY at register. Threshold is calibrated separately (mbf logs do NOT
  transfer to r50, different score scale). Used by BiometricService.cs.

Anti-spoof (passive liveness): minifasnet_v2.onnx + minifasnet_v1se_40.onnx
  Silent-Face MiniFASNet, 80x80 BGR input, 3-class softmax [fake1, live, fake2].
    minifasnet_v2.onnx       MiniFASNetV2,   crop scale 2.7  -- GATES the decision
    minifasnet_v1se_40.onnx  MiniFASNetV1SE, crop scale 4.0  -- MEASURED ONLY, see below

  Provenance: converted BY US from the vendor's official Apache-2.0 weights
  (github.com/minivision-ai/Silent-Face-Anti-Spoofing, resources/anti_spoof_models/,
  2.7_80x80_MiniFASNetV2.pth and 4_0_0_80x80_MiniFASNetV1SE.pth) with the legacy
  TorchScript exporter, opset 13, no softmax in the graph.

  WHY we converted them ourselves rather than downloading an ONNX: the enclave processes
  biometric data, so an unvetted third-party binary is a supply-chain risk. The previous
  file came from huggingface.co/garciafido/minifasnet-v2-anti-spoofing-onnx. Our export was
  verified against it on 32 real photographs: max difference 0.000001, i.e. behaviourally
  identical. Replacing it changed nothing except who vouches for the bytes.

  INPUT IS RAW BGR 0-255 -- do NOT divide by 255 and do NOT subtract a mean. The vendor's
  own reference code applies torchvision ToTensor() (which divides by 255), but that does
  NOT match these released weights: measured on 32 photographs, /255 collapses every input
  to one class (p_live 0.006 for real faces and screens alike) while raw 0-255 separates
  them. This was verified independently for both models. Trust the measurement, not the
  vendor's demo.

  WHY 4.0 DOES NOT GATE: the vendor designs these as a two-scale ensemble, and running only
  2.7 looked like a misconfiguration worth fixing. Measurement said otherwise -- on real
  face vs screen photographs the 4.0 model rates SCREENS HIGHER (more "live") than 2.7 does,
  and averaging the two separates worse than 2.7 alone (gap 0.264 vs 0.317). So it is loaded
  and scored for the record only; the gate stays on 2.7. Revisit if real-pipeline data
  (front camera, 1080p) disagrees with the photographs.
