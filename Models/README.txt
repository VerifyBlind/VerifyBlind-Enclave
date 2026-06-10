Please download "w600k_mbf.onnx" (MobileFaceNet or ArcFace R100) and place it here.
Filename MUST be: w600k_mbf.onnx
This model is used by BiometricService.cs for real face recognition.

Anti-spoof (passive liveness): minifasnet_v2.onnx
  Silent-Face MiniFASNetV2 (scale 2.7, 80x80 BGR input, 3-class softmax [live, print, replay]).
  Source: huggingface.co/garciafido/minifasnet-v2-anti-spoofing-onnx
  Used by the passive-liveness check (Stage c).

NOTE: *.onnx is gitignored — these files are NOT committed. For production they must ALSO exist
in the server static dir (~/static/) and be symlinked by the deploy script (like w600k_mbf.onnx).
