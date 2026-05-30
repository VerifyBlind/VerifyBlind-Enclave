#!/bin/sh
set -xe

echo "=== Enclave Booting (UNIX SOCKET MODE) ==="

# 1. Setup loopback + vsock bridges (required for KMS API and IAM credentials)
ip link set lo up || true

# KMS API: 127.0.0.1:8000 → parent vsock port 8000 → kms.eu-central-1.amazonaws.com:443
socat TCP-LISTEN:8000,reuseaddr,fork VSOCK-CONNECT:3:8000 &

# IMDS (IAM credentials): 127.0.0.1:8001 → parent vsock port 8001 → 169.254.169.254:80
socat TCP-LISTEN:8001,reuseaddr,fork VSOCK-CONNECT:3:8001 &

echo "vsock bridges started (KMS:8000, IMDS:8001)"

# 2. Create /tmp and ensure permissions
mkdir -p /tmp
chmod 1777 /tmp
rm -f /tmp/enclave.sock

# 3. Start .NET Application (it creates the socket)
if [ -f "/app/VerifyBlind.Enclave" ]; then
    chmod +x /app/VerifyBlind.Enclave
    # Run in background
    /app/VerifyBlind.Enclave &
else
    echo "ERROR: VerifyBlind.Enclave not found!"
    exit 1
fi

# 4. Wait for the socket file to appear
echo "Waiting for /tmp/enclave.sock..."
MAX_RETRIES=20
COUNT=0
while [ ! -S /tmp/enclave.sock ] && [ $COUNT -lt $MAX_RETRIES ]; do
    sleep 1
    COUNT=$((COUNT+1))
done

if [ -S /tmp/enclave.sock ]; then
    echo "SUCCESS: Socket created. Starting socat bridge..."
    # 5. Bridge: VSOCK -> Unix Socket
    exec socat VSOCK-LISTEN:5101,reuseaddr,fork UNIX-CONNECT:/tmp/enclave.sock
else
    echo "ERROR: /tmp/enclave.sock was never created!"
    ls -la /tmp
    exit 1
fi
