#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ERIGON_DIR="$(dirname "$SCRIPT_DIR")/erigon"

echo "── Building custom Erigon Docker image with NTT precompiles..."
docker build -t erigon-ntt:latest "$ERIGON_DIR"

echo "── Launching Kurtosis devnet..."
kurtosis run --enclave falcon-devnet github.com/ethpandaops/ethereum-package \
    --args-file "$SCRIPT_DIR/network_params.yaml"

echo "── Devnet is running. Get the RPC endpoint with:"
echo "   kurtosis port print falcon-devnet el-1-erigon-lighthouse rpc"
