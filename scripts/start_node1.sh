#!/usr/bin/env bash
# ===================================================================
# start_node1.sh — Launch NexaFlow Validator Node 1
#
# Listens on port 9001, connects to Node 2 on port 9002.
# ===================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Build Cython extensions if not already built
if [ ! -f nexaflow_core/*.so ] 2>/dev/null && [ ! -f nexaflow_core/*.pyd ] 2>/dev/null; then
    echo "Building Cython extensions..."
    python3 setup.py build_ext --inplace 2>&1 || {
        echo "⚠  Cython build failed — running in pure-Python fallback mode"
    }
fi

echo "════════════════════════════════════════════════════════"
echo "  Starting NexaFlow Node 1  (validator-1)"
echo "  Listening on port 9001"
echo "  Connecting to peer at 127.0.0.1:9002"
echo "════════════════════════════════════════════════════════"

exec python3 run_node.py \
    --node-id "validator-1" \
    --port 9001 \
    --peers "127.0.0.1:9002" \
    --fund-amount 50000
