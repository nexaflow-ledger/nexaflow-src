#!/usr/bin/env bash
# ===================================================================
# start_node2.sh — Launch NexaFlow Validator Node 2
#
# Listens on port 9002, connects to Node 1 on port 9001.
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
echo "  Starting NexaFlow Node 2  (validator-2)"
echo "  Listening on port 9002"
echo "  Connecting to peer at 127.0.0.1:9001"
echo "════════════════════════════════════════════════════════"

exec python3 run_node.py \
    --node-id "validator-2" \
    --port 9002 \
    --peers "127.0.0.1:9001" \
    --fund-amount 50000
