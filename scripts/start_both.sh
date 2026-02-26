#!/usr/bin/env bash
# ===================================================================
# start_both.sh — Launch both NexaFlow nodes in separate terminals
#
# Opens two Terminal.app windows (macOS) or two background processes.
# ===================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Install deps if needed
pip3 install -q cython ecdsa 2>/dev/null || true

# Build Cython extensions
echo "Building Cython extensions..."
python3 setup.py build_ext --inplace 2>&1 || {
    echo "⚠  Cython build failed — running in pure-Python fallback mode"
}

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Launching two NexaFlow validator nodes"
echo "  Node 1: port 9001  |  Node 2: port 9002"
echo "════════════════════════════════════════════════════════"
echo ""

# Detect macOS and use Terminal.app, otherwise fall back to background
if [[ "$(uname)" == "Darwin" ]]; then
    osascript -e "
        tell application \"Terminal\"
            activate
            do script \"cd '$SCRIPT_DIR' && bash start_node1.sh\"
            delay 1
            do script \"cd '$SCRIPT_DIR' && bash start_node2.sh\"
        end tell
    "
    echo "✓ Opened two Terminal windows."
    echo "  Use the CLI in each window to interact with the nodes."
    echo ""
    echo "  Quick test:"
    echo "    Node 1>  send <node2_address> 100"
    echo "    Node 1>  consensus"
    echo "    Node 2>  balance"
else
    # Linux / other — run in background with log files
    echo "Starting Node 1 in background (log: node1.log)..."
    bash start_node1.sh --no-cli > node1.log 2>&1 &
    PID1=$!

    sleep 1

    echo "Starting Node 2 in background (log: node2.log)..."
    bash start_node2.sh --no-cli > node2.log 2>&1 &
    PID2=$!

    echo ""
    echo "✓ Nodes running:  PID1=$PID1  PID2=$PID2"
    echo "  Logs: node1.log, node2.log"
    echo "  Stop: kill $PID1 $PID2"
fi
