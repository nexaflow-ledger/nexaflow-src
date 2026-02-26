#!/usr/bin/env bash
# Run the full NexaFlow test suite with pytest.
# Usage:  bash run_tests.sh
#         bash run_tests.sh -v          # verbose
#         bash run_tests.sh -k crypto   # filter by keyword

set -euo pipefail
cd "$(dirname "$0")"

echo "=== Building Cython extensions ==="
python setup.py build_ext --inplace 2>&1 | tail -1

echo ""
echo "=== Running test suite ==="
python -m pytest tests/ -x --tb=short "$@"
