#!/bin/bash
set -euo pipefail

# Run tracked_passwords tests using unittest (stdlib, no extra deps)
cd "$(dirname "$0")"

PYTHONPATH=src python3 -m unittest tests.test_tracked_passwords -v 2>&1
exit $?
