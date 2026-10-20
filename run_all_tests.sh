#!/usr/bin/env bash
set -euo pipefail

cmake -S . -B build -DBUILD_TESTING=ON -DBUILD_BENCHMARKS=OFF
cmake --build build -j
ctest --test-dir build --output-on-failure
