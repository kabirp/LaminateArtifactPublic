# Tests

Tests follow the [library module layout](../include/laminate/README.md).
[`test_base.cpp`](test_base.cpp), [`test_folded.cpp`](test_folded.cpp), and
[`test_laned.cpp`](test_laned.cpp) provide complete protocol examples. Module
directories cover arithmetic, storage, and rejection cases.

## Selecting coverage

The [build instructions](../README.md) configure the default
Mock suite. [`CMakeLists.txt`](CMakeLists.txt) defines the library test inventory.

| Configuration | Coverage |
| --- | --- |
| `LAMINATE_WITH_SEAL=OFF` | Deterministic Mock protocol tests, proof components, file-backed execution, resource admission, and CMake dependency checks. |
| `LAMINATE_WITH_SEAL=ON` | Real BGV evaluation and proof tests, SEAL context and transport checks, and accelerated field arithmetic. |
| `LAMINATE_EXTENDED_TESTS=ON` | Additional component and edge-case tests for the selected backend. |
| `BUILD_BENCHMARKS=ON` | Benchmark metadata, report, runner, and capacity checks registered by [`benches/CMakeLists.txt`](../benches/CMakeLists.txt). |

Use separate build directories for Mock and SEAL. A SEAL build selects its
own test inventory; running both builds covers the backend-independent and
real-ciphertext paths. Routine real-backend executables use the CTest labels
`seal` and `smoke`; target noise checks use `seal` and `target-noise`.

List the tests in a configured build or rerun a single executable through
CTest:

```bash
ctest --test-dir build -N
ctest --test-dir build -R '^test_base$' --output-on-failure
```

For the two `no_integrity_target_*_noise_seal` regressions, setting
`LAMINATE_NO_INTEGRITY_TEST_EVIDENCE_ROOT` to an absolute, existing directory
with mode `0700` preserves the context bundles and each encrypted input before
payload arithmetic. Each profile creates a new subdirectory; an existing
profile directory or a write failure rejects the test. Files use mode `0600`
and remain available after either success or failure. The client bundle contains
the secret key, so keep this directory private and outside version control.
Restore the bundles with `SealBackend::deserialize_context_bundles` and the
numbered input files with `SealBackend::deserialize_from_storage`.

## Reading and extending tests

[`support/test_helpers.hpp`](support/test_helpers.hpp) provides `CHECK` and
`test::Runner`. Each case reports its result; the executable returns nonzero if
any case fails. The other support headers construct small payloads, certified
setups, and independent cost or arithmetic references shared across tests.

The protocol and delegation tests cover transcript binding, malformed
messages, and role ownership. The `gkr/` tests compare resident references
with file-backed proving. Storage and checkpoint tests exercise bounded
buffers, aliases, corruption, and irreversible session cleanup. Tests in
`gates/`, `basefold/`, `packing/`, and `spartan/` cover the commitment and
packing proof components.

When Python 3 is available, the Mock configuration also registers two
standalone parameter checks:
[`crypto/check_poseidon_parameters.py`](crypto/check_poseidon_parameters.py) checks
the fixed profile against round-selection inequalities.
[`basefold/check_foldable_query_certificate.py`](basefold/check_foldable_query_certificate.py)
verifies the production query table using exact integer and rational arithmetic.
Their assumptions
and scope are documented in [ciphertext commitments](../include/laminate/crypto/README.md)
and [Wide GateMLE soundness](../docs/WIDE_GATE_SOUNDNESS.md).

Small fixtures and formula-based capacity tests keep routine validation
bounded. Full target throughput and peak-resource measurements belong to
the [benchmark workflow](../docs/BENCHMARKING.md).
