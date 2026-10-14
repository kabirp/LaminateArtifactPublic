<!-- laminate-benchmark-summary-v2 -->
# Local payload benchmark summary — target-mulHeavyPyramid

**PASS** — the client completed the scalar payload computation on one logical CPU.

## Highlights

| Highlight | Measured result |
| --- | --- |
| Laminate variant | local |
| Payload profile | `target-mulHeavyPyramid` |
| Scalar gates | 17,179,869,184 |
| Plaintext modulus | 65,537 |
| Client-local payload evaluation | 2.20 min |
| Initial ciphertext modulus | not applicable |
| VCoED server wall time | not applicable |
| Proof verification | not applicable |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | not applicable |

## Scalar operation ledger

| Gate kind | DAG gates | Scalar F_t operations |
|---|---:|---:|
| Add | 104,858 | 1,717,993,472 |
| AddPlain | 0 | 0 |
| Mul | 891,290 | 14,602,895,360 |
| MulPlain | 26,214 | 429,490,176 |
| Rotate | 26,214 | 0 |
| **Total** | 1,048,576 | 16,750,379,008 |

| Permutation handling | Count |
|---|---:|
| Semantic scalar permutation wiring | 429,490,176 |
| Materialized scalar rotation copies | 0 |

## Memory and storage

| Property | Measured or admitted value |
|---|---:|
| One-coordinate scalar wire buffer | 8.00 MiB |
| Indexed views and arithmetic prefix workspace | 3.42 GiB |
| Deterministic plaintext inputs | 8.00 MiB |
| Retained plaintext outputs | 128.00 KiB |
| Resident circuit representation | 33.00 MiB |
| Setup-admitted client peak | 3.72 GiB |
| Measured client peak RSS | 3.47 GiB |
| Host physical RAM | 365.88 GiB |
| Threads | one process pinned to one logical CPU |
| Compiler vectorization / external accelerator | enabled / none |
| Compiler CPU target | native |

The output checksum identifies the completed deterministic output but is not an independent correctness oracle. This benchmark measures ordinary local scalar field execution and makes no delegation or integrity claim.

## Provenance

| Property | Recorded value |
| --- | --- |
| Build | Release; `GNU 15.2.0` |
| Pinned CPUs | setup 0; client 1 |
