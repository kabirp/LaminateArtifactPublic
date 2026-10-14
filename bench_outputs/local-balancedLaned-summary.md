<!-- laminate-benchmark-summary-v2 -->
# Local payload benchmark summary — target-balancedLaned

**PASS** — the client completed the scalar payload computation on one logical CPU.

## Highlights

| Highlight | Measured result |
| --- | --- |
| Laminate variant | local |
| Payload profile | `target-balancedLaned` |
| Scalar gates | 17,179,869,184 |
| Plaintext modulus | 65,537 |
| Client-local payload evaluation | 1.03 min |
| Initial ciphertext modulus | not applicable |
| VCoED server wall time | not applicable |
| Proof verification | not applicable |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | not applicable |

## Scalar operation ledger

| Gate kind | DAG gates | Scalar F_t operations |
|---|---:|---:|
| Add | 471,859 | 7,730,937,856 |
| AddPlain | 52,429 | 858,996,736 |
| Mul | 524,288 | 8,589,934,592 |
| MulPlain | 0 | 0 |
| Rotate | 0 | 0 |
| **Total** | 1,048,576 | 17,179,869,184 |

## Memory and storage

| Property | Measured or admitted value |
|---|---:|
| One-coordinate scalar wire buffer | 8.00 MiB |
| Cross-slot prefix workspace | 0 B |
| Deterministic plaintext inputs | 8.00 MiB |
| Retained plaintext outputs | 128.00 KiB |
| Resident circuit representation | 33.00 MiB |
| Setup-admitted client peak | 305.13 MiB |
| Measured client peak RSS | 104.02 MiB |
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
