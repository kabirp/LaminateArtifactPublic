<!-- laminate-benchmark-summary-v2 -->
# Laminate noIntegrity benchmark summary — target-mulHeavyPyramid

**PASS** — the payload-only server returned an output ciphertext and the client decoded and fully decrypted it. No computation-integrity proof is provided.

## Highlights

| Highlight | Measured result |
| --- | --- |
| Laminate variant | noIntegrity |
| Payload profile | `target-mulHeavyPyramid` |
| Scalar gates | 17,179,869,184 (1,048,576 payload gates × 16,384 slots) |
| Initial ciphertext modulus (data primes only) | 398 bits |
| Plaintext modulus | 65,537 |
| Payload-only server wall time | 5.49 h |
| ↳ Payload computation | 5.48 h |
| Proof verification | not applicable (no proof) |
| Client full output decryption | 0.001 s |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | not applicable (no proof) |

## Server FHE operation ledger

| Operation | Calls |
| --- | --- |
| `add` | 131,024 |
| `mul_no_relin` | 891,290 |
| `relinearize` | 891,290 |
| `add_plain` | 0 |
| `mul_plain_scalar` | 0 |
| `mul_plain_vector` | 26,214 |
| `mod_switch` | 892,126 |
| `rotate` | 39,336 |
| `encrypt` | 0 |

## Protocol artifacts

| Artifact | Size |
| --- | --- |
| Client → server request | 144.01 MiB |
| Server → client response | 256.36 KiB |

## Memory and storage

| Property | Measured value |
| --- | --- |
| Server / client peak RSS | 50.35 GiB / 502.80 MiB |
| File-backed payload peak | 1.71 TiB physical; 55.56 GiB controlled resident |
| Target storage backend | `shared-root-filesystem` |
| Host OS / page-cache reserve | 14.90 GiB / 59.60 GiB |
| Payload transfer-buffer reserve | 384.00 MiB |
| Payload ephemeral foreground wait window | 0 B |
| Sequential payload readers | 2 |
| Prefetch logical window per reader | 256.00 MiB |
| Payload prefetch page-cache budget | 512.00 MiB (inside page-cache reserve) |
| Configured prefetch-request ceiling | 16.00 MiB; the Linux runtime further qualifies requests from the backing device's BDI read-ahead geometry |
| Payload replay work / checkpoints | 0 / 0 |
| Output-only plan | 1.76 TiB adjacent-layer disk peak; 56.14 GiB resident peak |
| Remaining admitted output-only disk headroom | 7.61 TiB |

## Provenance

| Property | Recorded value |
| --- | --- |
| Build | Release; SEAL `intel-hexl-runtime-dispatch`; SHA-256 `openssl` |
| Pinned CPUs | setup 0; server 0; client 1 |
| Target storage backend | `shared-root-filesystem` |
