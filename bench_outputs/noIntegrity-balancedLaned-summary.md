<!-- laminate-benchmark-summary-v2 -->
# Laminate noIntegrity benchmark summary — target-balancedLaned

**PASS** — the payload-only server returned an output ciphertext and the client decoded and fully decrypted it. No computation-integrity proof is provided.

## Highlights

| Highlight | Measured result |
| --- | --- |
| Laminate variant | noIntegrity |
| Payload profile | `target-balancedLaned` |
| Scalar gates | 17,179,869,184 (1,048,576 payload gates × 16,384 slots) |
| Initial ciphertext modulus (data primes only) | 398 bits |
| Plaintext modulus | 65,537 |
| Payload-only server wall time | 1.71 h |
| ↳ Payload computation | 1.71 h |
| Proof verification | not applicable (no proof) |
| Client full output decryption | 0.001 s |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | not applicable (no proof) |

## Server FHE operation ledger

| Operation | Calls |
| --- | --- |
| `add` | 471,859 |
| `mul_no_relin` | 524,288 |
| `relinearize` | 524,288 |
| `add_plain` | 52,429 |
| `mul_plain_scalar` | 0 |
| `mul_plain_vector` | 0 |
| `mod_switch` | 524,288 |
| `rotate` | 0 |
| `encrypt` | 0 |

## Protocol artifacts

| Artifact | Size |
| --- | --- |
| Client → server request | 144.01 MiB |
| Server → client response | 256.36 KiB |

## Memory and storage

| Property | Measured value |
| --- | --- |
| Server / client peak RSS | 27.39 GiB / 502.43 MiB |
| File-backed payload peak | 368.03 GiB physical; 22.40 GiB controlled resident |
| Target storage backend | `shared-root-filesystem` |
| Host OS / page-cache reserve | 14.90 GiB / 59.60 GiB |
| Payload transfer-buffer reserve | 384.00 MiB |
| Payload ephemeral foreground wait window | 0 B |
| Sequential payload readers | 2 |
| Prefetch logical window per reader | 256.00 MiB |
| Payload prefetch page-cache budget | 512.00 MiB (inside page-cache reserve) |
| Configured prefetch-request ceiling | 16.00 MiB; the Linux runtime further qualifies requests from the backing device's BDI read-ahead geometry |
| Payload replay work / checkpoints | 0 / 0 |
| Output-only plan | 381.54 GiB adjacent-layer disk peak; 270.33 GiB resident peak |
| Remaining admitted output-only disk headroom | 9.01 TiB |

## Provenance

| Property | Recorded value |
| --- | --- |
| Build | Release; SEAL `intel-hexl-runtime-dispatch`; SHA-256 `openssl` |
| Pinned CPUs | setup 0; server 0; client 1 |
| Target storage backend | `shared-root-filesystem` |
