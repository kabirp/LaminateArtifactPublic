<!-- laminate-benchmark-summary-v2 -->
# Laminate Laned benchmark summary — target-balancedLaned

**PASS** — setup, server, and client completed, and the client accepted the proof.

## Highlights

| Highlight | Measured result |
| --- | --- |
| Laminate variant | Laned |
| Payload profile | `target-balancedLaned` |
| Fiat–Shamir composition | One transcript: GKR, then Spartan packing argument |
| GKR layer transitions | One claim by selector interpolation |
| Lanes | 128 |
| Scalar gates | 134,217,728 (1,048,576 payload gates × 128 lanes) |
| Initial ciphertext modulus (data primes only) | 617 bits across 15 limbs |
| Plaintext modulus | 65,537 |
| VCoED server wall time | 30 h 22 m 24.938 s |
| ↳ Payload computation | 5 h 16 m 49.457 s |
| ↳ Witness packing | 0.000 s |
| ↳ GKR proving | 15 h 5 m 35.720 s |
| ↳ Transcript packing | 9 h 59 m 55.930 s |
| Per-request client computation | 2.246 s |
| Input encryption | 0.737 s |
| Output decryption | 0.001 s |
| VCoED proof verification | 1.508 s |
| ↳ GKR proof verification | 0.827 s |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.233 s |
| ↳↳ Plaintext GKR and affine gate-opening checks | 0.594 s |
| ↳ Terminal input MLE | 0.005 s |
| ↳ Spartan packing argument | 0.660 s |
| ↳ Well-formedness noise checks | 0.017 s |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | `LaminateImpl/ConservativePackedProofIngress/v3`; limbs by layer `1,4,7,4,7,4,7,4,7,4,7,4,7,4,7,4,7,4` |

## Server layer reductions and sumcheck round details

| Role | Span | Wall | CPU |
| --- | --- | --- | --- |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_0` | 3 m 2.409 s | 3 m 2.394 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_1` | 2 m 58.445 s | 2 m 58.434 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_2` | 3 m 1.403 s | 3 m 1.392 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_3` | 3 m 3.573 s | 3 m 3.562 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_4` | 3 m 0.209 s | 3 m 0.198 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_5` | 3 m 3.498 s | 3 m 3.487 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_6` | 2 m 57.128 s | 2 m 57.117 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_7` | 3 m 3.080 s | 3 m 3.069 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_8` | 2 m 56.479 s | 2 m 56.468 s |
| server | `laned.affine.slot_checkpoint.reduction_0.source_1.checkpoint_1.slot_index` | 1 m 59.937 s | 1 m 59.930 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_9` | 0.947 s | 0.947 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_10` | 1.031 s | 1.031 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_11` | 1.078 s | 1.078 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_12` | 1.114 s | 1.114 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_13` | 1.147 s | 1.147 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_14` | 1.170 s | 1.170 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_15` | 1.199 s | 1.199 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_16` | 1.222 s | 1.222 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_17` | 1.253 s | 1.253 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_18` | 1.281 s | 1.281 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_19` | 1.311 s | 1.311 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_20` | 1.336 s | 1.336 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_21` | 1.368 s | 1.367 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_22` | 1.394 s | 1.394 s |
| server | `laned.reduction.reduction_0.source_1` | 31 m 32.446 s | 31 m 27.389 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_0` | 4.414 s | 4.414 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_1` | 25.513 s | 25.511 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_2` | 15.429 s | 15.428 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_3` | 10.301 s | 10.301 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_4` | 7.717 s | 7.716 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_5` | 6.502 s | 6.501 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_6` | 5.873 s | 5.873 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_7` | 5.488 s | 5.487 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_8` | 5.297 s | 5.296 s |
| server | `laned.multiplication.slot_checkpoint.reduction_1.source_2.checkpoint_2.slot_index` | 2.468 s | 2.468 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_9` | 1.967 s | 1.967 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_10` | 2.174 s | 2.174 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_11` | 2.324 s | 2.324 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_12` | 2.401 s | 2.400 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_13` | 2.498 s | 2.498 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_14` | 2.583 s | 2.583 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_15` | 2.672 s | 2.672 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_16` | 2.757 s | 2.757 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_17` | 2.860 s | 2.860 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_18` | 2.958 s | 2.958 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_19` | 3.061 s | 3.061 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_20` | 3.151 s | 3.151 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_21` | 3.260 s | 3.260 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_22` | 3.197 s | 3.197 s |
| server | `laned.reduction.reduction_1.source_2` | 54 m 37.103 s | 52 m 54.397 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_0` | 2 m 59.115 s | 2 m 59.092 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_1` | 3 m 5.311 s | 3 m 5.299 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_2` | 2 m 56.812 s | 2 m 56.801 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_3` | 3 m 0.996 s | 3 m 0.984 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_4` | 3 m 0.402 s | 3 m 0.390 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_5` | 2 m 57.646 s | 2 m 57.635 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_6` | 3 m 0.459 s | 3 m 0.447 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_7` | 2 m 58.663 s | 2 m 58.651 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_8` | 3 m 0.995 s | 3 m 0.983 s |
| server | `laned.affine.slot_checkpoint.reduction_2.source_3.checkpoint_3.slot_index` | 2 m 1.135 s | 2 m 1.127 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_9` | 0.986 s | 0.986 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_10` | 1.050 s | 1.050 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_11` | 1.086 s | 1.086 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_12` | 1.117 s | 1.117 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_13` | 1.149 s | 1.149 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_14` | 1.172 s | 1.172 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_15` | 1.198 s | 1.198 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_16` | 1.222 s | 1.222 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_17` | 1.254 s | 1.254 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_18` | 1.282 s | 1.282 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_19` | 1.311 s | 1.311 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_20` | 1.338 s | 1.338 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_21` | 1.370 s | 1.370 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_22` | 1.396 s | 1.396 s |
| server | `laned.reduction.reduction_2.source_3` | 37 m 1.799 s | 36 m 53.181 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_0` | 4.394 s | 4.394 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_1` | 25.470 s | 25.468 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_2` | 15.440 s | 15.439 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_3` | 10.332 s | 10.331 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_4` | 7.758 s | 7.758 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_5` | 6.509 s | 6.508 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_6` | 5.900 s | 5.900 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_7` | 5.546 s | 5.546 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_8` | 5.290 s | 5.289 s |
| server | `laned.multiplication.slot_checkpoint.reduction_3.source_4.checkpoint_4.slot_index` | 2.446 s | 2.446 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_9` | 1.954 s | 1.954 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_10` | 2.152 s | 2.152 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_11` | 2.282 s | 2.281 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_12` | 2.385 s | 2.385 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_13` | 2.489 s | 2.489 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_14` | 2.586 s | 2.586 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_15` | 2.683 s | 2.683 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_16` | 2.774 s | 2.773 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_17` | 2.877 s | 2.877 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_18` | 2.973 s | 2.973 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_19` | 3.071 s | 3.070 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_20` | 3.160 s | 3.160 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_21` | 3.266 s | 3.266 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_22` | 3.196 s | 3.196 s |
| server | `laned.reduction.reduction_3.source_4` | 1 h 0 m 37.727 s | 57 m 36.289 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_0` | 3 m 0.637 s | 3 m 0.613 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_1` | 2 m 59.174 s | 2 m 59.161 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_2` | 2 m 57.475 s | 2 m 57.461 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_3` | 3 m 1.378 s | 3 m 1.364 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_4` | 2 m 58.734 s | 2 m 58.721 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_5` | 3 m 2.379 s | 3 m 2.366 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_6` | 3 m 4.754 s | 3 m 4.741 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_7` | 2 m 59.551 s | 2 m 59.539 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_8` | 2 m 58.612 s | 2 m 58.600 s |
| server | `laned.affine.slot_checkpoint.reduction_4.source_5.checkpoint_5.slot_index` | 2 m 2.494 s | 2 m 2.485 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_9` | 0.989 s | 0.989 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_10` | 1.055 s | 1.055 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_11` | 1.089 s | 1.089 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_12` | 1.117 s | 1.117 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_13` | 1.150 s | 1.150 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_14` | 1.175 s | 1.175 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_15` | 1.203 s | 1.203 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_16` | 1.227 s | 1.227 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_17` | 1.256 s | 1.256 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_18` | 1.283 s | 1.283 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_19` | 1.315 s | 1.314 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_20` | 1.342 s | 1.341 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_21` | 1.371 s | 1.371 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_22` | 1.396 s | 1.396 s |
| server | `laned.reduction.reduction_4.source_5` | 39 m 15.533 s | 39 m 6.997 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_0` | 4.391 s | 4.391 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_1` | 25.391 s | 25.389 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_2` | 15.452 s | 15.451 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_3` | 10.332 s | 10.331 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_4` | 7.806 s | 7.805 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_5` | 6.452 s | 6.451 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_6` | 5.821 s | 5.820 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_7` | 5.534 s | 5.534 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_8` | 5.261 s | 5.261 s |
| server | `laned.multiplication.slot_checkpoint.reduction_5.source_6.checkpoint_6.slot_index` | 2.451 s | 2.451 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_9` | 1.941 s | 1.941 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_10` | 2.140 s | 2.140 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_11` | 2.273 s | 2.272 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_12` | 2.370 s | 2.370 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_13` | 2.476 s | 2.476 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_14` | 2.570 s | 2.570 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_15` | 2.668 s | 2.668 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_16` | 2.756 s | 2.756 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_17` | 2.859 s | 2.859 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_18` | 2.958 s | 2.958 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_19` | 3.059 s | 3.059 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_20` | 3.152 s | 3.151 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_21` | 3.256 s | 3.255 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_22` | 3.195 s | 3.195 s |
| server | `laned.reduction.reduction_5.source_6` | 1 h 4 m 3.669 s | 1 h 1 m 58.082 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_0` | 2 m 59.817 s | 2 m 59.796 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_1` | 3 m 8.496 s | 3 m 8.484 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_2` | 2 m 57.366 s | 2 m 57.354 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_3` | 2 m 58.890 s | 2 m 58.879 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_4` | 2 m 58.724 s | 2 m 58.713 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_5` | 2 m 59.635 s | 2 m 59.623 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_6` | 2 m 58.153 s | 2 m 58.141 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_7` | 2 m 58.955 s | 2 m 58.943 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_8` | 3 m 9.412 s | 3 m 9.401 s |
| server | `laned.affine.slot_checkpoint.reduction_6.source_7.checkpoint_7.slot_index` | 2 m 1.042 s | 2 m 1.034 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_9` | 0.989 s | 0.989 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_10` | 1.055 s | 1.055 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_11` | 1.089 s | 1.089 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_12` | 1.119 s | 1.119 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_13` | 1.151 s | 1.151 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_14` | 1.176 s | 1.175 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_15` | 1.204 s | 1.204 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_16` | 1.227 s | 1.227 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_17` | 1.256 s | 1.256 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_18` | 1.284 s | 1.284 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_19` | 1.317 s | 1.317 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_20` | 1.339 s | 1.339 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_21` | 1.371 s | 1.371 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_22` | 1.398 s | 1.398 s |
| server | `laned.reduction.reduction_6.source_7` | 41 m 42.637 s | 41 m 34.811 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_0` | 4.406 s | 4.404 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_1` | 25.636 s | 25.631 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_2` | 15.453 s | 15.452 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_3` | 10.376 s | 10.376 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_4` | 7.795 s | 7.794 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_5` | 6.598 s | 6.598 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_6` | 5.898 s | 5.898 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_7` | 5.484 s | 5.484 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_8` | 5.313 s | 5.313 s |
| server | `laned.multiplication.slot_checkpoint.reduction_7.source_8.checkpoint_8.slot_index` | 2.472 s | 2.472 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_9` | 1.959 s | 1.959 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_10` | 2.157 s | 2.157 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_11` | 2.284 s | 2.284 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_12` | 2.386 s | 2.386 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_13` | 2.494 s | 2.493 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_14` | 2.586 s | 2.586 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_15` | 2.690 s | 2.690 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_16` | 2.778 s | 2.778 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_17` | 2.879 s | 2.879 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_18` | 2.978 s | 2.978 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_19` | 3.075 s | 3.074 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_20` | 3.153 s | 3.153 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_21` | 3.260 s | 3.260 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_22` | 3.191 s | 3.190 s |
| server | `laned.reduction.reduction_7.source_8` | 1 h 8 m 58.605 s | 1 h 6 m 55.363 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_0` | 3 m 0.796 s | 3 m 0.776 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_1` | 3 m 0.234 s | 3 m 0.222 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_2` | 2 m 57.980 s | 2 m 57.968 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_3` | 2 m 59.408 s | 2 m 59.397 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_4` | 3 m 0.458 s | 3 m 0.446 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_5` | 2 m 57.746 s | 2 m 57.734 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_6` | 3 m 0.545 s | 3 m 0.533 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_7` | 2 m 56.883 s | 2 m 56.872 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_8` | 2 m 57.008 s | 2 m 56.996 s |
| server | `laned.affine.slot_checkpoint.reduction_8.source_9.checkpoint_9.slot_index` | 1 m 59.914 s | 1 m 59.906 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_9` | 0.986 s | 0.986 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_10` | 1.054 s | 1.054 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_11` | 1.092 s | 1.092 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_12` | 1.119 s | 1.119 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_13` | 1.153 s | 1.153 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_14` | 1.178 s | 1.178 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_15` | 1.204 s | 1.204 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_16` | 1.229 s | 1.228 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_17` | 1.259 s | 1.258 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_18` | 1.286 s | 1.286 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_19` | 1.318 s | 1.318 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_20` | 1.342 s | 1.342 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_21` | 1.373 s | 1.373 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_22` | 1.396 s | 1.396 s |
| server | `laned.reduction.reduction_8.source_9` | 43 m 56.363 s | 43 m 50.714 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_0` | 4.425 s | 4.424 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_1` | 25.319 s | 25.314 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_2` | 15.527 s | 15.526 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_3` | 10.358 s | 10.357 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_4` | 7.759 s | 7.759 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_5` | 6.529 s | 6.529 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_6` | 5.879 s | 5.878 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_7` | 5.525 s | 5.524 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_8` | 5.296 s | 5.296 s |
| server | `laned.multiplication.slot_checkpoint.reduction_9.source_10.checkpoint_10.slot_index` | 2.451 s | 2.450 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_9` | 1.957 s | 1.957 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_10` | 2.152 s | 2.152 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_11` | 2.275 s | 2.275 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_12` | 2.377 s | 2.377 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_13` | 2.488 s | 2.487 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_14` | 2.584 s | 2.584 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_15` | 2.678 s | 2.678 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_16` | 2.769 s | 2.769 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_17` | 2.869 s | 2.869 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_18` | 2.966 s | 2.966 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_19` | 3.065 s | 3.064 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_20` | 3.159 s | 3.158 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_21` | 3.262 s | 3.262 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_22` | 3.195 s | 3.195 s |
| server | `laned.reduction.reduction_9.source_10` | 1 h 14 m 14.936 s | 1 h 12 m 5.578 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_0` | 3 m 2.823 s | 3 m 2.803 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_1` | 2 m 58.274 s | 2 m 58.263 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_2` | 2 m 59.029 s | 2 m 59.018 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_3` | 2 m 59.184 s | 2 m 59.173 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_4` | 3 m 1.827 s | 3 m 1.816 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_5` | 3 m 0.866 s | 3 m 0.855 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_6` | 2 m 57.753 s | 2 m 57.742 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_7` | 2 m 58.843 s | 2 m 58.831 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_8` | 2 m 59.906 s | 2 m 59.895 s |
| server | `laned.affine.slot_checkpoint.reduction_10.source_11.checkpoint_11.slot_index` | 2 m 0.797 s | 2 m 0.789 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_9` | 0.986 s | 0.986 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_10` | 1.050 s | 1.050 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_11` | 1.085 s | 1.085 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_12` | 1.114 s | 1.114 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_13` | 1.146 s | 1.146 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_14` | 1.171 s | 1.171 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_15` | 1.198 s | 1.198 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_16` | 1.224 s | 1.224 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_17` | 1.252 s | 1.252 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_18` | 1.281 s | 1.281 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_19` | 1.311 s | 1.311 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_20` | 1.336 s | 1.336 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_21` | 1.368 s | 1.368 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_22` | 1.396 s | 1.396 s |
| server | `laned.reduction.reduction_10.source_11` | 46 m 53.490 s | 46 m 47.590 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_0` | 4.423 s | 4.422 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_1` | 25.563 s | 25.557 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_2` | 15.454 s | 15.454 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_3` | 10.348 s | 10.347 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_4` | 7.836 s | 7.835 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_5` | 6.508 s | 6.508 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_6` | 5.885 s | 5.884 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_7` | 5.551 s | 5.550 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_8` | 5.346 s | 5.346 s |
| server | `laned.multiplication.slot_checkpoint.reduction_11.source_12.checkpoint_12.slot_index` | 2.474 s | 2.473 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_9` | 1.955 s | 1.955 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_10` | 2.152 s | 2.152 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_11` | 2.280 s | 2.279 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_12` | 2.381 s | 2.380 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_13` | 2.497 s | 2.497 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_14` | 2.584 s | 2.584 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_15` | 2.682 s | 2.682 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_16` | 2.773 s | 2.772 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_17` | 2.879 s | 2.879 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_18` | 2.994 s | 2.994 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_19` | 3.085 s | 3.085 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_20` | 3.184 s | 3.183 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_21` | 3.294 s | 3.294 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_22` | 3.219 s | 3.219 s |
| server | `laned.reduction.reduction_11.source_12` | 1 h 20 m 51.555 s | 1 h 17 m 55.763 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_0` | 2 m 58.168 s | 2 m 58.149 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_1` | 2 m 56.379 s | 2 m 56.367 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_2` | 3 m 2.630 s | 3 m 2.618 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_3` | 2 m 59.409 s | 2 m 59.397 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_4` | 3 m 1.670 s | 3 m 1.659 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_5` | 3 m 2.585 s | 3 m 2.573 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_6` | 2 m 58.180 s | 2 m 58.168 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_7` | 2 m 56.756 s | 2 m 56.745 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_8` | 3 m 3.402 s | 3 m 3.390 s |
| server | `laned.affine.slot_checkpoint.reduction_12.source_13.checkpoint_13.slot_index` | 1 m 59.457 s | 1 m 59.449 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_9` | 0.990 s | 0.990 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_10` | 1.055 s | 1.055 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_11` | 1.092 s | 1.092 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_12` | 1.122 s | 1.122 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_13` | 1.155 s | 1.155 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_14` | 1.180 s | 1.180 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_15` | 1.199 s | 1.199 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_16` | 1.230 s | 1.230 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_17` | 1.261 s | 1.261 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_18` | 1.289 s | 1.289 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_19` | 1.321 s | 1.321 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_20` | 1.344 s | 1.344 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_21` | 1.377 s | 1.377 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_22` | 1.400 s | 1.400 s |
| server | `laned.reduction.reduction_12.source_13` | 49 m 55.835 s | 49 m 47.854 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_0` | 4.413 s | 4.412 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_1` | 25.531 s | 25.529 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_2` | 15.511 s | 15.510 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_3` | 10.346 s | 10.346 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_4` | 7.807 s | 7.806 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_5` | 6.525 s | 6.524 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_6` | 5.842 s | 5.841 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_7` | 5.502 s | 5.502 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_8` | 5.300 s | 5.300 s |
| server | `laned.multiplication.slot_checkpoint.reduction_13.source_14.checkpoint_14.slot_index` | 2.458 s | 2.458 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_9` | 1.954 s | 1.954 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_10` | 2.152 s | 2.152 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_11` | 2.287 s | 2.287 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_12` | 2.387 s | 2.386 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_13` | 2.492 s | 2.492 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_14` | 2.590 s | 2.590 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_15` | 2.688 s | 2.688 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_16` | 2.775 s | 2.775 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_17` | 2.878 s | 2.878 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_18` | 2.977 s | 2.977 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_19` | 3.079 s | 3.079 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_20` | 3.167 s | 3.167 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_21` | 3.271 s | 3.271 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_22` | 3.202 s | 3.201 s |
| server | `laned.reduction.reduction_13.source_14` | 1 h 26 m 8.214 s | 1 h 23 m 58.875 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_0` | 3 m 2.053 s | 3 m 2.035 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_1` | 2 m 59.010 s | 2 m 58.998 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_2` | 3 m 0.822 s | 3 m 0.810 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_3` | 3 m 1.383 s | 3 m 1.371 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_4` | 3 m 5.113 s | 3 m 5.101 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_5` | 3 m 9.017 s | 3 m 9.005 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_6` | 2 m 56.510 s | 2 m 56.498 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_7` | 3 m 0.661 s | 3 m 0.650 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_8` | 2 m 57.359 s | 2 m 57.348 s |
| server | `laned.affine.slot_checkpoint.reduction_14.source_15.checkpoint_15.slot_index` | 1 m 58.800 s | 1 m 58.792 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_9` | 0.992 s | 0.992 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_10` | 1.057 s | 1.057 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_11` | 1.093 s | 1.093 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_12` | 1.123 s | 1.123 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_13` | 1.155 s | 1.155 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_14` | 1.180 s | 1.180 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_15` | 1.206 s | 1.206 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_16` | 1.229 s | 1.229 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_17` | 1.260 s | 1.260 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_18` | 1.289 s | 1.289 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_19` | 1.320 s | 1.320 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_20` | 1.344 s | 1.344 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_21` | 1.376 s | 1.376 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_22` | 1.402 s | 1.402 s |
| server | `laned.reduction.reduction_14.source_15` | 53 m 19.897 s | 53 m 12.832 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_0` | 4.392 s | 4.392 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_1` | 25.525 s | 25.524 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_2` | 15.466 s | 15.465 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_3` | 10.312 s | 10.311 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_4` | 7.809 s | 7.809 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_5` | 6.530 s | 6.529 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_6` | 5.893 s | 5.893 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_7` | 5.551 s | 5.551 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_8` | 5.291 s | 5.291 s |
| server | `laned.multiplication.slot_checkpoint.reduction_15.source_16.checkpoint_16.slot_index` | 2.485 s | 2.485 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_9` | 1.937 s | 1.937 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_10` | 2.148 s | 2.148 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_11` | 2.272 s | 2.272 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_12` | 2.377 s | 2.377 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_13` | 2.483 s | 2.482 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_14` | 2.572 s | 2.571 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_15` | 2.671 s | 2.671 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_16` | 2.764 s | 2.764 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_17` | 2.866 s | 2.866 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_18` | 2.959 s | 2.959 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_19` | 3.055 s | 3.054 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_20` | 3.148 s | 3.148 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_21` | 3.254 s | 3.254 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_22` | 3.188 s | 3.187 s |
| server | `laned.reduction.reduction_15.source_16` | 1 h 6 m 16.032 s | 1 h 6 m 1.587 s |
| server | `laned.affine.slot_checkpoint.reduction_16.source_17.checkpoint_17.slot_index` | 0.006 s | 0.006 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_0` | 0.542 s | 0.542 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_1` | 1.055 s | 1.055 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_2` | 1.090 s | 1.090 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_3` | 1.127 s | 1.127 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_4` | 1.153 s | 1.153 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_5` | 1.184 s | 1.184 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_6` | 1.212 s | 1.212 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_7` | 1.237 s | 1.237 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_8` | 1.264 s | 1.264 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_9` | 1.294 s | 1.293 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_10` | 1.323 s | 1.322 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_11` | 1.352 s | 1.352 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_12` | 1.376 s | 1.376 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_13` | 1.407 s | 1.407 s |
| server | `laned.reduction.reduction_16.source_17` | 19.863 s | 19.853 s |
| server | `laned.gate_mle_opening` | 5 m 49.978 s | 5 m 49.944 s |

## Client computation

| Component | Wall | CPU |
|---|---:|---:|
| Per-request client computation | 2.246 s | 2.246 s |
| Input encryption | 0.737 s | 0.737 s |
| Output decryption | 0.001 s | 0.001 s |
| VCoED proof verification | 1.508 s | 1.508 s |
| ↳ GKR proof verification | 0.827 s | 0.827 s |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.233 s | 0.233 s |
| ↳↳ Plaintext GKR and affine gate-opening checks | 0.594 s | 0.594 s |
| ↳ Terminal input MLE | 0.005 s | 0.005 s |
| ↳ Spartan packing argument | 0.660 s | 0.660 s |
| ↳ Well-formedness noise checks | 0.017 s | 0.017 s |

Client computation is input encryption + output decryption + VCoED proof verification. Preprocessing RAM loading, transport, peer waiting, and the optional output-noise audit are excluded. Verification rows form a hierarchy: add siblings only. Packed transcript recovery includes signed-digit recomposition into logical plaintexts.

## Client verifier details

Transcript-packing verification and message recovery: **0.573 s wall**. Gate-MLE opening: **0.587 s wall**. These are nested diagnostic spans; they do not define the disjoint computation hierarchy above.

| Circuit layer | Kind | Wall | CPU |
| --- | --- | --- | --- |
| 0 | `affine` | 0.000 s | 0.000 s |
| 1 | `multiplication` | 0.000 s | 0.000 s |
| 2 | `affine` | 0.000 s | 0.000 s |
| 3 | `multiplication` | 0.000 s | 0.000 s |
| 4 | `affine` | 0.000 s | 0.000 s |
| 5 | `multiplication` | 0.000 s | 0.000 s |
| 6 | `affine` | 0.000 s | 0.000 s |
| 7 | `multiplication` | 0.000 s | 0.000 s |
| 8 | `affine` | 0.000 s | 0.000 s |
| 9 | `multiplication` | 0.000 s | 0.000 s |
| 10 | `affine` | 0.000 s | 0.000 s |
| 11 | `multiplication` | 0.000 s | 0.000 s |
| 12 | `affine` | 0.000 s | 0.000 s |
| 13 | `multiplication` | 0.000 s | 0.000 s |
| 14 | `affine` | 0.000 s | 0.000 s |
| 15 | `multiplication` | 0.000 s | 0.000 s |
| 16 | `affine` | 0.000 s | 0.000 s |

### Transcript-packing verifier spans

| Role | Span | Wall | CPU |
| --- | --- | --- | --- |
| client | `transcript_packing.verifier_statement` | 0.018 s | 0.018 s |
| client | `transcript_packing.spartan_verify` | 0.536 s | 0.536 s |
| client | `transcript_packing.threshold_checks` | 0.017 s | 0.017 s |
| client | `transcript_packing.unpack` | 0.002 s | 0.002 s |

## Server FHE operation ledger

| Server stage | Operation | Calls | Limb operations | Calls by RNS limbs |
| --- | --- | --- | --- | --- |
| `server_payload_evaluation` | `add` | 608,570 | 6,970,454 | `5:65535,8:53676,9:53718,10:53652,11:53650,12:53652,13:53604,14:53682,15:167401` |
| `server_payload_evaluation` | `add_plain` | 52,429 | 602,941 | `8:6553,9:6553,10:6553,11:6554,12:6554,13:6554,14:6554,15:6554` |
| `server_payload_evaluation` | `decrypt` | 0 | 0 | `none` |
| `server_payload_evaluation` | `encrypt` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_add` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_mul` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_mul_plain` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_sub` | 0 | 0 | `none` |
| `server_payload_evaluation` | `mod_switch` | 655,364 | 6,881,294 | `2:1,3:1,4:1,5:1,6:65536,7:65536,8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536,15:65536` |
| `server_payload_evaluation` | `mul_no_relin` | 524,288 | 6,029,312 | `8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536,15:65536` |
| `server_payload_evaluation` | `mul_plain_scalar` | 0 | 0 | `none` |
| `server_payload_evaluation` | `mul_plain_vector` | 0 | 0 | `none` |
| `server_payload_evaluation` | `negate` | 0 | 0 | `none` |
| `server_payload_evaluation` | `relinearize` | 524,288 | 6,029,312 | `8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536,15:65536` |
| `server_payload_evaluation` | `rotate` | 0 | 0 | `none` |
| `server_payload_evaluation` | `sub` | 0 | 0 | `none` |
| `server_proving` | `add` | 65,075,683 | 266,309,032 | `1:25432,4:62529145,6:1480722,7:1040384` |
| `server_proving` | `add_plain` | 0 | 0 | `none` |
| `server_proving` | `decrypt` | 0 | 0 | `none` |
| `server_proving` | `encrypt` | 0 | 0 | `none` |
| `server_proving` | `logical_ext_add` | 26,105 | 116,132 | `4:20249,6:5856` |
| `server_proving` | `logical_ext_mul` | 4,304 | 25,824 | `6:4304` |
| `server_proving` | `logical_ext_mul_plain` | 24,505 | 107,364 | `4:19833,6:4672` |
| `server_proving` | `logical_ext_sub` | 350 | 1,848 | `4:126,6:224` |
| `server_proving` | `mod_switch` | 7,187,201 | 66,693,549 | `2:399,3:399,4:399,5:524544,6:459008,7:467008,8:1376385,9:1187970,10:999555,11:811140,12:622724,13:434307,14:245890,15:57473` |
| `server_proving` | `mul_no_relin` | 279,552 | 1,677,312 | `6:279552` |
| `server_proving` | `mul_plain_scalar` | 61,960,463 | 250,131,708 | `4:60815535,6:1144928` |
| `server_proving` | `mul_plain_vector` | 2,362,844 | 12,672,444 | `1:1596,4:1272608,6:40064,7:1048576` |
| `server_proving` | `negate` | 624,972 | 2,595,353 | `1:11933,4:547407,6:65632` |
| `server_proving` | `relinearize` | 2,944 | 17,664 | `6:2944` |
| `server_proving` | `rotate` | 1,897,237 | 12,371,608 | `3:12,4:284117,5:24,6:56604,7:1556480` |
| `server_proving` | `sub` | 6,896 | 39,360 | `4:1008,6:5888` |

## Protocol artifacts

| Quantity | Measured value |
| --- | --- |
| Proving key / server preprocessing | 8,683,342,764 B (8.087 GiB) |
| Verifying key / client preprocessing | 111,752,023 B (106.575 MiB) |
| `server.wire.request_bytes` | 251,669,908 B (240.011 MiB) |
| `server.wire.response_bytes` | 91,351,159 B (87.119 MiB) |
| `client.wire.request_bytes` | 251,669,908 B (240.011 MiB) |
| `client.wire.response_bytes` | 91,351,159 B (87.119 MiB) |
| `server.proof.canonical.committed_gkr_bytes` | 44,384,372 B (42.328 MiB) |
| `server.proof.canonical.digit_packing_ciphertext_bytes` | 1,049,064 B (1.000 MiB) |
| `server.proof.canonical.spartan_packing_proof_bytes` | 14,183,181 B (13.526 MiB) |
| `server.proof.canonical.statement_and_metadata_bytes` | 46 B |
| `server.proof.canonical.total_bytes` | 91,088,583 B (86.869 MiB) |
| `server.proof.canonical.well_formedness_reveal_bytes` | 31,471,920 B (30.014 MiB) |
| `server.proof.committed_gkr.commitment_digest_bytes` | 19,152 B (18.703 KiB) |
| `server.proof.committed_gkr.gate_mle_opening_bytes` | 44,364,476 B (42.309 MiB) |
| `server.proof.response.total_bytes` | 91,351,159 B (87.119 MiB) |

## Memory and storage

| Quantity | Measured value |
| --- | --- |
| `setup.memory.client.admitted_peak_resident_bytes` | 3,897,441,342 B (3.630 GiB) |
| `setup.memory.concurrent.admitted_peak_resident_bytes` | 312,855,969,792 B (291.370 GiB) |
| `setup.memory.host_budget.exact_client_peak_resident_bytes` | 3,897,441,342 B (3.630 GiB) |
| `setup.memory.host_budget.exact_server_resident_cap_bytes` | 308,958,528,450 B (287.740 GiB) |
| `setup.memory.host_budget.gross_resident_budget_bytes` | 312,855,969,792 B (291.370 GiB) |
| `setup.memory.host_budget.operating_system_reserve_bytes` | 16,000,000,000 B (14.901 GiB) |
| `setup.memory.host_budget.page_cache_reserve_bytes` | 64,000,000,000 B (59.605 GiB) |
| `setup.memory.payload_storage.prefetch_page_cache_budget_bytes` | 536,870,912 B (512.000 MiB) |
| `setup.memory.payload_storage.transfer_buffer_reserve_bytes` | 402,653,184 B (384.000 MiB) |
| `setup.memory.payload_storage.writeback_window_bytes` | 0 B |
| `setup.memory.planner_preflight.client_peak_resident_reserve_bytes` | 3,914,215,552 B (3.645 GiB) |
| `setup.memory.planner_preflight.gross_resident_budget_bytes` | 312,855,969,792 B (291.370 GiB) |
| `setup.memory.planner_preflight.observed_physical_ram_bytes` | 392,855,969,792 B (365.876 GiB) |
| `setup.memory.planner_preflight.safety_reserve_bytes` | 80,000,000,000 B (74.506 GiB) |
| `setup.memory.planner_preflight.server_resident_cap_bytes` | 308,941,754,240 B (287.724 GiB) |
| `setup.memory.replay.admitted_peak_resident_bytes` | 292,490,373,832 B (272.403 GiB) |
| `setup.memory.replay.dense_multiplication_alias_cache_peak_resident_bytes` | 292,490,373,832 B (272.403 GiB) |
| `setup.memory.server.admitted_peak_resident_bytes` | 308,958,528,450 B (287.740 GiB) |
| `setup.memory.server.affine_gate_preparation_workspace_upper_bytes` | 0 B |
| `setup.memory.server.common_resident_reserve_bytes` | 17,100,169,928 B (15.926 GiB) |
| `setup.memory.server.gate_mle_opening_workspace_upper_bytes` | 2,552,557,616 B (2.377 GiB) |
| `setup.memory.server.gate_mle_retained_prover_key_upper_bytes` | 10,373,482,416 B (9.661 GiB) |
| `setup.memory.server.laned_affine_workspace_reserve_bytes` | 1,248,067,584 B (1.162 GiB) |
| `setup.memory.server.multiplication_sort_buffer_limit_bytes` | 143,587,439,457 B (133.726 GiB) |
| `setup.memory.server.packing_only_resident_reserve_bytes` | 1,889,698,744 B (1.760 GiB) |
| `setup.memory.server.payload_gkr_only_resident_reserve_bytes` | 1,585,448,960 B (1.477 GiB) |
| `setup.memory.server.reduction_workspace_reserve_bytes` | 2,552,557,616 B (2.377 GiB) |
| `setup.memory.setup.peak_rss_bytes` | 19,090,067,456 B (17.779 GiB) |
| `setup.memory.setup.prepublication_admitted_peak_resident_bytes` | 25,200,009,633 B (23.469 GiB) |
| `setup.memory.setup.prepublication_observed_peak_rss_bytes` | 15,951,884,288 B (14.856 GiB) |
| `setup.memory.setup.prepublication_remaining_resident_reserve_bytes` | 9,248,125,345 B (8.613 GiB) |
| `server.memory.client.admitted_peak_resident_bytes` | 3,897,441,342 B (3.630 GiB) |
| `server.memory.concurrent.admitted_peak_resident_bytes` | 312,855,969,792 B (291.370 GiB) |
| `server.memory.gkr_multiplication_sort_peak_buffered_payload_bytes` | 0 B |
| `server.memory.server.admitted_peak_resident_bytes` | 308,958,528,450 B (287.740 GiB) |
| `server.memory.server.multiplication_sort_buffer_limit_bytes` | 143,587,439,457 B (133.726 GiB) |
| `server.memory.server.peak_rss_bytes` | 20,098,424,832 B (18.718 GiB) |
| `server.memory.server_witness_packing.peak_mask_cache_ntt_bytes` | 0 B |
| `client.memory.client.admitted_peak_resident_bytes` | 3,897,441,342 B (3.630 GiB) |
| `client.memory.client.peak_rss_bytes` | 1,873,346,560 B (1.745 GiB) |
| `server.storage.gkr_multiplication_sort_retained_temporary_bytes` | 0 B |
| `server.storage.gkr_peak_live_scratch_bytes` | 1,610,805,608 B (1.500 GiB) |
| `server.storage.packing.outer_assignment_physical_bytes` | 12,689,335,576 B (11.818 GiB) |
| `server.storage.packing.persistent_input_physical_bytes` | 15,457,578,990 B (14.396 GiB) |
| `server.storage.packing.preprocessing_validation_bytes` | 2,768,243,414 B (2.578 GiB) |
| `server.storage.packing.spartan_peak_live_bytes` | 937,069,138,900 B (872.714 GiB) |
| `server.storage.payload_replay_peak_live_physical_bytes` | 4,254,955,534,095 B (3.870 TiB) |
| `server.storage.payload_replay_peak_live_scratch_bytes` | 4,264,794,573,427 B (3.879 TiB) |
| `server.storage.payload_replay_total_reclaimed_physical_bytes` | 6,349,200,879,763 B (5.775 TiB) |
| `server.storage.server.admitted_peak_live_bytes` | 4,362,792,465,523 B (3.968 TiB) |

## Provenance

| Property | Bound value |
| --- | --- |
| Build / SEAL / SHA-256 acceleration | `Release` / `intel-hexl-runtime-dispatch` / `openssl` |
| Host | `INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz`; 392,855,969,792 B (365.876 GiB) RAM |
| Pinned CPUs | setup `0`; server `0`; client `1`; observer excluded from measured role CPU |
| Threading | setup: `1` worker(s); server and client: `single-cpu-process` |

| Property | Recorded value |
| --- | --- |
| Backend | `shared-root-filesystem` |
| Artifact root | `/var/lib/laminate-storage/laminate-bench` |
| Mount | `/dev/nvme0n1p1` on `/` |
| Filesystem | `ext4` (`rw,relatime,discard,errors=remount-ro,commit=30`) |
| Filesystem capacity | 10,414,378,115,072 B (9.472 TiB) |
| Shared storage directory | `/var/lib/laminate-storage` |
| Shares OS filesystem and I/O | **true — benchmark artifacts and the operating system share the root filesystem and I/O path.** |
| Available at setup start | 10,411,300,130,816 B (9.469 TiB) at `2026-10-12T16:35:38Z` |
| Available at server start | 10,402,610,208,768 B (9.461 TiB) at `2026-10-12T16:43:38Z` |
