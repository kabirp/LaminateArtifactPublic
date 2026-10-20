<!-- laminate-benchmark-summary-v2 -->
# Laminate Folded benchmark summary — target-mulHeavyPyramid

**PASS** — setup, server, and client completed, and the client accepted the proof.

## Highlights

| Highlight | Measured result |
| --- | --- |
| Laminate variant | Folded |
| Payload profile | `target-mulHeavyPyramid` |
| Fiat–Shamir composition | One transcript: GKR, then Spartan packing argument |
| GKR layer transitions | One claim by selector interpolation |
| Scalar gates | 17,179,869,184 (1,048,576 payload gates × 16,384 slots) |
| Initial ciphertext modulus (data primes only) | 626 bits across 14 limbs |
| Plaintext modulus | 65,537 |
| VCoED server wall time | 113 h 42 m 46.842 s |
| ↳ Payload computation | 10 h 18 m 36.259 s |
| ↳ Witness packing | 0.000 s |
| ↳ GKR proving | 92 h 59 m 24.808 s |
| ↳ Transcript packing | 10 h 24 m 42.082 s |
| Per-request client computation | 1.597 s |
| Input encryption | 0.747 s |
| Output decryption | 0.001 s |
| VCoED proof verification | 0.850 s |
| ↳ GKR proof verification | 0.131 s |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.021 s |
| ↳↳ Plaintext GKR and affine gate-opening checks | 0.110 s |
| ↳ Terminal input MLE | 0.038 s |
| ↳ Spartan packing argument | 0.663 s |
| ↳ Well-formedness noise checks | 0.017 s |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | `LaminateImpl/ConservativePackedProofIngress/v4`; limbs by layer `1,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4` |

## Server layer reductions and sumcheck round details

| Role | Span | Wall | CPU |
| --- | --- | --- | --- |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_0` | 2.512 s | 2.511 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_1` | 8.680 s | 8.680 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_2` | 8.376 s | 8.376 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_3` | 8.539 s | 8.538 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_4` | 8.835 s | 8.834 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_5` | 8.296 s | 8.296 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_6` | 9.133 s | 9.133 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_7` | 8.273 s | 8.272 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_8` | 9.089 s | 9.088 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_9` | 8.338 s | 8.338 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_10` | 8.615 s | 8.614 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_11` | 8.925 s | 8.925 s |
| server | `folded.affine.slot_checkpoint.reduction_0.source_1.checkpoint_1.slot_index` | 5.513 s | 5.513 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_12` | 1.013 s | 1.013 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_13` | 1.060 s | 1.060 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_14` | 1.091 s | 1.091 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_15` | 1.123 s | 1.123 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_16` | 1.149 s | 1.149 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_17` | 1.184 s | 1.184 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_18` | 1.218 s | 1.218 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_19` | 1.239 s | 1.238 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_20` | 1.262 s | 1.262 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_21` | 1.295 s | 1.295 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_22` | 1.322 s | 1.322 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_23` | 1.348 s | 1.348 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_24` | 1.373 s | 1.373 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_25` | 1.403 s | 1.403 s |
| server | `folded.reduction.reduction_0.source_1` | 2 m 1.016 s | 2 m 1.006 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_0` | 22.641 s | 22.640 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_1` | 3 m 10.449 s | 3 m 10.435 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_2` | 1 m 50.783 s | 1 m 50.774 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_3` | 1 m 8.900 s | 1 m 8.895 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_4` | 48.735 s | 48.731 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_5` | 38.121 s | 38.119 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_6` | 32.936 s | 32.934 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_7` | 30.544 s | 30.542 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_8` | 29.192 s | 29.190 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_9` | 28.703 s | 28.702 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_10` | 28.674 s | 28.672 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_11` | 27.721 s | 27.719 s |
| server | `folded.multiplication.slot_checkpoint.reduction_1.source_2.checkpoint_2.slot_index` | 19.521 s | 19.520 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_12` | 2.001 s | 2.001 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_13` | 2.168 s | 2.168 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_14` | 2.300 s | 2.300 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_15` | 2.404 s | 2.403 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_16` | 2.509 s | 2.509 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_17` | 2.605 s | 2.605 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_18` | 2.706 s | 2.706 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_19` | 2.804 s | 2.803 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_20` | 2.894 s | 2.894 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_21` | 2.991 s | 2.990 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_22` | 3.100 s | 3.100 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_23` | 3.199 s | 3.198 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_24` | 3.302 s | 3.301 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_25` | 3.235 s | 3.235 s |
| server | `folded.reduction.reduction_1.source_2` | 12 m 49.031 s | 12 m 41.114 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_0` | 13.952 s | 13.951 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_1` | 14.239 s | 14.238 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_2` | 14.920 s | 14.919 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_3` | 14.830 s | 14.829 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_4` | 16.165 s | 16.164 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_5` | 15.651 s | 15.650 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_6` | 15.427 s | 15.426 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_7` | 15.477 s | 15.476 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_8` | 14.904 s | 14.903 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_9` | 15.323 s | 15.322 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_10` | 15.931 s | 15.930 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_11` | 15.701 s | 15.700 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_12` | 14.944 s | 14.942 s |
| server | `folded.affine.slot_checkpoint.reduction_2.source_3.checkpoint_3.slot_index` | 10.130 s | 10.129 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_13` | 1.014 s | 1.014 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_14` | 1.055 s | 1.055 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_15` | 1.092 s | 1.092 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_16` | 1.130 s | 1.130 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_17` | 1.152 s | 1.152 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_18` | 1.177 s | 1.177 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_19` | 1.208 s | 1.208 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_20` | 1.237 s | 1.236 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_21` | 1.268 s | 1.268 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_22` | 1.290 s | 1.289 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_23` | 1.321 s | 1.321 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_24` | 1.346 s | 1.346 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_25` | 1.375 s | 1.375 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_26` | 1.403 s | 1.403 s |
| server | `folded.reduction.reduction_2.source_3` | 4 m 19.852 s | 4 m 19.642 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_0` | 42.637 s | 42.633 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_1` | 6 m 16.335 s | 6 m 16.307 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_2` | 3 m 37.810 s | 3 m 37.793 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_3` | 2 m 14.289 s | 2 m 14.279 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_4` | 1 m 33.094 s | 1 m 33.088 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_5` | 1 m 16.132 s | 1 m 16.127 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_6` | 1 m 1.727 s | 1 m 1.723 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_7` | 58.645 s | 58.642 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_8` | 55.048 s | 55.045 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_9` | 51.896 s | 51.893 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_10` | 56.097 s | 56.094 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_11` | 55.822 s | 55.819 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_12` | 52.677 s | 52.674 s |
| server | `folded.multiplication.slot_checkpoint.reduction_3.source_4.checkpoint_4.slot_index` | 34.278 s | 34.275 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_13` | 1.972 s | 1.972 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_14` | 2.181 s | 2.181 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_15` | 2.303 s | 2.303 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_16` | 2.411 s | 2.411 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_17` | 2.517 s | 2.517 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_18` | 2.607 s | 2.607 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_19` | 2.711 s | 2.711 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_20` | 2.814 s | 2.814 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_21` | 2.916 s | 2.916 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_22` | 3.008 s | 3.008 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_23` | 3.106 s | 3.105 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_24` | 3.205 s | 3.205 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_25` | 3.299 s | 3.298 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_26` | 3.234 s | 3.234 s |
| server | `folded.reduction.reduction_3.source_4` | 25 m 20.024 s | 25 m 18.602 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_0` | 28.046 s | 28.044 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_1` | 28.253 s | 28.252 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_2` | 29.903 s | 29.901 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_3` | 31.195 s | 31.193 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_4` | 31.386 s | 31.384 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_5` | 30.436 s | 30.434 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_6` | 30.581 s | 30.579 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_7` | 28.742 s | 28.740 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_8` | 29.030 s | 29.028 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_9` | 30.869 s | 30.867 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_10` | 30.218 s | 30.216 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_11` | 29.517 s | 29.515 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_12` | 28.262 s | 28.260 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_13` | 31.001 s | 30.999 s |
| server | `folded.affine.slot_checkpoint.reduction_4.source_5.checkpoint_5.slot_index` | 19.741 s | 19.740 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_14` | 1.006 s | 1.006 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_15` | 1.054 s | 1.054 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_16` | 1.086 s | 1.086 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_17` | 1.118 s | 1.118 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_18` | 1.144 s | 1.144 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_19` | 1.175 s | 1.175 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_20` | 1.202 s | 1.202 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_21` | 1.232 s | 1.232 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_22` | 1.258 s | 1.258 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_23` | 1.288 s | 1.288 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_24` | 1.315 s | 1.315 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_25` | 1.343 s | 1.343 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_26` | 1.366 s | 1.366 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_27` | 1.398 s | 1.398 s |
| server | `folded.reduction.reduction_4.source_5` | 9 m 8.744 s | 9 m 8.347 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_0` | 1 m 23.630 s | 1 m 23.624 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_1` | 12 m 40.045 s | 12 m 39.989 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_2` | 7 m 13.157 s | 7 m 13.127 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_3` | 4 m 27.302 s | 4 m 27.283 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_4` | 3 m 2.505 s | 3 m 2.492 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_5` | 2 m 22.429 s | 2 m 22.419 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_6` | 2 m 1.299 s | 2 m 1.291 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_7` | 1 m 52.034 s | 1 m 52.027 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_8` | 1 m 50.257 s | 1 m 50.251 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_9` | 1 m 47.702 s | 1 m 47.695 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_10` | 1 m 41.460 s | 1 m 41.454 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_11` | 1 m 41.659 s | 1 m 41.652 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_12` | 1 m 39.641 s | 1 m 39.635 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_13` | 1 m 40.329 s | 1 m 40.322 s |
| server | `folded.multiplication.slot_checkpoint.reduction_5.source_6.checkpoint_6.slot_index` | 1 m 9.016 s | 1 m 9.011 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_14` | 2.003 s | 2.003 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_15` | 2.188 s | 2.188 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_16` | 2.304 s | 2.304 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_17` | 2.407 s | 2.406 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_18` | 2.518 s | 2.518 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_19` | 2.605 s | 2.604 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_20` | 2.699 s | 2.699 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_21` | 2.797 s | 2.796 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_22` | 2.901 s | 2.901 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_23` | 2.996 s | 2.996 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_24` | 3.102 s | 3.102 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_25` | 3.194 s | 3.194 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_26` | 3.300 s | 3.300 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_27` | 3.236 s | 3.235 s |
| server | `folded.reduction.reduction_5.source_6` | 52 m 11.323 s | 52 m 1.184 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_0` | 59.098 s | 59.089 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_1` | 54.225 s | 54.218 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_2` | 54.834 s | 54.829 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_3` | 56.749 s | 56.745 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_4` | 55.715 s | 55.711 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_5` | 56.247 s | 56.243 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_6` | 58.128 s | 58.124 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_7` | 1 m 2.696 s | 1 m 2.692 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_8` | 57.115 s | 57.112 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_9` | 55.845 s | 55.842 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_10` | 56.963 s | 56.960 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_11` | 56.554 s | 56.551 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_12` | 56.061 s | 56.057 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_13` | 57.189 s | 57.186 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_14` | 57.573 s | 57.569 s |
| server | `folded.affine.slot_checkpoint.reduction_6.source_7.checkpoint_7.slot_index` | 38.892 s | 38.889 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_15` | 1.015 s | 1.015 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_16` | 1.053 s | 1.053 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_17` | 1.096 s | 1.096 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_18` | 1.127 s | 1.127 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_19` | 1.155 s | 1.155 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_20` | 1.180 s | 1.180 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_21` | 1.210 s | 1.210 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_22` | 1.235 s | 1.235 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_23` | 1.268 s | 1.268 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_24` | 1.285 s | 1.285 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_25` | 1.322 s | 1.322 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_26` | 1.345 s | 1.345 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_27` | 1.376 s | 1.375 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_28` | 1.399 s | 1.399 s |
| server | `folded.reduction.reduction_6.source_7` | 19 m 27.469 s | 19 m 24.062 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_0` | 2 m 53.831 s | 2 m 53.545 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_1` | 25 m 10.456 s | 25 m 10.345 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_2` | 14 m 23.434 s | 14 m 23.372 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_3` | 8 m 50.776 s | 8 m 50.737 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_4` | 6 m 5.057 s | 6 m 5.032 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_5` | 4 m 42.523 s | 4 m 42.504 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_6` | 4 m 7.619 s | 4 m 7.602 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_7` | 3 m 40.426 s | 3 m 40.412 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_8` | 3 m 39.481 s | 3 m 39.468 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_9` | 3 m 26.031 s | 3 m 26.019 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_10` | 3 m 25.026 s | 3 m 25.013 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_11` | 3 m 18.267 s | 3 m 18.254 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_12` | 3 m 18.007 s | 3 m 17.993 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_13` | 3 m 17.078 s | 3 m 17.065 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_14` | 3 m 17.329 s | 3 m 17.315 s |
| server | `folded.multiplication.slot_checkpoint.reduction_7.source_8.checkpoint_8.slot_index` | 2 m 23.718 s | 2 m 23.708 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_15` | 2.009 s | 2.009 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_16` | 2.188 s | 2.188 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_17` | 2.303 s | 2.302 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_18` | 2.404 s | 2.404 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_19` | 2.511 s | 2.510 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_20` | 2.610 s | 2.609 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_21` | 2.705 s | 2.704 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_22` | 2.800 s | 2.799 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_23` | 2.904 s | 2.903 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_24` | 2.989 s | 2.988 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_25` | 3.098 s | 3.098 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_26` | 3.188 s | 3.188 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_27` | 3.292 s | 3.292 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_28` | 3.232 s | 3.232 s |
| server | `folded.reduction.reduction_7.source_8` | 1 h 49 m 35.393 s | 1 h 49 m 4.653 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_0` | 1 m 50.533 s | 1 m 50.525 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_1` | 1 m 48.601 s | 1 m 48.593 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_2` | 1 m 48.609 s | 1 m 48.601 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_3` | 2 m 5.648 s | 2 m 5.639 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_4` | 2 m 5.206 s | 2 m 5.199 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_5` | 1 m 52.845 s | 1 m 52.838 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_6` | 1 m 52.524 s | 1 m 52.517 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_7` | 2 m 0.427 s | 2 m 0.420 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_8` | 1 m 49.273 s | 1 m 49.266 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_9` | 1 m 51.501 s | 1 m 51.494 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_10` | 1 m 52.552 s | 1 m 52.545 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_11` | 1 m 52.355 s | 1 m 52.348 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_12` | 1 m 51.150 s | 1 m 51.143 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_13` | 1 m 51.866 s | 1 m 51.859 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_14` | 1 m 51.084 s | 1 m 51.077 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_15` | 1 m 50.689 s | 1 m 50.681 s |
| server | `folded.affine.slot_checkpoint.reduction_8.source_9.checkpoint_9.slot_index` | 1 m 18.402 s | 1 m 18.397 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_16` | 1.005 s | 1.005 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_17` | 1.055 s | 1.055 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_18` | 1.085 s | 1.085 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_19` | 1.116 s | 1.116 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_20` | 1.143 s | 1.142 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_21` | 1.174 s | 1.174 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_22` | 1.202 s | 1.202 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_23` | 1.228 s | 1.228 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_24` | 1.252 s | 1.252 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_25` | 1.282 s | 1.282 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_26` | 1.307 s | 1.307 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_27` | 1.333 s | 1.333 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_28` | 1.358 s | 1.358 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_29` | 1.391 s | 1.391 s |
| server | `folded.reduction.reduction_8.source_9` | 42 m 41.196 s | 42 m 37.158 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_0` | 6 m 25.730 s | 6 m 25.705 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_1` | 51 m 17.912 s | 51 m 17.684 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_2` | 29 m 40.156 s | 29 m 40.012 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_3` | 18 m 32.714 s | 18 m 32.619 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_4` | 13 m 1.313 s | 13 m 1.253 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_5` | 10 m 18.492 s | 10 m 18.432 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_6` | 8 m 55.556 s | 8 m 55.512 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_7` | 8 m 19.378 s | 8 m 19.342 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_8` | 8 m 0.827 s | 8 m 0.789 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_9` | 7 m 38.317 s | 7 m 38.283 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_10` | 7 m 46.614 s | 7 m 46.573 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_11` | 7 m 34.476 s | 7 m 34.440 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_12` | 7 m 38.227 s | 7 m 38.196 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_13` | 7 m 34.596 s | 7 m 34.555 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_14` | 7 m 33.447 s | 7 m 33.411 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_15` | 7 m 38.378 s | 7 m 38.345 s |
| server | `folded.multiplication.slot_checkpoint.reduction_9.source_10.checkpoint_10.slot_index` | 5 m 34.008 s | 5 m 33.982 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_16` | 1.991 s | 1.991 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_17` | 2.179 s | 2.178 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_18` | 2.306 s | 2.305 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_19` | 2.414 s | 2.414 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_20` | 2.514 s | 2.514 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_21` | 2.612 s | 2.612 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_22` | 2.705 s | 2.704 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_23` | 2.800 s | 2.800 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_24` | 2.899 s | 2.899 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_25` | 2.994 s | 2.994 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_26` | 3.099 s | 3.099 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_27` | 3.188 s | 3.188 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_28` | 3.288 s | 3.288 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_29` | 3.217 s | 3.217 s |
| server | `folded.reduction.reduction_9.source_10` | 4 h 6 m 13.654 s | 4 h 4 m 41.779 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_0` | 3 m 58.503 s | 3 m 58.488 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_1` | 3 m 39.703 s | 3 m 39.689 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_2` | 3 m 30.451 s | 3 m 30.438 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_3` | 3 m 39.320 s | 3 m 39.306 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_4` | 3 m 41.327 s | 3 m 41.313 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_5` | 3 m 36.649 s | 3 m 36.635 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_6` | 3 m 38.212 s | 3 m 38.198 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_7` | 3 m 44.372 s | 3 m 44.358 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_8` | 3 m 35.974 s | 3 m 35.961 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_9` | 3 m 41.435 s | 3 m 41.421 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_10` | 3 m 37.614 s | 3 m 37.601 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_11` | 3 m 43.979 s | 3 m 43.965 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_12` | 3 m 37.998 s | 3 m 37.984 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_13` | 3 m 36.395 s | 3 m 36.381 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_14` | 3 m 38.438 s | 3 m 38.424 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_15` | 3 m 39.539 s | 3 m 39.525 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_16` | 3 m 37.263 s | 3 m 37.249 s |
| server | `folded.affine.slot_checkpoint.reduction_10.source_11.checkpoint_11.slot_index` | 2 m 40.080 s | 2 m 40.069 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_17` | 1.011 s | 1.011 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_18` | 1.054 s | 1.054 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_19` | 1.091 s | 1.091 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_20` | 1.120 s | 1.119 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_21` | 1.149 s | 1.149 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_22` | 1.173 s | 1.173 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_23` | 1.206 s | 1.206 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_24` | 1.231 s | 1.231 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_25` | 1.258 s | 1.258 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_26` | 1.283 s | 1.283 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_27` | 1.315 s | 1.315 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_28` | 1.338 s | 1.338 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_29` | 1.368 s | 1.368 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_30` | 1.391 s | 1.391 s |
| server | `folded.reduction.reduction_10.source_11` | 1 h 31 m 26.864 s | 1 h 31 m 17.452 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_0` | 12 m 57.136 s | 12 m 57.083 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_1` | 1 h 42 m 33.254 s | 1 h 42 m 32.804 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_2` | 59 m 31.141 s | 59 m 30.876 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_3` | 37 m 14.265 s | 37 m 14.099 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_4` | 26 m 23.306 s | 26 m 23.195 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_5` | 20 m 54.522 s | 20 m 54.434 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_6` | 18 m 8.804 s | 18 m 8.729 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_7` | 16 m 39.697 s | 16 m 39.631 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_8` | 15 m 59.243 s | 15 m 59.181 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_9` | 15 m 42.618 s | 15 m 42.557 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_10` | 15 m 21.776 s | 15 m 21.717 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_11` | 15 m 18.679 s | 15 m 18.620 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_12` | 15 m 5.601 s | 15 m 5.543 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_13` | 15 m 9.183 s | 15 m 9.125 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_14` | 15 m 12.652 s | 15 m 12.594 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_15` | 15 m 8.288 s | 15 m 8.230 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_16` | 15 m 9.021 s | 15 m 8.963 s |
| server | `folded.multiplication.slot_checkpoint.reduction_11.source_12.checkpoint_12.slot_index` | 11 m 14.737 s | 11 m 14.694 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_17` | 2.004 s | 2.003 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_18` | 2.188 s | 2.188 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_19` | 2.318 s | 2.318 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_20` | 2.424 s | 2.424 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_21` | 2.527 s | 2.527 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_22` | 2.616 s | 2.616 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_23` | 2.746 s | 2.746 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_24` | 2.821 s | 2.820 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_25` | 2.913 s | 2.913 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_26` | 3.004 s | 3.004 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_27` | 3.112 s | 3.112 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_28` | 3.207 s | 3.207 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_29` | 3.310 s | 3.310 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_30` | 3.241 s | 3.240 s |
| server | `folded.reduction.reduction_11.source_12` | 8 h 37 m 29.507 s | 8 h 34 m 34.630 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_0` | 8 m 19.460 s | 8 m 19.428 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_1` | 8 m 21.931 s | 8 m 21.898 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_2` | 8 m 21.258 s | 8 m 21.226 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_3` | 8 m 32.977 s | 8 m 32.945 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_4` | 8 m 32.833 s | 8 m 32.798 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_5` | 8 m 29.255 s | 8 m 29.221 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_6` | 8 m 49.739 s | 8 m 49.706 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_7` | 8 m 49.294 s | 8 m 49.261 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_8` | 8 m 30.647 s | 8 m 30.612 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_9` | 8 m 47.152 s | 8 m 47.118 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_10` | 8 m 52.960 s | 8 m 52.926 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_11` | 8 m 55.094 s | 8 m 55.060 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_12` | 9 m 2.054 s | 9 m 2.018 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_13` | 8 m 47.281 s | 8 m 47.248 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_14` | 8 m 29.064 s | 8 m 29.031 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_15` | 8 m 31.964 s | 8 m 31.932 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_16` | 8 m 40.565 s | 8 m 40.532 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_17` | 8 m 35.660 s | 8 m 35.627 s |
| server | `folded.affine.slot_checkpoint.reduction_12.source_13.checkpoint_13.slot_index` | 6 m 26.541 s | 6 m 26.516 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_18` | 1.002 s | 1.002 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_19` | 1.059 s | 1.058 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_20` | 1.089 s | 1.088 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_21` | 1.121 s | 1.121 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_22` | 1.146 s | 1.146 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_23` | 1.177 s | 1.177 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_24` | 1.206 s | 1.206 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_25` | 1.234 s | 1.234 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_26` | 1.257 s | 1.257 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_27` | 1.287 s | 1.287 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_28` | 1.314 s | 1.314 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_29` | 1.340 s | 1.340 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_30` | 1.379 s | 1.379 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_31` | 1.396 s | 1.396 s |
| server | `folded.reduction.reduction_12.source_13` | 3 h 44 m 32.911 s | 3 h 44 m 11.345 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_0` | 25 m 48.860 s | 25 m 48.575 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_1` | 3 h 24 m 47.199 s | 3 h 24 m 45.975 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_2` | 1 h 58 m 45.402 s | 1 h 58 m 44.663 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_3` | 1 h 14 m 22.384 s | 1 h 14 m 21.871 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_4` | 52 m 33.392 s | 52 m 32.983 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_5` | 41 m 40.004 s | 41 m 39.651 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_6` | 36 m 10.408 s | 36 m 10.094 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_7` | 33 m 18.082 s | 33 m 17.779 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_8` | 31 m 46.215 s | 31 m 45.917 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_9` | 31 m 14.425 s | 31 m 14.092 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_10` | 30 m 37.789 s | 30 m 37.010 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_11` | 30 m 24.653 s | 30 m 24.319 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_12` | 30 m 16.687 s | 30 m 16.035 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_13` | 30 m 13.527 s | 30 m 12.018 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_14` | 30 m 14.374 s | 30 m 14.005 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_15` | 30 m 9.854 s | 30 m 9.572 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_16` | 30 m 11.369 s | 30 m 11.086 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_17` | 30 m 13.489 s | 30 m 12.698 s |
| server | `folded.multiplication.slot_checkpoint.reduction_13.source_14.checkpoint_14.slot_index` | 22 m 21.291 s | 22 m 20.992 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_18` | 2.011 s | 2.010 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_19` | 2.204 s | 2.204 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_20` | 2.316 s | 2.315 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_21` | 2.415 s | 2.415 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_22` | 2.528 s | 2.528 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_23` | 2.625 s | 2.624 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_24` | 2.723 s | 2.722 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_25` | 2.810 s | 2.810 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_26` | 2.912 s | 2.911 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_27` | 3.018 s | 3.018 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_28` | 3.117 s | 3.116 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_29` | 3.196 s | 3.196 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_30` | 3.298 s | 3.298 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_31` | 3.255 s | 3.255 s |
| server | `folded.reduction.reduction_13.source_14` | 18 h 1 m 48.984 s | 17 h 56 m 6.601 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_0` | 19 m 36.408 s | 19 m 36.330 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_1` | 20 m 2.846 s | 20 m 2.750 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_2` | 20 m 21.139 s | 20 m 20.948 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_3` | 20 m 14.079 s | 20 m 14.002 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_4` | 20 m 29.084 s | 20 m 29.001 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_5` | 21 m 32.452 s | 21 m 32.362 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_6` | 22 m 3.562 s | 22 m 3.396 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_7` | 22 m 55.940 s | 22 m 55.851 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_8` | 24 m 58.975 s | 24 m 58.811 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_9` | 34 m 38.664 s | 34 m 38.520 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_10` | 46 m 34.344 s | 46 m 34.131 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_11` | 53 m 27.491 s | 53 m 26.965 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_12` | 1 h 27 m 40.534 s | 1 h 27 m 40.183 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_13` | 2 h 6 m 36.161 s | 2 h 6 m 35.604 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_14` | 2 h 9 m 5.505 s | 2 h 9 m 4.935 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_15` | 2 h 6 m 32.634 s | 2 h 6 m 32.081 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_16` | 2 h 5 m 55.834 s | 2 h 5 m 55.298 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_17` | 2 h 1 m 57.179 s | 2 h 1 m 56.669 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_18` | 2 h 4 m 38.174 s | 2 h 4 m 37.657 s |
| server | `folded.affine.slot_checkpoint.reduction_14.source_15.checkpoint_15.slot_index` | 12 m 1.341 s | 12 m 1.295 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_19` | 1.011 s | 1.011 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_20` | 1.059 s | 1.059 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_21` | 1.098 s | 1.098 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_22` | 1.129 s | 1.129 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_23` | 1.159 s | 1.159 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_24` | 1.182 s | 1.181 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_25` | 1.211 s | 1.211 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_26` | 1.236 s | 1.236 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_27` | 1.266 s | 1.266 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_28` | 1.286 s | 1.286 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_29` | 1.320 s | 1.320 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_30` | 1.349 s | 1.348 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_31` | 1.379 s | 1.379 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_32` | 1.402 s | 1.402 s |
| server | `folded.reduction.reduction_14.source_15` | 21 h 59 m 10.498 s | 21 h 58 m 26.128 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_0` | 44 m 38.194 s | 44 m 38.003 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_1` | 6 h 42 m 57.535 s | 6 h 42 m 55.741 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_2` | 3 h 48 m 47.103 s | 3 h 48 m 46.076 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_3` | 2 h 20 m 53.954 s | 2 h 20 m 53.324 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_4` | 1 h 36 m 20.873 s | 1 h 36 m 20.441 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_5` | 1 h 13 m 54.013 s | 1 h 13 m 53.691 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_6` | 1 h 2 m 7.220 s | 1 h 2 m 6.958 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_7` | 56 m 20.993 s | 56 m 20.759 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_8` | 53 m 25.884 s | 53 m 25.661 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_9` | 51 m 54.204 s | 51 m 53.996 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_10` | 51 m 8.329 s | 51 m 8.123 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_11` | 50 m 45.718 s | 50 m 45.514 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_12` | 50 m 33.160 s | 50 m 32.958 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_13` | 50 m 25.956 s | 50 m 25.753 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_14` | 50 m 28.689 s | 50 m 28.488 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_15` | 50 m 26.257 s | 50 m 26.055 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_16` | 50 m 26.084 s | 50 m 25.877 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_17` | 50 m 27.872 s | 50 m 27.668 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_18` | 50 m 30.056 s | 50 m 29.854 s |
| server | `folded.multiplication.slot_checkpoint.reduction_15.source_16.checkpoint_16.slot_index` | 35 m 46.479 s | 35 m 46.341 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_19` | 1.970 s | 1.969 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_20` | 2.178 s | 2.178 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_21` | 2.304 s | 2.304 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_22` | 2.405 s | 2.404 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_23` | 2.512 s | 2.512 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_24` | 2.603 s | 2.603 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_25` | 2.703 s | 2.702 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_26` | 2.791 s | 2.791 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_27` | 2.903 s | 2.902 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_28` | 2.995 s | 2.995 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_29` | 3.095 s | 3.094 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_30` | 3.195 s | 3.195 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_31` | 3.293 s | 3.292 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_32` | 3.231 s | 3.231 s |
| server | `folded.reduction.reduction_15.source_16` | 29 h 15 m 49.031 s | 29 h 14 m 22.314 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_0` | 6.135 s | 6.134 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_1` | 11.155 s | 11.154 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_2` | 12.905 s | 12.904 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_3` | 15.323 s | 15.322 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_4` | 20.934 s | 20.933 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_5` | 30.160 s | 30.158 s |
| server | `folded.affine.slot_checkpoint.reduction_16.source_17.checkpoint_17.slot_index` | 0.091 s | 0.091 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_6` | 0.989 s | 0.989 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_7` | 1.052 s | 1.052 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_8` | 1.087 s | 1.087 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_9` | 1.122 s | 1.122 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_10` | 1.149 s | 1.149 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_11` | 1.180 s | 1.180 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_12` | 1.204 s | 1.204 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_13` | 1.236 s | 1.236 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_14` | 1.260 s | 1.259 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_15` | 1.287 s | 1.287 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_16` | 1.313 s | 1.313 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_17` | 1.343 s | 1.343 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_18` | 1.370 s | 1.370 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_19` | 1.398 s | 1.398 s |
| server | `folded.reduction.reduction_16.source_17` | 22 m 43.414 s | 22 m 43.330 s |
| server | `folded.gate_mle_opening` | 42 m 35.865 s | 42 m 34.512 s |

## Client computation

| Component | Wall | CPU |
|---|---:|---:|
| Per-request client computation | 1.597 s | 1.597 s |
| Input encryption | 0.747 s | 0.747 s |
| Output decryption | 0.001 s | 0.001 s |
| VCoED proof verification | 0.850 s | 0.850 s |
| ↳ GKR proof verification | 0.131 s | 0.131 s |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.021 s | 0.021 s |
| ↳↳ Plaintext GKR and affine gate-opening checks | 0.110 s | 0.110 s |
| ↳ Terminal input MLE | 0.038 s | 0.038 s |
| ↳ Spartan packing argument | 0.663 s | 0.663 s |
| ↳ Well-formedness noise checks | 0.017 s | 0.017 s |

Client computation is input encryption + output decryption + VCoED proof verification. Preprocessing RAM loading, transport, peer waiting, and the optional output-noise audit are excluded. Verification rows form a hierarchy: add siblings only. Packed transcript recovery includes signed-digit recomposition into logical plaintexts.

## Client verifier details

Transcript-packing verification and message recovery: **0.676 s wall**. Gate-MLE opening: **0.103 s wall**. These are nested diagnostic spans; they do not define the disjoint computation hierarchy above.

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
| client | `transcript_packing.verifier_statement` | 0.023 s | 0.023 s |
| client | `transcript_packing.spartan_verify` | 0.633 s | 0.633 s |
| client | `transcript_packing.threshold_checks` | 0.017 s | 0.017 s |
| client | `transcript_packing.unpack` | 0.002 s | 0.002 s |

## Server FHE operation ledger

| Server stage | Operation | Calls | Limb operations | Calls by RNS limbs |
| --- | --- | --- | --- | --- |
| `server_payload_evaluation` | `add` | 131,024 | 1,770,520 | `4:3765,13:26166,14:101093` |
| `server_payload_evaluation` | `add_plain` | 0 | 0 | `none` |
| `server_payload_evaluation` | `decrypt` | 0 | 0 | `none` |
| `server_payload_evaluation` | `encrypt` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_add` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_mul` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_mul_plain` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_sub` | 0 | 0 | `none` |
| `server_payload_evaluation` | `mod_switch` | 899,661 | 11,641,319 | `2:1,3:1,4:1,5:3766,6:3766,7:3766,8:7196,9:14392,10:28784,11:57568,12:115136,13:230270,14:435014` |
| `server_payload_evaluation` | `mul_no_relin` | 891,290 | 11,588,954 | `7:3766,8:7196,9:14392,10:28784,11:57568,12:115134,13:229500,14:434950` |
| `server_payload_evaluation` | `mul_plain_scalar` | 0 | 0 | `none` |
| `server_payload_evaluation` | `mul_plain_vector` | 26,214 | 342,330 | `13:24666,14:1548` |
| `server_payload_evaluation` | `negate` | 0 | 0 | `none` |
| `server_payload_evaluation` | `relinearize` | 891,290 | 11,588,954 | `7:3766,8:7196,9:14392,10:28784,11:57568,12:115134,13:229500,14:434950` |
| `server_payload_evaluation` | `rotate` | 39,336 | 550,704 | `14:39336` |
| `server_payload_evaluation` | `sub` | 0 | 0 | `none` |
| `server_proving` | `add` | 1,024,607,419 | 5,124,488,661 | `1:32377,4:511496984,6:513078058` |
| `server_proving` | `add_plain` | 188,516 | 1,131,096 | `6:188516` |
| `server_proving` | `decrypt` | 0 | 0 | `none` |
| `server_proving` | `encrypt` | 0 | 0 | `none` |
| `server_proving` | `logical_ext_add` | 1,049,467 | 6,290,140 | `4:3331,6:1046136` |
| `server_proving` | `logical_ext_mul` | 1,044,688 | 6,268,128 | `6:1044688` |
| `server_proving` | `logical_ext_mul_plain` | 1,048,058 | 6,282,552 | `4:2898,6:1045160` |
| `server_proving` | `logical_ext_sub` | 350 | 1,848 | `4:126,6:224` |
| `server_proving` | `mod_switch` | 13,692,945 | 125,680,381 | `2:509,3:509,4:509,5:888668,6:888668,7:1930305,8:1915913,9:1887129,10:1829561,11:1714425,12:1484153,13:1023613,14:128983` |
| `server_proving` | `mul_no_relin` | 67,904,176 | 407,425,056 | `6:67904176` |
| `server_proving` | `mul_plain_scalar` | 967,001,033 | 4,779,607,894 | `4:511199152,6:455801881` |
| `server_proving` | `mul_plain_vector` | 228,140 | 1,001,556 | `1:2036,4:178552,6:47552` |
| `server_proving` | `negate` | 15,022,446 | 89,922,452 | `1:15380,4:67662,6:14939404` |
| `server_proving` | `relinearize` | 3,776 | 22,656 | `6:3776` |
| `server_proving` | `rotate` | 134,516 | 674,644 | `3:22,4:66176,5:34,6:68284` |
| `server_proving` | `sub` | 741,736 | 4,448,400 | `4:1008,6:740728` |

## Protocol artifacts

| Quantity | Measured value |
| --- | --- |
| Proving key / server preprocessing | 121,977,155,031 B (113.600 GiB) |
| Verifying key / client preprocessing | 147,614,102 B (140.776 MiB) |
| `server.wire.request_bytes` | 234,892,693 B (224.011 MiB) |
| `server.wire.response_bytes` | 52,378,878 B (49.952 MiB) |
| `client.wire.request_bytes` | 234,892,693 B (224.011 MiB) |
| `client.wire.response_bytes` | 52,378,878 B (49.952 MiB) |
| `server.proof.canonical.committed_gkr_bytes` | 5,429,706 B (5.178 MiB) |
| `server.proof.canonical.digit_packing_ciphertext_bytes` | 1,049,064 B (1.000 MiB) |
| `server.proof.canonical.spartan_packing_proof_bytes` | 14,165,565 B (13.509 MiB) |
| `server.proof.canonical.statement_and_metadata_bytes` | 46 B |
| `server.proof.canonical.total_bytes` | 52,116,301 B (49.702 MiB) |
| `server.proof.canonical.well_formedness_reveal_bytes` | 31,471,920 B (30.014 MiB) |
| `server.proof.committed_gkr.commitment_digest_bytes` | 24,432 B (23.859 KiB) |
| `server.proof.committed_gkr.gate_mle_opening_bytes` | 5,404,420 B (5.154 MiB) |
| `server.proof.response.total_bytes` | 52,378,878 B (49.952 MiB) |

## Memory and storage

| Quantity | Measured value |
| --- | --- |
| `setup.memory.client.admitted_peak_resident_bytes` | 11,132,157,085 B (10.368 GiB) |
| `setup.memory.concurrent.admitted_peak_resident_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.host_budget.exact_client_peak_resident_bytes` | 11,132,157,085 B (10.368 GiB) |
| `setup.memory.host_budget.exact_server_resident_cap_bytes` | 301,723,804,515 B (281.002 GiB) |
| `setup.memory.host_budget.gross_resident_budget_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.host_budget.operating_system_reserve_bytes` | 16,000,000,000 B (14.901 GiB) |
| `setup.memory.host_budget.page_cache_reserve_bytes` | 64,000,000,000 B (59.605 GiB) |
| `setup.memory.payload_storage.prefetch_page_cache_budget_bytes` | 536,870,912 B (512.000 MiB) |
| `setup.memory.payload_storage.transfer_buffer_reserve_bytes` | 402,653,184 B (384.000 MiB) |
| `setup.memory.payload_storage.writeback_window_bytes` | 0 B |
| `setup.memory.planner_preflight.client_peak_resident_reserve_bytes` | 11,148,669,215 B (10.383 GiB) |
| `setup.memory.planner_preflight.gross_resident_budget_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.planner_preflight.observed_physical_ram_bytes` | 392,855,961,600 B (365.876 GiB) |
| `setup.memory.planner_preflight.safety_reserve_bytes` | 80,000,000,000 B (74.506 GiB) |
| `setup.memory.planner_preflight.server_resident_cap_bytes` | 301,707,292,385 B (280.987 GiB) |
| `setup.memory.replay.admitted_peak_resident_bytes` | 88,905,662,625 B (82.800 GiB) |
| `setup.memory.replay.dense_multiplication_alias_cache_peak_resident_bytes` | 25,952,641,697 B (24.170 GiB) |
| `setup.memory.server.admitted_peak_resident_bytes` | 301,723,804,515 B (281.002 GiB) |
| `setup.memory.server.affine_gate_preparation_workspace_upper_bytes` | 14,752,489,472 B (13.739 GiB) |
| `setup.memory.server.common_resident_reserve_bytes` | 10,250,541,729 B (9.547 GiB) |
| `setup.memory.server.gate_mle_opening_workspace_upper_bytes` | 38,365,595,456 B (35.731 GiB) |
| `setup.memory.server.gate_mle_retained_prover_key_upper_bytes` | 344,636,416 B (328.671 MiB) |
| `setup.memory.server.multiplication_sort_buffer_limit_bytes` | 117,970,414,785 B (109.869 GiB) |
| `setup.memory.server.packing_only_resident_reserve_bytes` | 5,489,322,200 B (5.112 GiB) |
| `setup.memory.server.payload_gkr_only_resident_reserve_bytes` | 1,551,894,528 B (1.445 GiB) |
| `setup.memory.server.reduction_workspace_reserve_bytes` | 53,118,084,928 B (49.470 GiB) |
| `setup.memory.setup.peak_rss_bytes` | 15,723,266,048 B (14.643 GiB) |
| `setup.memory.setup.prepublication_admitted_peak_resident_bytes` | 21,378,420,135 B (19.910 GiB) |
| `setup.memory.setup.prepublication_observed_peak_rss_bytes` | 12,537,356,288 B (11.676 GiB) |
| `setup.memory.setup.prepublication_remaining_resident_reserve_bytes` | 8,841,063,847 B (8.234 GiB) |
| `server.memory.client.admitted_peak_resident_bytes` | 11,132,157,085 B (10.368 GiB) |
| `server.memory.concurrent.admitted_peak_resident_bytes` | 312,855,961,600 B (291.370 GiB) |
| `server.memory.gkr_multiplication_sort_peak_buffered_payload_bytes` | 117,969,834,820 B (109.868 GiB) |
| `server.memory.server.admitted_peak_resident_bytes` | 301,723,804,515 B (281.002 GiB) |
| `server.memory.server.multiplication_sort_buffer_limit_bytes` | 117,970,414,785 B (109.869 GiB) |
| `server.memory.server.peak_rss_bytes` | 204,809,445,376 B (190.744 GiB) |
| `server.memory.server_witness_packing.peak_mask_cache_ntt_bytes` | 0 B |
| `client.memory.client.admitted_peak_resident_bytes` | 11,132,157,085 B (10.368 GiB) |
| `client.memory.client.peak_rss_bytes` | 1,934,659,584 B (1.802 GiB) |
| `server.storage.gkr_multiplication_sort_retained_temporary_bytes` | 0 B |
| `server.storage.gkr_peak_live_scratch_bytes` | 1,445,999,736,266 B (1.315 TiB) |
| `server.storage.packing.outer_assignment_physical_bytes` | 16,178,686,992 B (15.068 GiB) |
| `server.storage.packing.persistent_input_physical_bytes` | 18,946,930,406 B (17.646 GiB) |
| `server.storage.packing.preprocessing_validation_bytes` | 2,768,243,414 B (2.578 GiB) |
| `server.storage.packing.spartan_peak_live_bytes` | 945,971,901,892 B (881.005 GiB) |
| `server.storage.payload_replay_peak_live_physical_bytes` | 5,921,972,755,718 B (5.386 TiB) |
| `server.storage.payload_replay_peak_live_scratch_bytes` | 6,051,792,238,517 B (5.504 TiB) |
| `server.storage.payload_replay_total_reclaimed_physical_bytes` | 8,485,283,086,025 B (7.717 TiB) |
| `server.storage.server.admitted_peak_live_bytes` | 6,439,257,816,158 B (5.856 TiB) |

## Provenance

| Property | Bound value |
| --- | --- |
| Build / SEAL / SHA-256 acceleration | `Release` / `intel-hexl-runtime-dispatch` / `openssl` |
| Host | `INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz`; 392,855,961,600 B (365.876 GiB) RAM |
| Pinned CPUs | setup `0,1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23`; server `0`; client `1`; observer excluded from measured role CPU |
| Threading | setup: `23` worker(s); server and client: `single-cpu-process` |

| Property | Recorded value |
| --- | --- |
| Backend | `shared-root-filesystem` |
| Artifact root | `/var/lib/laminate-storage/laminate-bench` |
| Mount | `/dev/nvme0n1p1` on `/` |
| Filesystem | `ext4` (`rw,relatime,discard,errors=remount-ro,commit=30`) |
| Filesystem capacity | 10,414,378,115,072 B (9.472 TiB) |
| Shared storage directory | `/var/lib/laminate-storage` |
| Shares OS filesystem and I/O | **true — benchmark artifacts and the operating system share the root filesystem and I/O path.** |
| Available at setup start | 10,390,707,974,144 B (9.450 TiB) at `2026-10-12T14:31:08Z` |
| Available at server start | 10,277,647,159,296 B (9.347 TiB) at `2026-10-12T18:49:11Z` |
