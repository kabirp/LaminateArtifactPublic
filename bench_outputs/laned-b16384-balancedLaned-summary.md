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
| Lanes | 16,384 |
| Scalar gates | 17,179,869,184 (1,048,576 payload gates × 16,384 lanes) |
| Initial ciphertext modulus (data primes only) | 577 bits across 14 limbs |
| Plaintext modulus | 65,537 |
| VCoED server wall time | 54 h 29 m 40.580 s |
| ↳ Payload computation | 4 h 54 m 21.836 s |
| ↳ Witness packing | 0.000 s |
| ↳ GKR proving | 39 h 21 m 58.808 s |
| ↳ Transcript packing | 10 h 13 m 12.898 s |
| Per-request client computation | 2.387 s |
| Input encryption | 0.753 s |
| Output decryption | 0.001 s |
| VCoED proof verification | 1.634 s |
| ↳ GKR proof verification | 0.831 s |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.235 s |
| ↳↳ Plaintext GKR and affine gate-opening checks | 0.596 s |
| ↳ Terminal input MLE | 0.039 s |
| ↳ Spartan packing argument | 0.748 s |
| ↳ Well-formedness noise checks | 0.017 s |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | `LaminateImpl/ConservativePackedProofIngress/v3`; limbs by layer `1,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4,6,4` |

## Server layer reductions and sumcheck round details

| Role | Span | Wall | CPU |
| --- | --- | --- | --- |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_0` | 35.322 s | 35.313 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_1` | 2 m 18.690 s | 2 m 18.682 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_2` | 2 m 12.706 s | 2 m 12.699 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_3` | 2 m 15.644 s | 2 m 15.637 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_4` | 2 m 12.903 s | 2 m 12.896 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_5` | 2 m 31.851 s | 2 m 31.842 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_6` | 2 m 9.854 s | 2 m 9.847 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_7` | 2 m 9.961 s | 2 m 9.954 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_8` | 2 m 36.200 s | 2 m 36.191 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_9` | 2 m 19.077 s | 2 m 19.069 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_10` | 2 m 10.478 s | 2 m 10.471 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_11` | 2 m 10.379 s | 2 m 10.372 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_12` | 2 m 11.501 s | 2 m 11.494 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_13` | 2 m 14.235 s | 2 m 14.228 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_14` | 2 m 18.082 s | 2 m 18.074 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_15` | 2 m 29.137 s | 2 m 29.129 s |
| server | `laned.affine.slot_checkpoint.reduction_0.source_1.checkpoint_1.slot_index` | 1 m 34.155 s | 1 m 34.150 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_16` | 0.888 s | 0.887 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_17` | 0.943 s | 0.943 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_18` | 0.980 s | 0.980 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_19` | 1.016 s | 1.016 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_20` | 1.040 s | 1.040 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_21` | 1.076 s | 1.076 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_22` | 1.099 s | 1.099 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_23` | 1.127 s | 1.127 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_24` | 1.152 s | 1.152 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_25` | 1.181 s | 1.181 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_26` | 1.208 s | 1.208 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_27` | 1.237 s | 1.237 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_28` | 1.263 s | 1.263 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_29` | 1.294 s | 1.294 s |
| server | `laned.reduction.reduction_0.source_1` | 38 m 56.259 s | 38 m 52.634 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_0` | 6 m 29.275 s | 6 m 29.251 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_1` | 52 m 30.408 s | 52 m 30.200 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_2` | 29 m 54.333 s | 29 m 54.212 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_3` | 18 m 53.635 s | 18 m 53.559 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_4` | 13 m 20.229 s | 13 m 20.085 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_5` | 10 m 32.058 s | 10 m 32.018 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_6` | 9 m 4.344 s | 9 m 4.310 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_7` | 8 m 24.582 s | 8 m 24.552 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_8` | 8 m 0.905 s | 8 m 0.876 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_9` | 7 m 49.637 s | 7 m 49.610 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_10` | 7 m 37.303 s | 7 m 37.276 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_11` | 7 m 34.259 s | 7 m 34.232 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_12` | 7 m 31.470 s | 7 m 31.444 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_13` | 7 m 32.058 s | 7 m 32.031 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_14` | 7 m 32.057 s | 7 m 32.031 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_15` | 7 m 31.760 s | 7 m 31.733 s |
| server | `laned.multiplication.slot_checkpoint.reduction_1.source_2.checkpoint_2.slot_index` | 5 m 17.599 s | 5 m 17.579 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_16` | 2.000 s | 2.000 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_17` | 2.177 s | 2.176 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_18` | 2.304 s | 2.304 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_19` | 2.417 s | 2.417 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_20` | 2.522 s | 2.522 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_21` | 2.617 s | 2.617 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_22` | 2.715 s | 2.715 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_23` | 2.807 s | 2.807 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_24` | 2.909 s | 2.909 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_25` | 2.998 s | 2.997 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_26` | 3.102 s | 3.102 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_27` | 3.201 s | 3.201 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_28` | 3.305 s | 3.304 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_29` | 3.243 s | 3.243 s |
| server | `laned.reduction.reduction_1.source_2` | 3 h 53 m 0.029 s | 3 h 50 m 55.446 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_0` | 2 m 17.480 s | 2 m 17.463 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_1` | 2 m 14.890 s | 2 m 14.879 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_2` | 2 m 14.258 s | 2 m 14.250 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_3` | 2 m 12.948 s | 2 m 12.941 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_4` | 2 m 13.764 s | 2 m 13.756 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_5` | 2 m 17.676 s | 2 m 17.669 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_6` | 2 m 18.460 s | 2 m 18.452 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_7` | 2 m 17.036 s | 2 m 17.029 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_8` | 2 m 16.888 s | 2 m 16.880 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_9` | 2 m 22.707 s | 2 m 22.699 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_10` | 2 m 15.604 s | 2 m 15.597 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_11` | 2 m 17.209 s | 2 m 17.201 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_12` | 2 m 16.523 s | 2 m 16.515 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_13` | 2 m 13.347 s | 2 m 13.340 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_14` | 2 m 16.140 s | 2 m 16.132 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_15` | 2 m 14.356 s | 2 m 14.348 s |
| server | `laned.affine.slot_checkpoint.reduction_2.source_3.checkpoint_3.slot_index` | 1 m 37.182 s | 1 m 37.176 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_16` | 0.978 s | 0.978 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_17` | 1.046 s | 1.046 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_18` | 1.090 s | 1.090 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_19` | 1.131 s | 1.131 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_20` | 1.161 s | 1.161 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_21` | 1.192 s | 1.191 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_22` | 1.216 s | 1.216 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_23` | 1.245 s | 1.245 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_24` | 1.271 s | 1.271 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_25` | 1.300 s | 1.300 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_26` | 1.325 s | 1.325 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_27` | 1.355 s | 1.355 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_28` | 1.384 s | 1.384 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_29` | 1.415 s | 1.415 s |
| server | `laned.reduction.reduction_2.source_3` | 44 m 8.699 s | 43 m 56.490 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_0` | 6 m 26.345 s | 6 m 26.321 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_1` | 51 m 41.015 s | 51 m 40.812 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_2` | 29 m 50.751 s | 29 m 50.633 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_3` | 18 m 49.695 s | 18 m 49.621 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_4` | 13 m 16.668 s | 13 m 16.618 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_5` | 10 m 28.861 s | 10 m 28.822 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_6` | 9 m 5.134 s | 9 m 5.101 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_7` | 8 m 19.095 s | 8 m 19.066 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_8` | 8 m 2.472 s | 8 m 2.445 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_9` | 7 m 44.009 s | 7 m 43.982 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_10` | 7 m 40.968 s | 7 m 40.942 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_11` | 7 m 34.807 s | 7 m 34.781 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_12` | 7 m 41.006 s | 7 m 40.980 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_13` | 7 m 38.808 s | 7 m 38.781 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_14` | 7 m 32.800 s | 7 m 32.774 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_15` | 7 m 30.494 s | 7 m 30.468 s |
| server | `laned.multiplication.slot_checkpoint.reduction_3.source_4.checkpoint_4.slot_index` | 5 m 26.611 s | 5 m 26.591 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_16` | 1.980 s | 1.980 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_17` | 2.168 s | 2.168 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_18` | 2.289 s | 2.288 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_19` | 2.392 s | 2.392 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_20` | 2.500 s | 2.500 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_21` | 2.595 s | 2.595 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_22` | 2.701 s | 2.701 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_23` | 2.791 s | 2.791 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_24` | 2.901 s | 2.901 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_25` | 2.982 s | 2.982 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_26` | 3.082 s | 3.081 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_27` | 3.172 s | 3.171 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_28` | 3.275 s | 3.274 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_29` | 3.216 s | 3.215 s |
| server | `laned.reduction.reduction_3.source_4` | 3 h 56 m 38.301 s | 3 h 54 m 22.602 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_0` | 2 m 12.333 s | 2 m 12.317 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_1` | 2 m 14.204 s | 2 m 14.192 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_2` | 2 m 15.381 s | 2 m 15.374 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_3` | 2 m 27.137 s | 2 m 27.129 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_4` | 2 m 14.975 s | 2 m 14.967 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_5` | 2 m 11.389 s | 2 m 11.382 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_6` | 2 m 13.548 s | 2 m 13.540 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_7` | 2 m 10.248 s | 2 m 10.240 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_8` | 2 m 16.792 s | 2 m 16.785 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_9` | 2 m 12.406 s | 2 m 12.399 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_10` | 2 m 14.647 s | 2 m 14.639 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_11` | 2 m 18.555 s | 2 m 18.548 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_12` | 2 m 18.512 s | 2 m 18.504 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_13` | 2 m 13.576 s | 2 m 13.568 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_14` | 2 m 15.031 s | 2 m 15.023 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_15` | 2 m 13.433 s | 2 m 13.425 s |
| server | `laned.affine.slot_checkpoint.reduction_4.source_5.checkpoint_5.slot_index` | 1 m 35.094 s | 1 m 35.088 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_16` | 0.979 s | 0.979 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_17` | 1.050 s | 1.050 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_18` | 1.092 s | 1.092 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_19` | 1.132 s | 1.132 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_20` | 1.154 s | 1.154 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_21` | 1.187 s | 1.187 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_22` | 1.216 s | 1.216 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_23` | 1.245 s | 1.245 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_24` | 1.272 s | 1.272 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_25` | 1.301 s | 1.301 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_26` | 1.329 s | 1.329 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_27` | 1.357 s | 1.357 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_28` | 1.379 s | 1.379 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_29` | 1.413 s | 1.412 s |
| server | `laned.reduction.reduction_4.source_5` | 45 m 49.429 s | 45 m 35.114 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_0` | 6 m 26.931 s | 6 m 26.906 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_1` | 51 m 47.201 s | 51 m 46.989 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_2` | 29 m 53.938 s | 29 m 53.816 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_3` | 18 m 53.240 s | 18 m 53.164 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_4` | 13 m 20.014 s | 13 m 19.964 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_5` | 10 m 32.938 s | 10 m 32.898 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_6` | 9 m 4.814 s | 9 m 4.781 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_7` | 8 m 22.448 s | 8 m 22.418 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_8` | 8 m 11.394 s | 8 m 11.366 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_9` | 7 m 48.168 s | 7 m 48.142 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_10` | 7 m 42.559 s | 7 m 42.533 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_11` | 7 m 38.608 s | 7 m 38.581 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_12` | 7 m 35.090 s | 7 m 35.064 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_13` | 7 m 36.897 s | 7 m 36.870 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_14` | 7 m 34.406 s | 7 m 34.380 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_15` | 7 m 34.632 s | 7 m 34.606 s |
| server | `laned.multiplication.slot_checkpoint.reduction_5.source_6.checkpoint_6.slot_index` | 5 m 21.426 s | 5 m 21.408 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_16` | 1.993 s | 1.993 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_17` | 2.176 s | 2.175 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_18` | 2.306 s | 2.306 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_19` | 2.407 s | 2.407 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_20` | 2.508 s | 2.508 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_21` | 2.620 s | 2.620 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_22` | 2.707 s | 2.707 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_23` | 2.798 s | 2.798 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_24` | 2.905 s | 2.905 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_25` | 2.999 s | 2.999 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_26` | 3.105 s | 3.105 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_27` | 3.196 s | 3.196 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_28` | 3.291 s | 3.291 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_29` | 3.221 s | 3.221 s |
| server | `laned.reduction.reduction_5.source_6` | 4 h 1 m 2.634 s | 3 h 59 m 2.209 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_0` | 2 m 11.236 s | 2 m 11.218 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_1` | 2 m 12.681 s | 2 m 12.671 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_2` | 2 m 17.476 s | 2 m 17.468 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_3` | 2 m 18.679 s | 2 m 18.671 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_4` | 2 m 11.715 s | 2 m 11.708 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_5` | 2 m 12.921 s | 2 m 12.914 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_6` | 2 m 17.017 s | 2 m 17.010 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_7` | 2 m 12.851 s | 2 m 12.843 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_8` | 2 m 12.490 s | 2 m 12.482 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_9` | 2 m 10.795 s | 2 m 10.787 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_10` | 2 m 11.763 s | 2 m 11.756 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_11` | 2 m 13.217 s | 2 m 13.209 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_12` | 2 m 13.936 s | 2 m 13.928 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_13` | 2 m 14.152 s | 2 m 14.145 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_14` | 2 m 17.493 s | 2 m 17.485 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_15` | 2 m 12.351 s | 2 m 12.343 s |
| server | `laned.affine.slot_checkpoint.reduction_6.source_7.checkpoint_7.slot_index` | 1 m 33.587 s | 1 m 33.581 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_16` | 0.982 s | 0.981 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_17` | 1.058 s | 1.057 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_18` | 1.100 s | 1.100 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_19` | 1.141 s | 1.141 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_20` | 1.166 s | 1.166 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_21` | 1.196 s | 1.196 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_22` | 1.224 s | 1.224 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_23` | 1.256 s | 1.256 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_24` | 1.276 s | 1.276 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_25` | 1.309 s | 1.308 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_26` | 1.334 s | 1.334 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_27` | 1.365 s | 1.365 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_28` | 1.391 s | 1.391 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_29` | 1.418 s | 1.417 s |
| server | `laned.reduction.reduction_6.source_7` | 47 m 32.084 s | 47 m 22.906 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_0` | 6 m 26.145 s | 6 m 26.120 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_1` | 52 m 9.392 s | 52 m 9.176 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_2` | 29 m 58.761 s | 29 m 58.645 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_3` | 18 m 55.934 s | 18 m 55.860 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_4` | 13 m 22.997 s | 13 m 22.945 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_5` | 10 m 33.237 s | 10 m 33.198 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_6` | 9 m 7.987 s | 9 m 7.954 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_7` | 8 m 24.523 s | 8 m 24.493 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_8` | 8 m 6.038 s | 8 m 6.010 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_9` | 7 m 49.805 s | 7 m 49.778 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_10` | 7 m 42.517 s | 7 m 42.490 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_11` | 7 m 41.167 s | 7 m 41.140 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_12` | 7 m 40.749 s | 7 m 40.722 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_13` | 7 m 38.052 s | 7 m 38.025 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_14` | 7 m 36.613 s | 7 m 36.587 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_15` | 7 m 36.483 s | 7 m 36.456 s |
| server | `laned.multiplication.slot_checkpoint.reduction_7.source_8.checkpoint_8.slot_index` | 5 m 23.631 s | 5 m 23.612 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_16` | 2.002 s | 2.002 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_17` | 2.186 s | 2.185 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_18` | 2.310 s | 2.310 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_19` | 2.412 s | 2.412 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_20` | 2.528 s | 2.528 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_21` | 2.618 s | 2.617 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_22` | 2.706 s | 2.706 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_23` | 2.799 s | 2.799 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_24` | 2.900 s | 2.900 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_25` | 3.007 s | 3.007 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_26` | 3.103 s | 3.103 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_27` | 3.202 s | 3.202 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_28` | 3.302 s | 3.302 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_29` | 3.240 s | 3.239 s |
| server | `laned.reduction.reduction_7.source_8` | 4 h 6 m 28.814 s | 4 h 4 m 20.109 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_0` | 2 m 15.204 s | 2 m 15.184 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_1` | 2 m 16.015 s | 2 m 16.006 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_2` | 2 m 13.056 s | 2 m 13.049 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_3` | 2 m 14.910 s | 2 m 14.903 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_4` | 2 m 12.566 s | 2 m 12.559 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_5` | 2 m 11.843 s | 2 m 11.835 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_6` | 2 m 19.647 s | 2 m 19.639 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_7` | 2 m 9.014 s | 2 m 9.007 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_8` | 2 m 11.537 s | 2 m 11.530 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_9` | 2 m 14.045 s | 2 m 14.037 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_10` | 2 m 10.377 s | 2 m 10.369 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_11` | 2 m 16.324 s | 2 m 16.317 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_12` | 2 m 11.569 s | 2 m 11.562 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_13` | 2 m 12.203 s | 2 m 12.196 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_14` | 2 m 12.828 s | 2 m 12.820 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_15` | 2 m 8.712 s | 2 m 8.704 s |
| server | `laned.affine.slot_checkpoint.reduction_8.source_9.checkpoint_9.slot_index` | 1 m 34.790 s | 1 m 34.784 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_16` | 0.974 s | 0.974 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_17` | 1.050 s | 1.050 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_18` | 1.097 s | 1.097 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_19` | 1.137 s | 1.137 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_20` | 1.164 s | 1.164 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_21` | 1.196 s | 1.195 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_22` | 1.219 s | 1.219 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_23` | 1.251 s | 1.251 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_24` | 1.272 s | 1.271 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_25` | 1.302 s | 1.302 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_26` | 1.330 s | 1.330 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_27` | 1.358 s | 1.358 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_28` | 1.384 s | 1.383 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_29` | 1.416 s | 1.415 s |
| server | `laned.reduction.reduction_8.source_9` | 49 m 48.357 s | 49 m 37.032 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_0` | 6 m 24.503 s | 6 m 24.478 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_1` | 51 m 49.472 s | 51 m 49.258 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_2` | 29 m 53.756 s | 29 m 53.633 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_3` | 18 m 55.042 s | 18 m 54.966 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_4` | 13 m 22.000 s | 13 m 21.947 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_5` | 10 m 31.255 s | 10 m 31.215 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_6` | 9 m 7.331 s | 9 m 7.296 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_7` | 8 m 23.308 s | 8 m 23.278 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_8` | 8 m 2.859 s | 8 m 2.831 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_9` | 7 m 49.953 s | 7 m 49.925 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_10` | 7 m 44.074 s | 7 m 44.047 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_11` | 7 m 40.221 s | 7 m 40.193 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_12` | 7 m 40.222 s | 7 m 40.194 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_13` | 7 m 37.968 s | 7 m 37.941 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_14` | 7 m 38.596 s | 7 m 38.569 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_15` | 7 m 36.926 s | 7 m 36.899 s |
| server | `laned.multiplication.slot_checkpoint.reduction_9.source_10.checkpoint_10.slot_index` | 5 m 21.477 s | 5 m 21.457 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_16` | 1.984 s | 1.984 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_17` | 2.170 s | 2.170 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_18` | 2.305 s | 2.305 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_19` | 2.410 s | 2.410 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_20` | 2.522 s | 2.522 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_21` | 2.606 s | 2.606 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_22` | 2.726 s | 2.726 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_23` | 2.796 s | 2.796 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_24` | 2.900 s | 2.900 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_25` | 2.988 s | 2.988 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_26` | 3.093 s | 3.093 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_27` | 3.199 s | 3.199 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_28` | 3.331 s | 3.331 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_29` | 3.247 s | 3.247 s |
| server | `laned.reduction.reduction_9.source_10` | 4 h 11 m 1.192 s | 4 h 8 m 42.977 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_0` | 2 m 11.564 s | 2 m 11.548 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_1` | 2 m 11.595 s | 2 m 11.587 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_2` | 2 m 12.850 s | 2 m 12.842 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_3` | 2 m 14.593 s | 2 m 14.586 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_4` | 2 m 11.348 s | 2 m 11.341 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_5` | 2 m 14.473 s | 2 m 14.466 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_6` | 2 m 13.084 s | 2 m 13.076 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_7` | 2 m 14.554 s | 2 m 14.547 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_8` | 2 m 23.910 s | 2 m 23.902 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_9` | 2 m 13.940 s | 2 m 13.932 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_10` | 2 m 15.295 s | 2 m 15.287 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_11` | 2 m 14.713 s | 2 m 14.705 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_12` | 2 m 13.693 s | 2 m 13.686 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_13` | 2 m 13.691 s | 2 m 13.683 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_14` | 2 m 12.165 s | 2 m 12.157 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_15` | 2 m 14.322 s | 2 m 14.314 s |
| server | `laned.affine.slot_checkpoint.reduction_10.source_11.checkpoint_11.slot_index` | 1 m 31.758 s | 1 m 31.752 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_16` | 0.979 s | 0.979 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_17` | 1.048 s | 1.048 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_18` | 1.091 s | 1.091 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_19` | 1.132 s | 1.132 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_20` | 1.164 s | 1.164 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_21` | 1.193 s | 1.193 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_22` | 1.217 s | 1.217 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_23` | 1.247 s | 1.246 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_24` | 1.290 s | 1.290 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_25` | 1.298 s | 1.298 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_26` | 1.323 s | 1.323 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_27` | 1.355 s | 1.354 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_28` | 1.385 s | 1.384 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_29` | 1.424 s | 1.424 s |
| server | `laned.reduction.reduction_10.source_11` | 52 m 35.520 s | 52 m 26.790 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_0` | 6 m 24.120 s | 6 m 24.091 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_1` | 51 m 48.406 s | 51 m 48.191 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_2` | 29 m 49.341 s | 29 m 49.221 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_3` | 18 m 50.854 s | 18 m 50.777 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_4` | 13 m 18.514 s | 13 m 18.462 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_5` | 10 m 32.683 s | 10 m 32.642 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_6` | 9 m 8.421 s | 9 m 8.387 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_7` | 8 m 29.350 s | 8 m 29.319 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_8` | 8 m 5.517 s | 8 m 5.488 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_9` | 7 m 49.092 s | 7 m 49.065 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_10` | 7 m 41.197 s | 7 m 41.170 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_11` | 7 m 39.421 s | 7 m 39.393 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_12` | 7 m 36.229 s | 7 m 36.203 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_13` | 7 m 35.681 s | 7 m 35.655 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_14` | 7 m 36.175 s | 7 m 36.148 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_15` | 7 m 34.873 s | 7 m 34.847 s |
| server | `laned.multiplication.slot_checkpoint.reduction_11.source_12.checkpoint_12.slot_index` | 5 m 20.954 s | 5 m 20.934 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_16` | 1.975 s | 1.974 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_17` | 2.176 s | 2.176 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_18` | 2.296 s | 2.295 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_19` | 2.399 s | 2.399 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_20` | 2.508 s | 2.507 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_21` | 2.606 s | 2.606 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_22` | 2.705 s | 2.704 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_23` | 2.793 s | 2.792 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_24` | 2.896 s | 2.895 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_25` | 2.988 s | 2.988 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_26` | 3.085 s | 3.085 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_27` | 3.176 s | 3.176 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_28` | 3.280 s | 3.279 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_29` | 3.220 s | 3.220 s |
| server | `laned.reduction.reduction_11.source_12` | 4 h 15 m 16.790 s | 4 h 13 m 33.244 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_0` | 2 m 11.650 s | 2 m 11.634 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_1` | 2 m 16.048 s | 2 m 16.040 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_2` | 2 m 9.416 s | 2 m 9.408 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_3` | 2 m 15.981 s | 2 m 15.972 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_4` | 2 m 15.052 s | 2 m 15.044 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_5` | 2 m 18.444 s | 2 m 18.435 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_6` | 2 m 13.695 s | 2 m 13.686 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_7` | 2 m 12.028 s | 2 m 12.019 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_8` | 2 m 12.458 s | 2 m 12.451 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_9` | 2 m 12.800 s | 2 m 12.793 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_10` | 2 m 15.496 s | 2 m 15.488 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_11` | 2 m 12.971 s | 2 m 12.964 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_12` | 2 m 15.139 s | 2 m 15.130 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_13` | 2 m 12.764 s | 2 m 12.756 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_14` | 2 m 13.127 s | 2 m 13.119 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_15` | 2 m 9.235 s | 2 m 9.227 s |
| server | `laned.affine.slot_checkpoint.reduction_12.source_13.checkpoint_13.slot_index` | 1 m 38.546 s | 1 m 38.540 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_16` | 0.972 s | 0.972 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_17` | 1.049 s | 1.049 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_18` | 1.093 s | 1.093 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_19` | 1.136 s | 1.135 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_20` | 1.158 s | 1.158 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_21` | 1.190 s | 1.189 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_22` | 1.217 s | 1.217 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_23` | 1.248 s | 1.248 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_24` | 1.271 s | 1.271 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_25` | 1.301 s | 1.301 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_26` | 1.328 s | 1.328 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_27` | 1.354 s | 1.354 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_28` | 1.380 s | 1.380 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_29` | 1.410 s | 1.410 s |
| server | `laned.reduction.reduction_12.source_13` | 55 m 11.354 s | 55 m 7.711 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_0` | 6 m 19.285 s | 6 m 19.261 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_1` | 51 m 34.265 s | 51 m 34.055 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_2` | 29 m 48.909 s | 29 m 48.793 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_3` | 18 m 51.711 s | 18 m 51.639 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_4` | 13 m 22.600 s | 13 m 22.548 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_5` | 10 m 34.197 s | 10 m 34.159 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_6` | 9 m 9.942 s | 9 m 9.911 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_7` | 8 m 26.342 s | 8 m 26.313 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_8` | 8 m 4.120 s | 8 m 4.093 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_9` | 7 m 51.993 s | 7 m 51.966 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_10` | 7 m 46.054 s | 7 m 46.028 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_11` | 7 m 42.600 s | 7 m 42.573 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_12` | 7 m 41.280 s | 7 m 41.254 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_13` | 7 m 40.184 s | 7 m 40.157 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_14` | 7 m 39.161 s | 7 m 39.135 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_15` | 7 m 39.739 s | 7 m 39.713 s |
| server | `laned.multiplication.slot_checkpoint.reduction_13.source_14.checkpoint_14.slot_index` | 5 m 19.109 s | 5 m 19.090 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_16` | 1.960 s | 1.960 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_17` | 2.163 s | 2.163 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_18` | 2.293 s | 2.293 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_19` | 2.401 s | 2.401 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_20` | 2.506 s | 2.506 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_21` | 2.596 s | 2.596 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_22` | 2.701 s | 2.700 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_23` | 2.792 s | 2.792 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_24` | 2.888 s | 2.888 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_25` | 2.980 s | 2.980 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_26` | 3.082 s | 3.082 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_27` | 3.180 s | 3.180 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_28` | 3.271 s | 3.271 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_29` | 3.207 s | 3.207 s |
| server | `laned.reduction.reduction_13.source_14` | 4 h 20 m 50.267 s | 4 h 19 m 22.507 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_0` | 2 m 12.919 s | 2 m 12.905 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_1` | 2 m 11.474 s | 2 m 11.467 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_2` | 2 m 13.936 s | 2 m 13.928 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_3` | 2 m 15.961 s | 2 m 15.954 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_4` | 2 m 11.158 s | 2 m 11.150 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_5` | 2 m 14.600 s | 2 m 14.592 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_6` | 2 m 13.278 s | 2 m 13.270 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_7` | 2 m 11.547 s | 2 m 11.539 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_8` | 2 m 13.389 s | 2 m 13.382 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_9` | 2 m 11.421 s | 2 m 11.413 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_10` | 2 m 13.513 s | 2 m 13.506 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_11` | 2 m 12.176 s | 2 m 12.168 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_12` | 2 m 12.858 s | 2 m 12.850 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_13` | 2 m 12.816 s | 2 m 12.808 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_14` | 2 m 13.574 s | 2 m 13.567 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_15` | 2 m 16.173 s | 2 m 16.165 s |
| server | `laned.affine.slot_checkpoint.reduction_14.source_15.checkpoint_15.slot_index` | 1 m 33.886 s | 1 m 33.880 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_16` | 0.979 s | 0.979 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_17` | 1.051 s | 1.051 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_18` | 1.091 s | 1.091 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_19` | 1.134 s | 1.133 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_20` | 1.162 s | 1.162 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_21` | 1.194 s | 1.194 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_22` | 1.214 s | 1.214 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_23` | 1.245 s | 1.245 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_24` | 1.275 s | 1.275 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_25` | 1.304 s | 1.304 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_26` | 1.325 s | 1.325 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_27` | 1.361 s | 1.361 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_28` | 1.383 s | 1.383 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_29` | 1.410 s | 1.410 s |
| server | `laned.reduction.reduction_14.source_15` | 58 m 7.769 s | 57 m 59.866 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_0` | 5 m 51.400 s | 5 m 51.373 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_1` | 51 m 55.478 s | 51 m 55.258 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_2` | 30 m 4.721 s | 30 m 4.598 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_3` | 19 m 4.178 s | 19 m 4.101 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_4` | 13 m 29.069 s | 13 m 29.015 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_5` | 10 m 34.815 s | 10 m 34.773 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_6` | 9 m 8.377 s | 9 m 8.340 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_7` | 8 m 24.105 s | 8 m 24.072 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_8` | 8 m 2.741 s | 8 m 2.710 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_9` | 7 m 50.565 s | 7 m 50.535 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_10` | 7 m 44.314 s | 7 m 44.283 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_11` | 7 m 41.689 s | 7 m 41.657 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_12` | 7 m 39.969 s | 7 m 39.941 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_13` | 7 m 40.117 s | 7 m 40.088 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_14` | 7 m 39.120 s | 7 m 39.091 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_15` | 7 m 40.912 s | 7 m 40.882 s |
| server | `laned.multiplication.slot_checkpoint.reduction_15.source_16.checkpoint_16.slot_index` | 5 m 23.930 s | 5 m 23.910 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_16` | 1.958 s | 1.957 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_17` | 2.163 s | 2.163 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_18` | 2.292 s | 2.292 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_19` | 2.401 s | 2.401 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_20` | 2.504 s | 2.504 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_21` | 2.597 s | 2.597 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_22` | 2.714 s | 2.714 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_23` | 2.880 s | 2.879 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_24` | 2.913 s | 2.913 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_25` | 3.006 s | 3.006 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_26` | 3.093 s | 3.093 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_27` | 3.207 s | 3.206 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_28` | 3.279 s | 3.279 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_29` | 3.228 s | 3.227 s |
| server | `laned.reduction.reduction_15.source_16` | 3 h 59 m 5.903 s | 3 h 58 m 45.790 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_0` | 2.044 s | 2.044 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_1` | 2.029 s | 2.029 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_2` | 2.030 s | 2.030 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_3` | 2.033 s | 2.032 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_4` | 2.031 s | 2.031 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_5` | 2.035 s | 2.034 s |
| server | `laned.affine.slot_checkpoint.reduction_16.source_17.checkpoint_17.slot_index` | 0.796 s | 0.796 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_6` | 0.983 s | 0.983 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_7` | 1.044 s | 1.044 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_8` | 1.089 s | 1.089 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_9` | 1.127 s | 1.127 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_10` | 1.159 s | 1.159 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_11` | 1.188 s | 1.188 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_12` | 1.213 s | 1.213 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_13` | 1.246 s | 1.246 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_14` | 1.268 s | 1.268 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_15` | 1.304 s | 1.304 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_16` | 1.321 s | 1.321 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_17` | 1.352 s | 1.352 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_18` | 1.380 s | 1.380 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_19` | 1.410 s | 1.410 s |
| server | `laned.reduction.reduction_16.source_17` | 32.696 s | 32.689 s |
| server | `laned.gate_mle_opening` | 5 m 52.680 s | 5 m 52.637 s |

## Client computation

| Component | Wall | CPU |
|---|---:|---:|
| Per-request client computation | 2.387 s | 2.387 s |
| Input encryption | 0.753 s | 0.753 s |
| Output decryption | 0.001 s | 0.001 s |
| VCoED proof verification | 1.634 s | 1.634 s |
| ↳ GKR proof verification | 0.831 s | 0.831 s |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.235 s | 0.235 s |
| ↳↳ Plaintext GKR and affine gate-opening checks | 0.596 s | 0.596 s |
| ↳ Terminal input MLE | 0.039 s | 0.039 s |
| ↳ Spartan packing argument | 0.748 s | 0.747 s |
| ↳ Well-formedness noise checks | 0.017 s | 0.017 s |

Client computation is input encryption + output decryption + VCoED proof verification. Preprocessing RAM loading, transport, peer waiting, and the optional output-noise audit are excluded. Verification rows form a hierarchy: add siblings only. Packed transcript recovery includes signed-digit recomposition into logical plaintexts.

## Client verifier details

Transcript-packing verification and message recovery: **0.666 s wall**. Gate-MLE opening: **0.589 s wall**. These are nested diagnostic spans; they do not define the disjoint computation hierarchy above.

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
| client | `transcript_packing.verifier_statement` | 0.022 s | 0.022 s |
| client | `transcript_packing.spartan_verify` | 0.624 s | 0.624 s |
| client | `transcript_packing.threshold_checks` | 0.017 s | 0.017 s |
| client | `transcript_packing.unpack` | 0.002 s | 0.002 s |

## Server FHE operation ledger

| Server stage | Operation | Calls | Limb operations | Calls by RNS limbs |
| --- | --- | --- | --- | --- |
| `server_payload_evaluation` | `add` | 608,570 | 6,427,419 | `5:65535,7:53676,8:53718,9:53652,10:53650,11:53652,12:53604,13:53682,14:167401` |
| `server_payload_evaluation` | `add_plain` | 52,429 | 550,512 | `7:6553,8:6553,9:6553,10:6554,11:6554,12:6554,13:6554,14:6554` |
| `server_payload_evaluation` | `decrypt` | 0 | 0 | `none` |
| `server_payload_evaluation` | `encrypt` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_add` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_mul` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_mul_plain` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_sub` | 0 | 0 | `none` |
| `server_payload_evaluation` | `mod_switch` | 589,828 | 5,898,254 | `2:1,3:1,4:1,5:1,6:65536,7:65536,8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536` |
| `server_payload_evaluation` | `mul_no_relin` | 524,288 | 5,505,024 | `7:65536,8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536` |
| `server_payload_evaluation` | `mul_plain_scalar` | 0 | 0 | `none` |
| `server_payload_evaluation` | `mul_plain_vector` | 0 | 0 | `none` |
| `server_payload_evaluation` | `negate` | 0 | 0 | `none` |
| `server_payload_evaluation` | `relinearize` | 524,288 | 5,505,024 | `7:65536,8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536` |
| `server_payload_evaluation` | `rotate` | 0 | 0 | `none` |
| `server_payload_evaluation` | `sub` | 0 | 0 | `none` |
| `server_proving` | `add` | 368,163,071 | 2,000,241,661 | `1:33039,4:104285785,6:263844247` |
| `server_proving` | `add_plain` | 7 | 42 | `6:7` |
| `server_proving` | `decrypt` | 0 | 0 | `none` |
| `server_proving` | `encrypt` | 0 | 0 | `none` |
| `server_proving` | `logical_ext_add` | 526,882 | 3,159,402 | `4:945,6:525937` |
| `server_proving` | `logical_ext_mul` | 524,496 | 3,146,976 | `6:524496` |
| `server_proving` | `logical_ext_mul_plain` | 525,618 | 3,152,424 | `4:642,6:524976` |
| `server_proving` | `logical_ext_sub` | 350 | 1,848 | `4:126,6:224` |
| `server_proving` | `mod_switch` | 6,720,659 | 57,690,727 | `2:517,3:517,4:517,5:524600,6:459064,7:1376385,8:1187970,9:999555,10:811140,11:622724,12:434307,13:245890,14:57473` |
| `server_proving` | `mul_no_relin` | 34,091,920 | 204,551,520 | `6:34091920` |
| `server_proving` | `mul_plain_scalar` | 339,007,727 | 1,825,778,868 | `4:104133747,6:234873980` |
| `server_proving` | `mul_plain_vector` | 98,956 | 485,876 | `1:2068,4:48760,6:48128` |
| `server_proving` | `negate` | 7,376,744 | 44,163,297 | `1:15519,4:9786,6:7351439` |
| `server_proving` | `relinearize` | 3,840 | 23,040 | `6:3840` |
| `server_proving` | `rotate` | 136,320 | 683,581 | `3:48,4:67082,5:31,6:69159` |
| `server_proving` | `sub` | 527,088 | 3,160,512 | `4:1008,6:526080` |

## Protocol artifacts

| Quantity | Measured value |
| --- | --- |
| Proving key / server preprocessing | 11,208,303,793 B (10.439 GiB) |
| Verifying key / client preprocessing | 112,139,063 B (106.944 MiB) |
| `server.wire.request_bytes` | 234,892,692 B (224.011 MiB) |
| `server.wire.response_bytes` | 91,755,557 B (87.505 MiB) |
| `client.wire.request_bytes` | 234,892,692 B (224.011 MiB) |
| `client.wire.response_bytes` | 91,755,557 B (87.505 MiB) |
| `server.proof.canonical.committed_gkr_bytes` | 44,390,154 B (42.334 MiB) |
| `server.proof.canonical.digit_packing_ciphertext_bytes` | 1,049,064 B (1.000 MiB) |
| `server.proof.canonical.spartan_packing_proof_bytes` | 14,581,797 B (13.906 MiB) |
| `server.proof.canonical.statement_and_metadata_bytes` | 46 B |
| `server.proof.canonical.total_bytes` | 91,492,981 B (87.255 MiB) |
| `server.proof.canonical.well_formedness_reveal_bytes` | 31,471,920 B (30.014 MiB) |
| `server.proof.committed_gkr.commitment_digest_bytes` | 24,816 B (24.234 KiB) |
| `server.proof.committed_gkr.gate_mle_opening_bytes` | 44,364,476 B (42.309 MiB) |
| `server.proof.response.total_bytes` | 91,755,557 B (87.505 MiB) |

## Memory and storage

| Quantity | Measured value |
| --- | --- |
| `setup.memory.client.admitted_peak_resident_bytes` | 3,863,766,830 B (3.598 GiB) |
| `setup.memory.concurrent.admitted_peak_resident_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.host_budget.exact_client_peak_resident_bytes` | 3,863,766,830 B (3.598 GiB) |
| `setup.memory.host_budget.exact_server_resident_cap_bytes` | 308,992,194,770 B (287.771 GiB) |
| `setup.memory.host_budget.gross_resident_budget_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.host_budget.operating_system_reserve_bytes` | 16,000,000,000 B (14.901 GiB) |
| `setup.memory.host_budget.page_cache_reserve_bytes` | 64,000,000,000 B (59.605 GiB) |
| `setup.memory.payload_storage.prefetch_page_cache_budget_bytes` | 536,870,912 B (512.000 MiB) |
| `setup.memory.payload_storage.transfer_buffer_reserve_bytes` | 402,653,184 B (384.000 MiB) |
| `setup.memory.payload_storage.writeback_window_bytes` | 0 B |
| `setup.memory.planner_preflight.client_peak_resident_reserve_bytes` | 3,880,278,960 B (3.614 GiB) |
| `setup.memory.planner_preflight.gross_resident_budget_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.planner_preflight.observed_physical_ram_bytes` | 392,855,961,600 B (365.876 GiB) |
| `setup.memory.planner_preflight.safety_reserve_bytes` | 80,000,000,000 B (74.506 GiB) |
| `setup.memory.planner_preflight.server_resident_cap_bytes` | 308,975,682,640 B (287.756 GiB) |
| `setup.memory.replay.admitted_peak_resident_bytes` | 291,985,153,130 B (271.932 GiB) |
| `setup.memory.replay.dense_multiplication_alias_cache_peak_resident_bytes` | 291,985,153,130 B (271.932 GiB) |
| `setup.memory.server.admitted_peak_resident_bytes` | 308,992,194,770 B (287.771 GiB) |
| `setup.memory.server.affine_gate_preparation_workspace_upper_bytes` | 0 B |
| `setup.memory.server.common_resident_reserve_bytes` | 16,627,455,082 B (15.486 GiB) |
| `setup.memory.server.gate_mle_opening_workspace_upper_bytes` | 2,552,557,616 B (2.377 GiB) |
| `setup.memory.server.gate_mle_retained_prover_key_upper_bytes` | 10,373,482,416 B (9.661 GiB) |
| `setup.memory.server.laned_affine_workspace_reserve_bytes` | 58,982,400 B (56.250 MiB) |
| `setup.memory.server.multiplication_sort_buffer_limit_bytes` | 143,856,727,580 B (133.977 GiB) |
| `setup.memory.server.packing_only_resident_reserve_bytes` | 1,872,864,592 B (1.744 GiB) |
| `setup.memory.server.payload_gkr_only_resident_reserve_bytes` | 1,551,894,528 B (1.445 GiB) |
| `setup.memory.server.reduction_workspace_reserve_bytes` | 2,552,557,616 B (2.377 GiB) |
| `setup.memory.setup.peak_rss_bytes` | 18,061,881,344 B (16.821 GiB) |
| `setup.memory.setup.prepublication_admitted_peak_resident_bytes` | 23,838,043,216 B (22.201 GiB) |
| `setup.memory.setup.prepublication_observed_peak_rss_bytes` | 15,316,254,720 B (14.264 GiB) |
| `setup.memory.setup.prepublication_remaining_resident_reserve_bytes` | 8,521,788,496 B (7.937 GiB) |
| `server.memory.client.admitted_peak_resident_bytes` | 3,863,766,830 B (3.598 GiB) |
| `server.memory.concurrent.admitted_peak_resident_bytes` | 312,855,961,600 B (291.370 GiB) |
| `server.memory.gkr_multiplication_sort_peak_buffered_payload_bytes` | 143,855,715,236 B (133.976 GiB) |
| `server.memory.server.admitted_peak_resident_bytes` | 308,992,194,770 B (287.771 GiB) |
| `server.memory.server.multiplication_sort_buffer_limit_bytes` | 143,856,727,580 B (133.977 GiB) |
| `server.memory.server.peak_rss_bytes` | 162,246,819,840 B (151.104 GiB) |
| `server.memory.server_witness_packing.peak_mask_cache_ntt_bytes` | 0 B |
| `client.memory.client.admitted_peak_resident_bytes` | 3,863,766,830 B (3.598 GiB) |
| `client.memory.client.peak_rss_bytes` | 1,775,419,392 B (1.653 GiB) |
| `server.storage.gkr_multiplication_sort_retained_temporary_bytes` | 0 B |
| `server.storage.gkr_peak_live_scratch_bytes` | 386,596,405,696 B (360.046 GiB) |
| `server.storage.packing.outer_assignment_physical_bytes` | 16,432,458,008 B (15.304 GiB) |
| `server.storage.packing.persistent_input_physical_bytes` | 21,968,942,062 B (20.460 GiB) |
| `server.storage.packing.preprocessing_validation_bytes` | 5,536,484,054 B (5.156 GiB) |
| `server.storage.packing.spartan_peak_live_bytes` | 949,387,616,212 B (884.186 GiB) |
| `server.storage.payload_replay_peak_live_physical_bytes` | 3,861,932,472,079 B (3.512 TiB) |
| `server.storage.payload_replay_peak_live_scratch_bytes` | 3,874,262,861,072 B (3.524 TiB) |
| `server.storage.payload_replay_total_reclaimed_physical_bytes` | 5,747,854,602,387 B (5.228 TiB) |
| `server.storage.server.admitted_peak_live_bytes` | 4,173,589,640,080 B (3.796 TiB) |

## Provenance

| Property | Bound value |
| --- | --- |
| Build / SEAL / SHA-256 acceleration | `Release` / `intel-hexl-runtime-dispatch` / `openssl` |
| Host | `INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz`; 392,855,961,600 B (365.876 GiB) RAM |
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
| Available at setup start | 10,410,394,435,584 B (9.468 TiB) at `2026-10-11T17:14:34Z` |
| Available at server start | 10,399,179,935,744 B (9.458 TiB) at `2026-10-11T17:23:34Z` |
