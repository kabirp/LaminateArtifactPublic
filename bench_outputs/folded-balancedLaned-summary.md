<!-- laminate-benchmark-summary-v2 -->
# Laminate Folded benchmark summary — target-balancedLaned

**PASS** — setup, server, and client completed, and the client accepted the proof.

## Highlights

| Highlight | Measured result |
| --- | --- |
| Laminate variant | Folded |
| Payload profile | `target-balancedLaned` |
| Fiat–Shamir composition | One transcript: GKR, then Spartan packing argument |
| GKR layer transitions | One claim by selector interpolation |
| Scalar gates | 17,179,869,184 (1,048,576 payload gates × 16,384 slots) |
| Initial ciphertext modulus (data primes only) | 577 bits across 14 limbs |
| Plaintext modulus | 65,537 |
| VCoED server wall time | 53 h 7 m 15.754 s |
| ↳ Payload computation | 4 h 40 m 56.230 s |
| ↳ Witness packing | 0.000 s |
| ↳ GKR proving | 38 h 4 m 16.583 s |
| ↳ Transcript packing | 10 h 21 m 56.006 s |
| Per-request client computation | 1.663 s |
| Input encryption | 0.770 s |
| Output decryption | 0.001 s |
| VCoED proof verification | 0.893 s |
| ↳ GKR proof verification | 0.153 s |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.027 s |
| ↳↳ Plaintext GKR and affine gate-opening checks | 0.126 s |
| ↳ Terminal input MLE | 0.038 s |
| ↳ Spartan packing argument | 0.685 s |
| ↳ Well-formedness noise checks | 0.017 s |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | `LaminateImpl/ConservativePackedProofIngress/v1`; limbs by layer `1,3,6,3,6,3,6,3,6,3,6,3,6,3,6,3,6,3` |

## Server layer reductions and sumcheck round details

| Role | Span | Wall | CPU |
| --- | --- | --- | --- |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_0` | 20.405 s | 20.403 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_1` | 1 m 31.031 s | 1 m 31.025 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_2` | 1 m 30.526 s | 1 m 30.520 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_3` | 1 m 30.430 s | 1 m 30.424 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_4` | 1 m 31.570 s | 1 m 31.564 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_5` | 1 m 31.063 s | 1 m 31.057 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_6` | 1 m 31.786 s | 1 m 31.781 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_7` | 1 m 31.362 s | 1 m 31.356 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_8` | 1 m 30.475 s | 1 m 30.469 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_9` | 1 m 30.626 s | 1 m 30.620 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_10` | 1 m 30.510 s | 1 m 30.505 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_11` | 1 m 30.267 s | 1 m 30.261 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_12` | 1 m 34.659 s | 1 m 34.653 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_13` | 1 m 31.779 s | 1 m 31.773 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_14` | 1 m 30.667 s | 1 m 30.661 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_15` | 1 m 30.775 s | 1 m 30.769 s |
| server | `folded.affine.slot_checkpoint.reduction_0.source_1.checkpoint_1.slot_index` | 1 m 4.697 s | 1 m 4.693 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_16` | 0.739 s | 0.739 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_17` | 0.778 s | 0.778 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_18` | 0.803 s | 0.803 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_19` | 0.831 s | 0.831 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_20` | 0.851 s | 0.851 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_21` | 0.870 s | 0.870 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_22` | 0.889 s | 0.889 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_23` | 0.910 s | 0.910 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_24` | 0.927 s | 0.927 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_25` | 0.949 s | 0.949 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_26` | 0.969 s | 0.969 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_27` | 0.989 s | 0.989 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_28` | 1.008 s | 1.008 s |
| server | `folded.affine.sumcheck_round.reduction_0.source_1.slot_index.round_29` | 1.029 s | 1.029 s |
| server | `folded.reduction.reduction_0.source_1` | 26 m 8.798 s | 26 m 5.804 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_0` | 6 m 28.154 s | 6 m 28.127 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_1` | 51 m 42.170 s | 51 m 41.949 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_2` | 29 m 46.703 s | 29 m 46.580 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_3` | 18 m 58.965 s | 18 m 58.886 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_4` | 13 m 21.336 s | 13 m 21.283 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_5` | 10 m 32.433 s | 10 m 32.392 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_6` | 9 m 2.581 s | 9 m 2.547 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_7` | 8 m 19.230 s | 8 m 19.200 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_8` | 7 m 58.087 s | 7 m 58.057 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_9` | 7 m 45.407 s | 7 m 45.378 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_10` | 7 m 38.551 s | 7 m 38.523 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_11` | 7 m 35.557 s | 7 m 35.529 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_12` | 7 m 34.518 s | 7 m 34.490 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_13` | 7 m 33.606 s | 7 m 33.578 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_14` | 7 m 35.509 s | 7 m 35.480 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_15` | 7 m 35.301 s | 7 m 35.273 s |
| server | `folded.multiplication.slot_checkpoint.reduction_1.source_2.checkpoint_2.slot_index` | 5 m 21.774 s | 5 m 21.754 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_16` | 2.028 s | 2.028 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_17` | 2.196 s | 2.195 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_18` | 2.313 s | 2.313 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_19` | 2.424 s | 2.424 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_20` | 2.553 s | 2.553 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_21` | 2.626 s | 2.626 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_22` | 2.780 s | 2.779 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_23` | 2.812 s | 2.812 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_24` | 2.915 s | 2.915 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_25` | 3.021 s | 3.021 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_26` | 3.115 s | 3.114 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_27` | 3.209 s | 3.209 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_28` | 3.325 s | 3.324 s |
| server | `folded.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_29` | 3.239 s | 3.239 s |
| server | `folded.reduction.reduction_1.source_2` | 3 h 51 m 51.820 s | 3 h 50 m 7.792 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_0` | 1 m 30.738 s | 1 m 30.727 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_1` | 1 m 33.109 s | 1 m 33.098 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_2` | 1 m 34.821 s | 1 m 34.815 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_3` | 1 m 39.887 s | 1 m 39.881 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_4` | 1 m 32.666 s | 1 m 32.660 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_5` | 1 m 31.008 s | 1 m 31.002 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_6` | 1 m 43.820 s | 1 m 43.814 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_7` | 1 m 31.185 s | 1 m 31.179 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_8` | 1 m 40.721 s | 1 m 40.715 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_9` | 1 m 38.081 s | 1 m 38.075 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_10` | 1 m 50.960 s | 1 m 50.954 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_11` | 1 m 43.396 s | 1 m 43.390 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_12` | 1 m 44.096 s | 1 m 44.090 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_13` | 1 m 35.752 s | 1 m 35.747 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_14` | 1 m 45.534 s | 1 m 45.527 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_15` | 1 m 35.445 s | 1 m 35.439 s |
| server | `folded.affine.slot_checkpoint.reduction_2.source_3.checkpoint_3.slot_index` | 1 m 10.616 s | 1 m 10.611 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_16` | 0.736 s | 0.736 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_17` | 0.780 s | 0.780 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_18` | 0.805 s | 0.805 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_19` | 0.829 s | 0.829 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_20` | 0.849 s | 0.849 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_21` | 0.872 s | 0.871 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_22` | 0.889 s | 0.889 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_23` | 0.912 s | 0.912 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_24` | 0.932 s | 0.932 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_25` | 0.952 s | 0.952 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_26` | 0.968 s | 0.968 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_27` | 0.992 s | 0.992 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_28` | 1.016 s | 1.016 s |
| server | `folded.affine.sumcheck_round.reduction_2.source_3.slot_index.round_29` | 1.032 s | 1.031 s |
| server | `folded.reduction.reduction_2.source_3` | 34 m 7.181 s | 34 m 0.680 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_0` | 6 m 26.279 s | 6 m 26.252 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_1` | 51 m 44.734 s | 51 m 44.506 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_2` | 29 m 51.270 s | 29 m 51.135 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_3` | 18 m 51.441 s | 18 m 51.360 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_4` | 13 m 14.960 s | 13 m 14.907 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_5` | 10 m 33.907 s | 10 m 33.865 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_6` | 9 m 7.059 s | 9 m 7.023 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_7` | 8 m 26.300 s | 8 m 26.269 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_8` | 8 m 5.145 s | 8 m 5.116 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_9` | 7 m 45.984 s | 7 m 45.955 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_10` | 7 m 41.901 s | 7 m 41.873 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_11` | 7 m 37.312 s | 7 m 37.284 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_12` | 7 m 43.484 s | 7 m 43.455 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_13` | 7 m 41.397 s | 7 m 41.369 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_14` | 7 m 35.355 s | 7 m 35.328 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_15` | 7 m 31.879 s | 7 m 31.852 s |
| server | `folded.multiplication.slot_checkpoint.reduction_3.source_4.checkpoint_4.slot_index` | 5 m 19.501 s | 5 m 19.481 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_16` | 1.981 s | 1.981 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_17` | 2.164 s | 2.164 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_18` | 2.282 s | 2.282 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_19` | 2.390 s | 2.390 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_20` | 2.495 s | 2.495 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_21` | 2.593 s | 2.593 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_22` | 2.694 s | 2.693 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_23` | 2.787 s | 2.787 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_24` | 2.890 s | 2.889 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_25` | 2.997 s | 2.997 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_26` | 3.083 s | 3.082 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_27` | 3.171 s | 3.171 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_28` | 3.278 s | 3.278 s |
| server | `folded.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_29` | 3.222 s | 3.221 s |
| server | `folded.reduction.reduction_3.source_4` | 3 h 57 m 3.469 s | 3 h 55 m 12.850 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_0` | 1 m 41.037 s | 1 m 41.025 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_1` | 1 m 36.667 s | 1 m 36.656 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_2` | 1 m 35.656 s | 1 m 35.650 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_3` | 1 m 42.277 s | 1 m 42.270 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_4` | 1 m 34.160 s | 1 m 34.154 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_5` | 1 m 49.218 s | 1 m 49.211 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_6` | 1 m 37.918 s | 1 m 37.911 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_7` | 1 m 32.726 s | 1 m 32.720 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_8` | 1 m 30.614 s | 1 m 30.608 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_9` | 1 m 34.078 s | 1 m 34.071 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_10` | 1 m 31.995 s | 1 m 31.989 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_11` | 1 m 38.901 s | 1 m 38.894 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_12` | 1 m 33.228 s | 1 m 33.221 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_13` | 1 m 33.811 s | 1 m 33.805 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_14` | 1 m 43.253 s | 1 m 43.247 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_15` | 1 m 29.538 s | 1 m 29.533 s |
| server | `folded.affine.slot_checkpoint.reduction_4.source_5.checkpoint_5.slot_index` | 1 m 7.769 s | 1 m 7.765 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_16` | 0.737 s | 0.737 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_17` | 0.780 s | 0.780 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_18` | 0.807 s | 0.806 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_19` | 0.826 s | 0.826 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_20` | 0.844 s | 0.844 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_21` | 0.868 s | 0.867 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_22` | 0.887 s | 0.887 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_23` | 0.909 s | 0.909 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_24` | 0.927 s | 0.927 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_25` | 0.949 s | 0.949 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_26` | 0.968 s | 0.968 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_27` | 0.987 s | 0.986 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_28` | 1.004 s | 1.004 s |
| server | `folded.affine.sumcheck_round.reduction_4.source_5.slot_index.round_29` | 1.028 s | 1.027 s |
| server | `folded.reduction.reduction_4.source_5` | 35 m 36.074 s | 35 m 29.053 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_0` | 6 m 26.825 s | 6 m 26.799 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_1` | 51 m 44.126 s | 51 m 43.914 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_2` | 29 m 46.631 s | 29 m 46.512 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_3` | 18 m 47.120 s | 18 m 47.049 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_4` | 13 m 21.147 s | 13 m 21.096 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_5` | 10 m 32.408 s | 10 m 32.368 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_6` | 9 m 6.590 s | 9 m 6.557 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_7` | 8 m 24.078 s | 8 m 24.049 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_8` | 8 m 1.158 s | 8 m 1.130 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_9` | 7 m 53.752 s | 7 m 53.724 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_10` | 7 m 44.231 s | 7 m 44.204 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_11` | 7 m 39.561 s | 7 m 39.535 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_12` | 7 m 33.213 s | 7 m 33.187 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_13` | 7 m 37.834 s | 7 m 37.809 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_14` | 7 m 34.781 s | 7 m 34.755 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_15` | 7 m 33.905 s | 7 m 33.879 s |
| server | `folded.multiplication.slot_checkpoint.reduction_5.source_6.checkpoint_6.slot_index` | 5 m 20.533 s | 5 m 20.515 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_16` | 1.998 s | 1.998 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_17` | 2.174 s | 2.174 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_18` | 2.301 s | 2.300 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_19` | 2.402 s | 2.402 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_20` | 2.505 s | 2.504 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_21` | 2.597 s | 2.596 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_22` | 2.701 s | 2.701 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_23` | 2.796 s | 2.795 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_24` | 2.904 s | 2.904 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_25` | 2.991 s | 2.991 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_26` | 3.095 s | 3.095 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_27` | 3.192 s | 3.192 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_28` | 3.285 s | 3.285 s |
| server | `folded.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_29` | 3.219 s | 3.219 s |
| server | `folded.reduction.reduction_5.source_6` | 4 h 0 m 59.849 s | 3 h 58 m 48.561 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_0` | 1 m 33.183 s | 1 m 33.172 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_1` | 1 m 33.291 s | 1 m 33.282 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_2` | 1 m 29.718 s | 1 m 29.713 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_3` | 1 m 30.061 s | 1 m 30.056 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_4` | 1 m 30.587 s | 1 m 30.582 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_5` | 1 m 40.721 s | 1 m 40.716 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_6` | 1 m 30.226 s | 1 m 30.221 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_7` | 1 m 31.237 s | 1 m 31.232 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_8` | 1 m 30.191 s | 1 m 30.186 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_9` | 1 m 30.144 s | 1 m 30.139 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_10` | 1 m 30.367 s | 1 m 30.362 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_11` | 1 m 30.731 s | 1 m 30.726 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_12` | 1 m 31.944 s | 1 m 31.939 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_13` | 1 m 30.630 s | 1 m 30.625 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_14` | 1 m 29.934 s | 1 m 29.929 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_15` | 1 m 29.751 s | 1 m 29.745 s |
| server | `folded.affine.slot_checkpoint.reduction_6.source_7.checkpoint_7.slot_index` | 1 m 5.602 s | 1 m 5.598 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_16` | 0.739 s | 0.739 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_17` | 0.784 s | 0.784 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_18` | 0.807 s | 0.807 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_19` | 0.831 s | 0.831 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_20` | 0.849 s | 0.849 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_21` | 0.869 s | 0.869 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_22` | 0.887 s | 0.887 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_23` | 0.909 s | 0.909 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_24` | 0.928 s | 0.928 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_25` | 0.950 s | 0.950 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_26` | 0.967 s | 0.967 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_27` | 0.989 s | 0.989 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_28` | 1.007 s | 1.007 s |
| server | `folded.affine.sumcheck_round.reduction_6.source_7.slot_index.round_29` | 1.027 s | 1.026 s |
| server | `folded.reduction.reduction_6.source_7` | 36 m 19.698 s | 36 m 14.910 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_0` | 6 m 24.170 s | 6 m 24.146 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_1` | 51 m 41.085 s | 51 m 40.880 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_2` | 29 m 59.025 s | 29 m 58.905 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_3` | 18 m 49.616 s | 18 m 49.544 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_4` | 13 m 22.899 s | 13 m 22.848 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_5` | 10 m 30.582 s | 10 m 30.543 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_6` | 9 m 6.977 s | 9 m 6.944 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_7` | 8 m 23.187 s | 8 m 23.158 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_8` | 7 m 57.583 s | 7 m 57.556 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_9` | 7 m 47.650 s | 7 m 47.624 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_10` | 7 m 42.591 s | 7 m 42.565 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_11` | 7 m 38.192 s | 7 m 38.166 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_12` | 7 m 42.236 s | 7 m 42.210 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_13` | 7 m 36.547 s | 7 m 36.522 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_14` | 7 m 34.016 s | 7 m 33.991 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_15` | 7 m 38.711 s | 7 m 38.685 s |
| server | `folded.multiplication.slot_checkpoint.reduction_7.source_8.checkpoint_8.slot_index` | 5 m 21.993 s | 5 m 21.974 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_16` | 2.007 s | 2.007 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_17` | 2.192 s | 2.192 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_18` | 2.320 s | 2.320 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_19` | 2.427 s | 2.427 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_20` | 2.532 s | 2.532 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_21` | 2.621 s | 2.621 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_22` | 2.723 s | 2.723 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_23` | 2.817 s | 2.817 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_24` | 2.917 s | 2.917 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_25` | 3.019 s | 3.018 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_26` | 3.120 s | 3.120 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_27` | 3.211 s | 3.210 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_28` | 3.318 s | 3.318 s |
| server | `folded.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_29` | 3.252 s | 3.252 s |
| server | `folded.reduction.reduction_7.source_8` | 4 h 5 m 40.528 s | 4 h 3 m 26.606 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_0` | 1 m 31.708 s | 1 m 31.697 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_1` | 1 m 30.964 s | 1 m 30.954 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_2` | 1 m 30.664 s | 1 m 30.659 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_3` | 1 m 32.069 s | 1 m 32.064 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_4` | 1 m 30.612 s | 1 m 30.606 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_5` | 1 m 30.196 s | 1 m 30.190 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_6` | 1 m 31.755 s | 1 m 31.749 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_7` | 1 m 33.086 s | 1 m 33.080 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_8` | 1 m 29.996 s | 1 m 29.991 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_9` | 1 m 30.208 s | 1 m 30.203 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_10` | 1 m 31.463 s | 1 m 31.458 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_11` | 1 m 31.029 s | 1 m 31.023 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_12` | 1 m 30.480 s | 1 m 30.475 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_13` | 1 m 31.596 s | 1 m 31.591 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_14` | 1 m 32.070 s | 1 m 32.064 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_15` | 1 m 29.888 s | 1 m 29.883 s |
| server | `folded.affine.slot_checkpoint.reduction_8.source_9.checkpoint_9.slot_index` | 1 m 3.449 s | 1 m 3.445 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_16` | 0.734 s | 0.734 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_17` | 0.778 s | 0.778 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_18` | 0.805 s | 0.805 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_19` | 0.828 s | 0.828 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_20` | 0.847 s | 0.847 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_21` | 0.869 s | 0.869 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_22` | 0.887 s | 0.887 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_23` | 0.906 s | 0.906 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_24` | 0.925 s | 0.925 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_25` | 0.946 s | 0.946 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_26` | 0.966 s | 0.966 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_27` | 0.987 s | 0.987 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_28` | 1.006 s | 1.006 s |
| server | `folded.affine.sumcheck_round.reduction_8.source_9.slot_index.round_29` | 1.029 s | 1.028 s |
| server | `folded.reduction.reduction_8.source_9` | 38 m 36.809 s | 38 m 31.832 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_0` | 6 m 25.984 s | 6 m 25.957 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_1` | 51 m 42.275 s | 51 m 42.069 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_2` | 30 m 6.235 s | 30 m 6.113 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_3` | 18 m 55.888 s | 18 m 55.812 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_4` | 13 m 23.237 s | 13 m 23.185 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_5` | 10 m 31.631 s | 10 m 31.590 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_6` | 9 m 8.143 s | 9 m 8.110 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_7` | 8 m 23.056 s | 8 m 23.026 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_8` | 8 m 1.789 s | 8 m 1.761 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_9` | 7 m 48.621 s | 7 m 48.594 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_10` | 7 m 41.281 s | 7 m 41.255 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_11` | 7 m 39.632 s | 7 m 39.606 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_12` | 7 m 37.323 s | 7 m 37.297 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_13` | 7 m 34.784 s | 7 m 34.758 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_14` | 7 m 34.822 s | 7 m 34.796 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_15` | 7 m 34.587 s | 7 m 34.562 s |
| server | `folded.multiplication.slot_checkpoint.reduction_9.source_10.checkpoint_10.slot_index` | 5 m 19.185 s | 5 m 19.166 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_16` | 1.985 s | 1.985 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_17` | 2.169 s | 2.169 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_18` | 2.293 s | 2.293 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_19` | 2.402 s | 2.402 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_20` | 2.507 s | 2.507 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_21` | 2.598 s | 2.597 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_22` | 2.699 s | 2.699 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_23` | 2.790 s | 2.790 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_24` | 2.890 s | 2.890 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_25` | 2.980 s | 2.980 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_26` | 3.087 s | 3.086 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_27` | 3.191 s | 3.191 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_28` | 3.304 s | 3.303 s |
| server | `folded.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_29` | 3.223 s | 3.223 s |
| server | `folded.reduction.reduction_9.source_10` | 4 h 10 m 39.495 s | 4 h 8 m 29.810 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_0` | 1 m 33.332 s | 1 m 33.321 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_1` | 1 m 32.337 s | 1 m 32.329 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_2` | 1 m 30.168 s | 1 m 30.163 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_3` | 1 m 30.656 s | 1 m 30.651 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_4` | 1 m 30.346 s | 1 m 30.341 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_5` | 1 m 31.401 s | 1 m 31.396 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_6` | 1 m 31.057 s | 1 m 31.051 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_7` | 1 m 30.582 s | 1 m 30.577 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_8` | 1 m 31.615 s | 1 m 31.610 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_9` | 1 m 32.683 s | 1 m 32.678 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_10` | 1 m 31.630 s | 1 m 31.625 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_11` | 1 m 30.649 s | 1 m 30.644 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_12` | 1 m 30.470 s | 1 m 30.464 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_13` | 1 m 31.312 s | 1 m 31.306 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_14` | 1 m 32.015 s | 1 m 32.009 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_15` | 1 m 30.348 s | 1 m 30.342 s |
| server | `folded.affine.slot_checkpoint.reduction_10.source_11.checkpoint_11.slot_index` | 1 m 3.644 s | 1 m 3.640 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_16` | 0.739 s | 0.739 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_17` | 0.781 s | 0.781 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_18` | 0.803 s | 0.803 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_19` | 0.828 s | 0.828 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_20` | 0.850 s | 0.850 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_21` | 0.872 s | 0.872 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_22` | 0.888 s | 0.888 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_23` | 0.912 s | 0.912 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_24` | 0.929 s | 0.929 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_25` | 0.948 s | 0.948 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_26` | 0.966 s | 0.965 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_27` | 0.988 s | 0.988 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_28` | 1.008 s | 1.008 s |
| server | `folded.affine.sumcheck_round.reduction_10.source_11.slot_index.round_29` | 1.031 s | 1.031 s |
| server | `folded.reduction.reduction_10.source_11` | 41 m 13.232 s | 41 m 9.716 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_0` | 6 m 24.803 s | 6 m 24.779 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_1` | 51 m 43.601 s | 51 m 43.397 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_2` | 29 m 53.231 s | 29 m 53.112 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_3` | 18 m 59.037 s | 18 m 58.960 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_4` | 13 m 20.740 s | 13 m 20.689 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_5` | 10 m 30.343 s | 10 m 30.304 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_6` | 9 m 6.371 s | 9 m 6.339 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_7` | 8 m 21.895 s | 8 m 21.867 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_8` | 7 m 59.611 s | 7 m 59.585 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_9` | 7 m 47.513 s | 7 m 47.487 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_10` | 7 m 39.900 s | 7 m 39.875 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_11` | 7 m 37.470 s | 7 m 37.445 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_12` | 7 m 35.545 s | 7 m 35.520 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_13` | 7 m 35.650 s | 7 m 35.625 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_14` | 7 m 34.454 s | 7 m 34.429 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_15` | 7 m 33.898 s | 7 m 33.872 s |
| server | `folded.multiplication.slot_checkpoint.reduction_11.source_12.checkpoint_12.slot_index` | 5 m 19.003 s | 5 m 18.984 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_16` | 1.977 s | 1.976 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_17` | 2.178 s | 2.178 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_18` | 2.297 s | 2.297 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_19` | 2.399 s | 2.399 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_20` | 2.511 s | 2.511 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_21` | 2.602 s | 2.602 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_22` | 2.706 s | 2.706 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_23` | 2.790 s | 2.790 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_24` | 2.896 s | 2.895 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_25` | 2.989 s | 2.989 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_26` | 3.081 s | 3.080 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_27` | 3.178 s | 3.178 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_28` | 3.282 s | 3.282 s |
| server | `folded.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_29` | 3.232 s | 3.232 s |
| server | `folded.reduction.reduction_11.source_12` | 4 h 15 m 40.757 s | 4 h 13 m 23.063 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_0` | 1 m 30.899 s | 1 m 30.888 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_1` | 1 m 31.188 s | 1 m 31.181 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_2` | 1 m 30.720 s | 1 m 30.715 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_3` | 1 m 31.380 s | 1 m 31.375 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_4` | 1 m 31.275 s | 1 m 31.270 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_5` | 1 m 32.036 s | 1 m 32.031 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_6` | 1 m 30.587 s | 1 m 30.582 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_7` | 1 m 32.057 s | 1 m 32.052 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_8` | 1 m 33.165 s | 1 m 33.160 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_9` | 1 m 30.930 s | 1 m 30.925 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_10` | 1 m 30.961 s | 1 m 30.956 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_11` | 1 m 30.746 s | 1 m 30.740 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_12` | 1 m 30.800 s | 1 m 30.794 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_13` | 1 m 30.961 s | 1 m 30.955 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_14` | 1 m 33.068 s | 1 m 33.063 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_15` | 1 m 32.557 s | 1 m 32.551 s |
| server | `folded.affine.slot_checkpoint.reduction_12.source_13.checkpoint_13.slot_index` | 1 m 3.613 s | 1 m 3.609 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_16` | 0.738 s | 0.738 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_17` | 0.781 s | 0.781 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_18` | 0.807 s | 0.807 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_19` | 0.827 s | 0.827 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_20` | 0.846 s | 0.846 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_21` | 0.867 s | 0.867 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_22` | 0.886 s | 0.886 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_23` | 0.912 s | 0.912 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_24` | 0.928 s | 0.928 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_25` | 0.949 s | 0.949 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_26` | 0.966 s | 0.966 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_27` | 0.985 s | 0.985 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_28` | 1.003 s | 1.003 s |
| server | `folded.affine.sumcheck_round.reduction_12.source_13.slot_index.round_29` | 1.025 s | 1.025 s |
| server | `folded.reduction.reduction_12.source_13` | 44 m 5.630 s | 44 m 2.136 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_0` | 6 m 22.807 s | 6 m 22.785 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_1` | 51 m 34.775 s | 51 m 34.576 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_2` | 29 m 50.903 s | 29 m 50.783 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_3` | 18 m 49.087 s | 18 m 49.013 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_4` | 13 m 18.633 s | 13 m 18.584 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_5` | 10 m 30.191 s | 10 m 30.152 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_6` | 9 m 6.344 s | 9 m 6.312 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_7` | 8 m 22.587 s | 8 m 22.558 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_8` | 7 m 59.916 s | 7 m 59.889 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_9` | 7 m 47.778 s | 7 m 47.752 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_10` | 7 m 40.816 s | 7 m 40.789 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_11` | 7 m 37.394 s | 7 m 37.367 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_12` | 7 m 36.958 s | 7 m 36.930 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_13` | 7 m 35.609 s | 7 m 35.582 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_14` | 7 m 35.261 s | 7 m 35.235 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_15` | 7 m 34.048 s | 7 m 34.023 s |
| server | `folded.multiplication.slot_checkpoint.reduction_13.source_14.checkpoint_14.slot_index` | 5 m 19.524 s | 5 m 19.506 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_16` | 1.967 s | 1.967 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_17` | 2.169 s | 2.169 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_18` | 2.299 s | 2.299 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_19` | 2.408 s | 2.408 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_20` | 2.507 s | 2.507 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_21` | 2.599 s | 2.599 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_22` | 2.702 s | 2.701 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_23` | 2.801 s | 2.800 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_24` | 2.907 s | 2.907 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_25` | 2.993 s | 2.993 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_26` | 3.094 s | 3.094 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_27` | 3.182 s | 3.182 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_28` | 3.295 s | 3.295 s |
| server | `folded.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_29` | 3.216 s | 3.216 s |
| server | `folded.reduction.reduction_13.source_14` | 4 h 20 m 43.513 s | 4 h 18 m 42.259 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_0` | 1 m 29.630 s | 1 m 29.619 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_1` | 1 m 30.607 s | 1 m 30.601 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_2` | 1 m 32.156 s | 1 m 32.151 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_3` | 1 m 30.464 s | 1 m 30.459 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_4` | 1 m 31.535 s | 1 m 31.530 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_5` | 1 m 30.993 s | 1 m 30.988 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_6` | 1 m 30.788 s | 1 m 30.783 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_7` | 1 m 31.265 s | 1 m 31.260 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_8` | 1 m 32.434 s | 1 m 32.429 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_9` | 1 m 29.946 s | 1 m 29.940 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_10` | 1 m 29.490 s | 1 m 29.485 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_11` | 1 m 30.872 s | 1 m 30.868 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_12` | 1 m 30.282 s | 1 m 30.277 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_13` | 1 m 30.224 s | 1 m 30.219 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_14` | 1 m 29.784 s | 1 m 29.779 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_15` | 1 m 31.896 s | 1 m 31.891 s |
| server | `folded.affine.slot_checkpoint.reduction_14.source_15.checkpoint_15.slot_index` | 1 m 3.848 s | 1 m 3.844 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_16` | 0.743 s | 0.743 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_17` | 0.782 s | 0.782 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_18` | 0.805 s | 0.805 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_19` | 0.830 s | 0.830 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_20` | 0.851 s | 0.851 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_21` | 0.871 s | 0.871 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_22` | 0.888 s | 0.888 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_23` | 0.910 s | 0.910 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_24` | 0.931 s | 0.931 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_25` | 0.952 s | 0.952 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_26` | 0.969 s | 0.969 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_27` | 0.992 s | 0.992 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_28` | 1.010 s | 1.010 s |
| server | `folded.affine.sumcheck_round.reduction_14.source_15.slot_index.round_29` | 1.028 s | 1.028 s |
| server | `folded.reduction.reduction_14.source_15` | 46 m 56.438 s | 46 m 52.041 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_0` | 5 m 47.777 s | 5 m 47.749 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_1` | 51 m 43.917 s | 51 m 43.699 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_2` | 30 m 1.780 s | 30 m 1.656 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_3` | 19 m 2.328 s | 19 m 2.250 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_4` | 13 m 27.821 s | 13 m 27.765 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_5` | 10 m 34.527 s | 10 m 34.484 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_6` | 9 m 7.116 s | 9 m 7.080 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_7` | 8 m 22.697 s | 8 m 22.665 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_8` | 8 m 1.539 s | 8 m 1.509 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_9` | 7 m 48.658 s | 7 m 48.630 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_10` | 7 m 44.210 s | 7 m 44.181 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_11` | 7 m 39.386 s | 7 m 39.358 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_12` | 7 m 39.657 s | 7 m 39.629 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_13` | 7 m 38.677 s | 7 m 38.650 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_14` | 7 m 37.102 s | 7 m 37.075 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_15` | 7 m 38.099 s | 7 m 38.072 s |
| server | `folded.multiplication.slot_checkpoint.reduction_15.source_16.checkpoint_16.slot_index` | 5 m 21.825 s | 5 m 21.805 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_16` | 1.951 s | 1.951 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_17` | 2.160 s | 2.160 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_18` | 2.284 s | 2.284 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_19` | 2.394 s | 2.393 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_20` | 2.496 s | 2.495 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_21` | 2.590 s | 2.590 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_22` | 2.690 s | 2.690 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_23` | 2.781 s | 2.781 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_24` | 2.895 s | 2.895 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_25` | 2.988 s | 2.988 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_26` | 3.079 s | 3.078 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_27` | 3.178 s | 3.177 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_28` | 3.281 s | 3.280 s |
| server | `folded.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_29` | 3.214 s | 3.213 s |
| server | `folded.reduction.reduction_15.source_16` | 3 h 58 m 25.320 s | 3 h 58 m 10.864 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_0` | 0.726 s | 0.726 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_1` | 0.716 s | 0.716 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_2` | 0.716 s | 0.716 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_3` | 0.718 s | 0.718 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_4` | 0.715 s | 0.715 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.ciphertext_index.round_5` | 0.718 s | 0.718 s |
| server | `folded.affine.slot_checkpoint.reduction_16.source_17.checkpoint_17.slot_index` | 0.063 s | 0.063 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_6` | 0.729 s | 0.729 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_7` | 0.778 s | 0.777 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_8` | 0.801 s | 0.801 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_9` | 0.825 s | 0.825 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_10` | 0.846 s | 0.846 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_11` | 0.868 s | 0.867 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_12` | 0.884 s | 0.884 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_13` | 0.905 s | 0.904 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_14` | 0.923 s | 0.923 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_15` | 0.941 s | 0.941 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_16` | 0.959 s | 0.959 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_17` | 0.982 s | 0.982 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_18` | 1.003 s | 1.003 s |
| server | `folded.affine.sumcheck_round.reduction_16.source_17.slot_index.round_19` | 1.024 s | 1.024 s |
| server | `folded.reduction.reduction_16.source_17` | 19.394 s | 19.380 s |
| server | `folded.gate_mle_opening` | 19 m 48.557 s | 19 m 47.256 s |

## Client computation

| Component | Wall | CPU |
|---|---:|---:|
| Per-request client computation | 1.663 s | 1.663 s |
| Input encryption | 0.770 s | 0.769 s |
| Output decryption | 0.001 s | 0.001 s |
| VCoED proof verification | 0.893 s | 0.893 s |
| ↳ GKR proof verification | 0.153 s | 0.153 s |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.027 s | 0.027 s |
| ↳↳ Plaintext GKR and affine gate-opening checks | 0.126 s | 0.126 s |
| ↳ Terminal input MLE | 0.038 s | 0.038 s |
| ↳ Spartan packing argument | 0.685 s | 0.685 s |
| ↳ Well-formedness noise checks | 0.017 s | 0.017 s |

Client computation is input encryption + output decryption + VCoED proof verification. Preprocessing RAM loading, transport, peer waiting, and the optional output-noise audit are excluded. Verification rows form a hierarchy: add siblings only. Packed transcript recovery includes signed-digit recomposition into logical plaintexts.

## Client verifier details

Transcript-packing verification and message recovery: **0.695 s wall**. Gate-MLE opening: **0.118 s wall**. These are nested diagnostic spans; they do not define the disjoint computation hierarchy above.

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
| client | `transcript_packing.verifier_statement` | 0.043 s | 0.043 s |
| client | `transcript_packing.spartan_verify` | 0.633 s | 0.633 s |
| client | `transcript_packing.threshold_checks` | 0.017 s | 0.017 s |
| client | `transcript_packing.unpack` | 0.002 s | 0.002 s |

## Server FHE operation ledger

| Server stage | Operation | Calls | Limb operations | Calls by RNS limbs |
| --- | --- | --- | --- | --- |
| `server_payload_evaluation` | `add` | 471,859 | 4,528,550 | `4:65535,7:50790,8:50790,9:50790,10:50790,11:50791,12:50791,13:50791,14:50791` |
| `server_payload_evaluation` | `add_plain` | 52,429 | 550,512 | `7:6553,8:6553,9:6553,10:6554,11:6554,12:6554,13:6554,14:6554` |
| `server_payload_evaluation` | `decrypt` | 0 | 0 | `none` |
| `server_payload_evaluation` | `encrypt` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_add` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_mul` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_mul_plain` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_sub` | 0 | 0 | `none` |
| `server_payload_evaluation` | `mod_switch` | 655,363 | 6,225,929 | `2:1,3:1,4:1,5:65536,6:65536,7:65536,8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536` |
| `server_payload_evaluation` | `mul_no_relin` | 524,288 | 5,505,024 | `7:65536,8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536` |
| `server_payload_evaluation` | `mul_plain_scalar` | 0 | 0 | `none` |
| `server_payload_evaluation` | `mul_plain_vector` | 0 | 0 | `none` |
| `server_payload_evaluation` | `negate` | 0 | 0 | `none` |
| `server_payload_evaluation` | `relinearize` | 524,288 | 5,505,024 | `7:65536,8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536` |
| `server_payload_evaluation` | `rotate` | 0 | 0 | `none` |
| `server_payload_evaluation` | `sub` | 0 | 0 | `none` |
| `server_proving` | `add` | 368,166,183 | 1,895,967,496 | `1:33214,3:104287844,6:263845125` |
| `server_proving` | `add_plain` | 7 | 42 | `6:7` |
| `server_proving` | `decrypt` | 0 | 0 | `none` |
| `server_proving` | `encrypt` | 0 | 0 | `none` |
| `server_proving` | `logical_ext_add` | 527,008 | 3,158,835 | `3:1071,6:525937` |
| `server_proving` | `logical_ext_mul` | 524,496 | 3,146,976 | `6:524496` |
| `server_proving` | `logical_ext_mul_plain` | 525,622 | 3,151,794 | `3:646,6:524976` |
| `server_proving` | `logical_ext_sub` | 350 | 1,722 | `3:126,6:224` |
| `server_proving` | `mod_switch` | 7,179,206 | 59,459,379 | `2:517,3:517,4:524600,5:459064,6:459064,7:1376385,8:1187970,9:999555,10:811140,11:622724,12:434307,13:245890,14:57473` |
| `server_proving` | `mul_no_relin` | 34,091,920 | 204,551,520 | `6:34091920` |
| `server_proving` | `mul_plain_scalar` | 339,011,038 | 1,721,649,660 | `3:104138856,6:234872182` |
| `server_proving` | `mul_plain_vector` | 95,660 | 427,228 | `1:2068,3:45464,6:48128` |
| `server_proving` | `negate` | 7,377,121 | 44,154,514 | `1:15586,3:10094,6:7351441` |
| `server_proving` | `relinearize` | 3,840 | 23,040 | `6:3840` |
| `server_proving` | `rotate` | 136,320 | 616,530 | `3:67099,4:31,5:31,6:69159` |
| `server_proving` | `sub` | 527,088 | 3,159,504 | `3:1008,6:526080` |

## Protocol artifacts

| Quantity | Measured value |
| --- | --- |
| Proving key / server preprocessing | 65,702,345,289 B (61.190 GiB) |
| Verifying key / client preprocessing | 121,908,735 B (116.261 MiB) |
| `server.wire.request_bytes` | 234,892,693 B (224.011 MiB) |
| `server.wire.response_bytes` | 54,335,166 B (51.818 MiB) |
| `client.wire.request_bytes` | 234,892,693 B (224.011 MiB) |
| `client.wire.response_bytes` | 54,335,166 B (51.818 MiB) |
| `server.proof.canonical.committed_gkr_bytes` | 6,996,978 B (6.673 MiB) |
| `server.proof.canonical.digit_packing_ciphertext_bytes` | 1,049,064 B (1.000 MiB) |
| `server.proof.canonical.spartan_packing_proof_bytes` | 14,554,581 B (13.880 MiB) |
| `server.proof.canonical.statement_and_metadata_bytes` | 46 B |
| `server.proof.canonical.total_bytes` | 54,072,589 B (51.568 MiB) |
| `server.proof.canonical.well_formedness_reveal_bytes` | 31,471,920 B (30.014 MiB) |
| `server.proof.committed_gkr.commitment_digest_bytes` | 24,816 B (24.234 KiB) |
| `server.proof.committed_gkr.gate_mle_opening_bytes` | 6,971,300 B (6.648 MiB) |
| `server.proof.response.total_bytes` | 54,335,166 B (51.818 MiB) |

## Memory and storage

| Quantity | Measured value |
| --- | --- |
| `setup.memory.client.admitted_peak_resident_bytes` | 11,881,741,110 B (11.066 GiB) |
| `setup.memory.concurrent.admitted_peak_resident_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.host_budget.exact_client_peak_resident_bytes` | 11,881,741,110 B (11.066 GiB) |
| `setup.memory.host_budget.exact_server_resident_cap_bytes` | 300,974,220,490 B (280.304 GiB) |
| `setup.memory.host_budget.gross_resident_budget_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.host_budget.operating_system_reserve_bytes` | 16,000,000,000 B (14.901 GiB) |
| `setup.memory.host_budget.page_cache_reserve_bytes` | 64,000,000,000 B (59.605 GiB) |
| `setup.memory.payload_storage.prefetch_page_cache_budget_bytes` | 536,870,912 B (512.000 MiB) |
| `setup.memory.payload_storage.transfer_buffer_reserve_bytes` | 402,653,184 B (384.000 MiB) |
| `setup.memory.payload_storage.writeback_window_bytes` | 0 B |
| `setup.memory.planner_preflight.client_peak_resident_reserve_bytes` | 11,898,253,240 B (11.081 GiB) |
| `setup.memory.planner_preflight.gross_resident_budget_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.planner_preflight.observed_physical_ram_bytes` | 392,855,961,600 B (365.876 GiB) |
| `setup.memory.planner_preflight.safety_reserve_bytes` | 80,000,000,000 B (74.506 GiB) |
| `setup.memory.planner_preflight.server_resident_cap_bytes` | 300,957,708,360 B (280.289 GiB) |
| `setup.memory.replay.admitted_peak_resident_bytes` | 285,928,763,346 B (266.292 GiB) |
| `setup.memory.replay.dense_multiplication_alias_cache_peak_resident_bytes` | 285,928,763,346 B (266.292 GiB) |
| `setup.memory.server.admitted_peak_resident_bytes` | 300,974,220,490 B (280.304 GiB) |
| `setup.memory.server.affine_gate_preparation_workspace_upper_bytes` | 922,777,784 B (880.029 MiB) |
| `setup.memory.server.common_resident_reserve_bytes` | 10,571,065,298 B (9.845 GiB) |
| `setup.memory.server.gate_mle_opening_workspace_upper_bytes` | 8,686,960,192 B (8.090 GiB) |
| `setup.memory.server.gate_mle_retained_prover_key_upper_bytes` | 303,220,656 B (289.174 MiB) |
| `setup.memory.server.multiplication_sort_buffer_limit_bytes` | 139,347,345,152 B (129.777 GiB) |
| `setup.memory.server.packing_only_resident_reserve_bytes` | 5,876,966,896 B (5.473 GiB) |
| `setup.memory.server.payload_gkr_only_resident_reserve_bytes` | 1,551,894,528 B (1.445 GiB) |
| `setup.memory.server.reduction_workspace_reserve_bytes` | 9,609,737,976 B (8.950 GiB) |
| `setup.memory.setup.peak_rss_bytes` | 10,549,526,528 B (9.825 GiB) |
| `setup.memory.setup.prepublication_admitted_peak_resident_bytes` | 15,897,859,416 B (14.806 GiB) |
| `setup.memory.setup.prepublication_observed_peak_rss_bytes` | 7,288,143,872 B (6.788 GiB) |
| `setup.memory.setup.prepublication_remaining_resident_reserve_bytes` | 8,609,715,544 B (8.018 GiB) |
| `server.memory.client.admitted_peak_resident_bytes` | 11,881,741,110 B (11.066 GiB) |
| `server.memory.concurrent.admitted_peak_resident_bytes` | 312,855,961,600 B (291.370 GiB) |
| `server.memory.gkr_multiplication_sort_peak_buffered_payload_bytes` | 139,345,821,024 B (129.776 GiB) |
| `server.memory.server.admitted_peak_resident_bytes` | 300,974,220,490 B (280.304 GiB) |
| `server.memory.server.multiplication_sort_buffer_limit_bytes` | 139,347,345,152 B (129.777 GiB) |
| `server.memory.server.peak_rss_bytes` | 194,199,392,256 B (180.862 GiB) |
| `server.memory.server_witness_packing.peak_mask_cache_ntt_bytes` | 0 B |
| `client.memory.client.admitted_peak_resident_bytes` | 11,881,741,110 B (11.066 GiB) |
| `client.memory.client.peak_rss_bytes` | 1,821,224,960 B (1.696 GiB) |
| `server.storage.gkr_multiplication_sort_retained_temporary_bytes` | 0 B |
| `server.storage.gkr_peak_live_scratch_bytes` | 386,596,405,696 B (360.046 GiB) |
| `server.storage.packing.outer_assignment_physical_bytes` | 16,432,458,008 B (15.304 GiB) |
| `server.storage.packing.persistent_input_physical_bytes` | 21,968,942,062 B (20.460 GiB) |
| `server.storage.packing.preprocessing_validation_bytes` | 5,536,484,054 B (5.156 GiB) |
| `server.storage.packing.spartan_peak_live_bytes` | 949,387,616,212 B (884.186 GiB) |
| `server.storage.payload_replay_peak_live_physical_bytes` | 3,861,932,472,079 B (3.512 TiB) |
| `server.storage.payload_replay_peak_live_scratch_bytes` | 3,933,536,951,112 B (3.578 TiB) |
| `server.storage.payload_replay_total_reclaimed_physical_bytes` | 5,593,219,002,515 B (5.087 TiB) |
| `server.storage.server.admitted_peak_live_bytes` | 4,232,863,730,120 B (3.850 TiB) |

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
| Available at setup start | 10,410,795,556,864 B (9.469 TiB) at `2026-10-06T16:46:22Z` |
| Available at server start | 10,345,086,988,288 B (9.409 TiB) at `2026-10-06T18:11:24Z` |
