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
| Lanes | 1 |
| Scalar gates | 1,048,576 (1,048,576 payload gates × 1 lane) |
| Initial ciphertext modulus (data primes only) | 617 bits across 15 limbs |
| Plaintext modulus | 65,537 |
| VCoED server wall time | 11 h 5 m 49.314 s |
| ↳ Payload computation | 5 h 27 m 17.975 s |
| ↳ Witness packing | 59 m 10.493 s |
| ↳ GKR proving | 14 m 21.551 s |
| ↳ Transcript packing | 4 h 24 m 55.478 s |
| Per-request client computation | 2.165 s |
| Input encryption | 0.725 s |
| Output decryption | 0.001 s |
| VCoED proof verification | 1.439 s |
| ↳ GKR proof verification | 0.832 s |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.237 s |
| ↳↳ Plaintext GKR and affine gate-opening checks | 0.595 s |
| ↳ Terminal input MLE | 0.005 s |
| ↳ Spartan packing argument | 0.585 s |
| ↳ Well-formedness noise checks | 0.017 s |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | `LaminateImpl/ConservativePackedProofIngress/v3`; limbs by layer `1,4,7,4,7,4,7,4,7,4,7,4,7,4,7,4,7,4` |

## Server layer reductions and sumcheck round details

| Role | Span | Wall | CPU |
| --- | --- | --- | --- |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_0` | 0.878 s | 0.877 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.ciphertext_index.round_1` | 0.883 s | 0.883 s |
| server | `laned.affine.slot_checkpoint.reduction_0.source_1.checkpoint_1.slot_index` | 0.036 s | 0.036 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_2` | 0.944 s | 0.943 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_3` | 1.032 s | 1.031 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_4` | 1.073 s | 1.072 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_5` | 1.116 s | 1.116 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_6` | 1.145 s | 1.145 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_7` | 1.172 s | 1.172 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_8` | 1.196 s | 1.196 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_9` | 1.227 s | 1.227 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_10` | 1.254 s | 1.254 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_11` | 1.283 s | 1.283 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_12` | 1.306 s | 1.306 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_13` | 1.339 s | 1.339 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_14` | 1.361 s | 1.361 s |
| server | `laned.affine.sumcheck_round.reduction_0.source_1.slot_index.round_15` | 1.388 s | 1.388 s |
| server | `laned.reduction.reduction_0.source_1` | 19.196 s | 19.192 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_0` | 1.692 s | 1.692 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.ciphertext_index.round_1` | 1.797 s | 1.797 s |
| server | `laned.multiplication.slot_checkpoint.reduction_1.source_2.checkpoint_2.slot_index` | 0.020 s | 0.020 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_2` | 1.926 s | 1.925 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_3` | 2.128 s | 2.128 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_4` | 2.257 s | 2.257 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_5` | 2.362 s | 2.361 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_6` | 2.464 s | 2.464 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_7` | 2.553 s | 2.553 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_8` | 2.659 s | 2.659 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_9` | 2.754 s | 2.754 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_10` | 2.846 s | 2.845 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_11` | 2.934 s | 2.934 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_12` | 3.037 s | 3.036 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_13` | 3.129 s | 3.129 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_14` | 3.225 s | 3.225 s |
| server | `laned.multiplication.sumcheck_round.reduction_1.source_2.slot_index.round_15` | 3.157 s | 3.157 s |
| server | `laned.reduction.reduction_1.source_2` | 42.569 s | 42.560 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_0` | 0.916 s | 0.916 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.ciphertext_index.round_1` | 0.927 s | 0.927 s |
| server | `laned.affine.slot_checkpoint.reduction_2.source_3.checkpoint_3.slot_index` | 0.037 s | 0.037 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_2` | 0.979 s | 0.979 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_3` | 1.055 s | 1.054 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_4` | 1.087 s | 1.087 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_5` | 1.116 s | 1.116 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_6` | 1.144 s | 1.144 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_7` | 1.176 s | 1.176 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_8` | 1.203 s | 1.203 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_9` | 1.239 s | 1.239 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_10` | 1.256 s | 1.256 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_11` | 1.287 s | 1.286 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_12` | 1.312 s | 1.312 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_13` | 1.336 s | 1.336 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_14` | 1.363 s | 1.363 s |
| server | `laned.affine.sumcheck_round.reduction_2.source_3.slot_index.round_15` | 1.394 s | 1.394 s |
| server | `laned.reduction.reduction_2.source_3` | 19.685 s | 19.682 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_0` | 1.699 s | 1.699 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.ciphertext_index.round_1` | 1.807 s | 1.807 s |
| server | `laned.multiplication.slot_checkpoint.reduction_3.source_4.checkpoint_4.slot_index` | 0.021 s | 0.021 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_2` | 1.932 s | 1.931 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_3` | 2.137 s | 2.137 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_4` | 2.252 s | 2.252 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_5` | 2.356 s | 2.356 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_6` | 2.467 s | 2.467 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_7` | 2.557 s | 2.557 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_8` | 2.660 s | 2.660 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_9` | 2.741 s | 2.741 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_10` | 2.844 s | 2.844 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_11` | 2.934 s | 2.934 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_12` | 3.030 s | 3.030 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_13` | 3.119 s | 3.119 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_14` | 3.225 s | 3.224 s |
| server | `laned.multiplication.sumcheck_round.reduction_3.source_4.slot_index.round_15` | 3.163 s | 3.163 s |
| server | `laned.reduction.reduction_3.source_4` | 42.572 s | 42.562 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_0` | 0.916 s | 0.916 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.ciphertext_index.round_1` | 0.928 s | 0.927 s |
| server | `laned.affine.slot_checkpoint.reduction_4.source_5.checkpoint_5.slot_index` | 0.037 s | 0.037 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_2` | 0.982 s | 0.982 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_3` | 1.049 s | 1.049 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_4` | 1.082 s | 1.082 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_5` | 1.121 s | 1.121 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_6` | 1.149 s | 1.149 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_7` | 1.180 s | 1.180 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_8` | 1.202 s | 1.201 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_9` | 1.231 s | 1.231 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_10` | 1.255 s | 1.255 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_11` | 1.282 s | 1.282 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_12` | 1.307 s | 1.307 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_13` | 1.337 s | 1.337 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_14` | 1.368 s | 1.368 s |
| server | `laned.affine.sumcheck_round.reduction_4.source_5.slot_index.round_15` | 1.399 s | 1.399 s |
| server | `laned.reduction.reduction_4.source_5` | 19.685 s | 19.680 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_0` | 1.702 s | 1.702 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.ciphertext_index.round_1` | 1.812 s | 1.812 s |
| server | `laned.multiplication.slot_checkpoint.reduction_5.source_6.checkpoint_6.slot_index` | 0.021 s | 0.021 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_2` | 1.935 s | 1.934 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_3` | 2.134 s | 2.133 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_4` | 2.258 s | 2.258 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_5` | 2.372 s | 2.372 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_6` | 2.467 s | 2.467 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_7` | 2.564 s | 2.564 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_8` | 2.658 s | 2.658 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_9` | 2.749 s | 2.748 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_10` | 2.843 s | 2.843 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_11` | 2.933 s | 2.933 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_12` | 3.038 s | 3.038 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_13` | 3.133 s | 3.133 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_14` | 3.238 s | 3.238 s |
| server | `laned.multiplication.sumcheck_round.reduction_5.source_6.slot_index.round_15` | 3.168 s | 3.168 s |
| server | `laned.reduction.reduction_5.source_6` | 42.663 s | 42.652 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_0` | 0.923 s | 0.923 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.ciphertext_index.round_1` | 0.930 s | 0.930 s |
| server | `laned.affine.slot_checkpoint.reduction_6.source_7.checkpoint_7.slot_index` | 0.037 s | 0.037 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_2` | 0.984 s | 0.984 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_3` | 1.057 s | 1.057 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_4` | 1.090 s | 1.090 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_5` | 1.122 s | 1.122 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_6` | 1.147 s | 1.146 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_7` | 1.175 s | 1.175 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_8` | 1.201 s | 1.201 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_9` | 1.227 s | 1.227 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_10` | 1.252 s | 1.251 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_11` | 1.281 s | 1.281 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_12` | 1.311 s | 1.311 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_13` | 1.342 s | 1.341 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_14` | 1.371 s | 1.371 s |
| server | `laned.affine.sumcheck_round.reduction_6.source_7.slot_index.round_15` | 1.395 s | 1.395 s |
| server | `laned.reduction.reduction_6.source_7` | 19.704 s | 19.700 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_0` | 1.692 s | 1.692 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.ciphertext_index.round_1` | 1.807 s | 1.807 s |
| server | `laned.multiplication.slot_checkpoint.reduction_7.source_8.checkpoint_8.slot_index` | 0.020 s | 0.020 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_2` | 1.923 s | 1.923 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_3` | 2.134 s | 2.134 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_4` | 2.260 s | 2.260 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_5` | 2.351 s | 2.351 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_6` | 2.475 s | 2.475 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_7` | 2.551 s | 2.551 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_8` | 2.646 s | 2.646 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_9` | 2.733 s | 2.733 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_10` | 2.836 s | 2.836 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_11` | 2.931 s | 2.930 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_12` | 3.037 s | 3.037 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_13` | 3.126 s | 3.125 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_14` | 3.230 s | 3.230 s |
| server | `laned.multiplication.sumcheck_round.reduction_7.source_8.slot_index.round_15` | 3.173 s | 3.173 s |
| server | `laned.reduction.reduction_7.source_8` | 42.560 s | 42.545 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_0` | 0.916 s | 0.916 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.ciphertext_index.round_1` | 0.928 s | 0.928 s |
| server | `laned.affine.slot_checkpoint.reduction_8.source_9.checkpoint_9.slot_index` | 0.037 s | 0.037 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_2` | 0.984 s | 0.984 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_3` | 1.055 s | 1.054 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_4` | 1.090 s | 1.090 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_5` | 1.120 s | 1.120 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_6` | 1.145 s | 1.145 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_7` | 1.173 s | 1.173 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_8` | 1.196 s | 1.196 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_9` | 1.228 s | 1.228 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_10` | 1.256 s | 1.256 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_11` | 1.286 s | 1.286 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_12` | 1.311 s | 1.311 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_13` | 1.341 s | 1.341 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_14` | 1.374 s | 1.374 s |
| server | `laned.affine.sumcheck_round.reduction_8.source_9.slot_index.round_15` | 1.397 s | 1.397 s |
| server | `laned.reduction.reduction_8.source_9` | 19.695 s | 19.690 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_0` | 1.705 s | 1.705 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.ciphertext_index.round_1` | 1.810 s | 1.810 s |
| server | `laned.multiplication.slot_checkpoint.reduction_9.source_10.checkpoint_10.slot_index` | 0.021 s | 0.021 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_2` | 1.930 s | 1.930 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_3` | 2.142 s | 2.142 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_4` | 2.260 s | 2.260 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_5` | 2.381 s | 2.381 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_6` | 2.462 s | 2.461 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_7` | 2.552 s | 2.551 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_8` | 2.650 s | 2.650 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_9` | 2.749 s | 2.749 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_10` | 2.852 s | 2.852 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_11` | 2.938 s | 2.938 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_12` | 3.042 s | 3.042 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_13` | 3.138 s | 3.138 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_14` | 3.243 s | 3.242 s |
| server | `laned.multiplication.sumcheck_round.reduction_9.source_10.slot_index.round_15` | 3.175 s | 3.175 s |
| server | `laned.reduction.reduction_9.source_10` | 42.689 s | 42.677 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_0` | 0.923 s | 0.923 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.ciphertext_index.round_1` | 0.933 s | 0.933 s |
| server | `laned.affine.slot_checkpoint.reduction_10.source_11.checkpoint_11.slot_index` | 0.037 s | 0.037 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_2` | 0.984 s | 0.984 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_3` | 1.053 s | 1.053 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_4` | 1.086 s | 1.086 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_5` | 1.118 s | 1.118 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_6` | 1.143 s | 1.143 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_7` | 1.175 s | 1.175 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_8` | 1.204 s | 1.204 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_9` | 1.234 s | 1.234 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_10` | 1.257 s | 1.257 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_11` | 1.291 s | 1.291 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_12` | 1.314 s | 1.314 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_13` | 1.343 s | 1.343 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_14` | 1.366 s | 1.366 s |
| server | `laned.affine.sumcheck_round.reduction_10.source_11.slot_index.round_15` | 1.402 s | 1.402 s |
| server | `laned.reduction.reduction_10.source_11` | 19.725 s | 19.722 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_0` | 1.697 s | 1.697 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.ciphertext_index.round_1` | 1.805 s | 1.804 s |
| server | `laned.multiplication.slot_checkpoint.reduction_11.source_12.checkpoint_12.slot_index` | 0.021 s | 0.021 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_2` | 1.936 s | 1.935 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_3` | 2.130 s | 2.130 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_4` | 2.266 s | 2.266 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_5` | 2.355 s | 2.355 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_6` | 2.461 s | 2.461 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_7` | 2.556 s | 2.556 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_8` | 2.659 s | 2.658 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_9` | 2.748 s | 2.748 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_10` | 2.850 s | 2.850 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_11` | 2.946 s | 2.946 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_12` | 3.041 s | 3.040 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_13` | 3.137 s | 3.137 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_14` | 3.240 s | 3.240 s |
| server | `laned.multiplication.sumcheck_round.reduction_11.source_12.slot_index.round_15` | 3.179 s | 3.178 s |
| server | `laned.reduction.reduction_11.source_12` | 42.659 s | 42.648 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_0` | 0.923 s | 0.923 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.ciphertext_index.round_1` | 0.934 s | 0.934 s |
| server | `laned.affine.slot_checkpoint.reduction_12.source_13.checkpoint_13.slot_index` | 0.037 s | 0.037 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_2` | 0.987 s | 0.987 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_3` | 1.054 s | 1.054 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_4` | 1.085 s | 1.085 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_5` | 1.122 s | 1.122 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_6` | 1.154 s | 1.154 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_7` | 1.184 s | 1.184 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_8` | 1.205 s | 1.205 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_9` | 1.237 s | 1.237 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_10` | 1.262 s | 1.262 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_11` | 1.289 s | 1.289 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_12` | 1.311 s | 1.311 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_13` | 1.345 s | 1.345 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_14` | 1.374 s | 1.374 s |
| server | `laned.affine.sumcheck_round.reduction_12.source_13.slot_index.round_15` | 1.397 s | 1.397 s |
| server | `laned.reduction.reduction_12.source_13` | 19.760 s | 19.755 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_0` | 1.692 s | 1.692 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.ciphertext_index.round_1` | 1.804 s | 1.803 s |
| server | `laned.multiplication.slot_checkpoint.reduction_13.source_14.checkpoint_14.slot_index` | 0.021 s | 0.021 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_2` | 1.922 s | 1.921 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_3` | 2.147 s | 2.147 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_4` | 2.255 s | 2.255 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_5` | 2.361 s | 2.361 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_6` | 2.467 s | 2.467 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_7` | 2.558 s | 2.558 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_8` | 2.659 s | 2.659 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_9` | 2.755 s | 2.755 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_10` | 2.852 s | 2.852 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_11` | 2.942 s | 2.942 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_12` | 3.041 s | 3.041 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_13` | 3.142 s | 3.142 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_14` | 3.244 s | 3.244 s |
| server | `laned.multiplication.sumcheck_round.reduction_13.source_14.slot_index.round_15` | 3.178 s | 3.177 s |
| server | `laned.reduction.reduction_13.source_14` | 42.668 s | 42.655 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_0` | 0.916 s | 0.916 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.ciphertext_index.round_1` | 0.925 s | 0.925 s |
| server | `laned.affine.slot_checkpoint.reduction_14.source_15.checkpoint_15.slot_index` | 0.037 s | 0.037 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_2` | 0.982 s | 0.982 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_3` | 1.054 s | 1.054 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_4` | 1.088 s | 1.088 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_5` | 1.123 s | 1.123 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_6` | 1.148 s | 1.148 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_7` | 1.180 s | 1.180 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_8` | 1.203 s | 1.203 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_9` | 1.233 s | 1.233 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_10` | 1.254 s | 1.254 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_11` | 1.283 s | 1.283 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_12` | 1.320 s | 1.320 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_13` | 1.340 s | 1.340 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_14` | 1.364 s | 1.364 s |
| server | `laned.affine.sumcheck_round.reduction_14.source_15.slot_index.round_15` | 1.396 s | 1.396 s |
| server | `laned.reduction.reduction_14.source_15` | 19.705 s | 19.702 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_0` | 1.686 s | 1.685 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.ciphertext_index.round_1` | 1.795 s | 1.794 s |
| server | `laned.multiplication.slot_checkpoint.reduction_15.source_16.checkpoint_16.slot_index` | 0.020 s | 0.020 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_2` | 1.934 s | 1.934 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_3` | 2.126 s | 2.125 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_4` | 2.249 s | 2.249 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_5` | 2.353 s | 2.353 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_6` | 2.460 s | 2.460 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_7` | 2.557 s | 2.557 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_8` | 2.651 s | 2.651 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_9` | 2.751 s | 2.750 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_10` | 2.851 s | 2.851 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_11` | 2.946 s | 2.946 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_12` | 3.048 s | 3.048 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_13` | 3.145 s | 3.145 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_14` | 3.247 s | 3.247 s |
| server | `laned.multiplication.sumcheck_round.reduction_15.source_16.slot_index.round_15` | 3.179 s | 3.179 s |
| server | `laned.reduction.reduction_15.source_16` | 42.619 s | 42.608 s |
| server | `laned.affine.slot_checkpoint.reduction_16.source_17.checkpoint_17.slot_index` | 0.001 s | 0.001 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_0` | 0.459 s | 0.459 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_1` | 0.570 s | 0.570 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_2` | 0.595 s | 0.595 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_3` | 0.625 s | 0.625 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_4` | 0.651 s | 0.650 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_5` | 0.680 s | 0.680 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_6` | 0.708 s | 0.707 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_7` | 0.736 s | 0.736 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_8` | 1.203 s | 1.203 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_9` | 1.238 s | 1.237 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_10` | 1.270 s | 1.270 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_11` | 1.289 s | 1.289 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_12` | 1.316 s | 1.316 s |
| server | `laned.affine.sumcheck_round.reduction_16.source_17.slot_index.round_13` | 1.352 s | 1.352 s |
| server | `laned.reduction.reduction_16.source_17` | 13.732 s | 13.729 s |
| server | `laned.gate_mle_opening` | 5 m 49.624 s | 5 m 49.585 s |

## Client computation

| Component | Wall | CPU |
|---|---:|---:|
| Per-request client computation | 2.165 s | 2.165 s |
| Input encryption | 0.725 s | 0.725 s |
| Output decryption | 0.001 s | 0.001 s |
| VCoED proof verification | 1.439 s | 1.439 s |
| ↳ GKR proof verification | 0.832 s | 0.832 s |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 0.237 s | 0.237 s |
| ↳↳ Plaintext GKR and affine gate-opening checks | 0.595 s | 0.595 s |
| ↳ Terminal input MLE | 0.005 s | 0.005 s |
| ↳ Spartan packing argument | 0.585 s | 0.585 s |
| ↳ Well-formedness noise checks | 0.017 s | 0.017 s |

Client computation is input encryption + output decryption + VCoED proof verification. Preprocessing RAM loading, transport, peer waiting, and the optional output-noise audit are excluded. Verification rows form a hierarchy: add siblings only. Packed transcript recovery includes signed-digit recomposition into logical plaintexts.

## Client verifier details

Transcript-packing verification and message recovery: **0.496 s wall**. Gate-MLE opening: **0.589 s wall**. These are nested diagnostic spans; they do not define the disjoint computation hierarchy above.

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
| client | `transcript_packing.verifier_statement` | 0.019 s | 0.019 s |
| client | `transcript_packing.spartan_verify` | 0.458 s | 0.458 s |
| client | `transcript_packing.threshold_checks` | 0.017 s | 0.017 s |
| client | `transcript_packing.unpack` | 0.002 s | 0.002 s |

## Server FHE operation ledger

| Server stage | Operation | Calls | Limb operations | Calls by RNS limbs |
| --- | --- | --- | --- | --- |
| `server_payload_evaluation` | `add` | 2,181,401 | 24,402,911 | `5:131067,8:250272,9:250314,10:250248,11:250246,12:250248,13:250200,14:250278,15:298528` |
| `server_payload_evaluation` | `add_plain` | 52,429 | 602,941 | `8:6553,9:6553,10:6553,11:6554,12:6554,13:6554,14:6554,15:6554` |
| `server_payload_evaluation` | `decrypt` | 0 | 0 | `none` |
| `server_payload_evaluation` | `encrypt` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_add` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_mul` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_mul_plain` | 0 | 0 | `none` |
| `server_payload_evaluation` | `logical_ext_sub` | 0 | 0 | `none` |
| `server_payload_evaluation` | `mod_switch` | 655,927 | 6,886,472 | `2:1,3:1,4:1,5:34,6:65565,7:65629,8:65629,9:65617,10:65605,11:65593,12:65581,13:65569,14:65557,15:65545` |
| `server_payload_evaluation` | `mul_no_relin` | 524,288 | 6,029,312 | `8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536,15:65536` |
| `server_payload_evaluation` | `mul_plain_scalar` | 0 | 0 | `none` |
| `server_payload_evaluation` | `mul_plain_vector` | 1,572,928 | 17,433,536 | `5:65536,8:196608,9:196608,10:196608,11:196608,12:196608,13:196608,14:196608,15:131136` |
| `server_payload_evaluation` | `negate` | 0 | 0 | `none` |
| `server_payload_evaluation` | `relinearize` | 524,288 | 6,029,312 | `8:65536,9:65536,10:65536,11:65536,12:65536,13:65536,14:65536,15:65536` |
| `server_payload_evaluation` | `rotate` | 0 | 0 | `none` |
| `server_payload_evaluation` | `sub` | 0 | 0 | `none` |
| `server_proving` | `add` | 175,001 | 829,134 | `1:18306,4:64671,6:92024` |
| `server_proving` | `add_plain` | 0 | 0 | `none` |
| `server_proving` | `decrypt` | 0 | 0 | `none` |
| `server_proving` | `encrypt` | 0 | 0 | `none` |
| `server_proving` | `logical_ext_add` | 2,849 | 15,204 | `4:945,6:1904` |
| `server_proving` | `logical_ext_mul` | 240 | 1,440 | `6:240` |
| `server_proving` | `logical_ext_mul_plain` | 866 | 4,456 | `4:370,6:496` |
| `server_proving` | `logical_ext_sub` | 350 | 1,848 | `4:126,6:224` |
| `server_proving` | `mod_switch` | 1,133 | 4,079 | `2:287,3:287,4:287,5:136,6:136` |
| `server_proving` | `mul_no_relin` | 15,392 | 92,352 | `6:15392` |
| `server_proving` | `mul_plain_scalar` | 2,014 | 11,380 | `4:352,6:1662` |
| `server_proving` | `mul_plain_vector` | 58,941 | 296,320 | `1:1148,4:25793,6:32000` |
| `server_proving` | `negate` | 16,737 | 52,192 | `1:8652,4:2485,6:5600` |
| `server_proving` | `relinearize` | 2,048 | 12,288 | `6:2048` |
| `server_proving` | `rotate` | 83,663 | 422,700 | `3:5,4:39623,5:17,6:44018` |
| `server_proving` | `sub` | 2,825 | 14,948 | `4:1001,6:1824` |

## Protocol artifacts

| Quantity | Measured value |
| --- | --- |
| Proving key / server preprocessing | 8,683,336,668 B (8.087 GiB) |
| Verifying key / client preprocessing | 111,745,927 B (106.569 MiB) |
| `server.wire.request_bytes` | 251,669,908 B (240.011 MiB) |
| `server.wire.response_bytes` | 90,846,991 B (86.638 MiB) |
| `client.wire.request_bytes` | 251,669,908 B (240.011 MiB) |
| `client.wire.response_bytes` | 90,846,991 B (86.638 MiB) |
| `server.proof.canonical.committed_gkr_bytes` | 44,378,884 B (42.323 MiB) |
| `server.proof.canonical.digit_packing_ciphertext_bytes` | 1,049,064 B (1.000 MiB) |
| `server.proof.canonical.spartan_packing_proof_bytes` | 13,684,501 B (13.051 MiB) |
| `server.proof.canonical.statement_and_metadata_bytes` | 46 B |
| `server.proof.canonical.total_bytes` | 90,584,415 B (86.388 MiB) |
| `server.proof.canonical.well_formedness_reveal_bytes` | 31,471,920 B (30.014 MiB) |
| `server.proof.committed_gkr.commitment_digest_bytes` | 13,776 B (13.453 KiB) |
| `server.proof.committed_gkr.gate_mle_opening_bytes` | 44,364,476 B (42.309 MiB) |
| `server.proof.response.total_bytes` | 90,846,991 B (86.638 MiB) |

## Memory and storage

| Quantity | Measured value |
| --- | --- |
| `setup.memory.client.admitted_peak_resident_bytes` | 3,866,949,118 B (3.601 GiB) |
| `setup.memory.concurrent.admitted_peak_resident_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.host_budget.exact_client_peak_resident_bytes` | 3,866,949,118 B (3.601 GiB) |
| `setup.memory.host_budget.exact_server_resident_cap_bytes` | 308,989,012,482 B (287.768 GiB) |
| `setup.memory.host_budget.gross_resident_budget_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.host_budget.operating_system_reserve_bytes` | 16,000,000,000 B (14.901 GiB) |
| `setup.memory.host_budget.page_cache_reserve_bytes` | 64,000,000,000 B (59.605 GiB) |
| `setup.memory.payload_storage.prefetch_page_cache_budget_bytes` | 536,870,912 B (512.000 MiB) |
| `setup.memory.payload_storage.transfer_buffer_reserve_bytes` | 402,653,184 B (384.000 MiB) |
| `setup.memory.payload_storage.writeback_window_bytes` | 0 B |
| `setup.memory.planner_preflight.client_peak_resident_reserve_bytes` | 3,883,723,328 B (3.617 GiB) |
| `setup.memory.planner_preflight.gross_resident_budget_bytes` | 312,855,961,600 B (291.370 GiB) |
| `setup.memory.planner_preflight.observed_physical_ram_bytes` | 392,855,961,600 B (365.876 GiB) |
| `setup.memory.planner_preflight.safety_reserve_bytes` | 80,000,000,000 B (74.506 GiB) |
| `setup.memory.planner_preflight.server_resident_cap_bytes` | 308,972,238,272 B (287.753 GiB) |
| `setup.memory.replay.admitted_peak_resident_bytes` | 86,321,871,808 B (80.394 GiB) |
| `setup.memory.replay.dense_multiplication_alias_cache_peak_resident_bytes` | 0 B |
| `setup.memory.server.admitted_peak_resident_bytes` | 308,989,012,482 B (287.768 GiB) |
| `setup.memory.server.affine_gate_preparation_workspace_upper_bytes` | 0 B |
| `setup.memory.server.common_resident_reserve_bytes` | 17,084,920,768 B (15.912 GiB) |
| `setup.memory.server.gate_mle_opening_workspace_upper_bytes` | 2,552,557,616 B (2.377 GiB) |
| `setup.memory.server.gate_mle_retained_prover_key_upper_bytes` | 10,373,482,416 B (9.661 GiB) |
| `setup.memory.server.laned_affine_workspace_reserve_bytes` | 1,248,067,584 B (1.162 GiB) |
| `setup.memory.server.multiplication_sort_buffer_limit_bytes` | 110,300,592,581 B (102.725 GiB) |
| `setup.memory.server.packing_only_resident_reserve_bytes` | 1,874,455,680 B (1.746 GiB) |
| `setup.memory.server.payload_gkr_only_resident_reserve_bytes` | 68,205,152,256 B (63.521 GiB) |
| `setup.memory.server.reduction_workspace_reserve_bytes` | 2,552,557,616 B (2.377 GiB) |
| `setup.memory.setup.peak_rss_bytes` | 17,386,864,640 B (16.193 GiB) |
| `setup.memory.setup.prepublication_admitted_peak_resident_bytes` | 23,496,993,617 B (21.883 GiB) |
| `setup.memory.setup.prepublication_observed_peak_rss_bytes` | 14,248,923,136 B (13.270 GiB) |
| `setup.memory.setup.prepublication_remaining_resident_reserve_bytes` | 9,248,070,481 B (8.613 GiB) |
| `server.memory.client.admitted_peak_resident_bytes` | 3,866,949,118 B (3.601 GiB) |
| `server.memory.concurrent.admitted_peak_resident_bytes` | 312,855,961,600 B (291.370 GiB) |
| `server.memory.gkr_multiplication_sort_peak_buffered_payload_bytes` | 12,584,288 B (12.001 MiB) |
| `server.memory.server.admitted_peak_resident_bytes` | 308,989,012,482 B (287.768 GiB) |
| `server.memory.server.multiplication_sort_buffer_limit_bytes` | 110,300,592,581 B (102.725 GiB) |
| `server.memory.server.peak_rss_bytes` | 226,182,086,656 B (210.648 GiB) |
| `server.memory.server_witness_packing.peak_mask_cache_ntt_bytes` | 32,212,254,720 B (30.000 GiB) |
| `client.memory.client.admitted_peak_resident_bytes` | 3,866,949,118 B (3.601 GiB) |
| `client.memory.client.peak_rss_bytes` | 1,873,047,552 B (1.744 GiB) |
| `server.storage.gkr_multiplication_sort_retained_temporary_bytes` | 0 B |
| `server.storage.gkr_peak_live_scratch_bytes` | 12,584,776 B (12.002 MiB) |
| `server.storage.packing.outer_assignment_physical_bytes` | 9,136,541,400 B (8.509 GiB) |
| `server.storage.packing.persistent_input_physical_bytes` | 11,904,784,814 B (11.087 GiB) |
| `server.storage.packing.preprocessing_validation_bytes` | 2,768,243,414 B (2.578 GiB) |
| `server.storage.packing.spartan_peak_live_bytes` | 477,032,941,396 B (444.272 GiB) |
| `server.storage.payload_replay_peak_live_physical_bytes` | 691,559,241,880 B (644.065 GiB) |
| `server.storage.payload_replay_peak_live_scratch_bytes` | 701,383,032,052 B (653.214 GiB) |
| `server.storage.payload_replay_total_reclaimed_physical_bytes` | 4,115,495,704,556 B (3.743 TiB) |
| `server.storage.server.admitted_peak_live_bytes` | 4,362,777,216,363 B (3.968 TiB) |

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
| Available at setup start | 10,400,778,850,304 B (9.459 TiB) at `2026-10-14T01:13:00Z` |
| Available at server start | 10,391,812,198,400 B (9.451 TiB) at `2026-10-14T01:44:13Z` |
