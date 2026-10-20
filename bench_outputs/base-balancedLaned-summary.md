<!-- laminate-benchmark-summary-v2 -->
# Laminate Base benchmark summary — target-balancedLaned

**PASS** — setup, server, and client completed, and the client accepted the proof.

## Highlights

| Highlight | Measured result |
| --- | --- |
| Laminate variant | Base |
| GKR layer transitions | One claim by selector interpolation |
| Payload profile | `target-balancedLaned` |
| Scalar gates | 17,179,869,184 (1,048,576 payload gates × 16,384 slots) |
| Initial ciphertext modulus (data primes only) | 430 bits across 11 data primes |
| Plaintext modulus | 65,537 |
| VCoED server wall time | 21h 56m 27.654s (78,987,654.087802 ms) |
| ↳ Payload computation | 2h 53m 46.513s (10,426,512.543035 ms) |
| ↳ GKR proving | 19h 2m 27.563s (68,547,563.137711 ms) |
| Per-request client computation | 5.660s (5,660.000331 ms) |
| Input encryption | 582.277 ms (582.277480 ms) |
| Output decryption | 0.927 ms (0.927372 ms) |
| VCoED proof verification | 5.077s (5,076.795479 ms) |
| ↳ GKR proof verification | 5.039s (5,038.737796 ms) |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 3.086s (3,086.221752 ms) |
| ↳↳ Plaintext GKR and affine gate-opening checks | 1.953s (1,952.516044 ms) |
| ↳ Terminal input MLE | 38.058 ms (38.057683 ms) |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | LaminateImpl/UniformBaseProofIngress/v1; 3 RNS limbs at every proof source |

## Server layer reductions

| Layer | Kind | Replay segment | Multiplication source build | Sumcheck rounds | Reduction total |
| --- | --- | --- | --- | --- | --- |
| 16 | affine | 0.037 ms (0.037 ms) wall / 0.036 ms (0.036 ms) CPU | — | 813.182 ms (813.182 ms) wall / 813.069 ms (813.069 ms) CPU | 2.781s (2,780.804 ms) wall / 2.714s (2,713.915 ms) CPU |
| 15 | multiplication | 0.014 ms (0.014 ms) wall / 0.014 ms (0.014 ms) CPU | 15m 49.439s (949,439.242 ms) wall / 14m 58.290s (898,289.612 ms) CPU | 1h 28m 51.453s (5,331,452.890 ms) wall / 1h 28m 51.090s (5,331,090.056 ms) CPU | 1h 46m 58.942s (6,418,941.707 ms) wall / 1h 46m 7.420s (6,367,419.742 ms) CPU |
| 14 | affine | 0.044 ms (0.044 ms) wall / 0.043 ms (0.043 ms) CPU | — | 24m 44.023s (1,484,022.805 ms) wall / 24m 43.925s (1,483,925.068 ms) CPU | 39m 32.430s (2,372,430.249 ms) wall / 38m 40.464s (2,320,463.528 ms) CPU |
| 13 | multiplication | 0.016 ms (0.016 ms) wall / 0.016 ms (0.016 ms) CPU | 29m 46.936s (1,786,935.555 ms) wall / 27m 36.569s (1,656,568.775 ms) CPU | 1h 29m 10.883s (5,350,882.799 ms) wall / 1h 29m 10.540s (5,350,540.497 ms) CPU | 2h 1m 17.877s (7,277,876.729 ms) wall / 1h 59m 7.147s (7,147,146.677 ms) CPU |
| 12 | affine | 0.033 ms (0.033 ms) wall / 0.032 ms (0.032 ms) CPU | — | 25m 9.205s (1,509,204.840 ms) wall / 25m 9.099s (1,509,098.594 ms) CPU | 37m 31.889s (2,251,888.842 ms) wall / 36m 50.038s (2,210,037.908 ms) CPU |
| 11 | multiplication | 0.018 ms (0.018 ms) wall / 0.018 ms (0.018 ms) CPU | 25m 10.547s (1,510,546.656 ms) wall / 23m 9.728s (1,389,727.643 ms) CPU | 1h 30m 3.254s (5,403,254.258 ms) wall / 1h 30m 2.916s (5,402,916.217 ms) CPU | 1h 57m 39.607s (7,059,607.147 ms) wall / 1h 55m 38.429s (6,938,429.106 ms) CPU |
| 10 | affine | 0.030 ms (0.030 ms) wall / 0.029 ms (0.029 ms) CPU | — | 24m 46.200s (1,486,199.657 ms) wall / 24m 46.092s (1,486,092.262 ms) CPU | 34m 41.808s (2,081,808.273 ms) wall / 34m 16.819s (2,056,818.799 ms) CPU |
| 9 | multiplication | 0.018 ms (0.018 ms) wall / 0.019 ms (0.019 ms) CPU | 19m 37.901s (1,177,901.273 ms) wall / 19m 3.638s (1,143,637.775 ms) CPU | 1h 28m 52.104s (5,332,103.854 ms) wall / 1h 28m 51.772s (5,331,772.174 ms) CPU | 1h 50m 51.010s (6,651,009.724 ms) wall / 1h 50m 16.085s (6,616,084.788 ms) CPU |
| 8 | affine | 0.031 ms (0.031 ms) wall / 0.030 ms (0.030 ms) CPU | — | 24m 58.811s (1,498,810.624 ms) wall / 24m 58.705s (1,498,704.647 ms) CPU | 32m 37.450s (1,957,449.846 ms) wall / 32m 29.171s (1,949,170.557 ms) CPU |
| 7 | multiplication | 0.011 ms (0.011 ms) wall / 0.011 ms (0.011 ms) CPU | 15m 57.169s (957,168.852 ms) wall / 15m 24.861s (924,860.959 ms) CPU | 1h 29m 43.673s (5,383,672.593 ms) wall / 1h 29m 43.328s (5,383,328.315 ms) CPU | 1h 48m 3.187s (6,483,186.855 ms) wall / 1h 47m 30.516s (6,450,515.975 ms) CPU |
| 6 | affine | 0.032 ms (0.032 ms) wall / 0.031 ms (0.031 ms) CPU | — | 25m 15.001s (1,515,001.318 ms) wall / 25m 14.897s (1,514,896.825 ms) CPU | 31m 17.917s (1,877,917.301 ms) wall / 31m 6.060s (1,866,060.128 ms) CPU |
| 5 | multiplication | 0.016 ms (0.016 ms) wall / 0.015 ms (0.015 ms) CPU | 12m 39.034s (759,033.825 ms) wall / 12m 12.157s (732,156.972 ms) CPU | 1h 28m 58.249s (5,338,248.986 ms) wall / 1h 28m 57.912s (5,337,912.241 ms) CPU | 1h 43m 57.164s (6,237,164.453 ms) wall / 1h 43m 29.932s (6,209,932.459 ms) CPU |
| 4 | affine | 0.034 ms (0.034 ms) wall / 0.033 ms (0.033 ms) CPU | — | 25m 12.360s (1,512,359.503 ms) wall / 25m 12.257s (1,512,256.997 ms) CPU | 29m 42.893s (1,782,892.880 ms) wall / 29m 28.562s (1,768,561.731 ms) CPU |
| 3 | multiplication | 0.014 ms (0.014 ms) wall / 0.014 ms (0.014 ms) CPU | 10m 3.679s (603,679.383 ms) wall / 9m 28.344s (568,344.049 ms) CPU | 1h 27m 32.138s (5,252,137.758 ms) wall / 1h 27m 31.804s (5,251,803.928 ms) CPU | 1h 40m 3.574s (6,003,574.367 ms) wall / 1h 39m 27.875s (5,967,875.369 ms) CPU |
| 2 | affine | 0.036 ms (0.036 ms) wall / 0.035 ms (0.035 ms) CPU | — | 24m 40.767s (1,480,767.398 ms) wall / 24m 40.663s (1,480,663.383 ms) CPU | 27m 55.085s (1,675,084.782 ms) wall / 27m 39.345s (1,659,344.815 ms) CPU |
| 1 | multiplication | 0.015 ms (0.015 ms) wall / 0.015 ms (0.015 ms) CPU | 7m 17.745s (437,745.170 ms) wall / 6m 40.408s (400,408.467 ms) CPU | 1h 26m 45.066s (5,205,066.398 ms) wall / 1h 26m 44.740s (5,204,740.294 ms) CPU | 1h 36m 28.142s (5,788,141.960 ms) wall / 1h 35m 50.449s (5,750,448.937 ms) CPU |
| 0 | affine | 0.039 ms (0.039 ms) wall / 0.038 ms (0.038 ms) CPU | — | 22m 31.077s (1,351,077.135 ms) wall / 22m 30.995s (1,350,995.278 ms) CPU | 23m 36.420s (1,416,420.204 ms) wall / 23m 36.328s (1,416,327.540 ms) CPU |

Reduction totals and replay segments are inclusive spans. Source-build and sumcheck columns explain time within those spans; the columns are not additive.

## Sumcheck round details

| Reduction layer | Source layer | Kind | Coordinate | Round | Side | Work units | Wall time | CPU time | CPU/wall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 16 | 17 | affine | ciphertext-index | 1/6 | — | — | 152.303 ms (152.303 ms) | 152.267 ms (152.267 ms) | 99.98% |
| 16 | 17 | affine | ciphertext-index | 2/6 | — | — | 132.843 ms (132.843 ms) | 132.822 ms (132.822 ms) | 99.98% |
| 16 | 17 | affine | ciphertext-index | 3/6 | — | — | 129.341 ms (129.341 ms) | 129.342 ms (129.342 ms) | 100.00% |
| 16 | 17 | affine | ciphertext-index | 4/6 | — | — | 131.680 ms (131.680 ms) | 131.655 ms (131.655 ms) | 99.98% |
| 16 | 17 | affine | ciphertext-index | 5/6 | — | — | 132.935 ms (132.935 ms) | 132.923 ms (132.923 ms) | 99.99% |
| 16 | 17 | affine | ciphertext-index | 6/6 | — | — | 134.079 ms (134.079 ms) | 134.060 ms (134.060 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 1/16 | — | 131,072 | 2m 24.311s (144,310.905 ms) | 2m 24.295s (144,294.560 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 2/16 | — | 131,072 | 22m 34.431s (1,354,431.452 ms) | 22m 34.339s (1,354,339.198 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 3/16 | — | 131,072 | 12m 46.750s (766,749.621 ms) | 12m 46.699s (766,698.785 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 4/16 | — | 131,072 | 8m 2.366s (482,366.387 ms) | 8m 2.334s (482,333.672 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 5/16 | — | 131,072 | 5m 40.180s (340,179.776 ms) | 5m 40.157s (340,157.290 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 6/16 | — | 131,072 | 4m 26.620s (266,620.264 ms) | 4m 26.602s (266,602.280 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 7/16 | — | 131,072 | 3m 47.722s (227,722.216 ms) | 3m 47.707s (227,706.736 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 8/16 | — | 131,072 | 3m 29.023s (209,022.807 ms) | 3m 29.009s (209,009.119 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 9/16 | — | 131,072 | 3m 19.364s (199,364.428 ms) | 3m 19.351s (199,351.420 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 10/16 | — | 131,072 | 3m 15.231s (195,230.960 ms) | 3m 15.218s (195,218.018 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 11/16 | — | 131,072 | 3m 12.466s (192,466.336 ms) | 3m 12.454s (192,453.748 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 12/16 | — | 131,072 | 3m 11.735s (191,735.287 ms) | 3m 11.722s (191,722.197 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 13/16 | — | 131,072 | 3m 11.154s (191,154.409 ms) | 3m 11.142s (191,141.919 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 14/16 | — | 131,072 | 3m 9.561s (189,561.460 ms) | 3m 9.549s (189,549.158 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 15/16 | — | 131,072 | 3m 10.269s (190,268.882 ms) | 3m 10.257s (190,256.623 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 16/16 | — | 131,072 | 3m 10.268s (190,267.700 ms) | 3m 10.255s (190,255.333 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 1/16 | — | — | 1m 32.510s (92,510.429 ms) | 1m 32.499s (92,498.518 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 2/16 | — | — | 1m 33.131s (93,130.513 ms) | 1m 33.123s (93,123.220 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 3/16 | — | — | 1m 31.581s (91,580.981 ms) | 1m 31.575s (91,575.326 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 4/16 | — | — | 1m 31.030s (91,029.948 ms) | 1m 31.024s (91,024.485 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 5/16 | — | — | 1m 35.346s (95,345.842 ms) | 1m 35.340s (95,340.096 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 6/16 | — | — | 1m 31.756s (91,756.303 ms) | 1m 31.751s (91,750.540 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 7/16 | — | — | 1m 29.728s (89,727.533 ms) | 1m 29.722s (89,721.918 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 8/16 | — | — | 1m 30.225s (90,225.316 ms) | 1m 30.220s (90,219.967 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 9/16 | — | — | 1m 29.955s (89,955.278 ms) | 1m 29.950s (89,949.916 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 10/16 | — | — | 1m 31.162s (91,162.313 ms) | 1m 31.157s (91,156.667 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 11/16 | — | — | 1m 31.068s (91,067.611 ms) | 1m 31.062s (91,062.216 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 12/16 | — | — | 1m 30.620s (90,620.041 ms) | 1m 30.615s (90,614.549 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 13/16 | — | — | 1m 32.415s (92,414.594 ms) | 1m 32.409s (92,409.185 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 14/16 | — | — | 1m 40.502s (100,502.182 ms) | 1m 40.496s (100,496.206 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 15/16 | — | — | 1m 39.808s (99,807.749 ms) | 1m 39.802s (99,801.588 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 16/16 | — | — | 1m 33.186s (93,186.172 ms) | 1m 33.181s (93,180.671 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 1/16 | — | 131,072 | 2m 24.207s (144,207.257 ms) | 2m 24.193s (144,193.379 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 2/16 | — | 131,072 | 22m 14.985s (1,334,984.734 ms) | 22m 14.902s (1,334,901.973 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 3/16 | — | 131,072 | 12m 48.045s (768,045.201 ms) | 12m 47.997s (767,996.771 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 4/16 | — | 131,072 | 8m 3.879s (483,878.855 ms) | 8m 3.848s (483,848.275 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 5/16 | — | 131,072 | 5m 42.394s (342,393.882 ms) | 5m 42.372s (342,371.579 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 6/16 | — | 131,072 | 4m 28.823s (268,823.280 ms) | 4m 28.806s (268,805.932 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 7/16 | — | 131,072 | 3m 53.106s (233,106.439 ms) | 3m 53.091s (233,091.412 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 8/16 | — | 131,072 | 3m 34.004s (214,003.853 ms) | 3m 33.990s (213,990.221 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 9/16 | — | 131,072 | 3m 23.940s (203,940.021 ms) | 3m 23.927s (203,927.195 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 10/16 | — | 131,072 | 3m 17.160s (197,159.716 ms) | 3m 17.148s (197,147.624 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 11/16 | — | 131,072 | 3m 15.836s (195,835.763 ms) | 3m 15.824s (195,823.523 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 12/16 | — | 131,072 | 3m 14.048s (194,048.091 ms) | 3m 14.036s (194,035.714 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 13/16 | — | 131,072 | 3m 13.396s (193,395.650 ms) | 3m 13.383s (193,383.250 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 14/16 | — | 131,072 | 3m 12.464s (192,463.598 ms) | 3m 12.452s (192,451.588 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 15/16 | — | 131,072 | 3m 12.423s (192,423.098 ms) | 3m 12.411s (192,410.887 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 16/16 | — | 131,072 | 3m 12.173s (192,173.361 ms) | 3m 12.161s (192,161.174 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 1/16 | — | — | 1m 40.074s (100,074.487 ms) | 1m 40.062s (100,061.702 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 2/16 | — | — | 1m 36.409s (96,409.136 ms) | 1m 36.400s (96,400.003 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 3/16 | — | — | 1m 33.697s (93,696.767 ms) | 1m 33.691s (93,690.956 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 4/16 | — | — | 1m 37.778s (97,777.807 ms) | 1m 37.772s (97,771.884 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 5/16 | — | — | 1m 34.575s (94,574.895 ms) | 1m 34.569s (94,569.038 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 6/16 | — | — | 1m 40.966s (100,965.745 ms) | 1m 40.960s (100,959.577 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 7/16 | — | — | 1m 31.828s (91,827.651 ms) | 1m 31.822s (91,821.864 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 8/16 | — | — | 1m 32.003s (92,002.672 ms) | 1m 31.997s (91,996.709 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 9/16 | — | — | 1m 40.671s (100,670.721 ms) | 1m 40.664s (100,664.271 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 10/16 | — | — | 1m 30.773s (90,773.040 ms) | 1m 30.767s (90,767.081 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 11/16 | — | — | 1m 32.057s (92,057.434 ms) | 1m 32.051s (92,051.308 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 12/16 | — | — | 1m 32.121s (92,121.079 ms) | 1m 32.115s (92,114.945 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 13/16 | — | — | 1m 31.761s (91,760.860 ms) | 1m 31.755s (91,754.645 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 14/16 | — | — | 1m 30.525s (90,524.769 ms) | 1m 30.519s (90,518.880 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 15/16 | — | — | 1m 33.661s (93,660.717 ms) | 1m 33.655s (93,654.557 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 16/16 | — | — | 1m 30.307s (90,307.060 ms) | 1m 30.301s (90,301.174 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 1/16 | — | 131,072 | 2m 34.859s (154,859.143 ms) | 2m 34.844s (154,843.566 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 2/16 | — | 131,072 | 22m 24.621s (1,344,621.109 ms) | 22m 24.538s (1,344,537.665 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 3/16 | — | 131,072 | 12m 59.703s (779,703.169 ms) | 12m 59.655s (779,654.831 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 4/16 | — | 131,072 | 8m 7.156s (487,155.929 ms) | 8m 7.126s (487,125.557 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 5/16 | — | 131,072 | 5m 44.254s (344,254.286 ms) | 5m 44.233s (344,233.128 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 6/16 | — | 131,072 | 4m 30.308s (270,308.116 ms) | 4m 30.291s (270,291.428 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 7/16 | — | 131,072 | 3m 54.260s (234,259.879 ms) | 3m 54.245s (234,245.038 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 8/16 | — | 131,072 | 3m 34.822s (214,821.516 ms) | 3m 34.808s (214,808.372 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 9/16 | — | 131,072 | 3m 25.239s (205,238.967 ms) | 3m 25.226s (205,226.401 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 10/16 | — | 131,072 | 3m 19.595s (199,594.853 ms) | 3m 19.583s (199,582.620 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 11/16 | — | 131,072 | 3m 17.162s (197,161.631 ms) | 3m 17.150s (197,149.966 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 12/16 | — | 131,072 | 3m 15.314s (195,314.371 ms) | 3m 15.303s (195,302.876 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 13/16 | — | 131,072 | 3m 13.996s (193,995.894 ms) | 3m 13.984s (193,984.366 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 14/16 | — | 131,072 | 3m 13.999s (193,999.305 ms) | 3m 13.988s (193,987.836 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 15/16 | — | 131,072 | 3m 13.910s (193,909.552 ms) | 3m 13.898s (193,897.802 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 16/16 | — | 131,072 | 3m 14.057s (194,056.538 ms) | 3m 14.045s (194,044.765 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 1/16 | — | — | 1m 31.090s (91,089.636 ms) | 1m 31.078s (91,078.126 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 2/16 | — | — | 1m 38.990s (98,989.793 ms) | 1m 38.978s (98,977.728 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 3/16 | — | — | 1m 31.688s (91,687.853 ms) | 1m 31.682s (91,682.334 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 4/16 | — | — | 1m 32.059s (92,058.855 ms) | 1m 32.053s (92,053.099 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 5/16 | — | — | 1m 31.218s (91,217.918 ms) | 1m 31.212s (91,212.376 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 6/16 | — | — | 1m 44.981s (104,980.865 ms) | 1m 44.975s (104,974.568 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 7/16 | — | — | 1m 30.552s (90,552.277 ms) | 1m 30.546s (90,546.166 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 8/16 | — | — | 1m 30.411s (90,411.071 ms) | 1m 30.405s (90,405.060 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 9/16 | — | — | 1m 31.269s (91,268.988 ms) | 1m 31.263s (91,262.969 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 10/16 | — | — | 1m 30.226s (90,226.260 ms) | 1m 30.220s (90,220.259 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 11/16 | — | — | 1m 34.941s (94,941.352 ms) | 1m 34.935s (94,934.956 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 12/16 | — | — | 1m 33.824s (93,823.550 ms) | 1m 33.817s (93,817.429 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 13/16 | — | — | 1m 30.410s (90,409.767 ms) | 1m 30.404s (90,403.785 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 14/16 | — | — | 1m 32.911s (92,910.689 ms) | 1m 32.904s (92,904.447 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 15/16 | — | — | 1m 31.127s (91,126.663 ms) | 1m 31.121s (91,120.716 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 16/16 | — | — | 1m 30.504s (90,504.120 ms) | 1m 30.498s (90,498.244 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 1/16 | — | 131,072 | 2m 27.501s (147,501.179 ms) | 2m 27.482s (147,481.932 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 2/16 | — | 131,072 | 22m 54.587s (1,374,587.357 ms) | 22m 54.508s (1,374,508.359 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 3/16 | — | 131,072 | 12m 50.497s (770,497.111 ms) | 12m 50.451s (770,450.659 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 4/16 | — | 131,072 | 8m 0.482s (480,482.275 ms) | 8m 0.453s (480,452.505 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 5/16 | — | 131,072 | 5m 36.217s (336,217.367 ms) | 5m 36.196s (336,196.231 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 6/16 | — | 131,072 | 4m 23.855s (263,854.694 ms) | 4m 23.838s (263,837.892 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 7/16 | — | 131,072 | 3m 47.417s (227,416.677 ms) | 3m 47.402s (227,402.190 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 8/16 | — | 131,072 | 3m 28.607s (208,606.510 ms) | 3m 28.594s (208,593.752 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 9/16 | — | 131,072 | 3m 18.669s (198,669.026 ms) | 3m 18.657s (198,656.994 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 10/16 | — | 131,072 | 3m 13.283s (193,282.908 ms) | 3m 13.271s (193,271.455 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 11/16 | — | 131,072 | 3m 10.324s (190,324.246 ms) | 3m 10.313s (190,312.796 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 12/16 | — | 131,072 | 3m 9.595s (189,595.064 ms) | 3m 9.583s (189,583.389 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 13/16 | — | 131,072 | 3m 8.230s (188,229.925 ms) | 3m 8.218s (188,218.496 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 14/16 | — | 131,072 | 3m 8.109s (188,108.865 ms) | 3m 8.097s (188,097.309 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 15/16 | — | 131,072 | 3m 7.563s (187,562.721 ms) | 3m 7.551s (187,551.354 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 16/16 | — | 131,072 | 3m 7.168s (187,167.929 ms) | 3m 7.157s (187,156.861 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 1/16 | — | — | 1m 39.922s (99,922.479 ms) | 1m 39.908s (99,907.547 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 2/16 | — | — | 1m 38.348s (98,347.701 ms) | 1m 38.338s (98,338.167 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 3/16 | — | — | 1m 39.505s (99,505.392 ms) | 1m 39.500s (99,499.532 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 4/16 | — | — | 1m 32.908s (92,908.143 ms) | 1m 32.903s (92,902.712 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 5/16 | — | — | 1m 35.407s (95,407.070 ms) | 1m 35.401s (95,401.471 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 6/16 | — | — | 1m 35.780s (95,780.043 ms) | 1m 35.774s (95,774.427 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 7/16 | — | — | 1m 30.034s (90,033.944 ms) | 1m 30.028s (90,028.099 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 8/16 | — | — | 1m 30.900s (90,899.595 ms) | 1m 30.894s (90,893.547 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 9/16 | — | — | 1m 30.876s (90,875.941 ms) | 1m 30.870s (90,870.110 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 10/16 | — | — | 1m 32.545s (92,545.390 ms) | 1m 32.539s (92,539.344 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 11/16 | — | — | 1m 30.882s (90,881.920 ms) | 1m 30.876s (90,876.111 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 12/16 | — | — | 1m 35.875s (95,875.299 ms) | 1m 35.869s (95,869.248 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 13/16 | — | — | 1m 33.644s (93,644.048 ms) | 1m 33.638s (93,638.236 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 14/16 | — | — | 1m 30.547s (90,547.497 ms) | 1m 30.542s (90,541.628 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 15/16 | — | — | 1m 30.029s (90,029.212 ms) | 1m 30.023s (90,023.400 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 16/16 | — | — | 1m 31.607s (91,606.949 ms) | 1m 31.601s (91,601.068 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 1/16 | — | 131,072 | 2m 32.043s (152,043.236 ms) | 2m 32.028s (152,027.549 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 2/16 | — | 131,072 | 22m 39.578s (1,359,578.353 ms) | 22m 39.496s (1,359,496.237 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 3/16 | — | 131,072 | 12m 48.629s (768,629.253 ms) | 12m 48.582s (768,581.978 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 4/16 | — | 131,072 | 8m 11.756s (491,756.455 ms) | 8m 11.726s (491,725.616 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 5/16 | — | 131,072 | 5m 41.008s (341,008.300 ms) | 5m 40.987s (340,986.923 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 6/16 | — | 131,072 | 4m 28.461s (268,461.074 ms) | 4m 28.444s (268,443.761 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 7/16 | — | 131,072 | 3m 51.401s (231,400.503 ms) | 3m 51.385s (231,385.116 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 8/16 | — | 131,072 | 3m 33.398s (213,398.187 ms) | 3m 33.384s (213,384.499 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 9/16 | — | 131,072 | 3m 22.743s (202,742.555 ms) | 3m 22.730s (202,729.611 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 10/16 | — | 131,072 | 3m 18.150s (198,149.622 ms) | 3m 18.137s (198,137.045 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 11/16 | — | 131,072 | 3m 14.825s (194,824.883 ms) | 3m 14.812s (194,812.173 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 12/16 | — | 131,072 | 3m 12.596s (192,595.523 ms) | 3m 12.583s (192,582.812 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 13/16 | — | 131,072 | 3m 12.535s (192,534.760 ms) | 3m 12.522s (192,522.475 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 14/16 | — | 131,072 | 3m 12.161s (192,161.484 ms) | 3m 12.149s (192,149.121 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 15/16 | — | 131,072 | 3m 11.834s (191,834.161 ms) | 3m 11.822s (191,821.902 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 16/16 | — | 131,072 | 3m 12.554s (192,554.243 ms) | 3m 12.541s (192,541.497 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 1/16 | — | — | 1m 41.835s (101,835.449 ms) | 1m 41.822s (101,822.412 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 2/16 | — | — | 1m 37.776s (97,776.105 ms) | 1m 37.767s (97,766.701 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 3/16 | — | — | 1m 32.148s (92,148.454 ms) | 1m 32.143s (92,142.967 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 4/16 | — | — | 1m 32.614s (92,614.327 ms) | 1m 32.609s (92,608.863 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 5/16 | — | — | 1m 31.545s (91,544.634 ms) | 1m 31.539s (91,539.185 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 6/16 | — | — | 1m 31.697s (91,696.517 ms) | 1m 31.691s (91,691.057 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 7/16 | — | — | 1m 32.270s (92,269.637 ms) | 1m 32.264s (92,263.517 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 8/16 | — | — | 1m 38.584s (98,584.019 ms) | 1m 38.578s (98,577.715 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 9/16 | — | — | 1m 36.014s (96,014.394 ms) | 1m 36.008s (96,008.477 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 10/16 | — | — | 1m 31.083s (91,083.014 ms) | 1m 31.077s (91,077.116 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 11/16 | — | — | 1m 31.282s (91,281.796 ms) | 1m 31.276s (91,275.929 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 12/16 | — | — | 1m 32.444s (92,443.871 ms) | 1m 32.438s (92,437.979 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 13/16 | — | — | 1m 34.560s (94,559.890 ms) | 1m 34.554s (94,553.970 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 14/16 | — | — | 1m 33.757s (93,757.027 ms) | 1m 33.751s (93,751.046 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 15/16 | — | — | 1m 43.675s (103,675.320 ms) | 1m 43.669s (103,669.052 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 16/16 | — | — | 1m 33.717s (93,716.863 ms) | 1m 33.711s (93,710.839 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 1/16 | — | 131,072 | 2m 29.848s (149,847.585 ms) | 2m 29.835s (149,835.065 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 2/16 | — | 131,072 | 22m 39.506s (1,359,506.110 ms) | 22m 39.426s (1,359,426.155 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 3/16 | — | 131,072 | 12m 41.513s (761,512.610 ms) | 12m 41.466s (761,466.062 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 4/16 | — | 131,072 | 8m 1.011s (481,010.627 ms) | 8m 0.981s (480,980.625 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 5/16 | — | 131,072 | 5m 36.655s (336,654.770 ms) | 5m 36.634s (336,633.857 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 6/16 | — | 131,072 | 4m 25.298s (265,298.410 ms) | 4m 25.281s (265,281.286 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 7/16 | — | 131,072 | 3m 50.006s (230,005.561 ms) | 3m 49.991s (229,990.648 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 8/16 | — | 131,072 | 3m 31.118s (211,117.668 ms) | 3m 31.104s (211,103.936 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 9/16 | — | 131,072 | 3m 21.945s (201,944.796 ms) | 3m 21.932s (201,931.853 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 10/16 | — | 131,072 | 3m 15.914s (195,914.066 ms) | 3m 15.901s (195,901.341 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 11/16 | — | 131,072 | 3m 13.101s (193,100.685 ms) | 3m 13.088s (193,087.847 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 12/16 | — | 131,072 | 3m 11.728s (191,727.500 ms) | 3m 11.715s (191,714.646 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 13/16 | — | 131,072 | 3m 10.393s (190,393.008 ms) | 3m 10.380s (190,380.360 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 14/16 | — | 131,072 | 3m 10.308s (190,307.762 ms) | 3m 10.295s (190,294.997 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 15/16 | — | 131,072 | 3m 10.294s (190,293.546 ms) | 3m 10.281s (190,281.467 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 16/16 | — | 131,072 | 3m 9.614s (189,614.281 ms) | 3m 9.602s (189,602.096 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 1/16 | — | — | 1m 35.069s (95,069.386 ms) | 1m 35.057s (95,057.216 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 2/16 | — | — | 1m 31.567s (91,567.237 ms) | 1m 31.557s (91,556.591 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 3/16 | — | — | 1m 38.921s (98,921.047 ms) | 1m 38.915s (98,915.326 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 4/16 | — | — | 1m 39.021s (99,021.307 ms) | 1m 39.016s (99,015.548 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 5/16 | — | — | 1m 29.921s (89,921.313 ms) | 1m 29.916s (89,915.872 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 6/16 | — | — | 1m 29.418s (89,418.376 ms) | 1m 29.413s (89,412.861 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 7/16 | — | — | 1m 34.705s (94,705.288 ms) | 1m 34.700s (94,699.556 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 8/16 | — | — | 1m 31.894s (91,893.848 ms) | 1m 31.888s (91,888.315 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 9/16 | — | — | 1m 34.539s (94,538.966 ms) | 1m 34.533s (94,533.034 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 10/16 | — | — | 1m 31.557s (91,556.642 ms) | 1m 31.551s (91,551.092 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 11/16 | — | — | 1m 31.338s (91,337.721 ms) | 1m 31.332s (91,332.180 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 12/16 | — | — | 1m 33.910s (93,909.813 ms) | 1m 33.904s (93,904.177 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 13/16 | — | — | 1m 41.016s (101,015.582 ms) | 1m 41.010s (101,009.514 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 14/16 | — | — | 1m 34.046s (94,045.532 ms) | 1m 34.040s (94,039.829 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 15/16 | — | — | 1m 29.923s (89,923.427 ms) | 1m 29.918s (89,918.061 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 16/16 | — | — | 1m 45.514s (105,514.017 ms) | 1m 45.508s (105,507.825 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 1/16 | — | 131,072 | 2m 35.980s (155,979.614 ms) | 2m 35.969s (155,969.049 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 2/16 | — | 131,072 | 22m 6.033s (1,326,032.903 ms) | 22m 5.951s (1,325,950.999 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 3/16 | — | 131,072 | 12m 39.068s (759,067.897 ms) | 12m 39.019s (759,019.085 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 4/16 | — | 131,072 | 7m 50.498s (470,497.652 ms) | 7m 50.467s (470,467.422 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 5/16 | — | 131,072 | 5m 33.118s (333,118.404 ms) | 5m 33.097s (333,096.809 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 6/16 | — | 131,072 | 4m 21.990s (261,989.524 ms) | 4m 21.972s (261,972.450 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 7/16 | — | 131,072 | 3m 45.695s (225,695.443 ms) | 3m 45.681s (225,680.980 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 8/16 | — | 131,072 | 3m 26.993s (206,992.603 ms) | 3m 26.978s (206,977.922 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 9/16 | — | 131,072 | 3m 18.267s (198,267.234 ms) | 3m 18.254s (198,254.406 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 10/16 | — | 131,072 | 3m 12.546s (192,546.045 ms) | 3m 12.534s (192,533.788 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 11/16 | — | 131,072 | 3m 9.189s (189,188.635 ms) | 3m 9.177s (189,176.903 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 12/16 | — | 131,072 | 3m 7.576s (187,575.790 ms) | 3m 7.564s (187,564.140 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 13/16 | — | 131,072 | 3m 6.738s (186,737.926 ms) | 3m 6.726s (186,725.998 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 14/16 | — | 131,072 | 3m 6.042s (186,041.707 ms) | 3m 6.030s (186,030.057 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 15/16 | — | 131,072 | 3m 6.328s (186,328.213 ms) | 3m 6.317s (186,316.892 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 16/16 | — | 131,072 | 3m 6.078s (186,078.169 ms) | 3m 6.067s (186,067.028 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 1/16 | — | — | 1m 31.231s (91,230.566 ms) | 1m 31.217s (91,216.875 ms) | 99.98% |
| 2 | 3 | affine | ciphertext-index | 2/16 | — | — | 1m 30.527s (90,527.021 ms) | 1m 30.515s (90,515.102 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 3/16 | — | — | 1m 30.915s (90,915.124 ms) | 1m 30.910s (90,909.624 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 4/16 | — | — | 1m 40.250s (100,249.958 ms) | 1m 40.244s (100,243.872 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 5/16 | — | — | 1m 29.630s (89,629.734 ms) | 1m 29.625s (89,624.537 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 6/16 | — | — | 1m 30.345s (90,344.959 ms) | 1m 30.340s (90,339.501 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 7/16 | — | — | 1m 31.999s (91,999.403 ms) | 1m 31.994s (91,993.858 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 8/16 | — | — | 1m 30.681s (90,680.743 ms) | 1m 30.675s (90,675.114 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 9/16 | — | — | 1m 34.342s (94,342.349 ms) | 1m 34.337s (94,336.671 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 10/16 | — | — | 1m 29.903s (89,902.639 ms) | 1m 29.897s (89,897.097 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 11/16 | — | — | 1m 33.430s (93,430.011 ms) | 1m 33.424s (93,424.040 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 12/16 | — | — | 1m 31.282s (91,282.221 ms) | 1m 31.277s (91,276.721 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 13/16 | — | — | 1m 29.405s (89,405.337 ms) | 1m 29.400s (89,400.290 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 14/16 | — | — | 1m 35.332s (95,331.932 ms) | 1m 35.326s (95,326.205 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 15/16 | — | — | 1m 40.319s (100,318.800 ms) | 1m 40.313s (100,312.762 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 16/16 | — | — | 1m 31.177s (91,176.600 ms) | 1m 31.171s (91,171.114 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 1/16 | — | 131,072 | 2m 37.985s (157,985.217 ms) | 2m 37.974s (157,974.452 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 2/16 | — | 131,072 | 21m 52.217s (1,312,216.980 ms) | 21m 52.138s (1,312,137.711 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 3/16 | — | 131,072 | 12m 27.420s (747,420.071 ms) | 12m 27.373s (747,372.592 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 4/16 | — | 131,072 | 7m 48.672s (468,671.621 ms) | 7m 48.641s (468,640.922 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 5/16 | — | 131,072 | 5m 28.164s (328,163.544 ms) | 5m 28.143s (328,142.589 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 6/16 | — | 131,072 | 4m 18.160s (258,160.399 ms) | 4m 18.144s (258,143.710 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 7/16 | — | 131,072 | 3m 43.505s (223,504.996 ms) | 3m 43.491s (223,490.732 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 8/16 | — | 131,072 | 3m 25.622s (205,621.779 ms) | 3m 25.609s (205,608.803 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 9/16 | — | 131,072 | 3m 15.942s (195,941.609 ms) | 3m 15.929s (195,929.455 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 10/16 | — | 131,072 | 3m 10.999s (190,998.751 ms) | 3m 10.987s (190,987.077 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 11/16 | — | 131,072 | 3m 7.911s (187,911.280 ms) | 3m 7.900s (187,899.724 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 12/16 | — | 131,072 | 3m 6.401s (186,401.173 ms) | 3m 6.390s (186,389.529 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 13/16 | — | 131,072 | 3m 5.689s (185,688.863 ms) | 3m 5.677s (185,677.464 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 14/16 | — | 131,072 | 3m 5.259s (185,258.784 ms) | 3m 5.247s (185,247.439 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 15/16 | — | 131,072 | 3m 6.071s (186,070.681 ms) | 3m 6.059s (186,059.027 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 16/16 | — | 131,072 | 3m 5.051s (185,050.649 ms) | 3m 5.039s (185,039.068 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 1/16 | — | — | 18.852s (18,852.105 ms) | 18.849s (18,848.554 ms) | 99.98% |
| 0 | 1 | affine | ciphertext-index | 2/16 | — | — | 1m 28.575s (88,574.810 ms) | 1m 28.570s (88,569.792 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 3/16 | — | — | 1m 28.327s (88,326.730 ms) | 1m 28.321s (88,321.499 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 4/16 | — | — | 1m 28.774s (88,773.902 ms) | 1m 28.769s (88,768.779 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 5/16 | — | — | 1m 28.900s (88,900.322 ms) | 1m 28.895s (88,895.087 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 6/16 | — | — | 1m 28.429s (88,428.606 ms) | 1m 28.424s (88,423.507 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 7/16 | — | — | 1m 29.093s (89,093.485 ms) | 1m 29.088s (89,088.468 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 8/16 | — | — | 1m 29.475s (89,474.903 ms) | 1m 29.469s (89,469.421 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 9/16 | — | — | 1m 28.748s (88,747.696 ms) | 1m 28.743s (88,742.701 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 10/16 | — | — | 1m 28.725s (88,724.771 ms) | 1m 28.720s (88,719.531 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 11/16 | — | — | 1m 28.563s (88,563.460 ms) | 1m 28.558s (88,558.221 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 12/16 | — | — | 1m 28.736s (88,735.726 ms) | 1m 28.730s (88,730.399 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 13/16 | — | — | 1m 28.804s (88,804.264 ms) | 1m 28.799s (88,798.988 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 14/16 | — | — | 1m 29.329s (89,328.687 ms) | 1m 29.323s (89,323.160 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 15/16 | — | — | 1m 28.932s (88,931.662 ms) | 1m 28.926s (88,926.394 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 16/16 | — | — | 1m 28.816s (88,816.006 ms) | 1m 28.811s (88,810.777 ms) | 99.99% |

Round numbers are displayed one-based; the telemetry stores zero-based round indices. These rows are the individual spans summed into each layer's `Sumcheck rounds` cell above.

## Client computation

| Component | Wall | CPU |
| --- | --- | --- |
| Per-request client computation | 5.660s (5,660.000331 ms) | 5.659s (5,658.758000 ms) |
| Input encryption | 582.277 ms (582.277480 ms) | 582.201 ms (582.201000 ms) |
| Output decryption | 0.927 ms (0.927372 ms) | 0.928 ms (0.928000 ms) |
| VCoED proof verification | 5.077s (5,076.795479 ms) | 5.076s (5,075.629000 ms) |
| ↳ GKR proof verification | 5.039s (5,038.737796 ms) | 5.038s (5,037.571000 ms) |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 3.086s (3,086.221752 ms) | 3.086s (3,085.972000 ms) |
| ↳↳ Plaintext GKR and affine gate-opening checks | 1.953s (1,952.516044 ms) | 1.952s (1,951.599000 ms) |
| ↳ Terminal input MLE | 38.058 ms (38.057683 ms) | 38.058 ms (38.058000 ms) |

Client computation is input encryption + output decryption + VCoED proof verification. Preprocessing RAM loading, session binding, transport, and peer waiting are excluded. Verification rows form a hierarchy: add siblings only.

## Client verifier details

| Verifier span | Circuit layer | Kind | Wall time | CPU time | CPU/wall |
| --- | --- | --- | --- | --- | --- |
| Decrypt and unpack proof messages | — | all messages | 1.733s (1,733.314690 ms) | 1.733s (1,733.239000 ms) | 100.00% |
| Verify layer reduction 1 | 0 | affine | 219.859 ms (219.859390 ms) | 219.838 ms (219.838000 ms) | 99.99% |
| Verify layer reduction 2 | 1 | multiplication | 388.687 ms (388.687270 ms) | 388.678 ms (388.678000 ms) | 100.00% |
| Verify layer reduction 3 | 2 | affine | 213.968 ms (213.967684 ms) | 213.968 ms (213.968000 ms) | 100.00% |
| Verify layer reduction 4 | 3 | multiplication | 387.133 ms (387.132505 ms) | 387.086 ms (387.086000 ms) | 99.99% |
| Verify layer reduction 5 | 4 | affine | 213.439 ms (213.438828 ms) | 213.385 ms (213.385000 ms) | 99.97% |
| Verify layer reduction 6 | 5 | multiplication | 387.964 ms (387.963636 ms) | 387.942 ms (387.942000 ms) | 99.99% |
| Verify layer reduction 7 | 6 | affine | 212.739 ms (212.739355 ms) | 212.740 ms (212.740000 ms) | 100.00% |
| Verify layer reduction 8 | 7 | multiplication | 387.404 ms (387.404225 ms) | 387.370 ms (387.370000 ms) | 99.99% |
| Verify layer reduction 9 | 8 | affine | 213.584 ms (213.584033 ms) | 213.575 ms (213.575000 ms) | 100.00% |
| Verify layer reduction 10 | 9 | multiplication | 386.650 ms (386.649691 ms) | 386.639 ms (386.639000 ms) | 100.00% |
| Verify layer reduction 11 | 10 | affine | 213.880 ms (213.880300 ms) | 213.559 ms (213.559000 ms) | 99.85% |
| Verify layer reduction 12 | 11 | multiplication | 387.464 ms (387.464356 ms) | 387.441 ms (387.441000 ms) | 99.99% |
| Verify layer reduction 13 | 12 | affine | 212.652 ms (212.652434 ms) | 212.638 ms (212.638000 ms) | 99.99% |
| Verify layer reduction 14 | 13 | multiplication | 387.438 ms (387.438234 ms) | 387.176 ms (387.176000 ms) | 99.93% |
| Verify layer reduction 15 | 14 | affine | 213.338 ms (213.338034 ms) | 213.339 ms (213.339000 ms) | 100.00% |
| Verify layer reduction 16 | 15 | multiplication | 389.733 ms (389.733185 ms) | 389.704 ms (389.704000 ms) | 99.99% |
| Verify layer reduction 17 | 16 | affine | 95.660 ms (95.659809 ms) | 95.660 ms (95.660000 ms) | 100.00% |
| Finish Gate-MLE opening | — | terminal | 118.892 ms (118.891544 ms) | 118.586 ms (118.586000 ms) | 99.74% |

Layer-reduction and terminal-opening spans are nested inside the proof-verification timer and are non-additive.

## Server FHE operation ledger

| Operation | Payload evaluation | GKR proving |
| --- | --- | --- |
| Negate | 0 calls; 0 limb-ops; RNS none | 7,341,547 calls; 22,024,641 limb-ops; RNS 3:7341547 |
| Ciphertext add | 471,859 calls; 3,244,043 limb-ops; RNS 3:65535,4:50790,5:50790,6:50790,7:50790,8:50791,9:50791,10:50791,11:50791 | 367,897,082 calls; 1,103,691,246 limb-ops; RNS 3:367897082 |
| Ciphertext subtract | 0 calls; 0 limb-ops; RNS none | 524,288 calls; 1,572,864 limb-ops; RNS 3:524288 |
| Ciphertext multiply (before relinearization) | 524,288 calls; 3,932,160 limb-ops; RNS 4:65536,5:65536,6:65536,7:65536,8:65536,9:65536,10:65536,11:65536 | 34,077,584 calls; 102,232,752 limb-ops; RNS 3:34077584 |
| Relinearize | 524,288 calls; 3,932,160 limb-ops; RNS 4:65536,5:65536,6:65536,7:65536,8:65536,9:65536,10:65536,11:65536 | 2,048 calls; 6,144 limb-ops; RNS 3:2048 |
| Add plaintext | 52,429 calls; 393,225 limb-ops; RNS 4:6553,5:6553,6:6553,7:6554,8:6554,9:6554,10:6554,11:6554 | 7 calls; 21 limb-ops; RNS 3:7 |
| Multiply by scalar plaintext | 0 calls; 0 limb-ops; RNS none | 339,013,091 calls; 1,017,039,273 limb-ops; RNS 3:339013091 |
| Multiply by vector plaintext | 0 calls; 0 limb-ops; RNS none | 17,040 calls; 51,120 limb-ops; RNS 3:17040 |
| Modulus switch | 524,288 calls; 3,932,160 limb-ops; RNS 4:65536,5:65536,6:65536,7:65536,8:65536,9:65536,10:65536,11:65536 | 5,744,228 calls; 35,124,318 limb-ops; RNS 2:4392,3:4392,4:1376385,5:1187970,6:999555,7:811140,8:622724,9:434307,10:245890,11:57473 |
| Logical extension-field add | 0 calls; 0 limb-ops; RNS none | 524,033 calls; 1,572,099 limb-ops; RNS 3:524033 |
| Logical extension-field multiply | 0 calls; 0 limb-ops; RNS none | 524,272 calls; 1,572,816 limb-ops; RNS 3:524272 |
| Logical extension-field plaintext multiply | 0 calls; 0 limb-ops; RNS none | 524,538 calls; 1,573,614 limb-ops; RNS 3:524538 |

A by-RNS entry `k:c` means `c` calls executed with `k` data limbs. All-zero operations are omitted. Logical extension-field rows describe wrapper operations and are not additive to the underlying SEAL primitive rows. Operation counts show the arithmetic schedule; CPU/wall ratios and profiling are needed to attribute elapsed time.

## Protocol artifacts

| Direction | Artifact | Size |
| --- | --- | --- |
| Client → server | `cli-to-srv-request.bin` | 176.01 MiB (184,561,043 bytes) |
| Server → client | `srv-to-cli-response.bin` | 1.08 GiB (1,163,431,930 bytes) |
| Both directions | One request plus one response | 1.26 GiB (1,347,992,973 bytes) |

| Response/proof component | Size |
| --- | --- |
| Complete server response | 1.08 GiB (1,163,431,930 bytes) |
| Encrypted-output statement (metadata and ciphertext) | 768.25 KiB (786,684 bytes) |
| Response envelope header | 43 bytes |
| Public binding digests | 128 bytes |
| Proof-length prefix | 8 bytes |
| Serialized proof transport | 1.08 GiB (1,162,645,067 bytes) |
| Proof statement and metadata | 370 bytes |
| Sumcheck round messages | 1.02 GiB (1,099,662,732 bytes) |
| Terminal proof messages | 50.03 MiB (52,464,825 bytes) |
| Partial Gate-MLE values | 3.38 MiB (3,539,016 bytes) |
| Gate-MLE opening | 6.65 MiB (6,978,124 bytes) |

The byte counts describe canonical files on local storage; they do not include network latency or throughput. There is no second claim/proof round trip and no plaintext output claim is transmitted: the client decrypts the output and reconstructs its verification claim locally.

## Memory and storage

| Resource | Meaning | Size |
| --- | --- | --- |
| Setup peak RSS | measured setup-process peak | 1.13 GiB (1,208,893,440 bytes) |
| Server peak RSS | measured server-process peak | 129.01 GiB (138,519,334,912 bytes) |
| Client peak RSS | measured client-process peak | 2.84 GiB (3,050,360,832 bytes) |
| Server preprocessing | serialized reusable server state | 36.00 MiB (37,750,536 bytes) |
| Client preprocessing | serialized client secret state | 115.13 MiB (120,722,927 bytes) |
| Shared setup record | public setup identity and parameters | 4.75 KiB (4,866 bytes) |
| Retained run artifacts | measured before summary generation | 55.74 GiB (59,847,682,954 bytes) |
| Peak payload/checkpoint artifacts | measured controlled peak; excludes persistent files | 2.44 TiB (2,682,863,286,031 bytes) |
| Peak GKR multiplication scratch | measured controlled peak; excludes persistent files | 90.02 GiB (96,660,652,580 bytes) |
| Sampled server peak live local storage | whole-role measurement | not reported |
| Predicted/admitted peak resident RAM | capacity-model bound | 269.54 GiB (289,415,194,282 bytes) |
| Operating-system RAM reserve | fixed host headroom | 14.90 GiB (16,000,000,000 bytes) |
| Page-cache RAM reserve | fixed sequential-I/O headroom | 59.60 GiB (64,000,000,000 bytes) |
| Payload transfer-buffer reserve | up to two input slabs plus one output slab | 384.00 MiB (402,653,184 bytes) |
| Setup-selected dense multiplication alias-cache peak | relation-scoped decoded cache plus one staging value; included in the selected replay resident peak | 243.43 GiB (261,380,201,104 bytes) |
| Selected replay resident peak | capacity-model bound including any admitted relation cache | 243.43 GiB (261,380,201,104 bytes) |
| Payload writeback window | explicit foreground wait window for ephemeral payload scratch | 0 bytes |
| Ephemeral payload writeback policy | Linux submits background writeback without explicit foreground wait/drain; portable fallback uses ordinary buffered writes | linux-submit-only-with-buffered-portable-fallback |
| Configured writeback range-hint ceiling | maximum range passed to one advisory submission | 16.00 MiB (16,777,216 bytes) |
| Sequential payload readers | concurrent readers charged by the payload plan | 2 |
| Prefetch logical window per reader | bounded page-cache advice; not process-resident memory | 256.00 MiB (268,435,456 bytes) |
| Payload prefetch page-cache budget | reader count times logical window; inside page-cache reserve | 512.00 MiB (536,870,912 bytes) |
| Configured prefetch-request ceiling | Linux further qualifies requests from backing-device BDI read-ahead | 16.00 MiB (16,777,216 bytes) |
| Multiplication-source sort buffer | host-adaptive limit; allocated only as the current layer needs | 125.56 GiB (134,815,122,957 bytes) |
| Multiplication-source sort passes | initial runs / merge passes | 0 / 0 |
| Multiplication-source peak buffered payload | measured one-shot reorder arena | 90.02 GiB (96,658,686,124 bytes) |
| Multiplication-source temporary bytes retained | must be zero before artifact consumption | 0 bytes |
| Predicted/admitted peak live disk | capacity-model bound | 2.78 TiB (3,051,808,841,168 bytes) |
| Selected replay checkpoint bytes | formula-derived replay plan | 2.48 TiB (2,732,005,859,615 bytes) |
| Selected replay peak live bytes | formula-derived replay plan | 2.59 TiB (2,842,421,582,424 bytes) |
| Selected replay checkpoints | formula-derived replay plan | 17 |
| Replay-plan objective | checkpoint selection policy | minimum-replay-work |
| Cumulative payload-work factor | forward evaluation plus replay / forward evaluation | 1.000000x |
| Setup-start available-disk requirement | capacity-model bound including client preprocessing and reserve | 2.87 TiB (3,153,956,324,816 bytes) |
| Configured live-server disk cap | admission ceiling; not predicted allocation | 9.38 TiB (10,308,083,992,576 bytes) |

Measured RSS rows are role-specific process peaks. Artifact peaks are separate controlled components and must not be added unless their lifetimes overlap. Capacity rows, when present, are conservative whole-server admission bounds.

| Target storage provenance | Recorded value |
| --- | --- |
| Backend | shared-root-filesystem |
| Artifact root | /var/lib/laminate-storage/laminate-bench |
| Mount | /dev/nvme0n1p1 on / |
| Filesystem | ext4 (rw,relatime,discard,errors=remount-ro,commit=30) |
| Filesystem capacity | 9.47 TiB (10,414,378,115,072 bytes) |
| Shared storage directory | /var/lib/laminate-storage |
| Shares OS filesystem and I/O | **true — benchmark artifacts and the operating system share the root filesystem and I/O path.** |
| Available at setup start | 9.47 TiB (10,410,231,529,472 bytes) at 2026-10-06T16:45:42Z |
| Available at server start | 9.41 TiB (10,351,733,649,408 bytes) at 2026-10-06T18:01:44Z |

These immutable snapshots were captured by the GCP wrapper outside the measured setup and server timers. They identify the filesystem used by all run artifacts; the available-byte samples are boundary observations, not a live-storage high-water mark.

| Host-derived planner budget | Recorded value |
| --- | --- |
| Observed available disk | 9.47 TiB (10,410,231,476,224 bytes) |
| Reserved free disk | 93.13 GiB (100,000,000,000 bytes) |
| Gross live-artifact budget | 9.38 TiB (10,310,231,476,224 bytes) |
| Persistent client preprocessing reserve | 2.00 GiB (2,147,483,648 bytes) |
| Server checkpoint/replay budget | 9.38 TiB (10,308,083,992,576 bytes) |
| Observed physical RAM | 365.88 GiB (392,855,961,600 bytes) |
| Reserved host RAM | 74.51 GiB (80,000,000,000 bytes) |
| Gross resident budget after host reserve | 291.37 GiB (312,855,961,600 bytes) |
| Concurrent client resident reserve | 21.83 GiB (23,440,767,318 bytes) |
| Net server resident cap | 269.54 GiB (289,415,194,282 bytes) |

The payload checkpoint plan is selected from this setup-time capacity observation. Workload and cryptographic parameters do not change with the host.

## Provenance

| Field | Value |
| --- | --- |
| Setup result | /var/lib/laminate-storage/laminate-bench/runs/base-target-balancedLaned-20261006T164542Z-60945/shared/setup-result.txt |
| Server result | /var/lib/laminate-storage/laminate-bench/runs/base-target-balancedLaned-20261006T164542Z-60945/server/result.txt |
| Client result | /var/lib/laminate-storage/laminate-bench/runs/base-target-balancedLaned-20261006T164542Z-60945/client/result.txt |
| Setup format | laminate-benchmark-setup-v1 |
| Server format | laminate-benchmark-server-v1 |
| Client format | laminate-benchmark-client-v2 |
| Variant | base |
| Profile | target-balancedLaned |
| Trace execution | file-backed-checkpoint-replay |
| Initial data modulus | 430 bits across 11 data primes |
| Key modulus | 463 bits (data and special prime) |
| Build type | Release |
| Compiler | GNU 15.2.0 |
| SEAL version | 4.1.2 |
| SEAL acceleration | intel-hexl-runtime-dispatch |
| SHA-256 acceleration | openssl |
| Operating system | Linux 7.0.0-1013-gcp x86_64 |
| CPU | INTEL(R) XEON(R) PLATINUM 8581C CPU @ 2.30GHz |
| Core topology | 24 physical / 24 logical |
| Setup CPU affinity | 0,1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 |
| Setup workers | 23 |
| Server pinned logical CPU | 0 |
| Client pinned logical CPU | 1 |
| Setup threading | setup-worker-pool |
| Online threading | single-cpu-process |
| AVX2 available | yes |
| AVX-512F available | yes |
| AVX-512DQ available | yes |
| AVX-512IFMA available | yes |
