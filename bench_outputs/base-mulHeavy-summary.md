<!-- laminate-benchmark-summary-v2 -->
# Laminate Base benchmark summary — target-mulHeavyPyramid

**PASS** — setup, server, and client completed, and the client accepted the proof.

## Highlights

| Highlight | Measured result |
| --- | --- |
| Laminate variant | Base |
| GKR layer transitions | One claim by selector interpolation |
| Payload profile | `target-mulHeavyPyramid` |
| Scalar gates | 17,179,869,184 (1,048,576 payload gates × 16,384 slots) |
| Initial ciphertext modulus (data primes only) | 490 bits across 11 data primes |
| Plaintext modulus | 65,537 |
| VCoED server wall time | 54h 58m 53.249s (197,933,249.163621 ms) |
| ↳ Payload computation | 7h 30m 1.629s (27,001,629.130752 ms) |
| ↳ GKR proving | 47h 28m 31.124s (170,911,124.468250 ms) |
| Per-request client computation | 5.612s (5,612.240903 ms) |
| Input encryption | 585.255 ms (585.255378 ms) |
| Output decryption | 1.027 ms (1.027203 ms) |
| VCoED proof verification | 5.026s (5,025.958322 ms) |
| ↳ GKR proof verification | 4.987s (4,986.968783 ms) |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 2.967s (2,967.052248 ms) |
| ↳↳ Plaintext GKR and affine gate-opening checks | 2.020s (2,019.916535 ms) |
| ↳ Terminal input MLE | 38.990 ms (38.989539 ms) |
| GCP VM and storage | `c4-highmem-48`; 10,000-GB Hyperdisk Balanced; 2,400 MiB/s throughput; 150,000 IOPS (current campaign reference configuration) |
| Proof-ingress schedule | LaminateImpl/UniformBaseProofIngress/v1; 3 RNS limbs at every proof source |

## Server layer reductions

| Layer | Kind | Replay segment | Multiplication source build | Sumcheck rounds | Reduction total |
| --- | --- | --- | --- | --- | --- |
| 16 | affine | 0.084 ms (0.084 ms) wall / 0.082 ms (0.082 ms) CPU | — | 54.777s (54,777.451 ms) wall / 54.774s (54,773.779 ms) CPU | 28m 36.488s (1,716,488.135 ms) wall / 28m 36.346s (1,716,346.203 ms) CPU |
| 15 | multiplication | 0.013 ms (0.013 ms) wall / 0.014 ms (0.014 ms) CPU | 35m 33.093s (2,133,093.321 ms) wall / 33m 58.834s (2,038,834.179 ms) CPU | 11h 26m 28.913s (41,188,912.952 ms) wall / 11h 26m 26.351s (41,186,351.424 ms) CPU | 12h 16m 5.843s (44,165,842.858 ms) wall / 12h 14m 28.959s (44,068,958.542 ms) CPU |
| 14 | affine | 0.056 ms (0.056 ms) wall / 0.054 ms (0.054 ms) CPU | — | 13h 16m 0.183s (47,760,183.256 ms) wall / 13h 15m 57.342s (47,757,342.347 ms) CPU | 14h 55m 21.541s (53,721,540.627 ms) wall / 14h 50m 14.204s (53,414,204.346 ms) CPU |
| 13 | multiplication | 0.016 ms (0.016 ms) wall / 0.016 ms (0.016 ms) CPU | 1h 52m 24.480s (6,744,480.189 ms) wall / 1h 45m 0.614s (6,300,614.422 ms) CPU | 6h 11m 55.014s (22,315,013.838 ms) wall / 6h 11m 53.533s (22,313,533.129 ms) CPU | 8h 13m 54.753s (29,634,752.942 ms) wall / 8h 6m 29.002s (29,189,001.782 ms) CPU |
| 12 | affine | 0.041 ms (0.041 ms) wall / 0.040 ms (0.040 ms) CPU | — | 1h 34m 3.099s (5,643,098.576 ms) wall / 1h 34m 2.784s (5,642,784.060 ms) CPU | 2h 17m 14.337s (8,234,336.644 ms) wall / 2h 14m 48.231s (8,088,230.911 ms) CPU |
| 11 | multiplication | 0.011 ms (0.011 ms) wall / 0.011 ms (0.011 ms) CPU | 48m 16.357s (2,896,357.196 ms) wall / 44m 55.428s (2,695,428.264 ms) CPU | 2h 45m 59.847s (9,959,847.265 ms) wall / 2h 45m 59.313s (9,959,312.621 ms) CPU | 3h 38m 11.941s (13,091,941.444 ms) wall / 3h 34m 50.327s (12,890,326.855 ms) CPU |
| 10 | affine | 0.032 ms (0.032 ms) wall / 0.032 ms (0.032 ms) CPU | — | 44m 23.917s (2,663,916.894 ms) wall / 44m 23.771s (2,663,771.103 ms) CPU | 1h 1m 14.931s (3,674,930.711 ms) wall / 1h 0m 58.193s (3,658,192.933 ms) CPU |
| 9 | multiplication | 0.015 ms (0.015 ms) wall / 0.014 ms (0.014 ms) CPU | 18m 30.569s (1,110,569.237 ms) wall / 18m 6.732s (1,086,731.631 ms) CPU | 1h 19m 48.040s (4,788,040.482 ms) wall / 1h 19m 47.778s (4,787,777.578 ms) CPU | 1h 40m 16.067s (6,016,066.528 ms) wall / 1h 39m 51.883s (5,991,882.543 ms) CPU |
| 8 | affine | 0.031 ms (0.031 ms) wall / 0.030 ms (0.030 ms) CPU | — | 20m 59.730s (1,259,729.852 ms) wall / 20m 59.658s (1,259,658.282 ms) CPU | 27m 44.082s (1,664,082.348 ms) wall / 27m 37.307s (1,657,307.029 ms) CPU |
| 7 | multiplication | 0.016 ms (0.016 ms) wall / 0.016 ms (0.016 ms) CPU | 7m 23.430s (443,429.834 ms) wall / 7m 13.302s (433,302.097 ms) CPU | 39m 5.929s (2,345,929.085 ms) wall / 39m 5.792s (2,345,792.003 ms) CPU | 47m 28.958s (2,848,958.123 ms) wall / 47m 18.673s (2,838,673.387 ms) CPU |
| 6 | affine | 0.032 ms (0.032 ms) wall / 0.030 ms (0.030 ms) CPU | — | 9m 58.370s (598,369.968 ms) wall / 9m 58.321s (598,320.959 ms) CPU | 12m 31.140s (751,139.945 ms) wall / 12m 28.566s (748,565.549 ms) CPU |
| 5 | multiplication | 0.022 ms (0.022 ms) wall / 0.022 ms (0.022 ms) CPU | 2m 44.091s (164,091.107 ms) wall / 2m 41.097s (161,097.124 ms) CPU | 19m 4.419s (1,144,419.493 ms) wall / 19m 4.354s (1,144,353.539 ms) CPU | 22m 20.862s (1,340,861.543 ms) wall / 22m 17.799s (1,337,799.423 ms) CPU |
| 4 | affine | 0.031 ms (0.031 ms) wall / 0.030 ms (0.030 ms) CPU | — | 4m 40.154s (280,154.216 ms) wall / 4m 40.135s (280,135.317 ms) CPU | 5m 33.540s (333,539.775 ms) wall / 5m 33.148s (333,148.112 ms) CPU |
| 3 | multiplication | 0.016 ms (0.016 ms) wall / 0.017 ms (0.017 ms) CPU | 1m 0.894s (60,894.041 ms) wall / 59.673s (59,673.238 ms) CPU | 9m 17.237s (557,237.194 ms) wall / 9m 17.204s (557,204.037 ms) CPU | 10m 34.123s (634,123.073 ms) wall / 10m 32.868s (632,868.218 ms) CPU |
| 2 | affine | 0.026 ms (0.026 ms) wall / 0.026 ms (0.026 ms) CPU | — | 2m 7.908s (127,908.453 ms) wall / 2m 7.897s (127,897.045 ms) CPU | 2m 26.692s (146,692.168 ms) wall / 2m 26.419s (146,418.905 ms) CPU |
| 1 | multiplication | 0.011 ms (0.011 ms) wall / 0.011 ms (0.011 ms) CPU | 23.739s (23,738.709 ms) wall / 22.516s (22,516.221 ms) CPU | 4m 32.099s (272,098.750 ms) wall / 4m 32.073s (272,072.846 ms) CPU | 5m 4.463s (304,462.568 ms) wall / 5m 3.213s (303,213.293 ms) CPU |
| 0 | affine | 0.045 ms (0.045 ms) wall / 0.044 ms (0.044 ms) CPU | — | 59.207s (59,206.833 ms) wall / 59.203s (59,203.372 ms) CPU | 1m 3.145s (63,144.772 ms) wall / 1m 3.136s (63,135.741 ms) CPU |

Reduction totals and replay segments are inclusive spans. Source-build and sumcheck columns explain time within those spans; the columns are not additive.

## Sumcheck round details

| Reduction layer | Source layer | Kind | Coordinate | Round | Side | Work units | Wall time | CPU time | CPU/wall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 16 | 17 | affine | ciphertext-index | 1/6 | — | — | 3.045s (3,044.868 ms) | 3.045s (3,044.629 ms) | 99.99% |
| 16 | 17 | affine | ciphertext-index | 2/6 | — | — | 5.608s (5,607.680 ms) | 5.607s (5,607.318 ms) | 99.99% |
| 16 | 17 | affine | ciphertext-index | 3/6 | — | — | 6.825s (6,825.077 ms) | 6.825s (6,824.655 ms) | 99.99% |
| 16 | 17 | affine | ciphertext-index | 4/6 | — | — | 8.556s (8,556.065 ms) | 8.556s (8,555.512 ms) | 99.99% |
| 16 | 17 | affine | ciphertext-index | 5/6 | — | — | 12.293s (12,293.011 ms) | 12.292s (12,292.156 ms) | 99.99% |
| 16 | 17 | affine | ciphertext-index | 6/6 | — | — | 18.451s (18,450.751 ms) | 18.450s (18,449.509 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 1/19 | — | 870,028 | 18m 13.078s (1,093,078.240 ms) | 18m 13.011s (1,093,011.239 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 2/19 | — | 870,028 | 2h 53m 48.710s (10,428,709.588 ms) | 2h 53m 48.053s (10,428,052.585 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 3/19 | — | 870,028 | 1h 37m 23.152s (5,843,152.364 ms) | 1h 37m 22.788s (5,842,788.108 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 4/19 | — | 870,028 | 59m 25.877s (3,565,877.384 ms) | 59m 25.650s (3,565,649.986 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 5/19 | — | 870,028 | 39m 48.323s (2,388,322.924 ms) | 39m 48.160s (2,388,160.316 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 6/19 | — | 870,028 | 30m 35.526s (1,835,526.037 ms) | 30m 35.405s (1,835,404.602 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 7/19 | — | 870,028 | 25m 3.616s (1,503,615.922 ms) | 25m 3.520s (1,503,519.895 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 8/19 | — | 870,028 | 22m 26.630s (1,346,630.019 ms) | 22m 26.545s (1,346,544.878 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 9/19 | — | 870,028 | 21m 8.108s (1,268,107.886 ms) | 21m 8.032s (1,268,031.547 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 10/19 | — | 870,028 | 20m 26.415s (1,226,415.496 ms) | 20m 26.341s (1,226,340.545 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 11/19 | — | 870,028 | 20m 5.007s (1,205,006.867 ms) | 20m 4.935s (1,204,934.940 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 12/19 | — | 870,028 | 19m 53.317s (1,193,317.066 ms) | 19m 53.246s (1,193,246.402 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 13/19 | — | 870,028 | 19m 48.473s (1,188,472.649 ms) | 19m 48.402s (1,188,401.728 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 14/19 | — | 870,028 | 19m 46.517s (1,186,516.665 ms) | 19m 46.446s (1,186,445.687 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 15/19 | — | 870,028 | 19m 45.161s (1,185,161.308 ms) | 19m 45.093s (1,185,092.614 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 16/19 | — | 870,028 | 19m 43.071s (1,183,071.466 ms) | 19m 43.002s (1,183,001.978 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 17/19 | — | 870,028 | 19m 42.987s (1,182,987.045 ms) | 19m 42.918s (1,182,918.040 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 18/19 | — | 870,028 | 19m 42.031s (1,182,031.393 ms) | 19m 41.963s (1,181,962.686 ms) | 99.99% |
| 15 | 16 | multiplication | ciphertext-index | 19/19 | — | 870,028 | 19m 42.913s (1,182,912.632 ms) | 19m 42.844s (1,182,843.648 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 1/19 | — | — | 13m 51.501s (831,500.851 ms) | 13m 51.452s (831,451.585 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 2/19 | — | — | 13m 53.103s (833,103.472 ms) | 13m 53.056s (833,055.598 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 3/19 | — | — | 14m 16.916s (856,915.648 ms) | 14m 16.867s (856,867.494 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 4/19 | — | — | 14m 28.567s (868,566.664 ms) | 14m 28.519s (868,518.714 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 5/19 | — | — | 14m 39.644s (879,644.458 ms) | 14m 39.595s (879,594.973 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 6/19 | — | — | 15m 2.486s (902,486.081 ms) | 15m 2.429s (902,428.541 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 7/19 | — | — | 15m 18.182s (918,181.625 ms) | 15m 18.129s (918,129.488 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 8/19 | — | — | 15m 59.308s (959,308.447 ms) | 15m 59.255s (959,254.782 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 9/19 | — | — | 17m 28.566s (1,048,565.985 ms) | 17m 28.505s (1,048,505.476 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 10/19 | — | — | 23m 22.062s (1,402,061.618 ms) | 23m 21.978s (1,401,978.100 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 11/19 | — | — | 32m 13.728s (1,933,728.170 ms) | 32m 13.609s (1,933,609.171 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 12/19 | — | — | 36m 59.257s (2,219,257.131 ms) | 36m 59.136s (2,219,136.056 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 13/19 | — | — | 1h 2m 29.373s (3,749,373.399 ms) | 1h 2m 29.158s (3,749,158.363 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 14/19 | — | — | 1h 24m 43.876s (5,083,876.324 ms) | 1h 24m 43.565s (5,083,564.831 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 15/19 | — | — | 1h 24m 15.479s (5,055,478.934 ms) | 1h 24m 15.174s (5,055,173.534 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 16/19 | — | — | 1h 24m 1.092s (5,041,091.762 ms) | 1h 24m 0.794s (5,040,793.559 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 17/19 | — | — | 1h 23m 50.170s (5,030,169.934 ms) | 1h 23m 49.872s (5,029,871.934 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 18/19 | — | — | 1h 24m 27.699s (5,067,699.405 ms) | 1h 24m 27.385s (5,067,384.970 ms) | 99.99% |
| 14 | 15 | affine | ciphertext-index | 19/19 | — | — | 1h 24m 39.173s (5,079,173.346 ms) | 1h 24m 38.865s (5,078,865.178 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 1/18 | — | 460,540 | 10m 52.381s (652,380.784 ms) | 10m 52.332s (652,331.708 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 2/18 | — | 460,540 | 1h 26m 59.991s (5,219,991.203 ms) | 1h 26m 59.692s (5,219,691.772 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 3/18 | — | 460,540 | 50m 3.296s (3,003,295.805 ms) | 50m 3.119s (3,003,119.309 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 4/18 | — | 460,540 | 30m 56.630s (1,856,629.893 ms) | 30m 56.514s (1,856,514.193 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 5/18 | — | 460,540 | 21m 52.449s (1,312,449.444 ms) | 21m 52.359s (1,312,358.884 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 6/18 | — | 460,540 | 17m 13.645s (1,033,644.970 ms) | 17m 13.571s (1,033,570.736 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 7/18 | — | 460,540 | 14m 51.190s (891,189.882 ms) | 14m 51.127s (891,127.001 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 8/18 | — | 460,540 | 13m 38.594s (818,593.876 ms) | 13m 38.536s (818,535.561 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 9/18 | — | 460,540 | 13m 1.953s (781,953.273 ms) | 13m 1.899s (781,899.157 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 10/18 | — | 460,540 | 12m 42.831s (762,831.485 ms) | 12m 42.777s (762,777.387 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 11/18 | — | 460,540 | 12m 33.462s (753,461.521 ms) | 12m 33.408s (753,408.155 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 12/18 | — | 460,540 | 12m 27.542s (747,542.243 ms) | 12m 27.488s (747,488.139 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 13/18 | — | 460,540 | 12m 21.747s (741,746.648 ms) | 12m 21.693s (741,692.787 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 14/18 | — | 460,540 | 12m 19.891s (739,890.544 ms) | 12m 19.836s (739,836.430 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 15/18 | — | 460,540 | 12m 20.249s (740,249.475 ms) | 12m 20.194s (740,193.557 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 16/18 | — | 460,540 | 12m 20.915s (740,914.611 ms) | 12m 20.857s (740,856.702 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 17/18 | — | 460,540 | 12m 42.722s (762,721.979 ms) | 12m 42.663s (762,662.669 ms) | 99.99% |
| 13 | 14 | multiplication | ciphertext-index | 18/18 | — | 460,540 | 12m 35.526s (755,526.202 ms) | 12m 35.469s (755,468.982 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 1/18 | — | — | 5m 30.105s (330,105.385 ms) | 5m 30.083s (330,082.750 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 2/18 | — | — | 4m 59.417s (299,417.065 ms) | 4m 59.400s (299,400.232 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 3/18 | — | — | 5m 3.564s (303,564.291 ms) | 5m 3.547s (303,547.373 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 4/18 | — | — | 5m 15.656s (315,655.534 ms) | 5m 15.638s (315,637.864 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 5/18 | — | — | 5m 15.523s (315,522.540 ms) | 5m 15.505s (315,504.983 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 6/18 | — | — | 5m 13.415s (313,414.915 ms) | 5m 13.398s (313,398.029 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 7/18 | — | — | 5m 13.584s (313,584.089 ms) | 5m 13.567s (313,566.899 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 8/18 | — | — | 5m 13.477s (313,477.157 ms) | 5m 13.460s (313,459.907 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 9/18 | — | — | 5m 13.830s (313,829.532 ms) | 5m 13.812s (313,812.400 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 10/18 | — | — | 5m 14.453s (314,453.127 ms) | 5m 14.436s (314,435.781 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 11/18 | — | — | 5m 13.905s (313,905.318 ms) | 5m 13.888s (313,887.858 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 12/18 | — | — | 5m 13.607s (313,607.368 ms) | 5m 13.590s (313,590.103 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 13/18 | — | — | 5m 13.933s (313,932.524 ms) | 5m 13.915s (313,915.134 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 14/18 | — | — | 5m 14.044s (314,044.400 ms) | 5m 14.027s (314,027.454 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 15/18 | — | — | 5m 13.499s (313,499.345 ms) | 5m 13.482s (313,482.416 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 16/18 | — | — | 5m 14.069s (314,068.680 ms) | 5m 14.052s (314,051.525 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 17/18 | — | — | 5m 14.508s (314,507.544 ms) | 5m 14.490s (314,490.405 ms) | 99.99% |
| 12 | 13 | affine | ciphertext-index | 18/18 | — | — | 5m 12.510s (312,509.763 ms) | 5m 12.493s (312,492.947 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 1/17 | — | 230,272 | 5m 42.673s (342,673.240 ms) | 5m 42.654s (342,654.434 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 2/17 | — | 230,272 | 42m 38.710s (2,558,710.102 ms) | 42m 38.579s (2,558,578.554 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 3/17 | — | 230,272 | 24m 4.397s (1,444,397.385 ms) | 24m 4.319s (1,444,319.260 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 4/17 | — | 230,272 | 14m 39.690s (879,689.762 ms) | 14m 39.642s (879,642.301 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 5/17 | — | 230,272 | 10m 5.531s (605,530.628 ms) | 10m 5.497s (605,497.342 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 6/17 | — | 230,272 | 7m 42.906s (462,906.336 ms) | 7m 42.881s (462,880.965 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 7/17 | — | 230,272 | 6m 33.802s (393,801.730 ms) | 6m 33.780s (393,779.928 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 8/17 | — | 230,272 | 5m 58.247s (358,246.659 ms) | 5m 58.227s (358,226.993 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 9/17 | — | 230,272 | 5m 39.611s (339,611.456 ms) | 5m 39.593s (339,593.077 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 10/17 | — | 230,272 | 5m 30.758s (330,757.943 ms) | 5m 30.740s (330,739.922 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 11/17 | — | 230,272 | 5m 24.934s (324,934.440 ms) | 5m 24.917s (324,916.730 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 12/17 | — | 230,272 | 5m 22.305s (322,305.391 ms) | 5m 22.288s (322,288.120 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 13/17 | — | 230,272 | 5m 20.049s (320,048.786 ms) | 5m 20.032s (320,031.646 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 14/17 | — | 230,272 | 5m 19.519s (319,519.063 ms) | 5m 19.501s (319,501.302 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 15/17 | — | 230,272 | 5m 19.384s (319,384.455 ms) | 5m 19.367s (319,366.974 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 16/17 | — | 230,272 | 5m 18.755s (318,754.508 ms) | 5m 18.737s (318,736.991 ms) | 99.99% |
| 11 | 12 | multiplication | ciphertext-index | 17/17 | — | 230,272 | 5m 18.575s (318,575.381 ms) | 5m 18.558s (318,558.082 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 1/17 | — | — | 2m 45.072s (165,072.196 ms) | 2m 45.063s (165,063.275 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 2/17 | — | — | 2m 31.114s (151,113.725 ms) | 2m 31.105s (151,105.348 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 3/17 | — | — | 2m 30.919s (150,919.041 ms) | 2m 30.911s (150,910.886 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 4/17 | — | — | 2m 37.560s (157,559.824 ms) | 2m 37.551s (157,551.247 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 5/17 | — | — | 2m 37.403s (157,403.348 ms) | 2m 37.395s (157,394.781 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 6/17 | — | — | 2m 36.381s (156,381.223 ms) | 2m 36.373s (156,372.862 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 7/17 | — | — | 2m 36.299s (156,298.830 ms) | 2m 36.290s (156,290.153 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 8/17 | — | — | 2m 37.292s (157,292.383 ms) | 2m 37.283s (157,283.483 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 9/17 | — | — | 2m 36.954s (156,953.965 ms) | 2m 36.946s (156,945.539 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 10/17 | — | — | 2m 36.943s (156,942.501 ms) | 2m 36.934s (156,933.951 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 11/17 | — | — | 2m 37.221s (157,221.037 ms) | 2m 37.212s (157,212.371 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 12/17 | — | — | 2m 36.710s (156,709.602 ms) | 2m 36.701s (156,700.855 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 13/17 | — | — | 2m 37.203s (157,202.605 ms) | 2m 37.194s (157,194.060 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 14/17 | — | — | 2m 36.914s (156,913.576 ms) | 2m 36.905s (156,905.143 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 15/17 | — | — | 2m 36.649s (156,648.756 ms) | 2m 36.640s (156,640.072 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 16/17 | — | — | 2m 36.806s (156,805.833 ms) | 2m 36.797s (156,797.310 ms) | 99.99% |
| 10 | 11 | affine | ciphertext-index | 17/17 | — | — | 2m 36.478s (156,478.449 ms) | 2m 36.470s (156,469.767 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 1/16 | — | 115,136 | 2m 37.210s (157,210.119 ms) | 2m 37.201s (157,200.646 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 2/16 | — | 115,136 | 21m 15.108s (1,275,108.035 ms) | 21m 15.040s (1,275,040.433 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 3/16 | — | 115,136 | 12m 1.522s (721,521.572 ms) | 12m 1.482s (721,481.750 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 4/16 | — | 115,136 | 7m 19.661s (439,661.498 ms) | 7m 19.637s (439,637.473 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 5/16 | — | 115,136 | 5m 2.741s (302,740.644 ms) | 5m 2.725s (302,724.517 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 6/16 | — | 115,136 | 3m 51.047s (231,047.111 ms) | 3m 51.035s (231,034.537 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 7/16 | — | 115,136 | 3m 15.866s (195,865.923 ms) | 3m 15.855s (195,855.057 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 8/16 | — | 115,136 | 2m 58.243s (178,243.136 ms) | 2m 58.233s (178,233.024 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 9/16 | — | 115,136 | 2m 48.900s (168,899.899 ms) | 2m 48.890s (168,890.451 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 10/16 | — | 115,136 | 2m 43.824s (163,824.211 ms) | 2m 43.815s (163,815.197 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 11/16 | — | 115,136 | 2m 40.986s (160,986.499 ms) | 2m 40.978s (160,977.620 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 12/16 | — | 115,136 | 2m 39.436s (159,435.667 ms) | 2m 39.427s (159,426.746 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 13/16 | — | 115,136 | 2m 39.034s (159,034.376 ms) | 2m 39.025s (159,025.242 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 14/16 | — | 115,136 | 2m 38.264s (158,264.314 ms) | 2m 38.255s (158,255.141 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 15/16 | — | 115,136 | 2m 37.899s (157,899.257 ms) | 2m 37.890s (157,890.497 ms) | 99.99% |
| 9 | 10 | multiplication | ciphertext-index | 16/16 | — | 115,136 | 2m 38.298s (158,298.223 ms) | 2m 38.289s (158,289.247 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 1/16 | — | — | 1m 19.116s (79,116.446 ms) | 1m 19.112s (79,111.985 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 2/16 | — | — | 1m 17.206s (77,206.400 ms) | 1m 17.202s (77,202.002 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 3/16 | — | — | 1m 15.871s (75,870.769 ms) | 1m 15.866s (75,866.413 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 4/16 | — | — | 1m 19.556s (79,556.160 ms) | 1m 19.552s (79,551.630 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 5/16 | — | — | 1m 19.098s (79,097.799 ms) | 1m 19.093s (79,093.329 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 6/16 | — | — | 1m 18.107s (78,107.205 ms) | 1m 18.103s (78,102.745 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 7/16 | — | — | 1m 19.518s (79,517.571 ms) | 1m 19.513s (79,512.930 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 8/16 | — | — | 1m 18.871s (78,871.033 ms) | 1m 18.867s (78,866.572 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 9/16 | — | — | 1m 19.501s (79,500.585 ms) | 1m 19.496s (79,496.146 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 10/16 | — | — | 1m 19.262s (79,262.076 ms) | 1m 19.258s (79,257.526 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 11/16 | — | — | 1m 18.648s (78,648.328 ms) | 1m 18.644s (78,643.875 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 12/16 | — | — | 1m 18.391s (78,391.350 ms) | 1m 18.387s (78,386.944 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 13/16 | — | — | 1m 19.060s (79,059.887 ms) | 1m 19.055s (79,055.362 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 14/16 | — | — | 1m 19.127s (79,126.617 ms) | 1m 19.122s (79,122.139 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 15/16 | — | — | 1m 19.604s (79,604.018 ms) | 1m 19.600s (79,599.634 ms) | 99.99% |
| 8 | 9 | affine | ciphertext-index | 16/16 | — | — | 1m 18.794s (78,793.607 ms) | 1m 18.789s (78,789.050 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 1/15 | — | 57,568 | 1m 8.852s (68,852.434 ms) | 1m 8.846s (68,845.528 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 2/15 | — | 57,568 | 10m 42.195s (642,194.825 ms) | 10m 42.161s (642,160.728 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 3/15 | — | 57,568 | 6m 11.559s (371,558.611 ms) | 6m 11.538s (371,538.319 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 4/15 | — | 57,568 | 3m 48.900s (228,899.958 ms) | 3m 48.887s (228,886.753 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 5/15 | — | 57,568 | 2m 34.387s (154,387.103 ms) | 2m 34.378s (154,378.168 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 6/15 | — | 57,568 | 1m 58.426s (118,425.769 ms) | 1m 58.419s (118,418.750 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 7/15 | — | 57,568 | 1m 39.273s (99,273.195 ms) | 1m 39.267s (99,267.301 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 8/15 | — | 57,568 | 1m 30.120s (90,120.026 ms) | 1m 30.115s (90,114.775 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 9/15 | — | 57,568 | 1m 25.737s (85,736.953 ms) | 1m 25.732s (85,731.806 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 10/15 | — | 57,568 | 1m 22.692s (82,692.177 ms) | 1m 22.687s (82,686.939 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 11/15 | — | 57,568 | 1m 21.519s (81,519.012 ms) | 1m 21.514s (81,513.991 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 12/15 | — | 57,568 | 1m 20.585s (80,584.938 ms) | 1m 20.580s (80,579.791 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 13/15 | — | 57,568 | 1m 20.716s (80,716.371 ms) | 1m 20.711s (80,711.268 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 14/15 | — | 57,568 | 1m 20.323s (80,323.223 ms) | 1m 20.318s (80,318.440 ms) | 99.99% |
| 7 | 8 | multiplication | ciphertext-index | 15/15 | — | 57,568 | 1m 20.644s (80,644.489 ms) | 1m 20.639s (80,639.446 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 1/15 | — | — | 39.630s (39,630.152 ms) | 39.625s (39,625.259 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 2/15 | — | — | 39.496s (39,496.040 ms) | 39.491s (39,491.196 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 3/15 | — | — | 38.562s (38,562.067 ms) | 38.557s (38,557.243 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 4/15 | — | — | 39.489s (39,488.731 ms) | 39.484s (39,483.860 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 5/15 | — | — | 39.181s (39,181.009 ms) | 39.178s (39,177.699 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 6/15 | — | — | 40.891s (40,890.907 ms) | 40.888s (40,888.268 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 7/15 | — | — | 40.554s (40,554.145 ms) | 40.551s (40,551.482 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 8/15 | — | — | 39.371s (39,371.320 ms) | 39.369s (39,368.859 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 9/15 | — | — | 39.653s (39,652.757 ms) | 39.650s (39,650.127 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 10/15 | — | — | 40.255s (40,255.073 ms) | 40.252s (40,252.422 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 11/15 | — | — | 40.652s (40,652.457 ms) | 40.650s (40,649.806 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 12/15 | — | — | 40.595s (40,595.385 ms) | 40.593s (40,592.725 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 13/15 | — | — | 39.667s (39,667.404 ms) | 39.665s (39,664.744 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 14/15 | — | — | 40.822s (40,821.502 ms) | 40.819s (40,818.853 ms) | 99.99% |
| 6 | 7 | affine | ciphertext-index | 15/15 | — | — | 39.551s (39,551.018 ms) | 39.548s (39,548.416 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 1/14 | — | 28,784 | 35.152s (35,152.467 ms) | 35.150s (35,149.835 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 2/14 | — | 28,784 | 5m 27.583s (327,582.904 ms) | 5m 27.565s (327,564.593 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 3/14 | — | 28,784 | 3m 5.307s (185,306.834 ms) | 3m 5.297s (185,296.550 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 4/14 | — | 28,784 | 1m 53.781s (113,780.867 ms) | 1m 53.774s (113,774.148 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 5/14 | — | 28,784 | 1m 17.083s (77,082.959 ms) | 1m 17.078s (77,078.360 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 6/14 | — | 28,784 | 1m 0.447s (60,447.368 ms) | 1m 0.444s (60,443.868 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 7/14 | — | 28,784 | 50.141s (50,141.345 ms) | 50.138s (50,138.387 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 8/14 | — | 28,784 | 45.611s (45,610.543 ms) | 45.608s (45,607.982 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 9/14 | — | 28,784 | 43.215s (43,215.372 ms) | 43.213s (43,212.878 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 10/14 | — | 28,784 | 41.893s (41,892.816 ms) | 41.890s (41,890.350 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 11/14 | — | 28,784 | 42.014s (42,014.077 ms) | 42.012s (42,011.758 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 12/14 | — | 28,784 | 40.673s (40,673.243 ms) | 40.671s (40,670.887 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 13/14 | — | 28,784 | 40.815s (40,814.761 ms) | 40.812s (40,812.303 ms) | 99.99% |
| 5 | 6 | multiplication | ciphertext-index | 14/14 | — | 28,784 | 40.704s (40,703.937 ms) | 40.702s (40,701.640 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 1/14 | — | — | 19.286s (19,285.789 ms) | 19.282s (19,282.100 ms) | 99.98% |
| 4 | 5 | affine | ciphertext-index | 2/14 | — | — | 19.743s (19,742.767 ms) | 19.741s (19,741.312 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 3/14 | — | — | 19.139s (19,139.081 ms) | 19.138s (19,137.935 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 4/14 | — | — | 20.920s (20,920.007 ms) | 20.919s (20,918.823 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 5/14 | — | — | 20.271s (20,270.736 ms) | 20.270s (20,269.592 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 6/14 | — | — | 20.079s (20,079.046 ms) | 20.078s (20,077.853 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 7/14 | — | — | 20.381s (20,380.849 ms) | 20.380s (20,379.700 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 8/14 | — | — | 20.003s (20,003.259 ms) | 20.002s (20,002.100 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 9/14 | — | — | 19.906s (19,906.066 ms) | 19.905s (19,904.845 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 10/14 | — | — | 20.698s (20,698.427 ms) | 20.697s (20,697.296 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 11/14 | — | — | 20.163s (20,162.937 ms) | 20.162s (20,161.813 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 12/14 | — | — | 19.716s (19,715.658 ms) | 19.715s (19,714.531 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 13/14 | — | — | 19.786s (19,785.899 ms) | 19.785s (19,784.816 ms) | 99.99% |
| 4 | 5 | affine | ciphertext-index | 14/14 | — | — | 20.064s (20,063.696 ms) | 20.063s (20,062.601 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 1/13 | — | 14,392 | 18.367s (18,366.978 ms) | 18.366s (18,365.592 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 2/13 | — | 14,392 | 2m 44.800s (164,800.264 ms) | 2m 44.791s (164,790.623 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 3/13 | — | 14,392 | 1m 34.473s (94,472.772 ms) | 1m 34.467s (94,467.448 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 4/13 | — | 14,392 | 59.067s (59,067.405 ms) | 59.064s (59,063.853 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 5/13 | — | 14,392 | 39.172s (39,171.867 ms) | 39.170s (39,169.520 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 6/13 | — | 14,392 | 29.826s (29,826.054 ms) | 29.824s (29,824.325 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 7/13 | — | 14,392 | 25.141s (25,141.146 ms) | 25.140s (25,139.603 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 8/13 | — | 14,392 | 22.752s (22,751.573 ms) | 22.750s (22,750.193 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 9/13 | — | 14,392 | 21.545s (21,545.343 ms) | 21.544s (21,544.036 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 10/13 | — | 14,392 | 20.928s (20,927.689 ms) | 20.926s (20,926.430 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 11/13 | — | 14,392 | 20.643s (20,642.573 ms) | 20.641s (20,641.231 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 12/13 | — | 14,392 | 20.386s (20,385.822 ms) | 20.385s (20,384.710 ms) | 99.99% |
| 3 | 4 | multiplication | ciphertext-index | 13/13 | — | 14,392 | 20.138s (20,137.708 ms) | 20.136s (20,136.473 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 1/13 | — | — | 9.554s (9,554.180 ms) | 9.553s (9,553.073 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 2/13 | — | — | 9.476s (9,475.956 ms) | 9.474s (9,473.795 ms) | 99.98% |
| 2 | 3 | affine | ciphertext-index | 3/13 | — | — | 9.616s (9,615.547 ms) | 9.615s (9,614.622 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 4/13 | — | — | 9.859s (9,859.399 ms) | 9.859s (9,858.718 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 5/13 | — | — | 9.946s (9,946.143 ms) | 9.946s (9,945.641 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 6/13 | — | — | 9.876s (9,875.536 ms) | 9.875s (9,874.818 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 7/13 | — | — | 9.838s (9,837.787 ms) | 9.837s (9,837.051 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 8/13 | — | — | 9.869s (9,869.357 ms) | 9.869s (9,868.582 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 9/13 | — | — | 9.928s (9,927.526 ms) | 9.927s (9,926.745 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 10/13 | — | — | 10.220s (10,219.852 ms) | 10.219s (10,219.018 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 11/13 | — | — | 9.851s (9,850.966 ms) | 9.850s (9,850.268 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 12/13 | — | — | 9.819s (9,819.283 ms) | 9.819s (9,818.573 ms) | 99.99% |
| 2 | 3 | affine | ciphertext-index | 13/13 | — | — | 10.057s (10,056.921 ms) | 10.056s (10,056.141 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 1/12 | — | 7,532 | 9.016s (9,015.688 ms) | 9.015s (9,014.676 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 2/12 | — | 7,532 | 1m 21.744s (81,744.493 ms) | 1m 21.733s (81,732.631 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 3/12 | — | 7,532 | 47.487s (47,487.466 ms) | 47.484s (47,484.443 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 4/12 | — | 7,532 | 29.394s (29,394.390 ms) | 29.392s (29,392.443 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 5/12 | — | 7,532 | 19.977s (19,977.287 ms) | 19.976s (19,975.831 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 6/12 | — | 7,532 | 15.433s (15,433.010 ms) | 15.432s (15,431.776 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 7/12 | — | 7,532 | 13.100s (13,099.521 ms) | 13.099s (13,098.560 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 8/12 | — | 7,532 | 11.947s (11,947.445 ms) | 11.947s (11,946.537 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 9/12 | — | 7,532 | 11.337s (11,337.129 ms) | 11.336s (11,336.224 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 10/12 | — | 7,532 | 11.024s (11,023.716 ms) | 11.023s (11,022.786 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 11/12 | — | 7,532 | 10.908s (10,908.143 ms) | 10.907s (10,907.283 ms) | 99.99% |
| 1 | 2 | multiplication | ciphertext-index | 12/12 | — | 7,532 | 10.730s (10,730.461 ms) | 10.730s (10,729.656 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 1/12 | — | — | 1.203s (1,203.281 ms) | 1.203s (1,203.208 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 2/12 | — | — | 5.454s (5,454.157 ms) | 5.454s (5,453.837 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 3/12 | — | — | 5.063s (5,062.950 ms) | 5.063s (5,062.650 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 4/12 | — | — | 5.222s (5,221.955 ms) | 5.222s (5,221.654 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 5/12 | — | — | 5.311s (5,311.138 ms) | 5.311s (5,310.839 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 6/12 | — | — | 5.230s (5,229.896 ms) | 5.230s (5,229.598 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 7/12 | — | — | 5.180s (5,179.954 ms) | 5.180s (5,179.667 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 8/12 | — | — | 5.236s (5,235.818 ms) | 5.235s (5,235.474 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 9/12 | — | — | 5.332s (5,331.622 ms) | 5.331s (5,331.302 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 10/12 | — | — | 5.200s (5,200.025 ms) | 5.200s (5,199.711 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 11/12 | — | — | 5.365s (5,364.571 ms) | 5.364s (5,364.249 ms) | 99.99% |
| 0 | 1 | affine | ciphertext-index | 12/12 | — | — | 5.411s (5,411.466 ms) | 5.411s (5,411.183 ms) | 99.99% |

Round numbers are displayed one-based; the telemetry stores zero-based round indices. These rows are the individual spans summed into each layer's `Sumcheck rounds` cell above.

## Client computation

| Component | Wall | CPU |
| --- | --- | --- |
| Per-request client computation | 5.612s (5,612.240903 ms) | 5.612s (5,611.623000 ms) |
| Input encryption | 585.255 ms (585.255378 ms) | 585.245 ms (585.245000 ms) |
| Output decryption | 1.027 ms (1.027203 ms) | 1.028 ms (1.028000 ms) |
| VCoED proof verification | 5.026s (5,025.958322 ms) | 5.025s (5,025.350000 ms) |
| ↳ GKR proof verification | 4.987s (4,986.968783 ms) | 4.986s (4,986.360000 ms) |
| ↳↳ Transcript recovery (FS, decryption, plaintext assembly) | 2.967s (2,967.052248 ms) | 2.967s (2,967.220000 ms) |
| ↳↳ Plaintext GKR and affine gate-opening checks | 2.020s (2,019.916535 ms) | 2.019s (2,019.140000 ms) |
| ↳ Terminal input MLE | 38.990 ms (38.989539 ms) | 38.990 ms (38.990000 ms) |

Client computation is input encryption + output decryption + VCoED proof verification. Preprocessing RAM loading, session binding, transport, and peer waiting are excluded. Verification rows form a hierarchy: add siblings only.

## Client verifier details

| Verifier span | Circuit layer | Kind | Wall time | CPU time | CPU/wall |
| --- | --- | --- | --- | --- | --- |
| Decrypt and unpack proof messages | — | all messages | 1.663s (1,663.270759 ms) | 1.664s (1,663.546000 ms) | 100.02% |
| Verify layer reduction 1 | 0 | affine | 171.300 ms (171.299924 ms) | 171.301 ms (171.301000 ms) | 100.00% |
| Verify layer reduction 2 | 1 | multiplication | 293.767 ms (293.766748 ms) | 293.767 ms (293.767000 ms) | 100.00% |
| Verify layer reduction 3 | 2 | affine | 176.658 ms (176.657620 ms) | 176.650 ms (176.650000 ms) | 100.00% |
| Verify layer reduction 4 | 3 | multiplication | 313.840 ms (313.840487 ms) | 313.841 ms (313.841000 ms) | 100.00% |
| Verify layer reduction 5 | 4 | affine | 187.556 ms (187.555827 ms) | 187.556 ms (187.556000 ms) | 100.00% |
| Verify layer reduction 6 | 5 | multiplication | 334.822 ms (334.821891 ms) | 334.802 ms (334.802000 ms) | 99.99% |
| Verify layer reduction 7 | 6 | affine | 200.362 ms (200.362038 ms) | 200.358 ms (200.358000 ms) | 100.00% |
| Verify layer reduction 8 | 7 | multiplication | 357.713 ms (357.713481 ms) | 357.702 ms (357.702000 ms) | 100.00% |
| Verify layer reduction 9 | 8 | affine | 210.948 ms (210.947762 ms) | 210.938 ms (210.938000 ms) | 100.00% |
| Verify layer reduction 10 | 9 | multiplication | 385.604 ms (385.603987 ms) | 385.600 ms (385.600000 ms) | 100.00% |
| Verify layer reduction 11 | 10 | affine | 223.788 ms (223.787854 ms) | 223.751 ms (223.751000 ms) | 99.98% |
| Verify layer reduction 12 | 11 | multiplication | 418.884 ms (418.883826 ms) | 418.871 ms (418.871000 ms) | 100.00% |
| Verify layer reduction 13 | 12 | affine | 234.399 ms (234.398602 ms) | 234.339 ms (234.339000 ms) | 99.97% |
| Verify layer reduction 14 | 13 | multiplication | 468.257 ms (468.257491 ms) | 468.211 ms (468.211000 ms) | 99.99% |
| Verify layer reduction 15 | 14 | affine | 246.137 ms (246.137274 ms) | 246.130 ms (246.130000 ms) | 100.00% |
| Verify layer reduction 16 | 15 | multiplication | 556.508 ms (556.507567 ms) | 556.133 ms (556.133000 ms) | 99.93% |
| Verify layer reduction 17 | 16 | affine | 95.377 ms (95.376996 ms) | 95.377 ms (95.377000 ms) | 100.00% |
| Finish Gate-MLE opening | — | terminal | 102.798 ms (102.797849 ms) | 102.789 ms (102.789000 ms) | 99.99% |

Layer-reduction and terminal-opening spans are nested inside the proof-verification timer and are non-additive.

## Server FHE operation ledger

| Operation | Payload evaluation | GKR proving |
| --- | --- | --- |
| Negate | 0 calls; 0 limb-ops; RNS none | 14,944,114 calls; 44,832,342 limb-ops; RNS 3:14944114 |
| Ciphertext add | 131,024 calls; 1,384,978 limb-ops; RNS 3:3765,10:26166,11:101093 | 1,024,292,738 calls; 3,072,878,214 limb-ops; RNS 3:1024292738 |
| Ciphertext subtract | 0 calls; 0 limb-ops; RNS none | 738,936 calls; 2,216,808 limb-ops; RNS 3:738936 |
| Ciphertext multiply (before relinearization) | 891,290 calls; 8,915,084 limb-ops; RNS 4:3766,5:7196,6:14392,7:28784,8:57568,9:115134,10:229500,11:434950 | 67,889,840 calls; 203,669,520 limb-ops; RNS 3:67889840 |
| Relinearize | 891,290 calls; 8,915,084 limb-ops; RNS 4:3766,5:7196,6:14392,7:28784,8:57568,9:115134,10:229500,11:434950 | 1,984 calls; 5,952 limb-ops; RNS 3:1984 |
| Add plaintext | 0 calls; 0 limb-ops; RNS none | 188,516 calls; 565,548 limb-ops; RNS 3:188516 |
| Multiply by scalar plaintext | 0 calls; 0 limb-ops; RNS none | 966,993,546 calls; 2,900,980,638 limb-ops; RNS 3:966993546 |
| Multiply by vector plaintext | 26,214 calls; 263,688 limb-ops; RNS 10:24666,11:1548 | 150,192 calls; 450,576 limb-ops; RNS 3:150192 |
| Rotate | 39,336 calls; 432,696 limb-ops; RNS 11:39336 | 0 calls; 0 limb-ops; RNS none |
| Modulus switch | 892,126 calls; 8,923,506 limb-ops; RNS 4:3766,5:7196,6:14392,7:28784,8:57568,9:115136,10:230270,11:435014 | 11,922,610 calls; 80,179,526 limb-ops; RNS 2:4264,3:4264,4:1930305,5:1915913,6:1887129,7:1829561,8:1714425,9:1484153,10:1023613,11:128983 |
| Logical extension-field add | 0 calls; 0 limb-ops; RNS none | 1,046,492 calls; 3,139,476 limb-ops; RNS 3:1046492 |
| Logical extension-field multiply | 0 calls; 0 limb-ops; RNS none | 1,044,464 calls; 3,133,392 limb-ops; RNS 3:1044464 |
| Logical extension-field plaintext multiply | 0 calls; 0 limb-ops; RNS none | 1,046,786 calls; 3,140,358 limb-ops; RNS 3:1046786 |

A by-RNS entry `k:c` means `c` calls executed with `k` data limbs. All-zero operations are omitted. Logical extension-field rows describe wrapper operations and are not additive to the underlying SEAL primitive rows. Operation counts show the arithmetic schedule; CPU/wall ratios and profiling are needed to attribute elapsed time.

## Protocol artifacts

| Direction | Artifact | Size |
| --- | --- | --- |
| Client → server | `cli-to-srv-request.bin` | 176.01 MiB (184,561,043 bytes) |
| Server → client | `srv-to-cli-response.bin` | 1.05 GiB (1,128,272,434 bytes) |
| Both directions | One request plus one response | 1.22 GiB (1,312,833,477 bytes) |

| Response/proof component | Size |
| --- | --- |
| Complete server response | 1.05 GiB (1,128,272,434 bytes) |
| Encrypted-output statement (metadata and ciphertext) | 768.25 KiB (786,684 bytes) |
| Response envelope header | 43 bytes |
| Public binding digests | 128 bytes |
| Proof-length prefix | 8 bytes |
| Serialized proof transport | 1.05 GiB (1,127,485,571 bytes) |
| Proof statement and metadata | 370 bytes |
| Sumcheck round messages | 1016.70 MiB (1,066,085,244 bytes) |
| Terminal proof messages | 50.03 MiB (52,464,825 bytes) |
| Partial Gate-MLE values | 3.38 MiB (3,539,016 bytes) |
| Gate-MLE opening | 5.15 MiB (5,396,116 bytes) |

The byte counts describe canonical files on local storage; they do not include network latency or throughput. There is no second claim/proof round trip and no plaintext output claim is transmitted: the client decrypts the output and reconstructs its verification claim locally.

## Memory and storage

| Resource | Meaning | Size |
| --- | --- | --- |
| Setup peak RSS | measured setup-process peak | 8.09 GiB (8,690,466,816 bytes) |
| Server peak RSS | measured server-process peak | 191.05 GiB (205,137,555,456 bytes) |
| Client peak RSS | measured client-process peak | 2.86 GiB (3,073,155,072 bytes) |
| Server preprocessing | serialized reusable server state | 894.16 MiB (937,592,190 bytes) |
| Client preprocessing | serialized client secret state | 139.65 MiB (146,428,540 bytes) |
| Shared setup record | public setup identity and parameters | 4.47 KiB (4,580 bytes) |
| Retained run artifacts | measured before summary generation | 111.53 GiB (119,756,042,860 bytes) |
| Peak payload/checkpoint artifacts | measured controlled peak; excludes persistent files | 4.07 TiB (4,477,488,274,694 bytes) |
| Peak GKR multiplication scratch | measured controlled peak; excludes persistent files | 673.43 GiB (723,086,275,978 bytes) |
| Sampled server peak live local storage | whole-role measurement | not reported |
| Predicted/admitted peak resident RAM | capacity-model bound | 270.74 GiB (290,707,821,770 bytes) |
| Operating-system RAM reserve | fixed host headroom | 14.90 GiB (16,000,000,000 bytes) |
| Page-cache RAM reserve | fixed sequential-I/O headroom | 59.60 GiB (64,000,000,000 bytes) |
| Payload transfer-buffer reserve | up to two input slabs plus one output slab | 384.00 MiB (402,653,184 bytes) |
| Setup-selected dense multiplication alias-cache peak | relation-scoped decoded cache plus one staging value; included in the selected replay resident peak | 26.01 GiB (27,926,054,032 bytes) |
| Selected replay resident peak | capacity-model bound including any admitted relation cache | 75.08 GiB (80,611,943,056 bytes) |
| Payload writeback window | explicit foreground wait window for ephemeral payload scratch | 0 bytes |
| Ephemeral payload writeback policy | Linux submits background writeback without explicit foreground wait/drain; portable fallback uses ordinary buffered writes | linux-submit-only-with-buffered-portable-fallback |
| Configured writeback range-hint ceiling | maximum range passed to one advisory submission | 16.00 MiB (16,777,216 bytes) |
| Sequential payload readers | concurrent readers charged by the payload plan | 2 |
| Prefetch logical window per reader | bounded page-cache advice; not process-resident memory | 256.00 MiB (268,435,456 bytes) |
| Payload prefetch page-cache budget | reader count times logical window; inside page-cache reserve | 512.00 MiB (536,870,912 bytes) |
| Configured prefetch-request ceiling | Linux further qualifies requests from backing-device BDI read-ahead | 16.00 MiB (16,777,216 bytes) |
| Multiplication-source sort buffer | host-adaptive limit; allocated only as the current layer needs | 126.32 GiB (135,636,142,109 bytes) |
| Multiplication-source sort passes | initial runs / merge passes | 5 / 2 |
| Multiplication-source peak buffered payload | measured one-shot reorder arena | 126.32 GiB (135,635,700,928 bytes) |
| Multiplication-source temporary bytes retained | must be zero before artifact consumption | 0 bytes |
| Predicted/admitted peak live disk | capacity-model bound | 5.16 TiB (5,677,690,797,607 bytes) |
| Selected replay checkpoint bytes | formula-derived replay plan | 4.34 TiB (4,771,010,726,063 bytes) |
| Selected replay peak live bytes | formula-derived replay plan | 4.45 TiB (4,894,510,780,495 bytes) |
| Selected replay checkpoints | formula-derived replay plan | 17 |
| Replay-plan objective | checkpoint selection policy | minimum-replay-work |
| Cumulative payload-work factor | forward evaluation plus replay / forward evaluation | 1.000000x |
| Setup-start available-disk requirement | capacity-model bound including client preprocessing and reserve | 5.26 TiB (5,779,838,281,255 bytes) |
| Configured live-server disk cap | admission ceiling; not predicted allocation | 9.38 TiB (10,308,257,060,864 bytes) |

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
| Available at setup start | 9.47 TiB (10,410,404,597,760 bytes) at 2026-10-09T04:48:46Z |
| Available at server start | 9.36 TiB (10,291,965,452,288 bytes) at 2026-10-09T08:47:49Z |

These immutable snapshots were captured by the GCP wrapper outside the measured setup and server timers. They identify the filesystem used by all run artifacts; the available-byte samples are boundary observations, not a live-storage high-water mark.

| Host-derived planner budget | Recorded value |
| --- | --- |
| Observed available disk | 9.47 TiB (10,410,404,544,512 bytes) |
| Reserved free disk | 93.13 GiB (100,000,000,000 bytes) |
| Gross live-artifact budget | 9.38 TiB (10,310,404,544,512 bytes) |
| Persistent client preprocessing reserve | 2.00 GiB (2,147,483,648 bytes) |
| Server checkpoint/replay budget | 9.38 TiB (10,308,257,060,864 bytes) |
| Observed physical RAM | 365.88 GiB (392,855,961,600 bytes) |
| Reserved host RAM | 74.51 GiB (80,000,000,000 bytes) |
| Gross resident budget after host reserve | 291.37 GiB (312,855,961,600 bytes) |
| Concurrent client resident reserve | 20.63 GiB (22,148,139,830 bytes) |
| Net server resident cap | 270.74 GiB (290,707,821,770 bytes) |

The payload checkpoint plan is selected from this setup-time capacity observation. Workload and cryptographic parameters do not change with the host.

## Provenance

| Field | Value |
| --- | --- |
| Setup result | /var/lib/laminate-storage/laminate-bench/runs/base-target-mulHeavyPyramid-20261009T044846Z-129223/shared/setup-result.txt |
| Server result | /var/lib/laminate-storage/laminate-bench/runs/base-target-mulHeavyPyramid-20261009T044846Z-129223/server/result.txt |
| Client result | /var/lib/laminate-storage/laminate-bench/runs/base-target-mulHeavyPyramid-20261009T044846Z-129223/client/result.txt |
| Setup format | laminate-benchmark-setup-v1 |
| Server format | laminate-benchmark-server-v1 |
| Client format | laminate-benchmark-client-v2 |
| Variant | base |
| Profile | target-mulHeavyPyramid |
| Trace execution | file-backed-checkpoint-replay |
| Initial data modulus | 490 bits across 11 data primes |
| Key modulus | 550 bits (data and special prime) |
| Build type | Release |
| Compiler | GNU 15.2.0 |
| SEAL version | 4.1.2 |
| SEAL acceleration | intel-hexl-runtime-dispatch |
| SHA-256 acceleration | openssl |
| Operating system | Linux 7.0.0-1011-gcp x86_64 |
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
