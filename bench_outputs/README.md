# Benchmark reports

These reports record the measured configuration, source revision, verification
outcome, timings, proof size, and resource use for each run.

| Protocol or baseline | balancedLaned | mulHeavyPyramid |
| --- | --- | --- |
| Local evaluation | [Report](local-balancedLaned-summary.md) | [Report](local-mulHeavy-summary.md) |
| FHE without integrity | [Report](noIntegrity-balancedLaned-summary.md) | [Report](noIntegrity-mulHeavy-summary.md) |
| LaminateBase | [Report](base-balancedLaned-summary.md) | [Report](base-mulHeavy-summary.md) |
| LaminateFolded | [Report](folded-balancedLaned-summary.md) | [Report](folded-mulHeavy-summary.md) |
| LaminateLaned, B=1 | [Report](laned-b1-balancedLaned-summary.md) | — |
| LaminateLaned, B=128 | [Report](laned-b128-balancedLaned-summary.md) | — |
| LaminateLaned, B=16,384 | [Report](laned-b16384-balancedLaned-summary.md) | — |

Folded supports both payloads. A dash marks a workload outside the variant's
supported payload language.

Full-width runs cover `2^34` scalar gates. Laned runs cover `B × 2^20` scalar
gates, so changing B changes the plaintext computation being measured.

See Section 7, “Evaluation,” of the paper for comparisons,
[measurement definitions](../docs/BENCHMARKING.md) for timing boundaries, and
the [GCP runbook](../docs/GCP_BENCHMARKS.md) to reproduce a run. Each report's
own parameters and source identity define its measurement.
