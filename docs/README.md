# Documentation

Start with the [project quick start](../README.md#build-and-run-a-small-proof)
and [artifact guide](ARTIFACT_GUIDE.md). For results, see the
[benchmark reports](../bench_outputs/README.md) and Section 7, “Evaluation,” of
the paper.

## Conceptual guides

These explain the implementation and help you find the relevant code.

| Read this to understand… | Guide |
| --- | --- |
| Roles, message flow, executable entry points, and main proof paths | [Architecture and code map](ARCHITECTURE.md) |
| How Base, Folded, and Laned correspond to the paper | [Protocols](PROTOCOLS.md) |
| How a payload becomes alternating affine and multiplication layers | [Layering](LAYERING.md) |
| How affine coefficients are represented and opened | [GateMLE](GATE_MLE_PERFORMANCE.md) |
| How Folded and Laned compress their proof messages | [Transcript packing](TRANSCRIPT_PACKING.md) |
| Supported behavior and security assumptions | [Implementation scope](STATUS.md) |

The [module guide](../include/laminate/README.md) links public interfaces,
implementations, and tests. The [test guide](../tests/README.md) explains the
Mock and SEAL suites.

## Runbooks and detailed reference

Use these when reproducing measurements or checking implementation details.

| Task | Document |
| --- | --- |
| Run benchmarks on the reference GCP host | [GCP runbook](GCP_BENCHMARKS.md) |
| Measure direct scalar evaluation | [Local runbook](LOCAL_BENCHMARKS.md) |
| Check the host and completed-run evidence | [Benchmark validation](BENCHMARK_VALIDATION.md) |
| Interpret workloads, timing boundaries, and report fields | [Benchmarking reference](BENCHMARKING.md) |
| Find a benchmark executable | [Benchmark catalog](../benches/README.md) |
| Locate memory, disk, and operation-count estimates | [Cost model](COST_MODEL.md) |
| Reproduce lattice attack estimates | [Privacy estimates](PRIVACY_ESTIMATES.md) |
| Inspect modulus chains and noise scheduling | [BGV parameters](BGV_NOISE_AND_MODULUS_SWITCHING.md) |
| Inspect integer well-formedness admission checks | [Well-formedness](WELL_FORMEDNESS_THEOREMS.md) |
| Inspect RS and generic foldable PCS query admission | [RS BaseFold](BASEFOLD_SOUNDNESS.md) and [Wide gates](WIDE_GATE_SOUNDNESS.md) |

## Paper and artifact

The accompanying paper, *Laminate: Succinct SIMD-Friendly Verifiable FHE*,
defines the constructions and proves their guarantees. These guides focus on
code and reproduction. The references below use the paper's section titles
and numbers.

| Topic | Paper section | Implementation guide |
| --- | --- | --- |
| BGV noise | Section 4.2.3, “Noise Budget and Efficiency” | [BGV parameters](BGV_NOISE_AND_MODULUS_SWITCHING.md) |
| Wide reductions | Appendix D, “Layer Reductions for Wide Payload Circuits” | [Protocols](PROTOCOLS.md) |
| Laned construction | Appendix E, “Specialized BhIP for Laned Payload Circuits” | [Layering](LAYERING.md) |
| Affine coefficient openings | Appendix C, “Affine Coefficients and Openings” | [Wide gates](WIDE_GATE_SOUNDNESS.md) |
| Transcript packing | Section 6.1, “Transcript Packing Compiler” | [Transcript packing](TRANSCRIPT_PACKING.md) |
| Well-formedness | Section F.4, “Proofs of the Well-Formedness Guarantees” | [Admission checks](WELL_FORMEDNESS_THEOREMS.md) |
| Integrity parameters | Section H.2, “Integrity Parameters” | [Implementation scope](STATUS.md) |
| Measurement boundaries | Section 7.1, “Methodology,” and Section H.1, “Builds and Timing Boundaries” | [Benchmarking reference](BENCHMARKING.md) |
