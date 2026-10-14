# Synthetic report fixtures

These records exercise report rendering and cleanup. All timings, resource
measurements, paths, host descriptions, and revision identifiers are invented.
The fixtures use the current workload geometry, proof policy, client timing
schema, and FHE prime schedule. They are not benchmark results.

`split-quick` covers detailed timing and storage diagnostics.
`split-target-balancedLaned` covers target storage admission and provenance.
The operator tests copy these records into the build directory before modifying
them, so lifecycle locks and failure cases never change the tracked fixtures.
