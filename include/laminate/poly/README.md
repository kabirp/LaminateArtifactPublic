# Multilinear polynomials

This directory provides the dense and sparse multilinear-polynomial helpers
shared by the proof layers.

[`multilinear.hpp`](multilinear.hpp) evaluates and folds materialized
hypercube tables. Its sparse representation sorts entries and rejects duplicate
indices, explicit zero entries, and out-of-domain indices.
[`eq.hpp`](eq.hpp) evaluates equality polynomials and the public BGV grid
rotation predicate.

Coordinates here are **most-significant-bit-first**: the first variable
selects the lower or upper half of a table. For example, `[0, 1]` selects
entry 1 of a four-entry table. `fix_first_variable(r)` replaces corresponding
entries from the two halves by `low + r * (high - low)`. The dense constructor
requires exactly `2^num_vars` entries, and evaluation requires exactly
`num_vars` coordinates.

The gate-table [`BaseFold helpers`](../basefold/common.hpp) use
least-significant-bit-first points. Callers must explicitly convert coordinate
order when crossing that boundary. The equality and rotation conventions are
checked in [`tests/poly/test_poly.cpp`](../../../tests/poly/test_poly.cpp).
