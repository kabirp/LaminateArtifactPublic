# Reproducing the prior-work estimates

[prior_work_estimates.py](../benches/reports/prior_work_estimates.py) reproduces
the Phalanx and Blind Fractal estimates in Section 7.4, “Comparison with Prior
Work,” of the Laminate paper. It needs only Python 3 and its standard library.
From the repository root, run:

```bash
python3 benches/reports/prior_work_estimates.py
python3 benches/reports/prior_work_estimates.py --json
```

The first command prints a table. The second also gives operation counts,
per-stage costs, ciphertext counts, and the parameters used. Neither command
runs a benchmark or downloads dependencies.

Each row estimates one proof for the entire circuit of size `2^20`, `2^27`, or
`2^34`. The encrypted witness is assumed to be available in the scheme's
required field and layout. The estimates cover selected costs in the published
provers, rather than the cost of a complete delegation request or a minimum
over all possible implementations. Sections H.3 and H.4, “Asymptotic Comparison
with Prior Work” and “Concrete Estimates for Prior Work,” state the asymptotic
bounds and comparison assumptions.

## What the script counts

**Phalanx.** Server time scales the reported 1,034-second matrix computation at
`n = 2^20` by `n / 2^20`, keeping ring dimension `N = 16,384` fixed. This stage
computes `Az`, `Bz`, and `Cz` for the R1CS check `Az * Bz = Cz`, with
entrywise multiplication. It is also needed by Phalanx*. The estimate excludes
packing, commitments, sumchecks, payload evaluation, and witness construction.
The comparison allows at most three sequential multiplication stages per
Phalanx NTT, but the counted matrix stage does not charge for those NTTs.

At `2^20`, proof size is the reported 61.4 MB for 504 ciphertexts. At larger
sizes, the commitment opens 240 columns to check the encoding and 240 more
to check the claimed evaluation. With `N`-row packing, each check also sends
a linear combination of the rows with `n/N` entries over a degree-three
extension field, requiring at least `ceil(3n/N^2)` ciphertexts. Each of
Spartan's two sumchecks contributes one ciphertext per round for
`log2(n/N)` rounds. The script therefore counts

```text
480 + 2 ceil(3n / N^2) + 2 log2(n / N)
```

ciphertexts, giving 510 at `2^27` and 904 at `2^34`, and prices them at the
reported average of `61.4 / 504` MB each. These larger-size estimates omit
other messages and authentication paths.

The separate storage calculation assumes one ciphertext per witness value,
with two polynomials of degree below `N` and six 64-bit limbs per coefficient. Each
ciphertext then occupies `2 * N * 6 * 8 = 1,572,864` bytes, about 1.57 MB.
Materializing all `n` ciphertexts takes approximately 211 TB at `2^27` or
27 PB at `2^34`, before storing the matrix products. This is not a
peak-memory estimate for a streaming implementation, and the server-time
estimate does not charge for storing, streaming, or recomputing the witness.

**Blind Fractal.** Server time counts unpacking, three sparse matrix products,
four inverse NTTs, and four initial forward NTTs. The transforms interpolate
`z`, `Az`, `Bz`, and `Cz`, then evaluate the resulting polynomials on the
larger Reed–Solomon code domain. The calculation follows the authors'
counting model, using 256 packed values per ciphertext and average matrix
row weight three. Each count is multiplied by the corresponding published
primitive time. The selected power-of-two NTT parameters minimize this
counted transform cost subject to depth at most five, or four at `2^27`:

| Circuit size | Radix | Inverse width | Forward width | Depth per NTT |
| --- | ---: | ---: | ---: | ---: |
| `2^20` | 8 | 1 | 2 | 5 |
| `2^27` | 64 | 2 | 4 | 4 |
| `2^34` | 64 | 4 | 8 | 5 |

The model uses ring dimension 12,288 with timings measured at dimension 16,384,
as in the source. The script retains the source's primitive prices at larger
sizes and does not rerun its noise analysis. The larger instances fail the
source's full noise checks, and at `2^34` the original field is too small for
the code domain and stated integrity target. The estimates omit any additional
cost of enlarging these parameters, as well as all later prover stages.

Blind Fractal's proof-data estimate uses the smaller ciphertexts in Remark 3:
dimension 768, a 24-bit modulus, and 16 slots. Its 101 independent query paths
can request the same ciphertext more than once. For `g` equally likely groups,
`occupied` computes `g * (1 - (1 - 1/g)^101)`, the expected number requested at
least once: each group is missed by all 101 paths with probability
`(1 - 1/g)^101`. For domain size `D = 2n`, 16 slots per ciphertext, and
`h = log2(D/16)`, the paired FRI openings in `bf_openings` total

```text
1 + 5 * occupied(D/16) + sum(occupied(D/(2^(i-1) * 16)), i=2,...,h).
```

The terms account for the final ciphertext, five initial polynomial tables,
and the later FRI levels. Each ciphertext contributes
`2 * 768 * 24 / 8 = 4,608` bytes. Hashes and other proof data are excluded.
Server time also excludes the conversion and repacking needed to obtain these
smaller ciphertexts.

**Client time.** Both rows estimate proof-ciphertext decryption alone, excluding
input encryption, output decryption, and all other verification work. Phalanx
uses a 0.40 ms single-limb BGV decryption price from our measurements. Blind
Fractal uses it as a proxy for GBFV and scales it by `N log2(N)` to dimension
768. These are partial-cost estimates, not measured client runtimes.

Sizes use decimal MB, TB, and PB. The script prints six decimal places and
retains more precision in JSON. The paper rounds server and client lower-bound
entries down and proof sizes to the nearest tenth of a megabyte.

## Sources

- [Phalanx](https://eprint.iacr.org/2025/302), Section 5.2 and Table 3 of the
  22-page version reporting 2.27 h and 0.68 h. The script uses the 1,034-second
  matrix stage, the 504-ciphertext count, and the 61.4 MB proof size.
- [Blind zkSNARKs for zkDel and vCOED](https://cic.iacr.org/p/2/3/10/pdf),
  Section 8.2.1, Appendix F, and Remark 3.
- [Blind Fractal estimator, commit
  `006d5cd`](https://github.com/KULeuven-COSIC/blind_zkSNARKs/tree/006d5cdff27479d7568646752e46982efbcb8164/blindFractal):
  `utils.m` for operation counts, the first four stages of `estimates.m`, and
  `HEspecs.m` for primitive timings.
