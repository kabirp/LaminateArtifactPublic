# Privacy estimates for the benchmark parameters

The proof-bearing depth-eight target profiles use ring degree `N=16,384` and target at
least **80 bits of classical privacy** under the attack model below. Estimates
use the full initial key modulus, including the special key-switching prime;
none of these profiles claims 128-bit privacy.

This page supplies reproducible estimator inputs for Section 7.1,
“Methodology.” Always match an estimate to the exact chain in the run's
setup records. Privacy and [protocol integrity](STATUS.md) are separate claims.

## Results and the governing modulus

| Target variant | Initial data-modulus bit length | Initial key-modulus bit length | Reported classical attack cost |
| --- | ---: | ---: | ---: |
| Base, balancedLaned | 430 | 463 | 118.8 bits |
| Base, mulHeavyPyramid | 490 | 550 | 99.9 bits |
| Folded, balancedLaned | 577 | 637 | 86.5 bits |
| Folded, mulHeavyPyramid | 626 | 686 | 80.8 bits |
| Laned, `B=1` or `128` | 617 | 677 | 81.8 bits |
| Laned, `B=N=16,384` | 577 | 637 | 86.5 bits |
| noIntegrity, mulHeavyPyramid | 500 | 555 | 98.9 bits |

Full-width Laned and Folded balancedLaned share the same exact chain,
ring dimension, and sampler, so they have the same estimate. These figures
apply to the targets, not reduced `quick` profiles.

Let `Q_fresh` be the product of the initial data primes and `P_ks` the special
key-switching prime. The estimator input is

```text
q = Q_key = Q_fresh * P_ks.
```

SEAL's public key and evaluation keys contain RLWE samples at `Q_key`. Later
modulus switching of payload ciphertexts does not remove this public
information. The concise benchmark summaries report **data-modulus** bit
lengths, which omit `P_ks`; using that smaller modulus would overstate the
privacy of the complete run. The terminal 60-bit packing prime is also not
the appropriate estimator modulus.

Bit length means `floor(log2(q)) + 1`, whereas the estimator receives the
exact integer product. Nominal sums of individual prime widths, such as
579/639 for Folded balanced/full-width Laned, 627/687 for Folded pyramid,
and 619/679 for partial-width Laned, are
not those product bit lengths.
A power of two does not substitute for an exact key-modulus product below.

The `noIntegrity` balanced target enforces SEAL's `tc128` parameter category,
with 398-bit data and 438-bit key products. The pyramid target uses
`sec_level_type::none` and the same 80-bit privacy target as the proof-bearing
profiles; its selected estimate is 98.9 bits. Exact chains are selected in
[`no_integrity_parameters.hpp`](../include/laminate/bench/no_integrity_parameters.hpp).
SEAL's table-based acceptance is distinct from the two-attack estimates here.
The `local` baseline has no encryption and no RLWE privacy parameter. Base,
Folded, and Laned use `sec_level_type::none`, which disables SEAL's parameter
table check and leaves their privacy assessment to the stated estimator model.
An estimator result does not establish correct decryption or proof
completeness; those depend on the [BGV schedule](BGV_NOISE_AND_MODULUS_SWITCHING.md).

## Estimator assumptions

The estimates use the [Lattice Estimator at commit
`3e48ef421ec256afddb3e7d2249a77eab6e9ba12`](https://github.com/malb/lattice-estimator/tree/3e48ef421ec256afddb3e7d2249a77eab6e9ba12).

| Input or convention | Setting |
| --- | --- |
| Runtime | SageMath 10.6 |
| LWE dimension | `n = 2**14`, the BGV ring degree, not the scalar payload gate count |
| Modulus | Exact `Q_key` product for the variant |
| Secret | `ND.Uniform(-1, 1, n)`: independent uniform ternary coefficients |
| Error | `ND.CenteredBinomial(21)` |
| Sample count | `m = oo` (unbounded, allowing the attack model to choose its sample count) |
| Lattice-reduction cost | Classical `RC.MATZOV` |
| Lattice shape | `red_shape_model="gsa"`, the geometric series assumption |
| Attacks reported | `LWE.primal_usvp` and `LWE.primal_bdd` |
| Bit estimate | The smaller `log2(result["rop"])` from those two attacks |

Here `rop` is the estimator's modeled operation cost. A value of 86.5 bits
means a modeled attack cost near `2^86.5`; it is not a measured attack runtime,
a failure probability, or a quantum-security estimate. The calculation covers the two classical lattice attacks listed above.
It does not survey every attack supported by the estimator or prove security
for the complete BGV protocol and its evaluation keys.

The centered-binomial model matches SEAL 4.1.2's default noise sampler when
`SEAL_USE_GAUSSIAN_NOISE=OFF`. Each error coefficient is the difference of two
independent sums of 21 fair bits, with standard deviation
`sqrt(21/2) = 3.24037...`.
SEAL's [sampler implementation](https://github.com/microsoft/SEAL/blob/v4.1.2/native/src/seal/util/rlwe.cpp)
defines both the uniform ternary secret and centered-binomial error sampling.
Preserve the dependency build's sampler setting when associating an estimate
with an archived run.

BGV introduces a factor of the plaintext modulus `t` in its error term.
Since `t=65,537` is invertible modulo `Q_key`, multiplying the public sample
by `t^-1` gives an equivalent RLWE sample with uniform public coefficient and
unscaled error. The estimator therefore uses `CenteredBinomial(21)`, not an
error distribution whose standard deviation is multiplied by `t`.

## Reproduce the reported attacks

This calculation needs SageMath 10.6 and the pinned estimator source, but no
SEAL build, secret keys, GCP VM, or payload benchmark. Work in a separate
directory so estimator files do not enter the Laminate source snapshot.
Download and extract the [pinned estimator archive](https://github.com/malb/lattice-estimator/archive/3e48ef421ec256afddb3e7d2249a77eab6e9ba12.tar.gz),
then save the following as `privacy_estimates.py` in its extracted root,
alongside the `estimator/` directory.

The data-prime lists and special primes below are the target chains. The
[Base benchmark](../benches/protocol/base_checkpoint_benchmark.cpp) specifies
its list directly. The [packed benchmark](../benches/protocol/packed_checkpoint_benchmark.cpp)
selects the Folded/Laned chains (including the explicit
[Folded pyramid primes](../include/laminate/bench/folded_pyramid_parameters.hpp)),
and the [SEAL context code](../src/fhe/seal/context.cpp)
generates and persists the exact primes. For an individual run, compare the
raw setup records: Folded/Laned expose `fhe.data_primes_bottom_to_top` and
`fhe.special_prime`; Base exposes `parameters.initial_ciphertext_modulus_primes`
with its special prime fixed in the linked source profile. The noIntegrity
records instead use `parameters.data_primes_bottom_to_top` and
`parameters.special_prime`. Concise summaries may omit these fields.

```python
from math import prod
from sage.all import ZZ, log, oo
from estimator import LWE, ND, RC

data_primes = {
    "Base balancedLaned": [
        1053858393162252289, 15032614913, 53687910401,
        96638238721, 98785755137, 118113402881, 122408435713,
        246964387841, 272734584833, 292062232577, 1095233372161,
    ],
    "Base mulHeavyPyramid": [
        1053858393162252289, 15032614913, 53687910401,
        35004517580801, 35017402679297, 35047467909121,
        35092565753857, 35111893401601, 35126926016513,
        35144106147841, 35156991246337,
    ],
    "Folded balancedLaned": [
        1053858393162252289, 281412698669057, 281449206448129,
        96638238721, 98785755137, 118113402881, 122408435713,
        246964387841, 272734584833, 547616686081, 998595133441,
        1005037682689, 1032955396097, 1095233372161,
    ],
    "noIntegrity mulHeavyPyramid": [
        1152921497895862273, 36028481325662209, 36028509243375617,
        36028635946844161, 36028638094360577, 36028674602139649,
        36028681044688897, 36028700372336641, 36028786272993281,
    ],
    "Laned B<N": [
        1053858393162252289, 281412698669057, 281449206448129,
        96638238721, 98785755137, 118113402881, 122408435713,
        246964387841, 272734584833, 547616686081, 972824936449,
        998595133441, 1005037682689, 1032955396097, 1095233372161,
    ],
}
special_primes = {
    "Base balancedLaned": 8590163969,
    "Base mulHeavyPyramid": 1152921504606748673,
    "Folded balancedLaned": 1152921504606748673,
    "Laned B<N": 1152921504606748673,
    "noIntegrity mulHeavyPyramid": 36028797017456641,
}
expected_bit_lengths = {
    "Base balancedLaned": (430, 463),
    "Base mulHeavyPyramid": (490, 550),
    "Folded balancedLaned": (577, 637),
    "Laned B<N": (617, 677),
    "noIntegrity mulHeavyPyramid": (500, 555),
}
data_primes["Folded mulHeavyPyramid"] = data_primes["Folded balancedLaned"][:6] + [
    35004517580801, 35017402679297, 35047467909121, 35092565753857,
    35111893401601, 35126926016513, 35144106147841, 35156991246337,
]
special_primes["Folded mulHeavyPyramid"] = 1152921504606748673
expected_bit_lengths["Folded mulHeavyPyramid"] = (626, 686)
data_primes["Laned B=N"] = data_primes["Folded balancedLaned"].copy()
special_primes["Laned B=N"] = special_primes["Folded balancedLaned"]
expected_bit_lengths["Laned B=N"] = expected_bit_lengths["Folded balancedLaned"]

for name, primes in data_primes.items():
    q_fresh = prod(primes)
    q_key = q_fresh * special_primes[name]
    assert (q_fresh.bit_length(), q_key.bit_length()) == expected_bit_lengths[name]
    params = LWE.Parameters(
        n=2**14,
        q=ZZ(q_key),
        Xs=ND.Uniform(-1, 1, 2**14),
        Xe=ND.CenteredBinomial(21),
        m=oo,
    )
    print(f"\n{name}: q={q_key}", flush=True)
    print(f"log2(q)={float(log(ZZ(q_key), 2).n()):.8f}", flush=True)
    bits = []
    for label, attack in (("primal-uSVP", LWE.primal_usvp),
                          ("primal-BDD", LWE.primal_bdd)):
        result = attack(params, red_cost_model=RC.MATZOV, red_shape_model="gsa")
        cost_bits = float(log(result["rop"], 2).n())
        bits.append(cost_bits)
        print(label, result, flush=True)
        print(f"log2(rop)={cost_bits:.8f}", flush=True)
    print(f"Reported minimum: {min(bits):.1f} bits", flush=True)
```

From that estimator directory, run:

```bash
set -euo pipefail
sage --version
sage -python privacy_estimates.py | tee privacy-estimates.txt
```

Expected values with the pinned version and settings. The packed prime lists
match SEAL 4.1.2 prime generation:

| Variant | `log2(Q_key)` | Primal-uSVP `log2(rop)` | Primal-BDD `log2(rop)` |
| --- | ---: | ---: | ---: |
| Base, balancedLaned | 462.86751230 | 118.99285330 | 118.76590563 |
| Base, mulHeavyPyramid | 549.28988409 | 99.94730270 | 99.93502208 |
| Folded, balancedLaned | 636.96406865 | 86.68780203 | 86.49347785 |
| Folded, mulHeavyPyramid | 685.63501843 | 80.90901772 | 80.77195869 |
| Laned, `B<N` | 676.78745791 | 81.77437006 | 81.75990297 |
| noIntegrity, mulHeavyPyramid | 554.99994917 | 99.08463739 | 98.85208996 |

Full-width `B=N` Laned uses the identical estimator input as Folded balancedLaned and therefore
has the same attack estimates. The [balanced and packed estimator output](privacy-estimates-balanced-and-laned.txt),
[Base pyramid estimator output](privacy-estimates-base-pyramid.txt),
[Folded pyramid estimator output](privacy-estimates-folded-pyramid.txt),
and [noIntegrity pyramid estimator output](privacy-estimates-nointegrity-pyramid.txt)
record the exact products, attack parameters, and costs.

Use these named attacks with explicit cost and shape models.
`LWE.estimate.rough` uses different assumptions, and a full `LWE.estimate`
invocation includes additional attacks; neither is the calculation reported
in this table. The [estimator documentation](https://github.com/malb/lattice-estimator/tree/3e48ef421ec256afddb3e7d2249a77eab6e9ba12#quick-start)
explains this distinction.

Each estimate is specific to its exact moduli, dimension, sampler, estimator
revision, Sage version, and attack model. The raw records above retain those
inputs with the complete attack output.
The [BGV guide](BGV_NOISE_AND_MODULUS_SWITCHING.md) separately documents
modulus switching and the honest-noise assumptions needed for correctness.
