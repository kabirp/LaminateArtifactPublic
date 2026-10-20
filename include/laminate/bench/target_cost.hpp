#ifndef LAMINATE_BENCH_TARGET_COST_HPP
#define LAMINATE_BENCH_TARGET_COST_HPP

/// @file target_cost.hpp
/// @brief RNS-level operation, wire-size, and client-crypto cost ledgers.
///
/// These ledgers describe operation counts, wire sizes, and memory bounds.
/// Runtime estimates require caller-supplied primitive timings. Measured
/// process results come from the corresponding benchmark run's result files.

#include "laminate/bench/schedule_cost.hpp"
#include "laminate/basefold/foldable.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace laminate::payload {
struct HonestBaseProofNormalizationPlan;
}

namespace laminate::bench {

/// Primitive calls issued while a ciphertext has exactly `rns_limbs` data
/// primes. A modulus switch is charged to its input level.
struct RnsLevelOperations {
    std::size_t rns_limbs = 0;
    ConcretePrimitiveUpperBound primitives;
    std::uint64_t modulus_switches = 0;
    /// Base-only subsets of `modulus_switches`.
    std::uint64_t base_proof_ingress_switches = 0;
    std::uint64_t base_proof_message_switches = 0;

    bool operator==(const RnsLevelOperations &) const = default;
};

/// RNS placement and one-time normalization counts for one Base reduction.
/// A zero natural-source count means that the formula-only caller configured
/// a uniform proof-ingress level without supplying an executable payload
/// schedule, so source-copy normalization is intentionally unmodeled.
struct BaseReductionRnsOperations {
    std::size_t reduction_layer = 0;
    std::size_t natural_source_rns_limbs = 0;
    std::size_t proof_ingress_rns_limbs = 0;
    std::size_t live_source_ciphertexts = 0;
    std::size_t proof_message_ciphertexts = 0;
    std::uint64_t ingress_switch_events = 0;
    std::uint64_t proof_message_switch_events = 0;

    bool operator==(const BaseReductionRnsOperations &) const = default;
};

struct ProverOperationLedger {
    ScheduleProtocol protocol = ScheduleProtocol::Base;
    /// Formula-only callers use this as a configured uniform proof-ingress
    /// limb count. Schedule-aware Base ledgers set it to the maximum approved
    /// per-reduction proof-ingress limb count.
    std::size_t core_rns_limbs = 0;
    /// True only when Base source-copy normalization was derived from an
    /// executable schedule rather than omitted by a formula-only projection.
    bool base_proof_ingress_normalization_modeled = false;
    std::uint64_t base_proof_ingress_switch_events = 0;
    std::uint64_t base_proof_message_switch_events = 0;
    std::vector<BaseReductionRnsOperations> base_reductions;
    /// Logical extension messages transported directly by Base. This count is
    /// exact even when the scalar-limb overload uses dense coordinate support.
    /// Zero for packed protocols.
    std::size_t direct_transcript_extension_messages = 0;
    /// Extension messages which are public algebraic zero in every coordinate.
    /// Circuit-aware and schedule-aware ledgers count topology-certified
    /// zeroes; runtime public-value annihilation may realize more. The scalar
    /// limb upper-bound overload leaves this at zero.
    std::size_t direct_transcript_public_zero_extension_messages = 0;
    /// Encrypted base-field coordinate capacity reserved for direct Base
    /// transport. The scalar-limb overload exposes the dense-coordinate bound;
    /// circuit-aware and schedule-aware ledgers use the conservative support
    /// envelope. Zero for packed protocols.
    std::size_t direct_transcript_ciphertexts = 0;
    /// Paper-equivalent raw transcript footprint `M*r` for packed protocols.
    /// This is a reserved-count comparison, not the number of transient
    /// ciphertext objects materialized by LaminateImpl's round encoder.
    std::size_t paper_raw_ciphertext_footprint = 0;
    /// One committed aligned ciphertext per packed BhIP round (`r`).
    /// Not used by Base.
    std::size_t aligned_ciphertexts = 0;
    /// Logical packed outputs `L = ceil(M*r/N)`. Not used by Base.
    std::size_t logical_packed_outputs = 0;
    std::size_t well_formedness_repetitions = 0;
    std::size_t signed_digits_per_output = 0;
    std::vector<RnsLevelOperations> levels;
};

/// Apply the selected implementation schedule. Base sends degree-eight
/// ciphertexts directly. Its scalar-limb overload is formula-only: it prices
/// every reduction at one configured uniform proof ingress and intentionally
/// does not infer a natural payload level. The normalization-plan overload is
/// schedule-aware and exposes one-time source-copy normalization separately.
/// Folded/Laned encode one aligned ciphertext per BhIP round, normally retain
/// three limbs for grid alignment, and run the base-17
/// well-formedness/packing arithmetic at one limb. The ledger charges
/// alignment rotations at the highest possible working level because the
/// public noise guard may retain a noisier message above three limbs. When
/// B<N, Laned witness masks run at the working level and its multiplication
/// reductions run one limb lower.
ProverOperationLedger base_operation_ledger(
    const ScheduleFormula &formula, std::size_t slot_count,
    std::size_t core_rns_limbs);
/// Circuit-aware formula-only Base ledger. It still omits natural payload
/// levels and source-ingress normalization, but derives a conservative public
/// support envelope for every proof message from the compiled circuit.
ProverOperationLedger base_operation_ledger(
    const payload::LayeredCircuit &circuit,
    const ScheduleFormula &formula, std::size_t slot_count,
    std::size_t core_rns_limbs);
/// Schedule-aware Base ledger. Each reduction's primitives run at its
/// setup-approved proof-ingress level. The ledger charges each live source
/// ciphertext once for every drop from its natural level to ingress, then
/// charges every proof coordinate admitted by the setup envelope from ingress
/// to q0. An execution may emit fewer ciphertext coordinates.
ProverOperationLedger base_operation_ledger(
    const ScheduleFormula &formula, std::size_t slot_count,
    const payload::HonestBaseProofNormalizationPlan &normalization_plan);
ProverOperationLedger packed_operation_ledger(
    const ScheduleFormula &formula, std::size_t slot_count,
    std::size_t core_rns_limbs,
    std::size_t well_formedness_repetitions =
        kPackingWellFormednessRepetitions,
    std::size_t signed_digits_per_output = 4);

/// RNS-weighted primitive runtime estimates. The switch proxy uses the
/// caller's key-switch timing for each modulus switch.
struct TargetRuntimeEstimate {
    double all_plain_ntt_ready_hours = 0;
    double preprocessing_aware_hours = 0;
    double all_plain_ntt_ready_with_modswitch_proxy_hours = 0;
    double preprocessing_aware_with_modswitch_proxy_hours = 0;
};

struct TargetRuntimeCalibration {
    double ntt_ready_plain_ms = 0;
    double online_plain_preparation_ms = 0;
    double ciphertext_product_ms = 0;
    double additive_ms = 0;
    double key_switch_ms = 0;
};

TargetRuntimeEstimate estimate_target_runtime(
    const ProverOperationLedger &ledger,
    const TargetRuntimeCalibration &calibration);

/// Online packed-prover runtime split at the committed-GKR boundary.
///
/// Preconditions:
/// - `ledger` describes Folded or Laned execution;
/// - its transcript-packing metadata and primitive rows are complete.
///
/// Postcondition: converting `gkr_and_alignment_hours` to seconds and adding
/// `transcript_packing_fhe_seconds` recovers the preprocessing-aware
/// estimate, up to floating-point rounding. Spartan is reported separately.
struct PackedProverRuntimeBreakdown {
    double gkr_and_alignment_hours = 0;
    double transcript_packing_fhe_seconds = 0;
};

PackedProverRuntimeBreakdown packed_prover_runtime_breakdown(
    const ProverOperationLedger &ledger,
    const TargetRuntimeCalibration &calibration);

struct PersistentBaseProofSizeEstimate {
    /// Persistent proof body encoded by Base's process transport.
    std::uint64_t inner_transport_bytes = 0;
    std::uint64_t fhe_message_bytes = 0;
    std::uint64_t partial_gate_mle_bytes = 0;
    std::uint64_t statement_and_metadata_bytes = 0;
    /// Fixed outer wire header and four public binding digests.
    std::uint64_t response_envelope_header_bytes = 0;
    std::uint64_t response_public_bindings_bytes = 0;
    /// Four u64 dimensions followed by the encoded output FHE-value vector.
    /// This target projection charges every logical output as a one-prime
    /// ciphertext, which is exact for the benchmark Diamond workloads.
    std::uint64_t response_output_dimensions_bytes = 0;
    std::uint64_t response_output_fhe_values_bytes = 0;
    std::uint64_t response_output_statement_bytes = 0;
    /// The u64 length immediately preceding `inner_transport_bytes`.
    std::uint64_t response_proof_length_prefix_bytes = 0;
    /// Every response byte outside the persistent proof body.
    std::uint64_t response_envelope_bytes = 0;
    /// Complete sole server-to-client response: bindings, encrypted output,
    /// and proof. No output claim is transmitted separately.
    std::uint64_t response_bytes = 0;
};

struct ProofSizeEstimate {
    /// Generic canonical proof encoding used by protocol::encode_canonical.
    /// The packing argument and outsourced GateMLE opening are added separately.
    std::uint64_t canonical_bytes_excluding_packing_argument = 0;
    /// Canonical bytes for FHE-backed proof messages, including their
    /// message/coordinate framing. This is not a raw ciphertext-byte count.
    std::uint64_t fhe_message_bytes = 0;
    std::uint64_t partial_gate_mle_bytes = 0;
    std::uint64_t gkr_commitment_bytes = 0;
    /// Extra wire allowance when a public slot-vector replaces a digest.
    std::uint64_t public_message_overhead_bytes = 0;
    std::uint64_t statement_and_metadata_bytes = 0;
    std::uint64_t one_prime_ciphertexts = 0;
    /// Present only for Base, whose process-persistent proof response has a
    /// distinct ciphertext encoding and outer message envelope.
    std::optional<PersistentBaseProofSizeEstimate> persistent_base;
};

/// Canonical outsourced Wide opening for the standard Base/Folded schedule:
/// one affine-input claim and one constant claim per affine layer. Geometry
/// comes from the compiled circuit, including local adjoints and shared masks.
/// The cap includes outer framing and every foldable PCS multiproof, using
/// their maximum frontiers. It needs no FHE evaluation or commitment files.
struct WideGateProofSizeEstimate {
    std::uint64_t canonical_bytes_upper_bound = 0;
    std::uint64_t pcs_bytes_upper_bound = 0;
    std::uint64_t outer_bytes = 0;
    std::size_t public_message_size = 0;
    std::size_t public_operands = 0;
    std::size_t adjoint_groups = 0;
};
WideGateProofSizeEstimate estimate_wide_gate_proof_size(
    const payload::LayeredCircuit &circuit,
    const basefold::foldable::Parameters &parameters = {});

/// Padding-aware target projection for the transcript-packing argument. The
/// Spartan core and the factored matrix-evaluation proof are reported
/// separately. The process benchmarks measure actual verification time.
struct SpartanPackingEstimate {
    /// Active equations; structural zero rows are excluded.
    std::uint64_t r1cs_constraints = 0;
    /// Matrix extent after binary-friendly row placement.
    std::uint64_t r1cs_matrix_rows = 0;
    std::uint64_t r1cs_logical_inputs = 0;
    std::uint64_t r1cs_public_inputs = 0;
    std::uint64_t r1cs_witness_variables = 0;
    std::uint64_t r1cs_nonzero_entries_upper_bound = 0;
    std::uint64_t padded_constraints = 0;
    std::uint64_t assignment_half_size = 0;

    /// One tensor per packed output. Owner counts follow the canonical
    /// fixed-message packing order; every padded count is a power of two.
    std::vector<std::uint64_t> factored_output_live_owners;
    std::vector<std::uint64_t> factored_output_padded_owners;
    std::uint64_t factored_tensor_live_elements = 0;
    std::uint64_t factored_tensor_padded_elements = 0;
    std::uint64_t factored_tensor_live_bytes = 0;
    std::uint64_t factored_tensor_padded_bytes = 0;
    std::uint64_t factored_largest_tensor_evaluations = 0;

    /// Payload-only retained-memory model for the selected top-level setup,
    /// with resident factored preprocessing. That key keeps
    /// its raw padded columns; BaseFold additionally keeps a message-column
    /// copy, rate-expanded codewords, and Merkle digests. The explicit
    /// artifact-backed process benchmark has its own admission model.
    /// Container metadata and allocator overhead are
    /// excluded.
    std::uint64_t factored_retained_raw_tensor_bytes = 0;
    std::uint64_t factored_retained_basefold_message_bytes = 0;
    std::uint64_t factored_retained_basefold_codeword_bytes = 0;
    std::uint64_t factored_retained_basefold_merkle_bytes = 0;
    std::uint64_t factored_retained_preprocessing_bytes_model = 0;
    /// Payload-only lower-bound peak for opening the largest tensor: retained
    /// preprocessing plus the simultaneously live dense Fq2 work tables.
    std::uint64_t factored_opening_peak_bytes_model = 0;

    /// Explicit verifier work in the compact regular evaluator. A
    /// ciphertext-segment visit contains a constant-rate Poseidon interval
    /// pass; an affine-segment visit is one owner/component/rate/segment DP
    /// branch. The counters expose the `Theta(T*r)` equality-weight queries
    /// and `r*polylog(T*r*N)` segmented work; each direct equality-weight query
    /// itself costs `Theta(log C_pad)` field operations.
    std::uint64_t regular_poseidon_segments = 0;
    std::uint64_t regular_poseidon_ciphertext_segment_visits = 0;
    std::uint64_t regular_poseidon_rate_interval_evaluations = 0;
    std::uint64_t regular_poseidon_boundary_segment_visits = 0;
    std::uint64_t regular_poseidon_digest_terms = 0;
    std::uint64_t regular_challenge_bit_visits = 0;
    std::uint64_t regular_test_ciphertext_pair_visits = 0;
    std::uint64_t regular_owner_affine_segment_visits = 0;
    std::uint64_t regular_public_affine_range_evaluations = 0;
    std::uint64_t regular_high_equality_table_elements = 0;

    /// Explicit verifier work in the factored residual proof.
    std::uint64_t factored_sumcheck_rounds = 0;
    std::uint64_t factored_digit_weight_terms = 0;
    std::uint64_t factored_terminal_owner_terms = 0;
    std::uint64_t factored_terminal_affine_segment_visits = 0;
    std::uint64_t factored_basefold_openings = 0;
    std::uint64_t factored_basefold_queries = 0;
    /// Algebraic fold-pair steps checked across all BaseFold queries. This is
    /// `query_count * sum(log2(K_o))`; only `log2(K_o)-1` intermediate layers
    /// per tensor carry Merkle openings because the final layer is explicit.
    std::uint64_t factored_basefold_query_fold_steps = 0;
    std::uint64_t factored_basefold_merkle_hashes = 0;

    /// Setup-derived upper bounds. Actual union-frontier openings can be
    /// smaller and are measured from their serialized proof objects.
    std::uint64_t core_proof_max_bytes = 0;
    std::uint64_t factored_proof_max_bytes = 0;
    std::uint64_t proof_max_bytes = 0;
    /// Payload-only phase model for the generic Spartan core. It counts the
    /// retained witness BaseFold state and live dense tables, but excludes the
    /// caller-owned witness, expanded R1CS key, allocator overhead, and proof
    /// objects. The peak is the maximum of the phases, never their sum.
    std::uint64_t core_retained_witness_pcs_bytes_model = 0;
    std::uint64_t core_assignment_commitment_peak_bytes_model = 0;
    std::uint64_t core_constraint_peak_memory_bytes_model = 0;
    std::uint64_t core_wiring_peak_memory_bytes_model = 0;
    std::uint64_t core_witness_opening_peak_memory_bytes_model = 0;
    std::uint64_t core_peak_memory_bytes_model = 0;
};

/// Exact SEAL-v4.1 uncompressed size for a normalized size-two ciphertext at
/// one data prime, as checked by the SEAL formula tests.
std::uint64_t one_prime_seal_ciphertext_bytes(std::size_t slot_count);

/// Circuit-only dense-coordinate upper bound for a Base proof. Retained for
/// small closed-form comparisons which intentionally do not derive message
/// support. The persistent estimate includes the sole combined response and
/// its one-prime encrypted output. It deliberately excludes the request:
/// fresh input-ciphertext bytes depend on the selected payload modulus
/// schedule and are sized by the schedule-aware benchmark preflight.
ProofSizeEstimate estimate_base_proof_size(
    const payload::LayeredCircuit &circuit,
    const ScheduleFormula &formula);
/// Base proof size using the ledger's safe optional-coordinate topology. The
/// circuit-aware and schedule-aware ledgers are exact when every planned
/// coordinate is encrypted; public-only
/// subcircuits can make the operational proof strictly smaller. A dense
/// scalar-limb ledger recovers the coarser upper-bound overload above. Request
/// sizing remains schedule-aware for the same reason as above.
ProofSizeEstimate estimate_base_proof_size(
    const payload::LayeredCircuit &circuit,
    const ScheduleFormula &formula,
    const ProverOperationLedger &ledger);
/// Packed wire cap, including nonuniform public messages. Every aligned
/// message reserves the larger of a digest and a sparse public vector with
/// at most sixteen nonzero fixed-message cells. This covers ciphertext
/// cancellation that exposes a public value for exceptional challenges.
ProofSizeEstimate estimate_packed_proof_size(
    const payload::LayeredCircuit &circuit,
    const ProverOperationLedger &ledger);

SpartanPackingEstimate estimate_spartan_packing(
    const payload::LayeredCircuit &circuit,
    const ProverOperationLedger &ledger);

struct VerifierCryptoLedger {
    std::uint64_t one_prime_decryptions = 0;
    std::uint64_t recovered_gkr_messages = 0;
    std::uint64_t direct_gate_mle_queries = 0;
    /// Boolean partial-GateMLE vectors authenticated by Base. Each vector
    /// contributes one N-term terminal use and one N-term MLE check.
    std::uint64_t base_partial_gate_mle_vectors = 0;
    /// Packing-side work excluded from this GKR-only ledger and priced as
    /// separate verifier components by the process benchmark.
    std::uint64_t excluded_packing_partial_decryption_norm_checks = 0;
    /// GKR commitment digests consumed by the direct packing public vector.
    std::uint64_t excluded_packing_commitment_digests = 0;
};

VerifierCryptoLedger estimate_verifier_crypto(
    const payload::LayeredCircuit &circuit,
    const ProverOperationLedger &ledger);

} // namespace laminate::bench

#endif // LAMINATE_BENCH_TARGET_COST_HPP
