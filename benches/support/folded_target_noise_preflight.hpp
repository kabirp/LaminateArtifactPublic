#ifndef LAMINATE_BENCHES_FOLDED_TARGET_NOISE_PREFLIGHT_HPP
#define LAMINATE_BENCHES_FOLDED_TARGET_NOISE_PREFLIGHT_HPP

#include "target_noise_preflight.hpp"
#include "laminate/bench/folded_pyramid_parameters.hpp"
#include "laminate/bench/packed_process_profile.hpp"
#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/folded/prover.hpp"
#include "laminate/packing/alignment/unpack.hpp"
#include "laminate/packing/analysis/unbound_lazy_ternary_diagnostic.hpp"
#include "laminate/payload/trace/trace_sink.hpp"
#include "laminate/protocol/detail/packing/aligned_commitments.hpp"
#include "laminate/protocol/detail/packing/gkr_transcript_replay.hpp"
#include "laminate/protocol/detail/packing/messages.hpp"
#include "laminate/protocol/detail/packing/transcript_reader.hpp"
#include "laminate/protocol/packed/setup/proof_ingress.hpp"

#include <filesystem>
#include <utility>

namespace laminate::bench {
namespace folded_preflight_detail {

// A preflight may remove only the directory it created successfully. Existing
// paths (including symlinks) are never accepted or recursively cleared.
class ScratchDirectory {
  public:
    explicit ScratchDirectory(const std::filesystem::path &path) : path_(path) {
        if (!std::filesystem::create_directory(path_))
            throw std::runtime_error("Folded live-key preflight requires a fresh scratch directory");
    }
    ~ScratchDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    ScratchDirectory(const ScratchDirectory &) = delete;
    ScratchDirectory &operator=(const ScratchDirectory &) = delete;
    std::filesystem::path child(const std::string &name) const {
        const auto result = path_ / name;
        if (!std::filesystem::create_directory(result))
            throw std::runtime_error("Folded live-key preflight scratch child already exists");
        return result;
    }
  private:
    std::filesystem::path path_;
};

inline void require(bool accepted, const std::string &what) {
    if (!accepted)
        throw std::runtime_error("Folded live-key noise preflight FAILED: " + what +
                                 "; refusing expensive preprocessing; do not resample keys");
}

} // namespace folded_preflight_detail

// Bounded admission check using the actual setup's secret/evaluation key pair.
// It never creates keys, retries randomness, selects a different chain, or
// weakens normal verification. The exact target ancestor and its public masks
// are retained. Coherent message amplification tests width sensitivity; it is
// not a certificate for every source in the full target. Outer Spartan is not
// needed to evaluate noise and is deliberately outside this preflight.
inline void require_folded_pyramid_live_key_preflight(
    const payload::PayloadCircuit &target,
    const payload::LayeredCircuit &target_circuit,
    const std::vector<fhe::SlotVector> &inputs,
    const fhe::SealBackend::EvalContext &eval,
    const fhe::SealBackend::ClientContext &client,
    const payload::FheEvaluationPlan &target_plan,
    const std::filesystem::path &scratch_directory,
    std::uint64_t available_resident_bytes, std::ostream &report) {
    using namespace payload;
    using namespace fhe;
    using namespace gkr;
    using Backend = SealBackend;
    using folded_preflight_detail::require;
    constexpr WireId root_wire = 1042862;
    constexpr std::uint64_t resident_allowance = std::uint64_t{16} << 30U;
    constexpr std::uint64_t scratch_allowance = std::uint64_t{32} << 30U;
    constexpr std::uint64_t canonical_error_cap = 17781;
    const auto profile = packed_process_profile(
        PackedProcessVariant::Folded, PackedProcessTier::TargetMulHeavy, 0);
    if (available_resident_bytes < resident_allowance)
        throw std::runtime_error("Folded live-key preflight requires a 16 GiB resident allowance");
    if (std::filesystem::space(scratch_directory.parent_path()).available < scratch_allowance)
        throw std::runtime_error("Folded live-key preflight requires 32 GiB available scratch");
    if (eval.parameters != client.parameters || eval.storage_id != client.storage_id ||
        eval.parameters.poly_modulus_degree != 16384 ||
        eval.parameters.fresh_rns_limbs != kFoldedPyramidDataPrimes.size() ||
        eval.parameters.exact_data_primes != std::vector<std::uint64_t>(
            kFoldedPyramidDataPrimes.begin(), kFoldedPyramidDataPrimes.end()) ||
        eval.parameters.exact_special_prime != kFoldedPyramidSpecialPrime ||
        !eval.parameters.generate_galois_keys || inputs.size() != target.input_count ||
        target_circuit.layers.size() != 18)
        throw std::invalid_argument("Folded live-key preflight: live contexts/profile do not match");
    const auto cone = pyramid_noise_preflight_cone(target, root_wire);
    const auto circuit = compile(cone);
    if (circuit.layers.size() != target_circuit.layers.size() || cone.gates.size() != 925)
        throw std::logic_error("Folded live-key preflight: selected target ancestry changed");
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer)
        if (layer_kind(circuit.layers[layer]) != layer_kind(target_circuit.layers[layer]))
            throw std::logic_error("Folded live-key preflight: cone/target layer kinds differ");
    target_plan.validate(target_circuit);
    target_plan.validate(circuit);
    const auto public_setup = make_direct_setup(cone, circuit);
    const auto selected_ingress = protocol::derive_conservative_packed_proof_ingress_schedule(
        protocol::PackingGkrVariant::Folded, cone, circuit, public_setup,
        packed_process_proof_ingress_policy(profile));
    const std::vector<std::size_t> ingress(selected_ingress.rns_limbs_by_layer().begin(),
                                         selected_ingress.rns_limbs_by_layer().end());
    std::vector<std::size_t> depths;
    for (const auto limbs : ingress) depths.push_back(limbs - 1U);
    if (target_plan != packed_process_evaluation_plan(profile, circuit, depths))
        throw std::invalid_argument("Folded live-key preflight: target level plan differs from selected profile");
    const auto storage = canonical_trace_storage_layout(circuit);
    const auto target_storage = canonical_trace_storage_layout(target_circuit);
    // The required12/24 doublings cover the linear/quadratic coherent fan-in
    // ratio only while every target/cone source ratio is at most2^12.
    for (std::size_t source = 1; source < storage.size(); ++source) {
        const auto count = storage[source].stored_wire_count;
        const auto target_count = target_storage[source].stored_wire_count;
        if (count == 0 || count > 1024 || target_count / count > 4096 ||
            (target_count / count == 4096 && target_count % count != 0))
            throw std::logic_error("Folded live-key preflight: width amplification no longer covers target");
    }
    std::uint64_t plaintext_bytes = 0;
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        if (storage[layer].stored_wire_count > 1024)
            throw std::logic_error("Folded live-key preflight: cone exceeds ciphertext cap");
        plaintext_bytes += layer_dimensions(circuit.layers[layer]).padded_size *
                           std::uint64_t{16384} * sizeof(Fp);
    }
    if (plaintext_bytes > (std::uint64_t{2} << 30U))
        throw std::logic_error("Folded live-key preflight: plaintext trace exceeds 2 GiB cap");
    report << "FOLDED LIVE-KEY PREFLIGHT: root=" << root_wire
           << "; sampled target ancestry; outer Spartan excluded; same setup key; no retries\n"
           << std::flush;
    folded_preflight_detail::ScratchDirectory scratch(scratch_directory);
    const FileTraceStoreOptions limits{.max_total_bytes = std::uint64_t{16} << 30U,
                                       .min_free_bytes = 1};
    const auto plain = synthesize_trace(cone, circuit, inputs);
    const auto encrypted = encrypt_wide_payload_inputs<Backend>(client, cone, inputs);
    const auto server = make_packed_evaluation_setup<Backend>(public_setup, eval);
    auto natural_plan = target_plan;
    natural_plan.proof_ingress_mult_depth_by_layer = target_plan.trace.required_mult_depth_by_layer;
    const auto natural_directory = scratch.child("natural-trace");
    const auto natural_written = evaluate_wide_fhe_trace_into<Backend>(
        eval, cone, circuit, encrypted, natural_plan,
        FileEncryptedTraceSink<Backend>(eval, natural_directory, limits));
    const auto natural_trace = FileEncryptedTraceStore<Backend>::open(
        eval, natural_directory, cone, circuit, natural_written.descriptor.provenance,
        natural_written.descriptor.trace_id);
    const auto proof_directory = scratch.child("proof-trace");
    FileEncryptedTraceSink<Backend> proof_sink(eval, proof_directory, limits);
    proof_sink.begin_trace(circuit.shape, natural_written.descriptor.provenance,
        natural_written.descriptor.circuit_id, natural_written.descriptor.trace_id,
        circuit.layers.size());
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        const auto &descriptor = natural_written.descriptor.layers[layer];
        proof_sink.begin_layer(layer, descriptor.layout, descriptor.dimensions,
                               depths[layer], descriptor.record_count);
        auto reader = natural_trace.active_layer_reader(layer);
        int natural_minimum = std::numeric_limits<int>::max();
        int proof_minimum = std::numeric_limits<int>::max();
        while (auto entry = reader.next()) {
            const auto &expected = plain.layers[layer][entry->padded_index];
            require(materialize_or_decrypt<Backend>(client, entry->value) == expected,
                    "natural payload plaintext mismatch at layer " + std::to_string(layer));
            if (entry->value.is_encrypted()) {
                require(Backend::rns_limb_count(eval, entry->value.ciphertext()) ==
                            target_plan.trace.required_mult_depth_by_layer[layer] + 1U,
                        "natural level mismatch");
                natural_minimum = std::min(natural_minimum,
                    Backend::invariant_noise_budget(client, entry->value.ciphertext()));
                normalize_ciphertext_for_proof<Backend>(eval, entry->value.ciphertext(), depths[layer]);
                proof_minimum = std::min(proof_minimum,
                    Backend::invariant_noise_budget(client, entry->value.ciphertext()));
                require(Backend::rns_limb_count(eval, entry->value.ciphertext()) == ingress[layer],
                        "proof ingress level mismatch");
            }
            require(materialize_or_decrypt<Backend>(client, entry->value) == expected,
                    "proof-source plaintext mismatch at layer " + std::to_string(layer));
            proof_sink.append_value(entry->value);
        }
        require(natural_minimum > 0 && proof_minimum > 0, "exhausted source noise budget");
        proof_sink.finish_layer();
        report << "FOLDED LIVE-KEY PREFLIGHT: source=" << layer << " natural_budget="
               << natural_minimum << " proof_budget=" << proof_minimum << '\n' << std::flush;
    }
    const auto written = std::move(proof_sink).finish();
    const auto trace = FileEncryptedTraceStore<Backend>::open(
        eval, proof_directory, cone, circuit, written.descriptor.provenance, written.descriptor.trace_id);
    const auto layout = packing::make_fixed_message_coset_packing_layout(
        profile.slots, protocol::folded_bhip_round_count(circuit),
        profile.slots / kFixedMessageCellCount);
    protocol::detail::AlignedCommitmentCollector<Backend> collector(eval, layout);
    folded_detail::FileFoldedGkrOptions options;
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer)
        if (layer_kind(circuit.layers[layer]) == LayerKind::Multiplication)
            options.multiplication_scratch.push_back({layer,
                scratch.child("mul-" + std::to_string(layer)), limits});
    std::size_t active_layer = 0, message_index = 0;
    options.progress = [&](const RuntimeProgressEvent &event) {
        if (event.boundary == RuntimeProgressBoundary::Begin &&
            event.stage == RuntimeProgressStage::FoldedReduction) {
            active_layer = event.reduction_layer;
            report << "FOLDED LIVE-KEY PREFLIGHT: reduction=" << active_layer << '\n' << std::flush;
        }
    };
    const auto packing_parameters = packing::selected_lazy_ternary_parameters();
    if (packing_parameters.honest_partial_decryption_bound() != 1165346165ULL ||
        packing_parameters.repetitions != 120)
        throw std::logic_error("Folded live-key preflight: packing admission parameters changed");
    std::uint64_t maximum_original_error = 0;
    std::array<std::uint64_t, 2> maximum_stress_error{};
    std::array<std::size_t, 2> stress_message_count{};
    const auto inspect_commit = [&](const FheValue<Backend> &message) {
        const auto index = message_index++;
        require(index < layout.placements.size(), "too many GKR messages");
        const auto expected = materialize_or_decrypt<Backend>(client, message);
        const auto rotation = layout.placements[index].rotation_steps;
        const auto inspect = [&](const FheValue<Backend> &value, const SlotVector &expected_value,
                                 const char *kind) {
            require(materialize_or_decrypt<Backend>(client, value) == expected_value,
                    std::string(kind) + " plaintext mismatch before alignment");
            const auto pre_budget = value.is_encrypted()
                ? Backend::invariant_noise_budget(client, value.ciphertext()) : -1;
            auto aligned = value_rotate<Backend>(eval, value, rotation);
            const auto expected_aligned = grid_rotate(expected_value, rotation);
            require(materialize_or_decrypt<Backend>(client, aligned) == expected_aligned,
                    std::string(kind) + " plaintext mismatch after rotation");
            if (!aligned.is_encrypted()) return std::uint64_t{0};
            const auto rotated_budget = Backend::invariant_noise_budget(client, aligned.ciphertext());
            Backend::mod_switch_to_lowest(eval, aligned.ciphertext());
            Backend::normalize_for_coefficient_commitment(eval, aligned.ciphertext());
            require(materialize_or_decrypt<Backend>(client, aligned) == expected_aligned,
                    std::string(kind) + " plaintext mismatch after normalization");
            const auto norm = Backend::partial_decryption_infinity_norm(client, aligned.ciphertext());
            const auto error = Backend::canonical_error_infinity_norm(eval, client, aligned.ciphertext());
            report << "FOLDED LIVE-KEY PREFLIGHT: message=" << index << " layer=" << active_layer
                   << " check=" << kind << " pre_budget=" << pre_budget
                   << " rotated_budget=" << rotated_budget << " normalized_budget="
                   << Backend::invariant_noise_budget(client, aligned.ciphertext())
                   << " partial_norm=" << norm << " canonical_error=" << error << '\n' << std::flush;
            require(norm <= packing_parameters.honest_partial_decryption_bound() &&
                    error <= canonical_error_cap,
                    std::string(kind) + " individual noise bound at message " + std::to_string(index) +
                    ", layer " + std::to_string(active_layer) + ", canonical error " + std::to_string(error));
            return error;
        };
        maximum_original_error = std::max(maximum_original_error, inspect(message, expected, "original"));
        const auto kind = layer_kind(circuit.layers[active_layer]);
        require(kind == LayerKind::Affine || kind == LayerKind::Multiplication,
                "message emitted outside a reduction");
        const std::size_t ordinal = kind == LayerKind::Affine ? 0 : 1;
        const std::size_t doublings = ordinal == 0 ? 12 : 24;
        auto stressed = message;
        auto expected_stressed = expected;
        for (std::size_t power = 0; power < doublings; ++power) {
            stressed = value_add<Backend>(eval, stressed, stressed);
            for (auto &slot : expected_stressed) slot += slot;
        }
        maximum_stress_error[ordinal] = std::max(maximum_stress_error[ordinal],
            inspect(stressed, expected_stressed, "coherent width stress"));
        ++stress_message_count[ordinal];
        return collector.commit(message);
    };
    constexpr auto domain = "laminate/bench/folded-live-key-noise-preflight/v1";
    Transcript prover_transcript(domain);
    protocol::observe_packed_fiat_shamir_schedule(prover_transcript);
    Transcript output_point_transcript("laminate/bench/folded-live-key-output-point/v1");
    std::vector<Fpk> output_point(base_detail::layer_vars(circuit, 0));
    for (auto &coordinate : output_point) coordinate = output_point_transcript.challenge_fpk();
    const auto claim = make_layer_claim(plain.layers.front(), std::move(output_point));
    const auto proved = folded_detail::prove_folded_gkr<Backend>(
        cone, circuit, trace, server, claim.point, prover_transcript, std::move(options),
        ingress, {.reserved_mult_depth = kPackingReservedMultDepth}, inspect_commit);
    require(message_index == layout.placements.size() && stress_message_count[0] > 0 &&
            stress_message_count[1] > 0, "missing GKR messages or stress checks");
    const auto collected = std::move(collector).finish();
    const auto committed = protocol::commit_gkr_round_messages<Backend>(
        proved.proof, collected.commitments());
    std::vector<SlotVector> original_messages;
    protocol::for_each_transcript_packing_round_value<Backend>(proved.proof,
        [&](const FheValue<Backend> &value) {
            original_messages.push_back(materialize_or_decrypt<Backend>(client, value));
        });
    Transcript verifier_transcript(domain);
    const auto replay = protocol::detail::replay_packed_gkr_transcript<
        ProtocolVariant::LaminateFolded, Backend>(
            circuit, public_setup, committed, claim.point, verifier_transcript);
    require(static_cast<bool>(replay), "public GKR transcript replay rejected");
    protocol::detail::PackedTranscriptReader original_reader(original_messages);
    require(replay->make_plaintext_verifier(plain.layers.back(), claim, committed, original_reader).run(),
            "original GKR verification rejected");
    Transcript packing_transcript = prover_transcript;
    protocol::detail::bind_committed_gkr_for_packing(committed, packing_transcript);
    std::vector<PoseidonDigest> digests;
    for (const auto &commitment : collected.commitments()) digests.push_back(commitment.digest);
    const auto challenges = packing::derive_committed_lazy_ternary_challenges(
        layout, digests, packing_transcript, packing_parameters);
    const auto evaluation = packing::evaluate_lazy_ternary<Backend>(
        eval, collected.aligned(), challenges, packing_parameters);
    const auto observed = packing::assess_observed_lazy_ternary_diagnostic<Backend>(
        client, collected.aligned(), evaluation);
    require(observed.observed_inputs_within_configured_bound &&
            observed.all_tests_within_configured_threshold &&
            observed.accepted_tests == packing_parameters.repetitions,
            "packing input bound or reveal threshold rejected");
    const auto packed_plaintexts = packing::decrypt_and_recompose_signed_digit_packing<Backend>(
        client, evaluation.packed_digit_values, layout.packed_ciphertext_count,
        packing_parameters.packing_radix);
    const auto recovered = packing::unpack_packed_plaintexts(layout, packed_plaintexts);
    protocol::detail::PackedTranscriptReader recovered_reader(recovered);
    require(replay->make_plaintext_verifier(plain.layers.back(), claim, committed, recovered_reader).run(),
            "signed-digit-recovered GKR verification rejected");
    report << "FOLDED LIVE-KEY PREFLIGHT: PASS sampled_messages=" << message_index
           << " original_max_canonical_error=" << maximum_original_error
           << " affine12_max_canonical_error=" << maximum_stress_error[0]
           << " multiplication24_max_canonical_error=" << maximum_stress_error[1]
           << " canonical_cap=" << canonical_error_cap << " reveals=" << observed.accepted_tests
           << "/" << packing_parameters.repetitions
           << "; original and recovered GKR accepted; full target still requires verification\n"
           << std::flush;
}

} // namespace laminate::bench
#endif
