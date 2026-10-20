/// @file test_base_affine_file_backed.cpp
/// @brief Exact Mock parity for compact LaminateBase affine reduction.

#include "test_helpers.hpp"

#include "laminate/bench/schedule_cost.hpp"
#include "laminate/diagnostics/setup_validation.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gates/gate_mle.hpp"
#include "laminate/gkr/detail/base/affine/verifier.hpp"
#include "laminate/gkr/detail/base/affine/prover.hpp"
#include "laminate/gkr/detail/base/verification/proof_reader.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"
#include "laminate/payload/trace.hpp"
#include "laminate/payload/trace/trace_crypto.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
using namespace laminate::payload;

constexpr std::size_t kSlots = 8;

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-base-affine-file-backed-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (!std::filesystem::exists(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to select a temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

SlotVector values(std::uint64_t seed) {
    SlotVector result;
    result.reserve(kSlots);
    for (std::size_t slot = 0; slot < kSlots; ++slot) {
        result.emplace_back(seed + 5 * slot + slot * slot);
    }
    return result;
}

PayloadCircuit affine_payload(std::size_t inputs = 3) {
    PayloadBuilder builder(PayloadShape::wide(kSlots), inputs);
    builder.set_outputs({builder.add(0, 1)});
    return builder.finish();
}

std::vector<Fpk> point(std::size_t variables, std::uint64_t seed) {
    std::vector<Fpk> result;
    result.reserve(variables);
    for (std::size_t variable = 0; variable < variables; ++variable) {
        result.push_back(Fpk::from_base(Fp(seed + 7 * variable)));
    }
    return result;
}

bool equal_extension(const ExtensionValue<MockBackend> &left,
                     const ExtensionValue<MockBackend> &right) {
    return serialize_extension_value<MockBackend>(left) ==
           serialize_extension_value<MockBackend>(right);
}

template <typename Reader> class ActiveReaderAdapter {
  public:
    explicit ActiveReaderAdapter(Reader reader)
        : reader_(std::move(reader)) {}

    auto next() { return reader_.next(); }
    void rewind() { reader_.rewind(); }
    std::size_t begin() const { return reader_.begin(); }
    std::size_t end() const { return reader_.end(); }
    std::size_t position() const { return reader_.position(); }
    std::uint64_t encoded_bytes_read() const {
        return reader_.encoded_bytes_read();
    }
    std::uint64_t serialized_records_read() const {
        return reader_.serialized_records_read();
    }

  private:
    Reader reader_;
};

/// A distinct source and reader pair exercises the narrow affine contracts
/// without exposing file paths or a serialized backend-context identifier.
template <fhe::PersistableFheBackend Backend>
class AffineSourceAdapter {
  public:
    explicit AffineSourceAdapter(
        const FileEncryptedTraceStore<Backend> &source)
        : source_(&source) {}

    const auto &descriptor() const { return source_->descriptor(); }
    bool matches_backend_context(
        const typename Backend::EvalContext &eval) const {
        return source_->matches_backend_context(eval);
    }
    const auto &layered_circuit_id() const {
        return source_->layered_circuit_id();
    }
    const auto &layer_support(std::size_t layer) const {
        return source_->layer_support(layer);
    }
    auto active_layer_reader(std::size_t layer) const {
        return ActiveReaderAdapter(source_->active_layer_reader(layer));
    }

  private:
    const FileEncryptedTraceStore<Backend> *source_;
};

bool equal_affine_proofs(
    const base_detail::ProvedAffine<MockBackend> &left,
    const base_detail::ProvedAffine<MockBackend> &right) {
    if (left.proof.rounds.size() != right.proof.rounds.size() ||
        left.proof.partial_gate_mle.evaluations !=
            right.proof.partial_gate_mle.evaluations ||
        left.next_claim != right.next_claim) {
        return false;
    }
    for (std::size_t round = 0; round < left.proof.rounds.size(); ++round) {
        for (std::size_t evaluation = 0; evaluation < 2; ++evaluation) {
            if (!equal_extension(
                    left.proof.rounds[round].evaluations[evaluation],
                    right.proof.rounds[round].evaluations[evaluation])) {
                return false;
            }
        }
    }
    return equal_extension(left.proof.source_vector,
                           right.proof.source_vector);
}

} // namespace

int main() {
    test::Runner runner("Base affine reduction");

    runner.run("compact active records produce a verified reduction",
               [] {
        const PayloadCircuit payload = affine_payload();
        const LayeredCircuit circuit = compile(payload);
        CHECK(circuit.layers.size() == 2);
        const std::vector<SlotVector> inputs{
            values(3), values(41), values(97)};
        const PlainTrace plain = synthesize_trace(
            payload, circuit, inputs);
        auto contexts = MockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = 8,
            .bits_per_limb = 128,
            .initial_noise_margin_bits = 4,
        });
        const EncryptedTrace<MockBackend> compact =
            encrypt_compact_synthetic_trace<MockBackend>(
                contexts.eval, contexts.client, payload, circuit, plain,
                TraceEncryptionPlan::uniform(circuit, 5));

        const auto support = canonical_trace_wire_support(circuit);
        CHECK(support[1].padded_wire_count == 4);
        CHECK(support[1].live_wire_count == 3);
        CHECK(!support[1].is_live(3));

        TemporaryDirectory directory;
        (void)write_file_encrypted_trace(
            contexts.eval, directory.path(),
            FileTraceStoreOptions{
                .max_total_bytes = std::uint64_t{1} << 24U,
                .min_free_bytes = 1,
            },
            circuit, compact);
        const auto store = FileEncryptedTraceStore<MockBackend>::open(
            contexts.eval, directory.path(), payload, circuit,
            compact.provenance, compact.trace_id);

        constexpr std::size_t kLayer = 0;
        const SingleClaim claim = make_layer_claim(
            plain.layers[kLayer],
            point(base_detail::layer_vars(circuit, kLayer), 17));
        const LayerClaim layer_claim = claim;
        const gates::DirectGateMle provider(circuit);

        MockBackend::reset_counts(contexts.eval);
        base_detail::BaseAffineStatistics statistics;
        Transcript production_transcript(
            "test/base/affine-file-backed/v1");
        const base_detail::BaseAffineSourceAdmission source_admission =
            base_detail::BaseAffineSourceAdmission::validate(circuit, store);
        diagnostics::LayeredCircuitValidationCounter recurring_scans;
        const auto production_proof = [&] {
            diagnostics::ObserveLayeredCircuitValidation observe(
                recurring_scans);
            return base_detail::prove_admitted_affine_reduction<MockBackend>(
                contexts.eval, circuit, store, source_admission,
                store.layer_support(kLayer + 1U), kLayer, layer_claim,
                provider, production_transcript, nullptr, &statistics);
        }();
        CHECK(recurring_scans.scans == 0);
        const OperationCounts proving_operations =
            MockBackend::counts(contexts.eval);

        const AffineSourceAdapter<MockBackend> adapted_source(store);
        base_detail::BaseAffineStatistics adapted_statistics;
        Transcript adapted_transcript(
            "test/base/affine-file-backed/v1");
        const auto adapted_proof =
            base_detail::prove_affine_reduction<MockBackend>(
                contexts.eval, circuit, adapted_source,
                adapted_source.layer_support(kLayer + 1U), kLayer,
                layer_claim, provider, adapted_transcript, nullptr,
                &adapted_statistics);
        CHECK(equal_affine_proofs(production_proof, adapted_proof));
        CHECK(statistics == adapted_statistics);

        const bench::ScheduleFormula formula =
            bench::base_schedule_formula(circuit);
        CHECK(formula.layers.size() == 1);
        const bench::ScheduleLayerFormula &layer_formula =
            formula.layers.front();
        CHECK(layer_formula.source_stored_values == 3);
        CHECK(layer_formula.source_virtual_wire_positions == 4);
        CHECK(layer_formula.source_materialized_packed_ciphertexts == 3);
        CHECK(layer_formula.source_virtual_packed_positions == 4);
        CHECK(layer_formula.reduction_domain_variables == 2);
        CHECK(layer_formula.operations.weighted_base_terms == 11);
        CHECK(layer_formula.operations.online_vector_weighted_base_terms == 0);
        CHECK(layer_formula.operations.extension_plain_multiplications == 3);
        CHECK(layer_formula.operations
                  .online_vector_extension_plain_multiplications == 3);
        CHECK(layer_formula.operations.extension_additions == 4);
        const bench::ConcretePrimitiveUpperBound bound =
            bench::concrete_primitive_upper_bound(
                layer_formula.operations, kSlots);
        CHECK(proving_operations.mul_plain_scalar +
                  proving_operations.mul_plain_vector <=
              bound.plain_multiplications);
        CHECK(proving_operations.add <= bound.additions);

        base_detail::ProofReader<MockBackend> reader(contexts.client);
        gates::DirectGateMle verifier_provider(circuit);
        Transcript verifier_transcript(
            "test/base/affine-file-backed/v1");
        const auto verified =
            base_detail::verify_affine_reduction<MockBackend>(
            reader, circuit, kLayer, layer_claim,
            production_proof.proof, verifier_provider,
            verifier_transcript);
        CHECK(verified.has_value());
        CHECK(verified->point == production_proof.next_claim.point);
        CHECK(*verified ==
              make_layer_claim(plain.layers[kLayer + 1],
                               verified->point));
        CHECK(production_transcript.challenge_fpk() ==
              verifier_transcript.challenge_fpk());

        const std::uint64_t expected_scans =
            static_cast<std::uint64_t>(
                base_detail::ciphertext_index_variables(circuit, 1) + 1);
        const std::uint64_t expected_records =
            expected_scans * support[1].live_wire_count;
        CHECK(statistics.source_scans == expected_scans);
        CHECK(statistics.source_rewinds == expected_scans);
        CHECK(statistics.source_ciphertexts_read == expected_records);
        CHECK(statistics.public_zero_positions ==
              expected_scans * (support[1].padded_wire_count -
                                support[1].live_wire_count));
        CHECK(statistics.source_logical_bytes_read > 0);
        CHECK(statistics.source_framed_record_bytes_read ==
              statistics.source_logical_bytes_read +
                  expected_records * sizeof(std::uint64_t));
        CHECK(statistics.peak_live_source_ciphertexts == 1);
        CHECK(statistics.peak_retained_extension_accumulators == 2);
        CHECK(statistics.source_scalar_promotions > 0);
        CHECK(statistics.prepared_rotation_bases > 0);
        CHECK(statistics.prepared_rotation_basis_applications > 0);
        CHECK(statistics.prepared_base_promotion_applications > 0);
        CHECK(layer_formula.operations.weighted_base_terms ==
              statistics.source_scalar_promotions +
                  support[1].live_wire_count + 1U);
        CHECK(layer_formula.operations.extension_plain_multiplications ==
              statistics.prepared_rotation_basis_applications);
        const std::uint64_t wire_variables =
            base_detail::ciphertext_index_variables(circuit, 1);
        const std::uint64_t expected_live_weight_work =
            support[1].live_wire_count * wire_variables;
        CHECK(statistics.public_live_source_candidate_weight_lookups ==
              2U * expected_live_weight_work);
        CHECK(statistics.public_live_source_weight_updates ==
              expected_live_weight_work);
        CHECK(statistics.public_gate_term_candidate_visits > 0);
        CHECK(statistics.public_gate_term_weight_updates > 0);
        CHECK(statistics.public_gate_term_candidate_visits ==
              2U * statistics.public_gate_term_weight_updates);
        CHECK(statistics.public_gate_binding_sorts == 0);
        CHECK(statistics.public_dense_prefix_table_entries == 0);
        CHECK(statistics.online_slot_vectors_constructed == 0);
        CHECK(statistics.per_record_coefficient_allocations == 0);
        CHECK(statistics.per_record_coefficient_hash_probes == 0);
        CHECK(statistics.avoided_online_slot_vector_elements ==
              statistics.prepared_rotation_basis_applications * kSlots);
        CHECK(proving_operations.prepared_extension_basis_setup_calls ==
              statistics.prepared_rotation_bases);
        CHECK(proving_operations.prepared_extension_basis_api_calls ==
              statistics.prepared_rotation_basis_applications -
                  statistics.prepared_base_promotion_applications);
        const std::uint64_t dense_prepared_base_application_bound =
            statistics.prepared_base_promotion_applications *
            kExtensionDegree;
        CHECK(proving_operations.prepared_base_basis_api_calls != 0);
        CHECK(proving_operations.prepared_base_basis_api_calls <
              dense_prepared_base_application_bound);
        CHECK(proving_operations.prepared_extension_promotion_api_calls ==
              statistics.prepared_base_promotion_applications);
        CHECK(proving_operations.mul_plain_vector_api_calls == 0);
        CHECK(proving_operations.mul_plain_vector_api_elements == 0);
        CHECK(MockBackend::counts(contexts.eval).encrypt == 0);
    });

    runner.run("trace identity mismatch rejects before a source scan", [] {
        const PayloadCircuit payload = affine_payload();
        const LayeredCircuit circuit = compile(payload);
        const std::vector<SlotVector> inputs{
            values(5), values(43), values(101)};
        const PlainTrace plain = synthesize_trace(
            payload, circuit, inputs);
        auto contexts = MockBackend::create(MockParameters{
            .slot_count = kSlots,
            .fresh_rns_limbs = 8,
            .bits_per_limb = 128,
            .initial_noise_margin_bits = 4,
        });
        const EncryptedTrace<MockBackend> compact =
            encrypt_compact_synthetic_trace<MockBackend>(
                contexts.eval, contexts.client, payload, circuit, plain,
                TraceEncryptionPlan::uniform(circuit, 5));
        TemporaryDirectory directory;
        (void)write_file_encrypted_trace(
            contexts.eval, directory.path(),
            FileTraceStoreOptions{
                .max_total_bytes = std::uint64_t{1} << 24U,
                .min_free_bytes = 1,
            },
            circuit, compact);
        const auto store = FileEncryptedTraceStore<MockBackend>::open(
            contexts.eval, directory.path(), payload, circuit,
            compact.provenance, compact.trace_id);

        const PayloadCircuit changed_payload = affine_payload(4);
        const LayeredCircuit changed_circuit = compile(changed_payload);
        const SingleClaim claim = make_layer_claim(
            plain.layers[0], point(base_detail::layer_vars(circuit, 0), 19));
        const gates::DirectGateMle provider(changed_circuit);
        base_detail::BaseAffineStatistics statistics;
        bool rejected = false;
        try {
            Transcript transcript("test/base/affine-file-backed/reject/v1");
            (void)base_detail::prove_affine_reduction<MockBackend>(
                contexts.eval, changed_circuit, store,
                store.layer_support(1), 0, claim, provider, transcript,
                nullptr, &statistics);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        CHECK(rejected);
        CHECK(statistics.source_scans == 0);
        CHECK(statistics.source_ciphertexts_read == 0);
    });

    return runner.summary();
}
