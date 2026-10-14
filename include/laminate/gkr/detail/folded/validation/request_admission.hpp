#ifndef LAMINATE_GKR_DETAIL_FOLDED_VALIDATION_REQUEST_ADMISSION_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_VALIDATION_REQUEST_ADMISSION_HPP

/// @file request_admission.hpp
/// @brief Request admission for file-backed Folded GKR.

#include "laminate/gkr/detail/base/geometry/circuit.hpp"
#include "laminate/gkr/detail/folded/validation/scratch.hpp"
#include "laminate/payload/checkpoint/plan.hpp"

#include <cstdint>
#include <limits>
#include <vector>

namespace laminate::gkr::folded_detail {

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void FoldedProver<Backend, TraceSource>::
validate_preprocessed_request_identity() {
    const auto &descriptor = trace_.descriptor();
    if (descriptor.shape.kind != payload::PayloadKind::Wide ||
        descriptor.layers.size() != circuit_.layers.size() ||
        Backend::slot_count(setup_.context) < 2U * kExtensionDegree ||
        Backend::slot_count(setup_.context) != descriptor.shape.slot_count ||
        Backend::storage_context_id(setup_.context) !=
            trace_.backend_context_id() ||
        descriptor.circuit_id != setup_.public_setup.circuit_digest ||
        output_claim_.point.size() !=
            base_detail::layer_vars(circuit_, 0) ||
        proof_ingress_rns_limbs_by_layer_.size() !=
            circuit_.layers.size()) {
        throw std::invalid_argument(
            "preprocessed LaminateFolded proof identity mismatch");
    }
    admitted_layer_support_.clear();
    admitted_layer_storage_.clear();
    admitted_layer_support_.reserve(circuit_.layers.size());
    admitted_layer_storage_.reserve(circuit_.layers.size());
    for (std::size_t layer = 0; layer < circuit_.layers.size(); ++layer) {
        const payload::LayerWireSupport &support =
            trace_.layer_support(layer);
        const payload::LayerStorageLayout &storage =
            trace_.layer_storage_layout(layer);
        payload::validate_layer_wire_support(support);
        payload::validate_layer_storage_layout(storage);
        const auto &trace_layer = descriptor.layers[layer];
        if (trace_layer.layout != payload::TraceLayerLayout::Wide ||
            trace_layer.dimensions !=
                payload::layer_dimensions(circuit_.layers[layer]) ||
            trace_layer.dimensions.padded_size !=
                support.padded_wire_count ||
            storage.padded_wire_count != support.padded_wire_count ||
            trace_layer.record_count != storage.stored_wire_count) {
            throw std::invalid_argument(
                "preprocessed LaminateFolded source support mismatch");
        }
        admitted_layer_support_.push_back(support);
        admitted_layer_storage_.push_back(storage);
        if (layer == 0) {
            continue;
        }
        const std::size_t expected_limbs =
            proof_ingress_rns_limbs_by_layer_[layer];
        if (expected_limbs == 0 ||
            descriptor.layers[layer].required_mult_depth ==
                std::numeric_limits<std::size_t>::max() ||
            descriptor.layers[layer].required_mult_depth + 1U !=
                expected_limbs) {
            throw std::invalid_argument(
                "preprocessed LaminateFolded proof-ingress mismatch");
        }
    }
    if constexpr (requires(const TraceSource &source) {
                      source.report().checkpoint_set_published;
                      source.report().all_payload_artifacts_retired;
                      source.proof_attempt_started();
                  }) {
        if (!trace_.report().checkpoint_set_published ||
            trace_.report().all_payload_artifacts_retired ||
            trace_.proof_attempt_started()) {
            throw std::invalid_argument(
                "preprocessed LaminateFolded replay is not fresh");
        }
    }
}

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void FoldedProver<Backend, TraceSource>::
bind_preprocessed_scratch_options() {
    normalized_scratch_ = options_.multiplication_scratch;
    if (!preprocessed_multiplication_source_plans_ ||
        preprocessed_multiplication_source_plans_->size() !=
            normalized_scratch_.size()) {
        throw std::invalid_argument(
            "preprocessed LaminateFolded multiplication plan mismatch");
    }
    for (std::size_t index = 0; index < normalized_scratch_.size();
         ++index) {
        const FileFoldedMultiplicationScratch &scratch =
            normalized_scratch_[index];
        const auto &source_plan =
            (*preprocessed_multiplication_source_plans_)[index];
        const auto status =
            std::filesystem::symlink_status(scratch.directory);
        if (!std::filesystem::is_directory(status) ||
            std::filesystem::is_symlink(status) ||
            !std::filesystem::is_empty(scratch.directory)) {
            throw std::invalid_argument(
                "preprocessed LaminateFolded scratch root is not an empty "
                "real directory");
        }
        if (source_plan.descriptor_template.reduction_layer !=
                scratch.reduction_layer ||
            scratch.storage_limits.max_total_bytes <
                source_plan.minimum_artifact_framing_bytes) {
            throw std::invalid_argument(
                "LaminateFolded scratch quota cannot hold artifact framing");
        }
        (void)::laminate::gkr::detail::
            bind_dense_multiplication_source_descriptor(
                source_plan, trace_.descriptor(), trace_.layered_circuit_id(),
                trace_.backend_context_id());
    }
    multiplication_source_plans_ =
        *preprocessed_multiplication_source_plans_;
}

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void FoldedProver<Backend, TraceSource>::
validate_request_identity() {
    setup_.public_setup.validate(payload_, circuit_);
    validate_profile(profile_, setup_.public_setup, circuit_);
    payload::validate_encrypted_trace_descriptor_for_circuit(
        trace_.descriptor(), payload_, circuit_);
    if (trace_.descriptor().shape.kind != payload::PayloadKind::Wide ||
        Backend::slot_count(setup_.context) < 2U * kExtensionDegree ||
        Backend::slot_count(setup_.context) !=
            trace_.descriptor().shape.slot_count ||
        Backend::storage_context_id(setup_.context) !=
            trace_.backend_context_id() ||
        trace_.layered_circuit_id() != payload::digest(circuit_) ||
        trace_.descriptor().circuit_id !=
            setup_.public_setup.circuit_digest ||
        output_claim_.point.size() !=
            base_detail::layer_vars(circuit_, 0)) {
        throw std::invalid_argument(
            "LaminateFolded file proof identity mismatch");
    }
    if (proof_ingress_rns_limbs_by_layer_.size() !=
        circuit_.layers.size()) {
        throw std::invalid_argument(
            "LaminateFolded setup has the wrong proof-ingress schedule "
            "length");
    }

    // Deriving compact support walks the complete circuit. Establish it once
    // here and pass each layer's admitted value into the reduction.
    payload::CanonicalTraceLayout canonical_layout =
        payload::canonical_trace_layout(circuit_);
    admitted_layer_support_ = std::move(canonical_layout.wire_support);
    admitted_layer_storage_ = std::move(canonical_layout.storage);
    for (std::size_t layer = 0;
         layer < admitted_layer_support_.size(); ++layer) {
        if (trace_.layer_support(layer) !=
            admitted_layer_support_[layer]) {
            throw std::invalid_argument(
                "LaminateFolded file source support is noncanonical");
        }
    }

    // Layer zero is returned for client decryption. Exact reverse-GKR proof
    // ingress therefore starts at layer one.
    for (std::size_t layer = 1; layer < circuit_.layers.size(); ++layer) {
        const std::size_t expected_limbs =
            proof_ingress_rns_limbs_by_layer_.at(layer);
        if (expected_limbs == 0) {
            throw std::invalid_argument(
                "LaminateFolded setup selected zero proof-ingress limbs");
        }
        const auto &descriptor_layer = trace_.descriptor().layers[layer];
        if (descriptor_layer.required_mult_depth ==
                std::numeric_limits<std::size_t>::max() ||
            descriptor_layer.required_mult_depth + 1U != expected_limbs) {
            throw std::invalid_argument(
                "LaminateFolded file trace metadata differs from the "
                "setup-bound exact proof-ingress limb count");
        }

        // Checkpoint replay is deliberately single-pass. Reopenable file traces
        // can additionally sample an encrypted value during preflight.
        if constexpr (!requires(const TraceSource &source) {
                          source.report().checkpoint_set_published;
                      }) {
            auto reader = trace_.active_layer_reader(layer);
            auto record = reader.next();
            const typename Backend::Ciphertext *level_reference = nullptr;
            while (record) {
                level_reference =
                    folded_affine_detail::
                        encrypted_ciphertext_ptr<Backend>(
                            folded_affine_detail::
                                record_stored_value(*record));
                if (level_reference != nullptr) {
                    break;
                }
                record = reader.next();
            }
            if (level_reference != nullptr &&
                Backend::rns_limb_count(setup_.context, *level_reference) !=
                    expected_limbs) {
                throw std::invalid_argument(
                    "LaminateFolded file ciphertext is not at the "
                    "setup-bound exact proof-ingress RNS level");
            }
        }
    }
    if constexpr (requires(const TraceSource &source) {
                      source.report().checkpoint_set_published;
                      source.report().all_payload_artifacts_retired;
                      source.proof_attempt_started();
                  }) {
        if (!trace_.report().checkpoint_set_published ||
            trace_.report().all_payload_artifacts_retired ||
            trace_.proof_attempt_started()) {
            throw std::invalid_argument(
                "LaminateFolded replay source is not a fresh published "
                "session");
        }
    }
}

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void FoldedProver<Backend, TraceSource>::
validate_static_claim_flow() const {
    // Every reduction returns one evaluation claim. Multiplication adds a
    // freshly sampled selector coordinate to its shared source point.
    std::size_t variables = output_claim_.point.size();
    for (std::size_t layer = 0; layer + 1U < circuit_.layers.size();
         ++layer) {
        if (variables != base_detail::layer_vars(circuit_, layer)) {
            throw std::invalid_argument(
                "LaminateFolded static claim geometry mismatch");
        }
        if (payload::layer_kind(circuit_.layers[layer]) ==
            payload::LayerKind::Multiplication) {
            (void)FoldedMultiplicationReductionGeometry::create(
                circuit_, layer,
                SingleClaim{std::vector<Fpk>(variables), Fpk::zero()});
        }
        variables = base_detail::layer_vars(circuit_, layer + 1U);
    }
}

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void FoldedProver<Backend, TraceSource>::
validate_scratch_options() {
    normalized_scratch_ =
        preflight_and_normalize_file_folded_gkr_scratch(
            circuit_, trace_.directory(), options_)
            .multiplication_scratch;
    const Digest setup_id = setup_digest(setup_.public_setup);
    owned_multiplication_source_plans_.clear();
    owned_multiplication_source_plans_.reserve(normalized_scratch_.size());
    for (const FileFoldedMultiplicationScratch &scratch :
         normalized_scratch_) {
        const std::size_t source_layer = scratch.reduction_layer + 1U;
        auto source_plan = ::laminate::gkr::detail::
            make_dense_multiplication_source_plan(
                circuit_, trace_.descriptor(), trace_.layered_circuit_id(),
                trace_.backend_context_id(), scratch.reduction_layer,
                admitted_layer_support_.at(source_layer),
                admitted_layer_storage_.at(source_layer),
                setup_id, proof_ingress_rns_limbs_by_layer_.at(
                              source_layer));
        if (scratch.storage_limits.max_total_bytes <
            source_plan.minimum_artifact_framing_bytes) {
            throw std::invalid_argument(
                "LaminateFolded scratch quota cannot hold artifact framing");
        }
        owned_multiplication_source_plans_.push_back(
            std::move(source_plan));
    }
    multiplication_source_plans_ = owned_multiplication_source_plans_;
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_VALIDATION_REQUEST_ADMISSION_HPP
