#ifndef LAMINATE_GKR_DETAIL_LANED_VALIDATION_REQUEST_ADMISSION_HPP
#define LAMINATE_GKR_DETAIL_LANED_VALIDATION_REQUEST_ADMISSION_HPP

/// @file request_admission.hpp
/// @brief Request admission for file-backed Laned GKR.

#include "laminate/gkr/detail/laned/prover.hpp"
#include "laminate/gkr/detail/laned/validation/scratch.hpp"

#include <algorithm>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <utility>

namespace laminate::gkr::laned_detail {

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void LanedProver<Backend, TraceSource>::
validate_preprocessed_request_identity() {
    const auto &descriptor = trace_.descriptor();
    if (descriptor.shape.kind != payload::PayloadKind::Laned ||
        descriptor.layers.size() != circuit_.layers.size() ||
        Backend::slot_count(setup_.context) < 2U * kExtensionDegree ||
        Backend::slot_count(setup_.context) !=
            descriptor.shape.slot_count ||
        Backend::storage_context_id(setup_.context) !=
            trace_.backend_context_id() ||
        descriptor.circuit_id != setup_.public_setup.circuit_digest ||
        output_claim_.point.size() != laned_layer_variables(circuit_, 0) ||
        proof_ingress_rns_limbs_by_layer_.size() !=
            circuit_.layers.size() ||
        std::any_of(proof_ingress_rns_limbs_by_layer_.begin(),
                    proof_ingress_rns_limbs_by_layer_.end(),
                    [](std::size_t limbs) { return limbs == 0; })) {
        throw std::invalid_argument("preprocessed Laned proof identity mismatch");
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
        if (trace_layer.layout != payload::TraceLayerLayout::BPeriodic ||
            trace_layer.dimensions !=
                payload::layer_dimensions(circuit_.layers[layer]) ||
            trace_layer.dimensions.padded_size !=
                support.padded_wire_count ||
            storage.padded_wire_count != support.padded_wire_count ||
            trace_layer.record_count != storage.stored_wire_count) {
            throw std::invalid_argument(
                "preprocessed Laned source support mismatch");
        }
        admitted_layer_support_.push_back(support);
        admitted_layer_storage_.push_back(storage);
    }
    if constexpr (requires(const TraceSource &source) {
                      source.report().checkpoint_set_published;
                      source.report().all_payload_artifacts_retired;
                      source.proof_attempt_started();
                  }) {
        if (!trace_.report().checkpoint_set_published ||
            trace_.report().all_payload_artifacts_retired ||
            trace_.proof_attempt_started()) {
            throw std::invalid_argument("preprocessed Laned replay is not fresh");
        }
    }
}

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void LanedProver<Backend, TraceSource>::
bind_preprocessed_scratch_options() {
    multiplication_scratch_plan_.clear();
    multiplication_scratch_plan_.reserve(
        options_.multiplication_scratch.size());
    if (!preprocessed_multiplication_source_plans_ ||
        preprocessed_multiplication_source_plans_->size() !=
            options_.multiplication_scratch.size()) {
        throw std::invalid_argument(
            "preprocessed Laned multiplication plan mismatch");
    }
    for (std::size_t index = 0;
         index < options_.multiplication_scratch.size(); ++index) {
        const FileLanedMultiplicationScratch &scratch =
            options_.multiplication_scratch[index];
        const auto &source_plan =
            (*preprocessed_multiplication_source_plans_)[index];
        const auto status =
            std::filesystem::symlink_status(scratch.directory);
        if (!std::filesystem::is_directory(status) ||
            std::filesystem::is_symlink(status) ||
            !std::filesystem::is_empty(scratch.directory)) {
            throw std::invalid_argument(
                "preprocessed Laned scratch root is not an empty real "
                "directory");
        }
        if (source_plan.descriptor_template.reduction_layer !=
                scratch.reduction_layer ||
            scratch.storage_limits.max_total_bytes <
                source_plan.minimum_artifact_framing_bytes) {
            throw std::invalid_argument(
                "preprocessed Laned multiplication scratch mismatch");
        }
        auto descriptor = ::laminate::gkr::detail::
            bind_dense_multiplication_source_descriptor(
                source_plan, trace_.descriptor(), trace_.layered_circuit_id(),
                trace_.backend_context_id());
        multiplication_scratch_plan_.push_back(
            LanedMultiplicationArtifactPlan{
                scratch.reduction_layer, scratch.directory,
                scratch.storage_limits,
                scratch.sort_buffer_payload_bytes,
                std::move(descriptor)});
    }
    multiplication_source_plans_ =
        *preprocessed_multiplication_source_plans_;
}

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void LanedProver<Backend, TraceSource>::
validate_static_claim_flow() const {
    // Both affine and multiplication reductions carry one evaluation claim.
    for (std::size_t layer = 0; layer + 1U < circuit_.layers.size();
         ++layer) {
        const payload::LayerKind kind =
            payload::layer_kind(circuit_.layers[layer]);
        if (kind == payload::LayerKind::Multiplication) {
            const packing::LanedPackingLayout output =
                laned_layout(circuit_, layer);
            const packing::LanedPackingLayout source =
                laned_layout(circuit_, layer + 1U);
            if (output.padded_ciphertext_count >
                    std::numeric_limits<std::size_t>::max() / 2U ||
                source.padded_ciphertext_count !=
                    2U * output.padded_ciphertext_count) {
                throw std::invalid_argument(
                    "file-backed Laned multiplication geometry mismatch");
            }
        } else {
            (void)laned_layout(circuit_, layer);
            (void)laned_layout(circuit_, layer + 1U);
        }
    }
}

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void LanedProver<Backend, TraceSource>::
validate_request_identity() {
    setup_.public_setup.validate(payload_, circuit_);
    validate_profile(profile_, setup_.public_setup, circuit_);
    payload::validate_encrypted_trace_descriptor_for_circuit(
        trace_.descriptor(), payload_, circuit_);
    if (trace_.descriptor().shape.kind != payload::PayloadKind::Laned ||
        Backend::slot_count(setup_.context) < 2U * kExtensionDegree ||
        Backend::slot_count(setup_.context) !=
            trace_.descriptor().shape.slot_count ||
        Backend::storage_context_id(setup_.context) !=
            trace_.backend_context_id() ||
        trace_.layered_circuit_id() != payload::digest(circuit_) ||
        trace_.descriptor().circuit_id !=
            setup_.public_setup.circuit_digest ||
        output_claim_.point.size() != laned_layer_variables(circuit_, 0) ||
        proof_ingress_rns_limbs_by_layer_.size() !=
            circuit_.layers.size() ||
        std::any_of(proof_ingress_rns_limbs_by_layer_.begin(),
                    proof_ingress_rns_limbs_by_layer_.end(),
                    [](std::size_t limbs) { return limbs == 0; })) {
        throw std::invalid_argument(
            "file-backed Laned proof requires matching trace, setup, and "
            "output geometry");
    }
    payload::CanonicalTraceLayout canonical_layout =
        payload::canonical_trace_layout(circuit_);
    admitted_layer_support_ = std::move(canonical_layout.wire_support);
    admitted_layer_storage_ = std::move(canonical_layout.storage);
    for (std::size_t layer = 0;
         layer < admitted_layer_support_.size(); ++layer) {
        if (trace_.layer_support(layer) !=
            admitted_layer_support_[layer]) {
            throw std::invalid_argument(
                "file-backed Laned source support is noncanonical");
        }
    }
}

template <fhe::PersistableFheBackend Backend, typename TraceSource>
void LanedProver<Backend, TraceSource>::
validate_scratch_options() {
    options_ = preflight_and_normalize_laned_gkr_scratch(
        circuit_, trace_.directory(), options_);

    const Digest expected_setup_id = setup_digest(setup_.public_setup);
    multiplication_scratch_plan_.clear();
    multiplication_scratch_plan_.reserve(
        options_.multiplication_scratch.size());
    owned_multiplication_source_plans_.clear();
    owned_multiplication_source_plans_.reserve(
        options_.multiplication_scratch.size());

    for (const FileLanedMultiplicationScratch &scratch :
         options_.multiplication_scratch) {
        const std::size_t source_layer = scratch.reduction_layer + 1U;
        // Plan construction validates the trace/circuit geometry without
        // touching the destination directory.
        auto source_plan = ::laminate::gkr::detail::
            make_dense_multiplication_source_plan(
                circuit_, trace_.descriptor(),
                trace_.layered_circuit_id(), trace_.backend_context_id(),
                scratch.reduction_layer,
                admitted_layer_support_.at(source_layer),
                admitted_layer_storage_.at(source_layer), expected_setup_id,
                proof_ingress_rns_limbs_by_layer_.at(
                    source_layer));
        if (scratch.storage_limits.max_total_bytes <
            source_plan.minimum_artifact_framing_bytes) {
            throw std::invalid_argument(
                "Laned multiplication scratch cannot hold artifact framing");
        }
        auto descriptor = ::laminate::gkr::detail::
            bind_dense_multiplication_source_descriptor(
                source_plan, trace_.descriptor(), trace_.layered_circuit_id(),
                trace_.backend_context_id());
        owned_multiplication_source_plans_.push_back(
            std::move(source_plan));
        multiplication_scratch_plan_.push_back(
            LanedMultiplicationArtifactPlan{
                scratch.reduction_layer,
                scratch.directory,
                scratch.storage_limits,
                scratch.sort_buffer_payload_bytes,
                std::move(descriptor),
            });
    }
    multiplication_source_plans_ = owned_multiplication_source_plans_;
}

} // namespace laminate::gkr::laned_detail

#endif // LAMINATE_GKR_DETAIL_LANED_VALIDATION_REQUEST_ADMISSION_HPP
