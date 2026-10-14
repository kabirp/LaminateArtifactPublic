#ifndef LAMINATE_PAYLOAD_CHECKPOINT_LANED_WITNESS_PACKING_HPP
#define LAMINATE_PAYLOAD_CHECKPOINT_LANED_WITNESS_PACKING_HPP

/// @file laned_witness_packing.hpp
/// @brief Challenge-independent S' construction between payload layers.

#include "laminate/fhe/backend.hpp"
#include "laminate/fhe/value.hpp"
#include "laminate/packing/alignment/laned.hpp"
#include "laminate/payload/checkpoint/plan.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::payload {

inline constexpr std::size_t kEagerLanedPackedCiphertextLimit = 64;

inline packing::LanedPackingLayout laned_witness_packing_layout(
    const LayeredCircuit &circuit, std::size_t source_layer) {
    if (circuit.shape.kind != PayloadKind::Laned ||
        source_layer >= circuit.layers.size()) {
        throw std::invalid_argument(
            "Laned witness packing layer is invalid");
    }
    return packing::LanedPackingLayout::create(
        circuit.shape,
        layer_dimensions(circuit.layers[source_layer]).padded_size);
}

inline bool supports_eager_laned_witness_packing(
    const LayeredCircuit &circuit) {
    if (circuit.shape.kind != PayloadKind::Laned ||
        circuit.layers.size() < 2U ||
        circuit.shape.lane_count == circuit.shape.slot_count) {
        return false;
    }
    for (std::size_t source_layer = 1;
         source_layer < circuit.layers.size(); ++source_layer) {
        if (laned_witness_packing_layout(circuit, source_layer)
                .logical_ciphertext_count >
            kEagerLanedPackedCiphertextLimit) {
            return false;
        }
    }
    return true;
}

/// The eager builder and prepared masks coexist with the payload working
/// set. Include resident_workspace_bytes in the caller's complete
/// reserved_resident_bytes before selecting a replay plan or optional cache.
/// Masks remain live between relations; their storage is not phase-disjoint
/// from the next relation's ciphertext cache.
struct EagerLanedWitnessPackingResources {
    bool eligible = false;
    std::vector<std::uint64_t> artifact_bytes_by_layer;
    std::uint64_t packed_artifact_bytes = 0;
    std::uint64_t largest_adjacent_natural_bytes = 0;
    std::uint64_t maximum_builder_resident_bytes = 0;
    std::uint64_t maximum_mask_cache_resident_bytes = 0;
    std::uint64_t resident_workspace_bytes = 0;

    bool operator==(
        const EagerLanedWitnessPackingResources &) const = default;
};

namespace laned_witness_resource_detail {

inline std::uint64_t checked_add(std::uint64_t a, std::uint64_t b) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) {
        throw std::overflow_error("eager Laned resource sum overflows");
    }
    return a + b;
}

inline std::uint64_t checked_mul(std::uint64_t a, std::uint64_t b) {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) {
        throw std::overflow_error("eager Laned resource product overflows");
    }
    return a * b;
}

} // namespace laned_witness_resource_detail

/// Value-free footprint for an already calibrated Laned replay problem.
/// Unsupported lane/width layouts return an empty, ineligible footprint.
inline EagerLanedWitnessPackingResources
eager_laned_witness_packing_resources(
    std::size_t slot_count, std::size_t lane_count,
    const PayloadCheckpointReplayProblem &problem) {
    (void)PayloadShape::laned(lane_count, slot_count);
    if (problem.layers.size() < 2U || lane_count == slot_count) {
        return {};
    }
    const std::size_t chunks = slot_count / lane_count;
    // Divide before adding so malformed large wire counts cannot wrap.
    const auto packed_count = [chunks](std::size_t wires) {
        return wires / chunks + static_cast<std::size_t>(wires % chunks != 0);
    };
    for (std::size_t layer = 1; layer < problem.layers.size(); ++layer) {
        if (packed_count(problem.layers[layer].virtual_wire_count) >
            kEagerLanedPackedCiphertextLimit) {
            return {};
        }
    }
    problem.validate();
    using laned_witness_resource_detail::checked_add;
    using laned_witness_resource_detail::checked_mul;
    EagerLanedWitnessPackingResources result;
    result.eligible = true;
    result.artifact_bytes_by_layer.resize(problem.layers.size(), 0);
    for (std::size_t layer = 1; layer < problem.layers.size(); ++layer) {
        const PayloadReplayLayer &resource = problem.layers[layer];
        const std::size_t count = packed_count(resource.virtual_wire_count);
        const std::uint64_t record_bytes =
            resource.proof_ingress_serialized_ciphertext_bytes == 0
                ? resource.serialized_ciphertext_bytes
                : resource.proof_ingress_serialized_ciphertext_bytes;
        const std::uint64_t resident_bytes =
            resource.resident_ciphertext_bytes == 0
                ? resource.serialized_ciphertext_bytes
                : resource.resident_ciphertext_bytes;
        const std::uint64_t artifact =
            standalone_checkpoint_layer_artifact_bytes(count, record_bytes);
        result.artifact_bytes_by_layer[layer] = artifact;
        result.packed_artifact_bytes =
            checked_add(result.packed_artifact_bytes, artifact);
        result.maximum_builder_resident_bytes = std::max(
            result.maximum_builder_resident_bytes,
            checked_mul(count, checked_add(record_bytes, resident_bytes)));
        result.maximum_mask_cache_resident_bytes = std::max(
            result.maximum_mask_cache_resident_bytes,
            checked_mul(std::min(chunks, resource.virtual_wire_count),
                        resident_bytes));
        result.largest_adjacent_natural_bytes = std::max(
            result.largest_adjacent_natural_bytes,
            checked_add(resource.checkpoint_bytes,
                        problem.layers[layer - 1U].checkpoint_bytes));
    }
    result.resident_workspace_bytes = checked_add(
        result.maximum_builder_resident_bytes,
        result.maximum_mask_cache_resident_bytes);
    return result;
}

inline EagerLanedWitnessPackingResources
eager_laned_witness_packing_resources(
    const LayeredCircuit &circuit,
    const PayloadCheckpointReplayProblem &problem) {
    if (!supports_eager_laned_witness_packing(circuit)) {
        return {};
    }
    if (problem.layers.size() != circuit.layers.size()) {
        throw std::invalid_argument("eager Laned resource layer count differs");
    }
    for (std::size_t layer = 0; layer < circuit.layers.size(); ++layer) {
        if (problem.layers[layer].virtual_wire_count !=
                layer_dimensions(circuit.layers[layer]).padded_size ||
            problem.layers[layer].kind != layer_kind(circuit.layers[layer])) {
            throw std::invalid_argument("eager Laned resource geometry differs");
        }
    }
    return eager_laned_witness_packing_resources(
        circuit.shape.slot_count, circuit.shape.lane_count, problem);
}

struct EagerLanedWitnessPackingAdmission {
    EagerLanedWitnessPackingResources resources;
    std::uint64_t peak_live_scratch_bytes = 0;
    std::uint64_t peak_resident_bytes = 0;
};

/// The complete caller reserve must include the eager workspace exactly
/// once, in addition to its other retained state. Replay planning then spends
/// only the remaining RAM on optional caches. The lower-bound check here
/// detects an omitted eager reserve; it does not certify unrelated state
/// declared by the caller. The caller must supply its certified replay plan.
inline EagerLanedWitnessPackingAdmission
admit_eager_laned_witness_packing(
    EagerLanedWitnessPackingResources resources,
    const PayloadCheckpointReplayBudgets &budgets,
    const PayloadCheckpointReplayPlan &plan) {
    if (!resources.eligible) {
        return {};
    }
    budgets.validate();
    if (budgets.reserved_resident_bytes < resources.resident_workspace_bytes) {
        throw std::invalid_argument(
            "eager Laned workspace is missing from the replay resident reserve");
    }
    const std::uint64_t live_peak =
        laned_witness_resource_detail::checked_add(
            budgets.reserved_live_scratch_bytes,
            laned_witness_resource_detail::checked_add(
                resources.packed_artifact_bytes,
                resources.largest_adjacent_natural_bytes));
    // The selected peak already includes the complete reserve. Adding the
    // builder or mask cache again would charge that memory twice.
    const std::uint64_t resident_peak = plan.selected.peak_resident_bytes;
    if (!plan.selected.feasible() ||
        resident_peak < budgets.reserved_resident_bytes ||
        live_peak > budgets.max_live_scratch_bytes ||
        resident_peak > budgets.max_resident_ciphertext_bytes) {
        throw std::invalid_argument(
            "eager Laned witness artifacts exceed setup-admitted "
            "storage or resident memory");
    }
    return {std::move(resources), live_peak, resident_peak};
}

inline EagerLanedWitnessPackingAdmission
admit_eager_laned_witness_packing(
    std::size_t slot_count, std::size_t lane_count,
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    const PayloadCheckpointReplayPlan &plan) {
    return admit_eager_laned_witness_packing(
        eager_laned_witness_packing_resources(slot_count, lane_count, problem),
        budgets, plan);
}

inline EagerLanedWitnessPackingAdmission
admit_eager_laned_witness_packing(
    const LayeredCircuit &circuit,
    const PayloadCheckpointReplayProblem &problem,
    const PayloadCheckpointReplayBudgets &budgets,
    const PayloadCheckpointReplayPlan &plan) {
    return admit_eager_laned_witness_packing(
        eager_laned_witness_packing_resources(circuit, problem), budgets, plan);
}

struct LanedWitnessPackingStatistics {
    std::uint64_t source_values = 0;
    std::uint64_t logical_values_packed = 0;
    std::uint64_t mask_preparations = 0;
    std::uint64_t mask_cache_hits = 0;
    std::uint64_t prepared_mask_ntt_bytes = 0;
    std::uint64_t modulus_switches = 0;
    std::uint64_t plain_multiplications = 0;
    std::uint64_t additions = 0;
    std::uint64_t rotations = 0;
    std::uint64_t packed_ciphertexts = 0;
};

/// Fixed destination selectors retained for one natural ciphertext level.
/// There are exactly N/B possible masks. A level change releases every old
/// representation before preparing the first mask for the new level.
template <fhe::FheBackend Backend>
class LanedWitnessMaskCache {
  public:
    struct Lookup {
        const fhe::PreparedFpSlotBasis<Backend> *basis = nullptr;
        bool prepared = false;
    };

    LanedWitnessMaskCache(std::size_t slot_count, std::size_t lane_count)
        : slot_count_(slot_count), lane_count_(lane_count) {
        if (slot_count == 0 || lane_count == 0 ||
            slot_count % lane_count != 0) {
            throw std::invalid_argument(
                "Laned witness mask-cache geometry is invalid");
        }
        masks_.resize(slot_count / lane_count);
    }

    Lookup get(const typename Backend::EvalContext &eval,
               const typename Backend::Ciphertext &level_reference,
               std::size_t chunk) {
        if (Backend::slot_count(eval) != slot_count_ ||
            chunk >= masks_.size()) {
            throw std::invalid_argument(
                "Laned witness mask-cache request is invalid");
        }
        const std::size_t level =
            Backend::rns_limb_count(eval, level_reference);
        if (!rns_limb_count_ || *rns_limb_count_ != level) {
            for (auto &mask : masks_) {
                mask.reset();
            }
            rns_limb_count_ = level;
            retained_ntt_bytes_ = 0;
        }

        std::optional<fhe::PreparedFpSlotBasis<Backend>> &prepared =
            masks_[chunk];
        if (prepared) {
            return Lookup{&*prepared, false};
        }
        fhe::SlotVector mask(slot_count_, Fp::zero());
        std::fill_n(
            mask.begin() + static_cast<std::ptrdiff_t>(chunk * lane_count_),
            lane_count_, Fp::one());
        prepared.emplace(fhe::prepare_fp_slot_basis<Backend>(
            eval, level_reference, mask));
        if (prepared->storage.ntt_coefficient_bytes >
            std::numeric_limits<std::uint64_t>::max() -
                retained_ntt_bytes_) {
            throw std::overflow_error(
                "Laned witness prepared-mask bytes overflow");
        }
        retained_ntt_bytes_ +=
            prepared->storage.ntt_coefficient_bytes;
        peak_ntt_bytes_ = std::max(peak_ntt_bytes_, retained_ntt_bytes_);
        return Lookup{&*prepared, true};
    }

    std::uint64_t peak_ntt_bytes() const noexcept {
        return peak_ntt_bytes_;
    }

  private:
    std::size_t slot_count_;
    std::size_t lane_count_;
    std::optional<std::size_t> rns_limb_count_;
    std::vector<std::optional<fhe::PreparedFpSlotBasis<Backend>>> masks_;
    std::uint64_t retained_ntt_bytes_ = 0;
    std::uint64_t peak_ntt_bytes_ = 0;
};

/// Incrementally packs the canonical distinct values of one completed layer.
/// The payload evaluator retains its natural-level value; this builder owns a
/// copy, places all setup-derived logical occurrences into S'=SB/N
/// ciphertexts at the natural level, and reduces only those packed outputs to
/// the public proof level. Packing and modulus switching preserve the same
/// plaintext relation, while postponing the switch avoids one full RNS-chain
/// traversal per source ciphertext.
template <fhe::FheBackend Backend>
class EagerLanedWitnessLayerBuilder {
  public:
    EagerLanedWitnessLayerBuilder(
        const typename Backend::EvalContext &eval,
        const LayeredCircuit &circuit, std::size_t source_layer,
        const LayerStorageLayout &storage,
        std::size_t source_proof_ingress_rns_limbs,
        LanedWitnessMaskCache<Backend> &mask_cache)
        : eval_(&eval), source_layer_(source_layer),
          layout_(laned_witness_packing_layout(circuit, source_layer)),
          storage_(storage),
          packed_rns_limbs_(packed_rns_limb_count(
              circuit, source_layer, layout_,
              source_proof_ingress_rns_limbs)),
          mask_cache_(&mask_cache),
          values_(layout_.logical_ciphertext_count,
                  fhe::FheValue<Backend>::public_zero()),
          occurrences_(storage.stored_wire_count) {
        if (source_layer == 0 ||
            source_proof_ingress_rns_limbs == 0 ||
            packed_rns_limbs_ == 0 ||
            layout_.chunks_per_ciphertext() == 1U ||
            layout_.logical_ciphertext_count >
                kEagerLanedPackedCiphertextLimit ||
            storage_.padded_wire_count != layout_.original_wire_count) {
            throw std::invalid_argument(
                "Laned witness packing geometry or level is invalid");
        }
        for (std::size_t padded = 0;
             padded < storage_.padded_wire_count; ++padded) {
            const std::optional<std::size_t> stored =
                storage_.stored_ordinal_of(padded);
            if (stored) {
                occurrences_.at(*stored).push_back(padded);
            }
        }
    }

    void append_stored_value(const fhe::FheValue<Backend> &natural) {
        if (next_stored_ >= occurrences_.size()) {
            throw std::logic_error(
                "Laned witness packing received too many source values");
        }
        const fhe::FheValue<Backend> &source = natural;
        ++statistics_.source_values;

        const std::size_t chunks = layout_.chunks_per_ciphertext();
        for (const std::size_t padded : occurrences_[next_stored_]) {
            const std::size_t packed = padded / chunks;
            const std::size_t chunk = padded % chunks;
            if (packed >= values_.size()) {
                throw std::logic_error(
                    "Laned witness packed index drifted");
            }

            fhe::FheValue<Backend> term;
            if (chunks == 1U) {
                term = source;
            } else {
                if (source.is_encrypted()) {
                    const auto prepared = mask_cache_->get(
                        *eval_, source.ciphertext(), chunk);
                    if (prepared.prepared) {
                        ++statistics_.mask_preparations;
                        statistics_.prepared_mask_ntt_bytes +=
                            prepared.basis->storage.ntt_coefficient_bytes;
                    } else {
                        ++statistics_.mask_cache_hits;
                    }
                    term = fhe::FheValue<Backend>::from_ciphertext(
                        fhe::mul_plain_prepared<Backend>(
                            *eval_, source.ciphertext(), *prepared.basis));
                } else {
                    fhe::SlotVector mask(layout_.slot_count, Fp::zero());
                    std::fill_n(
                        mask.begin() + static_cast<std::ptrdiff_t>(
                                           chunk * layout_.lane_count),
                        layout_.lane_count, Fp::one());
                    term = fhe::value_mul<Backend>(
                        *eval_, source,
                        fhe::FheValue<Backend>::public_slots(
                            std::move(mask)));
                }
                ++statistics_.plain_multiplications;
            }
            const bool accumulated = !values_[packed].is_public_zero();
            fhe::value_add_assign<Backend>(
                *eval_, values_[packed], std::move(term));
            if (accumulated) {
                ++statistics_.additions;
            }
            ++statistics_.logical_values_packed;
        }
        ++next_stored_;
    }

    std::vector<fhe::FheValue<Backend>> finish() && {
        if (next_stored_ != occurrences_.size()) {
            throw std::runtime_error(
                "Laned witness packing source ended early");
        }
        for (fhe::FheValue<Backend> &value : values_) {
            if (!value.is_encrypted()) {
                continue;
            }
            const std::size_t before = Backend::rns_limb_count(
                *eval_, value.ciphertext());
            if (before < packed_rns_limbs_) {
                throw std::runtime_error(
                    "Laned packed witness is below its proof level");
            }
            if (before != packed_rns_limbs_) {
                fhe::mod_switch_to_rns_limb_count<Backend>(
                    *eval_, value.ciphertext(), packed_rns_limbs_);
            }
            const std::size_t after = Backend::rns_limb_count(
                *eval_, value.ciphertext());
            if (after != packed_rns_limbs_ || after > before) {
                throw std::runtime_error(
                    "Laned packed witness did not reach its proof level");
            }
            statistics_.modulus_switches += before - after;
        }
        statistics_.packed_ciphertexts =
            static_cast<std::uint64_t>(std::count_if(
                values_.begin(), values_.end(),
                [](const auto &value) { return value.is_encrypted(); }));
        return std::move(values_);
    }

    const packing::LanedPackingLayout &layout() const noexcept {
        return layout_;
    }
    std::size_t source_layer() const noexcept { return source_layer_; }
    std::size_t packed_rns_limbs() const noexcept {
        return packed_rns_limbs_;
    }
    std::size_t completed_source_values() const noexcept {
        return next_stored_;
    }
    std::size_t total_source_values() const noexcept {
        return occurrences_.size();
    }
    const LanedWitnessPackingStatistics &statistics() const noexcept {
        return statistics_;
    }

  private:
    static std::size_t packed_rns_limb_count(
        const LayeredCircuit &circuit, std::size_t source_layer,
        const packing::LanedPackingLayout &layout,
        std::size_t source_proof_ingress_rns_limbs) {
        if (source_layer == 0 || source_layer >= circuit.layers.size() ||
            source_proof_ingress_rns_limbs == 0) {
            throw std::invalid_argument(
                "Laned witness packing source level is invalid");
        }
        const bool multiplication_source =
            layer_kind(circuit.layers[source_layer - 1U]) ==
                LayerKind::Multiplication &&
            layout.chunks_per_ciphertext() != 1U;
        if (multiplication_source &&
            source_proof_ingress_rns_limbs == 1U) {
            throw std::invalid_argument(
                "Laned multiplication packing has no remaining RNS limb");
        }
        return source_proof_ingress_rns_limbs -
               static_cast<std::size_t>(multiplication_source);
    }

    const typename Backend::EvalContext *eval_;
    std::size_t source_layer_;
    packing::LanedPackingLayout layout_;
    LayerStorageLayout storage_;
    std::size_t packed_rns_limbs_;
    LanedWitnessMaskCache<Backend> *mask_cache_;
    std::vector<fhe::FheValue<Backend>> values_;
    std::vector<std::vector<std::size_t>> occurrences_;
    std::size_t next_stored_ = 0;
    LanedWitnessPackingStatistics statistics_;
};

} // namespace laminate::payload

#endif // LAMINATE_PAYLOAD_CHECKPOINT_LANED_WITNESS_PACKING_HPP
