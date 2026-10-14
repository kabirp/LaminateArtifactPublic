#ifndef LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_REFERENCE_PACKING_HPP
#define LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_REFERENCE_PACKING_HPP

/// @file packing.hpp
/// @brief Resident trace-to-packed-source construction for Laned multiplication.

#include "laminate/gkr/detail/laned/multiplication/reference/source.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/plan.hpp"
#include "laminate/gkr/laned.hpp"
#include "laminate/gkr/detail/laned/validation/request.hpp"
#include "laminate/payload/storage/file_trace_store.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <limits>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace laminate::gkr::laned_detail::reference_multiplication_detail {

struct PackedSignatureHash {
    std::size_t operator()(
        const std::vector<std::size_t> &signature) const noexcept {
        std::size_t result = signature.size();
        for (const std::size_t ordinal : signature) {
            result ^= ordinal + std::size_t{0x9e3779b97f4a7c15ULL} +
                      (result << 6U) + (result >> 2U);
        }
        return result;
    }
};

/// Pack the compact B-periodic source into dense left/right operands.
///
/// When one logical operand already occupies one ciphertext, the packed
/// source borrows the trace record and performs no FHE work. Otherwise each
/// nonzero chunk crosses the packing boundary exactly once: multiply by the
/// prepared public first-lane mask, rotate to its public chunk position, and
/// add. Public padding is skipped rather than encrypted. The finished packed
/// ciphertext drops the one RNS limb consumed by this linear packing step.
template <fhe::FheBackend Backend>
PackedSource<Backend> pack_resident_dense_source(
    const typename Backend::EvalContext &eval,
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace, std::size_t layer,
    const packing::LanedPackingLayout &source_layout,
    std::size_t pair_count,
    std::size_t source_proof_ingress_rns_limbs) {
    const auto &source = trace.layers[layer + 1U];
    const payload::LayerWireSupport support =
        payload::canonical_layer_wire_support(circuit, layer + 1U);
    const payload::LayerStorageLayout storage =
        payload::canonical_layer_storage_layout(circuit, layer + 1U);
    if (source.wires.size() != storage.stored_wire_count ||
        support.padded_wire_count != source_layout.original_wire_count) {
        throw std::invalid_argument(
            "LaminateLaned resident multiplication source is not the "
            "canonical compact live-wire representation");
    }
    for (const auto &value : source.wires) {
        if (value.is_encrypted()) {
            validate_exact_proof_ingress_ciphertext<Backend>(
                eval, value.ciphertext(), source_proof_ingress_rns_limbs,
                "LaminateLaned resident multiplication source");
        }
    }

    const std::size_t chunks = source_layout.chunks_per_ciphertext();
    const bool consumes_level = chunks != 1U;
    const std::size_t half_source_wires = pair_count * chunks;
    const std::size_t left_live = payload::trace_storage::live_wire_rank(
        support, half_source_wires);
    const std::size_t right_live = support.live_wire_count - left_live;
    const bool canonical_paired_prefix =
        left_live != 0 && left_live == right_live &&
        support.live_ranges.size() == 2U &&
        support.live_ranges[0] == payload::LiveWireRange{0, left_live} &&
        support.live_ranges[1] ==
            payload::LiveWireRange{half_source_wires, right_live};
    const bool fully_live =
        support.live_wire_count == support.padded_wire_count &&
        support.live_ranges.size() == 1U &&
        support.live_ranges.front() ==
            payload::LiveWireRange{0, support.padded_wire_count};
    if (!canonical_paired_prefix && !fully_live) {
        throw std::logic_error(
            "LaminateLaned multiplication source support is not a "
            "paired prefix");
    }
    const std::size_t live_pair_count = (left_live - 1U) / chunks + 1U;
    if (consumes_level && source_proof_ingress_rns_limbs <= 1U) {
        throw std::invalid_argument(
            "LaminateLaned multiplication packing has no droppable "
            "proof-ingress RNS limb");
    }
    const std::size_t packed_proof_ingress_rns_limbs =
        source_proof_ingress_rns_limbs -
        static_cast<std::size_t>(consumes_level);

    std::optional<fhe::PreparedFpSlotBasis<Backend>> prepared_first_chunk;
    fhe::FheValue<Backend> public_first_chunk =
        fhe::FheValue<Backend>::public_zero();
    if (chunks != 1U) {
        fhe::SlotVector basis(circuit.shape.slot_count, Fp::zero());
        std::fill_n(basis.begin(), circuit.shape.lane_count, Fp::one());
        public_first_chunk = fhe::FheValue<Backend>::public_slots(basis);
        const auto encrypted = std::find_if(
            source.wires.begin(), source.wires.end(),
            [](const auto &value) { return value.is_encrypted(); });
        if (encrypted != source.wires.end()) {
            prepared_first_chunk = fhe::prepare_fp_slot_basis<Backend>(
                eval, encrypted->ciphertext(), basis);
        }
    }

    PackedSource<Backend> packed;
    packed.stored_source = &source.wires;
    packed.pair_domain_size = pair_count;
    packed.left.reserve(live_pair_count);
    packed.right.reserve(live_pair_count);
    packed.unique.reserve(2U * live_pair_count);
    std::unordered_map<std::vector<std::size_t>, std::size_t,
                       PackedSignatureHash>
        unique_by_signature;
    unique_by_signature.reserve(2U * live_pair_count);
    constexpr std::size_t kPaddingOrdinal =
        std::numeric_limits<std::size_t>::max();

    const auto pack_one = [&](std::size_t first_source) {
        std::vector<std::size_t> signature;
        signature.reserve(chunks);
        for (std::size_t chunk = 0; chunk < chunks; ++chunk) {
            const auto stored =
                storage.stored_ordinal_of(first_source + chunk);
            signature.push_back(stored.value_or(kPaddingOrdinal));
        }
        if (const auto existing = unique_by_signature.find(signature);
            existing != unique_by_signature.end()) {
            return existing->second;
        }

        typename PackedSource<Backend>::UniqueValue unique;
        if (chunks == 1U) {
            if (signature.front() == kPaddingOrdinal) {
                throw std::logic_error(
                    "LaminateLaned live packed source is padding");
            }
            unique.borrowed_stored_ordinal = signature.front();
        } else {
            fhe::FheValue<Backend> accumulator =
                fhe::FheValue<Backend>::public_zero();
            for (std::size_t chunk = 0; chunk < chunks; ++chunk) {
                const std::size_t padded_source = first_source + chunk;
                const std::optional<std::size_t> live_source =
                    storage.stored_ordinal_of(padded_source);
                if (!live_source ||
                    source.wires[*live_source].is_public_zero()) {
                    continue;
                }

                // This mask/rotate/add block is the only FHE work performed
                // while turning resident trace chunks into a packed operand.
                fhe::FheValue<Backend> term;
                if (source.wires[*live_source].is_encrypted()) {
                    if (!prepared_first_chunk) {
                        throw std::logic_error(
                            "LaminateLaned multiplication packing basis "
                            "was not prepared");
                    }
                    term = fhe::FheValue<Backend>::from_ciphertext(
                        fhe::mul_plain_prepared<Backend>(
                            eval, source.wires[*live_source].ciphertext(),
                            *prepared_first_chunk));
                } else {
                    term = fhe::value_mul<Backend>(
                        eval, source.wires[*live_source],
                        public_first_chunk);
                }
                if (chunk != 0) {
                    term = fhe::value_rotate<Backend>(
                        eval, term,
                        fhe::grid_inverse(
                            circuit.shape.slot_count,
                            chunk * circuit.shape.lane_count));
                }
                fhe::value_add_assign<Backend>(eval, accumulator,
                                               std::move(term));
            }
            if (accumulator.is_encrypted()) {
                fhe::mod_switch_to_rns_limb_count<Backend>(
                    eval, accumulator.ciphertext(),
                    packed_proof_ingress_rns_limbs);
            }
            unique.owned = std::move(accumulator);
        }
        const std::size_t unique_index = packed.unique.size();
        packed.unique.push_back(std::move(unique));
        unique_by_signature.emplace(std::move(signature), unique_index);
        return unique_index;
    };

    for (std::size_t pair = 0; pair < live_pair_count; ++pair) {
        packed.left.push_back(pack_one(pair * chunks));
        packed.right.push_back(
            pack_one(half_source_wires + pair * chunks));
    }
    packed.physical_order.resize(live_pair_count);
    std::iota(packed.physical_order.begin(), packed.physical_order.end(),
              std::size_t{0});
    const std::size_t bits = std::bit_width(pair_count) - 1U;
    std::sort(packed.physical_order.begin(), packed.physical_order.end(),
              [bits](std::size_t left, std::size_t right) {
                  return ::laminate::gkr::detail::bit_reverse_index(
                             left, bits) <
                         ::laminate::gkr::detail::bit_reverse_index(
                             right, bits);
              });
    return packed;
}

} // namespace laminate::gkr::laned_detail::reference_multiplication_detail

#endif // LAMINATE_GKR_DETAIL_LANED_MULTIPLICATION_REFERENCE_PACKING_HPP
