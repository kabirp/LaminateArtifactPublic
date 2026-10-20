#ifndef LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_MULTIPLICATION_SOURCE_HPP
#define LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_MULTIPLICATION_SOURCE_HPP

/// @file multiplication_source.hpp
/// @brief Resident Folded multiplication source for tests and analysis.

#include "laminate/gkr/detail/shared/dense_multiplication/source/plan.hpp"
#include "laminate/payload/trace/encrypted_trace.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

namespace laminate::gkr::folded_detail {

/// Alias-aware view of a resident Wide source.
///
/// The compiled multiplication layer is logically `(left, right)`, but its
/// compact trace may store repeated operands only once. This adapter retains
/// one reference to that stored layer plus public integer alias maps. It never
/// copies a ciphertext, and logical padding remains public zero rather than a
/// stored encrypted value.
template <fhe::FheBackend Backend>
class FoldedResidentMultiplicationSource {
  public:
    FoldedResidentMultiplicationSource(
        const payload::LayeredCircuit &circuit,
        const payload::EncryptedTrace<Backend> &trace,
        std::size_t layer)
        : stored_(&trace.layers.at(layer + 1U).wires),
          aliases_(::laminate::gkr::detail::
                       make_dense_multiplication_alias_plan(circuit,
                                                            layer)) {
        const payload::LayerStorageLayout storage =
            payload::canonical_layer_storage_layout(circuit, layer + 1U);
        const std::size_t padded_source =
            payload::layer_dimensions(circuit.layers[layer + 1U])
                .padded_size;
        compact_ = stored_->size() == storage.stored_wire_count;
        const bool dense_reference = stored_->size() == padded_source;
        if (circuit.shape.kind != payload::PayloadKind::Wide ||
            (!compact_ && !dense_reference)) {
            throw std::invalid_argument(
                "LaminateFolded resident multiplication source has a "
                "noncanonical Wide layout");
        }
        if (compact_) {
            for (const auto &signature : aliases_.operands) {
                if (signature.stored_ordinals.size() != 1U ||
                    !signature.stored_ordinals.front() ||
                    *signature.stored_ordinals.front() >= stored_->size()) {
                    throw std::logic_error(
                        "LaminateFolded resident operand alias is invalid");
                }
            }
        }
    }

    std::size_t pair_count() const { return aliases_.pair_count; }
    std::size_t live_pair_count() const { return aliases_.live_pair_count; }
    std::span<const std::size_t> physical_pair_order() const {
        return aliases_.physical_pair_order;
    }

    std::size_t first_round_scan_count(std::size_t suffix_count) const {
        return suffix_count;
    }

    const typename Backend::Ciphertext *level_reference() const {
        for (std::size_t pair = 0; pair < live_pair_count(); ++pair) {
            for (const auto *value : {&left_value(pair),
                                      &right_value(pair)}) {
                if (value->is_encrypted()) {
                    return &value->ciphertext();
                }
            }
        }
        return nullptr;
    }

    const fhe::FheValue<Backend> &left_value(std::size_t pair) const {
        if (!compact_) {
            return stored_->at(pair);
        }
        return operand(aliases_.left_operand.at(pair));
    }

    const fhe::FheValue<Backend> &right_value(std::size_t pair) const {
        if (!compact_) {
            return stored_->at(aliases_.pair_count + pair);
        }
        return operand(aliases_.right_operand.at(pair));
    }

  private:
    const fhe::FheValue<Backend> &operand(std::size_t operand_id) const {
        const auto &signature = aliases_.operands.at(operand_id);
        return stored_->at(*signature.stored_ordinals.front());
    }

    /// Canonical compact trace layer; ciphertext values remain owned by trace.
    const std::vector<fhe::FheValue<Backend>> *stored_;
    /// Maps each logical left/right pair to its compact stored operand.
    ::laminate::gkr::detail::DenseMultiplicationAliasPlan aliases_;
    /// Whether `stored_` uses the alias-compressed rather than padded layout.
    bool compact_ = false;
};

template <fhe::FheBackend Backend>
FoldedResidentMultiplicationSource<Backend>
make_folded_resident_multiplication_source(
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTrace<Backend> &trace,
    std::size_t layer, std::size_t expected_pair_count) {
    FoldedResidentMultiplicationSource<Backend> source(
        circuit, trace, layer);
    if (source.pair_count() != expected_pair_count) {
        throw std::logic_error(
            "LaminateFolded resident multiplication geometry drifted");
    }
    return source;
}

} // namespace laminate::gkr::folded_detail

#endif // LAMINATE_GKR_DETAIL_FOLDED_REFERENCE_MULTIPLICATION_SOURCE_HPP
