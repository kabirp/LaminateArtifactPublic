#ifndef LAMINATE_DELEGATION_BASE_SERVER_CAPACITY_WORKSPACE_HPP
#define LAMINATE_DELEGATION_BASE_SERVER_CAPACITY_WORKSPACE_HPP

/// @file server/capacity/workspace.hpp
/// @brief Derived GateMLE and dense-multiplication workspace floors.

#include "laminate/delegation/base/server/capacity/arithmetic.hpp"
#include "laminate/payload/trace/trace_wire_support.hpp"
#include "laminate/setup/gate_mle.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/resource_bounds.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace laminate::delegation::base_server_detail {

inline std::uint64_t minimum_outsourced_gate_opening_ram(
    const gates::GateTableProverKey &key) {
    if (key.tables.size() != key.verifier.tables.size()) {
        throw std::invalid_argument(
            "GateMLE prover/verifier table count mismatch");
    }
    for (std::size_t index = 0; index < key.tables.size(); ++index) {
        if (!(key.tables[index].verifier == key.verifier.tables[index])) {
            throw std::invalid_argument(
                "GateMLE prover/verifier table geometry mismatch");
        }
    }
    // Keep process-server admission on exactly the same conservative formula
    // (including allocator slack) that setup reports and persists.
    return gate_mle_prover_resource_bounds(key.verifier)
        .opening_workspace_bytes;
}

inline std::uint64_t minimum_dense_multiplication_builder_ram(
    const payload::LayerWireSupport &source_support,
    const payload::LayerStorageLayout &source_storage,
    const payload::PayloadReplayLayer &source,
    const gkr::detail::DenseMultiplicationAliasPlan &aliases) {
    if (source.serialized_ciphertext_bytes == 0 ||
        source.resident_ciphertext_bytes == 0) {
        throw std::invalid_argument(
            "Base dense multiplication source sizes must be nonzero");
    }
    (void)source_support;
    const std::uint64_t resident =
        source.proof_ingress_resident_ciphertext_bytes == 0
            ? source.resident_ciphertext_bytes
            : source.proof_ingress_resident_ciphertext_bytes;
    const std::uint64_t serialized =
        source.proof_ingress_serialized_ciphertext_bytes == 0
            ? source.serialized_ciphertext_bytes
            : source.proof_ingress_serialized_ciphertext_bytes;
    return gkr::detail::dense_multiplication_builder_workspace_bytes(
        aliases,
        std::max(resident, checked_capacity_add(
            serialized, 1U, "Base dense tagged source record bytes")),
        source_storage.stored_wire_count);
}

} // namespace laminate::delegation::base_server_detail

#endif // LAMINATE_DELEGATION_BASE_SERVER_CAPACITY_WORKSPACE_HPP
