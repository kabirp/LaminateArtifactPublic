#ifndef LAMINATE_DELEGATION_BASE_WIRE_DETAIL_GATE_MLE_PROOF_HPP
#define LAMINATE_DELEGATION_BASE_WIRE_DETAIL_GATE_MLE_PROOF_HPP

/// @file gate_mle_proof.hpp
/// @brief Bounded decoding for logical headers and outsourced GateMLE proofs.

#include "laminate/delegation/base/wire/detail/extension_values.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::delegation::base_wire_detail {

inline constexpr std::string_view kLogicalHeaderDomain =
    "LaminateImpl/LogicalProofHeader/v1";
inline constexpr std::string_view kOutsourcedGateProofDomain =
    "LaminateImpl/OutsourcedGateMleProof/v5";
inline constexpr std::string_view kBaseFoldProofDomain =
    "LaminateImpl/BaseFoldProof/v1";

/// Resource policy for every target matrix decoded by a structured opening.
/// A Wide sparse request has both its local table row and one shared-index
/// row per transparent operand. The latter has the full committed width.
inline std::size_t gate_target_values_upper_bound(
    const gates::GateTableVerifierKey &key,
    std::size_t maximum_sparse_requests) {
    constexpr const char *operation = "Base GateMLE target-value bound";
    std::size_t maximum_values_per_request = 0;
    for (const auto &table : key.tables) {
        std::size_t values = table.physical_width;
        if (key.layout.table_set == gates::GateTableSet::Wide) {
            if (!key.wide_public_commitment)
                wire_detail::reject(operation, "missing Wide public index");
            values = wire_detail::checked_add(values,
                wire_detail::checked_multiply(
                    gates::wide_public_operands_per_request(
                        table, *key.wide_public_commitment),
                    key.wide_public_commitment->width, operation), operation);
        }
        maximum_values_per_request =
            std::max(maximum_values_per_request, values);
    }
    return wire_detail::checked_multiply(
        maximum_sparse_requests, maximum_values_per_request, operation);
}

inline gkr::ProtocolVariant read_variant(Reader &reader,
                                         const char *operation) {
    const auto value = static_cast<gkr::ProtocolVariant>(reader.read_u8());
    switch (value) {
    case gkr::ProtocolVariant::LaminateBase:
    case gkr::ProtocolVariant::LaminateFolded:
    case gkr::ProtocolVariant::LaminateLaned:
        return value;
    }
    wire_detail::reject(operation, "unknown protocol variant");
}

inline GateMleProfile read_gate_profile(Reader &reader, const char *operation) {
    const auto value = static_cast<GateMleProfile>(reader.read_u8());
    switch (value) {
    case GateMleProfile::Direct:
    case GateMleProfile::DummyCommittedDirect:
    case GateMleProfile::OutsourcedBaseFold:
        return value;
    }
    wire_detail::reject(operation, "unknown GateMLE profile");
}

inline gkr::CrossRoundPacking read_cross_round_packing(Reader &reader,
                                                       const char *operation) {
    if (reader.read_u8() !=
        static_cast<std::uint8_t>(gkr::CrossRoundPacking::None)) {
        wire_detail::reject(operation, "unknown cross-round packing profile");
    }
    return gkr::CrossRoundPacking::None;
}

inline payload::TraceProvenance read_provenance(Reader &reader,
                                                const char *operation) {
    const auto value = static_cast<payload::TraceProvenance>(reader.read_u8());
    switch (value) {
    case payload::TraceProvenance::SyntheticTrace:
    case payload::TraceProvenance::FheEvaluated:
        return value;
    }
    wire_detail::reject(operation, "unknown trace provenance");
}

inline gkr::ProofHeader read_header(Reader &reader, const char *operation) {
    const std::size_t bytes = reader.read_size();
    Reader header(reader.read_bytes(bytes), operation);
    require_label(header, kLogicalHeaderDomain, operation);
    gkr::ProofHeader result;
    result.version = header.read_u64();
    result.profile.variant = read_variant(header, operation);
    result.profile.gate_mle = read_gate_profile(header, operation);
    result.profile.cross_round_packing =
        read_cross_round_packing(header, operation);
    result.provenance = read_provenance(header, operation);
    result.circuit_id = wire_detail::read_digest(header);
    result.setup_id = wire_detail::read_digest(header);
    result.trace_id = wire_detail::read_digest(header);
    result.layer_count = header.read_size();
    header.require_end();
    return result;
}

inline void append_partial_gate_mle(Bytes &output,
                                    const gkr::PartialGateMleVector &partial,
                                    const char *operation) {
    append_fpk_values(output, partial.evaluations, operation);
}

inline gkr::PartialGateMleVector
read_partial_gate_mle(Reader &reader, std::size_t expected_count,
                      DecodeBudget &budget, const BaseWireDecodeLimits &limits,
                      const char *operation) {
    if (expected_count > limits.max_partial_gate_values) {
        wire_detail::reject(operation,
                            "partial GateMLE width exceeds configured limit");
    }
    return gkr::PartialGateMleVector{
        read_fpk_values(reader, expected_count, budget, operation)};
}

inline std::vector<Fpk> read_bounded_fpk_values(Reader &reader,
                                                std::size_t maximum_count,
                                                DecodeBudget &budget,
                                                const char *operation) {
    const std::size_t count = reader.read_size();
    if (count > maximum_count) {
        wire_detail::reject(operation,
                            "field-vector length exceeds configured limit");
    }
    const std::size_t bytes =
        wire_detail::checked_multiply(count, kSerializedFpkBytes, operation);
    if (bytes > reader.remaining()) {
        wire_detail::reject(operation, "truncated field vector");
    }
    budget.add_fields(count);
    std::vector<Fpk> result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.push_back(
            deserialize_fpk(reader.read_bytes(kSerializedFpkBytes)));
    }
    return result;
}

struct SparseProofShape {
    std::size_t entry_variables = 0;
    std::size_t product_layers = 0;
};

inline std::size_t sparse_product_layers(std::size_t address_variables,
                                         const char *operation) {
    if (address_variables == std::numeric_limits<std::size_t>::max()) {
        wire_detail::reject(operation, "sparse GateMLE dimension overflows");
    }
    const std::size_t factor_count = address_variables + 1U;
    std::size_t padded_factors = 1U;
    std::size_t layers = 0;
    while (padded_factors < factor_count) {
        if (padded_factors > std::numeric_limits<std::size_t>::max() / 2U) {
            wire_detail::reject(operation,
                                "sparse GateMLE factor tree overflows");
        }
        padded_factors *= 2U;
        ++layers;
    }
    return layers;
}

inline std::vector<SparseProofShape>
validate_sparse_table_shapes(const gates::GateTableVerifierKey &key,
                             const char *operation) {
    if (key.layout.tables.size() != key.tables.size()) {
        wire_detail::reject(operation,
                            "sparse GateMLE key has mismatched tables");
    }
    std::vector<SparseProofShape> shapes;
    shapes.reserve(key.tables.size());
    for (std::size_t selector = 0; selector < key.tables.size(); ++selector) {
        const gates::GateTableDescriptor &descriptor =
            key.layout.tables[selector];
        const gates::SparseTableCommitment &table = key.tables[selector];
        if (descriptor.selector != selector ||
            !gates::valid_sparse_table_commitment(descriptor, table,
                                                  key.basefold_parameters)) {
            wire_detail::reject(operation,
                                "invalid sparse GateMLE table geometry");
        }
        shapes.push_back(SparseProofShape{
            basefold::log2_exact(table.message_size),
            sparse_product_layers(descriptor.local_variables, operation)});
    }
    return shapes;
}

inline bool has_sparse_proof_shape(std::span<const SparseProofShape> shapes,
                                   std::size_t entry_variables,
                                   std::size_t product_layers) {
    return std::any_of(shapes.begin(), shapes.end(),
                       [&](const SparseProofShape &shape) {
                           return shape.entry_variables == entry_variables &&
                                  shape.product_layers == product_layers;
                       });
}

inline gates::WideActionSumcheckProof
read_action_sumcheck(Reader &reader, std::size_t maximum_rounds,
                     DecodeBudget &budget, const BaseWireDecodeLimits &limits,
                     const char *operation) {
    const std::size_t round_count = reader.read_size();
    if (round_count == 0 || round_count > maximum_rounds ||
        round_count > limits.max_gate_proof_rounds) {
        wire_detail::reject(operation,
                            "invalid Wide action sumcheck round count");
    }
    const std::size_t round_fields =
        wire_detail::checked_multiply(round_count, 2U, operation);
    const std::size_t total_fields =
        wire_detail::checked_add(round_fields, 1U, operation);
    const std::size_t bytes = wire_detail::checked_multiply(
        total_fields, kSerializedFpkBytes, operation);
    if (bytes > reader.remaining()) {
        wire_detail::reject(operation, "truncated Wide action sumcheck");
    }

    gates::WideActionSumcheckProof result;
    result.rounds.reserve(round_count);
    for (std::size_t round = 0; round < round_count; ++round) {
        result.rounds.push_back(gates::WideActionSumcheckRound{
            read_fpk(reader, budget), read_fpk(reader, budget)});
    }
    result.terminal_compact_weight = read_fpk(reader, budget);
    return result;
}

inline gates::sparse::SparseProductProof
read_sparse_product(Reader &reader, std::span<const SparseProofShape> shapes,
                    DecodeBudget &budget, const BaseWireDecodeLimits &limits,
                    const char *operation) {
    const std::size_t root_round_count = reader.read_size();
    if (root_round_count > limits.max_gate_proof_rounds ||
        std::none_of(shapes.begin(), shapes.end(),
                     [&](const SparseProofShape &shape) {
                         return shape.entry_variables == root_round_count;
                     })) {
        wire_detail::reject(operation,
                            "invalid sparse root sumcheck round count");
    }
    const std::size_t root_bytes = wire_detail::checked_multiply(
        root_round_count, kSerializedFpkBytes, operation);
    if (root_bytes > reader.remaining()) {
        wire_detail::reject(operation, "truncated sparse root sumcheck");
    }

    gates::sparse::SparseProductProof result;
    result.root_rounds.reserve(root_round_count);
    for (std::size_t round = 0; round < root_round_count; ++round) {
        result.root_rounds.push_back(read_fpk(reader, budget));
    }

    const std::size_t layer_count = reader.read_size();
    if (layer_count > limits.max_gate_proof_rounds ||
        !has_sparse_proof_shape(shapes, root_round_count, layer_count)) {
        wire_detail::reject(operation,
                            "invalid sparse product-tree layer count");
    }
    result.layers.reserve(layer_count);
    for (std::size_t layer = 0; layer < layer_count; ++layer) {
        const std::size_t expected_rounds =
            wire_detail::checked_add(root_round_count, layer, operation);
        if (expected_rounds > limits.max_gate_proof_rounds ||
            reader.read_size() != expected_rounds) {
            wire_detail::reject(operation,
                                "invalid sparse product-layer round count");
        }
        const std::size_t round_fields =
            wire_detail::checked_multiply(expected_rounds, 2U, operation);
        const std::size_t layer_fields =
            wire_detail::checked_add(round_fields, 2U, operation);
        const std::size_t layer_bytes = wire_detail::checked_multiply(
            layer_fields, kSerializedFpkBytes, operation);
        if (layer_bytes > reader.remaining()) {
            wire_detail::reject(operation, "truncated sparse product layer");
        }

        gates::sparse::ProductLayerProof product_layer;
        product_layer.rounds.reserve(expected_rounds);
        for (std::size_t round = 0; round < expected_rounds; ++round) {
            product_layer.rounds.push_back(
                {read_fpk(reader, budget), read_fpk(reader, budget)});
        }
        product_layer.left_claim = read_fpk(reader, budget);
        product_layer.right_claim = read_fpk(reader, budget);
        result.layers.push_back(std::move(product_layer));
    }
    return result;
}

inline basefold::Proof
read_basefold_proof(Reader &reader, const gates::SparseTableCommitment &table,
                    const basefold::Parameters &parameters,
                    std::size_t operand_count, DecodeBudget &budget,
                    const BaseWireDecodeLimits &limits, const char *operation) {
    require_label(reader, kBaseFoldProofDomain, operation);
    const std::size_t message_length = table.shard_size;
    const std::size_t width = table.physical_width;
    const std::size_t message_variables = basefold::log2_exact(message_length);
    const std::size_t encoded_length =
        basefold::codeword_length(message_length, parameters.log_rate);
    const std::size_t final_length =
        basefold::codeword_length(1, parameters.log_rate);
    const std::size_t query_count = parameters.num_queries;
    if (operand_count == 0 ||
        message_variables > limits.max_gate_proof_rounds ||
        query_count > limits.max_basefold_queries) {
        wire_detail::reject(operation,
                            "BaseFold shape exceeds configured limit");
    }
    if (encoded_length < 2) {
        wire_detail::reject(operation, "invalid BaseFold codeword length");
    }

    basefold::Proof result;
    if (reader.read_size() != message_variables) {
        wire_detail::reject(operation,
                            "unexpected BaseFold sumcheck round count");
    }
    result.sumcheck.rounds.reserve(message_variables);
    for (std::size_t round = 0; round < message_variables; ++round) {
        std::array<Fpk, 3> evaluations{};
        for (Fpk &evaluation : evaluations) {
            evaluation = read_fpk(reader, budget);
        }
        result.sumcheck.rounds.push_back(std::move(evaluations));
    }
    result.sumcheck.operand_evaluations =
        read_fpk_values(reader, operand_count, budget, operation);

    const std::size_t root_count =
        message_variables == 0 ? 0 : message_variables - 1;
    if (reader.read_size() != root_count) {
        wire_detail::reject(operation,
                            "unexpected BaseFold folding-root count");
    }
    budget.add_digests(root_count);
    result.folding.roots.reserve(root_count);
    for (std::size_t root = 0; root < root_count; ++root) {
        basefold::Digest digest{};
        const auto encoded = reader.read_bytes(digest.size());
        std::copy(encoded.begin(), encoded.end(), digest.begin());
        result.folding.roots.push_back(digest);
    }
    result.folding.final_codeword =
        read_fpk_values(reader, final_length, budget, operation);

    if (reader.read_size() != query_count) {
        wire_detail::reject(operation, "unexpected BaseFold query count");
    }
    result.queries.openings.reserve(query_count);
    const std::size_t base_path_length = basefold::log2_exact(encoded_length);
    const std::size_t half_codeword = encoded_length / 2;
    for (std::size_t query = 0; query < query_count; ++query) {
        basefold::QueryOpening opening;
        opening.index = reader.read_size();
        if (opening.index >= half_codeword) {
            wire_detail::reject(operation,
                                "BaseFold query index is out of range");
        }
        opening.base_lo = read_fp_values(reader, width, budget, operation);
        opening.base_hi = read_fp_values(reader, width, budget, operation);
        opening.base_path_lo = read_digest_path(reader, base_path_length,
                                                budget, limits, operation);
        opening.base_path_hi = read_digest_path(reader, base_path_length,
                                                budget, limits, operation);
        if (reader.read_size() != root_count) {
            wire_detail::reject(operation,
                                "unexpected BaseFold fold-opening count");
        }
        opening.folds.reserve(root_count);
        for (std::size_t fold = 0; fold < root_count; ++fold) {
            basefold::FoldOpening fold_opening;
            fold_opening.lo = read_fpk(reader, budget);
            fold_opening.hi = read_fpk(reader, budget);
            const std::size_t layer_length = encoded_length >> (fold + 1U);
            const std::size_t path_length = basefold::log2_exact(layer_length);
            fold_opening.path_lo = read_digest_path(reader, path_length, budget,
                                                    limits, operation);
            fold_opening.path_hi = read_digest_path(reader, path_length, budget,
                                                    limits, operation);
            opening.folds.push_back(std::move(fold_opening));
        }
        result.queries.openings.push_back(std::move(opening));
    }
    return result;
}

inline bool read_gate_flag(Reader &reader, const char *operation) {
    const auto flag = reader.read_u8();
    if (flag > 1)
        wire_detail::reject(operation, "noncanonical GateMLE flag");
    return flag != 0;
}

inline gates::QuadraticProductProof
read_quadratic_product(Reader &reader, std::size_t maximum_rounds,
                       DecodeBudget &budget, const BaseWireDecodeLimits &limits,
                       const char *operation) {
    const auto count = reader.read_size();
    if (count > maximum_rounds || count > limits.max_gate_proof_rounds)
        wire_detail::reject(operation,
                            "invalid quadratic sumcheck round count");
    const auto fields = wire_detail::checked_add(
        wire_detail::checked_multiply(count, 3U, operation), 2U, operation);
    if (fields > reader.remaining() / kSerializedFpkBytes)
        wire_detail::reject(operation, "truncated quadratic sumcheck");
    gates::QuadraticProductProof result;
    result.rounds.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        result.rounds.push_back({read_fpk(reader, budget),
                                 read_fpk(reader, budget),
                                 read_fpk(reader, budget)});
    result.left = read_fpk(reader, budget);
    result.right = read_fpk(reader, budget);
    return result;
}

/// Charge the enclosing message budget before the standalone PCS decoder
/// allocates anything. This scan skips canonical scalar bytes; the exact PCS
/// decoder subsequently checks their encodings and all coupled shape bounds.
inline void account_foldable_blob(std::span<const std::uint8_t> blob,
                                  DecodeBudget &budget,
                                  const BaseWireDecodeLimits &limits,
                                  const char *operation) {
    Reader reader(blob, operation);
    if (reader.read_u64() != basefold::foldable::kHierarchyVersion)
        wire_detail::reject(operation, "unknown foldable proof version");
    const auto rounds = reader.read_size();
    if (rounds > basefold::foldable::kMaxVariables ||
        rounds > limits.max_gate_proof_rounds)
        wire_detail::reject(operation, "foldable round count exceeds limit");
    const auto fields = [&](std::size_t count) {
        const auto bytes = wire_detail::checked_multiply(
            count, kSerializedFpkBytes, operation);
        if (bytes > reader.remaining())
            wire_detail::reject(operation, "truncated foldable fields");
        budget.add_fields(count);
        (void)reader.read_bytes(bytes);
    };
    const auto digests = [&] {
        const auto count = reader.read_size();
        const auto bytes = wire_detail::checked_multiply(
            count, basefold::Digest{}.size(), operation);
        if (bytes > reader.remaining())
            wire_detail::reject(operation, "truncated foldable digests");
        budget.add_digests(count);
        (void)reader.read_bytes(bytes);
    };
    fields(wire_detail::checked_multiply(rounds, 3U, operation));
    fields(reader.read_size()); // Transparent operand terminal values.
    digests();                  // Intermediate folding roots.
    fields(reader.read_size()); // Final constant codeword.
    fields(reader.read_size()); // Initial paired openings.
    digests();
    const auto folds = reader.read_size();
    if (folds > rounds)
        wire_detail::reject(operation, "invalid foldable opening count");
    for (std::size_t i = 0; i < folds; ++i) {
        fields(reader.read_size());
        digests();
    }
    reader.require_end();
}

inline basefold::foldable::Proof read_foldable_proof(
    Reader &reader, const basefold::foldable::Metadata &metadata,
    std::size_t operands, const basefold::foldable::Parameters &parameters,
    DecodeBudget &budget, const BaseWireDecodeLimits &limits,
    const char *operation) {
    if (!basefold::foldable::valid_shape(metadata, parameters) ||
        parameters.num_queries > limits.max_basefold_queries ||
        basefold::log2_exact(metadata.m) > limits.max_gate_proof_rounds ||
        basefold::log2_exact(metadata.m) + 2U > limits.max_merkle_path_digests)
        wire_detail::reject(operation,
                            "foldable shape exceeds configured limit");
    const auto bytes = reader.read_size();
    if (bytes >
        basefold::foldable::proof_size_bound(metadata, operands, parameters))
        wire_detail::reject(operation, "foldable proof exceeds byte bound");
    const auto blob = reader.read_bytes(bytes);
    account_foldable_blob(blob, budget, limits, operation);
    return basefold::foldable::decode_canonical(blob, metadata, operands,
                                                parameters);
}

inline gates::WideLocalOpeningProof
read_wide_local(Reader &reader, std::span<const SparseProofShape> shapes,
                std::size_t slot_variables, std::size_t mask_variables,
                std::size_t &sparse_products, DecodeBudget &budget,
                const BaseWireDecodeLimits &limits, const char *operation) {
    gates::WideLocalOpeningProof result;
    result.first_component = read_fpk(reader, budget);
    result.second_component = read_fpk(reader, budget);
    if (read_gate_flag(reader, operation))
        result.action = read_action_sumcheck(reader, slot_variables, budget,
                                             limits, operation);
    if (read_gate_flag(reader, operation)) {
        gates::MaskedActionProof masked;
        masked.masks = read_quadratic_product(reader, mask_variables, budget,
                                              limits, operation);
        masked.slots = read_quadratic_product(reader, slot_variables, budget,
                                              limits, operation);
        result.masked = std::move(masked);
    }
    const auto count = reader.read_size();
    if (count > 3U)
        wire_detail::reject(operation, "too many local sparse reductions");
    sparse_products =
        wire_detail::checked_add(sparse_products, count, operation);
    result.products.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        result.products.push_back(
            read_sparse_product(reader, shapes, budget, limits, operation));
    return result;
}

inline gates::WideGateOpeningProof
read_wide_gate_proof(Reader &reader, const gates::GateTableVerifierKey &key,
                     std::span<const SparseProofShape> shapes,
                     std::size_t claims, DecodeBudget &budget,
                     const BaseWireDecodeLimits &limits,
                     const char *operation) {
    if (key.layout.wide_layers.empty() || !key.layout.wide_masks.mask_width ||
        !key.layout.wide_masks.slots)
        wire_detail::reject(operation, "missing Wide program geometry");
    const auto slot_variables =
        basefold::log2_exact(key.layout.wide_masks.slots);
    const auto mask_variables =
        basefold::log2_exact(key.layout.wide_masks.mask_width);
    std::size_t maximum_variables = 0;
    for (const auto &layer : key.layout.wide_layers)
        maximum_variables =
            std::max(maximum_variables,
                     basefold::log2_exact(layer.dimensions.internal_scalars));
    if (maximum_variables > basefold::foldable::kMaxVariables)
        wire_detail::reject(operation,
                            "Wide internal domain exceeds PCS policy");
    const auto traces = reader.read_size();
    // Reserve at most two output points per affine layer as a conservative
    // decoding cap. Current GKR requests one; ordered-query verification
    // rejects extras. Generic gate-opening proofs use a separate API.
    const auto maximum_traces = wire_detail::checked_multiply(
        key.layout.wide_layers.size(), 2U, operation);
    if (traces == 0 || traces > claims || traces > maximum_traces)
        wire_detail::reject(operation, "invalid Wide trace count");
    // Presence flag, four counters, one boundary, residual and two terminals.
    constexpr std::size_t minimum_trace_bytes =
        4U * sizeof(std::uint64_t) + 4U * kSerializedFpkBytes + 1U;
    if (traces > reader.remaining() / minimum_trace_bytes)
        wire_detail::reject(operation, "truncated Wide trace headers");
    const auto maximum_boundaries =
        wire_detail::checked_add(claims, traces, operation);
    const auto maximum_locals =
        wire_detail::checked_multiply(maximum_boundaries, 2U, operation);
    gates::WideGateOpeningProof result;
    result.traces.reserve(traces);
    std::size_t boundaries = 0, locals = 0, sparse_products = 0;
    for (std::size_t i = 0; i < traces; ++i) {
        gates::WideTraceOpeningProof trace;
        trace.has_adjoint = read_gate_flag(reader, operation);
        trace.boundary_values = read_bounded_fpk_values(
            reader, maximum_boundaries - boundaries, budget, operation);
        if (trace.boundary_values.empty())
            wire_detail::reject(operation, "empty Wide trace boundary");
        boundaries += trace.boundary_values.size();
        trace.residual_evaluation = read_fpk(reader, budget);
        trace.product = read_quadratic_product(reader, maximum_variables,
                                               budget, limits, operation);
        trace.terminal_values = read_bounded_fpk_values(
            reader, trace.boundary_values.size(), budget, operation);
        const auto count = reader.read_size();
        if (count > maximum_locals - locals ||
            count > wire_detail::checked_multiply(trace.boundary_values.size(),
                                                  2U, operation))
            wire_detail::reject(operation, "invalid Wide local opening count");
        constexpr std::size_t minimum_local_bytes =
            2U * kSerializedFpkBytes + 2U + sizeof(std::uint64_t);
        if (count > reader.remaining() / minimum_local_bytes)
            wire_detail::reject(operation, "truncated Wide local openings");
        locals += count;
        trace.local_openings.reserve(count);
        for (std::size_t j = 0; j < count; ++j)
            trace.local_openings.push_back(
                read_wide_local(reader, shapes, slot_variables, mask_variables,
                                sparse_products, budget, limits, operation));
        if (trace.has_adjoint) {
            const auto variables = trace.product.rounds.size();
            const auto m = std::size_t{1} << variables;
            if (std::none_of(key.layout.wide_layers.begin(),
                             key.layout.wide_layers.end(),
                             [m](const auto &layer) {
                                 return layer.node_count != 0 &&
                                        layer.dimensions.internal_scalars == m;
                             }))
                wire_detail::reject(operation,
                                    "Wide witness shape not admitted by setup");
            if (trace.terminal_values.size() != trace.boundary_values.size() ||
                trace.local_openings.size() !=
                    2U * trace.boundary_values.size())
                wire_detail::reject(operation,
                                    "inconsistent nonempty Wide trace shape");
        } else if (!trace.residual_evaluation.is_zero() ||
                   !trace.product.rounds.empty() ||
                   !trace.product.left.is_zero() ||
                   !trace.product.right.is_zero() ||
                   !trace.terminal_values.empty() ||
                   trace.local_openings.size() !=
                       trace.boundary_values.size()) {
            wire_detail::reject(operation, "noncanonical empty Wide trace");
        }
        result.traces.push_back(std::move(trace));
    }
    std::vector<std::size_t> trace_sizes;
    for (const auto &trace : result.traces)
        trace_sizes.push_back(
            trace.has_adjoint ? std::size_t{1} << trace.product.rounds.size()
                              : 0);
    const auto groups = gates::wide_adjoint_group_layout(trace_sizes);
    const auto group_count = reader.read_size();
    if (group_count != groups.size())
        wire_detail::reject(
            operation, "Wide adjoint group count disagrees with trace shapes");
    result.adjoint_groups.reserve(group_count);
    for (const auto &group : groups) {
        gates::WideAdjointGroupProof opening;
        const auto root = reader.read_bytes(opening.root.size());
        budget.add_digests(1);
        std::copy(root.begin(), root.end(), opening.root.begin());
        opening.opening = read_foldable_proof(
            reader, {opening.root, group.message_size, 1},
            2U * group.trace_indices.size(), key.foldable_parameters, budget,
            limits, operation);
        result.adjoint_groups.push_back(std::move(opening));
    }
    const auto table_count = reader.read_size();
    if (table_count > key.tables.size() || table_count > sparse_products)
        wire_detail::reject(operation, "invalid Wide public opening count");
    result.tables.reserve(table_count);
    std::size_t opened_rows = 0, targets_total = 0, previous = 0, public_operands = 0;
    for (std::size_t i = 0; i < table_count; ++i) {
        const auto selector = reader.read_size();
        if (selector >= key.tables.size() || (i && selector <= previous))
            wire_detail::reject(operation,
                                "Wide public openings not canonically ordered");
        previous = selector;
        const auto &table = key.tables[selector];
        if (!table.wide_block_offset || !key.wide_public_commitment)
            wire_detail::reject(operation,
                                "Wide public table lacks its shared index");
        const auto bytes = reader.read_size();
        Reader target_reader(reader.read_bytes(bytes), operation);
        const auto rows = target_reader.read_size();
        if (rows == 0 || rows > sparse_products - opened_rows)
            wire_detail::reject(operation, "invalid Wide public target rows");
        targets_total =
            wire_detail::checked_add(targets_total,
                                     wire_detail::checked_multiply(
                                         rows, table.physical_width, operation),
                                     operation);
        if (targets_total > limits.max_gate_target_values)
            wire_detail::reject(operation,
                                "Wide public target values exceed limit");
        const auto minimum_target_row_bytes = wire_detail::checked_add(
            sizeof(std::uint64_t),
            wire_detail::checked_multiply(table.physical_width,
                                          kSerializedFpkBytes, operation),
            operation);
        if (rows > target_reader.remaining() / minimum_target_row_bytes)
            wire_detail::reject(operation, "truncated Wide public target rows");
        basefold::ColumnTargets targets;
        targets.reserve(rows);
        for (std::size_t row = 0; row < rows; ++row)
            targets.push_back(read_fpk_values(
                target_reader, table.physical_width, budget, operation));
        target_reader.require_end();
        opened_rows += rows;
        public_operands = wire_detail::checked_add(public_operands,
            wire_detail::checked_multiply(rows,
                gates::wide_public_operands_per_request(table, *key.wide_public_commitment),
                operation), operation);
        if (public_operands > 65536)
            wire_detail::reject(operation, "Wide public operands exceed PCS policy");
        result.tables.push_back({selector, std::move(targets)});
    }
    if (opened_rows != sparse_products)
        wire_detail::reject(operation,
                            "Wide public target rows disagree with reductions");
    if (opened_rows) {
        const auto rows = reader.read_size();
        const auto width = key.wide_public_commitment->width;
        if (rows != public_operands)
            wire_detail::reject(operation, "Wide honest-column target row count mismatch");
        targets_total = wire_detail::checked_add(targets_total,
            wire_detail::checked_multiply(rows, width, operation), operation);
        if (targets_total > limits.max_gate_target_values)
            wire_detail::reject(operation, "Wide public target values exceed limit");
        const auto row_bytes = wire_detail::checked_add(sizeof(std::uint64_t),
            wire_detail::checked_multiply(width, kSerializedFpkBytes, operation), operation);
        if (rows > reader.remaining() / row_bytes)
            wire_detail::reject(operation, "truncated Wide honest-column target matrix");
        result.public_column_targets.reserve(rows);
        for (std::size_t r = 0; r < rows; ++r)
            result.public_column_targets.push_back(read_fpk_values(reader, width, budget, operation));
        result.public_opening = read_foldable_proof(
            reader, *key.wide_public_commitment, public_operands,
            key.foldable_parameters, budget, limits, operation);
    }
    return result;
}

inline gates::OutsourcedGateMleProof read_outsourced_gate_proof(
    Reader &reader, const gates::GateTableVerifierKey &key,
    DecodeBudget &budget, const BaseWireDecodeLimits &limits,
    const char *operation) {
    const std::size_t proof_bytes = reader.read_size();
    Reader proof(reader.read_bytes(proof_bytes), operation);
    require_label(proof, kOutsourcedGateProofDomain, operation);
    const std::vector<SparseProofShape> sparse_shapes =
        validate_sparse_table_shapes(key, operation);
    // Current GKR requests one constant and one coefficient per affine layer.
    // Retain two output points as a conservative cap, bounded by authenticated
    // structure before allocating any claim-dependent objects.
    const auto maximum_claims =
        key.layout.table_set == gates::GateTableSet::Wide
            ? std::min(limits.max_gate_claims,
                       wire_detail::checked_multiply(
                           key.layout.wide_layers.size(), 4U, operation))
            : limits.max_gate_claims;
    std::vector<Fpk> claims =
        read_bounded_fpk_values(proof, maximum_claims, budget, operation);
    if (claims.empty()) {
        wire_detail::reject(operation,
                            "outsourced GateMLE proof has no claims");
    }

    const bool wide = read_gate_flag(proof, operation);
    if (wide != (key.layout.table_set == gates::GateTableSet::Wide))
        wire_detail::reject(operation,
                            "GateMLE proof strategy differs from setup");
    if (wide) {
        gates::OutsourcedGateMleProof result;
        result.wide =
            read_wide_gate_proof(proof, key, sparse_shapes, claims.size(),
                                 budget, limits, operation);
        result.claimed_values = std::move(claims);
        proof.require_end();
        return result;
    }

    const std::size_t maximum_sparse_claims =
        wire_detail::checked_multiply(claims.size(), 2U, operation);
    std::vector<Fpk> sparse_values = read_bounded_fpk_values(
        proof, maximum_sparse_claims, budget, operation);

    std::size_t maximum_action_rounds = 0;
    for (const gates::GateTableDescriptor &descriptor : key.layout.tables) {
        if (descriptor.kind == gates::GateTableKind::WideAffineWeight) {
            maximum_action_rounds =
                std::max(maximum_action_rounds, descriptor.local_variables);
        }
    }
    const std::size_t action_count = proof.read_size();
    if (action_count > claims.size() ||
        (action_count != 0 && maximum_action_rounds == 0)) {
        wire_detail::reject(operation, "invalid Wide action sumcheck count");
    }
    std::vector<gates::WideActionSumcheckProof> action_sumchecks;
    action_sumchecks.reserve(action_count);
    for (std::size_t action = 0; action < action_count; ++action) {
        action_sumchecks.push_back(read_action_sumcheck(
            proof, maximum_action_rounds, budget, limits, operation));
    }

    const std::size_t sparse_product_count = proof.read_size();
    if (sparse_product_count != sparse_values.size() ||
        sparse_product_count > maximum_sparse_claims) {
        wire_detail::reject(operation,
                            "sparse GateMLE proof count disagrees with claims");
    }
    std::vector<gates::sparse::SparseProductProof> sparse_products;
    sparse_products.reserve(sparse_product_count);
    for (std::size_t product = 0; product < sparse_product_count; ++product) {
        sparse_products.push_back(read_sparse_product(
            proof, sparse_shapes, budget, limits, operation));
    }

    const std::size_t opening_count = proof.read_size();
    if (opening_count > key.tables.size() ||
        opening_count > sparse_product_count) {
        wire_detail::reject(operation, "invalid sparse table-opening count");
    }
    std::vector<gates::SparseTableOpeningProof> table_openings;
    table_openings.reserve(opening_count);
    std::size_t opened_rows = 0;
    std::size_t decoded_target_values = 0;
    std::size_t previous_selector = 0;
    bool have_previous_selector = false;
    for (std::size_t opening_index = 0; opening_index < opening_count;
         ++opening_index) {
        const std::size_t selector = proof.read_size();
        if (selector >= key.tables.size() ||
            (have_previous_selector && selector <= previous_selector)) {
            wire_detail::reject(
                operation, "sparse table openings are not canonically ordered");
        }
        previous_selector = selector;
        have_previous_selector = true;
        const gates::SparseTableCommitment &table = key.tables[selector];

        const std::size_t target_blob_bytes = proof.read_size();
        Reader targets_reader(proof.read_bytes(target_blob_bytes), operation);
        const std::size_t rows = targets_reader.read_size();
        if (rows == 0 || rows > sparse_product_count - opened_rows) {
            wire_detail::reject(operation,
                                "invalid sparse table target-row count");
        }
        const std::size_t table_target_values = wire_detail::checked_multiply(
            rows, table.physical_width, operation);
        decoded_target_values = wire_detail::checked_add(
            decoded_target_values, table_target_values, operation);
        if (decoded_target_values > limits.max_gate_target_values) {
            wire_detail::reject(operation,
                                "GateMLE targets exceed configured limit");
        }
        basefold::ColumnTargets targets;
        targets.reserve(rows);
        for (std::size_t row = 0; row < rows; ++row) {
            targets.push_back(read_fpk_values(
                targets_reader, table.physical_width, budget, operation));
        }
        targets_reader.require_end();
        opened_rows = wire_detail::checked_add(opened_rows, rows, operation);

        const std::size_t opening_bytes = proof.read_size();
        Reader opening_reader(proof.read_bytes(opening_bytes), operation);
        basefold::Proof opening =
            read_basefold_proof(opening_reader, table, key.basefold_parameters,
                                rows, budget, limits, operation);
        opening_reader.require_end();
        table_openings.push_back(gates::SparseTableOpeningProof{
            selector, std::move(targets), std::move(opening)});
    }
    if (opened_rows != sparse_product_count) {
        wire_detail::reject(
            operation, "sparse table target rows disagree with reductions");
    }
    proof.require_end();
    gates::OutsourcedGateMleProof result;
    result.claimed_values = std::move(claims);
    result.sparse_values = std::move(sparse_values);
    result.action_sumchecks = std::move(action_sumchecks);
    result.sparse_products = std::move(sparse_products);
    result.table_openings = std::move(table_openings);
    return result;
}

} // namespace laminate::delegation::base_wire_detail

#endif // LAMINATE_DELEGATION_BASE_WIRE_DETAIL_GATE_MLE_PROOF_HPP
