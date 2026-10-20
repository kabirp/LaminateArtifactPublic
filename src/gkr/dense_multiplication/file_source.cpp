/// @file file_source.cpp
/// @brief Identity and geometry checks for file-backed multiplication sources.

#include "laminate/gkr/detail/shared/dense_multiplication/source/descriptor.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/disk_bounds.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/plan.hpp"

#include "laminate/payload/checkpoint/plan.hpp"
#include "laminate/storage/external_record_sort.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace laminate::gkr::detail {
namespace {

bool is_zero(const Digest &value) {
    return std::all_of(value.begin(), value.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

void append_u64(std::vector<std::uint8_t> &output, std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "packed multiplication descriptor value exceeds u64");
        }
    }
    const auto word = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < sizeof(word); ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            word >> static_cast<unsigned>(8U * byte)));
    }
}

void append_digest(std::vector<std::uint8_t> &output,
                   const Digest &value) {
    output.insert(output.end(), value.begin(), value.end());
}

void append_shape(std::vector<std::uint8_t> &output,
                  const payload::PayloadShape &shape) {
    append_u64(output,
               shape.kind == payload::PayloadKind::Laned ? 0U : 1U);
    append_u64(output, shape.lane_count);
    append_u64(output, shape.slot_count);
}

void append_layout(std::vector<std::uint8_t> &output,
                   const packing::LanedPackingLayout &layout) {
    append_u64(output, layout.slot_count);
    append_u64(output, layout.lane_count);
    append_u64(output, layout.original_wire_count);
    append_u64(output, layout.logical_ciphertext_count);
    append_u64(output, layout.padded_ciphertext_count);
}

void append_dimensions(std::vector<std::uint8_t> &output,
                       const payload::LayerDimensions &dimensions) {
    append_u64(output, dimensions.logical_size);
    append_u64(output, dimensions.padded_size);
    append_u64(output, dimensions.payload_size);
    append_u64(output, dimensions.forward_size);
}

Digest compute_artifact_id(
    const FileDenseMultiplicationSourceDescriptor &descriptor) {
    static constexpr std::string_view kDomain =
        "LaminateImpl/FileDenseMultiplicationSource/v1";
    std::vector<std::uint8_t> encoded(kDomain.begin(), kDomain.end());
    append_digest(encoded, descriptor.setup_id);
    append_digest(encoded, descriptor.backend_context_id);
    append_digest(encoded, descriptor.circuit_id);
    append_digest(encoded, descriptor.layered_circuit_id);
    append_digest(encoded, descriptor.trace_id);
    append_u64(encoded,
               descriptor.provenance ==
                       payload::TraceProvenance::SyntheticTrace
                   ? 0U
                   : 1U);
    append_shape(encoded, descriptor.shape);
    append_u64(encoded, descriptor.reduction_layer);
    append_layout(encoded, descriptor.output_layout);
    append_layout(encoded, descriptor.source_layout);
    append_dimensions(encoded, descriptor.source_dimensions);
    append_u64(encoded, descriptor.source_required_mult_depth);
    append_u64(encoded, descriptor.source_proof_ingress_rns_limbs);
    append_u64(encoded, descriptor.packed_proof_ingress_rns_limbs);
    append_u64(encoded, descriptor.packed_required_mult_depth);
    append_u64(encoded, descriptor.chunks_per_packed_ciphertext);
    append_u64(encoded, descriptor.pair_count);
    append_u64(encoded, descriptor.live_pair_count);
    append_u64(encoded, descriptor.stored_value_count);
    return sha256(encoded);
}

std::size_t checked_twice(std::size_t value, const char *description) {
    if (value > std::numeric_limits<std::size_t>::max() / 2U) {
        throw std::overflow_error(std::string(description) +
                                  " overflows size_t");
    }
    return 2U * value;
}

std::size_t checked_product(std::size_t left, std::size_t right,
                            const char *description) {
    if (left != 0 &&
        right > std::numeric_limits<std::size_t>::max() / left) {
        throw std::overflow_error(std::string(description) +
                                  " overflows size_t");
    }
    return left * right;
}

std::uint64_t checked_u64(std::size_t value,
                          const char *description) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(std::string(description) +
                                      " exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t checked_add_u64(std::uint64_t left, std::uint64_t right,
                              const char *description) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(description) +
                                  " overflows u64");
    }
    return left + right;
}

std::uint64_t checked_multiply_u64(std::uint64_t left,
                                   std::uint64_t right,
                                   const char *description) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(description) +
                                  " overflows u64");
    }
    return left * right;
}

} // namespace

FileDenseMultiplicationSourceDiskBounds
file_dense_multiplication_source_disk_bounds(
    std::size_t stored_value_count, std::uint64_t max_record_bytes,
    bool uses_external_sort, std::uint64_t sort_buffer_payload_bytes) {
    if (stored_value_count == 0 || max_record_bytes == 0) {
        throw std::invalid_argument(
            "dense multiplication disk bounds require nonzero records and "
            "record bytes");
    }

    const std::uint64_t records = checked_u64(
        stored_value_count, "dense multiplication stored value count");
    const std::uint64_t artifact = checked_add_u64(
        payload::file_trace_manifest_bytes(1),
        payload::file_trace_layer_artifact_bytes(
            stored_value_count, max_record_bytes),
        "dense multiplication completed artifact");
    if (!uses_external_sort) {
        return {artifact, artifact};
    }
    if (sort_buffer_payload_bytes <
        kDenseMultiplicationMinimumSortBufferBytes) {
        throw std::invalid_argument(
            "dense multiplication sort buffer is below the minimum");
    }
    if (max_record_bytes > sort_buffer_payload_bytes) {
        throw std::invalid_argument(
            "dense multiplication sorted record exceeds the configured "
            "buffered payload cap");
    }

    // If the configured byte cap can hold fewer than the record cap
    // records, every nonfinal initial run still contains at least that many:
    // otherwise the next <=B-byte record could not have triggered a flush.
    // Later generations preserve the record bytes and only reduce the number
    // of 16-byte run headers.
    const std::uint64_t records_by_payload =
        sort_buffer_payload_bytes / max_record_bytes;
    const std::uint64_t records_by_host_metadata =
        sort_buffer_payload_bytes / 256U;
    const std::uint64_t records_per_run = std::min<std::uint64_t>(
        records_by_host_metadata, records_by_payload);
    const std::uint64_t initial_runs =
        1 + (records - 1) / records_per_run;
    const std::uint64_t run_record_bytes = checked_add_u64(
        max_record_bytes,
        storage::kExternalRecordSortRecordFramingBytes,
        "dense multiplication temporary record");
    const std::uint64_t run_population = checked_add_u64(
        checked_multiply_u64(
            records, run_record_bytes,
            "dense multiplication temporary records"),
        checked_multiply_u64(
            initial_runs, storage::kExternalRecordSortRunHeaderBytes,
            "dense multiplication temporary run headers"),
        "dense multiplication temporary run population");

    // The writer has emitted only its 40-byte layer prefix while
    // intermediate runs are merged. A replacement run can be no larger than
    // one whole generation, so that phase is prefix + 2S. The final merge
    // writes directly into the artifact instead of another run, so its phase
    // is at most S + A. Index and manifest publication happens only after the
    // temporary runs have been erased.
    constexpr std::uint64_t kPartialLayerPrefixBytes =
        5 * sizeof(std::uint64_t);
    const std::uint64_t intermediate_merge_peak = checked_add_u64(
        kPartialLayerPrefixBytes,
        checked_multiply_u64(
            2, run_population,
            "dense multiplication intermediate run populations"),
        "dense multiplication intermediate merge peak");
    const std::uint64_t final_merge_peak = checked_add_u64(
        run_population, artifact,
        "dense multiplication final merge peak");
    return {artifact,
            std::max(intermediate_merge_peak, final_merge_peak)};
}

DenseMultiplicationAliasPlan make_dense_multiplication_alias_plan(
    const payload::LayeredCircuit &circuit, std::size_t reduction_layer) {
    const payload::CanonicalTraceLayout canonical =
        payload::canonical_trace_layout(circuit);
    if (reduction_layer + 1U >= canonical.wire_support.size()) {
        throw std::out_of_range(
            "packed multiplication source layer is out of range");
    }
    return make_dense_multiplication_alias_plan(
        circuit, reduction_layer,
        canonical.wire_support[reduction_layer + 1U],
        canonical.storage[reduction_layer + 1U]);
}

DenseMultiplicationAliasPlan make_dense_multiplication_alias_plan(
    const payload::LayeredCircuit &circuit, std::size_t reduction_layer,
    const payload::LayerWireSupport &support,
    const payload::LayerStorageLayout &storage) {
    if (reduction_layer + 1U >= circuit.layers.size() ||
        payload::layer_kind(circuit.layers[reduction_layer]) !=
            payload::LayerKind::Multiplication) {
        throw std::invalid_argument(
            "packed multiplication alias plan names no reduction");
    }

    const packing::LanedPackingLayout output =
        dense_multiplication_storage_layout(circuit, reduction_layer);
    const packing::LanedPackingLayout source =
        dense_multiplication_storage_layout(circuit,
                                            reduction_layer + 1U);
    if (source.padded_ciphertext_count !=
        2U * output.padded_ciphertext_count) {
        throw std::logic_error(
            "packed multiplication alias plan has misaligned halves");
    }
    payload::validate_layer_wire_support(support);
    payload::validate_layer_storage_layout(storage);
    if (support.padded_wire_count != source.original_wire_count ||
        storage.padded_wire_count != support.padded_wire_count) {
        throw std::invalid_argument(
            "packed multiplication cached source layout has wrong domain");
    }
    for (std::size_t padded = 0; padded < support.padded_wire_count;
         ++padded) {
        if (support.is_live(padded) !=
            storage.stored_ordinal_of(padded).has_value()) {
            throw std::invalid_argument(
                "packed multiplication cached support/storage disagree");
        }
    }
    const std::size_t chunks = source.chunks_per_ciphertext();
    const std::size_t half_source_wires =
        output.padded_ciphertext_count * chunks;
    const std::size_t left_live =
        payload::trace_storage::live_wire_rank(
            support, half_source_wires);
    const std::size_t right_live = support.live_wire_count - left_live;
    if (left_live == 0U || left_live != right_live) {
        throw std::logic_error(
            "packed multiplication alias plan source is not paired");
    }

    DenseMultiplicationAliasPlan result;
    result.pair_count = output.padded_ciphertext_count;
    result.live_pair_count = (left_live - 1U) / chunks + 1U;
    result.left_operand.reserve(result.live_pair_count);
    result.right_operand.reserve(result.live_pair_count);

    struct SignatureHash {
        std::size_t operator()(
            const DenseMultiplicationOperandSignature &signature) const
            noexcept {
            std::size_t value = signature.stored_ordinals.size();
            for (const auto ordinal : signature.stored_ordinals) {
                const std::size_t part = ordinal.value_or(
                    std::numeric_limits<std::size_t>::max());
                value ^= part + std::size_t{0x9e3779b97f4a7c15ULL} +
                         (value << 6U) + (value >> 2U);
            }
            return value;
        }
    };
    std::unordered_map<DenseMultiplicationOperandSignature, std::size_t,
                       SignatureHash>
        operand_by_signature;
    operand_by_signature.reserve(2U * result.live_pair_count);
    const auto intern_operand = [&](std::size_t first_source) {
        DenseMultiplicationOperandSignature signature;
        signature.stored_ordinals.reserve(chunks);
        for (std::size_t chunk = 0; chunk < chunks; ++chunk) {
            signature.stored_ordinals.push_back(
                storage.stored_ordinal_of(first_source + chunk));
        }
        const auto [entry, inserted] = operand_by_signature.emplace(
            signature, result.operands.size());
        if (inserted) {
            result.operands.push_back(std::move(signature));
        }
        return entry->second;
    };
    for (std::size_t pair = 0; pair < result.live_pair_count; ++pair) {
        result.left_operand.push_back(intern_operand(pair * chunks));
        result.right_operand.push_back(
            intern_operand(half_source_wires + pair * chunks));
    }

    result.physical_pair_order = live_packed_indices_in_physical_order(
        result.live_pair_count, result.pair_count);
    result.storage_ordinal_by_operand.assign(
        result.operands.size(), std::numeric_limits<std::size_t>::max());
    result.operand_occurrences.assign(result.operands.size(), 0U);
    for (const std::size_t pair : result.physical_pair_order) {
        for (const std::size_t operand :
             {result.left_operand[pair], result.right_operand[pair]}) {
            ++result.operand_occurrences[operand];
            if (result.storage_ordinal_by_operand[operand] ==
                std::numeric_limits<std::size_t>::max()) {
                result.storage_ordinal_by_operand[operand] =
                    result.storage_order.size();
                result.storage_order.push_back(operand);
            }
        }
    }
    if (result.storage_order.size() != result.operands.size()) {
        throw std::logic_error(
            "packed multiplication alias plan omitted an operand");
    }
    return result;
}

std::size_t bit_reverse_index(std::size_t value, std::size_t bit_count) {
    constexpr std::size_t kBits =
        std::numeric_limits<std::size_t>::digits;
    if (bit_count >= kBits ||
        (bit_count == 0 ? value != 0
                        : value >= (std::size_t{1} << bit_count))) {
        throw std::out_of_range(
            "bit_reverse_index: value is outside the selected domain");
    }
    std::size_t result = 0;
    for (std::size_t bit = 0; bit < bit_count; ++bit) {
        result = (result << 1U) | (value & std::size_t{1});
        value >>= 1U;
    }
    return result;
}

namespace file_dense_multiplication_source_detail {

void validate_descriptor(
    const FileDenseMultiplicationSourceDescriptor &descriptor) {
    descriptor.shape.validate();
    const bool power_of_two =
        descriptor.pair_count != 0 &&
        (descriptor.pair_count & (descriptor.pair_count - 1U)) == 0;
    const bool known_provenance =
        descriptor.provenance ==
            payload::TraceProvenance::SyntheticTrace ||
        descriptor.provenance == payload::TraceProvenance::FheEvaluated;
    const std::size_t source_packed =
        checked_twice(descriptor.pair_count,
                      "packed multiplication source count");
    const std::size_t source_wires = checked_product(
        source_packed, descriptor.chunks_per_packed_ciphertext,
        "packed multiplication source wires");
    const bool valid_source_dimensions =
        descriptor.source_dimensions.logical_size != 0 &&
        descriptor.source_dimensions.logical_size <=
            descriptor.source_dimensions.padded_size &&
        descriptor.source_dimensions.payload_size <=
            descriptor.source_dimensions.logical_size &&
        descriptor.source_dimensions.forward_size <=
            descriptor.source_dimensions.logical_size -
                descriptor.source_dimensions.payload_size &&
        descriptor.source_dimensions.payload_size +
                descriptor.source_dimensions.forward_size ==
            descriptor.source_dimensions.logical_size;
    const auto expected_layout =
        [&](std::size_t original_wire_count) {
            if (descriptor.shape.kind == payload::PayloadKind::Laned) {
                return packing::LanedPackingLayout::create(
                    descriptor.shape, original_wire_count);
            }
            return packing::LanedPackingLayout{
                descriptor.shape.slot_count,
                descriptor.shape.slot_count,
                original_wire_count,
                original_wire_count,
                original_wire_count};
        };
    const bool valid_layouts =
        descriptor.output_layout.original_wire_count != 0 &&
        descriptor.output_layout ==
            expected_layout(descriptor.output_layout.original_wire_count) &&
        descriptor.source_layout ==
            expected_layout(descriptor.source_dimensions.padded_size);
    const bool even_logical_source =
        descriptor.source_dimensions.logical_size % 2U == 0;
    const std::size_t live_wires_per_side =
        descriptor.source_dimensions.logical_size / 2U;
    const std::size_t expected_live_pairs =
        even_logical_source && live_wires_per_side != 0 &&
                descriptor.chunks_per_packed_ciphertext != 0
            ? (live_wires_per_side - 1U) /
                      descriptor.chunks_per_packed_ciphertext +
                  1U
            : 0;
    const bool valid_sparse_boundary =
        even_logical_source && descriptor.live_pair_count != 0 &&
        descriptor.live_pair_count <= descriptor.pair_count &&
        descriptor.live_pair_count == expected_live_pairs;
    const bool valid_stored_values =
        descriptor.stored_value_count != 0U &&
        descriptor.stored_value_count <=
            checked_twice(descriptor.live_pair_count,
                          "packed multiplication dense stored values");
    if (is_zero(descriptor.setup_id) ||
        is_zero(descriptor.backend_context_id) ||
        is_zero(descriptor.circuit_id) ||
        is_zero(descriptor.layered_circuit_id) ||
        is_zero(descriptor.trace_id) || !known_provenance ||
        !power_of_two ||
        descriptor.output_layout.slot_count !=
            descriptor.shape.slot_count ||
        descriptor.source_layout.slot_count !=
            descriptor.shape.slot_count ||
        descriptor.output_layout.padded_ciphertext_count !=
            descriptor.pair_count ||
        descriptor.source_layout.padded_ciphertext_count != source_packed ||
        descriptor.source_layout.chunks_per_ciphertext() !=
            descriptor.chunks_per_packed_ciphertext ||
        descriptor.source_dimensions.padded_size != source_wires ||
        descriptor.source_layout.original_wire_count != source_wires ||
        !valid_source_dimensions || !valid_layouts ||
        !valid_sparse_boundary || !valid_stored_values ||
        descriptor.source_proof_ingress_rns_limbs == 0 ||
        descriptor.packed_proof_ingress_rns_limbs == 0 ||
        descriptor.packed_proof_ingress_rns_limbs >
            descriptor.source_proof_ingress_rns_limbs ||
        descriptor.packed_required_mult_depth + 1U !=
            descriptor.packed_proof_ingress_rns_limbs ||
        descriptor.artifact_id != compute_artifact_id(descriptor)) {
        throw std::invalid_argument(
            "invalid packed multiplication source descriptor");
    }
}

FileDenseMultiplicationSourceDescriptor make_descriptor(
    const payload::LayeredCircuit &circuit,
    const payload::EncryptedTraceDescriptor &trace,
    const Digest &layered_circuit_id, const Digest &backend_context_id,
    std::size_t reduction_layer,
    const payload::LayerWireSupport &source_support,
    const DenseMultiplicationAliasPlan &aliases, const Digest &setup_id,
    std::size_t source_proof_ingress_rns_limbs) {
    // Whole-circuit validation, digesting, support discovery, and storage
    // discovery belong to admission. This layer-local constructor checks only
    // the entries selected from that admitted metadata.
    payload::validate_encrypted_trace_descriptor(trace);
    const payload::TraceLayerLayout expected_source_layout =
        circuit.shape.kind == payload::PayloadKind::Laned
            ? payload::TraceLayerLayout::BPeriodic
            : payload::TraceLayerLayout::Wide;
    if (circuit.layers.empty() ||
        reduction_layer >= circuit.layers.size() - 1U ||
        source_proof_ingress_rns_limbs == 0 ||
        payload::layer_kind(circuit.layers[reduction_layer]) !=
            payload::LayerKind::Multiplication ||
        !(trace.shape == circuit.shape) ||
        trace.layers.size() != circuit.layers.size() ||
        trace.layers[reduction_layer + 1].layout !=
            expected_source_layout ||
        !(trace.layers[reduction_layer + 1].dimensions ==
          payload::layer_dimensions(circuit.layers[reduction_layer + 1]))) {
        throw std::invalid_argument(
            "packed multiplication source circuit or trace mismatch");
    }

    FileDenseMultiplicationSourceDescriptor descriptor;
    descriptor.setup_id = setup_id;
    descriptor.backend_context_id = backend_context_id;
    descriptor.circuit_id = trace.circuit_id;
    descriptor.layered_circuit_id = layered_circuit_id;
    descriptor.trace_id = trace.trace_id;
    descriptor.provenance = trace.provenance;
    descriptor.shape = circuit.shape;
    descriptor.reduction_layer = reduction_layer;
    descriptor.output_layout =
        dense_multiplication_storage_layout(circuit, reduction_layer);
    descriptor.source_layout = dense_multiplication_storage_layout(
        circuit, reduction_layer + 1);
    descriptor.source_dimensions =
        trace.layers[reduction_layer + 1].dimensions;
    descriptor.source_required_mult_depth =
        trace.layers[reduction_layer + 1].required_mult_depth;
    descriptor.source_proof_ingress_rns_limbs =
        source_proof_ingress_rns_limbs;
    descriptor.chunks_per_packed_ciphertext =
        descriptor.source_layout.chunks_per_ciphertext();
    if (descriptor.chunks_per_packed_ciphertext != 1U &&
        source_proof_ingress_rns_limbs < 2U) {
        throw std::invalid_argument(
            "dense multiplication packing needs one proof-ingress limb");
    }
    descriptor.packed_proof_ingress_rns_limbs =
        source_proof_ingress_rns_limbs -
        static_cast<std::size_t>(
            descriptor.chunks_per_packed_ciphertext != 1);
    descriptor.packed_required_mult_depth =
        descriptor.packed_proof_ingress_rns_limbs - 1U;
    descriptor.pair_count =
        descriptor.output_layout.padded_ciphertext_count;
    const std::size_t half_source_wires = checked_product(
        descriptor.pair_count, descriptor.chunks_per_packed_ciphertext,
        "packed multiplication source half");
    const std::size_t left_live_wires =
        payload::trace_storage::live_wire_rank(
            source_support, half_source_wires);
    const std::size_t right_live_wires =
        source_support.live_wire_count - left_live_wires;
    const bool full_support = left_live_wires == half_source_wires;
    const bool canonical_paired_prefix =
        left_live_wires != 0 && left_live_wires == right_live_wires &&
        ((full_support && source_support.live_ranges.size() == 1U &&
          source_support.live_ranges.front() ==
              payload::LiveWireRange{0, source_support.padded_wire_count}) ||
         (!full_support && source_support.live_ranges.size() == 2U &&
          source_support.live_ranges[0] ==
              payload::LiveWireRange{0, left_live_wires} &&
          source_support.live_ranges[1] ==
              payload::LiveWireRange{half_source_wires,
                                     right_live_wires}));
    if (!canonical_paired_prefix ||
        source_support.live_wire_count !=
            descriptor.source_dimensions.logical_size) {
        throw std::logic_error(
            "dense multiplication source support is not a paired prefix");
    }
    descriptor.live_pair_count =
        (left_live_wires - 1U) /
            descriptor.chunks_per_packed_ciphertext +
        1U;
    if (aliases.pair_count != descriptor.pair_count ||
        aliases.live_pair_count != descriptor.live_pair_count) {
        throw std::logic_error(
            "packed multiplication alias geometry drifted");
    }
    descriptor.stored_value_count = aliases.operands.size();
    descriptor.artifact_id = compute_artifact_id(descriptor);
    validate_descriptor(descriptor);
    return descriptor;
}

DenseMultiplicationSourcePlan make_dense_multiplication_source_plan_impl(
    const payload::LayeredCircuit &circuit,
    payload::EncryptedTraceDescriptor trace_template,
    const Digest &layered_circuit_id, const Digest &backend_context_id,
    std::size_t reduction_layer,
    const payload::LayerWireSupport &source_support,
    const payload::LayerStorageLayout &source_storage,
    const Digest &setup_id,
    std::size_t source_proof_ingress_rns_limbs) {
    trace_template.trace_id = Digest{};
    DenseMultiplicationAliasPlan aliases =
        make_dense_multiplication_alias_plan(
            circuit, reduction_layer, source_support, source_storage);
    payload::EncryptedTraceDescriptor validation_trace = trace_template;
    validation_trace.trace_id.front() = 1U;
    FileDenseMultiplicationSourceDescriptor descriptor = make_descriptor(
        circuit, validation_trace, layered_circuit_id,
        backend_context_id, reduction_layer, source_support, aliases, setup_id,
        source_proof_ingress_rns_limbs);
    if (aliases.operands.size() != descriptor.stored_value_count ||
        aliases.live_pair_count != descriptor.live_pair_count ||
        aliases.pair_count != descriptor.pair_count) {
        throw std::logic_error(
            "dense multiplication source plan alias geometry drifted");
    }
    const payload::EncryptedTraceDescriptor artifact_storage =
        storage_descriptor(descriptor);
    std::uint64_t minimum_framing =
        payload::file_trace_manifest_bytes(artifact_storage.layers.size());
    for (const auto &layer : artifact_storage.layers) {
        minimum_framing = checked_add_u64(
            minimum_framing,
            payload::file_trace_layer_artifact_bytes(
                layer.record_count, 0),
            "dense multiplication source plan artifact framing");
    }
    descriptor.trace_id = Digest{};
    descriptor.artifact_id = Digest{};
    return DenseMultiplicationSourcePlan{
        std::move(trace_template), std::move(descriptor),
        source_support, source_storage, std::move(aliases),
        minimum_framing};
}

FileDenseMultiplicationSourceDescriptor
bind_dense_multiplication_source_descriptor_impl(
    const DenseMultiplicationSourcePlan &plan,
    const payload::EncryptedTraceDescriptor &trace,
    const Digest &layered_circuit_id, const Digest &backend_context_id) {
    if (is_zero(trace.trace_id) ||
        layered_circuit_id !=
            plan.descriptor_template.layered_circuit_id ||
        backend_context_id !=
            plan.descriptor_template.backend_context_id) {
        throw std::invalid_argument(
            "dense multiplication source plan request identity mismatch");
    }
    payload::EncryptedTraceDescriptor normalized = trace;
    normalized.trace_id = Digest{};
    if (normalized != plan.trace_template) {
        throw std::invalid_argument(
            "dense multiplication source plan trace metadata mismatch");
    }
    FileDenseMultiplicationSourceDescriptor descriptor =
        plan.descriptor_template;
    descriptor.trace_id = trace.trace_id;
    descriptor.artifact_id = compute_artifact_id(descriptor);
    validate_descriptor(descriptor);
    return descriptor;
}

payload::EncryptedTraceDescriptor storage_descriptor(
    const FileDenseMultiplicationSourceDescriptor &descriptor) {
    validate_descriptor(descriptor);
    const std::uint64_t stored = checked_stored_values(descriptor);
    if (stored == 0 || stored > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(
            "packed multiplication source has no stored values");
    }
    const std::size_t value_count =
        static_cast<std::size_t>(stored);
    constexpr std::size_t kLargestPowerOfTwo =
        std::size_t{1}
        << (std::numeric_limits<std::size_t>::digits - 1U);
    if (value_count > kLargestPowerOfTwo) {
        throw std::overflow_error(
            "packed multiplication storage domain overflows size_t");
    }
    const std::size_t padded_count = std::bit_ceil(value_count);
    const payload::TraceLayerLayout artifact_layout =
        descriptor.shape.kind == payload::PayloadKind::Laned
            ? payload::TraceLayerLayout::BPeriodic
            : payload::TraceLayerLayout::Wide;
    return payload::EncryptedTraceDescriptor{
        descriptor.shape,
        descriptor.provenance,
        descriptor.artifact_id,
        descriptor.trace_id,
        {payload::EncryptedTraceLayerDescriptor{
            artifact_layout,
            payload::LayerDimensions{value_count, padded_count,
                                     value_count, 0},
            descriptor.packed_required_mult_depth,
            value_count,
        }},
    };
}

std::filesystem::path validate_empty_private_directory(
    const std::filesystem::path &directory) {
    if (directory.empty()) {
        throw std::invalid_argument(
            "packed multiplication source directory is empty");
    }
    const std::filesystem::path normalized =
        std::filesystem::absolute(directory).lexically_normal();
    const auto status = std::filesystem::symlink_status(normalized);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::directory_iterator(normalized) !=
            std::filesystem::directory_iterator()) {
        throw std::invalid_argument(
            "packed multiplication source requires an existing empty "
            "private directory");
    }
    return normalized;
}

} // namespace file_dense_multiplication_source_detail

DenseMultiplicationSourcePlan make_dense_multiplication_source_plan(
    const payload::LayeredCircuit &circuit,
    payload::EncryptedTraceDescriptor trace_template,
    const Digest &layered_circuit_id, const Digest &backend_context_id,
    std::size_t reduction_layer,
    const payload::LayerWireSupport &source_support,
    const payload::LayerStorageLayout &source_storage,
    const Digest &setup_id,
    std::size_t source_proof_ingress_rns_limbs) {
    return file_dense_multiplication_source_detail::
        make_dense_multiplication_source_plan_impl(
            circuit, std::move(trace_template), layered_circuit_id,
            backend_context_id, reduction_layer, source_support,
            source_storage, setup_id,
            source_proof_ingress_rns_limbs);
}

FileDenseMultiplicationSourceDescriptor
bind_dense_multiplication_source_descriptor(
    const DenseMultiplicationSourcePlan &plan,
    const payload::EncryptedTraceDescriptor &trace,
    const Digest &layered_circuit_id, const Digest &backend_context_id) {
    return file_dense_multiplication_source_detail::
        bind_dense_multiplication_source_descriptor_impl(
            plan, trace, layered_circuit_id, backend_context_id);
}

} // namespace laminate::gkr::detail
