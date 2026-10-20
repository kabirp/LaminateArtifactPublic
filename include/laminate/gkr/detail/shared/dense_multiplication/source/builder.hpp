#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_BUILDER_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_BUILDER_HPP

/// @file builder.hpp
/// @brief Construction of the challenge-independent multiplication artifact.

#include "laminate/gkr/detail/shared/dense_multiplication/source/building/operand.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/disk_bounds.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/plan.hpp"
#include "laminate/gkr/detail/shared/dense_multiplication/source/store.hpp"
#include "laminate/storage/external_record_sort.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::gkr::detail {

/// Optional observation of the source records packed into a multiplication
/// artifact. It is diagnostic only and cannot affect artifact order.
using DenseMultiplicationSourceBuildProgress =
    std::function<void(std::uint64_t completed, std::uint64_t total)>;

/// Freshly published artifact together with the trusted private source that
/// adopted its writer-owned file identities and indexes. `written` is the
/// durable report retained after `source` is consumed or reclaimed.
template <fhe::PersistableFheBackend Backend>
struct BuiltFileDenseMultiplicationSource {
    FileDenseMultiplicationSourceWriteResult written;
    FileDenseMultiplicationSource<Backend> source;
};

/// Construction keeps bounded ciphertext residency. Wide and eager-packed
/// sources scan once into a bounded external sorter. Other aliased packed
/// sources gather one operand at a time through an indexed source reader.
/// Build the challenge-independent dense pair artifact. Logical reader
/// position `y` denotes canonical pair
/// `bit_reverse_index(y, log2(pair_count))`. Distinct packed operands are
/// stored in their first-use order; the circuit-derived alias plan restores
/// logical left/right pairs without duplicating ciphertext records.
template <fhe::PersistableFheBackend Backend, typename TraceSource>
BuiltFileDenseMultiplicationSource<Backend>
build_file_dense_multiplication_source(
    const typename Backend::EvalContext &eval,
    const TraceSource &trace,
    const DenseMultiplicationSourcePlan &plan,
    const std::filesystem::path &directory,
    payload::FileTraceStoreOptions options,
    std::uint64_t sort_buffer_payload_bytes =
        kDenseMultiplicationSortMaxBufferedPayloadBytes,
    DenseMultiplicationSourceBuildProgress progress = {}) {
    const auto descriptor =
        bind_dense_multiplication_source_descriptor(
            plan, trace.descriptor(), trace.layered_circuit_id(),
            Backend::storage_context_id(eval));
    const std::size_t reduction_layer = descriptor.reduction_layer;
    if (trace.backend_context_id() != descriptor.backend_context_id) {
        throw std::invalid_argument(
            "packed multiplication source backend context mismatch");
    }
    const std::size_t chunks = descriptor.chunks_per_packed_ciphertext;
    const std::size_t half_source_wires = descriptor.pair_count * chunks;
    const std::filesystem::path destination =
        file_dense_multiplication_source_detail::validate_empty_private_directory(
            directory);
    const payload::EncryptedTraceDescriptor storage =
        file_dense_multiplication_source_detail::storage_descriptor(descriptor);
    if (sort_buffer_payload_bytes <
        kDenseMultiplicationMinimumSortBufferBytes) {
        throw std::invalid_argument(
            "dense multiplication sort buffer is below the minimum");
    }
    payload::trace_storage::SerializedTraceWriter writer(
        destination, options, descriptor.backend_context_id);
    writer.begin_trace(storage.shape, storage.provenance, storage.circuit_id,
                       storage.trace_id, storage.layers.size());
    const auto &layer = storage.layers.front();
    writer.begin_layer(0, layer.layout, layer.dimensions,
                       layer.required_mult_depth, layer.record_count);

    FileDenseMultiplicationSourceBuildStatistics statistics;
    auto sort_budget =
        std::make_shared<storage::ExternalRecordSortBudget>(
            options.max_total_bytes, options.min_free_bytes);
    sort_budget->set_external_live_bytes(
        writer.current_physical_bytes());
    const auto append_artifact_record =
        [&](std::span<const std::uint8_t> encoded) {
            std::uint64_t projected = writer.current_physical_bytes();
            file_dense_multiplication_source_detail::checked_accumulate(
                projected, sizeof(std::uint64_t),
                "packed multiplication artifact record framing");
            file_dense_multiplication_source_detail::checked_accumulate(
                projected,
                file_dense_multiplication_source_detail::checked_count(
                    encoded.size(),
                    "packed multiplication artifact record payload"),
                "packed multiplication artifact record payload");
            sort_budget->set_external_live_bytes(projected);
            writer.append_serialized(encoded);
            if (writer.current_physical_bytes() != projected) {
                throw std::logic_error(
                    "packed multiplication artifact writer byte ledger "
                    "drifted");
            }
        };
    const payload::LayerStorageLayout &canonical_source_storage =
        plan.source_storage;
    const payload::LayerWireSupport &canonical_source_support =
        plan.source_support;
    const DenseMultiplicationAliasPlan &aliases = plan.aliases;
    if (aliases.operands.size() != descriptor.stored_value_count ||
        aliases.live_pair_count != descriptor.live_pair_count ||
        aliases.pair_count != descriptor.pair_count) {
        throw std::logic_error(
            "packed multiplication alias plan drifted");
    }

    const auto make_sorter = [&] {
        return std::make_unique<storage::ExternalSerializedRecordSorter>(
            storage::ExternalRecordSortOptions{
                .parent_directory = destination,
                .workspace_name = ".dense-multiplication-source-sort",
                .shared_budget = sort_budget,
                .max_buffered_records = static_cast<std::size_t>(
                    std::min<std::uint64_t>(
                        std::numeric_limits<std::size_t>::max(),
                        std::max<std::uint64_t>(1U, sort_buffer_payload_bytes / 256U))),
                .max_buffered_payload_bytes = sort_buffer_payload_bytes,
                .merge_fan_in = kDenseMultiplicationSortMergeFanIn,
            });
    };
    const auto finish_operand_sort = [&](auto &sorter) {
        std::uint64_t next = 0;
        const auto report = sorter.write_sorted(
            [&](std::uint64_t key, std::span<const std::uint8_t> encoded) {
                if (key != next++) {
                    throw std::runtime_error(
                        "packed multiplication distinct operand order drifted");
                }
                append_artifact_record(encoded);
            });
        if (next != aliases.operands.size()) {
            throw std::runtime_error("packed multiplication sort omitted operands");
        }
        statistics.external_sort_initial_runs = report.initial_runs;
        statistics.external_sort_runs_created = report.runs_created;
        statistics.external_sort_merge_passes = report.merge_passes;
        statistics.external_sort_maximum_open_runs = report.maximum_open_runs;
        statistics.external_sort_temporary_bytes_written = report.temporary_bytes_written;
        statistics.external_sort_temporary_bytes_deleted = report.temporary_bytes_deleted;
        statistics.external_sort_peak_live_temporary_bytes = sort_budget->peak_live_bytes();
        statistics.external_sort_retained_temporary_bytes = sort_budget->current_live_bytes();
        statistics.external_sort_peak_buffered_records = report.peak_buffered_records;
        statistics.external_sort_peak_buffered_payload_bytes = report.peak_buffered_payload_bytes;
    };
    const auto finish_artifact = [&]() {
        statistics.live_pairs_written = descriptor.live_pair_count;
        writer.finish_layer();
        auto serialized = std::move(writer).finish_private_single_layer_store();
        const payload::FileTraceStoreWriteResult written{
            serialized.directory(), serialized.backend_context_id(),
            serialized.descriptor(), serialized.report(), serialized.write_diagnostics()};
        sort_budget->set_external_live_bytes(written.report.physical_bytes);
        statistics.external_sort_peak_combined_artifact_bytes =
            sort_budget->peak_combined_live_bytes();
        if (written.descriptor != storage ||
            statistics.external_sort_retained_temporary_bytes != 0 ||
            statistics.external_sort_temporary_bytes_written !=
                statistics.external_sort_temporary_bytes_deleted) {
            throw std::logic_error("packed multiplication artifact ledger drifted");
        }
        FileDenseMultiplicationSourceWriteResult report{
            destination, descriptor,
            FileDenseMultiplicationSourceReport{
                written.report.logical_record_bytes, written.report.physical_bytes,
                file_dense_multiplication_source_detail::checked_stored_values(descriptor)},
            statistics};
        auto source = FileDenseMultiplicationSource<Backend>::adopt_same_writer_store(
            eval, descriptor, plan, std::move(serialized));
        return BuiltFileDenseMultiplicationSource<Backend>{std::move(report), std::move(source)};
    };

    if constexpr (requires {
                      trace.uses_eager_laned_witness_packing();
                      trace.laned_packed_layer_reader(reduction_layer + 1U);
                      trace.laned_packed_layer_layout(reduction_layer + 1U);
                      trace.laned_packed_layer_rns_limbs(reduction_layer + 1U);
                  }) {
        if (trace.uses_eager_laned_witness_packing()) {
            const std::size_t source_layer = reduction_layer + 1U;
            if (!(trace.laned_packed_layer_layout(source_layer) == descriptor.source_layout) ||
                trace.laned_packed_layer_rns_limbs(source_layer) !=
                    descriptor.packed_proof_ingress_rns_limbs) {
                throw std::invalid_argument("eager packed multiplication source metadata mismatch");
            }
            constexpr auto missing = std::numeric_limits<std::size_t>::max();
            std::vector<std::size_t> representative(aliases.operands.size(), missing);
            for (std::size_t packed = 0; packed < aliases.live_pair_count; ++packed) {
                auto &left = representative.at(aliases.left_operand[packed]);
                auto &right = representative.at(aliases.right_operand[packed]);
                if (left == missing) left = packed;
                if (right == missing) right = descriptor.pair_count + packed;
            }
            std::vector<std::size_t> output_by_packed(
                descriptor.source_layout.logical_ciphertext_count, missing);
            for (std::size_t operand = 0; operand < representative.size(); ++operand)
                output_by_packed.at(representative[operand]) =
                    aliases.storage_ordinal_by_operand[operand];
            auto sorter = make_sorter();
            auto source_reader = trace.laned_packed_layer_reader(source_layer);
            std::size_t packed = 0;
            while (auto value = source_reader.next()) {
                if (value->is_encrypted())
                    validate_dense_artifact_ingress_ciphertext<Backend>(eval,
                        value->ciphertext(), descriptor.packed_proof_ingress_rns_limbs,
                        "eager packed multiplication source");
                const auto output = output_by_packed.at(packed++);
                if (output != missing)
                    sorter->append(output, std::make_shared<const std::vector<std::uint8_t>>(
                        fhe::encode_fhe_value_record<Backend>(eval, *value)));
                if (progress && (packed % 1024U == 0 || packed == output_by_packed.size()))
                    progress(packed, output_by_packed.size());
            }
            if (packed != output_by_packed.size())
                throw std::runtime_error("eager packed multiplication source ended early");
            statistics.source_range_opens = 1;
            statistics.source_sequential_passes = 1;
            statistics.source_values_read = packed;
            statistics.source_logical_record_bytes_read = source_reader.encoded_bytes_read();
            statistics.peak_live_source_values = 1;
            statistics.peak_live_packed_values = 1;
            finish_operand_sort(*sorter);
            return finish_artifact();
        }
    }

    // Keep progress coarse enough that telemetry never becomes part of the
    // hot record loop. A nested checkpoint replay may run while the first
    // reader opens, so the first update also restores the artifact build as
    // the operator-visible active phase.
    const auto make_progress_reporter = [&](std::size_t total) {
        const std::size_t stride = std::max<std::size_t>(1U, total / 64U);
        return [progress, total, stride,
                next = stride](std::size_t completed) mutable {
            if (!progress || (completed < next && completed != total)) {
                return;
            }
            progress(static_cast<std::uint64_t>(completed),
                     static_cast<std::uint64_t>(total));
            while (next <= completed && next < total) {
                next = std::min(total, next + stride);
            }
        };
    };

    // Aliased sources have no reason to retain the whole layer. Wide
    // operands are serialized once in source order and externally reordered.
    // Packed operands gather their chunks through one reusable indexed reader
    // and are immediately serialized in final order.
    if (canonical_source_storage.stored_wire_count !=
        canonical_source_support.live_wire_count) {
        auto source_reader = trace.active_layer_reader(reduction_layer + 1U);
        statistics.source_range_opens = 1;
        if (chunks == 1U) {
            constexpr auto missing = std::numeric_limits<std::size_t>::max();
            std::vector<std::size_t> output_by_source(
                canonical_source_storage.stored_wire_count, missing);
            for (std::size_t operand = 0; operand < aliases.operands.size(); ++operand) {
                const auto &signature = aliases.operands[operand].stored_ordinals;
                if (signature.size() != 1 || !signature.front())
                    throw std::logic_error("wide multiplication operand has no source");
                auto &output = output_by_source.at(*signature.front());
                if (output != missing)
                    throw std::logic_error("wide multiplication source is duplicated");
                output = aliases.storage_ordinal_by_operand[operand];
            }
            auto sorter = make_sorter();
            auto report_progress = make_progress_reporter(output_by_source.size());
            std::size_t ordinal = 0;
            while (auto source = source_reader.next()) {
                if (source->padded_index !=
                    canonical_source_storage.representative_padded_index_of(ordinal))
                    throw std::runtime_error("multiplication distinct source order drifted");
                if (source->value.is_encrypted())
                    validate_dense_artifact_ingress_ciphertext<Backend>(eval,
                        source->value.ciphertext(), descriptor.source_proof_ingress_rns_limbs,
                        "dense multiplication artifact input");
                const auto output = output_by_source.at(ordinal++);
                if (output == missing)
                    throw std::logic_error("multiplication source has no output operand");
                sorter->append(output, std::make_shared<const std::vector<std::uint8_t>>(
                    fhe::encode_fhe_value_record<Backend>(eval, source->value)));
                report_progress(ordinal);
            }
            if (ordinal != output_by_source.size())
                throw std::runtime_error("multiplication distinct source ended early");
            statistics.source_values_read = ordinal;
            statistics.source_sequential_passes = 1;
            statistics.peak_live_source_values = 1;
            statistics.peak_live_packed_values = 1;
            finish_operand_sort(*sorter);
        } else {
            fhe::SlotVector first_chunk_basis(descriptor.shape.slot_count, Fp::zero());
            std::fill_n(first_chunk_basis.begin(), descriptor.shape.lane_count, Fp::one());
            std::optional<fhe::PreparedFpSlotBasis<Backend>> prepared_first_chunk;
            auto report_progress = make_progress_reporter(aliases.operands.size());
            std::size_t completed = 0;
            for (const auto operand : aliases.storage_order) {
                fhe::FheValue<Backend> accumulator = fhe::FheValue<Backend>::public_zero();
                const auto &ordinals = aliases.operands[operand].stored_ordinals;
                for (std::size_t chunk = 0; chunk < ordinals.size(); ++chunk) {
                    if (!ordinals[chunk]) continue;
                    if (source_reader.position() != *ordinals[chunk]) {
                        source_reader.seek_to(*ordinals[chunk]);
                        ++statistics.source_indexed_seeks;
                    }
                    auto source = source_reader.next();
                    if (!source || source->padded_index !=
                        canonical_source_storage.representative_padded_index_of(*ordinals[chunk]))
                        throw std::runtime_error("multiplication indexed chunk is missing");
                    ++statistics.source_values_read;
                    statistics.peak_live_source_values = 1;
                    if (source->value.is_public_zero()) continue;
                    fhe::FheValue<Backend> term;
                    if (source->value.is_public()) {
                        term = fhe::value_mul<Backend>(eval, source->value,
                            fhe::FheValue<Backend>::public_slots(first_chunk_basis));
                    } else {
                        validate_dense_artifact_ingress_ciphertext<Backend>(eval,
                            source->value.ciphertext(), descriptor.source_proof_ingress_rns_limbs,
                            "dense multiplication artifact input");
                        if (!prepared_first_chunk) {
                            prepared_first_chunk = fhe::prepare_fp_slot_basis<Backend>(
                                eval, source->value.ciphertext(), first_chunk_basis);
                            statistics.prepared_chunk_bases = 1;
                        }
                        term = fhe::FheValue<Backend>::from_ciphertext(
                            fhe::mul_plain_prepared<Backend>(eval, source->value.ciphertext(),
                                *prepared_first_chunk));
                        ++statistics.prepared_chunk_basis_applications;
                        statistics.avoided_online_slot_vector_elements += descriptor.shape.slot_count;
                    }
                    if (chunk != 0U) {
                        term = fhe::value_rotate<Backend>(eval, term,
                            fhe::grid_inverse(descriptor.shape.slot_count,
                                chunk * descriptor.shape.lane_count));
                        ++statistics.chunk_placement_rotations;
                    }
                    fhe::value_add_assign<Backend>(eval, accumulator, std::move(term));
                }
                if (accumulator.is_encrypted())
                    fhe::mod_switch_to_rns_limb_count<Backend>(eval,
                        accumulator.ciphertext(), descriptor.packed_proof_ingress_rns_limbs);
                append_artifact_record(fhe::encode_fhe_value_record<Backend>(eval, accumulator));
                statistics.peak_live_packed_values = 2;
                report_progress(++completed);
            }
        }
        statistics.source_logical_record_bytes_read = source_reader.encoded_bytes_read();
        return finish_artifact();
    }
    const std::size_t bits =
        std::bit_width(descriptor.pair_count) - 1U;
    const std::size_t live_wires_per_side =
        descriptor.source_dimensions.logical_size / 2U;
    const std::size_t total_source_values =
        descriptor.source_dimensions.logical_size;
    auto report_progress = make_progress_reporter(total_source_values);
    std::size_t source_values_completed = 0;
    file_dense_multiplication_source_detail::checked_accumulate(
        statistics.source_range_opens, 2,
        "packed multiplication source reader opens");

    storage::ExternalSerializedRecordSorter sorter({
        .parent_directory = destination,
        .workspace_name = ".dense-multiplication-source-sort",
        .shared_budget = sort_budget,
        // Reserve at least 256 bytes of host budget per record for the
        // pending key, shared ownership, and allocator metadata. Encrypted
        // records normally hit the payload-byte cap first.
        .max_buffered_records = static_cast<std::size_t>(
            std::min<std::uint64_t>(
                std::numeric_limits<std::size_t>::max(),
                std::max<std::uint64_t>(
                    1U, sort_buffer_payload_bytes / 256U))),
        .max_buffered_payload_bytes = sort_buffer_payload_bytes,
        .merge_fan_in = kDenseMultiplicationSortMergeFanIn,
    });
    std::optional<fhe::PreparedFpSlotBasis<Backend>> prepared_first_chunk;
    const auto scan_half = [&](auto &reader, std::size_t padded_base,
                               std::uint64_t side) {
        file_dense_multiplication_source_detail::checked_accumulate(
            statistics.source_sequential_passes, 1,
            "packed multiplication source sequential passes");
        for (std::size_t packed = 0;
             packed < descriptor.live_pair_count; ++packed) {
            const std::size_t consumed = packed * chunks;
            const std::size_t remaining = live_wires_per_side - consumed;
            fhe::FheValue<Backend> value =
                file_dense_multiplication_source_detail::
                    pack_one_sequential<Backend>(
                        eval, reader, padded_base + consumed, remaining,
                        descriptor, prepared_first_chunk, statistics,
                        [&] {
                            report_progress(++source_values_completed);
                        });
            const std::size_t physical = bit_reverse_index(packed, bits);
            sorter.append(
                file_dense_multiplication_source_detail::checked_count(
                    2U * physical + static_cast<std::size_t>(side),
                    "packed multiplication physical side index"),
                std::make_shared<const std::vector<std::uint8_t>>(
                    fhe::encode_fhe_value_record<Backend>(eval, value)));
        }
        if (reader.next()) {
            throw std::runtime_error(
                "packed multiplication sequential half scan exceeded its "
                "live boundary");
        }
        file_dense_multiplication_source_detail::checked_accumulate(
            statistics.source_logical_record_bytes_read,
            reader.encoded_bytes_read(),
            "packed multiplication source bytes");
    };
    {
        auto left_reader = trace.active_layer_reader(
            reduction_layer + 1U, 0, live_wires_per_side);
        scan_half(left_reader, 0, 0);
    }
    {
        auto right_reader = trace.active_layer_reader(
            reduction_layer + 1U, live_wires_per_side,
            2U * live_wires_per_side);
        scan_half(right_reader, half_source_wires, 1);
    }
    std::optional<std::uint64_t> pending_left_physical;
    std::optional<std::uint64_t> previous_key;
    std::uint64_t emitted = 0;
    const storage::ExternalRecordSortReport sort_report =
        sorter.write_sorted(
            [&](std::uint64_t key,
                std::span<const std::uint8_t> encoded) {
            const std::uint64_t physical = key / 2U;
            const std::uint64_t side = key % 2U;
            if ((previous_key && key <= *previous_key) ||
                physical >= descriptor.pair_count ||
                bit_reverse_index(
                    static_cast<std::size_t>(physical),
                    bits) >= descriptor.live_pair_count) {
                throw std::runtime_error(
                    "packed multiplication external order is invalid");
            }
            previous_key = key;
            if (side == 0U) {
                if (pending_left_physical) {
                    throw std::runtime_error(
                        "packed multiplication sorted sides are not "
                        "adjacent");
                }
                pending_left_physical = physical;
            } else {
                if (!pending_left_physical ||
                    *pending_left_physical != physical) {
                    throw std::runtime_error(
                        "packed multiplication sorted right side has no "
                        "left side");
                }
                pending_left_physical.reset();
                ++emitted;
            }
            append_artifact_record(encoded);
        });
    if (pending_left_physical || emitted != descriptor.live_pair_count) {
        throw std::runtime_error(
            "packed multiplication external sort omitted live pairs");
    }
    statistics.external_sort_initial_runs = sort_report.initial_runs;
    statistics.external_sort_runs_created = sort_report.runs_created;
    statistics.external_sort_merge_passes = sort_report.merge_passes;
    statistics.external_sort_maximum_open_runs =
        sort_report.maximum_open_runs;
    statistics.external_sort_temporary_bytes_written =
        sort_report.temporary_bytes_written;
    statistics.external_sort_temporary_bytes_deleted =
        sort_report.temporary_bytes_deleted;
    statistics.external_sort_peak_live_temporary_bytes =
        sort_budget->peak_live_bytes();
    statistics.external_sort_peak_combined_artifact_bytes =
        sort_budget->peak_combined_live_bytes();
    statistics.external_sort_retained_temporary_bytes =
        sort_budget->current_live_bytes();
    statistics.external_sort_peak_buffered_records =
        sort_report.peak_buffered_records;
    statistics.external_sort_peak_buffered_payload_bytes =
        sort_report.peak_buffered_payload_bytes;
    statistics.live_pairs_written =
        file_dense_multiplication_source_detail::checked_count(
            descriptor.live_pair_count,
            "packed multiplication written live-pair count");
    writer.finish_layer();
    auto serialized =
        std::move(writer).finish_private_single_layer_store();
    const payload::FileTraceStoreWriteResult written{
        serialized.directory(), serialized.backend_context_id(),
        serialized.descriptor(), serialized.report(),
        serialized.write_diagnostics()};
    sort_budget->set_external_live_bytes(written.report.physical_bytes);
    statistics.external_sort_peak_combined_artifact_bytes =
        sort_budget->peak_combined_live_bytes();
    const std::uint64_t stored_values =
        file_dense_multiplication_source_detail::checked_stored_values(
            descriptor);
    if (statistics.source_values_read !=
            descriptor.source_dimensions.logical_size ||
        statistics.live_pairs_written != descriptor.live_pair_count ||
        statistics.external_sort_temporary_bytes_written !=
            statistics.external_sort_temporary_bytes_deleted ||
        statistics.external_sort_retained_temporary_bytes != 0 ||
        written.descriptor != storage) {
        throw std::logic_error(
            "packed multiplication source construction ledger drifted");
    }
    FileDenseMultiplicationSourceWriteResult report{
        destination,
        descriptor,
        FileDenseMultiplicationSourceReport{
            written.report.logical_record_bytes,
            written.report.physical_bytes,
            stored_values,
        },
        statistics,
    };
    auto source = FileDenseMultiplicationSource<Backend>::
        adopt_same_writer_store(eval, descriptor, plan,
                                std::move(serialized));
    return BuiltFileDenseMultiplicationSource<Backend>{
        std::move(report), std::move(source)};
}

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_BUILDER_HPP
