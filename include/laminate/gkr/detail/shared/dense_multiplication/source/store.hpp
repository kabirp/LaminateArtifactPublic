#ifndef LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_STORE_HPP
#define LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_STORE_HPP

/// @file store.hpp
/// @brief Validated admission and lifetime of a multiplication artifact.

#include "laminate/gkr/detail/shared/dense_multiplication/source/reader.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>

namespace laminate::gkr::detail {

/// Validated packed source. Persisted artifacts enter through `open`, which
/// verifies the complete descriptor and data file, including canonical backend
/// decoding. A freshly built private artifact can instead transfer the
/// writer's already-validated file identities and indexes through
/// `adopt_same_writer_store`; that path never weakens the standalone opener.
/// A reader retains only operands which the public alias plan reuses; one-use
/// operands remain file-backed.
template <fhe::PersistableFheBackend Backend>
class FileDenseMultiplicationSource {
  public:
    /// Reopen one complete artifact against the same immutable plan used to
    /// build it. There is deliberately no unplanned or circuit-rescanning open
    /// path in the production file-backed protocol.
    static FileDenseMultiplicationSource open(
        const typename Backend::EvalContext &eval,
        const std::filesystem::path &directory,
        const FileDenseMultiplicationSourceDescriptor &expected,
        const DenseMultiplicationSourcePlan &plan) {
        validate_expected(eval, expected, plan);
        const payload::EncryptedTraceDescriptor storage =
            file_dense_multiplication_source_detail::storage_descriptor(expected);
        auto serialized =
            payload::trace_storage::SerializedTraceStore::open(
                directory, expected.backend_context_id,
                [&](const payload::EncryptedTraceDescriptor &actual) {
                    if (actual != storage) {
                        throw std::invalid_argument(
                            "packed multiplication source identity mismatch");
                    }
                },
                [&](std::size_t, std::size_t,
                    std::span<const std::uint8_t> encoded) {
                    fhe::validate_fhe_value_record<Backend>(
                        eval, encoded,
                        expected.packed_proof_ingress_rns_limbs,
                        Backend::storage_ciphertext_byte_limit(eval));
                });
        return FileDenseMultiplicationSource(
            eval, expected, std::move(serialized), plan.aliases);
    }

    /// Adopt a one-layer store returned directly by its private writer.
    ///
    /// The writer handoff carries the exact offsets, digests, and bound file
    /// identities established while canonical records were emitted. This is
    /// the trusted same-process counterpart to `open`: it checks the complete
    /// public plan and storage descriptor but deliberately does not reread and
    /// decode every record. Persisted or independently supplied artifacts must
    /// continue to use `open`.
    static FileDenseMultiplicationSource adopt_same_writer_store(
        const typename Backend::EvalContext &eval,
        const FileDenseMultiplicationSourceDescriptor &expected,
        const DenseMultiplicationSourcePlan &plan,
        payload::trace_storage::SerializedTraceStore serialized) {
        validate_expected(eval, expected, plan);
        const payload::EncryptedTraceDescriptor storage =
            file_dense_multiplication_source_detail::storage_descriptor(expected);
        if (serialized.backend_context_id() != expected.backend_context_id ||
            serialized.descriptor() != storage) {
            throw std::invalid_argument(
                "same-writer dense multiplication source identity mismatch");
        }
        return FileDenseMultiplicationSource(
            eval, expected, std::move(serialized), plan.aliases);
    }

    const FileDenseMultiplicationSourceDescriptor &descriptor() const {
        return descriptor_;
    }

    FileDenseMultiplicationSourceReport report() const {
        return FileDenseMultiplicationSourceReport{
            serialized_.report().logical_record_bytes,
            serialized_.report().physical_bytes,
            file_dense_multiplication_source_detail::checked_stored_values(
                descriptor_),
        };
    }

    FileDenseMultiplicationSourceReader<Backend> reader() const {
        const auto count = static_cast<std::size_t>(
            file_dense_multiplication_source_detail::
                checked_stored_values(descriptor_));
        std::optional<payload::trace_storage::ValidatedPrivateLayerRangeReader>
            alias_reader;
        if (aliases_.has_aliases()) {
            // Both handles lease the already-validated layer and bind its
            // identity. Opening the second handle does not revalidate records
            // or reconstruct the shared index.
            alias_reader.emplace(serialized_.layer_range(
                0, 0, count, nullptr, payload::FileTraceStoreReadPattern::Random));
        }
        return FileDenseMultiplicationSourceReader<Backend>(
            *eval_, serialized_.layer_range(0, 0, count),
            std::move(alias_reader),
            descriptor_, aliases_);
    }

    /// Remove this completely validated disposable artifact after every
    /// consumer reader has been released. The caller-owned directory remains
    /// present and empty. The returned value is the exact finalized store
    /// length removed, not filesystem allocated blocks.
    std::uint64_t remove_validated_files() && {
        return serialized_.remove_validated_files();
    }

  private:
    static void validate_expected(
        const typename Backend::EvalContext &eval,
        const FileDenseMultiplicationSourceDescriptor &expected,
        const DenseMultiplicationSourcePlan &plan) {
        FileDenseMultiplicationSourceDescriptor expected_template = expected;
        expected_template.trace_id = Digest{};
        expected_template.artifact_id = Digest{};
        if (plan.descriptor_template != expected_template ||
            plan.aliases.operands.size() != expected.stored_value_count) {
            throw std::invalid_argument(
                "dense multiplication source plan identity mismatch");
        }
        file_dense_multiplication_source_detail::validate_descriptor(expected);
        if (expected.backend_context_id !=
            Backend::storage_context_id(eval)) {
            throw std::invalid_argument(
                "packed multiplication source context mismatch");
        }
    }

    FileDenseMultiplicationSource(
        const typename Backend::EvalContext &eval,
        FileDenseMultiplicationSourceDescriptor descriptor,
        payload::trace_storage::SerializedTraceStore serialized,
        DenseMultiplicationAliasPlan aliases)
        : eval_(&eval), descriptor_(std::move(descriptor)),
          serialized_(std::move(serialized)), aliases_(std::move(aliases)) {}

    const typename Backend::EvalContext *eval_;
    FileDenseMultiplicationSourceDescriptor descriptor_;
    payload::trace_storage::SerializedTraceStore serialized_;
    DenseMultiplicationAliasPlan aliases_;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_DENSE_MULTIPLICATION_SOURCE_STORE_HPP
