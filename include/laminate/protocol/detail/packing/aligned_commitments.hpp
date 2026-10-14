#ifndef LAMINATE_PROTOCOL_DETAIL_PACKING_ALIGNED_COMMITMENTS_HPP
#define LAMINATE_PROTOCOL_DETAIL_PACKING_ALIGNED_COMMITMENTS_HPP

/// @file aligned_commitments.hpp
/// @brief Online canonicalization at the encrypted-GKR transcript boundary.

#include "laminate/packing/alignment/placement.hpp"
#include "laminate/packing/evaluation/lazy_ternary.hpp"
#include "laminate/protocol/packed/setup.hpp"

#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate::protocol {

template <ProofOfPackingBackend Backend>
class TranscriptPackingExternalProverInput;

} // namespace laminate::protocol

namespace laminate::protocol::detail {

template <ProofOfPackingBackend Backend>
class AlignedCommitmentCollector;

/// Move-only, collector-certified pairing of normalized GKR sources with
/// their exact setup-selected commitments. Read-only access supports the resident
/// prover; only the one-shot external wrapper may separate the owned fields.
template <ProofOfPackingBackend Backend>
class CollectedAlignedCommitments {
  public:
    CollectedAlignedCommitments(CollectedAlignedCommitments &&) noexcept =
        default;
    CollectedAlignedCommitments &operator=(
        CollectedAlignedCommitments &&) noexcept = default;
    CollectedAlignedCommitments(
        const CollectedAlignedCommitments &) = delete;
    CollectedAlignedCommitments &operator=(
        const CollectedAlignedCommitments &) = delete;

    const packing::NormalizedAlignedTranscript<Backend> &aligned() const {
        return aligned_;
    }
    std::span<const gkr::HashCommitCT> commitments() const {
        return commitments_;
    }

  private:
    CollectedAlignedCommitments(
        packing::NormalizedAlignedTranscript<Backend> aligned,
        std::vector<gkr::HashCommitCT> commitments)
        : aligned_(std::move(aligned)),
          commitments_(std::move(commitments)) {}

    friend class AlignedCommitmentCollector<Backend>;
    template <ProofOfPackingBackend OtherBackend>
    friend class ::laminate::protocol::
        TranscriptPackingExternalProverInput;

    packing::NormalizedAlignedTranscript<Backend> aligned_;
    std::vector<gkr::HashCommitCT> commitments_;
};

/// Stateful callback used by encrypted GKR. Each round value is rotated by its
/// setup-fixed placement and committed with the setup-selected `HashCommitCT`
/// relation before the next Fiat--Shamir challenge is sampled. Encrypted
/// values are dropped to the native bottom prime and normalized. Public values
/// use their formal `(c0, 0)` coordinates and never acquire a transparent
/// ciphertext representation. Security-bearing target setups select Poseidon.
template <ProofOfPackingBackend Backend>
class AlignedCommitmentCollector {
  public:
    AlignedCommitmentCollector(
        const typename Backend::EvalContext &eval,
        const packing::PackingLayout &layout,
        gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy =
            gkr::CiphertextCommitmentPolicy::poseidon_v2())
        : eval_(eval), layout_(layout),
          ciphertext_commitment_policy_(ciphertext_commitment_policy) {
        ciphertext_commitment_policy_.validate();
        layout_.validate();
        if (layout_.placements.size() !=
            layout_.message_active_slots.size()) {
            throw std::invalid_argument(
                "aligned commitment collector requires one placement per "
                "GKR message");
        }
        aligned_.reserve(layout_.placements.size());
        public_coordinates_.reserve(layout_.placements.size());
        public_sources_.reserve(layout_.placements.size());
        commitments_.reserve(layout_.placements.size());
    }

    gkr::HashCommitCT commit(
        const fhe::FheValue<Backend> &round_value) {
        if (next_ >= layout_.placements.size()) {
            throw std::invalid_argument(
                "encrypted GKR emitted more rounds than setup permits");
        }
        const packing::PackingPlacement &placement =
            layout_.placements[next_];
        if (placement.message_index != next_) {
            throw std::logic_error(
                "packing setup is not in canonical GKR message order");
        }
        fhe::FheValue<Backend> aligned = fhe::value_rotate<Backend>(
            eval_, round_value, placement.rotation_steps);
        std::vector<std::uint64_t> owned_public_coordinates;
        gkr::HashCommitCT commitment;
        if (aligned.is_public_zero()) {
            if (!public_zero_commitment_) {
                public_zero_commitment_ =
                    gkr::hash_commit_normalized_zero_ciphertext_coordinates(
                        layout_.slot_count,
                        ciphertext_commitment_policy_);
            }
            commitment = *public_zero_commitment_;
        } else {
            std::span<const std::uint64_t> coordinates;
            if (aligned.is_public()) {
                owned_public_coordinates =
                    packing::normalized_public_value_coordinates<Backend>(
                        eval_, aligned.plaintext());
                coordinates = owned_public_coordinates;
            } else {
                Backend::mod_switch_to_lowest(eval_, aligned.ciphertext());
                Backend::normalize_for_coefficient_commitment(
                    eval_, aligned.ciphertext());
                coordinates =
                    Backend::coefficient_commitment_ntt_coordinate_view(
                        aligned.ciphertext());
            }
            commitment =
                gkr::hash_commit_normalized_ciphertext_coordinates(
                    layout_.slot_count, coordinates,
                    ciphertext_commitment_policy_);
        }
        aligned_.push_back(std::move(aligned));
        // The composed protocol already committed the formal `(0, 0)`
        // coordinates above. Keep that selected-path source allocation-free;
        // the borrowed outer assignment supplies zeros on demand.
        public_coordinates_.push_back(
            aligned_.back().is_public_zero()
                ? std::vector<std::uint64_t>{}
                : std::move(owned_public_coordinates));
        public_sources_.push_back(aligned_.back().is_public());
        commitments_.push_back(commitment);
        ++next_;
        return commitment;
    }

    CollectedAlignedCommitments<Backend> finish() && {
        if (next_ != layout_.placements.size()) {
            throw std::invalid_argument(
                "encrypted GKR emitted fewer rounds than setup permits");
        }
        return CollectedAlignedCommitments<Backend>(
            packing::NormalizedAlignedTranscript<Backend>{
                .layout = std::move(layout_),
                .values = std::move(aligned_),
                .public_coordinates = std::move(public_coordinates_),
                .public_sources = std::move(public_sources_),
                .ciphertext_list_digest = std::nullopt,
            },
            std::move(commitments_));
    }

  private:
    const typename Backend::EvalContext &eval_;
    packing::PackingLayout layout_;
    gkr::CiphertextCommitmentPolicy ciphertext_commitment_policy_;
    std::vector<fhe::FheValue<Backend>> aligned_;
    std::vector<std::vector<std::uint64_t>> public_coordinates_;
    std::vector<bool> public_sources_;
    std::vector<gkr::HashCommitCT> commitments_;
    std::optional<gkr::HashCommitCT> public_zero_commitment_;
    std::size_t next_ = 0;
};

} // namespace laminate::protocol::detail

#endif // LAMINATE_PROTOCOL_DETAIL_PACKING_ALIGNED_COMMITMENTS_HPP
