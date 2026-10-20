#ifndef LAMINATE_BASEFOLD_FOLDABLE_HPP
#define LAMINATE_BASEFOLD_FOLDABLE_HPP

#include "laminate/basefold/foldable_storage.hpp"
#include "laminate/basefold/merkle.hpp"
#include "laminate/basefold/sumcheck.hpp"
#include <array>
#include <filesystem>
#include <memory>
#include <optional>

namespace laminate::basefold::foldable {

/// One universal, non-grindable hierarchy: RS through 13 variables, then
/// full-Fpk random-oracle diagonals. All commitments share its prefixes.
inline constexpr std::uint64_t kHierarchyVersion = 1;
inline constexpr std::size_t kLogRate = 3;
inline constexpr std::size_t kRsBaseVariables = 13;
inline constexpr std::size_t kMaxVariables = 40;
inline constexpr std::size_t kDefaultQueries = 300;
inline constexpr std::size_t kLocalRbrSecurityBits = 112;
inline constexpr std::size_t kHierarchyFailureSecurityBits = 123;
struct Parameters {
    std::size_t num_queries = kDefaultQueries;
    bool operator==(const Parameters &) const = default;
};
struct Options {
    std::size_t block_elements = 8192;
    std::uint64_t max_disk_bytes = std::uint64_t{1} << 40;
    std::uint64_t min_free_bytes = std::uint64_t{1} << 20;
    /// Additional shared RAM for complete low-level diagonal tables during
    /// encoding. Reused across recursion and columns, then released. Zero
    /// disables caching. Admission must include this allowance in peak RAM.
    std::uint64_t diagonal_cache_bytes = std::uint64_t{64} << 20;
};
struct Metadata {
    Digest root{};
    std::size_t m = 0;
    std::size_t width = 0;
    std::uint64_t hierarchy_version = kHierarchyVersion;
    bool operator==(const Metadata &) const = default;
};
/// This explicit premise is required for width > 1. Random batching of
/// malicious independent columns is deliberately not supported.
enum class CommitmentPremise { ArbitrarySingleColumn, HonestCodewordColumns };
struct Commitment {
    Metadata metadata;
    std::vector<ScalarArray> columns;
    std::vector<ScalarArray> codewords;
    struct Authentication;
    std::shared_ptr<Authentication> authentication;
};
struct MultiOpening {
    /// Two values per selected pair, in [all low columns, all high columns]
    /// order. Selected pair indices are derived, never prover supplied.
    std::vector<Fpk> values;
    std::vector<Digest> frontier;
};
struct Proof {
    SumcheckProof sumcheck;
    std::vector<Digest> roots;
    std::vector<Fpk> final_codeword;
    MultiOpening initial;
    std::vector<MultiOpening> folded;
};
struct ProverOutput { Proof proof; OperandReduction reduction; };

bool valid_shape(const Metadata &, const Parameters & = {});
/// Returns 110 for an admitted policy, including slack for the separately
/// bounded hierarchy failure; zero means the policy is not certified.
std::size_t conservative_rbr_soundness_bits(const Metadata &,
    const Parameters & = {}, CommitmentPremise = CommitmentPremise::ArbitrarySingleColumn);
/// Integer-only admission certificate for every hierarchy prefix <= 40.
bool distance_certificate();
/// Conservative disk reservation, including temporary encoding/tree files.
std::uint64_t commitment_disk_bound(std::size_t m, std::size_t width);
std::uint64_t retained_commitment_disk_bound(std::size_t m, std::size_t width);
/// Additional disk beyond the retained commitment and caller-owned sources.
/// The reduced bound applies only to width one with its weight equal to one.
std::uint64_t proving_disk_bound(std::size_t m, std::size_t operands,
                                bool single_column_unit_weight = false);

/// Preprocess with 1..256 CPU workers, including the calling thread. Encoding
/// and Merkle hashing share block buffers; callbacks, recursion, and file I/O
/// remain sequential. Worker count does not affect disk or block-size limits.
/// The diagonal cache uses its Options allowance; thread stacks and per-hash
/// scratch add resident overhead. The default runs entirely on the caller.
Commitment commit(std::span<const ValueSource> columns,
                  const std::filesystem::path &directory,
                  const Options & = {}, std::size_t worker_threads = 1);
/// Publish reusable prover files in a newly created private directory. Files
/// are hard-linked on the same filesystem and copied in bounded blocks across
/// filesystems. The manifest is published last; existing destinations fail.
/// The caller must stop modifying the original commitment after publication.
void export_commitment(const Commitment &, const std::filesystem::path &);
/// Reopen immutable prover files against independently supplied metadata.
/// Checks canonical manifest, regular-file geometry, and the stored root;
/// does not re-encode columns or rehash the tree. PCS verification authenticates
/// the subsequently opened values. Use caller-owned, immutable storage.
Commitment reopen_commitment(const std::filesystem::path &, const Metadata &);

/// Also useful for tests/independent reference code. Output is a disk array;
/// the input is a Boolean evaluation table in least-significant-bit order.
ScalarArray encode(const ValueSource &, const std::filesystem::path &directory,
                   const Options & = {});

/// All metadata, weights, targets, premise, and policy are absorbed here
/// before independent operand batching. The caller may bind them earlier too.
/// The caller must discharge the returned transparent operand evaluations.
ProverOutput prove(const Commitment &, std::span<const ValueSource> operands,
                   std::span<const Fpk> column_weights,
                   std::span<const Fpk> targets, PublicCoin &,
                   const std::filesystem::path &scratch,
                   CommitmentPremise = CommitmentPremise::ArbitrarySingleColumn,
                   const Parameters & = {}, const Options & = {});
/// Transparent operand supported on one aligned dyadic block. In the block,
/// entry row + (column << point_lsb.size()) is eq(point_lsb,row) times
/// column_weights[column]. Row variables are least significant; remaining
/// variables select the block. Column weights have power-of-two size <= 256.
/// A single equality operand uses column_weights = {1}.
struct BlockOperand {
    std::size_t offset = 0;
    std::vector<Fpk> point_lsb;
    std::vector<Fpk> column_weights{Fpk::one()};
};
/// Reject malformed dimensions or overflow. Layout validation additionally
/// requires offset aligned to this size and the block contained in m.
std::size_t block_operand_size(const BlockOperand &);
/// Evaluate the full zero-extended operand at a point of log2(m) variables.
/// Checks dimensions, containment, and alignment before doing field work.
Fpk evaluate_block_operand(const BlockOperand &, std::size_t m,
                           std::span<const Fpk> point_lsb);
/// Bind all block descriptors before the ordinary PCS statement. Generate
/// only their supported intervals, write one batched operand, and evaluate
/// terminal operands analytically. Uses the canonical PCS proof format.
ProverOutput prove_blocks(const Commitment &, std::span<const BlockOperand>,
    std::span<const Fpk> column_weights, std::span<const Fpk> targets,
    PublicCoin &, const std::filesystem::path &scratch,
    CommitmentPremise = CommitmentPremise::ArbitrarySingleColumn,
    const Parameters & = {}, const Options & = {});
/// Verify the PCS and explicitly discharge every transparent block operand.
std::optional<OperandReduction> verify_blocks(
    const Metadata &, std::span<const BlockOperand>,
    std::span<const Fpk> column_weights, std::span<const Fpk> targets,
    const Proof &, PublicCoin &,
    CommitmentPremise = CommitmentPremise::ArbitrarySingleColumn,
    const Parameters & = {});

std::optional<OperandReduction> verify(
    const Metadata &, std::size_t num_operands,
    std::span<const Fpk> column_weights, std::span<const Fpk> targets,
    const Proof &, PublicCoin &,
    CommitmentPremise = CommitmentPremise::ArbitrarySingleColumn,
    const Parameters & = {});

/// Full-field, nonzero hierarchy diagonal; RS powers below the base cutoff.
Fpk diagonal(std::size_t message_variables, std::size_t index);

/// Canonical field encodings, explicit bounded vector lengths, no query
/// indices (the verifier derives them). Decoding rejects trailing bytes.
std::vector<std::uint8_t> encode_canonical(const Proof &);
Proof decode_canonical(std::span<const std::uint8_t>, const Metadata &,
                       std::size_t num_operands, const Parameters & = {});
/// For outer proof codecs whose exact witness shape is derived later.
/// Width is exact; message length and operand count are bounded here.
/// The composing verifier must still check the exact expected shape.
Proof decode_canonical_bounded(std::span<const std::uint8_t>,
    std::size_t max_m, std::size_t width, std::size_t max_operands,
    const Parameters & = {});
std::uint64_t proof_size_bound(const Metadata &, std::size_t num_operands,
                               const Parameters & = {});

} // namespace laminate::basefold::foldable
#endif
