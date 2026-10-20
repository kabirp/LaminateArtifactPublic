#include "laminate/basefold/proof_io.hpp"

#include "laminate/basefold/common.hpp"

#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>

namespace laminate::basefold {
namespace {

using Bytes = std::vector<std::uint8_t>;

void append_u64(Bytes &output, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("BaseFold proof size exceeds u64");
    }
    const auto word = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (word >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

void append_label(Bytes &output, std::string_view label) {
    append_u64(output, label.size());
    output.insert(output.end(), label.begin(), label.end());
}

void append_digest(Bytes &output, const Digest &digest) {
    output.insert(output.end(), digest.begin(), digest.end());
}

void append_path(Bytes &output, std::span<const Digest> path) {
    append_u64(output, path.size());
    for (const Digest &digest : path) {
        append_digest(output, digest);
    }
}

void append_fp_values(Bytes &output, std::span<const Fp> values) {
    append_u64(output, values.size());
    const Bytes encoded = serialize_values(values);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void append_fpk_values(Bytes &output, std::span<const Fpk> values) {
    append_u64(output, values.size());
    const Bytes encoded = serialize_values(values);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

void append_sumcheck(Bytes &output, const SumcheckProof &proof) {
    append_u64(output, proof.rounds.size());
    for (const std::array<Fpk, 3> &round : proof.rounds) {
        const Bytes encoded = serialize_values(round);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
    append_fpk_values(output, proof.operand_evaluations);
}

void append_folding(Bytes &output, const FoldingProof &proof) {
    append_u64(output, proof.roots.size());
    for (const Digest &root : proof.roots) {
        append_digest(output, root);
    }
    append_fpk_values(output, proof.final_codeword);
}

void append_fold_opening(Bytes &output, const FoldOpening &opening) {
    const std::array<Fpk, 2> values{opening.lo, opening.hi};
    const Bytes encoded = serialize_values(values);
    output.insert(output.end(), encoded.begin(), encoded.end());
    append_path(output, opening.path_lo);
    append_path(output, opening.path_hi);
}

void append_query(Bytes &output, const QueryOpening &opening) {
    append_u64(output, opening.index);
    append_fp_values(output, opening.base_lo);
    append_fp_values(output, opening.base_hi);
    append_path(output, opening.base_path_lo);
    append_path(output, opening.base_path_hi);
    append_u64(output, opening.folds.size());
    for (const FoldOpening &fold : opening.folds) {
        append_fold_opening(output, fold);
    }
}

} // namespace

std::vector<std::uint8_t> encode_canonical(const Proof &proof) {
    Bytes output;
    append_label(output, "LaminateImpl/BaseFoldProof/v1");
    append_sumcheck(output, proof.sumcheck);
    append_folding(output, proof.folding);
    append_u64(output, proof.queries.openings.size());
    for (const QueryOpening &opening : proof.queries.openings) {
        append_query(output, opening);
    }
    return output;
}

} // namespace laminate::basefold
