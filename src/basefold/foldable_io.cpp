#include "laminate/basefold/foldable.hpp"
#include "laminate/basefold/common.hpp"
#include "laminate/field/serialization.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace laminate::basefold::foldable {
namespace {
void integer(std::vector<std::uint8_t> &out, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}
void field(std::vector<std::uint8_t> &out, const Fpk &value) {
    const auto bytes = serialize(value);
    out.insert(out.end(), bytes.begin(), bytes.end());
}
void fields(std::vector<std::uint8_t> &out, std::span<const Fpk> values) {
    integer(out, values.size());
    for (const auto &v : values)
        field(out, v);
}
void digests(std::vector<std::uint8_t> &out, std::span<const Digest> values) {
    integer(out, values.size());
    for (const auto &v : values)
        out.insert(out.end(), v.begin(), v.end());
}
void opening(std::vector<std::uint8_t> &out, const MultiOpening &proof) {
    fields(out, proof.values);
    digests(out, proof.frontier);
}
// Maximum canonical frontier size for <=q distinct selected leaves.
std::size_t frontier_bound(std::size_t leaves, std::size_t q) {
    if (leaves == 1)
        return 0;
    const auto selected = std::min(q, leaves / 2);
    auto occupied = selected;
    std::size_t result = 0;
    for (auto nodes = leaves; nodes > 1;) {
        nodes /= 2;
        const auto parents = std::min(selected, nodes);
        result += 2 * parents - occupied;
        occupied = parents;
    }
    return result;
}
std::uint64_t opening_bound(std::size_t n, std::size_t width,
                            std::size_t queries) {
    const auto leaves = n / 2;
    return 16 + std::min(queries, leaves) * 2 * width * kSerializedFpkBytes +
           frontier_bound(leaves, queries) * Digest{}.size();
}
class Reader {
  public:
    explicit Reader(std::span<const std::uint8_t> input) : bytes(input) {}
    std::span<const std::uint8_t> take(std::size_t n) {
        if (n > bytes.size())
            throw std::invalid_argument("foldable proof truncated");
        auto result = bytes.first(n);
        bytes = bytes.subspan(n);
        return result;
    }
    std::size_t count(std::size_t maximum) {
        const auto b = take(8);
        std::uint64_t n = 0;
        for (std::size_t i = 0; i < 8; ++i)
            n |= static_cast<std::uint64_t>(b[i]) << (8 * i);
        if (n > maximum)
            throw std::invalid_argument("foldable proof length exceeds shape");
        return static_cast<std::size_t>(n);
    }
    void exact(std::size_t n) {
        if (count(n) != n)
            throw std::invalid_argument("foldable proof shape mismatch");
    }
    Fpk field() { return deserialize_fpk(take(kSerializedFpkBytes)); }
    std::vector<Fpk> fields(std::size_t maximum) {
        const auto n = count(maximum);
        if (n > bytes.size() / kSerializedFpkBytes)
            throw std::invalid_argument("foldable proof field count truncated");
        std::vector<Fpk> out;
        out.reserve(n);
        for (std::size_t i = 0; i < n; ++i)
            out.push_back(field());
        return out;
    }
    std::vector<Digest> digests(std::size_t maximum) {
        const auto n = count(maximum);
        if (n > bytes.size() / Digest{}.size())
            throw std::invalid_argument(
                "foldable proof digest count truncated");
        std::vector<Digest> out(n);
        for (auto &d : out) {
            const auto b = take(d.size());
            std::copy(b.begin(), b.end(), d.begin());
        }
        return out;
    }
    MultiOpening opening(std::size_t n, std::size_t width, std::size_t q) {
        return {fields(std::min(q, n / 2) * 2 * width),
                digests(frontier_bound(n / 2, q))};
    }
    bool empty() const { return bytes.empty(); }

  private:
    std::span<const std::uint8_t> bytes;
};
}
std::uint64_t proof_size_bound(const Metadata &meta, std::size_t operands,
                               const Parameters &params) {
    if (!valid_shape(meta, params) || !operands || operands > 65536)
        throw std::invalid_argument("foldable proof size: invalid shape");
    const auto mu = log2_exact(meta.m), folds = mu ? mu - 1 : 0;
    std::uint64_t result = 8 + 8 + mu * 3 * kSerializedFpkBytes + 8 +
                           operands * kSerializedFpkBytes + 8 +
                           folds * Digest{}.size() + 8 +
                           8 * kSerializedFpkBytes + 8;
    result += opening_bound(meta.m * 8, meta.width, params.num_queries);
    for (std::size_t r = 1; r < mu; ++r)
        result += opening_bound((meta.m * 8) >> r, 1, params.num_queries);
    return result;
}
std::vector<std::uint8_t> encode_canonical(const Proof &proof) {
    std::vector<std::uint8_t> out;
    integer(out, kHierarchyVersion);
    integer(out, proof.sumcheck.rounds.size());
    for (const auto &round : proof.sumcheck.rounds)
        for (const auto &v : round)
            field(out, v);
    fields(out, proof.sumcheck.operand_evaluations);
    digests(out, proof.roots);
    fields(out, proof.final_codeword);
    opening(out, proof.initial);
    integer(out, proof.folded.size());
    for (const auto &o : proof.folded)
        opening(out, o);
    return out;
}
Proof decode_canonical(std::span<const std::uint8_t> bytes,
                       const Metadata &meta, std::size_t operands,
                       const Parameters &params) {
    if (bytes.size() > proof_size_bound(meta, operands, params))
        throw std::invalid_argument("foldable proof exceeds byte cap");
    Reader in(bytes);
    in.exact(kHierarchyVersion);
    const auto mu = log2_exact(meta.m), folds = mu ? mu - 1 : 0;
    in.exact(mu);
    Proof proof;
    proof.sumcheck.rounds.resize(mu);
    for (auto &round : proof.sumcheck.rounds)
        for (auto &v : round)
            v = in.field();
    proof.sumcheck.operand_evaluations = in.fields(operands);
    if (proof.sumcheck.operand_evaluations.size() != operands)
        throw std::invalid_argument("foldable operand count");
    proof.roots = in.digests(folds);
    if (proof.roots.size() != folds)
        throw std::invalid_argument("foldable root count");
    proof.final_codeword = in.fields(8);
    if (proof.final_codeword.size() != 8)
        throw std::invalid_argument("foldable terminal length");
    proof.initial = in.opening(meta.m * 8, meta.width, params.num_queries);
    in.exact(folds);
    for (std::size_t r = 1; r < mu; ++r)
        proof.folded.push_back(
            in.opening((meta.m * 8) >> r, 1, params.num_queries));
    if (!in.empty())
        throw std::invalid_argument("foldable proof trailing bytes");
    return proof;
}
Proof decode_canonical_bounded(std::span<const std::uint8_t> bytes,
                               std::size_t max_m, std::size_t width,
                               std::size_t max_operands,
                               const Parameters &params) {
    if (!valid_shape(Metadata{{}, max_m, width}, params) || !max_operands ||
        max_operands > 65536)
        throw std::invalid_argument("foldable bounded decoder policy");
    Reader header(bytes);
    header.exact(kHierarchyVersion);
    const auto mu = header.count(log2_exact(max_m));
    (void)header.take(mu * 3 * kSerializedFpkBytes);
    const auto operands = header.count(max_operands);
    return decode_canonical(bytes, Metadata{{}, std::size_t{1} << mu, width},
                            operands, params);
}
} // namespace laminate::basefold::foldable
