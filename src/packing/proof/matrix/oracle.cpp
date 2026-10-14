/// @file oracle.cpp
/// @brief Reference/prover-only matrix evaluator for proof-of-packing R1CS.

#include "laminate/packing/proof/matrix/oracle.hpp"

#include "laminate/crypto/poseidon.hpp"
#include "laminate/packing/alignment/affine_weight.hpp"
#include "laminate/packing/proof/detail/poseidon_template.hpp"
#include "laminate/packing/outer_relation/tensor.hpp"
#include "laminate/spartan/factored.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::packing {
namespace {

using MatrixValues = std::array<Fq2, 3>;

std::size_t as_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(label);
    }
    return static_cast<std::size_t>(value);
}

std::uint64_t checked_add_u64(std::uint64_t left, std::uint64_t right,
                              const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(label);
    }
    return left + right;
}

std::uint64_t checked_multiply_u64(std::uint64_t left,
                                   std::uint64_t right,
                                   const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(label);
    }
    return left * right;
}

std::size_t log2_exact(std::size_t value, const char *label) {
    if (value == 0 || !std::has_single_bit(value)) {
        throw std::invalid_argument(label);
    }
    return std::bit_width(value) - 1U;
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

Fq2 equality_weight(std::size_t index,
                    std::span<const Fq2> point) {
    if (point.size() >= std::numeric_limits<std::size_t>::digits ||
        index >= (std::size_t{1} << point.size())) {
        throw std::out_of_range("MLE equality index is out of range");
    }
    Fq2 result = Fq2::one();
    for (std::size_t bit = 0; bit < point.size(); ++bit) {
        const bool one =
            ((index >> (point.size() - 1U - bit)) & 1U) != 0;
        result *= one ? point[bit] : Fq2::one() - point[bit];
    }
    return result;
}

std::vector<Fq2> equality_table(std::span<const Fq2> point) {
    if (point.size() >= std::numeric_limits<std::size_t>::digits) {
        throw std::overflow_error("MLE equality table is too large");
    }
    std::vector<Fq2> result(std::size_t{1} << point.size(), Fq2::zero());
    result[0] = Fq2::one();
    std::size_t active = 1;
    for (const Fq2 &coordinate : point) {
        for (std::size_t index = active; index-- > 0;) {
            const Fq2 previous = result[index];
            const Fq2 high = previous * coordinate;
            result[2 * index] = previous - high;
            result[2 * index + 1] = high;
        }
        active *= 2;
    }
    return result;
}

Fq2 prefix_from_bit_weights(std::span<const Fq2> zero_weights,
                            std::span<const Fq2> one_weights,
                            std::size_t exclusive_limit) {
    if (zero_weights.size() != one_weights.size() ||
        zero_weights.size() >= std::numeric_limits<std::size_t>::digits) {
        throw std::invalid_argument("invalid MLE prefix domain");
    }
    const std::size_t domain = std::size_t{1} << zero_weights.size();
    if (exclusive_limit > domain) {
        throw std::invalid_argument("MLE prefix exceeds its domain");
    }
    std::vector<Fq2> suffix(zero_weights.size() + 1, Fq2::one());
    for (std::size_t bit = zero_weights.size(); bit-- > 0;) {
        suffix[bit] =
            (zero_weights[bit] + one_weights[bit]) * suffix[bit + 1];
    }
    if (exclusive_limit == domain) {
        return suffix.front();
    }
    Fq2 result = Fq2::zero();
    Fq2 equal_prefix = Fq2::one();
    for (std::size_t bit = 0; bit < zero_weights.size(); ++bit) {
        const bool limit_bit =
            ((exclusive_limit >>
              (zero_weights.size() - 1U - bit)) &
             1U) != 0;
        if (limit_bit) {
            result += equal_prefix * zero_weights[bit] * suffix[bit + 1];
            equal_prefix *= one_weights[bit];
        } else {
            equal_prefix *= zero_weights[bit];
        }
    }
    return result;
}

Fq2 equality_prefix_sum(std::span<const Fq2> point,
                        std::size_t exclusive_limit) {
    std::vector<Fq2> zero;
    std::vector<Fq2> one;
    zero.reserve(point.size());
    one.reserve(point.size());
    for (const Fq2 &coordinate : point) {
        zero.push_back(Fq2::one() - coordinate);
        one.push_back(coordinate);
    }
    return prefix_from_bit_weights(zero, one, exclusive_limit);
}

Fq2 equality_product_prefix_sum(
    std::span<const Fq2> left, std::span<const Fq2> right,
    std::size_t exclusive_limit) {
    if (left.size() != right.size()) {
        throw std::invalid_argument(
            "MLE product-prefix points have different dimensions");
    }
    std::vector<Fq2> zero;
    std::vector<Fq2> one;
    zero.reserve(left.size());
    one.reserve(left.size());
    for (std::size_t bit = 0; bit < left.size(); ++bit) {
        zero.push_back((Fq2::one() - left[bit]) *
                       (Fq2::one() - right[bit]));
        one.push_back(left[bit] * right[bit]);
    }
    return prefix_from_bit_weights(zero, one, exclusive_limit);
}

Fq2 equality_product_interval_sum(
    std::span<const Fq2> left, std::span<const Fq2> right,
    std::size_t begin, std::size_t end) {
    if (begin > end) {
        throw std::invalid_argument("MLE product interval is reversed");
    }
    return equality_product_prefix_sum(left, right, end) -
           equality_product_prefix_sum(left, right, begin);
}

std::vector<AffineBitWeightPair> equality_bit_weights(
    std::span<const Fq2> point) {
    std::vector<AffineBitWeightPair> result;
    result.reserve(point.size());
    for (const Fq2 &coordinate : point) {
        result.push_back(
            {Fq2::one() - coordinate, coordinate});
    }
    return result;
}

std::vector<AffineBitWeightPair> equality_product_bit_weights(
    std::span<const Fq2> left, std::span<const Fq2> right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument(
            "MLE product points have different dimensions");
    }
    std::vector<AffineBitWeightPair> result;
    result.reserve(left.size());
    for (std::size_t bit = 0; bit < left.size(); ++bit) {
        result.push_back(
            {(Fq2::one() - left[bit]) * (Fq2::one() - right[bit]),
             left[bit] * right[bit]});
    }
    return result;
}

Fq2 paired_affine_weight_sum(
    std::uint64_t count, std::uint64_t left_offset,
    std::uint64_t left_stride,
    std::span<const AffineBitWeightPair> left_weights,
    std::uint64_t right_offset, std::uint64_t right_stride,
    std::span<const AffineBitWeightPair> right_weights) {
    if (count == 0) {
        return Fq2::zero();
    }
    return affine_range_weight_sum(
        0, count,
        AffineWeightDomain{left_offset, left_stride, left_weights},
        AffineWeightDomain{right_offset, right_stride, right_weights});
}

Fq2 successor_product_prefix_sum(
    std::span<const Fq2> successor_point,
    std::span<const Fq2> predecessor_point,
    std::size_t exclusive_limit) {
    if (successor_point.size() != predecessor_point.size() ||
        successor_point.size() >=
            std::numeric_limits<std::size_t>::digits ||
        exclusive_limit >
            (std::size_t{1} << successor_point.size())) {
        throw std::invalid_argument("invalid successor MLE domain");
    }
    if (exclusive_limit <= 1) {
        return Fq2::zero();
    }

    // Let x=p-1. The two-state carry machine evaluates
    //
    //   sum_{0 <= x < limit-1} eq(r, x+1) eq(c, x)
    //
    // from least-significant to most-significant bit. A subtraction borrow
    // enforces x < limit-1 without enumerating the prefix.
    const std::size_t count = exclusive_limit - 1;
    std::array<std::array<Fq2, 2>, 2> state{};
    state[1][0] = Fq2::one(); // increment carry, comparison borrow
    for (std::size_t lsb = 0; lsb < successor_point.size(); ++lsb) {
        std::array<std::array<Fq2, 2>, 2> next{};
        const bool count_bit = ((count >> lsb) & 1U) != 0;
        const std::size_t point_bit = successor_point.size() - 1U - lsb;
        for (std::size_t carry = 0; carry < 2; ++carry) {
            for (std::size_t borrow = 0; borrow < 2; ++borrow) {
                for (std::size_t x = 0; x < 2; ++x) {
                    const std::size_t sum = x + carry;
                    const std::size_t successor = sum & 1U;
                    const std::size_t next_carry = sum >> 1U;
                    const int difference =
                        static_cast<int>(x) -
                        static_cast<int>(count_bit) -
                        static_cast<int>(borrow);
                    const std::size_t next_borrow = difference < 0 ? 1 : 0;
                    const Fq2 row_weight =
                        successor != 0
                            ? successor_point[point_bit]
                            : Fq2::one() - successor_point[point_bit];
                    const Fq2 column_weight =
                        x != 0 ? predecessor_point[point_bit]
                               : Fq2::one() -
                                     predecessor_point[point_bit];
                    next[next_carry][next_borrow] +=
                        state[carry][borrow] * row_weight * column_weight;
                }
            }
        }
        state = next;
    }
    return state[0][1];
}

std::span<const Fq2> low_bits(std::span<const Fq2> point,
                              std::size_t bits) {
    if (bits > point.size()) {
        throw std::invalid_argument("MLE low-bit split is too wide");
    }
    return point.last(bits);
}

std::span<const Fq2> high_bits(std::span<const Fq2> point,
                               std::size_t low_bit_count) {
    if (low_bit_count > point.size()) {
        throw std::invalid_argument("MLE high-bit split is too wide");
    }
    return point.first(point.size() - low_bit_count);
}

class ColumnWeights {
  public:
    explicit ColumnWeights(std::span<const Fq2> point)
        : point_(point), selector_(point.empty() ? Fq2::zero()
                                                : point.front()),
          tail_(point.empty() ? point : point.subspan(1)) {
        if (point_.empty()) {
            throw std::invalid_argument("R1CS column point is empty");
        }
    }

    const Fq2 &witness_selector() const { return selector_; }
    std::span<const Fq2> tail() const { return tail_; }

    Fq2 public_weight(std::size_t index) const {
        return (Fq2::one() - selector_) * equality_weight(index, tail_);
    }

    Fq2 witness_weight(std::size_t index) const {
        return selector_ * equality_weight(index, tail_);
    }

  private:
    std::span<const Fq2> point_;
    Fq2 selector_{};
    std::span<const Fq2> tail_;
};

/// Cached column weights for a segmented, rate-major Poseidon input family.
///
/// Inside one power-of-two segment of `P` permutations, an input witness has
/// index
///
///     input_begin + rate * P + local_permutation.
///
/// Since `input_begin` is P-aligned, its equality weight factors into one
/// small high-part weight and one P-entry low-part table. The cache retains
/// only one low weight and one segment identifier per global permutation.
class SegmentedInputWeights {
  public:
    SegmentedInputWeights(
        std::span<const ProofOfPackingPoseidonSegment> segments,
        std::span<const Fq2> column_tail,
        const Fq2 &witness_selector) {
        if (segments.empty() || segments.size() > 255) {
            throw std::invalid_argument(
                "invalid Poseidon input segment family");
        }
        const std::size_t permutations = as_size(
            segments.back().permutation_end(),
            "Poseidon input permutation count exceeds size_t");
        low_weights_.resize(permutations);
        segment_ids_.resize(permutations);
        high_weights_.resize(segments.size());

        std::uint64_t expected_begin = 0;
        for (std::size_t segment_id = 0;
             segment_id < segments.size(); ++segment_id) {
            const ProofOfPackingPoseidonSegment &segment =
                segments[segment_id];
            if (segment.permutation_begin != expected_begin) {
                throw std::invalid_argument(
                    "Poseidon input segments are not contiguous");
            }
            const std::size_t count = as_size(
                segment.permutations,
                "Poseidon input segment exceeds size_t");
            const std::size_t bits = log2_exact(
                count, "Poseidon input segment is not a power of two");
            if (bits > column_tail.size() ||
                segment.input_witness_begin % segment.permutations != 0) {
                throw std::invalid_argument(
                    "Poseidon input segment is not MLE-aligned");
            }

            const std::vector<Fq2> local_weights = equality_table(
                low_bits(column_tail, bits));
            const std::size_t begin = as_size(
                segment.permutation_begin,
                "Poseidon segment begin exceeds size_t");
            for (std::size_t local = 0; local < count; ++local) {
                low_weights_[begin + local] = local_weights[local];
                segment_ids_[begin + local] =
                    static_cast<std::uint8_t>(segment_id);
            }

            const auto high_point = high_bits(column_tail, bits);
            const std::uint64_t high_base =
                segment.input_witness_begin / segment.permutations;
            for (std::size_t rate = 0; rate < kPoseidonRate; ++rate) {
                high_weights_[segment_id][rate] =
                    witness_selector * equality_weight(
                        as_size(high_base + rate,
                                "Poseidon input high index exceeds size_t"),
                        high_point);
            }
            expected_begin = segment.permutation_end();
        }
    }

    Fq2 weight(std::uint64_t permutation, std::size_t rate) const {
        if (permutation >= low_weights_.size() ||
            rate >= kPoseidonRate) {
            throw std::out_of_range(
                "Poseidon input weight is out of range");
        }
        const std::size_t index = static_cast<std::size_t>(permutation);
        return high_weights_[segment_ids_[index]][rate] *
               low_weights_[index];
    }

  private:
    std::vector<std::array<Fq2, kPoseidonRate>> high_weights_;
    std::vector<Fq2> low_weights_;
    std::vector<std::uint8_t> segment_ids_;
};

Fq2 segmented_aligned_contraction(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout, std::size_t aligned,
    const std::array<Fq2, 2> &component_weights,
    std::span<const AffineBitWeightPair> coordinate_weights,
    std::span<const AffineBitWeightPair> witness_weights,
    const Fq2 &witness_selector) {
    if (aligned >= plan.shape.aligned_ciphertexts ||
        coordinate_weights.size() !=
            log2_exact(plan.shape.ring_degree,
                       "packing ring degree is not a power of two")) {
        throw std::invalid_argument(
            "aligned contraction has inconsistent dimensions");
    }
    const std::uint64_t degree = plan.shape.ring_degree;
    const std::uint64_t permutations_per_hash =
        layout.ciphertext_permutations_per_hash;
    Fq2 result = Fq2::zero();

    for (std::size_t component = 0; component < 2; ++component) {
        const std::uint64_t input_base =
            gkr::kCiphertextCommitmentMetadataElements +
            component * degree;
        for (std::size_t rate = 0; rate < kPoseidonRate; ++rate) {
            const std::uint64_t residue = input_base % kPoseidonRate;
            const std::uint64_t first_coordinate =
                (rate + kPoseidonRate - residue) % kPoseidonRate;
            if (first_coordinate >= degree) {
                continue;
            }
            const std::uint64_t live =
                1U + (degree - 1U - first_coordinate) /
                          kPoseidonRate;
            const std::uint64_t first_block =
                (input_base + first_coordinate) / kPoseidonRate;
            const std::uint64_t global_base =
                aligned * permutations_per_hash + first_block;

            for (const ProofOfPackingPoseidonSegment &segment :
                 layout.ciphertext_segments) {
                const std::uint64_t segment_begin =
                    segment.permutation_begin;
                const std::uint64_t segment_end =
                    segment.permutation_end();
                const std::uint64_t begin =
                    segment_begin > global_base
                        ? segment_begin - global_base
                        : 0;
                const std::uint64_t end =
                    segment_end > global_base
                        ? std::min(live, segment_end - global_base)
                        : 0;
                if (begin >= end) {
                    continue;
                }
                const std::uint64_t coordinate_offset =
                    first_coordinate + kPoseidonRate * begin;
                const std::uint64_t witness_offset =
                    segment.input_witness_begin +
                    rate * segment.permutations +
                    (global_base + begin - segment_begin);
                result += component_weights[component] *
                          paired_affine_weight_sum(
                              end - begin, coordinate_offset,
                              kPoseidonRate, coordinate_weights,
                              witness_offset, 1, witness_weights);
            }
        }
    }
    return witness_selector * result;
}

void add(MatrixValues &values, spartan::Matrix matrix,
         const Fq2 &value) {
    values[static_cast<std::size_t>(matrix)] += value;
}

struct PoseidonDomainWeights {
    std::span<const Fq2> row_high;
    std::span<const Fq2> row_low;
    std::span<const Fq2> column_high;
    std::span<const Fq2> column_low;
    std::uint64_t row_high_base = 0;
    std::uint64_t auxiliary_high_base = 0;
    std::uint64_t input_high_base = 0;
    std::uint64_t permutation_begin = 0;
    std::uint64_t permutations = 0;
};

class ProofOfPackingMatrixOracle final
    : public spartan::MatrixEvaluationOracle {
  public:
    ProofOfPackingMatrixOracle(
        OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
        NativePackingOperator native_packing_operator,
        std::shared_ptr<const spartan::R1csInstance> reference_circuit)
        : plan_(std::move(plan)), layout_(std::move(layout)),
          native_packing_operator_(std::move(native_packing_operator)),
          reference_circuit_(std::move(reference_circuit)) {
        native_packing_operator_->validate(plan_);
        initialize_reference_circuit();
    }

    ProofOfPackingMatrixOracle(
        OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
        std::shared_ptr<const spartan::R1csInstance> reference_circuit)
        : plan_(std::move(plan)), layout_(std::move(layout)),
          reference_circuit_(std::move(reference_circuit)) {
        initialize_reference_circuit();
    }

    ProofOfPackingMatrixOracle(
        OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
        Digest circuit_digest, std::size_t row_variables,
        std::size_t column_variables)
        : plan_(std::move(plan)), layout_(std::move(layout)),
          row_variables_(row_variables), column_variables_(column_variables),
          circuit_digest_(circuit_digest) {
        const std::uint64_t expected_logical_inputs =
            plan_.shape.aligned_ciphertexts * kPoseidonDigestElements +
            plan_.variables.public_inputs.total;
        if (layout_.logical_inputs != expected_logical_inputs ||
            layout_.rows.total == 0 || layout_.witness.total == 0 ||
            row_variables_ == 0 || column_variables_ == 0) {
            throw std::invalid_argument(
                "compact packing matrix evaluator has inconsistent dimensions");
        }
        initialize_oracle_digest();
    }

    const Digest &circuit_digest() const override { return circuit_digest_; }
    const Digest &oracle_digest() const override { return oracle_digest_; }
    std::size_t row_variables() const override { return row_variables_; }
    std::size_t column_variables() const override {
        return column_variables_;
    }

    std::array<Fq2, 3> evaluate_matrices(
        std::span<const Fq2> row_point,
        std::span<const Fq2> column_point) const override {
        if (!native_packing_operator_.has_value()) {
            throw std::logic_error(
                "compact packing evaluator cannot evaluate fixed packing A");
        }
        MatrixValues result = evaluate_regular_matrices(
            row_point, column_point);
        const ColumnWeights columns(column_point);
        const SegmentedInputWeights aligned_weights(
            layout_.ciphertext_segments, columns.tail(),
            columns.witness_selector());
        evaluate_fixed_packing_a(row_point, aligned_weights, result);
        return result;
    }

    std::array<Fq2, 3> evaluate_regular_matrices(
        std::span<const Fq2> row_point,
        std::span<const Fq2> column_point) const {
        if (row_point.size() != row_variables_ ||
            column_point.size() != column_variables_) {
            throw std::invalid_argument(
                "packing matrix oracle point has wrong dimensions");
        }
        const ColumnWeights columns(column_point);

        // Step 1: evaluate the setup-selected ciphertext-commitment tensor.
        MatrixValues result =
            plan_.shape.ciphertext_commitment_policy.relation ==
                    gkr::CiphertextCommitmentRelation::PoseidonV2
                ? evaluate_ciphertext_poseidon(row_point, columns)
                : evaluate_ciphertext_simple_hash(row_point, columns);

        // Step 2: add the five outer-relation matrix families.
        const MatrixValues outer = evaluate_outer(row_point, columns);
        for (std::size_t matrix = 0; matrix < result.size(); ++matrix) {
            result[matrix] += outer[matrix];
        }
        return result;
    }

    std::vector<Fq> multiply(
        spartan::Matrix matrix,
        std::span<const Fq> padded_assignment) const override {
        if (reference_circuit_ == nullptr) {
            throw std::logic_error(
                "compact packing evaluator has no prover matrix engine");
        }
        return reference_circuit_->multiply(matrix, padded_assignment);
    }

    std::vector<Fq2> batched_wiring_table(
        std::span<const Fq2> row_point,
        const Fq2 &gamma) const override {
        if (reference_circuit_ == nullptr) {
            throw std::logic_error(
                "compact packing evaluator has no prover wiring engine");
        }
        return reference_circuit_->batched_wiring_table(row_point, gamma);
    }

  private:
    void initialize_reference_circuit() {
        if (reference_circuit_ == nullptr ||
            reference_circuit_->shape().constraints != layout_.rows.total ||
            reference_circuit_->shape().public_inputs !=
                layout_.logical_inputs ||
            reference_circuit_->shape().witness_variables !=
                layout_.witness.total) {
            throw std::invalid_argument(
                "packing matrix oracle has inconsistent R1CS dimensions");
        }
        circuit_digest_ = reference_circuit_->digest();
        row_variables_ = reference_circuit_->row_variables();
        column_variables_ = reference_circuit_->column_variables();
        initialize_oracle_digest();
    }

    void initialize_oracle_digest() {
        std::vector<std::uint8_t> encoding;
        constexpr std::string_view domain =
            "LaminateImpl/PackingMatrixOracle/v2";
        encoding.insert(encoding.end(), domain.begin(), domain.end());
        encoding.insert(encoding.end(), circuit_digest_.begin(),
                        circuit_digest_.end());
        append_u64(encoding, layout_.rows.total);
        append_u64(encoding, layout_.witness.total);
        append_u64(encoding, layout_.ciphertext_segments.size());
        append_u64(encoding, layout_.logical_inputs);
        oracle_digest_ = sha256(encoding);
    }

    PoseidonDomainWeights poseidon_weights(
        const ProofOfPackingPoseidonSegment &segment,
        std::span<const Fq2> row_point,
        const ColumnWeights &columns) const {
        const std::size_t permutation_bits = log2_exact(
            as_size(segment.permutations,
                    "Poseidon segment exceeds size_t"),
            "Poseidon segment is not a power of two");
        return PoseidonDomainWeights{
            .row_high = high_bits(row_point, permutation_bits),
            .row_low = low_bits(row_point, permutation_bits),
            .column_high = high_bits(columns.tail(), permutation_bits),
            .column_low = low_bits(columns.tail(), permutation_bits),
            .row_high_base =
                segment.row_begin / segment.permutations,
            .auxiliary_high_base =
                segment.auxiliary_witness_begin / segment.permutations,
            .input_high_base =
                segment.input_witness_begin / segment.permutations,
            .permutation_begin = segment.permutation_begin,
            .permutations = segment.permutations,
        };
    }

    std::array<Fq, kPoseidonWidth> initial_state(
        PoseidonDomain domain, std::uint64_t input_count) const {
        std::array<Fq, kPoseidonWidth> result{};
        result[kPoseidonRate] = Fq(static_cast<std::uint64_t>(domain));
        result[kPoseidonRate + 1] = Fq(input_count);
        result[kPoseidonRate + 2] = Fq(input_count);
        result[kPoseidonRate + 3] = Fq(kPoseidonEncodingVersionDelimiter);
        return result;
    }

    MatrixValues evaluate_poseidon_template(
        const PoseidonDomainWeights &weights,
        const ColumnWeights &columns,
        std::span<const Fq2> data_relations,
        std::span<const Fq2> absorbed_constants,
        const std::array<Fq2, kPoseidonWidth> &prior_columns) const {
        const auto &local =
            detail::proof_of_packing_poseidon_permutation_template();
        const std::size_t live = as_size(
            weights.permutations,
            "live Poseidon permutation count exceeds size_t");
        const Fq2 current_relation = equality_product_prefix_sum(
            weights.row_low, weights.column_low, live);
        const Fq2 row_prefix = equality_prefix_sum(weights.row_low, live);
        const Fq2 constant_column = columns.public_weight(0);
        MatrixValues result{};

        const auto evaluate_entries = [&](spartan::Matrix matrix,
                                          const auto &entries) {
            for (const spartan::R1csEntry &entry : entries) {
                const Fq2 row_high = equality_weight(
                    as_size(weights.row_high_base + entry.row,
                            "Poseidon row-high index exceeds size_t"),
                    weights.row_high);
                Fq2 column_relation = Fq2::zero();
                if (entry.column == 0) {
                    column_relation = constant_column * row_prefix;
                } else if (entry.column <= kPoseidonWidth) {
                    const std::size_t word =
                        as_size(entry.column - 1,
                                "Poseidon prior-state word exceeds size_t");
                    column_relation = prior_columns[word];
                } else if (entry.column <=
                           kPoseidonWidth + kPoseidonRate) {
                    const std::size_t rate = as_size(
                        entry.column - 1 - kPoseidonWidth,
                        "Poseidon absorbed rate exceeds size_t");
                    const Fq2 input_high = equality_weight(
                        as_size(weights.input_high_base + rate,
                                "Poseidon input-high index exceeds size_t"),
                        weights.column_high);
                    column_relation =
                        columns.witness_selector() * input_high *
                            data_relations[rate] +
                        constant_column * absorbed_constants[rate];
                } else {
                    const std::uint64_t auxiliary =
                        entry.column - 1 - kPoseidonWidth - kPoseidonRate;
                    const Fq2 auxiliary_high = equality_weight(
                        as_size(weights.auxiliary_high_base + auxiliary,
                                "Poseidon auxiliary-high index exceeds size_t"),
                        weights.column_high);
                    column_relation =
                        columns.witness_selector() * auxiliary_high *
                        current_relation;
                }
                add(result, matrix,
                    row_high * column_relation * entry.value);
            }
        };
        evaluate_entries(spartan::Matrix::A, local.a);
        evaluate_entries(spartan::Matrix::B, local.b);
        evaluate_entries(spartan::Matrix::C, local.c);
        return result;
    }

    MatrixValues evaluate_ciphertext_poseidon(
        std::span<const Fq2> row_point,
        const ColumnWeights &columns) const {
        const std::size_t ciphertexts = plan_.shape.aligned_ciphertexts;
        const std::size_t permutations_per_hash = as_size(
            layout_.ciphertext_permutations_per_hash,
            "ciphertext permutations per hash exceed size_t");
        const std::size_t preimage =
            gkr::kCiphertextCommitmentMetadataElements +
            plan_.shape.ciphertext_components * plan_.shape.ring_degree;
        const std::array<Fq, 4> metadata{
            Fq(plan_.shape.ring_degree), Fq(2), Fq(1), Fq(1)};
        const std::size_t padding_block = preimage / kPoseidonRate;
        const std::size_t padding_rate = preimage % kPoseidonRate;
        const auto initial = initial_state(
            PoseidonDomain::CiphertextCommitment, preimage);
        const auto &local =
            detail::proof_of_packing_poseidon_permutation_template();
        MatrixValues result{};

        for (const ProofOfPackingPoseidonSegment &segment :
             layout_.ciphertext_segments) {
            const PoseidonDomainWeights weights =
                poseidon_weights(segment, row_point, columns);
            const std::size_t segment_begin = as_size(
                segment.permutation_begin,
                "ciphertext segment begin exceeds size_t");
            const std::size_t segment_end = as_size(
                segment.permutation_end(),
                "ciphertext segment end exceeds size_t");
            std::array<Fq2, kPoseidonRate> data{};
            std::array<Fq2, kPoseidonRate> constants{};
            Fq2 initial_sum = Fq2::zero();

            for (std::size_t ciphertext = 0; ciphertext < ciphertexts;
                 ++ciphertext) {
                const std::size_t base =
                    ciphertext * permutations_per_hash;
                if (base >= segment_begin && base < segment_end) {
                    const std::size_t local_permutation =
                        base - segment_begin;
                    initial_sum += equality_weight(
                        local_permutation, weights.row_low);
                    for (std::size_t rate = 0; rate < metadata.size();
                         ++rate) {
                        constants[rate] +=
                            equality_weight(local_permutation,
                                            weights.row_low) *
                            metadata[rate];
                    }
                }
                const std::size_t padding = base + padding_block;
                if (padding >= segment_begin && padding < segment_end) {
                    constants[padding_rate] += equality_weight(
                        padding - segment_begin, weights.row_low);
                }

                for (std::size_t rate = 0; rate < kPoseidonRate; ++rate) {
                    const std::size_t first_input =
                        gkr::kCiphertextCommitmentMetadataElements;
                    const std::size_t last_input = preimage - 1;
                    if (last_input < rate) {
                        continue;
                    }
                    const std::size_t first_block =
                        first_input <= rate
                            ? 0
                            : (first_input - rate + kPoseidonRate - 1) /
                                  kPoseidonRate;
                    const std::size_t last_block =
                        (last_input - rate) / kPoseidonRate;
                    const std::size_t begin =
                        std::max(segment_begin, base + first_block);
                    const std::size_t end =
                        std::min(segment_end, base + last_block + 1);
                    if (begin < end) {
                        data[rate] += equality_product_interval_sum(
                            weights.row_low, weights.column_low,
                            begin - segment_begin, end - segment_begin);
                    }
                }
            }

            Fq2 internal_prior = successor_product_prefix_sum(
                weights.row_low, weights.column_low,
                as_size(segment.permutations,
                        "ciphertext segment size exceeds size_t"));
            for (std::size_t ciphertext = 1; ciphertext < ciphertexts;
                 ++ciphertext) {
                const std::size_t boundary =
                    ciphertext * permutations_per_hash;
                if (boundary > segment_begin && boundary < segment_end) {
                    const std::size_t local_boundary =
                        boundary - segment_begin;
                    internal_prior -=
                        equality_weight(local_boundary, weights.row_low) *
                        equality_weight(local_boundary - 1,
                                        weights.column_low);
                }
            }
            const bool cross_segment_prior =
                segment_begin != 0 &&
                segment_begin % permutations_per_hash != 0;
            std::array<Fq2, kPoseidonWidth> prior_columns{};
            for (std::size_t word = 0; word < kPoseidonWidth; ++word) {
                const Fq2 auxiliary_high = equality_weight(
                    as_size(weights.auxiliary_high_base +
                                local.final_auxiliary[word],
                            "ciphertext auxiliary high exceeds size_t"),
                    weights.column_high);
                prior_columns[word] =
                    columns.witness_selector() * auxiliary_high *
                        internal_prior +
                    columns.public_weight(0) * initial[word] * initial_sum;
                if (cross_segment_prior) {
                    const std::uint64_t previous =
                        layout_
                            .ciphertext_poseidon_auxiliary_witness_index(
                                local.final_auxiliary[word],
                                segment.permutation_begin - 1);
                    prior_columns[word] +=
                        equality_weight(0, weights.row_low) *
                        columns.witness_weight(as_size(
                            previous,
                            "cross-segment ciphertext auxiliary exceeds size_t"));
                }
            }
            const MatrixValues segment_values = evaluate_poseidon_template(
                weights, columns, data, constants, prior_columns);
            for (std::size_t matrix = 0; matrix < result.size(); ++matrix) {
                result[matrix] += segment_values[matrix];
            }
        }

        // Final state checks: one small row and one logical digest cell per
        // `(ciphertext, digest element)`.
        for (std::size_t ciphertext = 0; ciphertext < ciphertexts;
             ++ciphertext) {
            const std::size_t last_permutation =
                (ciphertext + 1) * permutations_per_hash - 1;
            for (std::size_t element = 0;
                 element < kPoseidonDigestElements; ++element) {
                const Fq2 row = equality_weight(
                    as_size(layout_.ciphertext_output_row(ciphertext,
                                                          element),
                            "ciphertext output row exceeds size_t"),
                    row_point);
                const std::uint64_t auxiliary =
                    layout_.ciphertext_poseidon_auxiliary_witness_index(
                        local.final_auxiliary[element], last_permutation);
                add(result, spartan::Matrix::A,
                    row * columns.witness_weight(as_size(
                              auxiliary,
                              "ciphertext final auxiliary exceeds size_t")));
                add(result, spartan::Matrix::B,
                    row * columns.public_weight(0));
                add(result, spartan::Matrix::C,
                    row * logical_column_weight(
                              ciphertext * kPoseidonDigestElements + element,
                              columns));
            }
        }
        return result;
    }

    MatrixValues evaluate_ciphertext_simple_hash(
        std::span<const Fq2> row_point,
        const ColumnWeights &columns) const {
        const std::size_t q = plan_.coordinates_per_ciphertext();
        const std::size_t q_bits = log2_exact(
            q, "diagnostic ciphertext coordinate count is not a power of "
               "two");
        if (layout_.rows.ciphertext_poseidon.begin % q != 0 ||
            layout_.witness.ciphertext_poseidon_auxiliary.begin % q != 0) {
            throw std::logic_error(
                "diagnostic ciphertext-hash domains are not q-aligned");
        }
        const auto row_low_point = low_bits(row_point, q_bits);
        const std::vector<Fq2> row_high =
            equality_table(high_bits(row_point, q_bits));
        const auto column_low_point = low_bits(columns.tail(), q_bits);
        const std::vector<Fq2> column_high =
            equality_table(high_bits(columns.tail(), q_bits));
        const std::size_t row_base = as_size(
            layout_.rows.ciphertext_poseidon.begin / q,
            "diagnostic hash row base exceeds size_t");
        const std::size_t auxiliary_base = as_size(
            layout_.witness.ciphertext_poseidon_auxiliary.begin / q,
            "diagnostic hash auxiliary base exceeds size_t");
        const std::size_t ciphertexts =
            plan_.shape.aligned_ciphertexts;

        MatrixValues result{};
        Fq2 active_row_high = Fq2::zero();
        Fq2 auxiliary_high_identity = Fq2::zero();
        Fq2 coordinate_contraction = Fq2::zero();
        for (std::size_t ciphertext = 0; ciphertext < ciphertexts;
             ++ciphertext) {
            const Fq2 row = row_high[row_base + ciphertext];
            active_row_high += row;
            auxiliary_high_identity +=
                row * column_high[auxiliary_base + ciphertext];
            coordinate_contraction +=
                row * aligned_coordinate_contraction(
                          ciphertext, row_low_point, columns);
        }

        const Fq2 first_row = equality_weight(0, row_low_point);
        const Fq2 predecessor_relation = successor_product_prefix_sum(
            row_low_point, column_low_point, q);
        const Fq2 current_relation = equality_product_prefix_sum(
            row_low_point, column_low_point, q);
        const Fq alpha(gkr::kDiagnosticSimpleCtHashAlpha);
        const Fq initial =
            gkr::diagnostic_simple_ct_hash_initial_state(
                plan_.shape.ring_degree);
        add(result, spartan::Matrix::A, coordinate_contraction);
        add(result, spartan::Matrix::A,
            columns.witness_selector() * auxiliary_high_identity *
                predecessor_relation * alpha);
        add(result, spartan::Matrix::A,
            active_row_high * first_row * columns.public_weight(0) *
                (alpha * initial));
        add(result, spartan::Matrix::B,
            active_row_high * columns.public_weight(0));
        add(result, spartan::Matrix::C,
            columns.witness_selector() * auxiliary_high_identity *
                current_relation);

        // The six public digest rows are a tiny suffix; evaluating them
        // directly keeps their intentionally simple affine semantics clear.
        for (std::size_t ciphertext = 0; ciphertext < ciphertexts;
             ++ciphertext) {
            const std::uint64_t final_auxiliary =
                layout_.ciphertext_simple_hash_auxiliary_witness_index(
                    plan_, ciphertext, q - 1);
            for (std::size_t element = 0;
                 element < kPoseidonDigestElements; ++element) {
                const Fq2 row = equality_weight(
                    as_size(layout_.ciphertext_output_row(
                                ciphertext, element),
                            "diagnostic hash output row exceeds size_t"),
                    row_point);
                add(result, spartan::Matrix::A,
                    row * columns.witness_weight(as_size(
                              final_auxiliary,
                              "diagnostic hash final witness exceeds "
                              "size_t")));
                add(result, spartan::Matrix::A,
                    row * columns.public_weight(0) *
                        Fq(gkr::kDiagnosticSimpleCtHashOutputDomains[
                            element]));
                add(result, spartan::Matrix::B,
                    row * columns.public_weight(0));
                add(result, spartan::Matrix::C,
                    row * logical_column_weight(
                              ciphertext * kPoseidonDigestElements +
                                  element,
                              columns));
            }
        }
        return result;
    }

    Fq2 logical_column_weight(std::uint64_t logical_index,
                              const ColumnWeights &columns) const {
        if (logical_index >= layout_.logical_inputs) {
            throw std::out_of_range(
                "logical public-input column is out of range");
        }
        const std::size_t index = as_size(
            logical_index, "logical public-input column exceeds size_t");
        if (index == std::numeric_limits<std::size_t>::max()) {
            throw std::overflow_error(
                "logical public-input column index overflows");
        }
        return columns.public_weight(index + 1);
    }

    Fq2 aligned_column_weight(std::size_t aligned, std::size_t q,
                              const SegmentedInputWeights &weights) const {
        const std::size_t input =
            gkr::kCiphertextCommitmentMetadataElements + q;
        const std::size_t local_permutation = input / kPoseidonRate;
        const std::size_t rate = input % kPoseidonRate;
        const std::size_t permutation =
            aligned * as_size(layout_.ciphertext_permutations_per_hash,
                              "ciphertext permutation stride exceeds size_t") +
            local_permutation;
        return weights.weight(permutation, rate);
    }

    Fq2 aligned_coordinate_contraction(
        std::size_t aligned, std::span<const Fq2> row_low_point,
        const ColumnWeights &columns) const {
        const std::size_t coordinate_bits = log2_exact(
            plan_.shape.ring_degree,
            "packing ring degree is not a power of two");
        if (aligned >= plan_.shape.aligned_ciphertexts ||
            row_low_point.size() != coordinate_bits + 1U) {
            throw std::invalid_argument(
                "aligned contraction has inconsistent dimensions");
        }
        const Fq2 component_point = row_low_point.front();
        const std::vector<AffineBitWeightPair> coordinate_weights =
            equality_bit_weights(row_low_point.subspan(1));
        const std::vector<AffineBitWeightPair> witness_weights =
            equality_bit_weights(columns.tail());
        return segmented_aligned_contraction(
            plan_, layout_, aligned,
            {Fq2::one() - component_point, component_point},
            coordinate_weights, witness_weights,
            columns.witness_selector());
    }

    MatrixValues evaluate_outer(std::span<const Fq2> row_point,
                                const ColumnWeights &columns) const {
        MatrixValues result{};
        evaluate_booleanity_and_recomposition(row_point, columns, result);
        evaluate_well_formedness_products(row_point, columns, result);
        evaluate_revealed_tests(row_point, columns, result);
        evaluate_revealed_packing_regular(row_point, columns, result);
        return result;
    }

    void evaluate_booleanity_and_recomposition(
        std::span<const Fq2> row_point, const ColumnWeights &columns,
        MatrixValues &result) const {
        const Fq2 constant = columns.public_weight(0);
        const std::uint64_t bit_count =
            plan_.variables.witness.derived_challenge_bits.count;
        for (std::uint64_t bit = 0; bit < bit_count; ++bit) {
            const Fq2 row = equality_weight(
                as_size(layout_.rows.challenge_bit_booleanity.begin + bit,
                        "booleanity row exceeds size_t"),
                row_point);
            const Fq2 column = columns.witness_weight(as_size(
                layout_.witness.challenge_bits.begin + bit,
                "challenge-bit witness exceeds size_t"));
            add(result, spartan::Matrix::A, row * column);
            add(result, spartan::Matrix::B,
                row * (column - constant));
        }

        const std::uint64_t word_count =
            plan_.variables.public_inputs.packed_challenge_words.count;
        const std::size_t capacity =
            plan_.shape.public_input_capacity_bits;
        for (std::uint64_t word = 0; word < word_count; ++word) {
            const Fq2 row = equality_weight(
                as_size(
                    layout_.rows.challenge_word_recomposition.begin + word,
                    "challenge recomposition row exceeds size_t"),
                row_point);
            const std::uint64_t first = word * capacity;
            const std::uint64_t remaining = bit_count - first;
            const std::size_t live = static_cast<std::size_t>(
                std::min<std::uint64_t>(capacity, remaining));
            Fq coefficient = Fq::one();
            for (std::size_t offset = 0; offset < live; ++offset) {
                const Fq2 column = columns.witness_weight(as_size(
                    layout_.witness.challenge_bits.begin + first + offset,
                    "challenge-bit witness exceeds size_t"));
                add(result, spartan::Matrix::A,
                    row * column * coefficient);
                coefficient += coefficient;
            }
            add(result, spartan::Matrix::B, row * constant);
            const std::uint64_t logical =
                plan_.shape.aligned_ciphertexts *
                    kPoseidonDigestElements +
                plan_.variables.public_inputs.packed_challenge_words.begin +
                word;
            add(result, spartan::Matrix::C,
                row * logical_column_weight(logical, columns));
        }
    }

    void evaluate_well_formedness_products(
        std::span<const Fq2> row_point, const ColumnWeights &columns,
        MatrixValues &result) const {
        const std::size_t q = plan_.coordinates_per_ciphertext();
        const std::size_t q_bits = log2_exact(
            q, "ciphertext coordinate count is not a power of two");
        const auto row_high_point = high_bits(row_point, q_bits);
        const auto row_low_point = low_bits(row_point, q_bits);
        const std::vector<Fq2> row_high = equality_table(row_high_point);
        const auto column_high_point = high_bits(columns.tail(), q_bits);
        const auto column_low_point = low_bits(columns.tail(), q_bits);
        const std::vector<Fq2> column_high =
            equality_table(column_high_point);
        const std::size_t row_base = as_size(
            layout_.rows.well_formedness_products.begin / q,
            "product row base exceeds size_t");
        const std::size_t product_column_base = as_size(
            layout_.witness.well_formedness_products.begin / q,
            "product witness base exceeds size_t");
        const std::size_t tests = plan_.shape.repetitions;
        const std::size_t aligned = plan_.shape.aligned_ciphertexts;

        std::vector<Fq2> aligned_dots(aligned, Fq2::zero());
        for (std::size_t ciphertext = 0; ciphertext < aligned;
             ++ciphertext) {
            aligned_dots[ciphertext] = aligned_coordinate_contraction(
                ciphertext, row_low_point, columns);
        }

        for (std::size_t test = 0; test < tests; ++test) {
            for (std::size_t ciphertext = 0; ciphertext < aligned;
                 ++ciphertext) {
                const std::size_t local = test * aligned + ciphertext;
                const Fq2 row_prefix = row_high[row_base + local];
                const std::uint64_t plus =
                    plan_.challenge_bit_witness_index(
                        test, ciphertext,
                        OuterRelationPlan::ChallengeBit::Plus);
                const std::uint64_t minus =
                    plan_.challenge_bit_witness_index(
                        test, ciphertext,
                        OuterRelationPlan::ChallengeBit::Minus);
                const Fq2 plus_weight = columns.witness_weight(as_size(
                    layout_.outer_witness_index(plan_, plus),
                    "plus-bit witness exceeds size_t"));
                const Fq2 minus_weight = columns.witness_weight(as_size(
                    layout_.outer_witness_index(plan_, minus),
                    "minus-bit witness exceeds size_t"));
                add(result, spartan::Matrix::A,
                    row_prefix * (plus_weight - minus_weight));
                add(result, spartan::Matrix::B,
                    row_prefix * aligned_dots[ciphertext]);
            }
        }

        Fq2 product_identity = Fq2::zero();
        const std::size_t live_prefixes = tests * aligned;
        for (std::size_t local = 0; local < live_prefixes; ++local) {
            product_identity +=
                row_high[row_base + local] *
                column_high[product_column_base + local];
        }
        const Fq2 low_identity = equality_product_prefix_sum(
            row_low_point, column_low_point, q);
        add(result, spartan::Matrix::C,
            columns.witness_selector() * product_identity * low_identity);
    }

    void evaluate_revealed_tests(
        std::span<const Fq2> row_point, const ColumnWeights &columns,
        MatrixValues &result) const {
        const std::size_t q = plan_.coordinates_per_ciphertext();
        const std::size_t q_bits = log2_exact(
            q, "ciphertext coordinate count is not a power of two");
        const auto row_low_point = low_bits(row_point, q_bits);
        const std::vector<Fq2> row_high =
            equality_table(high_bits(row_point, q_bits));
        const auto product_low_point = low_bits(columns.tail(), q_bits);
        const std::vector<Fq2> product_high =
            equality_table(high_bits(columns.tail(), q_bits));
        const std::size_t row_base = as_size(
            layout_.rows.revealed_test_equalities.begin / q,
            "test row base exceeds size_t");
        const std::size_t product_base = as_size(
            layout_.witness.well_formedness_products.begin / q,
            "product witness base exceeds size_t");
        const std::size_t tests = plan_.shape.repetitions;
        const std::size_t aligned = plan_.shape.aligned_ciphertexts;

        const Fq2 low_identity = equality_product_prefix_sum(
            row_low_point, product_low_point, q);
        Fq2 a = Fq2::zero();
        for (std::size_t test = 0; test < tests; ++test) {
            for (std::size_t ciphertext = 0; ciphertext < aligned;
                 ++ciphertext) {
                a += row_high[row_base + test] *
                     product_high[product_base + test * aligned +
                                  ciphertext];
            }
        }
        add(result, spartan::Matrix::A,
            columns.witness_selector() * a * low_identity);

        Fq2 row_prefix = Fq2::zero();
        for (std::size_t test = 0; test < tests; ++test) {
            row_prefix += row_high[row_base + test];
        }
        add(result, spartan::Matrix::B,
            row_prefix * columns.public_weight(0));

        const std::uint64_t commitment_fields =
            plan_.shape.aligned_ciphertexts * kPoseidonDigestElements;
        const std::uint64_t logical_base =
            commitment_fields +
            plan_.variables.public_inputs.revealed_test_coordinates.begin;
        const std::vector<AffineBitWeightPair> row_low_weights =
            equality_bit_weights(row_low_point);
        const std::vector<AffineBitWeightPair> public_weights =
            equality_bit_weights(columns.tail());
        for (std::size_t test = 0; test < tests; ++test) {
            const Fq2 high = row_high[row_base + test];
            const std::uint64_t public_offset =
                logical_base + test * q + 1U;
            add(result, spartan::Matrix::C,
                high * (Fq2::one() - columns.witness_selector()) *
                    paired_affine_weight_sum(
                        q, 0, 1, row_low_weights, public_offset, 1,
                        public_weights));
        }
    }

    void evaluate_fixed_packing_a(
        std::span<const Fq2> row_point,
        const SegmentedInputWeights &aligned_weights,
        MatrixValues &result) const {
        if (!native_packing_operator_.has_value()) {
            throw std::logic_error("fixed packing A evaluator is absent");
        }
        const std::size_t q = plan_.coordinates_per_ciphertext();
        const std::size_t q_bits = log2_exact(
            q, "ciphertext coordinate count is not a power of two");
        const auto row_low_point = low_bits(row_point, q_bits);
        const std::vector<Fq2> row_high =
            equality_table(high_bits(row_point, q_bits));
        const std::vector<Fq2> row_low = equality_table(row_low_point);
        const std::size_t row_base = as_size(
            layout_.rows.revealed_packing_equalities.begin / q,
            "packing row base exceeds size_t");
        const std::size_t digits = plan_.shape.packing_digit_count;
        for (std::size_t logical = 0;
             logical < native_packing_operator_->logical_outputs; ++logical) {
            const NativePackingRow &first =
                native_packing_operator_->rows[logical * digits];
            for (std::size_t contribution_index = 0;
                 contribution_index < first.contributions.size();
                 ++contribution_index) {
                const std::size_t aligned =
                    first.contributions[contribution_index]
                        .aligned_ciphertext;
                std::vector<Fq2> digit_sums(digits, Fq2::zero());
                for (std::size_t coordinate = 0; coordinate < q;
                     ++coordinate) {
                    const Fq2 common =
                        row_low[coordinate] * aligned_column_weight(
                                                  aligned, coordinate,
                                                  aligned_weights);
                    const std::size_t ntt_coordinate =
                        coordinate % plan_.shape.ring_degree;
                    for (std::size_t digit = 0; digit < digits; ++digit) {
                        const NativePackingContribution &contribution =
                            native_packing_operator_->rows[
                                logical * digits + digit]
                                .contributions[contribution_index];
                        digit_sums[digit] +=
                            common * Fq(contribution
                                            .multiplier_ntt_coordinates
                                                [ntt_coordinate]);
                    }
                }
                for (std::size_t digit = 0; digit < digits; ++digit) {
                    add(result, spartan::Matrix::A,
                        row_high[row_base + logical * digits + digit] *
                            digit_sums[digit]);
                }
            }
        }
    }

    void evaluate_revealed_packing_regular(
        std::span<const Fq2> row_point, const ColumnWeights &columns,
        MatrixValues &result) const {
        const std::size_t q = plan_.coordinates_per_ciphertext();
        const std::size_t q_bits = log2_exact(
            q, "ciphertext coordinate count is not a power of two");
        const auto row_low_point = low_bits(row_point, q_bits);
        const std::vector<Fq2> row_high =
            equality_table(high_bits(row_point, q_bits));
        const std::size_t row_base = as_size(
            layout_.rows.revealed_packing_equalities.begin / q,
            "packing row base exceeds size_t");
        const std::size_t digits = plan_.shape.packing_digit_count;

        const std::size_t physical =
            plan_.shape.logical_packed_outputs * digits;
        Fq2 row_prefix = Fq2::zero();
        for (std::size_t output = 0; output < physical; ++output) {
            row_prefix += row_high[row_base + output];
        }
        add(result, spartan::Matrix::B,
            row_prefix * columns.public_weight(0));

        const std::uint64_t commitment_fields =
            plan_.shape.aligned_ciphertexts * kPoseidonDigestElements;
        const std::uint64_t logical_base =
            commitment_fields +
            plan_.variables.public_inputs.revealed_packing_coordinates.begin;
        const std::vector<AffineBitWeightPair> row_low_weights =
            equality_bit_weights(row_low_point);
        const std::vector<AffineBitWeightPair> public_weights =
            equality_bit_weights(columns.tail());
        for (std::size_t output = 0; output < physical; ++output) {
            const Fq2 high = row_high[row_base + output];
            const std::uint64_t public_offset =
                logical_base + output * q + 1U;
            add(result, spartan::Matrix::C,
                high * (Fq2::one() - columns.witness_selector()) *
                    paired_affine_weight_sum(
                        q, 0, 1, row_low_weights, public_offset, 1,
                        public_weights));
        }
    }

    OuterRelationPlan plan_;
    ProofOfPackingR1csLayout layout_;
    std::optional<NativePackingOperator> native_packing_operator_;
    std::shared_ptr<const spartan::R1csInstance> reference_circuit_;
    std::size_t row_variables_ = 0;
    std::size_t column_variables_ = 0;
    Digest circuit_digest_{};
    Digest oracle_digest_{};
};

class ProofOfPackingFactoredStructure final
    : public spartan::FactoredMatrixStructure {
  public:
    ProofOfPackingFactoredStructure(
        OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
        std::span<const PackingTensorMapping> mappings,
        const spartan::R1csMetadata &circuit)
        : plan_(std::move(plan)), layout_(std::move(layout)),
          regular_evaluator_(plan_, layout_, circuit.digest(),
                             circuit.row_variables(),
                             circuit.column_variables()),
          circuit_digest_(circuit.digest()),
          row_variables_(circuit.row_variables()),
          column_variables_(circuit.column_variables()) {
        if (mappings.size() != plan_.shape.logical_packed_outputs ||
            row_variables_ == 0 || column_variables_ == 0) {
            throw std::invalid_argument(
                "packing factored structure has inconsistent dimensions");
        }
        descriptors_.reserve(mappings.size());
        owners_.reserve(mappings.size());
        std::vector<std::size_t> owner_counts;
        owner_counts.reserve(mappings.size());
        for (const PackingTensorMapping &mapping : mappings) {
            owner_counts.push_back(mapping.global_owners.size());
        }
        const PackingTensorGeometry expected_geometry =
            packing_tensor_geometry(
                owner_counts, plan_.shape.ring_degree,
                plan_.shape.packing_digit_count, kSerializedFqBytes);
        std::vector<bool> seen_owner(plan_.shape.aligned_ciphertexts, false);
        for (std::size_t output = 0; output < mappings.size(); ++output) {
            const PackingTensorMapping &mapping =
                mappings[output];
            const PackingTensorDescriptor &descriptor = mapping.descriptor;
            if (descriptor != expected_geometry.outputs[output]) {
                throw std::invalid_argument(
                    "packing factored tensor descriptor is inconsistent");
            }
            for (const std::size_t owner : mapping.global_owners) {
                if (owner >= seen_owner.size() || seen_owner[owner]) {
                    throw std::invalid_argument(
                        "packing factored tensor owner map is invalid");
                }
                seen_owner[owner] = true;
            }
            descriptors_.push_back(descriptor);
            owners_.push_back(mapping.global_owners);
        }
        if (!std::all_of(seen_owner.begin(), seen_owner.end(),
                         [](bool seen) { return seen; })) {
            throw std::invalid_argument(
                "packing factored tensor owner map is incomplete");
        }

        std::vector<std::uint8_t> encoding;
        constexpr std::string_view domain =
            "LaminateImpl/PackingFactoredStructure/v1";
        encoding.insert(encoding.end(), domain.begin(), domain.end());
        encoding.insert(encoding.end(), circuit_digest_.begin(),
                        circuit_digest_.end());
        append_u64(encoding, row_variables_);
        append_u64(encoding, column_variables_);
        append_u64(encoding, plan_.shape.ring_degree);
        append_u64(encoding, plan_.shape.aligned_ciphertexts);
        append_u64(encoding, plan_.shape.logical_packed_outputs);
        append_u64(encoding, plan_.shape.packing_digit_count);
        append_u64(
            encoding,
            plan_.shape.ciphertext_commitment_policy.wire_code());
        append_u64(encoding, kPoseidonRate);
        append_u64(encoding,
                   gkr::kCiphertextCommitmentMetadataElements);
        append_u64(encoding,
                   layout_.rows.revealed_packing_equalities.begin);
        append_u64(encoding,
                   layout_.witness.aligned_coordinates.begin);
        append_u64(encoding,
                   layout_.ciphertext_permutations_per_hash);
        append_u64(encoding, layout_.ciphertext_segments.size());
        for (const ProofOfPackingPoseidonSegment &segment :
             layout_.ciphertext_segments) {
            append_u64(encoding, segment.permutation_begin);
            append_u64(encoding, segment.permutations);
            append_u64(encoding, segment.input_witness_begin);
        }
        append_u64(encoding, descriptors_.size());
        for (std::size_t output = 0; output < descriptors_.size(); ++output) {
            const PackingTensorDescriptor &descriptor = descriptors_[output];
            append_u64(encoding, descriptor.logical_output);
            append_u64(encoding, descriptor.live_owner_count);
            append_u64(encoding, descriptor.padded_owner_count);
            append_u64(encoding, descriptor.ring_degree);
            append_u64(encoding, descriptor.digit_count);
            append_u64(encoding, owners_[output].size());
            for (const std::size_t owner : owners_[output]) {
                append_u64(encoding, owner);
            }
        }
        structure_digest_ = sha256(encoding);
    }

    Digest circuit_digest() const override { return circuit_digest_; }
    Digest structure_digest() const override { return structure_digest_; }
    std::uint64_t row_variables() const override {
        return row_variables_;
    }
    std::uint64_t column_variables() const override {
        return column_variables_;
    }

    std::size_t tensor_count() const override {
        return descriptors_.size();
    }

    std::vector<PackingTensorMapping>
    tensor_mappings() const {
        std::vector<PackingTensorMapping> result;
        result.reserve(descriptors_.size());
        for (std::size_t index = 0; index < descriptors_.size(); ++index) {
            result.push_back(PackingTensorMapping{
                .descriptor = descriptors_[index],
                .global_owners = owners_[index],
            });
        }
        return result;
    }

    spartan::FactoredTensorShape tensor_shape(
        std::size_t tensor_index) const override {
        const PackingTensorDescriptor &descriptor =
            descriptors_.at(tensor_index);
        const std::uint64_t evaluations =
            descriptor.padded_owner_count * descriptor.ring_degree;
        return spartan::FactoredTensorShape{
            .evaluation_count = evaluations,
            .column_count = descriptor.digit_count,
        };
    }

    spartan::FactoredTensorOperandWorkingSet
    tensor_operand_working_set(
        std::size_t tensor_index) const override {
        const PackingTensorDescriptor &descriptor =
            descriptors_.at(tensor_index);
        if (layout_.ciphertext_segments.empty()) {
            throw std::logic_error(
                "packing operand has no ciphertext segments");
        }
        const std::uint64_t result_fields = checked_multiply_u64(
            descriptor.padded_owner_count, descriptor.ring_degree,
            "packing operand result fields overflow");
        const std::uint64_t coordinate_table_fields =
            descriptor.ring_degree;
        const std::uint64_t permutation_fields =
            layout_.ciphertext_segments.back().permutation_end();
        const std::uint64_t high_cache_fields = checked_multiply_u64(
            layout_.ciphertext_segments.size(), kPoseidonRate,
            "packing operand high cache overflows");
        std::uint64_t largest_local_table_fields = 0;
        for (const ProofOfPackingPoseidonSegment &segment :
             layout_.ciphertext_segments) {
            largest_local_table_fields = std::max(
                largest_local_table_fields, segment.permutations);
        }
        const std::uint64_t retained_cache_fields = checked_add_u64(
            checked_add_u64(coordinate_table_fields, permutation_fields,
                            "packing operand caches overflow"),
            high_cache_fields, "packing operand caches overflow");
        const std::uint64_t cache_construction_peak = checked_add_u64(
            retained_cache_fields, largest_local_table_fields,
            "packing operand local equality table overflows");
        const std::uint64_t result_construction_peak = checked_add_u64(
            retained_cache_fields, result_fields,
            "packing operand result peak overflows");

        const std::uint64_t coordinate_bits = log2_exact(
            descriptor.ring_degree,
            "packing ring degree is not a power of two");
        const std::uint64_t witness_bits = column_variables_ - 1U;
        const std::uint64_t compact_pair_fields = checked_multiply_u64(
            checked_add_u64(coordinate_bits, witness_bits,
                            "packing compact operand bits overflow"),
            2U, "packing compact operand caches overflow");
        return {
            .materialization_peak_field_bytes = checked_multiply_u64(
                std::max(cache_construction_peak,
                         result_construction_peak),
                sizeof(Fq2),
                "packing operand materialization bytes overflow"),
            .compact_evaluation_peak_field_bytes = checked_multiply_u64(
                compact_pair_fields, sizeof(Fq2),
                "packing compact operand bytes overflow"),
        };
    }

    MatrixValues regular_matrix_evaluations(
        std::span<const Fq2> row_point,
        std::span<const Fq2> column_point) const override {
        return regular_evaluator_.evaluate_regular_matrices(
            row_point, column_point);
    }

    std::vector<Fq2> tensor_column_weights(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point,
        const Fq2 &gamma) const override {
        (void)gamma; // The committed residual belongs only to matrix A.
        validate_points(row_point, column_point);
        const std::size_t q = plan_.coordinates_per_ciphertext();
        const std::size_t q_bits = log2_exact(
            q, "ciphertext coordinate count is not a power of two");
        const auto row_high = high_bits(row_point, q_bits);
        const std::size_t row_base = as_size(
            layout_.rows.revealed_packing_equalities.begin / q,
            "packing row base exceeds size_t");
        const PackingTensorDescriptor &descriptor =
            descriptors_.at(tensor_index);
        std::vector<Fq2> result(descriptor.digit_count);
        for (std::size_t digit = 0; digit < descriptor.digit_count;
             ++digit) {
            result[digit] = equality_weight(
                row_base + descriptor.logical_output *
                               descriptor.digit_count +
                    digit,
                row_high);
        }
        return result;
    }

    std::vector<Fq2> materialize_tensor_operand(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point,
        const Fq2 &gamma) const override {
        (void)gamma;
        validate_points(row_point, column_point);
        const PackingTensorDescriptor &descriptor =
            descriptors_.at(tensor_index);
        const std::size_t q_bits = log2_exact(
            plan_.coordinates_per_ciphertext(),
            "ciphertext coordinate count is not a power of two");
        const auto row_low = low_bits(row_point, q_bits);
        const Fq2 component_point = row_low.front();
        const std::vector<Fq2> coordinate_weights =
            equality_table(row_low.subspan(1));
        const ColumnWeights columns(column_point);
        const SegmentedInputWeights aligned_weights(
            layout_.ciphertext_segments, columns.tail(),
            columns.witness_selector());
        const std::size_t length =
            descriptor.padded_owner_count * descriptor.ring_degree;
        std::vector<Fq2> result(length, Fq2::zero());
        for (std::size_t local_owner = 0;
             local_owner < owners_[tensor_index].size(); ++local_owner) {
            const std::size_t owner = owners_[tensor_index][local_owner];
            for (std::size_t coordinate = 0;
                 coordinate < descriptor.ring_degree; ++coordinate) {
                const Fq2 column_relation =
                    (Fq2::one() - component_point) *
                        aligned_input_weight(
                            owner, coordinate, aligned_weights) +
                    component_point * aligned_input_weight(
                                          owner,
                                          descriptor.ring_degree +
                                              coordinate,
                                          aligned_weights);
                result[local_owner * descriptor.ring_degree + coordinate] =
                    coordinate_weights[coordinate] * column_relation;
            }
        }
        return result;
    }

    Fq2 evaluate_tensor_operand(
        std::size_t tensor_index, std::span<const Fq2> row_point,
        std::span<const Fq2> column_point, const Fq2 &gamma,
        std::span<const Fq2> tensor_point) const override {
        (void)gamma;
        validate_points(row_point, column_point);
        const PackingTensorDescriptor &descriptor =
            descriptors_.at(tensor_index);
        const std::size_t coordinate_bits = log2_exact(
            descriptor.ring_degree,
            "packing ring degree is not a power of two");
        const std::size_t owner_bits = log2_exact(
            descriptor.padded_owner_count,
            "packing owner domain is not a power of two");
        if (tensor_point.size() != owner_bits + coordinate_bits) {
            throw std::invalid_argument(
                "packing tensor point has the wrong dimension");
        }
        const std::size_t q_bits = coordinate_bits + 1U;
        const auto row_low = low_bits(row_point, q_bits);
        const Fq2 component_point = row_low.front();
        const auto owner_point = tensor_point.first(owner_bits);
        const auto coordinate_point = tensor_point.last(coordinate_bits);
        const std::vector<AffineBitWeightPair> coordinate_weights =
            equality_product_bit_weights(
                row_low.subspan(1), coordinate_point);
        const ColumnWeights columns(column_point);
        const std::vector<AffineBitWeightPair> witness_weights =
            equality_bit_weights(columns.tail());
        Fq2 result = Fq2::zero();
        for (std::size_t local_owner = 0;
             local_owner < owners_[tensor_index].size(); ++local_owner) {
            result += equality_weight(local_owner, owner_point) *
                      segmented_aligned_contraction(
                          plan_, layout_,
                          owners_[tensor_index][local_owner],
                          {Fq2::one() - component_point,
                           component_point},
                          coordinate_weights, witness_weights,
                          columns.witness_selector());
        }
        return result;
    }

  private:
    void validate_points(std::span<const Fq2> row_point,
                         std::span<const Fq2> column_point) const {
        if (row_point.size() != row_variables_ ||
            column_point.size() != column_variables_) {
            throw std::invalid_argument(
                "packing factored matrix point has wrong dimensions");
        }
    }

    Fq2 aligned_input_weight(
        std::size_t aligned, std::size_t q,
        const SegmentedInputWeights &weights) const {
        const std::size_t input =
            gkr::kCiphertextCommitmentMetadataElements + q;
        const std::size_t local_permutation = input / kPoseidonRate;
        const std::size_t rate = input % kPoseidonRate;
        const std::size_t permutation =
            aligned * as_size(layout_.ciphertext_permutations_per_hash,
                              "ciphertext permutation stride exceeds size_t") +
            local_permutation;
        return weights.weight(permutation, rate);
    }

    OuterRelationPlan plan_;
    ProofOfPackingR1csLayout layout_;
    ProofOfPackingMatrixOracle regular_evaluator_;
    std::vector<PackingTensorDescriptor> descriptors_;
    std::vector<std::vector<std::size_t>> owners_;
    Digest circuit_digest_{};
    Digest structure_digest_{};
    std::size_t row_variables_ = 0;
    std::size_t column_variables_ = 0;
};

} // namespace

std::shared_ptr<const spartan::MatrixEvaluationOracle>
make_proof_of_packing_matrix_oracle(
    OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
    NativePackingOperator native_packing_operator,
    std::shared_ptr<const spartan::R1csInstance> reference_circuit) {
    return std::make_shared<const ProofOfPackingMatrixOracle>(
        std::move(plan), std::move(layout),
        std::move(native_packing_operator), std::move(reference_circuit));
}

std::shared_ptr<const spartan::MatrixEvaluationOracle>
make_proof_of_packing_factored_prover_oracle(
    OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
    std::shared_ptr<const spartan::R1csInstance> reference_circuit) {
    return std::make_shared<const ProofOfPackingMatrixOracle>(
        std::move(plan), std::move(layout), std::move(reference_circuit));
}

std::shared_ptr<const spartan::FactoredMatrixStructure>
make_proof_of_packing_factored_structure(
    OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
    std::span<const PackingTensor> tensors,
    const spartan::R1csMetadata &circuit) {
    std::vector<PackingTensorMapping> mappings;
    mappings.reserve(tensors.size());
    for (const PackingTensor &tensor : tensors) {
        mappings.push_back(PackingTensorMapping{
            .descriptor = tensor.descriptor,
            .global_owners = tensor.global_owners,
        });
    }
    return std::make_shared<const ProofOfPackingFactoredStructure>(
        std::move(plan), std::move(layout), mappings, circuit);
}

std::shared_ptr<const spartan::FactoredMatrixStructure>
make_proof_of_packing_factored_structure(
    OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
    std::span<const PackingTensorMapping> mappings,
    const spartan::R1csMetadata &circuit) {
    return std::make_shared<const ProofOfPackingFactoredStructure>(
        std::move(plan), std::move(layout), mappings, circuit);
}

std::vector<PackingTensorMapping>
proof_of_packing_factored_tensor_mappings(
    const spartan::FactoredMatrixStructure &structure) {
    const auto *packing =
        dynamic_cast<const ProofOfPackingFactoredStructure *>(&structure);
    if (packing == nullptr) {
        throw std::invalid_argument(
            "factored structure is not a proof-of-packing structure");
    }
    return packing->tensor_mappings();
}

} // namespace laminate::packing
