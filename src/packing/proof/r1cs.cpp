/// @file r1cs.cpp
/// @brief Complete native-field packing-circuit synthesis.

#include "laminate/packing/proof/r1cs.hpp"

#include "laminate/crypto/poseidon.hpp"
#include "laminate/packing/proof/detail/poseidon_template.hpp"
#include "laminate/packing/proof/reference/materialized_assignment.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <filesystem>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace laminate::packing {
namespace {

constexpr std::string_view kAssignmentArtifactIdentityDomain =
    "LaminateImpl/ProofOfPackingAssignmentArtifact/v2";
constexpr std::string_view kAssignmentPublicInputsArray =
    kProofOfPackingAssignmentPublicInputs;
constexpr std::string_view kAssignmentWitnessValuesArray =
    kProofOfPackingAssignmentWitnessValues;

std::uint64_t checked_size(std::size_t value, const char *label) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds u64");
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        throw std::overflow_error(std::string(label) + " overflows u64");
    }
    return left + right;
}

std::uint64_t checked_mul(std::uint64_t left, std::uint64_t right,
                          const char *label) {
    if (left != 0 &&
        right > std::numeric_limits<std::uint64_t>::max() / left) {
        throw std::overflow_error(std::string(label) + " overflows u64");
    }
    return left * right;
}

std::uint64_t ceil_div(std::uint64_t numerator,
                       std::uint64_t denominator) {
    if (denominator == 0) {
        throw std::invalid_argument("division by zero");
    }
    return numerator / denominator +
           (numerator % denominator != 0 ? 1U : 0U);
}

std::size_t as_size(std::uint64_t value, const char *label) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error(std::string(label) + " exceeds size_t");
    }
    return static_cast<std::size_t>(value);
}

void append_u64(std::vector<std::uint8_t> &output,
                std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void append_bytes(std::vector<std::uint8_t> &output,
                  std::span<const std::uint8_t> bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_string(std::vector<std::uint8_t> &output,
                   std::string_view value) {
    append_u64(output, checked_size(value.size(), "identity string"));
    output.insert(output.end(), value.begin(), value.end());
}

std::size_t exact_power_of_two_padding(std::uint64_t value,
                                       const char *label) {
    const std::size_t converted = as_size(value, label);
    if (converted == 0 ||
        converted >
            (std::numeric_limits<std::size_t>::max() >> 1U) + 1U) {
        throw std::overflow_error(std::string(label) + " cannot be padded");
    }
    return std::bit_ceil(converted);
}

class AssignmentArtifactCleanup {
  public:
    explicit AssignmentArtifactCleanup(std::filesystem::path directory)
        : directory_(std::move(directory)) {}

    AssignmentArtifactCleanup(const AssignmentArtifactCleanup &) = delete;
    AssignmentArtifactCleanup &operator=(
        const AssignmentArtifactCleanup &) = delete;

    ~AssignmentArtifactCleanup() {
        if (!armed_) {
            return;
        }
        std::error_code error;
        std::filesystem::directory_iterator entry(directory_, error);
        const std::filesystem::directory_iterator end;
        while (!error && entry != end) {
            const std::filesystem::path child = entry->path();
            entry.increment(error);
            std::error_code ignored;
            std::filesystem::remove_all(child, ignored);
        }
    }

    void disarm() { armed_ = false; }

  private:
    std::filesystem::path directory_;
    bool armed_ = true;
};

void validate_empty_assignment_directory(
    const std::filesystem::path &directory) {
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(directory);
    if (!std::filesystem::is_directory(status) ||
        std::filesystem::is_symlink(status) ||
        !std::filesystem::is_empty(directory)) {
        throw std::invalid_argument(
            "proof-of-packing assignment destination must be an empty "
            "real directory");
    }
}

std::uint64_t local_poseidon_rows_per_permutation() {
    std::uint64_t checkpoints = 0;
    for (std::size_t round = 0;
         round < kPoseidonFullRounds + kPoseidonPartialRounds; ++round) {
        checkpoints += poseidon_round_is_r1cs_checkpoint(round) ? 1 : 0;
    }
    return 3 * (kPoseidonFullRounds * kPoseidonWidth +
                kPoseidonPartialRounds) +
           checkpoints * kPoseidonWidth;
}

struct ExpressionTerm {
    std::uint64_t column = 0;
    Fq coefficient{};
};

struct Expression {
    std::vector<ExpressionTerm> terms;

    static Expression constant(const Fq &value) {
        Expression result;
        if (!value.is_zero()) {
            result.terms.push_back({0, value});
        }
        return result;
    }

    static Expression variable(std::uint64_t column) {
        return Expression{{ExpressionTerm{column, Fq::one()}}};
    }
};

Expression linear_combination(
    std::span<const std::pair<Fq, Expression>> inputs) {
    std::map<std::uint64_t, Fq> accumulated;
    for (const auto &[scale, expression] : inputs) {
        if (scale.is_zero()) {
            continue;
        }
        for (const ExpressionTerm &term : expression.terms) {
            accumulated[term.column] += scale * term.coefficient;
        }
    }
    Expression result;
    result.terms.reserve(accumulated.size());
    for (const auto &[column, coefficient] : accumulated) {
        if (!coefficient.is_zero()) {
            result.terms.push_back({column, coefficient});
        }
    }
    return result;
}

Expression add(const Expression &left, const Expression &right) {
    const std::array<std::pair<Fq, Expression>, 2> inputs{
        std::pair{Fq::one(), left}, std::pair{Fq::one(), right}};
    return linear_combination(inputs);
}

struct Wire {
    Expression expression;
    Fq value{};
};

class PoseidonR1csSynthesizer {
  public:
    PoseidonR1csSynthesizer(
        std::uint64_t public_inputs,
        const ProofOfPackingR1csLayout &layout,
        std::vector<spartan::R1csEntry> *a,
        std::vector<spartan::R1csEntry> *b,
        std::vector<spartan::R1csEntry> *c,
        std::vector<Fq> *auxiliary_values)
        : public_inputs_(public_inputs),
          layout_(&layout), a_(a),
          b_(b), c_(c), auxiliary_values_(auxiliary_values) {}

    void synthesize_ciphertext(
        std::size_t ring_degree, std::uint64_t ciphertext_index,
        std::span<const std::uint64_t> coordinate_witness_indices,
        std::span<const Fq> coordinate_values,
        std::span<const Fq> expected_digest) {
        const std::size_t coordinate_count = 2 * ring_degree;
        if (coordinate_witness_indices.size() != coordinate_count ||
            (!coordinate_values.empty() &&
             coordinate_values.size() != coordinate_count) ||
            (!expected_digest.empty() &&
             expected_digest.size() != kPoseidonDigestElements)) {
            throw std::invalid_argument(
                "Poseidon ciphertext gadget has inconsistent dimensions");
        }

        const std::uint64_t preimage_count = checked_add(
            gkr::kCiphertextCommitmentMetadataElements,
            checked_size(coordinate_count, "ciphertext coordinate count"),
            "ciphertext Poseidon preimage");
        const std::uint64_t first_permutation = checked_mul(
            ciphertext_index, layout_->ciphertext_permutations_per_hash,
            "ciphertext permutation base");
        std::array<Wire, kPoseidonWidth> state = synthesize_sponge(
            first_permutation, preimage_count,
            PoseidonDomain::CiphertextCommitment,
            preimage_count, [&](std::uint64_t input) {
                if (input < gkr::kCiphertextCommitmentMetadataElements) {
                    const std::array<Fq, 4> metadata{
                        Fq(ring_degree),
                        Fq(gkr::kCiphertextCommitmentComponents),
                        Fq(gkr::kCiphertextCommitmentNttFlag),
                        Fq(gkr::kCiphertextCommitmentCorrectionFactor)};
                    return constant_wire(
                        metadata[as_size(input, "metadata index")]);
                }
                const std::size_t coordinate = as_size(
                    input - gkr::kCiphertextCommitmentMetadataElements,
                    "ciphertext coordinate index");
                return Wire{
                    Expression::variable(witness_column(
                        coordinate_witness_indices[coordinate])),
                    coordinate_values.empty() ? Fq::zero()
                                              : coordinate_values[coordinate]};
            });

        for (std::size_t element = 0;
             element < kPoseidonDigestElements; ++element) {
            const std::uint64_t logical_index = checked_add(
                checked_mul(ciphertext_index, kPoseidonDigestElements,
                            "ciphertext commitment input"),
                element, "ciphertext commitment input");
            emit_at(layout_->ciphertext_output_row(
                        as_size(ciphertext_index, "ciphertext index"),
                        element),
                    state[element].expression,
                    Expression::constant(Fq::one()),
                    Expression::variable(
                        public_input_column(logical_index)));
            if (!expected_digest.empty() &&
                state[element].value != expected_digest[element]) {
                throw std::invalid_argument(
                    "Poseidon witness does not match its public commitment");
            }
        }
    }

    std::uint64_t constraints() const { return total_constraints_; }
    std::uint64_t auxiliary_count() const { return total_auxiliary_count_; }
    std::uint64_t nonzero_entries() const { return nonzero_entries_; }

    std::array<std::uint64_t, kPoseidonWidth>
    synthesize_template_permutation() {
        std::array<Wire, kPoseidonWidth> state{};
        for (std::size_t word = 0; word < state.size(); ++word) {
            state[word] = Wire{
                Expression::variable(witness_column(word)), Fq::zero()};
        }
        for (std::size_t rate = 0; rate < kPoseidonRate; ++rate) {
            state[rate].expression = add(
                state[rate].expression,
                Expression::variable(witness_column(
                    kPoseidonWidth + rate)));
        }
        begin_permutation(0);
        permute(state);
        finish_permutation();

        std::array<std::uint64_t, kPoseidonWidth> result{};
        constexpr std::uint64_t kAuxiliaryColumn =
            1 + kPoseidonWidth + kPoseidonRate;
        for (std::size_t word = 0; word < state.size(); ++word) {
            if (state[word].expression.terms.size() != 1 ||
                state[word].expression.terms.front().coefficient !=
                    Fq::one() ||
                state[word].expression.terms.front().column <
                    kAuxiliaryColumn) {
                throw std::logic_error(
                    "Poseidon final state is not a checkpoint wire");
            }
            result[word] =
                state[word].expression.terms.front().column -
                kAuxiliaryColumn;
        }
        return result;
    }

  private:
    static Wire constant_wire(const Fq &value) {
        return Wire{Expression::constant(value), value};
    }

    std::uint64_t witness_column(std::uint64_t witness_index) const {
        return checked_add(
            checked_add(1, public_inputs_, "R1CS witness column"),
            witness_index, "R1CS witness column");
    }

    std::uint64_t public_input_column(std::uint64_t input_index) const {
        if (input_index >= public_inputs_) {
            throw std::out_of_range(
                "Poseidon public input index is out of range");
        }
        return checked_add(1, input_index, "R1CS public input column");
    }

    Wire allocate_auxiliary(const Fq &value) {
        if (!permutation_active_) {
            throw std::logic_error(
                "Poseidon auxiliary allocated outside a permutation");
        }
        const std::uint64_t witness_index =
            layout_->ciphertext_poseidon_auxiliary_witness_index(
                local_auxiliary_count_, permutation_);
        ++local_auxiliary_count_;
        ++total_auxiliary_count_;
        if (auxiliary_values_ != nullptr) {
            auxiliary_values_->at(
                as_size(witness_index, "Poseidon auxiliary witness")) =
                value;
        }
        return Wire{Expression::variable(witness_column(witness_index)),
                    value};
    }

    Wire sbox(const Wire &input) {
        Wire squared = allocate_auxiliary(input.value * input.value);
        emit(input.expression, input.expression, squared.expression);
        Wire fourth =
            allocate_auxiliary(squared.value * squared.value);
        emit(squared.expression, squared.expression, fourth.expression);
        Wire fifth = allocate_auxiliary(fourth.value * input.value);
        emit(fourth.expression, input.expression, fifth.expression);
        return fifth;
    }

    void begin_permutation(std::uint64_t permutation) {
        if (permutation_active_) {
            throw std::logic_error("Poseidon permutation is already active");
        }
        permutation_ = permutation;
        local_row_ = 0;
        local_auxiliary_count_ = 0;
        permutation_active_ = true;
    }

    void finish_permutation() {
        if (!permutation_active_ ||
            local_row_ != layout_->poseidon_rows_per_permutation ||
            local_auxiliary_count_ !=
                layout_->poseidon_rows_per_permutation) {
            throw std::logic_error(
                "Poseidon permutation disagrees with its structured layout");
        }
        permutation_active_ = false;
    }

    template <typename Next>
    std::array<Wire, kPoseidonWidth> synthesize_sponge(
        std::uint64_t first_permutation,
        std::uint64_t input_count, PoseidonDomain domain,
        std::uint64_t logical_length, Next &&next) {
        std::array<Wire, kPoseidonWidth> state{};
        for (Wire &wire : state) {
            wire = constant_wire(Fq::zero());
        }
        state[kPoseidonRate] = constant_wire(
            Fq(static_cast<std::uint64_t>(domain)));
        state[kPoseidonRate + 1] = constant_wire(Fq(logical_length));
        state[kPoseidonRate + 2] = constant_wire(Fq(input_count));
        state[kPoseidonRate + 3] = constant_wire(
            Fq(kPoseidonEncodingVersionDelimiter));

        std::uint64_t consumed = 0;
        std::uint64_t permutation = first_permutation;
        bool padded = false;
        while (!padded) {
            for (std::size_t rate = 0; rate < kPoseidonRate; ++rate) {
                Wire absorbed = constant_wire(Fq::zero());
                if (consumed < input_count) {
                    absorbed = next(consumed++);
                } else if (!padded) {
                    absorbed = constant_wire(
                        Fq(kPoseidonRatePaddingDelimiter));
                    padded = true;
                }
                state[rate].expression =
                    add(state[rate].expression, absorbed.expression);
                state[rate].value += absorbed.value;
            }
            begin_permutation(permutation++);
            permute(state);
            finish_permutation();
        }
        return state;
    }

    void permute(std::array<Wire, kPoseidonWidth> &state) {
        const PoseidonRoundConstants &round_constants =
            poseidon_round_constants();
        const PoseidonMdsMatrix &mds = poseidon_mds_matrix();
        for (std::size_t round = 0; round < round_constants.size(); ++round) {
            for (std::size_t index = 0; index < state.size(); ++index) {
                state[index].expression = add(
                    state[index].expression,
                    Expression::constant(round_constants[round][index]));
                state[index].value += round_constants[round][index];
            }
            if (poseidon_round_is_full(round)) {
                for (Wire &wire : state) {
                    wire = sbox(wire);
                }
            } else {
                state[0] = sbox(state[0]);
            }

            std::array<Wire, kPoseidonWidth> mixed{};
            for (std::size_t row = 0; row < state.size(); ++row) {
                std::vector<std::pair<Fq, Expression>> expressions;
                expressions.reserve(state.size());
                Fq value = Fq::zero();
                for (std::size_t column = 0; column < state.size();
                     ++column) {
                    expressions.emplace_back(mds[row][column],
                                             state[column].expression);
                    value += mds[row][column] * state[column].value;
                }
                mixed[row] = Wire{linear_combination(expressions), value};
            }
            state = std::move(mixed);
            if (poseidon_round_is_r1cs_checkpoint(round)) {
                for (Wire &wire : state) {
                    Wire checkpoint = allocate_auxiliary(wire.value);
                    emit(wire.expression, Expression::constant(Fq::one()),
                         checkpoint.expression);
                    wire = std::move(checkpoint);
                }
            }
        }
    }

    void append(std::vector<spartan::R1csEntry> *matrix,
                std::uint64_t row, const Expression &expression) {
        nonzero_entries_ = checked_add(
            nonzero_entries_, checked_size(expression.terms.size(),
                                            "Poseidon sparse entries"),
            "Poseidon sparse entries");
        if (matrix == nullptr) {
            return;
        }
        for (const ExpressionTerm &term : expression.terms) {
            matrix->push_back(spartan::R1csEntry{
                row, term.column, term.coefficient});
        }
    }

    void emit(const Expression &a, const Expression &b,
              const Expression &c) {
        if (!permutation_active_) {
            throw std::logic_error(
                "Poseidon local row emitted outside a permutation");
        }
        const std::uint64_t row = layout_->ciphertext_poseidon_row(
            local_row_, permutation_);
        append(a_, row, a);
        append(b_, row, b);
        append(c_, row, c);
        ++local_row_;
        ++total_constraints_;
    }

    void emit_at(std::uint64_t row, const Expression &a,
                 const Expression &b, const Expression &c) {
        if (permutation_active_) {
            throw std::logic_error(
                "Poseidon output emitted during a permutation");
        }
        append(a_, row, a);
        append(b_, row, b);
        append(c_, row, c);
        ++total_constraints_;
    }

    std::uint64_t public_inputs_ = 0;
    const ProofOfPackingR1csLayout *layout_ = nullptr;
    std::vector<spartan::R1csEntry> *a_ = nullptr;
    std::vector<spartan::R1csEntry> *b_ = nullptr;
    std::vector<spartan::R1csEntry> *c_ = nullptr;
    std::vector<Fq> *auxiliary_values_ = nullptr;
    std::uint64_t permutation_ = 0;
    std::uint64_t local_row_ = 0;
    std::uint64_t local_auxiliary_count_ = 0;
    std::uint64_t total_constraints_ = 0;
    std::uint64_t total_auxiliary_count_ = 0;
    std::uint64_t nonzero_entries_ = 0;
    bool permutation_active_ = false;
};

/// Evaluate the ciphertext sponge while retaining only the auxiliary values
/// allocated by one ciphertext. Allocation order is permutation-major and
/// matches PoseidonR1csSynthesizer exactly; the artifact writer transposes
/// these values into the structured witness layout after synthesis.
std::array<Fq, kPoseidonDigestElements>
synthesize_ciphertext_poseidon_values(
    std::size_t ring_degree, std::span<const Fq> coordinates,
    std::vector<Fq> &auxiliary_values) {
    if (ring_degree == 0 ||
        ring_degree > std::numeric_limits<std::size_t>::max() / 2U ||
        coordinates.size() != 2U * ring_degree) {
        throw std::invalid_argument(
            "ciphertext Poseidon values have inconsistent dimensions");
    }
    const std::uint64_t coordinate_count = checked_size(
        coordinates.size(), "ciphertext coordinate count");
    const std::uint64_t input_count = checked_add(
        gkr::kCiphertextCommitmentMetadataElements, coordinate_count,
        "ciphertext Poseidon input count");
    const std::array<Fq, gkr::kCiphertextCommitmentMetadataElements>
        metadata{
            Fq(checked_size(ring_degree, "ring degree")),
            Fq(gkr::kCiphertextCommitmentComponents),
            Fq(gkr::kCiphertextCommitmentNttFlag),
            Fq(gkr::kCiphertextCommitmentCorrectionFactor)};

    auxiliary_values.clear();
    std::array<Fq, kPoseidonWidth> state{};
    state[kPoseidonRate] =
        Fq(static_cast<std::uint64_t>(PoseidonDomain::CiphertextCommitment));
    state[kPoseidonRate + 1] = Fq(input_count);
    state[kPoseidonRate + 2] = Fq(input_count);
    state[kPoseidonRate + 3] =
        Fq(kPoseidonEncodingVersionDelimiter);

    const PoseidonRoundConstants &round_constants =
        poseidon_round_constants();
    const PoseidonMdsMatrix &mds = poseidon_mds_matrix();
    const std::uint64_t rows_per_permutation =
        local_poseidon_rows_per_permutation();
    std::uint64_t consumed = 0;
    bool padded = false;
    while (!padded) {
        for (std::size_t rate = 0; rate < kPoseidonRate; ++rate) {
            Fq absorbed = Fq::zero();
            if (consumed < input_count) {
                if (consumed < metadata.size()) {
                    absorbed = metadata[as_size(consumed,
                                                "metadata input index")];
                } else {
                    absorbed = coordinates[as_size(
                        consumed - metadata.size(),
                        "coordinate input index")];
                }
                ++consumed;
            } else if (!padded) {
                absorbed = Fq(kPoseidonRatePaddingDelimiter);
                padded = true;
            }
            state[rate] += absorbed;
        }

        const std::size_t permutation_auxiliary_begin =
            auxiliary_values.size();
        for (std::size_t round = 0;
             round < round_constants.size(); ++round) {
            for (std::size_t index = 0; index < state.size(); ++index) {
                state[index] += round_constants[round][index];
            }
            const auto apply_sbox = [&](Fq &wire) {
                const Fq squared = wire * wire;
                auxiliary_values.push_back(squared);
                const Fq fourth = squared * squared;
                auxiliary_values.push_back(fourth);
                const Fq fifth = fourth * wire;
                auxiliary_values.push_back(fifth);
                wire = fifth;
            };
            if (poseidon_round_is_full(round)) {
                for (Fq &wire : state) {
                    apply_sbox(wire);
                }
            } else {
                apply_sbox(state[0]);
            }

            std::array<Fq, kPoseidonWidth> mixed{};
            for (std::size_t row = 0; row < state.size(); ++row) {
                for (std::size_t column = 0; column < state.size();
                     ++column) {
                    mixed[row] += mds[row][column] * state[column];
                }
            }
            state = mixed;
            if (poseidon_round_is_r1cs_checkpoint(round)) {
                auxiliary_values.insert(auxiliary_values.end(),
                                        state.begin(), state.end());
            }
        }
        if (auxiliary_values.size() - permutation_auxiliary_begin !=
            as_size(rows_per_permutation,
                    "Poseidon rows per permutation")) {
            throw std::logic_error(
                "value-only Poseidon synthesis disagrees with its layout");
        }
    }
    if (consumed != input_count) {
        throw std::logic_error(
            "value-only Poseidon sponge did not consume its preimage");
    }

    std::array<Fq, kPoseidonDigestElements> digest{};
    std::copy_n(state.begin(), digest.size(), digest.begin());
    return digest;
}

std::array<Fq, kPoseidonDigestElements>
synthesize_ciphertext_simple_hash_values(
    std::size_t ring_degree, std::span<const Fq> coordinates,
    std::vector<Fq> &auxiliary_values) {
    if (ring_degree == 0 ||
        ring_degree > std::numeric_limits<std::size_t>::max() / 2U ||
        coordinates.size() != 2U * ring_degree) {
        throw std::invalid_argument(
            "diagnostic ciphertext-hash values have inconsistent "
            "dimensions");
    }
    auxiliary_values.clear();
    auxiliary_values.reserve(coordinates.size());
    const Fq alpha(gkr::kDiagnosticSimpleCtHashAlpha);
    Fq state =
        gkr::diagnostic_simple_ct_hash_initial_state(ring_degree);
    for (const Fq &coordinate : coordinates) {
        state = alpha * state + coordinate;
        auxiliary_values.push_back(state);
    }
    return gkr::diagnostic_simple_ct_hash_output_fields(state);
}

std::uint64_t poseidon_nonzero_entries_per_ciphertext(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout) {
    const std::size_t ring_degree = plan.shape.ring_degree;
    if (ring_degree == 0 ||
        ring_degree > std::numeric_limits<std::size_t>::max() / 2U) {
        throw std::invalid_argument(
            "Poseidon sparse-entry ledger has invalid ring degree");
    }
    const std::size_t coordinate_count = 2 * ring_degree;
    std::vector<std::uint64_t> coordinate_indices(coordinate_count);
    for (std::size_t coordinate = 0; coordinate < coordinate_count;
         ++coordinate) {
        coordinate_indices[coordinate] =
            layout.aligned_coordinate_witness_index(
                plan, 0, coordinate / ring_degree,
                coordinate % ring_degree);
    }
    PoseidonR1csSynthesizer poseidon(
        layout.logical_inputs, layout,
        nullptr, nullptr, nullptr, nullptr);
    poseidon.synthesize_ciphertext(
        ring_degree, 0, coordinate_indices, {}, {});
    return poseidon.nonzero_entries();
}

std::uint64_t witness_column(const ProofOfPackingR1csLedger &ledger,
                             std::uint64_t witness_index,
                             const char *label) {
    return checked_add(
        checked_add(1, ledger.total_public_inputs, label), witness_index,
        label);
}

struct SimpleCtHashSynthesisResult {
    std::uint64_t constraints = 0;
    std::uint64_t auxiliary_count = 0;
    std::uint64_t nonzero_entries = 0;
};

void append_simple_hash_entry(
    std::vector<spartan::R1csEntry> *matrix, std::uint64_t row,
    std::uint64_t column, const Fq &value,
    SimpleCtHashSynthesisResult &result) {
    if (value.is_zero()) {
        return;
    }
    ++result.nonzero_entries;
    if (matrix != nullptr) {
        matrix->push_back(spartan::R1csEntry{row, column, value});
    }
}

SimpleCtHashSynthesisResult synthesize_ciphertext_simple_hash(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLedger &ledger,
    const ProofOfPackingR1csLayout &layout,
    std::uint64_t ciphertext,
    std::span<const std::uint64_t> coordinate_witness_indices,
    std::span<const Fq> coordinate_values,
    std::span<const Fq> expected_digest,
    std::vector<spartan::R1csEntry> *a,
    std::vector<spartan::R1csEntry> *b,
    std::vector<spartan::R1csEntry> *c,
    std::vector<Fq> *witness_values) {
    const std::size_t coordinate_count =
        plan.shape.ciphertext_components * plan.shape.ring_degree;
    if (plan.shape.ciphertext_commitment_policy.relation !=
            gkr::CiphertextCommitmentRelation::DiagnosticSimpleCtHashV2 ||
        coordinate_witness_indices.size() != coordinate_count ||
        (!coordinate_values.empty() &&
         coordinate_values.size() != coordinate_count) ||
        (!expected_digest.empty() &&
         expected_digest.size() != kPoseidonDigestElements)) {
        throw std::invalid_argument(
            "diagnostic ciphertext-hash synthesis has inconsistent inputs");
    }

    SimpleCtHashSynthesisResult result;
    const Fq alpha(gkr::kDiagnosticSimpleCtHashAlpha);
    Fq state = gkr::diagnostic_simple_ct_hash_initial_state(
        plan.shape.ring_degree);
    for (std::size_t coordinate = 0; coordinate < coordinate_count;
         ++coordinate) {
        const std::uint64_t row = layout.ciphertext_simple_hash_row(
            plan, as_size(ciphertext, "ciphertext index"), coordinate);
        const std::uint64_t current_auxiliary =
            layout.ciphertext_simple_hash_auxiliary_witness_index(
                plan, as_size(ciphertext, "ciphertext index"), coordinate);
        if (coordinate == 0) {
            append_simple_hash_entry(
                a, row, 0, alpha * state, result);
        } else {
            const std::uint64_t previous_auxiliary =
                layout.ciphertext_simple_hash_auxiliary_witness_index(
                    plan, as_size(ciphertext, "ciphertext index"),
                    coordinate - 1);
            append_simple_hash_entry(
                a, row,
                witness_column(ledger, previous_auxiliary,
                               "diagnostic hash previous state"),
                alpha, result);
        }
        append_simple_hash_entry(
            a, row,
            witness_column(ledger, coordinate_witness_indices[coordinate],
                           "diagnostic hash coordinate"),
            Fq::one(), result);
        append_simple_hash_entry(b, row, 0, Fq::one(), result);
        append_simple_hash_entry(
            c, row,
            witness_column(ledger, current_auxiliary,
                           "diagnostic hash current state"),
            Fq::one(), result);
        ++result.constraints;
        ++result.auxiliary_count;

        if (!coordinate_values.empty()) {
            state = alpha * state + coordinate_values[coordinate];
            if (witness_values != nullptr) {
                witness_values->at(as_size(
                    current_auxiliary,
                    "diagnostic hash auxiliary witness")) = state;
            }
        }
    }

    const auto output_fields =
        gkr::diagnostic_simple_ct_hash_output_fields(state);
    const std::uint64_t final_auxiliary =
        layout.ciphertext_simple_hash_auxiliary_witness_index(
            plan, as_size(ciphertext, "ciphertext index"),
            coordinate_count - 1);
    for (std::size_t element = 0;
         element < kPoseidonDigestElements; ++element) {
        const std::uint64_t row = layout.ciphertext_output_row(
            as_size(ciphertext, "ciphertext index"), element);
        append_simple_hash_entry(
            a, row,
            witness_column(ledger, final_auxiliary,
                           "diagnostic hash final state"),
            Fq::one(), result);
        append_simple_hash_entry(
            a, row, 0,
            Fq(gkr::kDiagnosticSimpleCtHashOutputDomains[element]),
            result);
        append_simple_hash_entry(b, row, 0, Fq::one(), result);
        const std::uint64_t logical_index = checked_add(
            checked_mul(ciphertext, kPoseidonDigestElements,
                        "diagnostic hash public input"),
            element, "diagnostic hash public input");
        append_simple_hash_entry(
            c, row, checked_add(1, logical_index,
                               "diagnostic hash public-input column"),
            Fq::one(), result);
        ++result.constraints;
        if (!expected_digest.empty() &&
            output_fields[element] != expected_digest[element]) {
            throw std::invalid_argument(
                "diagnostic ciphertext-hash witness does not match its "
                "public commitment");
        }
    }
    return result;
}

std::uint64_t conventional_column(
    const OuterRelationR1csVariable &variable,
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLedger &ledger,
    const ProofOfPackingR1csLayout &layout) {
    switch (variable.kind) {
    case OuterRelationR1csVariableKind::ConstantOne:
        if (variable.index != 0) {
            throw std::invalid_argument(
                "packing R1CS constant-one index is not zero");
        }
        return 0;
    case OuterRelationR1csVariableKind::PublicInput:
        if (variable.index >= plan.variables.public_inputs.total) {
            throw std::out_of_range(
                "packing public input index is out of range");
        }
        return checked_add(
            checked_add(1, ledger.commitment_logical_inputs,
                        "packing public-input column"),
            variable.index, "packing public-input column");
    case OuterRelationR1csVariableKind::Witness:
        return witness_column(
            ledger, layout.outer_witness_index(plan, variable.index),
            "packing relation witness column");
    }
    throw std::invalid_argument("packing R1CS variable kind is invalid");
}

std::vector<spartan::R1csEntry> *select_matrix(
    OuterRelationR1csMatrix matrix,
    std::vector<spartan::R1csEntry> &a,
    std::vector<spartan::R1csEntry> &b,
    std::vector<spartan::R1csEntry> &c) {
    switch (matrix) {
    case OuterRelationR1csMatrix::A:
        return &a;
    case OuterRelationR1csMatrix::B:
        return &b;
    case OuterRelationR1csMatrix::C:
        return &c;
    }
    throw std::invalid_argument("packing R1CS matrix kind is invalid");
}

void append_outer_combination(
    const OuterRelationR1csLinearCombination &source,
    std::uint64_t row, const OuterRelationPlan &plan,
    const ProofOfPackingR1csLedger &ledger,
    const ProofOfPackingR1csLayout &layout,
    std::vector<spartan::R1csEntry> &destination) {
    for (const OuterRelationR1csTerm &term : source) {
        destination.push_back(spartan::R1csEntry{
            row, conventional_column(term.variable, plan, ledger, layout),
            Fq(term.coefficient)});
    }
}

void append_outer_row(const OuterRelationR1csRow &source,
                      const OuterRelationPlan &plan,
                      const ProofOfPackingR1csLedger &ledger,
                      const ProofOfPackingR1csLayout &layout,
                      std::vector<spartan::R1csEntry> &a,
                      std::vector<spartan::R1csEntry> &b,
                      std::vector<spartan::R1csEntry> &c) {
    const std::uint64_t row =
        layout.outer_constraint_row(plan, source.constraint_index);
    append_outer_combination(source.a, row, plan, ledger, layout, a);
    append_outer_combination(source.b, row, plan, ledger, layout, b);
    append_outer_combination(source.c, row, plan, ledger, layout, c);
}

void validate_plan(const OuterRelationPlan &plan) {
    plan.shape.ciphertext_commitment_policy.validate();
    if (plan.shape.native_modulus != kOuterFieldOrder ||
        plan.shape.ciphertext_components != 2 ||
        plan.shape.aligned_ciphertexts == 0 ||
        plan.shape.ring_degree == 0) {
        throw std::invalid_argument(
            "proof-of-packing R1CS needs the native field and size-two "
            "ciphertexts");
    }
}

void validate_assignment_metadata(
    const spartan::R1csMetadata &metadata,
    const ProofOfPackingR1csLayout &layout) {
    if (!metadata.is_well_formed() ||
        metadata.shape() != spartan::R1csShape{
                                .constraints = layout.rows.total,
                                .public_inputs = layout.logical_inputs,
                                .witness_variables = layout.witness.total}) {
        throw std::invalid_argument(
            "proof-of-packing assignment has inconsistent R1CS metadata");
    }
    const std::size_t expected_constraints = exact_power_of_two_padding(
        layout.rows.total, "proof-of-packing constraints");
    const std::uint64_t public_side = checked_add(
        layout.logical_inputs, 1, "proof-of-packing public half");
    const std::size_t expected_assignment_half = exact_power_of_two_padding(
        std::max(public_side, layout.witness.total),
        "proof-of-packing assignment half");
    if (metadata.padded_constraints() != expected_constraints ||
        metadata.assignment_half_size() != expected_assignment_half) {
        throw std::invalid_argument(
            "proof-of-packing assignment metadata has noncanonical "
            "padding");
    }
}

void validate_outer_assignment_artifact(
    const OuterRelationPlan &plan,
    const storage::NativeFieldArtifact &outer_assignment) {
    if (outer_assignment.identity() !=
            outer_relation_assignment_artifact_identity(plan) ||
        outer_assignment.arrays().size() != 2) {
        throw std::invalid_argument(
            "proof-of-packing source is not the canonical outer "
            "assignment");
    }
    const storage::NativeFieldArrayDescriptor &public_inputs =
        outer_assignment.array(kAssignmentPublicInputsArray);
    const storage::NativeFieldArrayDescriptor &witness =
        outer_assignment.array("witness");
    if (public_inputs.kind != storage::NativeFieldElementKind::Fq ||
        witness.kind != storage::NativeFieldElementKind::Fq ||
        public_inputs.element_count !=
            plan.variables.public_inputs.total ||
        witness.element_count != plan.variables.witness.total) {
        throw std::invalid_argument(
            "proof-of-packing source outer assignment has the wrong "
            "layout");
    }
}

ProofOfPackingR1csLayout validate_assignment_inputs(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &metadata,
    const storage::NativeFieldArtifact &outer_assignment,
    std::span<const gkr::HashCommitCT> commitments) {
    validate_plan(plan);
    ProofOfPackingR1csLayout layout =
        make_proof_of_packing_r1cs_layout(plan);
    validate_assignment_metadata(metadata, layout);
    validate_outer_assignment_artifact(plan, outer_assignment);
    if (commitments.size() != plan.shape.aligned_ciphertexts) {
        throw std::invalid_argument(
            "proof-of-packing assignment has the wrong commitment count");
    }
    return layout;
}

void append_witness_storage_segment(
    ProofOfPackingWitnessStorageLayout &storage,
    std::uint64_t logical_begin, std::uint64_t element_count) {
    if (element_count == 0) {
        return;
    }
    const std::uint64_t logical_end = checked_add(
        logical_begin, element_count, "witness support end");
    if (logical_end > storage.logical_elements) {
        throw std::logic_error(
            "proof-of-packing witness support exceeds its logical half");
    }
    if (!storage.segments.empty()) {
        ProofOfPackingWitnessStorageSegment &previous =
            storage.segments.back();
        const std::uint64_t previous_end = checked_add(
            previous.logical_begin, previous.element_count,
            "previous witness support end");
        if (logical_begin < previous_end) {
            throw std::logic_error(
                "proof-of-packing witness support overlaps");
        }
        if (logical_begin == previous_end) {
            previous.element_count = checked_add(
                previous.element_count, element_count,
                "merged witness support count");
            storage.stored_elements = checked_add(
                storage.stored_elements, element_count,
                "stored witness count");
            return;
        }
    }
    storage.segments.push_back(ProofOfPackingWitnessStorageSegment{
        .logical_begin = logical_begin,
        .stored_begin = storage.stored_elements,
        .element_count = element_count,
    });
    storage.stored_elements = checked_add(
        storage.stored_elements, element_count,
        "stored witness count");
}

ProofOfPackingWitnessStorageLayout make_witness_storage_layout(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &metadata,
    const ProofOfPackingR1csLayout &layout) {
    ProofOfPackingWitnessStorageLayout result{
        .logical_elements = checked_size(
            metadata.assignment_half_size(), "assignment half"),
    };

    if (layout.witness.challenge_bits.live !=
            plan.variables.witness.derived_challenge_bits.count ||
        layout.witness.aligned_coordinates.live !=
            plan.variables.witness.aligned_ciphertext_coordinates.count ||
        layout.witness.well_formedness_products.live !=
            plan.variables.witness.well_formedness_products.count ||
        layout.witness.ciphertext_poseidon_auxiliary.live !=
            layout.witness.ciphertext_poseidon_auxiliary.extent) {
        throw std::logic_error(
            "proof-of-packing witness support disagrees with its layout");
    }

    append_witness_storage_segment(
        result, layout.witness.challenge_bits.begin,
        layout.witness.challenge_bits.live);

    const std::uint64_t coordinates_per_ciphertext = checked_mul(
        plan.shape.ciphertext_components,
        checked_size(plan.shape.ring_degree, "ring degree"),
        "coordinates per ciphertext");
    const std::uint64_t input_begin =
        gkr::kCiphertextCommitmentMetadataElements;
    const std::uint64_t input_end = checked_add(
        input_begin, coordinates_per_ciphertext,
        "ciphertext coordinate input end");
    const std::uint64_t permutations_per_hash =
        layout.ciphertext_permutations_per_hash;
    std::uint64_t stored_coordinates = 0;
    for (const ProofOfPackingPoseidonSegment &segment :
         layout.ciphertext_segments) {
        for (std::uint64_t rate = 0; rate < kPoseidonRate; ++rate) {
            const std::uint64_t first_local = std::min(
                permutations_per_hash,
                input_begin > rate
                    ? ceil_div(input_begin - rate, kPoseidonRate)
                    : 0U);
            const std::uint64_t end_local = std::min(
                permutations_per_hash,
                input_end > rate
                    ? ceil_div(input_end - rate, kPoseidonRate)
                    : 0U);
            for (std::uint64_t ciphertext = 0;
                 ciphertext < plan.shape.aligned_ciphertexts;
                 ++ciphertext) {
                const std::uint64_t ciphertext_begin = checked_mul(
                    ciphertext, permutations_per_hash,
                    "ciphertext permutation begin");
                const std::uint64_t active_begin = checked_add(
                    ciphertext_begin, first_local,
                    "active coordinate permutation begin");
                const std::uint64_t active_end = checked_add(
                    ciphertext_begin, end_local,
                    "active coordinate permutation end");
                const std::uint64_t overlap_begin = std::max(
                    active_begin, segment.permutation_begin);
                const std::uint64_t overlap_end = std::min(
                    active_end, segment.permutation_end());
                if (overlap_begin >= overlap_end) {
                    continue;
                }
                const std::uint64_t count = overlap_end - overlap_begin;
                append_witness_storage_segment(
                    result,
                    checked_add(
                        segment.input_witness_begin,
                        checked_add(
                            checked_mul(rate, segment.permutations,
                                        "rate-major support offset"),
                            overlap_begin - segment.permutation_begin,
                            "coordinate support offset"),
                        "coordinate support begin"),
                    count);
                stored_coordinates = checked_add(
                    stored_coordinates, count,
                    "stored coordinate count");
            }
        }
    }
    if (stored_coordinates !=
        plan.variables.witness.aligned_ciphertext_coordinates.count) {
        throw std::logic_error(
            "proof-of-packing coordinate support has the wrong size");
    }

    append_witness_storage_segment(
        result, layout.witness.well_formedness_products.begin,
        layout.witness.well_formedness_products.live);
    append_witness_storage_segment(
        result, layout.witness.ciphertext_poseidon_auxiliary.begin,
        layout.witness.ciphertext_poseidon_auxiliary.live);

    const std::uint64_t expected = checked_add(
        plan.variables.witness.total,
        layout.witness.ciphertext_poseidon_auxiliary.live,
        "active proof-of-packing witnesses");
    if (result.stored_elements != expected) {
        throw std::logic_error(
            "proof-of-packing witness support count is inconsistent");
    }
    return result;
}

void append_metadata_identity(
    std::vector<std::uint8_t> &encoding,
    const spartan::R1csMetadata &metadata) {
    append_u64(encoding, metadata.shape().constraints);
    append_u64(encoding, metadata.shape().public_inputs);
    append_u64(encoding, metadata.shape().witness_variables);
    append_u64(encoding, checked_size(metadata.padded_constraints(),
                                      "padded constraint count"));
    append_u64(encoding, checked_size(metadata.assignment_half_size(),
                                      "assignment half"));
    append_bytes(encoding, metadata.digest());
}

void append_array_identity(
    std::vector<std::uint8_t> &encoding,
    const storage::NativeFieldArrayDescriptor &array) {
    append_string(encoding, array.name);
    append_u64(encoding, static_cast<std::uint64_t>(array.kind));
    append_u64(encoding, array.element_count);
    append_u64(encoding, array.encoded_element_bytes);
    append_u64(encoding, array.physical_bytes);
    append_bytes(encoding, array.file_digest);
}

void append_witness_storage_identity(
    std::vector<std::uint8_t> &encoding,
    const ProofOfPackingWitnessStorageLayout &storage) {
    append_u64(encoding, storage.logical_elements);
    append_u64(encoding, storage.stored_elements);
    append_u64(encoding, checked_size(storage.segments.size(),
                                      "witness support segment count"));
    for (const ProofOfPackingWitnessStorageSegment &segment :
         storage.segments) {
        append_u64(encoding, segment.logical_begin);
        append_u64(encoding, segment.stored_begin);
        append_u64(encoding, segment.element_count);
    }
}

} // namespace

namespace detail {

const PoseidonPermutationR1csTemplate &
proof_of_packing_poseidon_permutation_template() {
    static const PoseidonPermutationR1csTemplate result = [] {
        ProofOfPackingR1csLayout layout;
        layout.poseidon_rows_per_permutation =
            local_poseidon_rows_per_permutation();
        layout.ciphertext_permutations_per_hash = 1;
        layout.ciphertext_permutations = 1;
        layout.largest_ciphertext_segment = 1;
        layout.rows.ciphertext_poseidon = {
            0, layout.poseidon_rows_per_permutation,
            layout.poseidon_rows_per_permutation};
        layout.witness.ciphertext_poseidon_auxiliary = {
            kPoseidonWidth + kPoseidonRate,
            layout.poseidon_rows_per_permutation,
            layout.poseidon_rows_per_permutation};
        layout.ciphertext_segments.push_back(
            ProofOfPackingPoseidonSegment{
                .permutation_begin = 0,
                .permutations = 1,
                .row_begin = 0,
                .input_witness_begin = 0,
                .auxiliary_witness_begin =
                    kPoseidonWidth + kPoseidonRate,
            });

        PoseidonPermutationR1csTemplate generated;
        PoseidonR1csSynthesizer synthesizer(
            0, layout, &generated.a, &generated.b, &generated.c, nullptr);
        generated.final_auxiliary =
            synthesizer.synthesize_template_permutation();
        generated.rows = synthesizer.constraints();
        if (generated.rows != layout.poseidon_rows_per_permutation ||
            synthesizer.auxiliary_count() != generated.rows) {
            throw std::logic_error(
                "Poseidon local template has inconsistent dimensions");
        }
        return generated;
    }();
    return result;
}

} // namespace detail

ProofOfPackingWitnessStorageLayout
proof_of_packing_witness_storage_layout(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata) {
    validate_plan(plan);
    const ProofOfPackingR1csLayout layout =
        make_proof_of_packing_r1cs_layout(plan);
    validate_assignment_metadata(circuit_metadata, layout);
    return make_witness_storage_layout(plan, circuit_metadata, layout);
}

std::uint64_t proof_of_packing_assignment_artifact_physical_bytes(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata) {
    const ProofOfPackingWitnessStorageLayout witness =
        proof_of_packing_witness_storage_layout(plan, circuit_metadata);
    const std::array<storage::NativeFieldArrayLayout, 2> arrays{{
        {std::string(kProofOfPackingAssignmentPublicInputs),
         storage::NativeFieldElementKind::Fq,
         circuit_metadata.shape().public_inputs},
        {std::string(kProofOfPackingAssignmentWitnessValues),
         storage::NativeFieldElementKind::Fq,
         witness.stored_elements},
    }};
    return storage::native_field_artifact_physical_bytes(arrays);
}

struct ProofOfPackingWitnessReader::Impl {
    Impl(const OuterRelationPlan &plan,
         const spartan::R1csMetadata &circuit_metadata,
         const storage::NativeFieldArtifact &artifact)
        : storage_layout(proof_of_packing_witness_storage_layout(
              plan, circuit_metadata)),
          reader(artifact.open_array(
              kProofOfPackingAssignmentWitnessValues)) {
        const storage::NativeFieldArrayDescriptor &public_inputs =
            artifact.array(kProofOfPackingAssignmentPublicInputs);
        const storage::NativeFieldArrayDescriptor &witness_values =
            artifact.array(kProofOfPackingAssignmentWitnessValues);
        if (artifact.arrays().size() != 2 ||
            public_inputs.kind !=
                storage::NativeFieldElementKind::Fq ||
            witness_values.kind !=
                storage::NativeFieldElementKind::Fq ||
            public_inputs.element_count !=
                circuit_metadata.shape().public_inputs ||
            witness_values.element_count !=
                storage_layout.stored_elements ||
            reader.kind() != storage::NativeFieldElementKind::Fq ||
            reader.size() != storage_layout.stored_elements) {
            throw std::invalid_argument(
                "proof-of-packing witness artifact has the wrong layout");
        }
    }

    ProofOfPackingWitnessStorageLayout storage_layout;
    storage::NativeFieldArrayReader reader;
};

ProofOfPackingWitnessReader::ProofOfPackingWitnessReader(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &artifact)
    : impl_(std::make_unique<Impl>(plan, circuit_metadata, artifact)) {}

ProofOfPackingWitnessReader::~ProofOfPackingWitnessReader() = default;
ProofOfPackingWitnessReader::ProofOfPackingWitnessReader(
    ProofOfPackingWitnessReader &&) noexcept = default;
ProofOfPackingWitnessReader &ProofOfPackingWitnessReader::operator=(
    ProofOfPackingWitnessReader &&) noexcept = default;

std::uint64_t ProofOfPackingWitnessReader::size() const {
    return impl_->storage_layout.logical_elements;
}

std::uint64_t ProofOfPackingWitnessReader::stored_size() const {
    return impl_->storage_layout.stored_elements;
}

const ProofOfPackingWitnessStorageLayout &
ProofOfPackingWitnessReader::layout() const {
    return impl_->storage_layout;
}

ProofOfPackingWitnessReadReport
ProofOfPackingWitnessReader::read_at(
    std::uint64_t logical_begin, std::span<Fq> output) {
    const std::uint64_t output_size = checked_size(
        output.size(), "logical witness read size");
    if (logical_begin > size() || output_size > size() - logical_begin) {
        throw std::out_of_range(
            "proof-of-packing witness read is out of range");
    }
    std::fill(output.begin(), output.end(), Fq::zero());
    ProofOfPackingWitnessReadReport report;
    if (output.empty()) {
        return report;
    }
    const std::uint64_t logical_end = logical_begin + output_size;
    const auto &segments = impl_->storage_layout.segments;
    auto segment = std::lower_bound(
        segments.begin(), segments.end(), logical_begin,
        [](const ProofOfPackingWitnessStorageSegment &candidate,
           std::uint64_t position) {
            return candidate.logical_begin + candidate.element_count <=
                   position;
        });
    for (; segment != segments.end() &&
           segment->logical_begin < logical_end;
         ++segment) {
        const std::uint64_t segment_end =
            segment->logical_begin + segment->element_count;
        const std::uint64_t overlap_begin =
            std::max(logical_begin, segment->logical_begin);
        const std::uint64_t overlap_end =
            std::min(logical_end, segment_end);
        if (overlap_begin >= overlap_end) {
            continue;
        }
        const std::uint64_t source_begin = checked_add(
            segment->stored_begin,
            overlap_begin - segment->logical_begin,
            "compact witness read source");
        if (impl_->reader.position() != source_begin) {
            impl_->reader.seek(source_begin);
            report.seek_operations = checked_add(
                report.seek_operations, 1,
                "compact witness seek operations");
        }
        const std::size_t destination_begin = as_size(
            overlap_begin - logical_begin,
            "logical witness output begin");
        const std::size_t count = as_size(
            overlap_end - overlap_begin,
            "logical witness overlap size");
        std::size_t consumed = 0;
        while (consumed < count) {
            const std::size_t read = impl_->reader.read(
                output.subspan(destination_begin + consumed,
                               count - consumed));
            if (read == 0) {
                throw std::runtime_error(
                    "compact proof-of-packing witness ended early");
            }
            consumed += read;
            report.stored_elements = checked_add(
                report.stored_elements,
                checked_size(read, "compact witness read elements"),
                "compact witness read elements");
            report.read_operations = checked_add(
                report.read_operations, 1,
                "compact witness read operations");
        }
    }
    return report;
}

static ProofOfPackingR1csLedger proof_of_packing_r1cs_ledger_impl(
    const OuterRelationPlan &plan, bool include_nonzero_entries) {
    validate_plan(plan);
    const ProofOfPackingR1csLayout layout =
        make_proof_of_packing_r1cs_layout(plan);
    const std::uint64_t aligned = checked_size(
        plan.shape.aligned_ciphertexts, "aligned ciphertext count");
    const std::uint64_t degree =
        checked_size(plan.shape.ring_degree, "ring degree");
    const std::uint64_t preimage = checked_add(
        checked_mul(2, degree, "ciphertext coordinates"),
        gkr::kCiphertextCommitmentMetadataElements,
        "ciphertext Poseidon preimage");
    const bool use_poseidon =
        plan.shape.ciphertext_commitment_policy.relation ==
        gkr::CiphertextCommitmentRelation::PoseidonV2;
    const std::uint64_t sbox_constraints =
        use_poseidon
            ? poseidon_r1cs_constraints_for_field_elements(preimage)
            : 0;
    const std::uint64_t checkpoint_constraints =
        use_poseidon
            ? poseidon_r1cs_checkpoint_constraints_for_field_elements(
                  preimage)
            : 0;
    const std::uint64_t recurrence_constraints =
        use_poseidon ? 0 : checked_mul(2, degree,
                                      "diagnostic hash recurrence rows");
    const std::uint64_t per_ciphertext = checked_add(
        checked_add(sbox_constraints, checkpoint_constraints,
                    "ciphertext commitment constraints"),
        checked_add(recurrence_constraints, kPoseidonDigestElements,
                    "ciphertext commitment constraints"),
        "ciphertext commitment constraints");
    const std::uint64_t ciphertext_commitment_constraints = checked_mul(
        aligned, per_ciphertext,
        "all ciphertext commitment constraints");
    const std::uint64_t ciphertext_poseidon_constraints = checked_mul(
        aligned, use_poseidon ? per_ciphertext : 0,
        "all ciphertext Poseidon constraints");
    const std::uint64_t poseidon_nonzero_per_ciphertext =
        use_poseidon && include_nonzero_entries
        ? poseidon_nonzero_entries_per_ciphertext(plan, layout)
        : 0;
    const std::uint64_t ciphertext_poseidon_nonzero_entries = checked_mul(
        aligned, poseidon_nonzero_per_ciphertext,
        "all ciphertext Poseidon sparse entries");
    const std::uint64_t commitment_nonzero_per_ciphertext =
        !include_nonzero_entries
            ? 0
            : use_poseidon ? poseidon_nonzero_per_ciphertext
                           : checked_mul(
                                 4,
                                 checked_add(
                                     recurrence_constraints,
                                     kPoseidonDigestElements,
                                     "diagnostic hash row count"),
                                 "diagnostic hash sparse entries");
    const std::uint64_t ciphertext_commitment_nonzero_entries = checked_mul(
        aligned, commitment_nonzero_per_ciphertext,
        "all ciphertext commitment sparse entries");
    const OuterRelationR1csSize packing_size =
        estimate_outer_relation_r1cs_size(plan);
    const std::uint64_t commitment_logical_inputs = checked_mul(
        aligned, kPoseidonDigestElements, "commitment logical inputs");
    const std::uint64_t total_logical_inputs = checked_add(
        commitment_logical_inputs, plan.variables.public_inputs.total,
        "all logical public inputs");
    const std::uint64_t ciphertext_poseidon_auxiliary = checked_mul(
        aligned,
        use_poseidon
            ? checked_add(sbox_constraints, checkpoint_constraints,
                          "ciphertext Poseidon auxiliary witness")
            : 0,
        "ciphertext Poseidon auxiliary witness");
    const std::uint64_t ciphertext_commitment_auxiliary = checked_mul(
        aligned,
        use_poseidon
            ? checked_add(sbox_constraints, checkpoint_constraints,
                          "ciphertext commitment auxiliary witness")
            : recurrence_constraints,
        "ciphertext commitment auxiliary witness");
    const std::uint64_t active_witness_variables = checked_add(
        plan.variables.witness.total, ciphertext_commitment_auxiliary,
        "active proof-of-packing witnesses");
    return ProofOfPackingR1csLedger{
        .aligned_ciphertexts = aligned,
        .ciphertext_preimage_field_elements = preimage,
        .ciphertext_commitment_constraints_per_ciphertext =
            per_ciphertext,
        .ciphertext_commitment_constraints =
            ciphertext_commitment_constraints,
        .poseidon_sbox_constraints_per_ciphertext = sbox_constraints,
        .poseidon_checkpoint_constraints_per_ciphertext =
            checkpoint_constraints,
        .poseidon_output_constraints_per_ciphertext =
            use_poseidon ? kPoseidonDigestElements : 0,
        .ciphertext_poseidon_constraints =
            ciphertext_poseidon_constraints,
        .total_poseidon_constraints = ciphertext_poseidon_constraints,
        .packing_relation_constraints = plan.constraints.total,
        .total_constraints = checked_add(
            ciphertext_commitment_constraints, plan.constraints.total,
            "proof-of-packing constraints"),
        .matrix_rows = layout.rows.total,
        .ciphertext_poseidon_nonzero_entries_per_ciphertext =
            poseidon_nonzero_per_ciphertext,
        .ciphertext_poseidon_nonzero_entries =
            ciphertext_poseidon_nonzero_entries,
        .ciphertext_commitment_nonzero_entries_per_ciphertext =
            commitment_nonzero_per_ciphertext,
        .ciphertext_commitment_nonzero_entries =
            ciphertext_commitment_nonzero_entries,
        .packing_relation_nonzero_entries_upper_bound =
            include_nonzero_entries ? packing_size.total_nonzero_entries : 0,
        .total_nonzero_entries_upper_bound = checked_add(
            ciphertext_commitment_nonzero_entries,
            include_nonzero_entries ? packing_size.total_nonzero_entries : 0,
            "proof-of-packing sparse entries"),
        .nonzero_entry_counts_available = include_nonzero_entries,
        .commitment_logical_inputs = commitment_logical_inputs,
        .packing_logical_inputs = plan.variables.public_inputs.total,
        .total_logical_inputs = total_logical_inputs,
        .total_public_inputs = total_logical_inputs,
        .packing_witness_variables = plan.variables.witness.total,
        .ciphertext_poseidon_auxiliary_witness_variables =
            ciphertext_poseidon_auxiliary,
        .ciphertext_commitment_auxiliary_witness_variables =
            ciphertext_commitment_auxiliary,
        .active_witness_variables = active_witness_variables,
        .total_witness_variables = layout.witness.total,
    };
}

ProofOfPackingR1csLedger
proof_of_packing_r1cs_ledger(const OuterRelationPlan &plan) {
    return proof_of_packing_r1cs_ledger_impl(plan, true);
}

ProofOfPackingR1csLedger
proof_of_packing_r1cs_dimension_ledger(const OuterRelationPlan &plan) {
    return proof_of_packing_r1cs_ledger_impl(plan, false);
}

CompiledProofOfPackingR1cs compile_proof_of_packing_r1cs(
    const OuterRelationPlan &plan,
    const PackingLinearOperator &packing_operator,
    ProofOfPackingR1csEncoders encoders, BalancedRadix radix) {
    validate_plan(plan);
    packing_operator.validate();
    const ProofOfPackingR1csLedger ledger =
        proof_of_packing_r1cs_ledger(plan);
    const ProofOfPackingR1csLayout layout =
        make_proof_of_packing_r1cs_layout(plan);
    NativePackingOperator native_packing_operator =
        make_native_signed_digit_packing_operator(
            packing_operator, encoders.centered_coefficients,
            encoders.native_ntt, plan.shape.native_modulus, radix);
    std::vector<spartan::R1csEntry> a;
    std::vector<spartan::R1csEntry> b;
    std::vector<spartan::R1csEntry> c;

    // Step 1: bind every private aligned ciphertext to the corresponding
    // six-field commitment at the front of the public statement. Target
    // setups use Poseidon; diagnostic setups use the explicitly collisionable
    // sparse linear recurrence.
    const std::uint64_t coordinates_per_ciphertext = checked_mul(
        2, checked_size(plan.shape.ring_degree, "ring degree"),
        "coordinates per ciphertext");
    std::uint64_t ciphertext_commitment_constraints = 0;
    std::uint64_t ciphertext_commitment_auxiliaries = 0;
    std::uint64_t ciphertext_commitment_nonzero_entries = 0;
    if (plan.shape.ciphertext_commitment_policy.relation ==
        gkr::CiphertextCommitmentRelation::PoseidonV2) {
        PoseidonR1csSynthesizer poseidon(
            ledger.total_public_inputs, layout, &a, &b, &c, nullptr);
        for (std::uint64_t ciphertext = 0;
             ciphertext < ledger.aligned_ciphertexts; ++ciphertext) {
            std::vector<std::uint64_t> coordinate_indices(
                as_size(coordinates_per_ciphertext,
                        "ciphertext coordinate count"));
            for (std::uint64_t coordinate = 0;
                 coordinate < coordinates_per_ciphertext; ++coordinate) {
                coordinate_indices[as_size(coordinate,
                                           "coordinate index")] =
                    layout.aligned_coordinate_witness_index(
                        plan, as_size(ciphertext, "ciphertext index"),
                        as_size(coordinate, "coordinate index") /
                            plan.shape.ring_degree,
                        as_size(coordinate, "coordinate index") %
                            plan.shape.ring_degree);
            }
            poseidon.synthesize_ciphertext(
                plan.shape.ring_degree, ciphertext, coordinate_indices,
                {}, {});
        }
        ciphertext_commitment_constraints = poseidon.constraints();
        ciphertext_commitment_auxiliaries = poseidon.auxiliary_count();
        ciphertext_commitment_nonzero_entries =
            poseidon.nonzero_entries();
    } else {
        for (std::uint64_t ciphertext = 0;
             ciphertext < ledger.aligned_ciphertexts; ++ciphertext) {
            std::vector<std::uint64_t> coordinate_indices(
                as_size(coordinates_per_ciphertext,
                        "ciphertext coordinate count"));
            for (std::uint64_t coordinate = 0;
                 coordinate < coordinates_per_ciphertext; ++coordinate) {
                coordinate_indices[as_size(coordinate,
                                           "coordinate index")] =
                    layout.aligned_coordinate_witness_index(
                        plan, as_size(ciphertext, "ciphertext index"),
                        as_size(coordinate, "coordinate index") /
                            plan.shape.ring_degree,
                        as_size(coordinate, "coordinate index") %
                            plan.shape.ring_degree);
            }
            const SimpleCtHashSynthesisResult simple =
                synthesize_ciphertext_simple_hash(
                    plan, ledger, layout, ciphertext,
                    coordinate_indices, {}, {}, &a, &b, &c, nullptr);
            ciphertext_commitment_constraints = checked_add(
                ciphertext_commitment_constraints, simple.constraints,
                "diagnostic ciphertext-hash constraints");
            ciphertext_commitment_auxiliaries = checked_add(
                ciphertext_commitment_auxiliaries,
                simple.auxiliary_count,
                "diagnostic ciphertext-hash auxiliaries");
            ciphertext_commitment_nonzero_entries = checked_add(
                ciphertext_commitment_nonzero_entries,
                simple.nonzero_entries,
                "diagnostic ciphertext-hash sparse entries");
        }
    }
    if (ciphertext_commitment_constraints !=
            ledger.ciphertext_commitment_constraints ||
        ciphertext_commitment_auxiliaries !=
            ledger.ciphertext_commitment_auxiliary_witness_variables ||
        ciphertext_commitment_nonzero_entries !=
            ledger.ciphertext_commitment_nonzero_entries) {
        throw std::logic_error(
            "ciphertext commitment ledger disagrees with synthesis");
    }

    // Step 2: append the four regular packing-relation families.
    OuterRelationR1csCursor dynamic_rows(
        plan, 0, plan.constraints.revealed_packing_equalities.begin);
    while (!dynamic_rows.empty()) {
        append_outer_row(dynamic_rows.next(), plan, ledger, layout,
                         a, b, c);
    }

    // Step 3: stream the large fixed signed-digit NTT family.
    FixedPackingR1csEntryCursor fixed(
        plan, packing_operator,
        FixedPackingR1csEntryCursor::Encoders{
            std::move(encoders.centered_coefficients),
            std::move(encoders.native_ntt)},
        std::move(radix));
    while (!fixed.empty()) {
        const OuterRelationR1csMatrixEntry entry = fixed.next();
        select_matrix(entry.matrix, a, b, c)
            ->push_back(spartan::R1csEntry{
                layout.outer_constraint_row(plan,
                                            entry.constraint_index),
                conventional_column(entry.variable, plan, ledger,
                                    layout),
                Fq(entry.coefficient)});
    }
    const FixedPackingR1csStreamStatistics statistics = fixed.statistics();
    if (!statistics.complete) {
        throw std::logic_error("fixed packing R1CS stream did not finish");
    }

    // Step 4: canonicalize and cross-check the completed matrices.
    spartan::R1csInstance circuit(
        spartan::R1csShape{
            .constraints = ledger.matrix_rows,
            .public_inputs = ledger.total_public_inputs,
            .witness_variables = ledger.total_witness_variables,
        },
        std::move(a), std::move(b), std::move(c));
    const OuterRelationR1csSize packing_size =
        estimate_outer_relation_r1cs_size(plan);
    if (packing_size.total_nonzero_entries <
        packing_size.packing_a_entries) {
        throw std::logic_error(
            "packing sparse-entry ledger is internally inconsistent");
    }
    const std::uint64_t exact_packing_entries = checked_add(
        packing_size.total_nonzero_entries -
            packing_size.packing_a_entries,
        statistics.a_nonzero_entries,
        "exact packing sparse entries");
    const std::uint64_t exact_total_entries = checked_add(
        ciphertext_commitment_nonzero_entries,
        exact_packing_entries,
        "exact proof-of-packing sparse entries");
    if (circuit.nonzero_entries() != exact_total_entries ||
        exact_total_entries > ledger.total_nonzero_entries_upper_bound) {
        throw std::logic_error(
            "proof-of-packing sparse-entry ledger disagrees with synthesis");
    }
    return CompiledProofOfPackingR1cs{
        std::move(circuit), ledger, layout,
        std::move(native_packing_operator), statistics};
}

std::vector<Fq> proof_of_packing_commitment_logical_inputs(
    std::span<const gkr::HashCommitCT> commitments) {
    std::vector<Fq> result;
    if (commitments.size() >
        std::numeric_limits<std::size_t>::max() /
            kPoseidonDigestElements) {
        throw std::overflow_error("packing commitment input count overflows");
    }
    result.reserve(commitments.size() * kPoseidonDigestElements);
    for (const gkr::HashCommitCT &commitment : commitments) {
        const auto fields =
            gkr::hash_commitment_field_elements(commitment);
        result.insert(result.end(), fields.begin(), fields.end());
    }
    return result;
}

std::vector<Fq> make_proof_of_packing_logical_inputs(
    const OuterRelationPlan &plan,
    std::span<const gkr::HashCommitCT> commitments,
    const OuterRelationPublicInputs &packing_public_inputs) {
    validate_plan(plan);
    if (commitments.size() !=
            as_size(plan.shape.aligned_ciphertexts,
                    "aligned ciphertext count") ||
        packing_public_inputs.packed_challenge_words.size() !=
            as_size(plan.variables.public_inputs
                        .packed_challenge_words.count,
                    "packed challenge word count") ||
        packing_public_inputs.revealed_test_coordinates.size() !=
            as_size(plan.variables.public_inputs
                        .revealed_test_coordinates.count,
                    "revealed test coordinate count") ||
        packing_public_inputs.revealed_packing_coordinates.size() !=
            as_size(plan.variables.public_inputs
                        .revealed_packing_coordinates.count,
                    "revealed packing coordinate count")) {
        throw std::invalid_argument(
            "proof-of-packing public inputs have inconsistent dimensions");
    }

    std::vector<Fq> result =
        proof_of_packing_commitment_logical_inputs(commitments);
    const std::uint64_t total_logical_inputs = checked_add(
        checked_mul(checked_size(commitments.size(), "commitment count"),
                    kPoseidonDigestElements,
                    "commitment logical inputs"),
        plan.variables.public_inputs.total, "total logical input count");
    result.reserve(as_size(total_logical_inputs,
                           "total logical input count"));
    const auto append = [&](std::span<const std::uint64_t> values) {
        for (const std::uint64_t value : values) {
            if (value >= kOuterFieldOrder) {
                throw std::invalid_argument(
                    "proof-of-packing public input is noncanonical");
            }
            result.emplace_back(value);
        }
    };
    append(packing_public_inputs.packed_challenge_words);
    append(packing_public_inputs.revealed_test_coordinates);
    append(packing_public_inputs.revealed_packing_coordinates);
    if (result.size() !=
        as_size(total_logical_inputs,
                "total logical input count")) {
        throw std::logic_error(
            "proof-of-packing logical input ledger disagrees with layout");
    }
    return result;
}

std::vector<Fq> make_proof_of_packing_public_inputs(
    const OuterRelationPlan &plan,
    std::span<const gkr::HashCommitCT> commitments,
    const OuterRelationPublicInputs &packing_public_inputs) {
    return make_proof_of_packing_logical_inputs(
        plan, commitments, packing_public_inputs);
}

spartan::R1csAssignment make_proof_of_packing_r1cs_assignment(
    const OuterRelationPlan &plan,
    std::span<const gkr::HashCommitCT> commitments,
    const OuterRelationR1csAssignmentView &packing_assignment) {
    validate_plan(plan);
    const ProofOfPackingR1csLedger ledger =
        proof_of_packing_r1cs_ledger(plan);
    const ProofOfPackingR1csLayout layout =
        make_proof_of_packing_r1cs_layout(plan);
    if (commitments.size() != as_size(
                                  ledger.aligned_ciphertexts,
                                  "aligned ciphertext count") ||
        &packing_assignment.plan() != &plan) {
        throw std::invalid_argument(
            "proof-of-packing assignment has inconsistent dimensions");
    }

    // Step 1: materialize only Spartan's required public/witness vectors. The
    // outer view continues to derive implicit zero slices and products on
    // demand, so no separate flattened outer assignment is retained.
    spartan::R1csAssignment result;
    result.public_inputs =
        proof_of_packing_commitment_logical_inputs(commitments);
    result.public_inputs.reserve(
        as_size(ledger.total_logical_inputs,
                "total logical input count"));
    OuterRelationPublicValueCursor public_cursor(packing_assignment);
    while (!public_cursor.empty()) {
        const OuterRelationPublicValue item = public_cursor.next();
        const std::uint64_t value = item.value;
        if (value >= kOuterFieldOrder) {
            throw std::invalid_argument(
                "packing public input is not a native-field residue");
        }
        result.public_inputs.emplace_back(value);
    }
    if (result.public_inputs.size() !=
        as_size(ledger.total_logical_inputs,
                "total logical input count")) {
        throw std::logic_error(
            "proof-of-packing logical input ledger disagrees with layout");
    }
    result.witness.assign(
        as_size(ledger.total_witness_variables, "total witness count"),
        Fq::zero());
    OuterRelationWitnessValueCursor witness_cursor(packing_assignment);
    while (!witness_cursor.empty()) {
        const OuterRelationWitnessValue item = witness_cursor.next();
        const std::uint64_t value = item.value;
        if (value >= kOuterFieldOrder) {
            throw std::invalid_argument(
                "packing witness is not a native-field residue");
        }
        result.witness.at(as_size(
            layout.outer_witness_index(plan, item.index),
            "structured packing witness index")) = Fq(value);
    }

    // Step 2: append auxiliary wires proving that every aligned ciphertext
    // opens the corresponding public commitment under the setup-bound
    // relation policy.
    std::unique_ptr<PoseidonR1csSynthesizer> poseidon;
    if (plan.shape.ciphertext_commitment_policy.relation ==
        gkr::CiphertextCommitmentRelation::PoseidonV2) {
        poseidon = std::make_unique<PoseidonR1csSynthesizer>(
            ledger.total_public_inputs, layout, nullptr, nullptr, nullptr,
            &result.witness);
    }
    std::uint64_t commitment_constraints = 0;
    std::uint64_t commitment_auxiliaries = 0;
    const std::uint64_t coordinates_per_ciphertext = checked_mul(
        2, checked_size(plan.shape.ring_degree, "ring degree"),
        "coordinates per ciphertext");
    for (std::uint64_t ciphertext = 0;
         ciphertext < ledger.aligned_ciphertexts; ++ciphertext) {
        std::vector<std::uint64_t> coordinate_indices(
            as_size(coordinates_per_ciphertext,
                    "ciphertext coordinate count"));
        std::vector<Fq> coordinate_values(coordinate_indices.size());
        std::vector<std::uint64_t> native_coordinates(
            coordinate_indices.size());
        for (std::uint64_t coordinate = 0;
             coordinate < coordinates_per_ciphertext; ++coordinate) {
            const std::uint64_t witness_index = checked_add(
                plan.variables.witness.aligned_ciphertext_coordinates.begin,
                checked_add(
                    checked_mul(ciphertext, coordinates_per_ciphertext,
                                "aligned coordinate base"),
                    coordinate, "aligned coordinate index"),
                "aligned coordinate witness index");
            coordinate_indices[as_size(coordinate, "coordinate index")] =
                layout.outer_witness_index(plan, witness_index);
            const std::uint64_t value =
                packing_assignment.witness_value(witness_index);
            native_coordinates[as_size(coordinate, "coordinate index")] =
                value;
            coordinate_values[as_size(coordinate, "coordinate index")] =
                Fq(value);
        }
        if (gkr::hash_commit_normalized_ciphertext_coordinates(
                plan.shape.ring_degree, native_coordinates,
                plan.shape.ciphertext_commitment_policy) !=
            commitments[as_size(ciphertext, "ciphertext index")]) {
            throw std::invalid_argument(
                "aligned coordinates do not match their commitment");
        }
        const auto digest = gkr::hash_commitment_field_elements(
            commitments[as_size(ciphertext, "ciphertext index")]);
        if (poseidon != nullptr) {
            poseidon->synthesize_ciphertext(
                plan.shape.ring_degree, ciphertext, coordinate_indices,
                coordinate_values, digest);
        } else {
            const SimpleCtHashSynthesisResult simple =
                synthesize_ciphertext_simple_hash(
                    plan, ledger, layout, ciphertext,
                    coordinate_indices, coordinate_values, digest,
                    nullptr, nullptr, nullptr, &result.witness);
            commitment_constraints = checked_add(
                commitment_constraints, simple.constraints,
                "diagnostic ciphertext-hash constraints");
            commitment_auxiliaries = checked_add(
                commitment_auxiliaries, simple.auxiliary_count,
                "diagnostic ciphertext-hash auxiliaries");
        }
    }
    if (poseidon != nullptr) {
        commitment_constraints = poseidon->constraints();
        commitment_auxiliaries = poseidon->auxiliary_count();
    }

    if (commitment_constraints !=
            ledger.ciphertext_commitment_constraints ||
        commitment_auxiliaries !=
            ledger.ciphertext_commitment_auxiliary_witness_variables ||
        result.witness.size() !=
            as_size(ledger.total_witness_variables,
                    "total witness count")) {
        throw std::logic_error(
            "proof-of-packing commitment witness disagrees with its ledger");
    }
    return result;
}

namespace reference {

spartan::R1csAssignment make_materialized_proof_of_packing_assignment(
    const OuterRelationPlan &plan,
    std::span<const gkr::HashCommitCT> commitments,
    const OuterRelationR1csAssignment &packing_assignment) {
    validate_plan(plan);
    const ProofOfPackingR1csLedger ledger =
        proof_of_packing_r1cs_ledger(plan);
    if (packing_assignment.public_inputs.size() !=
            as_size(ledger.packing_logical_inputs,
                    "packing logical input count") ||
        packing_assignment.witness.size() !=
            as_size(ledger.packing_witness_variables,
                    "packing witness count")) {
        throw std::invalid_argument(
            "proof-of-packing assignment has inconsistent dimensions");
    }
    for (const std::uint64_t value : packing_assignment.witness) {
        if (value >= kOuterFieldOrder) {
            throw std::invalid_argument(
                "packing witness is not a native-field residue");
        }
    }

    const std::span<const std::uint64_t> public_values(
        packing_assignment.public_inputs);
    const std::span<const std::uint64_t> witness_values(
        packing_assignment.witness);
    const auto public_slice = [&](const OuterRelationRange &range) {
        return public_values.subspan(
            as_size(range.begin, "public range begin"),
            as_size(range.count, "public range count"));
    };
    OuterRelationR1csInputSlices slices;
    slices.packed_challenge_words = public_slice(
        plan.variables.public_inputs.packed_challenge_words);
    const std::size_t width = plan.coordinates_per_ciphertext();
    const auto append_ciphertexts = [width](
        std::vector<OuterRelationCiphertextCoordinateSlice> &destination,
        std::span<const std::uint64_t> coordinates,
        std::size_t count) {
        destination.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            destination.push_back(
                OuterRelationCiphertextCoordinateSlice::borrowed(
                    coordinates.subspan(index * width, width)));
        }
    };
    append_ciphertexts(
        slices.revealed_test_ciphertexts,
        public_slice(
            plan.variables.public_inputs.revealed_test_coordinates),
        plan.shape.repetitions);
    append_ciphertexts(
        slices.revealed_packing_ciphertexts,
        public_slice(
            plan.variables.public_inputs.revealed_packing_coordinates),
        plan.physical_packed_ciphertexts());
    const OuterRelationRange aligned_range =
        plan.variables.witness.aligned_ciphertext_coordinates;
    append_ciphertexts(
        slices.aligned_ciphertexts,
        witness_values.subspan(
            as_size(aligned_range.begin, "aligned witness begin"),
            as_size(aligned_range.count, "aligned witness count")),
        plan.shape.aligned_ciphertexts);

    const OuterRelationR1csAssignmentView view(plan, std::move(slices));
    spartan::R1csAssignment result =
        make_proof_of_packing_r1cs_assignment(
            plan, commitments, view);

    // Reference tests may deliberately supply malformed auxiliary values.
    // Preserve those values after the production borrowed builder has
    // synthesized its canonical witness.
    const ProofOfPackingR1csLayout layout =
        make_proof_of_packing_r1cs_layout(plan);
    for (std::uint64_t index = 0;
         index < ledger.packing_witness_variables; ++index) {
        result.witness.at(as_size(
            layout.outer_witness_index(plan, index),
            "structured packing witness index")) =
            Fq(packing_assignment.witness[as_size(
                index, "packing witness index")]);
    }
    return result;
}

} // namespace reference

Digest proof_of_packing_assignment_artifact_identity(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &outer_assignment,
    std::span<const gkr::HashCommitCT> commitments) {
    const ProofOfPackingR1csLayout layout = validate_assignment_inputs(
        plan, circuit_metadata, outer_assignment, commitments);
    const ProofOfPackingWitnessStorageLayout witness_storage =
        make_witness_storage_layout(plan, circuit_metadata, layout);

    std::vector<std::uint8_t> encoding(
        kAssignmentArtifactIdentityDomain.begin(),
        kAssignmentArtifactIdentityDomain.end());
    append_bytes(encoding,
                 outer_relation_assignment_artifact_identity(plan));
    append_metadata_identity(encoding, circuit_metadata);
    append_witness_storage_identity(encoding, witness_storage);
    append_bytes(encoding, outer_assignment.identity());
    append_u64(encoding, outer_assignment.physical_bytes());
    append_u64(encoding, checked_size(outer_assignment.arrays().size(),
                                      "outer assignment array count"));
    append_array_identity(
        encoding, outer_assignment.array(kAssignmentPublicInputsArray));
    append_array_identity(encoding, outer_assignment.array("witness"));
    append_u64(encoding,
               checked_size(commitments.size(), "commitment count"));
    for (const gkr::HashCommitCT &commitment : commitments) {
        append_bytes(encoding, commitment.digest);
    }
    return sha256(encoding);
}

std::shared_ptr<const storage::NativeFieldArtifact>
open_proof_of_packing_assignment_artifact(
    const std::filesystem::path &directory,
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &outer_assignment,
    std::span<const gkr::HashCommitCT> commitments) {
    const Digest identity = proof_of_packing_assignment_artifact_identity(
        plan, circuit_metadata, outer_assignment, commitments);
    auto artifact = std::make_shared<storage::NativeFieldArtifact>(
        storage::NativeFieldArtifact::open(directory, identity));
    const ProofOfPackingWitnessStorageLayout witness_storage =
        proof_of_packing_witness_storage_layout(plan, circuit_metadata);
    const auto &public_inputs =
        artifact->array(kAssignmentPublicInputsArray);
    const auto &witness_values =
        artifact->array(kAssignmentWitnessValuesArray);
    if (artifact->arrays().size() != 2 ||
        public_inputs.kind != storage::NativeFieldElementKind::Fq ||
        witness_values.kind != storage::NativeFieldElementKind::Fq ||
        public_inputs.element_count !=
            circuit_metadata.shape().public_inputs ||
        witness_values.element_count != witness_storage.stored_elements) {
        throw std::invalid_argument(
            "proof-of-packing assignment artifact has the wrong layout");
    }
    return artifact;
}

ProofOfPackingAssignmentArtifactPlan
plan_proof_of_packing_assignment_artifact(
    const OuterRelationPlan &plan,
    const ProofOfPackingR1csLayout &layout,
    const spartan::R1csMetadata &circuit_metadata,
    std::uint64_t max_working_bytes,
    std::size_t requested_block_elements) {
    if (max_working_bytes == 0 || requested_block_elements == 0) {
        throw std::invalid_argument(
            "assignment planning needs explicit nonzero memory limits");
    }
    const std::uint64_t coordinates_per_ciphertext = checked_mul(
        plan.shape.ciphertext_components,
        checked_size(plan.shape.ring_degree, "ring degree"),
        "coordinates per ciphertext");
    const std::uint64_t aligned_ciphertexts = checked_size(
        plan.shape.aligned_ciphertexts, "aligned ciphertext count");
    if (layout.witness.ciphertext_poseidon_auxiliary.live %
            aligned_ciphertexts != 0) {
        throw std::logic_error(
            "proof-of-packing commitment auxiliary layout is uneven");
    }
    const std::uint64_t auxiliaries_per_ciphertext =
        layout.witness.ciphertext_poseidon_auxiliary.live /
        aligned_ciphertexts;
    if (checked_mul(auxiliaries_per_ciphertext,
                    aligned_ciphertexts,
                    "all ciphertext auxiliaries") !=
        layout.witness.ciphertext_poseidon_auxiliary.live) {
        throw std::logic_error(
            "proof-of-packing auxiliary layout is inconsistent");
    }
    const std::uint64_t retained_field_elements = checked_add(
        coordinates_per_ciphertext, auxiliaries_per_ciphertext,
        "retained assignment fields");
    const std::uint64_t retained_field_bytes = checked_mul(
        retained_field_elements, sizeof(Fq),
        "retained assignment field bytes");
    const std::uint64_t minimum_working_bytes = checked_add(
        retained_field_bytes, sizeof(Fq),
        "minimum assignment working bytes");
    if (max_working_bytes < minimum_working_bytes) {
        throw std::invalid_argument(
            "proof-of-packing assignment memory limit cannot hold one "
            "ciphertext, its commitment advice, and one I/O value");
    }
    const std::uint64_t available_block_elements =
        (max_working_bytes - retained_field_bytes) / sizeof(Fq);
    const std::size_t block_elements = std::min(
        requested_block_elements,
        as_size(available_block_elements,
                "proof-of-packing assignment I/O block"));
    return {
        .physical_bytes =
            proof_of_packing_assignment_artifact_physical_bytes(
                plan, circuit_metadata),
        .retained_working_bytes = retained_field_bytes,
        .minimum_working_bytes = minimum_working_bytes,
        .effective_block_elements = block_elements,
        .peak_working_bytes = checked_add(
            retained_field_bytes,
            checked_mul(checked_size(block_elements,
                                     "assignment I/O block"),
                        sizeof(Fq), "assignment I/O block bytes"),
            "proof-of-packing peak working bytes"),
    };
}

ProofOfPackingAssignmentArtifact
write_proof_of_packing_assignment_artifact(
    const OuterRelationPlan &plan,
    const spartan::R1csMetadata &circuit_metadata,
    const storage::NativeFieldArtifact &outer_assignment,
    std::span<const gkr::HashCommitCT> commitments,
    ProofOfPackingAssignmentArtifactOptions options) {
    if (options.directory.empty() ||
        options.storage_limits.max_total_bytes == 0 ||
        options.storage_limits.min_free_bytes == 0 ||
        options.max_working_bytes == 0 ||
        options.block_elements == 0) {
        throw std::invalid_argument(
            "proof-of-packing assignment artifact requires explicit "
            "nonzero limits");
    }
    options.directory =
        std::filesystem::absolute(options.directory).lexically_normal();
    validate_empty_assignment_directory(options.directory);

    const ProofOfPackingR1csLayout layout = validate_assignment_inputs(
        plan, circuit_metadata, outer_assignment, commitments);
    const std::uint64_t witness_half_elements = checked_size(
        circuit_metadata.assignment_half_size(), "assignment half");
    const ProofOfPackingWitnessStorageLayout witness_storage =
        make_witness_storage_layout(plan, circuit_metadata, layout);
    const std::array<storage::NativeFieldArrayLayout, 2> artifact_layout{{
        {std::string(kAssignmentPublicInputsArray),
         storage::NativeFieldElementKind::Fq,
         circuit_metadata.shape().public_inputs},
        {std::string(kAssignmentWitnessValuesArray),
         storage::NativeFieldElementKind::Fq,
         witness_storage.stored_elements},
    }};
    const std::uint64_t expected_physical_bytes =
        storage::native_field_artifact_physical_bytes(artifact_layout);
    if (expected_physical_bytes >
        options.storage_limits.max_total_bytes) {
        throw std::invalid_argument(
            "proof-of-packing assignment quota is below its exact size");
    }
    const std::uint64_t required_free = checked_add(
        expected_physical_bytes, options.storage_limits.min_free_bytes,
        "proof-of-packing assignment free-space preflight");
    if (std::filesystem::space(options.directory).available <
        required_free) {
        throw std::runtime_error(
            "proof-of-packing assignment has insufficient free space");
    }

    const ProofOfPackingAssignmentArtifactPlan resource_plan =
        plan_proof_of_packing_assignment_artifact(
            plan, layout, circuit_metadata, options.max_working_bytes,
            options.block_elements);
    const std::size_t block_elements =
        resource_plan.effective_block_elements;
    const std::uint64_t coordinates_per_ciphertext = checked_mul(
        plan.shape.ciphertext_components,
        checked_size(plan.shape.ring_degree, "ring degree"),
        "coordinates per ciphertext");
    const std::uint64_t auxiliaries_per_ciphertext =
        layout.witness.ciphertext_poseidon_auxiliary.live /
        checked_size(plan.shape.aligned_ciphertexts,
                     "aligned ciphertext count");

    const std::uint64_t encoded_fq_bytes =
        storage::encoded_element_bytes(
            storage::NativeFieldElementKind::Fq);
    const std::uint64_t public_payload_bytes = checked_mul(
        circuit_metadata.shape().public_inputs, encoded_fq_bytes,
        "proof-of-packing public payload");
    const std::uint64_t logical_witness_payload_bytes = checked_mul(
        witness_half_elements, encoded_fq_bytes,
        "proof-of-packing logical witness payload");
    const std::uint64_t stored_witness_payload_bytes = checked_mul(
        witness_storage.stored_elements, encoded_fq_bytes,
        "proof-of-packing stored witness payload");
    const std::uint64_t active_witness_elements = checked_add(
        plan.variables.witness.total,
        layout.witness.ciphertext_poseidon_auxiliary.live,
        "active proof-of-packing witnesses");
    if (active_witness_elements != witness_storage.stored_elements ||
        active_witness_elements > witness_half_elements) {
        throw std::logic_error(
            "proof-of-packing active witness exceeds its Spartan half");
    }
    ProofOfPackingAssignmentArtifactReport report{
        .public_input_elements =
            circuit_metadata.shape().public_inputs,
        .witness_half_elements = witness_half_elements,
        .stored_witness_elements = witness_storage.stored_elements,
        .active_outer_witness_elements =
            plan.variables.witness.total,
        .ciphertext_commitment_auxiliary_elements =
            layout.witness.ciphertext_poseidon_auxiliary.live,
        .zero_witness_elements =
            witness_half_elements - active_witness_elements,
        .public_payload_bytes = public_payload_bytes,
        .logical_witness_payload_bytes =
            logical_witness_payload_bytes,
        .stored_witness_payload_bytes =
            stored_witness_payload_bytes,
        .physical_bytes = expected_physical_bytes,
        .sequential_output_payload_bytes = public_payload_bytes,
        .positional_output_payload_bytes =
            stored_witness_payload_bytes,
        .artifact_validation_bytes = expected_physical_bytes,
        .peak_working_bytes = resource_plan.peak_working_bytes,
    };

    const Digest identity = proof_of_packing_assignment_artifact_identity(
        plan, circuit_metadata, outer_assignment, commitments);
    AssignmentArtifactCleanup cleanup(options.directory);
    storage::NativeFieldArtifactWriter writer(
        options.directory, options.storage_limits, identity);
    std::vector<Fq> buffer(block_elements);
    std::vector<Fq> coordinates(
        as_size(coordinates_per_ciphertext,
                "coordinates per ciphertext"));
    std::vector<Fq> auxiliary_values;
    auxiliary_values.reserve(as_size(auxiliaries_per_ciphertext,
                                     "commitment auxiliary count"));

    const auto account_read = [&](std::size_t count) {
        report.source_read_payload_bytes = checked_add(
            report.source_read_payload_bytes,
            checked_mul(checked_size(count, "source read elements"),
                        encoded_fq_bytes, "source read bytes"),
            "source read bytes");
        report.source_read_operations = checked_add(
            report.source_read_operations, 1, "source read operations");
    };
    const auto read_exact = [&](storage::NativeFieldArrayReader &reader,
                                std::span<Fq> output) {
        std::size_t offset = 0;
        while (offset < output.size()) {
            const std::size_t count = reader.read(output.subspan(offset));
            if (count == 0) {
                throw std::runtime_error(
                    "proof-of-packing source ended unexpectedly");
            }
            account_read(count);
            offset += count;
        }
    };
    const auto seek_source = [&](storage::NativeFieldArrayReader &reader,
                                 std::uint64_t position) {
        if (reader.position() != position) {
            reader.seek(position);
            report.source_seek_operations = checked_add(
                report.source_seek_operations, 1,
                "source seek operations");
        }
    };
    const auto positional_write = [&](std::uint64_t logical_begin,
                                      std::span<const Fq> values) {
        if (values.empty()) {
            return;
        }
        const std::uint64_t value_count = checked_size(
            values.size(), "logical witness write size");
        if (logical_begin > witness_storage.logical_elements ||
            value_count > witness_storage.logical_elements - logical_begin) {
            throw std::logic_error(
                "proof-of-packing witness write is out of range");
        }
        const std::uint64_t logical_end = logical_begin + value_count;
        const auto &segments = witness_storage.segments;
        std::size_t source_cursor = 0;
        const auto require_omitted_zeros = [&](std::size_t end) {
            if (end < source_cursor || end > values.size() ||
                std::any_of(
                    values.begin() +
                        static_cast<std::ptrdiff_t>(source_cursor),
                    values.begin() + static_cast<std::ptrdiff_t>(end),
                    [](const Fq &value) { return !value.is_zero(); })) {
                throw std::logic_error(
                    "proof-of-packing omitted witness value is nonzero");
            }
            source_cursor = end;
        };
        auto segment = std::lower_bound(
            segments.begin(), segments.end(), logical_begin,
            [](const ProofOfPackingWitnessStorageSegment &candidate,
               std::uint64_t position) {
                return candidate.logical_begin + candidate.element_count <=
                       position;
            });
        for (; segment != segments.end() &&
               segment->logical_begin < logical_end;
             ++segment) {
            const std::uint64_t segment_end =
                segment->logical_begin + segment->element_count;
            const std::uint64_t overlap_begin =
                std::max(logical_begin, segment->logical_begin);
            const std::uint64_t overlap_end =
                std::min(logical_end, segment_end);
            if (overlap_begin >= overlap_end) {
                continue;
            }
            const std::uint64_t stored_begin = checked_add(
                segment->stored_begin,
                overlap_begin - segment->logical_begin,
                "stored witness write begin");
            const std::size_t source_begin = as_size(
                overlap_begin - logical_begin,
                "witness write source begin");
            const std::size_t count = as_size(
                overlap_end - overlap_begin,
                "witness write overlap size");
            require_omitted_zeros(source_begin);
            writer.write_fq_at(
                stored_begin, values.subspan(source_begin, count));
            source_cursor = source_begin + count;
            report.positional_output_write_operations = checked_add(
                report.positional_output_write_operations, 1,
                "positional output writes");
        }
        require_omitted_zeros(values.size());
    };
    const auto copy_source_range = [&](
        storage::NativeFieldArrayReader &reader,
        std::uint64_t source_begin, std::uint64_t destination_begin,
        std::uint64_t count) {
        seek_source(reader, source_begin);
        std::uint64_t copied = 0;
        while (copied < count) {
            const std::size_t block = std::min<std::uint64_t>(
                buffer.size(), count - copied);
            read_exact(reader, std::span<Fq>(buffer).first(block));
            positional_write(
                checked_add(destination_begin, copied,
                            "copy destination"),
                std::span<const Fq>(buffer).first(block));
            copied = checked_add(copied, checked_size(block, "copy block"),
                                 "copied source values");
        }
    };

    // The public half is already sequential: commitment fields precede the
    // complete canonical outer public input array.
    writer.begin_array(std::string(kAssignmentPublicInputsArray),
                       storage::NativeFieldElementKind::Fq,
                       circuit_metadata.shape().public_inputs);
    for (const gkr::HashCommitCT &commitment : commitments) {
        const auto fields =
            gkr::hash_commitment_field_elements(commitment);
        writer.append(std::span<const Fq>(fields));
    }
    storage::NativeFieldArrayReader public_reader =
        outer_assignment.open_array(kAssignmentPublicInputsArray);
    while (public_reader.position() < public_reader.size()) {
        const std::size_t count = std::min<std::uint64_t>(
            buffer.size(), public_reader.size() - public_reader.position());
        read_exact(public_reader, std::span<Fq>(buffer).first(count));
        writer.append(std::span<const Fq>(buffer).first(count));
    }
    writer.finish_array();

    // The private half retains its logical padded coordinates, but the file
    // contains only the canonical live support. Logical writes are projected
    // into that compact order; gaps and the Spartan tail are never written.
    writer.begin_positional_fq_array(
        std::string(kAssignmentWitnessValuesArray),
        witness_storage.stored_elements);
    storage::NativeFieldArrayReader witness_reader =
        outer_assignment.open_array("witness");

    const OuterRelationRange challenge_bits =
        plan.variables.witness.derived_challenge_bits;
    copy_source_range(witness_reader, challenge_bits.begin,
                      layout.witness.challenge_bits.begin,
                      challenge_bits.count);

    const std::uint64_t aligned_source_begin =
        plan.variables.witness.aligned_ciphertext_coordinates.begin;
    const std::uint64_t permutations_per_hash =
        layout.ciphertext_permutations_per_hash;
    const std::uint64_t rows_per_permutation =
        layout.poseidon_rows_per_permutation;
    for (std::uint64_t ciphertext = 0;
         ciphertext < commitments.size(); ++ciphertext) {
        const std::uint64_t coordinate_source = checked_add(
            aligned_source_begin,
            checked_mul(ciphertext, coordinates_per_ciphertext,
                        "ciphertext coordinate source"),
            "ciphertext coordinate source");
        seek_source(witness_reader, coordinate_source);
        read_exact(witness_reader, coordinates);

        const auto digest =
            plan.shape.ciphertext_commitment_policy.relation ==
                    gkr::CiphertextCommitmentRelation::PoseidonV2
                ? synthesize_ciphertext_poseidon_values(
                      plan.shape.ring_degree, coordinates,
                      auxiliary_values)
                : synthesize_ciphertext_simple_hash_values(
                      plan.shape.ring_degree, coordinates,
                      auxiliary_values);
        if (digest != gkr::hash_commitment_field_elements(
                          commitments[as_size(ciphertext,
                                              "commitment index")])) {
            throw std::invalid_argument(
                "aligned coordinates do not match their commitment");
        }
        if (auxiliary_values.size() !=
            as_size(auxiliaries_per_ciphertext,
                    "commitment auxiliary count")) {
            throw std::logic_error(
                "ciphertext commitment advice has the wrong length");
        }

        const std::uint64_t ciphertext_permutation_begin = checked_mul(
            ciphertext, permutations_per_hash,
            "ciphertext permutation begin");
        const std::uint64_t ciphertext_permutation_end = checked_add(
            ciphertext_permutation_begin, permutations_per_hash,
            "ciphertext permutation end");
        for (const ProofOfPackingPoseidonSegment &segment :
             layout.ciphertext_segments) {
            const std::uint64_t intersection_begin = std::max(
                ciphertext_permutation_begin, segment.permutation_begin);
            const std::uint64_t intersection_end = std::min(
                ciphertext_permutation_end, segment.permutation_end());
            if (intersection_begin >= intersection_end) {
                continue;
            }

            for (std::uint64_t rate = 0; rate < kPoseidonRate; ++rate) {
                std::uint64_t permutation = intersection_begin;
                while (permutation < intersection_end) {
                    const std::size_t count = std::min<std::uint64_t>(
                        buffer.size(), intersection_end - permutation);
                    for (std::size_t offset = 0; offset < count; ++offset) {
                        const std::uint64_t global_permutation = checked_add(
                            permutation, checked_size(offset, "rate offset"),
                            "rate permutation");
                        const std::uint64_t local_permutation =
                            global_permutation -
                            ciphertext_permutation_begin;
                        const std::uint64_t input = checked_add(
                            checked_mul(local_permutation, kPoseidonRate,
                                        "Poseidon input block"),
                            rate, "Poseidon input position");
                        if (input >=
                                gkr::kCiphertextCommitmentMetadataElements &&
                            input < checked_add(
                                        gkr::kCiphertextCommitmentMetadataElements,
                                        coordinates_per_ciphertext,
                                        "ciphertext input end")) {
                            buffer[offset] = coordinates[as_size(
                                input -
                                    gkr::kCiphertextCommitmentMetadataElements,
                                "coordinate input")];
                        } else {
                            buffer[offset] = Fq::zero();
                        }
                    }
                    const std::uint64_t destination = checked_add(
                        segment.input_witness_begin,
                        checked_add(
                            checked_mul(rate, segment.permutations,
                                        "rate-major destination"),
                            permutation - segment.permutation_begin,
                            "rate-major destination"),
                        "rate-major destination");
                    positional_write(
                        destination,
                        std::span<const Fq>(buffer).first(count));
                    permutation = checked_add(
                        permutation, checked_size(count, "rate block"),
                        "rate permutation");
                }
            }

            if (plan.shape.ciphertext_commitment_policy.relation !=
                gkr::CiphertextCommitmentRelation::PoseidonV2) {
                continue;
            }
            for (std::uint64_t local_auxiliary = 0;
                 local_auxiliary < rows_per_permutation;
                 ++local_auxiliary) {
                std::uint64_t permutation = intersection_begin;
                while (permutation < intersection_end) {
                    const std::size_t count = std::min<std::uint64_t>(
                        buffer.size(), intersection_end - permutation);
                    for (std::size_t offset = 0; offset < count; ++offset) {
                        const std::uint64_t global_permutation = checked_add(
                            permutation,
                            checked_size(offset, "auxiliary offset"),
                            "auxiliary permutation");
                        const std::uint64_t local_permutation =
                            global_permutation -
                            ciphertext_permutation_begin;
                        const std::uint64_t source = checked_add(
                            checked_mul(local_permutation,
                                        rows_per_permutation,
                                        "auxiliary permutation source"),
                            local_auxiliary,
                            "auxiliary permutation source");
                        buffer[offset] = auxiliary_values[as_size(
                            source, "auxiliary source index")];
                    }
                    const std::uint64_t destination = checked_add(
                        segment.auxiliary_witness_begin,
                        checked_add(
                            checked_mul(local_auxiliary,
                                        segment.permutations,
                                        "auxiliary-major destination"),
                            permutation - segment.permutation_begin,
                            "auxiliary-major destination"),
                        "auxiliary-major destination");
                    positional_write(
                        destination,
                        std::span<const Fq>(buffer).first(count));
                    permutation = checked_add(
                        permutation,
                        checked_size(count, "auxiliary block"),
                        "auxiliary permutation");
                }
            }
        }
        if (plan.shape.ciphertext_commitment_policy.relation ==
            gkr::CiphertextCommitmentRelation::DiagnosticSimpleCtHashV2) {
            positional_write(
                layout.ciphertext_simple_hash_auxiliary_witness_index(
                    plan, as_size(ciphertext, "ciphertext index"), 0),
                auxiliary_values);
        }
    }

    const OuterRelationRange products =
        plan.variables.witness.well_formedness_products;
    copy_source_range(witness_reader, products.begin,
                      layout.witness.well_formedness_products.begin,
                      products.count);
    writer.finish_array();

    const std::uint64_t expected_source_payload_bytes = checked_mul(
        checked_add(plan.variables.public_inputs.total,
                    plan.variables.witness.total,
                    "outer source elements"),
        encoded_fq_bytes, "outer source payload");
    if (report.source_read_payload_bytes !=
            expected_source_payload_bytes ||
        public_reader.position() != public_reader.size() ||
        witness_reader.position() != witness_reader.size()) {
        throw std::logic_error(
            "proof-of-packing source was not consumed exactly once");
    }

    const storage::NativeFieldArtifactWriteResult written = writer.finish();
    if (written.physical_bytes != expected_physical_bytes) {
        throw std::logic_error(
            "proof-of-packing assignment preflight disagrees with output");
    }
    report.positional_publication_read_bytes =
        written.positional_publication_read_bytes;
    report.positional_publication_read_operations =
        written.positional_publication_read_operations;
    auto artifact = open_proof_of_packing_assignment_artifact(
        options.directory, plan, circuit_metadata, outer_assignment,
        commitments);
    cleanup.disarm();
    return {std::move(artifact), report};
}

} // namespace laminate::packing
