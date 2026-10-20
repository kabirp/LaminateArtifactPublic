#include "laminate/fhe/mock_backend.hpp"

#include "laminate/field/serialization.hpp"

#include <algorithm>
#include <atomic>
#include <bit>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace laminate::fhe {
namespace {

using Ciphertext = MockBackend::Ciphertext;
using EvalContext = MockBackend::EvalContext;

constexpr std::size_t kScalarPlainNoiseBits = 17;
constexpr std::array<std::uint8_t, 8> kMockStorageMagic{
    'L', 'M', 'C', 'T', 'M', 'O', 'C', 'K'};
constexpr std::uint8_t kMockStorageVersion = 1;
constexpr std::size_t kMockStorageFixedBytes =
    kMockStorageMagic.size() + 1 + Digest{}.size() + 6 * 8 + 8 + 1 + 8 +
    8 + 8;

std::uint64_t fresh_ciphertext_identity() {
    static std::atomic<std::uint64_t> next{1};
    const std::uint64_t identity =
        next.fetch_add(1, std::memory_order_relaxed);
    if (identity == 0) {
        throw std::overflow_error(
            "MockBackend: ciphertext identity space exhausted");
    }
    return identity;
}

void assign_fresh_identity(Ciphertext &ciphertext) {
    ciphertext.identity = fresh_ciphertext_identity();
}

void validate_parameters(const MockParameters &parameters) {
    if (parameters.slot_count < 2 ||
        (parameters.slot_count & (parameters.slot_count - 1)) != 0) {
        throw std::invalid_argument(
            "MockBackend::create: slot count must be a power of two >= 2");
    }
    if (parameters.fresh_rns_limbs == 0 || parameters.bits_per_limb == 0) {
        throw std::invalid_argument(
            "MockBackend::create: modulus-chain dimensions must be nonzero");
    }
    if (parameters.fresh_rns_limbs >
        std::numeric_limits<std::size_t>::max() / parameters.bits_per_limb) {
        throw std::invalid_argument(
            "MockBackend::create: coefficient modulus size overflows");
    }
    if (parameters.initial_noise_margin_bits >=
        parameters.fresh_rns_limbs * parameters.bits_per_limb) {
        throw std::invalid_argument(
            "MockBackend::create: initial noise margin exhausts the chain");
    }
}

void validate_counters(const std::shared_ptr<OperationCounts> &counters,
                       const char *operation) {
    if (!counters) {
        throw std::invalid_argument(std::string(operation) +
                                    ": context has no operation counters");
    }
}

void validate_ciphertext(const MockParameters &parameters,
                         const Ciphertext &ciphertext,
                         const char *operation) {
    if (ciphertext.slots.size() != parameters.slot_count) {
        throw std::invalid_argument(std::string(operation) +
                                    ": ciphertext has the wrong slot count");
    }
    if (ciphertext.rns_limbs == 0 ||
        ciphertext.rns_limbs > parameters.fresh_rns_limbs) {
        throw std::invalid_argument(std::string(operation) +
                                    ": ciphertext has an invalid RNS level");
    }
    if (ciphertext.identity == 0) {
        throw std::invalid_argument(std::string(operation) +
                                    ": ciphertext has no provenance identity");
    }
}

void validate_binary(const EvalContext &context, const Ciphertext &left,
                     const Ciphertext &right, const char *operation) {
    validate_ciphertext(context.parameters, left, operation);
    validate_ciphertext(context.parameters, right, operation);
    if (left.rns_limbs != right.rns_limbs) {
        throw std::invalid_argument(std::string(operation) +
                                    ": ciphertext RNS levels differ");
    }
}

std::optional<std::size_t> validate_extension(
    const EvalContext &context,
    const MockBackend::ExtCiphertext &ciphertext,
    const char *operation) {
    std::optional<std::size_t> expected_limbs;
    for (const auto &coefficient : ciphertext) {
        if (!coefficient) {
            continue;
        }
        validate_ciphertext(context.parameters, *coefficient, operation);
        if (expected_limbs && coefficient->rns_limbs != *expected_limbs) {
            throw std::invalid_argument(std::string(operation) +
                                        ": extension RNS levels differ");
        }
        expected_limbs = coefficient->rns_limbs;
    }
    return expected_limbs;
}

void validate_extension_pair(
    const EvalContext &context,
    const MockBackend::ExtCiphertext &left,
    const MockBackend::ExtCiphertext &right,
    const char *operation) {
    const auto left_limbs = validate_extension(
        context, left, operation);
    const auto right_limbs = validate_extension(
        context, right, operation);
    if (left_limbs && right_limbs && left_limbs != right_limbs) {
        throw std::invalid_argument(std::string(operation) +
                                    ": extension RNS levels differ");
    }
}

std::size_t ciphertext_multiplication_noise_bits(
    const MockParameters &parameters) {
    return kScalarPlainNoiseBits +
           (std::bit_width(parameters.slot_count) - 1U);
}

std::size_t multiplicative_level_noise_bits(
    const MockParameters &parameters) {
    return ciphertext_multiplication_noise_bits(parameters) +
           parameters.relinearization_noise_bits;
}

int estimate_noise_bits(const MockParameters &parameters,
                        const Ciphertext &ciphertext) {
    const std::size_t total =
        ciphertext.rns_limbs * parameters.bits_per_limb;
    const std::size_t consumed =
        parameters.initial_noise_margin_bits + ciphertext.noise_loss_bits;
    if (consumed >= total) {
        const std::size_t deficit = consumed - total;
        if (deficit >= static_cast<std::size_t>(std::numeric_limits<int>::max())) {
            return std::numeric_limits<int>::min();
        }
        return -static_cast<int>(deficit);
    }
    const std::size_t remaining = total - consumed;
    return remaining > static_cast<std::size_t>(std::numeric_limits<int>::max())
               ? std::numeric_limits<int>::max()
               : static_cast<int>(remaining);
}

void require_positive_budget(const EvalContext &context,
                             const Ciphertext &ciphertext,
                             const char *operation) {
    if (estimate_noise_bits(context.parameters, ciphertext) <= 0) {
        throw std::runtime_error(std::string(operation) +
                                 ": mock noise budget exhausted");
    }
}

SlotVector padded_plaintext(const MockParameters &parameters,
                            const SlotVector &plaintext,
                            const char *operation) {
    if (plaintext.size() > parameters.slot_count) {
        throw std::invalid_argument(std::string(operation) +
                                    ": plaintext exceeds the slot count");
    }
    SlotVector padded(parameters.slot_count, Fp::zero());
    std::copy(plaintext.begin(), plaintext.end(), padded.begin());
    return padded;
}

bool is_all_zero(const SlotVector &values) {
    return std::all_of(values.begin(), values.end(),
                       [](const Fp &value) { return value.is_zero(); });
}

bool is_uniform(const SlotVector &values) {
    return !values.empty() &&
           std::all_of(values.begin() + 1, values.end(),
                       [&](const Fp &value) { return value == values.front(); });
}

bool has_commitment_coordinates(const Ciphertext &ciphertext) {
    return ciphertext.slots.size() <=
               std::numeric_limits<std::size_t>::max() / 2U &&
           ciphertext.coefficient_commitment_coordinates.size() ==
               2 * ciphertext.slots.size();
}

void clear_commitment_coordinates(Ciphertext &ciphertext) {
    ciphertext.coefficient_commitment_coordinates.clear();
}

void negate_commitment_coordinates(Ciphertext &ciphertext) {
    if (!has_commitment_coordinates(ciphertext)) {
        clear_commitment_coordinates(ciphertext);
        return;
    }
    for (std::uint64_t &coordinate :
         ciphertext.coefficient_commitment_coordinates) {
        coordinate = coordinate == 0 ? 0 : kOuterFieldOrder - coordinate;
    }
}

void combine_commitment_coordinates(Ciphertext &destination,
                                    const Ciphertext &right,
                                    bool subtract) {
    if (!has_commitment_coordinates(destination) ||
        !has_commitment_coordinates(right)) {
        clear_commitment_coordinates(destination);
        return;
    }
    for (std::size_t index = 0;
         index < destination.coefficient_commitment_coordinates.size();
         ++index) {
        const std::uint64_t left =
            destination.coefficient_commitment_coordinates[index];
        const std::uint64_t rhs =
            right.coefficient_commitment_coordinates[index];
        destination.coefficient_commitment_coordinates[index] =
            subtract
                ? (left >= rhs ? left - rhs
                               : kOuterFieldOrder - (rhs - left))
                : static_cast<std::uint64_t>(
                      (static_cast<unsigned __int128>(left) + rhs) %
                      kOuterFieldOrder);
    }
}

using OptionalCiphertext = std::optional<Ciphertext>;

void accumulate(const EvalContext &context, OptionalCiphertext &destination,
                Ciphertext term) {
    if (destination) {
        destination = MockBackend::add(context, *destination, term);
    } else {
        destination = std::move(term);
    }
}

template <std::size_t Size>
void reduce_extension_polynomial(
    const EvalContext &context,
    std::array<OptionalCiphertext, Size> &coefficients) {
    static_assert(Size >= 2 * kExtensionDegree - 1);
    for (std::size_t degree = Size; degree-- > kExtensionDegree;) {
        if (!coefficients[degree]) {
            continue;
        }
        Ciphertext negative =
            MockBackend::negate(context, *coefficients[degree]);
        accumulate(context, coefficients[degree - kExtensionDegree], negative);
        accumulate(context, coefficients[degree - kExtensionDegree + 3],
                   MockBackend::negate(context, *coefficients[degree]));
    }
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(
            static_cast<std::uint8_t>((value >> (8U * byte)) & 0xffU));
    }
}

std::uint64_t read_u64(std::span<const std::uint8_t> bytes,
                       std::size_t &offset, const char *operation) {
    if (offset > bytes.size() || bytes.size() - offset < 8) {
        throw std::invalid_argument(std::string(operation) +
                                    ": truncated integer");
    }
    std::uint64_t value = 0;
    for (std::size_t byte = 0; byte < 8; ++byte) {
        value |= static_cast<std::uint64_t>(bytes[offset + byte])
                 << (8U * byte);
    }
    offset += 8;
    return value;
}

std::size_t checked_size(std::uint64_t value, const char *operation) {
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": length exceeds this platform");
    }
    return static_cast<std::size_t>(value);
}

std::size_t mock_storage_size(std::size_t slots, std::size_t coordinates,
                              const char *operation) {
    constexpr std::size_t maximum =
        std::numeric_limits<std::size_t>::max();
    if (slots > (maximum - kMockStorageFixedBytes) / kSerializedFpBytes) {
        throw std::invalid_argument(std::string(operation) +
                                    ": slot length overflows");
    }
    const std::size_t through_slots =
        kMockStorageFixedBytes + slots * kSerializedFpBytes;
    if (coordinates > (maximum - through_slots) / 8) {
        throw std::invalid_argument(std::string(operation) +
                                    ": coordinate length overflows");
    }
    return through_slots + coordinates * 8;
}

} // namespace

MockBackend::Contexts MockBackend::create(const MockParameters &parameters) {
    validate_parameters(parameters);
    auto counters = std::make_shared<OperationCounts>();
    auto fixed_message_bases =
        std::make_shared<std::vector<PreparedSlotBasis>>();
    return Contexts{EvalContext{parameters, counters,
                                std::move(fixed_message_bases)},
                    ClientContext{parameters, std::move(counters)}};
}

MockBackend::PublicVerifierContext
MockBackend::make_public_verifier_context(const EvalContext &context) {
    validate_parameters(context.parameters);
    return PublicVerifierContext(context.parameters);
}

MockBackend::PublicVerifierContext
MockBackend::make_public_verifier_context(const ClientContext &context) {
    validate_parameters(context.parameters);
    return PublicVerifierContext(context.parameters);
}

namespace {

MockBackend::EvalContext mock_verifier_eval_context(
    const MockBackend::PublicVerifierContext &context) {
    return MockBackend::EvalContext{
        context.parameters, std::make_shared<OperationCounts>(),
        std::make_shared<std::vector<MockBackend::PreparedSlotBasis>>()};
}

} // namespace

MockBackend::Ciphertext
MockBackend::encrypt(const ClientContext &context, const SlotVector &slots) {
    validate_counters(context.counters, "MockBackend::encrypt");
    SlotVector padded =
        padded_plaintext(context.parameters, slots, "MockBackend::encrypt");
    ++context.counters->encrypt;
    return Ciphertext{std::move(padded), context.parameters.fresh_rns_limbs,
                      true, 0, 0, {}, fresh_ciphertext_identity()};
}

SlotVector MockBackend::decrypt(const ClientContext &context,
                                const Ciphertext &ciphertext) {
    validate_counters(context.counters, "MockBackend::decrypt");
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::decrypt");
    if (estimate_noise_bits(context.parameters, ciphertext) <= 0) {
        throw std::runtime_error(
            "MockBackend::decrypt: mock noise budget exhausted");
    }
    ++context.counters->decrypt;
    return ciphertext.slots;
}

MockBackend::Ciphertext
MockBackend::negate(const EvalContext &context,
                    const Ciphertext &ciphertext) {
    validate_counters(context.counters, "MockBackend::negate");
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::negate");
    Ciphertext result = ciphertext;
    for (Fp &slot : result.slots) {
        slot = Fp::zero() - slot;
    }
    negate_commitment_coordinates(result);
    assign_fresh_identity(result);
    ++context.counters->negate;
    return result;
}

MockBackend::Ciphertext MockBackend::add(const EvalContext &context,
                                         const Ciphertext &left,
                                         const Ciphertext &right) {
    validate_counters(context.counters, "MockBackend::add");
    validate_binary(context, left, right, "MockBackend::add");
    Ciphertext result = left;
    for (std::size_t slot = 0; slot < result.slots.size(); ++slot) {
        result.slots[slot] += right.slots[slot];
    }
    combine_commitment_coordinates(result, right, false);
    result.relinearized = left.relinearized && right.relinearized;
    result.depth_half_levels =
        std::max(left.depth_half_levels, right.depth_half_levels);
    result.noise_loss_bits =
        std::max(left.noise_loss_bits, right.noise_loss_bits);
    assign_fresh_identity(result);
    ++context.counters->add;
    return result;
}

bool MockBackend::same_ciphertext(const EvalContext &context,
                                  const Ciphertext &left,
                                  const Ciphertext &right) {
    validate_binary(context, left, right,
                    "MockBackend::same_ciphertext");
    if (left.identity != right.identity) {
        return false;
    }
    if (left.slots != right.slots ||
        left.relinearized != right.relinearized ||
        left.depth_half_levels != right.depth_half_levels ||
        left.noise_loss_bits != right.noise_loss_bits ||
        left.coefficient_commitment_coordinates !=
            right.coefficient_commitment_coordinates) {
        throw std::invalid_argument(
            "MockBackend::same_ciphertext: inconsistent provenance "
            "identity");
    }
    return true;
}

MockBackend::Ciphertext MockBackend::sub(const EvalContext &context,
                                         const Ciphertext &left,
                                         const Ciphertext &right) {
    validate_counters(context.counters, "MockBackend::sub");
    validate_binary(context, left, right, "MockBackend::sub");
    Ciphertext result = left;
    for (std::size_t slot = 0; slot < result.slots.size(); ++slot) {
        result.slots[slot] -= right.slots[slot];
    }
    combine_commitment_coordinates(result, right, true);
    result.relinearized = left.relinearized && right.relinearized;
    result.depth_half_levels =
        std::max(left.depth_half_levels, right.depth_half_levels);
    result.noise_loss_bits =
        std::max(left.noise_loss_bits, right.noise_loss_bits);
    assign_fresh_identity(result);
    ++context.counters->sub;
    return result;
}

MockBackend::Ciphertext
MockBackend::mul_no_relin(const EvalContext &context, const Ciphertext &left,
                          const Ciphertext &right) {
    validate_counters(context.counters, "MockBackend::mul_no_relin");
    validate_binary(context, left, right, "MockBackend::mul_no_relin");
    if (!left.relinearized || !right.relinearized) {
        throw std::invalid_argument(
            "MockBackend::mul_no_relin: inputs must be relinearized");
    }
    Ciphertext result = left;
    for (std::size_t slot = 0; slot < result.slots.size(); ++slot) {
        result.slots[slot] *= right.slots[slot];
    }
    clear_commitment_coordinates(result);
    result.relinearized = false;
    result.depth_half_levels =
        std::max(left.depth_half_levels, right.depth_half_levels) + 2;
    result.noise_loss_bits =
        std::max(left.noise_loss_bits, right.noise_loss_bits) +
        ciphertext_multiplication_noise_bits(context.parameters);
    assign_fresh_identity(result);
    ++context.counters->mul_no_relin;
    require_positive_budget(context, result, "MockBackend::mul_no_relin");
    return result;
}

void MockBackend::relinearize(const EvalContext &context,
                              Ciphertext &ciphertext) {
    validate_counters(context.counters, "MockBackend::relinearize");
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::relinearize");
    if (ciphertext.relinearized) {
        throw std::invalid_argument(
            "MockBackend::relinearize: ciphertext is already relinearized");
    }
    ciphertext.relinearized = true;
    ciphertext.noise_loss_bits +=
        context.parameters.relinearization_noise_bits;
    assign_fresh_identity(ciphertext);
    ++context.counters->relinearize;
    require_positive_budget(context, ciphertext, "MockBackend::relinearize");
}

MockBackend::Ciphertext MockBackend::mul(const EvalContext &context,
                                         const Ciphertext &left,
                                         const Ciphertext &right) {
    Ciphertext result = mul_no_relin(context, left, right);
    relinearize(context, result);
    return result;
}

MockBackend::Ciphertext
MockBackend::add_plain(const EvalContext &context,
                       const Ciphertext &ciphertext,
                       const SlotVector &plaintext) {
    validate_counters(context.counters, "MockBackend::add_plain");
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::add_plain");
    const SlotVector padded = padded_plaintext(
        context.parameters, plaintext, "MockBackend::add_plain");
    ++context.counters->add_plain_vector_api_calls;
    context.counters->add_plain_vector_api_elements += plaintext.size();
    Ciphertext result = ciphertext;
    for (std::size_t slot = 0; slot < result.slots.size(); ++slot) {
        result.slots[slot] += padded[slot];
    }
    clear_commitment_coordinates(result);
    assign_fresh_identity(result);
    ++context.counters->add_plain;
    return result;
}

MockBackend::Ciphertext MockBackend::add_plain_scalar(
    const EvalContext &context, const Ciphertext &ciphertext,
    const Fp &plaintext) {
    validate_counters(context.counters,
                      "MockBackend::add_plain_scalar");
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::add_plain_scalar");
    ++context.counters->add_plain_scalar_api_calls;
    Ciphertext result = ciphertext;
    for (Fp &slot : result.slots) {
        slot += plaintext;
    }
    clear_commitment_coordinates(result);
    assign_fresh_identity(result);
    ++context.counters->add_plain;
    return result;
}

MockBackend::Ciphertext
MockBackend::mul_plain(const EvalContext &context,
                       const Ciphertext &ciphertext,
                       const SlotVector &plaintext) {
    validate_counters(context.counters, "MockBackend::mul_plain");
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::mul_plain");
    const SlotVector padded = padded_plaintext(
        context.parameters, plaintext, "MockBackend::mul_plain");
    ++context.counters->mul_plain_vector_api_calls;
    context.counters->mul_plain_vector_api_elements += plaintext.size();
    Ciphertext result = ciphertext;
    for (std::size_t slot = 0; slot < result.slots.size(); ++slot) {
        result.slots[slot] *= padded[slot];
    }
    if (has_commitment_coordinates(result)) {
        const std::vector<std::int64_t> coefficients =
            encode_centered_plaintext_coefficients(context, padded);
        const std::vector<std::uint64_t> multiplier =
            encode_lowest_plaintext_ntt_coordinates(context, coefficients);
        for (std::size_t component = 0; component < 2; ++component) {
            for (std::size_t coordinate = 0;
                 coordinate < multiplier.size(); ++coordinate) {
                std::uint64_t &value =
                    result.coefficient_commitment_coordinates[
                        component * multiplier.size() + coordinate];
                value = static_cast<std::uint64_t>(
                    (static_cast<unsigned __int128>(value) *
                     multiplier[coordinate]) %
                    kOuterFieldOrder);
            }
        }
    } else {
        clear_commitment_coordinates(result);
    }
    if (is_uniform(padded)) {
        ++result.depth_half_levels;
        result.noise_loss_bits += kScalarPlainNoiseBits;
        ++context.counters->mul_plain_scalar;
    } else {
        result.depth_half_levels += 2;
        result.noise_loss_bits +=
            ciphertext_multiplication_noise_bits(context.parameters);
        ++context.counters->mul_plain_vector;
    }
    assign_fresh_identity(result);
    require_positive_budget(context, result, "MockBackend::mul_plain");
    return result;
}

MockBackend::Ciphertext
MockBackend::mul_plain_scalar(const EvalContext &context,
                              const Ciphertext &ciphertext,
                              const Fp &plaintext) {
    validate_counters(context.counters,
                      "MockBackend::mul_plain_scalar");
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::mul_plain_scalar");
    ++context.counters->mul_plain_scalar_api_calls;

    Ciphertext result = ciphertext;
    for (Fp &slot : result.slots) {
        slot *= plaintext;
    }
    if (has_commitment_coordinates(result)) {
        const std::uint64_t value = plaintext.value();
        const std::uint64_t multiplier = value <= (kBaseFieldOrder - 1) / 2
            ? value : kOuterFieldOrder - (kBaseFieldOrder - value);
        for (std::uint64_t &coordinate :
             result.coefficient_commitment_coordinates) {
            coordinate = static_cast<std::uint64_t>(
                (static_cast<unsigned __int128>(coordinate) * multiplier) %
                kOuterFieldOrder);
        }
    } else {
        clear_commitment_coordinates(result);
    }
    ++result.depth_half_levels;
    result.noise_loss_bits += kScalarPlainNoiseBits;
    ++context.counters->mul_plain_scalar;
    assign_fresh_identity(result);
    require_positive_budget(context, result,
                            "MockBackend::mul_plain_scalar");
    return result;
}

MockBackend::PreparedSlotBasis MockBackend::prepare_slot_basis(
    const EvalContext &context, const SlotVector &basis) {
    validate_counters(context.counters,
                      "MockBackend::prepare_slot_basis");
    if (basis.size() != context.parameters.slot_count) {
        throw std::invalid_argument(
            "MockBackend::prepare_slot_basis: basis must fill all slots");
    }
    ++context.counters->prepared_base_basis_setup_calls;
    return PreparedSlotBasis{basis};
}

MockBackend::Ciphertext MockBackend::mul_plain_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedSlotBasis &basis) {
    const std::uint64_t calls_before =
        context.counters->mul_plain_vector_api_calls;
    const std::uint64_t elements_before =
        context.counters->mul_plain_vector_api_elements;
    Ciphertext result = mul_plain(context, ciphertext, basis.plaintext);
    const std::uint64_t calls =
        context.counters->mul_plain_vector_api_calls - calls_before;
    const std::uint64_t elements =
        context.counters->mul_plain_vector_api_elements - elements_before;
    context.counters->mul_plain_vector_api_calls = calls_before;
    context.counters->mul_plain_vector_api_elements = elements_before;
    ++context.counters->prepared_base_basis_api_calls;
    context.counters->prepared_base_basis_avoided_vector_elements +=
        elements;
    context.counters->prepared_base_basis_avoided_batch_encodes += calls;
    return result;
}

MockBackend::PreparedLevelSlotBasis
MockBackend::prepare_level_slot_basis(
    const EvalContext &context, const Ciphertext &level_reference,
    const SlotVector &basis) {
    validate_ciphertext(context.parameters, level_reference,
                        "MockBackend::prepare_level_slot_basis");
    if (basis.size() != context.parameters.slot_count) {
        throw std::invalid_argument(
            "MockBackend::prepare_level_slot_basis: basis must fill all "
            "slots");
    }
    ++context.counters->prepared_base_basis_setup_calls;
    ++context.counters->prepared_base_basis_level_representations;
    context.counters->prepared_base_basis_ntt_bytes_created +=
        basis.size() * level_reference.rns_limbs * sizeof(std::uint64_t);
    return PreparedLevelSlotBasis{basis, level_reference.rns_limbs};
}

MockBackend::Ciphertext MockBackend::mul_plain_level_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedLevelSlotBasis &basis) {
    if (ciphertext.rns_limbs != basis.rns_limbs) {
        throw std::invalid_argument(
            "MockBackend::mul_plain_level_prepared: basis has wrong level");
    }
    return mul_plain_prepared(
        context, ciphertext, PreparedSlotBasis{basis.plaintext});
}

PreparedBasisStorageStats
MockBackend::prepared_level_slot_basis_storage(
    const PreparedLevelSlotBasis &basis) {
    return PreparedBasisStorageStats{
        1,
        basis.plaintext.size() * basis.rns_limbs * sizeof(std::uint64_t),
        basis.plaintext.size() * sizeof(Fp)};
}

void MockBackend::preprocess_fixed_message_cells(
    const EvalContext &context) {
    validate_counters(context.counters,
                      "MockBackend::preprocess_fixed_message_cells");
    if (!context.fixed_message_bases) {
        throw std::logic_error(
            "MockBackend::preprocess_fixed_message_cells: cache is "
            "unavailable");
    }
    if (!context.fixed_message_bases->empty()) {
        return;
    }
    if (context.parameters.slot_count < kFixedMessageCellCount) {
        throw std::invalid_argument(
            "MockBackend::preprocess_fixed_message_cells: too few slots");
    }
    context.fixed_message_bases->reserve(kFixedMessageCellCount);
    for (std::size_t cell = 0; cell < kFixedMessageCellCount; ++cell) {
        SlotVector mask(context.parameters.slot_count, Fp::zero());
        mask[fixed_message_cell_slot(context.parameters.slot_count, cell)] =
            Fp::one();
        context.fixed_message_bases->push_back(
            PreparedSlotBasis{std::move(mask)});
    }
    context.counters->fixed_message_basis_setup_calls +=
        kFixedMessageCellCount;
}

MockBackend::Ciphertext MockBackend::mul_plain_fixed_message_cell(
    const EvalContext &context, const Ciphertext &ciphertext,
    std::size_t cell) {
    validate_counters(context.counters,
                      "MockBackend::mul_plain_fixed_message_cell");
    if (!context.fixed_message_bases ||
        context.fixed_message_bases->size() != kFixedMessageCellCount) {
        throw std::logic_error(
            "MockBackend::mul_plain_fixed_message_cell: fixed cells were "
            "not preprocessed");
    }
    if (cell >= kFixedMessageCellCount) {
        throw std::invalid_argument(
            "MockBackend::mul_plain_fixed_message_cell: cell is out of "
            "range");
    }
    Ciphertext result = mul_plain_prepared(
        context, ciphertext, (*context.fixed_message_bases)[cell]);
    // This is a more specific prepared-basis entry point. Keep the generic
    // prepared counters reserved for user-supplied bases.
    --context.counters->prepared_base_basis_api_calls;
    context.counters->prepared_base_basis_avoided_vector_elements -=
        context.parameters.slot_count;
    --context.counters->prepared_base_basis_avoided_batch_encodes;
    ++context.counters->fixed_message_basis_api_calls;
    context.counters->fixed_message_basis_avoided_vector_elements +=
        context.parameters.slot_count;
    ++context.counters->fixed_message_basis_avoided_batch_encodes;
    ++context.counters->fixed_message_basis_avoided_hash_probes;
    return result;
}

MockBackend::PreparedExtensionSlotBasis
MockBackend::prepare_extension_slot_basis(
    const EvalContext &context, const Ciphertext &level_reference,
    const PlainExtension &basis) {
    validate_counters(context.counters,
                      "MockBackend::prepare_extension_slot_basis");
    validate_ciphertext(context.parameters, level_reference,
                        "MockBackend::prepare_extension_slot_basis");
    for (const SlotVector &coefficient : basis) {
        if (coefficient.size() != context.parameters.slot_count) {
            throw std::invalid_argument(
                "MockBackend::prepare_extension_slot_basis: every "
                "coefficient must fill all slots");
        }
    }
    ++context.counters->prepared_extension_basis_setup_calls;
    return PreparedExtensionSlotBasis{basis,
                                      level_reference.rns_limbs};
}

MockBackend::Ciphertext MockBackend::rotate(const EvalContext &context,
                                            const Ciphertext &ciphertext,
                                            std::size_t steps) {
    validate_counters(context.counters, "MockBackend::rotate");
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::rotate");
    Ciphertext result = ciphertext;
    result.slots = grid_rotate(ciphertext.slots, steps);
    if (has_commitment_coordinates(result)) {
        const std::size_t degree = result.slots.size();
        for (std::size_t component = 0; component < 2; ++component) {
            std::vector<std::uint64_t> source(
                result.coefficient_commitment_coordinates.begin() +
                    static_cast<std::ptrdiff_t>(component * degree),
                result.coefficient_commitment_coordinates.begin() +
                    static_cast<std::ptrdiff_t>((component + 1) * degree));
            std::vector<std::uint64_t> rotated(degree);
            for (std::size_t destination = 0; destination < degree;
                 ++destination) {
                rotated[destination] = source[grid_source(
                    degree, steps, destination)];
            }
            std::copy(rotated.begin(), rotated.end(),
                      result.coefficient_commitment_coordinates.begin() +
                          static_cast<std::ptrdiff_t>(component * degree));
        }
    }
    result.noise_loss_bits += context.parameters.rotation_noise_bits;
    assign_fresh_identity(result);
    ++context.counters->rotate;
    require_positive_budget(context, result, "MockBackend::rotate");
    return result;
}

MockBackend::Ciphertext MockBackend::fold(const EvalContext &context,
                                          const Ciphertext &ciphertext) {
    validate_ciphertext(context.parameters, ciphertext, "MockBackend::fold");
    Ciphertext result = ciphertext;
    const std::size_t half = context.parameters.slot_count / 2;
    for (std::size_t shift = 1; shift < half; shift *= 2) {
        result = add(context, result, rotate(context, result, shift));
    }
    return add(context, result, rotate(context, result, half));
}

MockBackend::ExtCiphertext
MockBackend::ext_add(const EvalContext &context, const ExtCiphertext &left,
                     const ExtCiphertext &right) {
    validate_extension_pair(context, left, right,
                            "MockBackend::ext_add");
    ++context.counters->logical_ext_add;
    ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (left[coefficient] && right[coefficient]) {
            result[coefficient] = add(
                context, *left[coefficient], *right[coefficient]);
        } else if (left[coefficient]) {
            result[coefficient] = *left[coefficient];
        } else if (right[coefficient]) {
            result[coefficient] = *right[coefficient];
        }
    }
    return result;
}

void MockBackend::record_logical_extension_add(
    const EvalContext &context, const Ciphertext &encrypted_anchor) {
    validate_counters(context.counters,
                      "MockBackend::record_logical_extension_add");
    validate_ciphertext(context.parameters, encrypted_anchor,
                        "MockBackend::record_logical_extension_add");
    ++context.counters->logical_ext_add;
}

MockBackend::ExtCiphertext
MockBackend::ext_sub(const EvalContext &context, const ExtCiphertext &left,
                     const ExtCiphertext &right) {
    validate_extension_pair(context, left, right,
                            "MockBackend::ext_sub");
    ++context.counters->logical_ext_sub;
    ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (left[coefficient] && right[coefficient]) {
            result[coefficient] = sub(
                context, *left[coefficient], *right[coefficient]);
        } else if (left[coefficient]) {
            result[coefficient] = *left[coefficient];
        } else if (right[coefficient]) {
            result[coefficient] = negate(context, *right[coefficient]);
        }
    }
    return result;
}

void MockBackend::record_logical_extension_sub(
    const EvalContext &context, const Ciphertext &encrypted_anchor) {
    validate_counters(context.counters,
                      "MockBackend::record_logical_extension_sub");
    validate_ciphertext(context.parameters, encrypted_anchor,
                        "MockBackend::record_logical_extension_sub");
    ++context.counters->logical_ext_sub;
}

void MockBackend::record_logical_extension_mul_plain(
    const EvalContext &context, const Ciphertext &encrypted_anchor) {
    validate_counters(context.counters,
                      "MockBackend::record_logical_extension_mul_plain");
    validate_ciphertext(context.parameters, encrypted_anchor,
                        "MockBackend::record_logical_extension_mul_plain");
    ++context.counters->logical_ext_mul_plain;
}

MockBackend::ExtCiphertext MockBackend::ext_mul_no_relin(
    const EvalContext &context, const ExtCiphertext &left,
    const ExtCiphertext &right) {
    validate_extension_pair(context, left, right,
                            "MockBackend::ext_mul_no_relin");
    ++context.counters->logical_ext_mul;

    std::array<OptionalCiphertext, 2 * kExtensionDegree - 1> coefficients{};
    for (std::size_t left_degree = 0; left_degree < kExtensionDegree;
         ++left_degree) {
        if (!left[left_degree]) {
            continue;
        }
        for (std::size_t right_degree = 0;
             right_degree < kExtensionDegree; ++right_degree) {
            if (!right[right_degree]) {
                continue;
            }
            accumulate(context, coefficients[left_degree + right_degree],
                       mul_no_relin(context, *left[left_degree],
                                    *right[right_degree]));
        }
    }
    reduce_extension_polynomial(context, coefficients);

    ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient] = std::move(coefficients[coefficient]);
    }
    return result;
}

void MockBackend::ext_relinearize(const EvalContext &context,
                                  ExtCiphertext &ciphertext) {
    validate_extension(context, ciphertext, "MockBackend::ext_relinearize");
    for (auto &coefficient : ciphertext) {
        if (coefficient && !coefficient->relinearized) {
            relinearize(context, *coefficient);
        }
    }
}

MockBackend::ExtCiphertext
MockBackend::ext_mul(const EvalContext &context, const ExtCiphertext &left,
                     const ExtCiphertext &right) {
    ExtCiphertext result = ext_mul_no_relin(context, left, right);
    ext_relinearize(context, result);
    return result;
}

MockBackend::ExtCiphertext MockBackend::ext_mul_plain(
    const EvalContext &context, const ExtCiphertext &ciphertext,
    const PlainExtension &plaintext) {
    validate_extension(context, ciphertext, "MockBackend::ext_mul_plain");
    ++context.counters->logical_ext_mul_plain;

    std::array<OptionalCiphertext, 2 * kExtensionDegree - 1> coefficients{};
    for (std::size_t ciphertext_degree = 0;
         ciphertext_degree < kExtensionDegree; ++ciphertext_degree) {
        if (!ciphertext[ciphertext_degree]) {
            continue;
        }
        for (std::size_t plaintext_degree = 0;
             plaintext_degree < kExtensionDegree; ++plaintext_degree) {
            const SlotVector padded = padded_plaintext(
                context.parameters, plaintext[plaintext_degree],
                "MockBackend::ext_mul_plain");
            if (is_all_zero(padded)) {
                continue;
            }
            accumulate(context,
                       coefficients[ciphertext_degree + plaintext_degree],
                       mul_plain(context, *ciphertext[ciphertext_degree],
                                 padded));
        }
    }
    reduce_extension_polynomial(context, coefficients);

    ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient] = std::move(coefficients[coefficient]);
    }
    return result;
}

MockBackend::ExtCiphertext MockBackend::ext_mul_plain_prepared(
    const EvalContext &context, const ExtCiphertext &ciphertext,
    const PreparedExtensionSlotBasis &basis) {
    validate_counters(context.counters,
                      "MockBackend::ext_mul_plain_prepared");
    for (const auto &coefficient : ciphertext) {
        if (coefficient && coefficient->rns_limbs != basis.rns_limbs) {
            throw std::invalid_argument(
                "MockBackend::ext_mul_plain_prepared: basis has the wrong "
                "level");
        }
    }
    const std::uint64_t calls_before =
        context.counters->mul_plain_vector_api_calls;
    const std::uint64_t elements_before =
        context.counters->mul_plain_vector_api_elements;
    ExtCiphertext result =
        ext_mul_plain(context, ciphertext, basis.plaintext);
    const std::uint64_t nonzero_coefficients =
        static_cast<std::uint64_t>(std::count_if(
            basis.plaintext.begin(), basis.plaintext.end(),
            [](const SlotVector &coefficient) {
                return !is_all_zero(coefficient);
            }));
    context.counters->mul_plain_vector_api_calls = calls_before;
    context.counters->mul_plain_vector_api_elements = elements_before;
    ++context.counters->prepared_extension_basis_api_calls;
    context.counters->prepared_extension_basis_avoided_vector_elements +=
        nonzero_coefficients * context.parameters.slot_count;
    context.counters->prepared_extension_basis_avoided_batch_encodes +=
        nonzero_coefficients;
    return result;
}

MockBackend::ExtCiphertext MockBackend::promote_plain_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedExtensionSlotBasis &basis) {
    ++context.counters->prepared_extension_promotion_api_calls;
    return promote_plain_prepared_untracked(context, ciphertext, basis);
}

MockBackend::ExtCiphertext MockBackend::promote_plain_prepared_untracked(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedExtensionSlotBasis &basis) {
    if (ciphertext.rns_limbs != basis.rns_limbs) {
        throw std::invalid_argument(
            "MockBackend::promote_plain_prepared_untracked: basis has the "
            "wrong level");
    }
    ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        if (is_all_zero(basis.plaintext[coefficient])) {
            continue;
        }
        result[coefficient] =
            mul_plain_prepared(
                context, ciphertext,
                PreparedSlotBasis{basis.plaintext[coefficient]});
    }
    return result;
}

PreparedBasisStorageStats
MockBackend::prepared_extension_slot_basis_storage(
    const PreparedExtensionSlotBasis &basis) {
    return PreparedBasisStorageStats{
        .level_representations = 0,
        .ntt_coefficient_bytes = 0,
        .host_basis_bytes =
            basis.plaintext.size() * basis.plaintext.front().size() *
            sizeof(Fp),
    };
}

MockBackend::ExtCiphertext MockBackend::ext_mul_plain_scalar(
    const EvalContext &context, const ExtCiphertext &ciphertext,
    const PlainExtensionScalar &plaintext) {
    validate_extension(context, ciphertext,
                       "MockBackend::ext_mul_plain_scalar");
    ++context.counters->logical_ext_mul_plain;

    std::array<OptionalCiphertext, 2 * kExtensionDegree - 1> coefficients{};
    for (std::size_t ciphertext_degree = 0;
         ciphertext_degree < kExtensionDegree; ++ciphertext_degree) {
        if (!ciphertext[ciphertext_degree]) {
            continue;
        }
        for (std::size_t plaintext_degree = 0;
             plaintext_degree < kExtensionDegree; ++plaintext_degree) {
            if (plaintext[plaintext_degree].is_zero()) {
                continue;
            }
            accumulate(
                context,
                coefficients[ciphertext_degree + plaintext_degree],
                mul_plain_scalar(context, *ciphertext[ciphertext_degree],
                                 plaintext[plaintext_degree]));
        }
    }
    reduce_extension_polynomial(context, coefficients);

    ExtCiphertext result{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        result[coefficient] = std::move(coefficients[coefficient]);
    }
    return result;
}

void MockBackend::mod_switch_to_next(const EvalContext &context,
                                     Ciphertext &ciphertext) {
    validate_counters(context.counters, "MockBackend::mod_switch_to_next");
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::mod_switch_to_next");
    if (ciphertext.rns_limbs == 1) {
        throw std::invalid_argument(
            "MockBackend::mod_switch_to_next: already at the lowest level");
    }
    --ciphertext.rns_limbs;
    assign_fresh_identity(ciphertext);
    ++context.counters->mod_switch;
    require_positive_budget(context, ciphertext,
                            "MockBackend::mod_switch_to_next");
}

void MockBackend::mod_switch_to_lowest(const EvalContext &context,
                                       Ciphertext &ciphertext) {
    validate_counters(context.counters, "MockBackend::mod_switch_to_lowest");
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::mod_switch_to_lowest");
    while (ciphertext.rns_limbs > 1) {
        mod_switch_to_next(context, ciphertext);
    }
}

std::size_t
MockBackend::remaining_mult_depth(const EvalContext &context,
                                  const Ciphertext &ciphertext) {
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::remaining_mult_depth");
    const int remaining = estimate_noise_bits(context.parameters, ciphertext);
    if (remaining <= 0) {
        return 0;
    }
    return static_cast<std::size_t>(remaining) /
           multiplicative_level_noise_bits(context.parameters);
}

std::size_t MockBackend::rns_limb_count(const EvalContext &context,
                                        const Ciphertext &ciphertext) {
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::rns_limb_count");
    return ciphertext.rns_limbs;
}

std::size_t MockBackend::rns_limb_count(
    const PublicVerifierContext &context,
    const Ciphertext &ciphertext) {
    return rns_limb_count(mock_verifier_eval_context(context), ciphertext);
}

std::size_t MockBackend::coeff_modulus_bits(const EvalContext &context,
                                            const Ciphertext &ciphertext) {
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::coeff_modulus_bits");
    return ciphertext.rns_limbs * context.parameters.bits_per_limb;
}

int MockBackend::estimated_noise_bits(const EvalContext &context,
                                      const Ciphertext &ciphertext) {
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::estimated_noise_bits");
    return estimate_noise_bits(context.parameters, ciphertext);
}

std::size_t MockBackend::slot_count(const EvalContext &context) {
    return context.parameters.slot_count;
}

std::size_t MockBackend::slot_count(const ClientContext &context) {
    return context.parameters.slot_count;
}

std::size_t MockBackend::slot_count(
    const PublicVerifierContext &context) {
    validate_parameters(context.parameters);
    return context.parameters.slot_count;
}

std::uint64_t MockBackend::plaintext_modulus(const EvalContext &context) {
    validate_parameters(context.parameters);
    return kBaseFieldOrder;
}

std::vector<std::uint8_t>
MockBackend::serialize(const Ciphertext &ciphertext) {
    constexpr std::size_t fixed_bytes =
        4U + 1U + 8U + 8U + 1U + 8U + 8U + 8U;
    if (ciphertext.slots.size() >
            (std::numeric_limits<std::size_t>::max() - fixed_bytes) /
                kSerializedFpBytes ||
        ciphertext.coefficient_commitment_coordinates.size() >
            (std::numeric_limits<std::size_t>::max() - fixed_bytes -
             ciphertext.slots.size() * kSerializedFpBytes) /
                sizeof(std::uint64_t)) {
        throw std::overflow_error(
            "MockBackend::serialize: ciphertext size overflows");
    }
    std::vector<std::uint8_t> output;
    output.reserve(
        fixed_bytes + ciphertext.slots.size() * kSerializedFpBytes +
        ciphertext.coefficient_commitment_coordinates.size() *
            sizeof(std::uint64_t));
    output.insert(output.end(), {'L', 'M', 'C', 'T'});
    output.push_back(2); // Lossless protocol encoding version.
    append_u64(output, ciphertext.slots.size());
    append_u64(output, ciphertext.rns_limbs);
    output.push_back(ciphertext.relinearized ? 1U : 0U);
    append_u64(output, ciphertext.depth_half_levels);
    append_u64(output, ciphertext.noise_loss_bits);
    append_u64(output,
               ciphertext.coefficient_commitment_coordinates.size());
    for (const Fp &slot : ciphertext.slots) {
        const SerializedFp encoded = laminate::serialize(slot);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
    for (const std::uint64_t coordinate :
         ciphertext.coefficient_commitment_coordinates) {
        if (coordinate >= kOuterFieldOrder) {
            throw std::invalid_argument(
                "MockBackend::serialize: commitment coordinate is outside "
                "Fq");
        }
        append_u64(output, coordinate);
    }
    return output;
}

MockBackend::Ciphertext MockBackend::deserialize_protocol(
    const EvalContext &context, std::span<const std::uint8_t> bytes) {
    constexpr const char *operation = "MockBackend::deserialize_protocol";
    validate_parameters(context.parameters);
    constexpr std::size_t fixed_bytes =
        4U + 1U + 8U + 8U + 1U + 8U + 8U + 8U;
    if (bytes.size() < fixed_bytes || bytes[0] != 'L' ||
        bytes[1] != 'M' || bytes[2] != 'C' || bytes[3] != 'T' ||
        bytes[4] != 2U) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid canonical header");
    }
    std::size_t offset = 5U;
    const std::size_t slot_count =
        checked_size(read_u64(bytes, offset, operation), operation);
    const std::size_t rns_limbs =
        checked_size(read_u64(bytes, offset, operation), operation);
    const std::uint8_t relinearized = bytes[offset++];
    const std::size_t depth_half_levels =
        checked_size(read_u64(bytes, offset, operation), operation);
    const std::size_t noise_loss_bits =
        checked_size(read_u64(bytes, offset, operation), operation);
    const std::size_t coordinate_count =
        checked_size(read_u64(bytes, offset, operation), operation);
    if (slot_count != context.parameters.slot_count ||
        relinearized > 1U ||
        (coordinate_count != 0U &&
         (slot_count > std::numeric_limits<std::size_t>::max() / 2U ||
          coordinate_count != 2U * slot_count)) ||
        slot_count >
            (std::numeric_limits<std::size_t>::max() - fixed_bytes) /
                kSerializedFpBytes ||
        coordinate_count >
            (std::numeric_limits<std::size_t>::max() - fixed_bytes -
             slot_count * kSerializedFpBytes) /
                sizeof(std::uint64_t) ||
        bytes.size() != fixed_bytes + slot_count * kSerializedFpBytes +
                            coordinate_count * sizeof(std::uint64_t)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": noncanonical ciphertext shape");
    }

    SlotVector slots;
    slots.reserve(slot_count);
    for (std::size_t slot = 0; slot < slot_count; ++slot) {
        slots.push_back(deserialize_fp(
            bytes.subspan(offset, kSerializedFpBytes)));
        offset += kSerializedFpBytes;
    }
    std::vector<std::uint64_t> coordinates;
    coordinates.reserve(coordinate_count);
    for (std::size_t coordinate = 0; coordinate < coordinate_count;
         ++coordinate) {
        const std::uint64_t value = read_u64(bytes, offset, operation);
        if (value >= kOuterFieldOrder) {
            throw std::invalid_argument(std::string(operation) +
                                        ": commitment coordinate is outside "
                                        "Fq");
        }
        coordinates.push_back(value);
    }
    Ciphertext result{std::move(slots), rns_limbs,
                      relinearized != 0U, depth_half_levels,
                      noise_loss_bits, std::move(coordinates),
                      fresh_ciphertext_identity()};
    validate_ciphertext(context.parameters, result, operation);
    if (serialize(result) !=
        std::vector<std::uint8_t>(bytes.begin(), bytes.end())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": noncanonical ciphertext encoding");
    }
    return result;
}

MockBackend::Ciphertext MockBackend::deserialize_protocol(
    const PublicVerifierContext &context,
    std::span<const std::uint8_t> bytes) {
    return deserialize_protocol(mock_verifier_eval_context(context), bytes);
}

Digest MockBackend::storage_context_id(const EvalContext &context) {
    validate_parameters(context.parameters);
    static constexpr std::string_view domain =
        "LaminateImpl/MockStorageContext/v1";
    std::vector<std::uint8_t> encoded(domain.begin(), domain.end());
    append_u64(encoded, context.parameters.slot_count);
    append_u64(encoded, context.parameters.fresh_rns_limbs);
    append_u64(encoded, context.parameters.bits_per_limb);
    append_u64(encoded, context.parameters.initial_noise_margin_bits);
    append_u64(encoded, context.parameters.rotation_noise_bits);
    append_u64(encoded, context.parameters.relinearization_noise_bits);
    return sha256(encoded);
}

Digest MockBackend::storage_context_id(const ClientContext &context) {
    validate_parameters(context.parameters);
    return storage_context_id(
        PublicVerifierContext(context.parameters));
}

Digest MockBackend::storage_context_id(
    const PublicVerifierContext &context) {
    return storage_context_id(mock_verifier_eval_context(context));
}

std::uint64_t MockBackend::storage_ciphertext_byte_limit(
    const EvalContext &context) {
    constexpr const char *operation =
        "MockBackend::storage_ciphertext_byte_limit";
    validate_parameters(context.parameters);
    if (context.parameters.slot_count >
        std::numeric_limits<std::size_t>::max() / 2U) {
        throw std::invalid_argument(std::string(operation) +
                                    ": coordinate length overflows");
    }
    const std::size_t maximum = mock_storage_size(
        context.parameters.slot_count,
        2U * context.parameters.slot_count, operation);
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (maximum > std::numeric_limits<std::uint64_t>::max()) {
            throw std::invalid_argument(std::string(operation) +
                                        ": byte limit exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(maximum);
}

std::vector<std::uint8_t> MockBackend::serialize_for_storage(
    const EvalContext &context, const Ciphertext &ciphertext) {
    std::vector<std::uint8_t> output;
    append_storage_serialization(context, ciphertext, output);
    return output;
}

void MockBackend::append_storage_serialization(
    const EvalContext &context, const Ciphertext &ciphertext,
    std::vector<std::uint8_t> &output) {
    constexpr const char *operation =
        "MockBackend::append_storage_serialization";
    validate_parameters(context.parameters);
    validate_ciphertext(context.parameters, ciphertext, operation);
    if (!ciphertext.coefficient_commitment_coordinates.empty() &&
        !has_commitment_coordinates(ciphertext)) {
        throw std::invalid_argument(
            std::string(operation) +
            ": commitment-coordinate length is not canonical");
    }
    if (std::any_of(
            ciphertext.coefficient_commitment_coordinates.begin(),
            ciphertext.coefficient_commitment_coordinates.end(),
            [](std::uint64_t value) { return value >= kOuterFieldOrder; })) {
        throw std::invalid_argument(
            std::string(operation) +
            ": commitment coordinate is outside the native field");
    }

    const std::size_t append_bytes = mock_storage_size(
        ciphertext.slots.size(),
        ciphertext.coefficient_commitment_coordinates.size(), operation);
    if (append_bytes >
        std::numeric_limits<std::size_t>::max() - output.size()) {
        throw std::invalid_argument(std::string(operation) +
                                    ": output length overflows");
    }
    output.reserve(output.size() + append_bytes);
    output.insert(output.end(), kMockStorageMagic.begin(),
                  kMockStorageMagic.end());
    output.push_back(kMockStorageVersion);
    const Digest context_id = storage_context_id(context);
    output.insert(output.end(), context_id.begin(), context_id.end());
    append_u64(output, context.parameters.slot_count);
    append_u64(output, context.parameters.fresh_rns_limbs);
    append_u64(output, context.parameters.bits_per_limb);
    append_u64(output, context.parameters.initial_noise_margin_bits);
    append_u64(output, context.parameters.rotation_noise_bits);
    append_u64(output, context.parameters.relinearization_noise_bits);
    append_u64(output, ciphertext.rns_limbs);
    output.push_back(ciphertext.relinearized ? 1 : 0);
    append_u64(output, ciphertext.depth_half_levels);
    append_u64(output, ciphertext.noise_loss_bits);
    append_u64(output,
               ciphertext.coefficient_commitment_coordinates.size());
    for (const Fp &slot : ciphertext.slots) {
        const SerializedFp encoded = laminate::serialize(slot);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
    for (const std::uint64_t coordinate :
         ciphertext.coefficient_commitment_coordinates) {
        append_u64(output, coordinate);
    }
}

std::vector<std::uint8_t> MockBackend::serialize_for_storage(
    const ClientContext &context, const Ciphertext &ciphertext) {
    return serialize_for_storage(
        PublicVerifierContext(context.parameters), ciphertext);
}

std::vector<std::uint8_t> MockBackend::serialize_for_storage(
    const PublicVerifierContext &context,
    const Ciphertext &ciphertext) {
    return serialize_for_storage(mock_verifier_eval_context(context),
                                 ciphertext);
}

MockBackend::Ciphertext MockBackend::deserialize_from_storage(
    const EvalContext &context, std::span<const std::uint8_t> bytes) {
    constexpr const char *operation =
        "MockBackend::deserialize_from_storage";
    validate_parameters(context.parameters);
    if (bytes.size() < kMockStorageFixedBytes ||
        !std::equal(kMockStorageMagic.begin(), kMockStorageMagic.end(),
                    bytes.begin())) {
        throw std::invalid_argument(std::string(operation) +
                                    ": invalid storage header");
    }

    std::size_t offset = kMockStorageMagic.size();
    if (bytes[offset++] != kMockStorageVersion) {
        throw std::invalid_argument(std::string(operation) +
                                    ": unsupported encoding version");
    }
    Digest encoded_context_id{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                encoded_context_id.size(), encoded_context_id.begin());
    offset += encoded_context_id.size();
    if (encoded_context_id != storage_context_id(context)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": storage context mismatch");
    }
    const MockParameters encoded_parameters{
        .slot_count =
            checked_size(read_u64(bytes, offset, operation), operation),
        .fresh_rns_limbs =
            checked_size(read_u64(bytes, offset, operation), operation),
        .bits_per_limb =
            checked_size(read_u64(bytes, offset, operation), operation),
        .initial_noise_margin_bits =
            checked_size(read_u64(bytes, offset, operation), operation),
        .rotation_noise_bits =
            checked_size(read_u64(bytes, offset, operation), operation),
        .relinearization_noise_bits =
            checked_size(read_u64(bytes, offset, operation), operation),
    };
    const std::size_t rns_limbs =
        checked_size(read_u64(bytes, offset, operation), operation);
    const std::uint8_t relinearized = bytes[offset++];
    if (relinearized > 1) {
        throw std::invalid_argument(std::string(operation) +
                                    ": noncanonical Boolean flag");
    }
    const std::size_t depth_half_levels =
        checked_size(read_u64(bytes, offset, operation), operation);
    const std::size_t noise_loss_bits =
        checked_size(read_u64(bytes, offset, operation), operation);
    const std::size_t coordinate_count =
        checked_size(read_u64(bytes, offset, operation), operation);

    if (encoded_parameters.slot_count != context.parameters.slot_count ||
        encoded_parameters.fresh_rns_limbs !=
            context.parameters.fresh_rns_limbs ||
        encoded_parameters.bits_per_limb !=
            context.parameters.bits_per_limb ||
        encoded_parameters.initial_noise_margin_bits !=
            context.parameters.initial_noise_margin_bits ||
        encoded_parameters.rotation_noise_bits !=
            context.parameters.rotation_noise_bits ||
        encoded_parameters.relinearization_noise_bits !=
            context.parameters.relinearization_noise_bits) {
        throw std::invalid_argument(std::string(operation) +
                                    ": encoded parameters do not match context");
    }
    const std::size_t slot_count = encoded_parameters.slot_count;
    if (coordinate_count != 0 &&
        (slot_count > std::numeric_limits<std::size_t>::max() / 2U ||
         coordinate_count != 2 * slot_count)) {
        throw std::invalid_argument(
            std::string(operation) +
            ": commitment-coordinate length is not canonical");
    }
    if (bytes.size() !=
        mock_storage_size(slot_count, coordinate_count, operation)) {
        throw std::invalid_argument(std::string(operation) +
                                    ": truncated or trailing storage data");
    }

    SlotVector slots;
    slots.reserve(slot_count);
    for (std::size_t slot = 0; slot < slot_count; ++slot) {
        slots.push_back(deserialize_fp(
            bytes.subspan(offset, kSerializedFpBytes)));
        offset += kSerializedFpBytes;
    }
    std::vector<std::uint64_t> coordinates;
    coordinates.reserve(coordinate_count);
    for (std::size_t coordinate = 0; coordinate < coordinate_count;
         ++coordinate) {
        const std::uint64_t value = read_u64(bytes, offset, operation);
        if (value >= kOuterFieldOrder) {
            throw std::invalid_argument(
                std::string(operation) +
                ": commitment coordinate is outside the native field");
        }
        coordinates.push_back(value);
    }

    Ciphertext result{std::move(slots), rns_limbs, relinearized != 0,
                      depth_half_levels, noise_loss_bits,
                      std::move(coordinates), fresh_ciphertext_identity()};
    validate_ciphertext(context.parameters, result, operation);
    return result;
}

MockBackend::Ciphertext MockBackend::deserialize_from_storage(
    const ClientContext &context,
    std::span<const std::uint8_t> bytes) {
    return deserialize_from_storage(
        PublicVerifierContext(context.parameters), bytes);
}

MockBackend::Ciphertext MockBackend::deserialize_from_storage(
    const PublicVerifierContext &context,
    std::span<const std::uint8_t> bytes) {
    return deserialize_from_storage(mock_verifier_eval_context(context),
                                    bytes);
}

std::vector<std::int64_t>
MockBackend::encode_centered_plaintext_coefficients(
    const EvalContext &context, const SlotVector &slots) {
    const SlotVector padded = padded_plaintext(
        context.parameters, slots,
        "MockBackend::encode_centered_plaintext_coefficients");
    const std::uint64_t radius = (kBaseFieldOrder - 1) / 2;
    std::vector<std::int64_t> result;
    result.reserve(padded.size());
    for (const Fp &slot : padded) {
        // A diagonal invertible transform is enough for the exact mock. The
        // large scale makes all four base-17 digit rows nontransparent, like
        // a real batching transform, while `decode` remains its exact inverse.
        const std::uint64_t residue =
            (slot * Fp(std::uint64_t{32768})).value();
        result.push_back(
            residue <= radius
                ? static_cast<std::int64_t>(residue)
                : -static_cast<std::int64_t>(kBaseFieldOrder - residue));
    }
    return result;
}

std::vector<std::int64_t>
MockBackend::encode_centered_plaintext_coefficients(
    const PublicVerifierContext &context, const SlotVector &slots) {
    return encode_centered_plaintext_coefficients(
        mock_verifier_eval_context(context), slots);
}

SlotVector MockBackend::decode_centered_plaintext_coefficients(
    const EvalContext &context,
    std::span<const std::int64_t> centered_coefficients) {
    const std::int64_t radius =
        static_cast<std::int64_t>((kBaseFieldOrder - 1) / 2);
    if (centered_coefficients.size() != context.parameters.slot_count) {
        throw std::invalid_argument(
            "MockBackend::decode_centered_plaintext_coefficients: wrong "
            "coefficient count");
    }
    SlotVector result;
    result.reserve(centered_coefficients.size());
    const Fp inverse_scale = Fp(std::uint64_t{32768}).inverse();
    for (const std::int64_t coefficient : centered_coefficients) {
        if (coefficient < -radius || coefficient > radius) {
            throw std::invalid_argument(
                "MockBackend::decode_centered_plaintext_coefficients: "
                "coefficient is outside the centered interval");
        }
        const std::uint64_t residue =
            coefficient >= 0
                ? static_cast<std::uint64_t>(coefficient)
                : kBaseFieldOrder -
                      static_cast<std::uint64_t>(-coefficient);
        result.push_back(Fp(residue) * inverse_scale);
    }
    return result;
}

SlotVector MockBackend::decode_centered_plaintext_coefficients(
    const PublicVerifierContext &context,
    std::span<const std::int64_t> centered_coefficients) {
    return decode_centered_plaintext_coefficients(
        mock_verifier_eval_context(context), centered_coefficients);
}

std::uint64_t MockBackend::lowest_coefficient_modulus(
    const EvalContext &context) {
    validate_parameters(context.parameters);
    return kOuterFieldOrder;
}

std::vector<std::uint64_t>
MockBackend::encode_lowest_plaintext_ntt_coordinates(
    const EvalContext &context,
    std::span<const std::int64_t> centered_coefficients) {
    const SlotVector decoded = decode_centered_plaintext_coefficients(
        context, centered_coefficients);
    std::vector<std::uint64_t> result;
    result.reserve(decoded.size());
    for (const Fp value : decoded) {
        result.push_back(value.value());
    }
    return result;
}

std::vector<std::uint64_t>
MockBackend::encode_lowest_plaintext_ntt_coordinates(
    const PublicVerifierContext &context,
    std::span<const std::int64_t> centered_coefficients) {
    return encode_lowest_plaintext_ntt_coordinates(
        mock_verifier_eval_context(context), centered_coefficients);
}

void MockBackend::normalize_for_coefficient_commitment(
    const EvalContext &context, Ciphertext &ciphertext) {
    mod_switch_to_lowest(context, ciphertext);
    if (!ciphertext.relinearized) {
        throw std::invalid_argument(
            "MockBackend::normalize_for_coefficient_commitment: "
            "ciphertext must have size two");
    }
    ciphertext.coefficient_commitment_coordinates.assign(
        2 * ciphertext.slots.size(), 0);
    for (std::size_t coordinate = 0; coordinate < ciphertext.slots.size();
         ++coordinate) {
        ciphertext.coefficient_commitment_coordinates[coordinate] =
            ciphertext.slots[coordinate].value();
    }
    assign_fresh_identity(ciphertext);
}

bool MockBackend::is_normalized_for_coefficient_commitment(
    const Ciphertext &ciphertext) {
    return ciphertext.rns_limbs == 1 && ciphertext.relinearized &&
           has_commitment_coordinates(ciphertext);
}

std::span<const std::uint64_t>
MockBackend::coefficient_commitment_ntt_coordinate_view(
    const Ciphertext &ciphertext) {
    if (!is_normalized_for_coefficient_commitment(ciphertext)) {
        throw std::invalid_argument(
            "MockBackend::coefficient_commitment_ntt_coordinate_view: "
            "ciphertext is not normalized");
    }
    return ciphertext.coefficient_commitment_coordinates;
}

std::uint64_t MockBackend::partial_decryption_infinity_norm(
    const ClientContext &context, const Ciphertext &ciphertext) {
    validate_ciphertext(context.parameters, ciphertext,
                        "MockBackend::partial_decryption_infinity_norm");
    // This is a scheduling mock, not a coefficient-noise model. Preserve a
    // monotone diagnostic without pretending to reproduce BGV error.
    return std::uint64_t{1} + ciphertext.noise_loss_bits;
}

std::uint64_t
MockBackend::partial_decryption_with_public_ntt_offset_infinity_norm(
    const ClientContext &context, const Ciphertext *ciphertext,
    std::span<const std::uint64_t> public_c0_coordinates) {
    const std::size_t degree = context.parameters.slot_count;
    if (!public_c0_coordinates.empty() &&
        public_c0_coordinates.size() != degree) {
        throw std::invalid_argument(
            "MockBackend::partial_decryption_with_public_ntt_offset_"
            "infinity_norm: wrong public coordinate count");
    }
    std::vector<std::uint64_t> combined(degree, 0);
    if (ciphertext != nullptr) {
        validate_ciphertext(
            context.parameters, *ciphertext,
            "MockBackend::partial_decryption_with_public_ntt_offset_"
            "infinity_norm");
        if (!is_normalized_for_coefficient_commitment(*ciphertext)) {
            throw std::invalid_argument(
                "MockBackend mixed partial-decryption input is not "
                "normalized");
        }
        const auto coordinates =
            coefficient_commitment_ntt_coordinate_view(*ciphertext);
        std::copy_n(coordinates.begin(), degree, combined.begin());
    }
    for (std::size_t index = 0; index < public_c0_coordinates.size();
         ++index) {
        const std::uint64_t value = public_c0_coordinates[index];
        if (value >= kOuterFieldOrder) {
            throw std::invalid_argument(
                "MockBackend mixed public coordinate is outside Fq");
        }
        combined[index] = combined[index] >= kOuterFieldOrder - value
                              ? combined[index] -
                                    (kOuterFieldOrder - value)
                              : combined[index] + value;
    }
    const std::uint64_t half = kOuterFieldOrder >> 1U;
    std::uint64_t maximum = 0;
    for (const std::uint64_t value : combined) {
        maximum = std::max(maximum,
                           value > half ? kOuterFieldOrder - value : value);
    }
    return maximum;
}

bool MockBackend::partial_decryption_within_bound(
    const ClientContext &context, const Ciphertext &ciphertext,
    std::uint64_t threshold) {
    return partial_decryption_infinity_norm(context, ciphertext) <= threshold;
}

const OperationCounts &MockBackend::counts(const EvalContext &context) {
    validate_counters(context.counters, "MockBackend::counts");
    return *context.counters;
}

void MockBackend::reset_counts(const EvalContext &context) {
    validate_counters(context.counters, "MockBackend::reset_counts");
    *context.counters = OperationCounts{};
}

} // namespace laminate::fhe
