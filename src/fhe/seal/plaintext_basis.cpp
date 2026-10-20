/// @file plaintext_basis.cpp
/// @brief Plaintext arithmetic and prepared Base/Fpk slot bases.
///
/// Public slot vectors are encoded or preprocessed here. Raw ciphertext
/// multiplication and modulus switching remain in `arithmetic.cpp`.

#include "arithmetic_internal.hpp"
#include "state.hpp"

#include "seal/util/polyarithsmallmod.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace laminate::fhe::seal_detail {

seal::Plaintext encode_slots(const std::shared_ptr<seal::BatchEncoder> &encoder,
                             const SlotVector &slots,
                             const char *operation) {
    const std::size_t width = encoder->slot_count();
    if (slots.size() > width) {
        throw std::invalid_argument(std::string(operation) +
                                    ": plaintext exceeds the slot count");
    }
    std::vector<std::uint64_t> values(width, 0);
    for (std::size_t slot = 0; slot < slots.size(); ++slot) {
        values[slot] = slots[slot].value();
    }
    seal::Plaintext result;
    encoder->encode(values, result);
    return result;
}

bool is_scalar_plaintext(const SlotVector &plaintext, std::size_t width) {
    const Fp first = plaintext.empty() ? Fp::zero() : plaintext.front();
    for (std::size_t slot = 0; slot < width; ++slot) {
        const Fp value =
            slot < plaintext.size() ? plaintext[slot] : Fp::zero();
        if (!(value == first)) {
            return false;
        }
    }
    return true;
}

bool is_zero_plaintext(const SlotVector &plaintext) {
    return std::all_of(plaintext.begin(), plaintext.end(),
                       [](const Fp &value) { return value.is_zero(); });
}

SlotVector canonical_plaintext(const SlotVector &plaintext,
                               std::size_t width,
                               const char *operation) {
    if (plaintext.size() > width) {
        throw std::invalid_argument(std::string(operation) +
                                    ": plaintext exceeds the slot count");
    }
    SlotVector result(width, Fp::zero());
    std::copy(plaintext.begin(), plaintext.end(), result.begin());
    return result;
}

std::uint64_t plaintext_cache_hash(std::span<const Fp> plaintext) {
    // The hash is only a lookup accelerator.  Every hit is followed by an
    // exact SlotVector comparison, so collisions cannot change arithmetic.
    std::uint64_t result = 1469598103934665603ULL;
    constexpr std::uint64_t prime = 1099511628211ULL;
    for (const Fp &value : plaintext) {
        std::uint64_t word = value.value();
        for (std::size_t byte = 0; byte < sizeof(word); ++byte) {
            result ^= (word >> (8U * byte)) & UINT64_C(0xff);
            result *= prime;
        }
    }
    return result;
}

std::shared_ptr<const SealBackend::PreparedPlaintextCache::Entry>
find_preprocessed_plaintext(const EvalContext &context,
                            std::span<const Fp> plaintext) {
    if (!context.prepared_plaintexts) {
        return {};
    }
    const std::uint64_t hash = plaintext_cache_hash(plaintext);
    std::lock_guard lock(context.prepared_plaintexts->mutex);
    const auto bucket = context.prepared_plaintexts->by_hash.find(hash);
    if (bucket == context.prepared_plaintexts->by_hash.end()) {
        return {};
    }
    for (const auto &entry : bucket->second) {
        if (std::equal(entry->slots.begin(), entry->slots.end(),
                       plaintext.begin(), plaintext.end())) {
            return entry;
        }
    }
    return {};
}

const seal::Plaintext &preprocessed_at_ciphertext_level(
    const SealBackend::PreparedPlaintextCache::Entry &entry,
    const Ciphertext &ciphertext) {
    const auto found = entry.by_level.find(ciphertext.raw.parms_id());
    if (found == entry.by_level.end()) {
        throw std::logic_error(
            "SealBackend: preprocessed plaintext is missing a data level");
    }
    return found->second;
}

Ciphertext multiply_plain_encoded(
    const EvalContext &context, const Ciphertext &ciphertext,
    const seal::Plaintext &encoded, bool scalar) {
    Ciphertext result = ciphertext;
    if (const auto *bound = tracked_bound(context, ciphertext)) {
        result.deterministic_noise_bound =
            bound_plaintext_multiplication(
                *bound, plaintext_l1_bound(context, scalar),
                data_moduli(context, result));
    }
    try {
        record(context,
               scalar ? OperationKind::MulPlainScalar
                      : OperationKind::MulPlainVector,
               result);
        context.evaluator->multiply_plain_inplace(result.raw, encoded);
    } catch (const std::logic_error &error) {
        if (result.raw.is_transparent()) {
            reject_transparent_result("SealBackend::mul_plain");
        }
        rethrow("SealBackend::mul_plain", error);
    }
    if (result.raw.is_transparent()) {
        reject_transparent_result("SealBackend::mul_plain");
    }
    result.noise_loss_bits = saturated_add(
        ciphertext.noise_loss_bits,
        scalar ? scalar_noise_bits()
               : full_multiplication_noise_bits(
                     SealBackend::slot_count(context)));
    return result;
}

Ciphertext multiply_plain_scalar_direct(
    const EvalContext &context, const Ciphertext &ciphertext,
    const Fp &scalar) {
    if (scalar.is_zero()) {
        reject_transparent_result("SealBackend::mul_plain_scalar");
    }
    const auto level =
        context.context->get_context_data(ciphertext.raw.parms_id());
    if (!level) {
        throw std::invalid_argument(
            "SealBackend::mul_plain: unknown ciphertext parameters");
    }

    Ciphertext result = ciphertext;
    if (const auto *bound = tracked_bound(context, ciphertext)) {
        result.deterministic_noise_bound =
            bound_plaintext_multiplication(
                *bound, plaintext_l1_bound(context, true),
                data_moduli(context, result));
    }
    record(context, OperationKind::MulPlainScalar, result);

    const std::size_t degree = result.raw.poly_modulus_degree();
    const auto &moduli = level->parms().coeff_modulus();
    const std::uint64_t value = scalar.value();
    const std::uint64_t threshold =
        level->plain_upper_half_threshold();
    for (std::size_t component = 0; component < result.raw.size();
         ++component) {
        std::uint64_t *component_data = result.raw.data(component);
        for (std::size_t limb = 0; limb < moduli.size(); ++limb) {
            const std::uint64_t lifted =
                value < threshold
                    ? value
                    : moduli[limb].value() -
                          (kBaseFieldOrder - value);
            seal::util::multiply_poly_scalar_coeffmod(
                component_data + limb * degree, degree, lifted,
                moduli[limb], component_data + limb * degree);
        }
    }
    result.noise_loss_bits = saturated_add(
        ciphertext.noise_loss_bits, scalar_noise_bits());
    return result;
}

seal::Plaintext encode_plaintext_at_ciphertext_level(
    const EvalContext &context, const SlotVector &plaintext,
    const Ciphertext &ciphertext) {
    seal::Plaintext result = encode_slots(
        context.encoder, plaintext,
        "SealBackend::ext_mul_plain");
    context.evaluator->transform_to_ntt_inplace(
        result, ciphertext.raw.parms_id());
    return result;
}


} // namespace laminate::fhe::seal_detail

namespace laminate::fhe {

using namespace seal_detail;

// --------------------------------------------------------------------------
// One-shot plaintext/ciphertext arithmetic.
//
// Vector multiplications reuse a preprocessed NTT plaintext when setup has
// registered an exact match. Scalars take a direct coefficient-wise path and
// avoid allocating a slot-sized temporary.
// --------------------------------------------------------------------------

SealBackend::Ciphertext SealBackend::add_plain(
    const EvalContext &context, const Ciphertext &ciphertext,
    const SlotVector &plaintext) {
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.add_plain_vector_api_calls;
        context.counters->counts.add_plain_vector_api_elements +=
            plaintext.size();
    }
    const seal::Plaintext encoded =
        encode_slots(context.encoder, plaintext, "SealBackend::add_plain");
    Ciphertext result = ciphertext;
    if (const auto *bound = tracked_bound(context, ciphertext)) {
        result.deterministic_noise_bound = bound_plaintext_addition(
            *bound, plaintext_radius(), data_moduli(context, result));
    }
    try {
        record(context, OperationKind::AddPlain, result);
        context.evaluator->add_plain_inplace(result.raw, encoded);
    } catch (const std::logic_error &error) {
        if (result.raw.is_transparent()) {
            reject_transparent_result("SealBackend::add_plain");
        }
        rethrow("SealBackend::add_plain", error);
    }
    if (result.raw.is_transparent()) {
        reject_transparent_result("SealBackend::add_plain");
    }
    return result;
}

SealBackend::Ciphertext SealBackend::add_plain_scalar(
    const EvalContext &context, const Ciphertext &ciphertext,
    const Fp &plaintext) {
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.add_plain_scalar_api_calls;
    }
    seal::Plaintext encoded;
    encoded.resize(1);
    encoded[0] = plaintext.value();

    Ciphertext result = ciphertext;
    if (const auto *bound = tracked_bound(context, ciphertext)) {
        result.deterministic_noise_bound = bound_plaintext_addition(
            *bound, plaintext_radius(), data_moduli(context, result));
    }
    try {
        record(context, OperationKind::AddPlain, result);
        context.evaluator->add_plain_inplace(result.raw, encoded);
    } catch (const std::logic_error &error) {
        if (result.raw.is_transparent()) {
            reject_transparent_result("SealBackend::add_plain_scalar");
        }
        rethrow("SealBackend::add_plain_scalar", error);
    }
    if (result.raw.is_transparent()) {
        reject_transparent_result("SealBackend::add_plain_scalar");
    }
    return result;
}

SealBackend::Ciphertext SealBackend::mul_plain(
    const EvalContext &context, const Ciphertext &ciphertext,
    const SlotVector &plaintext) {
    const std::size_t width = slot_count(context);
    if (plaintext.size() > width) {
        throw std::invalid_argument(
            "SealBackend::mul_plain: plaintext exceeds the slot count");
    }
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.mul_plain_vector_api_calls;
        context.counters->counts.mul_plain_vector_api_elements +=
            plaintext.size();
    }
    const bool scalar =
        is_scalar_plaintext(plaintext, width);
    if (scalar) {
        return multiply_plain_scalar_direct(
            context, ciphertext,
            plaintext.empty() ? Fp::zero() : plaintext.front());
    }
    // Cached setup plaintexts are canonical full-width vectors. Avoid an
    // N-slot allocation on every online multiplication merely to probe the
    // cache; shortened vectors still use SEAL's ordinary zero-padding path.
    const auto prepared = plaintext.size() == width
                              ? find_preprocessed_plaintext(context,
                                                            plaintext)
                              : nullptr;
    std::optional<seal::Plaintext> online_encoded;
    const seal::Plaintext *encoded = nullptr;
    if (prepared) {
        encoded = &preprocessed_at_ciphertext_level(*prepared, ciphertext);
    } else {
        online_encoded = encode_slots(
            context.encoder, plaintext, "SealBackend::mul_plain");
        encoded = &*online_encoded;
    }
    return multiply_plain_encoded(
        context, ciphertext, *encoded, false);
}

SealBackend::Ciphertext SealBackend::mul_plain_scalar(
    const EvalContext &context, const Ciphertext &ciphertext,
    const Fp &plaintext) {
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.mul_plain_scalar_api_calls;
    }
    return multiply_plain_scalar_direct(context, ciphertext, plaintext);
}

// --------------------------------------------------------------------------
// Prepared base-field slot bases.
//
// These immutable handles bind a setup-time public vector to one SEAL context
// and provide the plaintext at the ciphertext's current RNS level.
// --------------------------------------------------------------------------

SealBackend::PreparedSlotBasis SealBackend::prepare_slot_basis(
    const EvalContext &context, const SlotVector &basis) {
    const std::size_t width = slot_count(context);
    if (basis.size() != width) {
        throw std::invalid_argument(
            "SealBackend::prepare_slot_basis: basis must fill all slots");
    }
    auto impl = std::make_shared<PreparedSlotBasis::Impl>();
    impl->storage_id = context.storage_id;
    impl->slot_count = width;
    impl->zero = is_zero_plaintext(basis);
    if (!impl->zero) {
        impl->scalar = is_scalar_plaintext(basis, width);
        if (impl->scalar) {
            impl->scalar_value = basis.front();
        } else {
            (void)preprocess_plaintext(context, basis);
            impl->vector = find_preprocessed_plaintext(context, basis);
            if (!impl->vector) {
                throw std::logic_error(
                    "SealBackend::prepare_slot_basis: preprocessing did "
                    "not retain the basis");
            }
        }
    }
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.prepared_base_basis_setup_calls;
    }
    return PreparedSlotBasis(std::move(impl));
}

SealBackend::Ciphertext SealBackend::mul_plain_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedSlotBasis &basis) {
    if (!basis.impl_ || basis.impl_->storage_id != context.storage_id ||
        basis.impl_->slot_count != slot_count(context)) {
        throw std::invalid_argument(
            "SealBackend::mul_plain_prepared: basis belongs to another "
            "context");
    }
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.prepared_base_basis_api_calls;
    }
    if (basis.impl_->zero) {
        return multiply_plain_scalar_direct(
            context, ciphertext, Fp::zero());
    }
    if (basis.impl_->scalar) {
        return multiply_plain_scalar_direct(
            context, ciphertext, basis.impl_->scalar_value);
    }
    if (context.counters && context.counters->enabled) {
        context.counters->counts
            .prepared_base_basis_avoided_vector_elements +=
            basis.impl_->slot_count;
        ++context.counters->counts
              .prepared_base_basis_avoided_batch_encodes;
    }
    return multiply_plain_encoded(
        context, ciphertext,
        preprocessed_at_ciphertext_level(*basis.impl_->vector,
                                         ciphertext),
        false);
}

SealBackend::PreparedLevelSlotBasis
SealBackend::prepare_level_slot_basis(
    const EvalContext &context, const Ciphertext &level_reference,
    const SlotVector &basis) {
    const std::size_t width = slot_count(context);
    if (basis.size() != width ||
        !context.context->get_context_data(
            level_reference.raw.parms_id())) {
        throw std::invalid_argument(
            "SealBackend::prepare_level_slot_basis: invalid basis or "
            "reference level");
    }
    auto impl = std::make_shared<PreparedLevelSlotBasis::Impl>();
    impl->storage_id = context.storage_id;
    impl->parms_id = level_reference.raw.parms_id();
    impl->slot_count = width;
    impl->zero = is_zero_plaintext(basis);
    if (!impl->zero) {
        impl->scalar = is_scalar_plaintext(basis, width);
        if (impl->scalar) {
            impl->scalar_value = basis.front();
        } else {
            impl->vector = encode_plaintext_at_ciphertext_level(
                context, basis, level_reference);
            impl->level_representations = 1;
            impl->ntt_coefficient_bytes =
                impl->vector->coeff_count() * sizeof(std::uint64_t);
        }
    }
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.prepared_base_basis_setup_calls;
        context.counters->counts
            .prepared_base_basis_level_representations +=
            impl->level_representations;
        context.counters->counts.prepared_base_basis_ntt_bytes_created +=
            impl->ntt_coefficient_bytes;
    }
    return PreparedLevelSlotBasis(std::move(impl));
}

SealBackend::Ciphertext SealBackend::mul_plain_level_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedLevelSlotBasis &basis) {
    if (!basis.impl_ || basis.impl_->storage_id != context.storage_id ||
        basis.impl_->slot_count != slot_count(context) ||
        basis.impl_->parms_id != ciphertext.raw.parms_id()) {
        throw std::invalid_argument(
            "SealBackend::mul_plain_level_prepared: basis belongs to "
            "another context or level");
    }
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.prepared_base_basis_api_calls;
    }
    if (basis.impl_->zero) {
        return multiply_plain_scalar_direct(
            context, ciphertext, Fp::zero());
    }
    if (basis.impl_->scalar) {
        return multiply_plain_scalar_direct(
            context, ciphertext, basis.impl_->scalar_value);
    }
    if (context.counters && context.counters->enabled) {
        context.counters->counts
            .prepared_base_basis_avoided_vector_elements +=
            basis.impl_->slot_count;
        ++context.counters->counts
              .prepared_base_basis_avoided_batch_encodes;
    }
    return multiply_plain_encoded(
        context, ciphertext, *basis.impl_->vector, false);
}

PreparedBasisStorageStats
SealBackend::prepared_level_slot_basis_storage(
    const PreparedLevelSlotBasis &basis) {
    if (!basis.impl_) {
        throw std::invalid_argument(
            "SealBackend::prepared_level_slot_basis_storage: empty basis");
    }
    return PreparedBasisStorageStats{
        basis.impl_->level_representations,
        basis.impl_->ntt_coefficient_bytes,
        0};
}

void SealBackend::preprocess_fixed_message_cells(
    const EvalContext &context) {
    if (!context.prepared_plaintexts) {
        throw std::logic_error(
            "SealBackend::preprocess_fixed_message_cells: cache is "
            "unavailable");
    }
    const std::size_t width = slot_count(context);
    if (width < kFixedMessageCellCount) {
        throw std::invalid_argument(
            "SealBackend::preprocess_fixed_message_cells: too few slots");
    }
    {
        std::lock_guard lock(context.prepared_plaintexts->mutex);
        if (std::all_of(
                context.prepared_plaintexts->fixed_message_cells.begin(),
                context.prepared_plaintexts->fixed_message_cells.end(),
                [](const auto &entry) { return entry != nullptr; })) {
            return;
        }
    }

    std::array<std::shared_ptr<const PreparedPlaintextCache::Entry>,
               kFixedMessageCellCount>
        prepared{};
    for (std::size_t cell = 0; cell < kFixedMessageCellCount; ++cell) {
        SlotVector mask(width, Fp::zero());
        mask[fixed_message_cell_slot(width, cell)] = Fp::one();
        (void)preprocess_plaintext(context, mask);
        prepared[cell] = find_preprocessed_plaintext(context, mask);
        if (!prepared[cell]) {
            throw std::logic_error(
                "SealBackend::preprocess_fixed_message_cells: "
                "preprocessing did not retain a cell mask");
        }
    }

    bool installed = false;
    {
        std::lock_guard lock(context.prepared_plaintexts->mutex);
        if (!std::all_of(
                context.prepared_plaintexts->fixed_message_cells.begin(),
                context.prepared_plaintexts->fixed_message_cells.end(),
                [](const auto &entry) { return entry != nullptr; })) {
            context.prepared_plaintexts->fixed_message_cells =
                std::move(prepared);
            installed = true;
        }
    }
    if (installed && context.counters && context.counters->enabled) {
        context.counters->counts.fixed_message_basis_setup_calls +=
            kFixedMessageCellCount;
    }
}

// --------------------------------------------------------------------------
// Fixed-message cell lookup.
//
// A setup bundle contains one prepared plaintext for every message cell and
// RNS level. Online GKR scans select an entry without re-encoding or an NTT.
// --------------------------------------------------------------------------

SealBackend::Ciphertext SealBackend::mul_plain_fixed_message_cell(
    const EvalContext &context, const Ciphertext &ciphertext,
    std::size_t cell) {
    if (cell >= kFixedMessageCellCount) {
        throw std::invalid_argument(
            "SealBackend::mul_plain_fixed_message_cell: cell is out of "
            "range");
    }
    if (!context.prepared_plaintexts) {
        throw std::logic_error(
            "SealBackend::mul_plain_fixed_message_cell: cache is "
            "unavailable");
    }
    std::shared_ptr<const PreparedPlaintextCache::Entry> prepared;
    {
        std::lock_guard lock(context.prepared_plaintexts->mutex);
        prepared = context.prepared_plaintexts->fixed_message_cells[cell];
    }
    if (!prepared) {
        throw std::logic_error(
            "SealBackend::mul_plain_fixed_message_cell: fixed cells were "
            "not preprocessed");
    }
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.fixed_message_basis_api_calls;
        context.counters->counts
            .fixed_message_basis_avoided_vector_elements +=
            prepared->slots.size();
        ++context.counters->counts
              .fixed_message_basis_avoided_batch_encodes;
        ++context.counters->counts
              .fixed_message_basis_avoided_hash_probes;
    }
    return multiply_plain_encoded(
        context, ciphertext,
        preprocessed_at_ciphertext_level(*prepared, ciphertext), false);
}

// --------------------------------------------------------------------------
// Prepared degree-eight extension slot bases.
//
// Each public extension coefficient has its own prepared base-field basis;
// absent coefficients remain known public zeros and perform no FHE work.
// --------------------------------------------------------------------------

SealBackend::PreparedExtensionSlotBasis
SealBackend::prepare_extension_slot_basis(
    const EvalContext &context, const Ciphertext &level_reference,
    const PlainExtension &basis) {
    const std::size_t width = slot_count(context);
    if (!context.context->get_context_data(
            level_reference.raw.parms_id())) {
        throw std::invalid_argument(
            "SealBackend::prepare_extension_slot_basis: reference has an "
            "unknown level");
    }
    auto impl =
        std::make_shared<PreparedExtensionSlotBasis::Impl>();
    impl->storage_id = context.storage_id;
    impl->parms_id = level_reference.raw.parms_id();
    impl->slot_count = width;
    for (std::size_t coefficient = 0; coefficient < basis.size();
         ++coefficient) {
        if (basis[coefficient].size() != width) {
            throw std::invalid_argument(
                "SealBackend::prepare_extension_slot_basis: every "
                "coefficient must fill all slots");
        }
        auto &prepared = impl->coefficients[coefficient];
        prepared.zero = is_zero_plaintext(basis[coefficient]);
        if (prepared.zero) {
            continue;
        }
        prepared.scalar = is_scalar_plaintext(basis[coefficient], width);
        if (prepared.scalar) {
            prepared.scalar_value = basis[coefficient].front();
            continue;
        }
        prepared.vector = encode_plaintext_at_ciphertext_level(
            context, basis[coefficient], level_reference);
        ++impl->level_representations;
        impl->ntt_coefficient_bytes +=
            prepared.vector->coeff_count() * sizeof(std::uint64_t);
        if (context.counters && context.counters->enabled) {
            ++context.counters->counts
                  .prepared_extension_basis_level_representations;
            context.counters->counts
                .prepared_extension_basis_ntt_bytes_created +=
                prepared.vector->coeff_count() * sizeof(std::uint64_t);
        }
    }
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.prepared_extension_basis_setup_calls;
    }
    return PreparedExtensionSlotBasis(std::move(impl));
}

SealBackend::ExtCiphertext SealBackend::ext_mul_plain_prepared(
    const EvalContext &context, const ExtCiphertext &ciphertext,
    const PreparedExtensionSlotBasis &basis) {
    if (!basis.impl_ || basis.impl_->storage_id != context.storage_id ||
        basis.impl_->slot_count != slot_count(context)) {
        throw std::invalid_argument(
            "SealBackend::ext_mul_plain_prepared: basis belongs to another "
            "context");
    }
    const Ciphertext *anchor = validate_extension_level(
        context, ciphertext,
        "SealBackend::ext_mul_plain_prepared");
    if (anchor != nullptr &&
        anchor->raw.parms_id() != basis.impl_->parms_id) {
        throw std::invalid_argument(
            "SealBackend::ext_mul_plain_prepared: basis has the wrong "
            "level");
    }
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts.prepared_extension_basis_api_calls;
    }

    if (anchor == nullptr) {
        return {};
    }
    record(context, OperationKind::LogicalExtMulPlain, *anchor);
    std::array<std::optional<Ciphertext>,
               2 * kExtensionDegree - 1>
        coefficients{};
    for (std::size_t plain_degree = 0;
         plain_degree < kExtensionDegree; ++plain_degree) {
        const auto &prepared = basis.impl_->coefficients[plain_degree];
        if (prepared.zero) {
            continue;
        }
        if (context.counters && context.counters->enabled &&
            !prepared.scalar) {
            context.counters->counts
                .prepared_extension_basis_avoided_vector_elements +=
                basis.impl_->slot_count;
            ++context.counters->counts
                  .prepared_extension_basis_avoided_batch_encodes;
        }
        for (std::size_t cipher_degree = 0;
             cipher_degree < kExtensionDegree; ++cipher_degree) {
            if (!ciphertext[cipher_degree]) {
                continue;
            }
            Ciphertext term = prepared.scalar
                                  ? multiply_plain_scalar_direct(
                                        context,
                                        *ciphertext[cipher_degree],
                                        prepared.scalar_value)
                                  : multiply_plain_encoded(
                                        context,
                                        *ciphertext[cipher_degree],
                                        *prepared.vector,
                                        false);
            auto &destination =
                coefficients[cipher_degree + plain_degree];
            accumulate_ciphertext_coordinate(
                context, destination, std::move(term),
                "SealBackend::ext_mul_plain_prepared");
        }
    }
    reduce_extension_polynomial(context, coefficients);

    ExtCiphertext result{};
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        result[coefficient] = std::move(coefficients[coefficient]);
    }
    return result;
}

SealBackend::ExtCiphertext SealBackend::promote_plain_prepared(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedExtensionSlotBasis &basis) {
    if (context.counters && context.counters->enabled) {
        ++context.counters->counts
              .prepared_extension_promotion_api_calls;
    }
    return promote_plain_prepared_untracked(context, ciphertext, basis);
}

SealBackend::ExtCiphertext SealBackend::promote_plain_prepared_untracked(
    const EvalContext &context, const Ciphertext &ciphertext,
    const PreparedExtensionSlotBasis &basis) {
    if (!basis.impl_ || basis.impl_->storage_id != context.storage_id ||
        basis.impl_->slot_count != slot_count(context) ||
        ciphertext.raw.parms_id() != basis.impl_->parms_id) {
        throw std::invalid_argument(
            "SealBackend::promote_plain_prepared_untracked: basis has the "
            "wrong context or level");
    }
    ExtCiphertext result{};
    for (std::size_t coefficient = 0;
         coefficient < kExtensionDegree; ++coefficient) {
        const auto &prepared = basis.impl_->coefficients[coefficient];
        if (prepared.zero) {
            continue;
        } else if (prepared.scalar) {
            result[coefficient] = multiply_plain_scalar_direct(
                context, ciphertext, prepared.scalar_value);
        } else {
            if (context.counters && context.counters->enabled) {
                context.counters->counts
                    .prepared_extension_basis_avoided_vector_elements +=
                    basis.impl_->slot_count;
                ++context.counters->counts
                      .prepared_extension_basis_avoided_batch_encodes;
            }
            result[coefficient] = multiply_plain_encoded(
                context, ciphertext, *prepared.vector, false);
        }
    }
    return result;
}

PreparedBasisStorageStats
SealBackend::prepared_extension_slot_basis_storage(
    const PreparedExtensionSlotBasis &basis) {
    if (!basis.impl_) {
        return {};
    }
    return PreparedBasisStorageStats{
        .level_representations = basis.impl_->level_representations,
        .ntt_coefficient_bytes = basis.impl_->ntt_coefficient_bytes,
        .host_basis_bytes = 0,
    };
}

// --------------------------------------------------------------------------
// Generic plaintext cache and extension/plaintext multiplication.
// --------------------------------------------------------------------------

bool SealBackend::preprocess_plaintext(
    const EvalContext &context, const SlotVector &plaintext) {
    if (!context.prepared_plaintexts) {
        throw std::logic_error(
            "SealBackend::preprocess_plaintext: cache is unavailable");
    }
    SlotVector canonical = canonical_plaintext(
        plaintext, slot_count(context),
        "SealBackend::preprocess_plaintext");
    if (is_zero_plaintext(canonical)) {
        throw std::invalid_argument(
            "SealBackend::preprocess_plaintext: all-zero plaintext");
    }
    if (find_preprocessed_plaintext(context, canonical)) {
        return false;
    }

    auto entry = std::make_shared<PreparedPlaintextCache::Entry>();
    entry->slots = std::move(canonical);
    const seal::Plaintext coefficient_plaintext = encode_slots(
        context.encoder, entry->slots,
        "SealBackend::preprocess_plaintext");
    for (auto level = context.context->first_context_data(); level;
         level = level->next_context_data()) {
        seal::Plaintext transformed = coefficient_plaintext;
        context.evaluator->transform_to_ntt_inplace(
            transformed, level->parms_id());
        entry->ntt_coefficient_bytes +=
            transformed.coeff_count() * sizeof(std::uint64_t);
        entry->by_level.emplace(level->parms_id(),
                                std::move(transformed));
    }

    const std::uint64_t hash = plaintext_cache_hash(entry->slots);
    std::lock_guard lock(context.prepared_plaintexts->mutex);
    auto &bucket = context.prepared_plaintexts->by_hash[hash];
    for (const auto &existing : bucket) {
        if (existing->slots == entry->slots) {
            return false;
        }
    }
    context.prepared_plaintexts->stats.logical_plaintexts += 1;
    context.prepared_plaintexts->stats.level_representations +=
        entry->by_level.size();
    context.prepared_plaintexts->stats.ntt_coefficient_bytes +=
        entry->ntt_coefficient_bytes;
    bucket.push_back(std::move(entry));
    return true;
}

SealBackend::PlaintextPreprocessingStats
SealBackend::plaintext_preprocessing_stats(
    const EvalContext &context) {
    if (!context.prepared_plaintexts) {
        return {};
    }
    std::lock_guard lock(context.prepared_plaintexts->mutex);
    return context.prepared_plaintexts->stats;
}

SealBackend::ExtCiphertext SealBackend::ext_mul_plain(
    const EvalContext &context, const ExtCiphertext &ciphertext,
    const PlainExtension &plaintext) {
    const Ciphertext *anchor = validate_extension_level(
        context, ciphertext, "SealBackend::ext_mul_plain");
    if (anchor == nullptr) {
        return {};
    }
    record(context, OperationKind::LogicalExtMulPlain, *anchor);
    std::array<std::optional<Ciphertext>, 2 * kExtensionDegree - 1>
        coefficients{};
    for (std::size_t plain_degree = 0;
         plain_degree < kExtensionDegree; ++plain_degree) {
        if (is_zero_plaintext(plaintext[plain_degree])) {
            continue;
        }
        const SlotVector &coefficient_plaintext =
            plaintext[plain_degree];
        const std::size_t width = slot_count(context);
        if (coefficient_plaintext.size() > width) {
            throw std::invalid_argument(
                "SealBackend::ext_mul_plain: plaintext exceeds the slot "
                "count");
        }
        const bool scalar =
            is_scalar_plaintext(coefficient_plaintext, width);
        // One extension-plaintext coefficient is multiplied into every
        // present encrypted coordinate. Lift/NTT it once here, then reuse
        // that representation for the coefficientwise products; absent
        // public-zero coordinates do no work.
        std::shared_ptr<const PreparedPlaintextCache::Entry> preprocessed;
        if (!scalar && coefficient_plaintext.size() == width) {
            preprocessed =
                find_preprocessed_plaintext(context,
                                            coefficient_plaintext);
        }
        std::optional<seal::Plaintext> online_encoded;
        const seal::Plaintext *encoded = nullptr;
        if (preprocessed) {
            encoded = &preprocessed_at_ciphertext_level(
                *preprocessed, *anchor);
        } else if (!scalar) {
            online_encoded = encode_plaintext_at_ciphertext_level(
                context, coefficient_plaintext, *anchor);
            encoded = &*online_encoded;
        }
        for (std::size_t cipher_degree = 0;
             cipher_degree < kExtensionDegree; ++cipher_degree) {
            if (!ciphertext[cipher_degree]) {
                continue;
            }
            Ciphertext term =
                scalar
                    ? multiply_plain_scalar_direct(
                          context, *ciphertext[cipher_degree],
                          coefficient_plaintext.front())
                    : multiply_plain_encoded(
                          context, *ciphertext[cipher_degree], *encoded,
                          false);
            auto &destination =
                coefficients[cipher_degree + plain_degree];
            accumulate_ciphertext_coordinate(
                context, destination, std::move(term),
                "SealBackend::ext_mul_plain");
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

SealBackend::ExtCiphertext SealBackend::ext_mul_plain_scalar(
    const EvalContext &context, const ExtCiphertext &ciphertext,
    const PlainExtensionScalar &plaintext) {
    const Ciphertext *anchor = validate_extension_level(
        context, ciphertext, "SealBackend::ext_mul_plain_scalar");
    if (anchor == nullptr) {
        return {};
    }
    record(context, OperationKind::LogicalExtMulPlain, *anchor);
    std::array<std::optional<Ciphertext>, 2 * kExtensionDegree - 1>
        coefficients{};
    for (std::size_t plain_degree = 0;
         plain_degree < kExtensionDegree; ++plain_degree) {
        if (plaintext[plain_degree].is_zero()) {
            continue;
        }
        for (std::size_t cipher_degree = 0;
             cipher_degree < kExtensionDegree; ++cipher_degree) {
            if (!ciphertext[cipher_degree]) {
                continue;
            }
            Ciphertext term = mul_plain_scalar(
                context, *ciphertext[cipher_degree],
                plaintext[plain_degree]);
            auto &destination =
                coefficients[cipher_degree + plain_degree];
            accumulate_ciphertext_coordinate(
                context, destination, std::move(term),
                "SealBackend::ext_mul_plain_scalar");
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


} // namespace laminate::fhe
