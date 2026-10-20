/// @file test_seal_context_bundle.cpp
/// @brief Real-SEAL process-boundary key-bundle tests.

#include "test_helpers.hpp"

#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/fhe/seal_backend.hpp"
#include "laminate/fhe/layout/slot_grid.hpp"
#include "laminate/setup.hpp"
#include "laminate/transcript/hash.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;

namespace {

constexpr std::size_t kSlots = 1024;

static_assert(!std::is_aggregate_v<SealBackend::EvalContext>);
static_assert(!std::is_aggregate_v<SealBackend::ClientContext>);
static_assert(!std::is_aggregate_v<SealBackend::PublicVerifierContext>);
static_assert(CiphertextStorageContext<SealBackend,
                                      SealBackend::EvalContext>);
static_assert(CiphertextStorageContext<SealBackend,
                                      SealBackend::ClientContext>);
static_assert(CiphertextStorageContext<
              SealBackend, SealBackend::PublicVerifierContext>);
static_assert(!std::is_convertible_v<SealBackend::PublicVerifierContext,
                                     SealBackend::EvalContext>);

template <typename Context>
concept AuthorizesSealEvaluation = requires(
    const Context &context, const SealBackend::Ciphertext &ciphertext) {
    SealBackend::add(context, ciphertext, ciphertext);
};

static_assert(!AuthorizesSealEvaluation<
              SealBackend::PublicVerifierContext>);
static_assert(!std::is_assignable_v<
              decltype((std::declval<SealBackend::EvalContext &>()
                            .relin_keys)),
              std::shared_ptr<const seal::RelinKeys>>);
static_assert(!std::is_assignable_v<
              decltype((std::declval<SealBackend::ClientContext &>()
                            .secret_key)),
              std::shared_ptr<const seal::SecretKey>>);

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

bool throws_logic_error(const auto &body) {
    try {
        body();
    } catch (const std::logic_error &) {
        return true;
    }
    return false;
}

SealParameters bundle_parameters(bool generate_galois_keys = true) {
    return SealParameters{
        .poly_modulus_degree = kSlots,
        .fresh_rns_limbs = 3,
        .data_prime_bit_sizes = {60, 42, 37},
        .bits_per_data_prime = 53,
        .special_prime_bits = 45,
        .security_level = seal::sec_level_type::none,
        .track_deterministic_noise_bounds = false,
        .max_fresh_ciphertext_modulus_bits = 139,
        .max_key_modulus_bits = 184,
        .generate_galois_keys = generate_galois_keys,
    };
}

SlotVector slots(std::uint64_t seed) {
    SlotVector result(kSlots);
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = Fp(seed + 7 * index + index * index);
    }
    return result;
}

void check_parameters(const SealParameters &observed,
                      const SealParameters &expected) {
    CHECK(observed.poly_modulus_degree == expected.poly_modulus_degree);
    CHECK(observed.fresh_rns_limbs == expected.fresh_rns_limbs);
    CHECK(observed.data_prime_bit_sizes == expected.data_prime_bit_sizes);
    CHECK(observed.exact_data_primes == expected.exact_data_primes);
    CHECK(observed.exact_special_prime == expected.exact_special_prime);
    CHECK(observed.bits_per_data_prime == expected.bits_per_data_prime);
    CHECK(observed.special_prime_bits == expected.special_prime_bits);
    CHECK(observed.security_level == expected.security_level);
    CHECK(observed.track_deterministic_noise_bounds ==
          expected.track_deterministic_noise_bounds);
    CHECK(observed.max_fresh_ciphertext_modulus_bits ==
          expected.max_fresh_ciphertext_modulus_bits);
    CHECK(observed.max_key_modulus_bits == expected.max_key_modulus_bits);
    CHECK(observed.generate_galois_keys == expected.generate_galois_keys);
}

template <typename SealObject>
std::vector<std::uint8_t> seal_bytes(const SealObject &object) {
    std::stringstream stream(std::ios::binary | std::ios::in |
                             std::ios::out);
    object.save(stream, seal::compr_mode_type::none);
    const std::string bytes = stream.str();
    return std::vector<std::uint8_t>(bytes.begin(), bytes.end());
}

std::uint64_t read_u64(std::span<const std::uint8_t> bytes,
                       std::size_t &offset) {
    if (offset > bytes.size() || bytes.size() - offset < 8) {
        throw std::logic_error("truncated test bundle");
    }
    std::uint64_t result = 0;
    for (std::size_t byte = 0; byte < 8; ++byte) {
        result |= static_cast<std::uint64_t>(bytes[offset + byte])
                  << (8U * byte);
    }
    offset += 8;
    return result;
}

std::pair<std::size_t, std::size_t> relin_key_region(
    std::span<const std::uint8_t> bundle) {
    std::size_t offset = 10;
    const std::size_t descriptor_size = read_u64(bundle, offset);
    offset += descriptor_size + Digest{}.size();
    const std::size_t public_key_size = read_u64(bundle, offset);
    offset += public_key_size;
    const std::size_t relin_key_size = read_u64(bundle, offset);
    if (offset > bundle.size() || relin_key_size > bundle.size() - offset) {
        throw std::logic_error("invalid test bundle key region");
    }
    return {offset, relin_key_size};
}

void rewrite_bundle_checksum(std::vector<std::uint8_t> &bundle) {
    if (bundle.size() < Digest{}.size()) {
        throw std::logic_error("short test bundle");
    }
    constexpr std::string_view domain =
        "LaminateImpl/SealContextBundleChecksum/v1";
    Sha256Hasher hasher;
    hasher.update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(domain.data()),
        domain.size()));
    hasher.update(std::span<const std::uint8_t>(bundle).first(
        bundle.size() - Digest{}.size()));
    const Digest checksum = hasher.finish();
    std::copy(checksum.begin(), checksum.end(),
              bundle.end() - static_cast<std::ptrdiff_t>(checksum.size()));
}

void write_u64(std::vector<std::uint8_t> &bytes, std::size_t offset,
               std::uint64_t value) {
    if (offset > bytes.size() || bytes.size() - offset < 8) {
        throw std::logic_error("short test artifact");
    }
    for (std::size_t byte = 0; byte < 8; ++byte) {
        bytes[offset + byte] = static_cast<std::uint8_t>(
            (value >> (8U * byte)) & UINT64_C(0xff));
    }
}

void rewrite_fixed_message_cell_preprocessing_checksum(
    std::vector<std::uint8_t> &artifact) {
    if (artifact.size() < Digest{}.size()) {
        throw std::logic_error("short test artifact");
    }
    constexpr std::string_view domain =
        "LaminateImpl/SealFixedMessageCellPreprocessingChecksum/v1";
    Sha256Hasher hasher;
    hasher.update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(domain.data()),
        domain.size()));
    hasher.update(std::span<const std::uint8_t>(artifact).first(
        artifact.size() - Digest{}.size()));
    const Digest checksum = hasher.finish();
    std::copy(checksum.begin(), checksum.end(),
              artifact.end() -
                  static_cast<std::ptrdiff_t>(checksum.size()));
}

std::size_t fixed_message_cell_record_bytes(
    const SealBackend::EvalContext &context) {
    std::size_t result = 3 * 8;
    for (auto level = context.context->first_context_data(); level;
         level = level->next_context_data()) {
        result += 6 * 8;
        result += level->parms().poly_modulus_degree() *
                  level->parms().coeff_modulus().size() * 8;
    }
    return result;
}

} // namespace

int main() {
    test::Runner runner("test_seal_context_bundle");

    runner.run("identity-bound key material is immutable", [&] {
        CHECK(!std::is_aggregate_v<SealBackend::EvalContext>);
        CHECK(!std::is_aggregate_v<SealBackend::ClientContext>);
        CHECK(!std::is_aggregate_v<
              SealBackend::PublicVerifierContext>);
        CHECK((!std::is_assignable_v<
              decltype((std::declval<SealBackend::EvalContext &>()
                            .relin_keys)),
              std::shared_ptr<const seal::RelinKeys>>));
        CHECK((!std::is_assignable_v<
              decltype((std::declval<SealBackend::ClientContext &>()
                            .secret_key)),
              std::shared_ptr<const seal::SecretKey>>));
    });

    runner.run("public verifier bundle is key-free and bounded", [&] {
        const SealParameters parameters = bundle_parameters();
        const SealBackend::Contexts original =
            SealBackend::create(parameters);
        const SealBackend::PublicVerifierContext from_eval =
            SealBackend::make_public_verifier_context(original.eval);
        const SealBackend::PublicVerifierContext from_client =
            SealBackend::make_public_verifier_context(original.client);
        const std::vector<std::uint8_t> bundle =
            SealBackend::serialize_public_verifier_context_bundle(
                from_client);
        CHECK(bundle ==
              SealBackend::serialize_public_verifier_context_bundle(
                  from_eval));
        CHECK(SealBackend::storage_context_id(from_client) ==
              SealBackend::storage_context_id(original.eval));

        const std::vector<std::uint8_t> public_key =
            seal_bytes(*original.eval.public_key);
        const std::vector<std::uint8_t> relin_keys =
            seal_bytes(*original.eval.relin_keys);
        const std::vector<std::uint8_t> galois_keys =
            seal_bytes(*original.eval.galois_keys);
        const std::vector<std::uint8_t> secret_key =
            seal_bytes(*original.client.secret_key);
        for (const auto &key : {public_key, relin_keys, galois_keys,
                                secret_key}) {
            CHECK(std::search(bundle.begin(), bundle.end(), key.begin(),
                              key.end()) == bundle.end());
        }

        SealBackend::PublicVerifierContext restored =
            SealBackend::deserialize_public_verifier_context_bundle(
                bundle, SealBackend::storage_context_id(original.eval),
                SealPublicVerifierContextDecodeLimits{
                    bundle.size(), kSlots, 4});
        check_parameters(restored.parameters, parameters);
        CHECK(SealBackend::slot_count(restored) == kSlots);
        CHECK(SealBackend::serialize_public_verifier_context_bundle(
                  restored) == bundle);

        const SlotVector plaintext = slots(43);
        const auto coefficients =
            SealBackend::encode_centered_plaintext_coefficients(
                original.eval, plaintext);
        CHECK(SealBackend::encode_centered_plaintext_coefficients(
                  restored, plaintext) == coefficients);
        CHECK(SealBackend::decode_centered_plaintext_coefficients(
                  restored, coefficients) == plaintext);
        CHECK(SealBackend::encode_lowest_plaintext_ntt_coordinates(
                  restored, coefficients) ==
              SealBackend::encode_lowest_plaintext_ntt_coordinates(
                  original.eval, coefficients));

        const auto ciphertext =
            SealBackend::encrypt(original.client, plaintext);
        const std::vector<std::uint8_t> persisted =
            SealBackend::serialize_for_storage(original.eval, ciphertext);
        const auto storage_decoded =
            SealBackend::deserialize_from_storage(restored, persisted);
        CHECK(SealBackend::decrypt(original.client, storage_decoded) ==
              plaintext);
        CHECK(SealBackend::serialize_for_storage(restored,
                                                 storage_decoded) ==
              persisted);
        CHECK(SealBackend::rns_limb_count(restored, storage_decoded) ==
              parameters.fresh_rns_limbs);

        auto normalized = ciphertext;
        SealBackend::mod_switch_to_lowest(original.eval, normalized);
        SealBackend::normalize_for_coefficient_commitment(original.eval,
                                                           normalized);
        const std::vector<std::uint8_t> protocol =
            SealBackend::serialize(normalized);
        const auto protocol_decoded =
            SealBackend::deserialize_protocol(restored, protocol);
        CHECK(SealBackend::serialize(protocol_decoded) == protocol);

        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_public_verifier_context_bundle(
                bundle, SealBackend::storage_context_id(original.eval),
                SealPublicVerifierContextDecodeLimits{
                    bundle.size() - 1U, kSlots, 4});
        }));
        Digest wrong_identity =
            SealBackend::storage_context_id(original.eval);
        wrong_identity.front() ^= 1U;
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_public_verifier_context_bundle(
                bundle, wrong_identity,
                SealPublicVerifierContextDecodeLimits{
                    bundle.size(), kSlots, 4});
        }));
        auto corrupt = bundle;
        corrupt[corrupt.size() / 2U] ^= 0x80U;
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_public_verifier_context_bundle(
                corrupt, SealBackend::storage_context_id(original.eval),
                SealPublicVerifierContextDecodeLimits{
                    corrupt.size(), kSlots, 4});
        }));
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_public_verifier_context_bundle(
                bundle, SealBackend::storage_context_id(original.eval),
                SealPublicVerifierContextDecodeLimits{
                    bundle.size(), kSlots / 2U, 4});
        }));
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_public_verifier_context_bundle(
                bundle, SealBackend::storage_context_id(original.eval),
                SealPublicVerifierContextDecodeLimits{
                    bundle.size(), kSlots, 2});
        }));
    });

    runner.run("role bundles reload an independent evaluation", [&] {
        const SealParameters parameters = bundle_parameters();
        const SealBackend::Contexts original = SealBackend::create(parameters);
        const std::vector<std::uint8_t> evaluation_bundle =
            SealBackend::serialize_evaluation_context_bundle(original.eval);
        const std::vector<std::uint8_t> client_bundle =
            SealBackend::serialize_client_context_bundle(original.client);

        CHECK(evaluation_bundle ==
              SealBackend::serialize_evaluation_context_bundle(
                  original.eval));
        CHECK(client_bundle ==
              SealBackend::serialize_client_context_bundle(
                  original.client));
        CHECK(SealBackend::storage_context_id(original.eval) ==
              SealBackend::storage_context_id(original.client));

        SealBackend::EvalContext server =
            SealBackend::deserialize_evaluation_context_bundle(
                evaluation_bundle);
        SealBackend::ClientContext client =
            SealBackend::deserialize_client_context_bundle(client_bundle);
        CHECK(SealBackend::storage_context_id(server) ==
              SealBackend::storage_context_id(client));
        check_parameters(server.parameters, parameters);
        check_parameters(client.parameters, parameters);
        CHECK(SealBackend::coefficient_moduli(server) ==
              SealBackend::coefficient_moduli(original.eval));

        const SlotVector left_slots = slots(17);
        const SlotVector right_slots = slots(91);
        const auto left = SealBackend::encrypt(client, left_slots);
        const auto right = SealBackend::encrypt(client, right_slots);
        auto result = SealBackend::mul(server, left, right);
        result = SealBackend::rotate(server, result, 37);

        const std::vector<std::uint8_t> server_persisted =
            SealBackend::serialize_for_storage(server, result);
        const std::vector<std::uint8_t> client_persisted =
            SealBackend::serialize_for_storage(client, result);
        CHECK(client_persisted == server_persisted);
        result = {};
        const auto server_reopened =
            SealBackend::deserialize_from_storage(server, client_persisted);
        const auto client_reopened =
            SealBackend::deserialize_from_storage(client, server_persisted);
        SlotVector expected(kSlots);
        for (std::size_t index = 0; index < kSlots; ++index) {
            expected[index] = left_slots[index] * right_slots[index];
        }
        expected = grid_rotate(expected, 37);
        CHECK(SealBackend::decrypt(client, server_reopened) == expected);
        CHECK(SealBackend::decrypt(client, client_reopened) == expected);

        const SealBackend::Contexts paired =
            SealBackend::deserialize_context_bundles(evaluation_bundle,
                                                     client_bundle);
        CHECK(SealBackend::storage_context_id(paired.eval) ==
              SealBackend::storage_context_id(paired.client));

        const std::vector<std::uint8_t> secret =
            seal_bytes(*original.client.secret_key);
        CHECK(std::search(evaluation_bundle.begin(), evaluation_bundle.end(),
                          secret.begin(), secret.end()) ==
              evaluation_bundle.end());
    });

    runner.run("fixed message NTT bases restore without online setup", [&] {
        const SealParameters parameters = bundle_parameters();
        const SealBackend::Contexts original = SealBackend::create(parameters);
        SealBackend::reset_counts(original.eval);
        SealBackend::set_counting(original.eval, true);
        SealBackend::preprocess_fixed_message_cells(original.eval);
        const auto setup_counts = SealBackend::counts(original.eval);
        CHECK(setup_counts.fixed_message_basis_setup_calls ==
              kFixedMessageCellCount);
        SealBackend::set_counting(original.eval, false);
        const auto original_stats =
            SealBackend::plaintext_preprocessing_stats(original.eval);
        CHECK(original_stats.logical_plaintexts == kFixedMessageCellCount);
        CHECK(original_stats.level_representations ==
              kFixedMessageCellCount * parameters.fresh_rns_limbs);

        const std::vector<std::uint8_t> artifact =
            SealBackend::serialize_fixed_message_cell_preprocessing(
                original.eval);
        const Digest artifact_id =
            SealBackend::fixed_message_cell_preprocessing_artifact_id(
                artifact);
        const std::vector<std::uint8_t> evaluation_bundle =
            SealBackend::serialize_evaluation_context_bundle(original.eval);
        SealBackend::EvalContext restored =
            SealBackend::deserialize_evaluation_context_bundle(
                evaluation_bundle);
        const SlotVector all_ones(kSlots, Fp::one());
        const auto encrypted =
            SealBackend::encrypt(original.client, all_ones);
        CHECK(throws_logic_error([&] {
            (void)SealBackend::mul_plain_fixed_message_cell(
                restored, encrypted, 0);
        }));

        const SealFixedMessageCellPreprocessingMetadata metadata =
            SealBackend::restore_fixed_message_cell_preprocessing(
                restored, artifact, artifact_id,
                SealFixedMessageCellPreprocessingDecodeLimits{
                    artifact.size(),
                    original_stats.ntt_coefficient_bytes});
        CHECK(metadata.artifact_id == artifact_id);
        CHECK(metadata.storage_context_id ==
              SealBackend::storage_context_id(original.eval));
        CHECK(metadata.artifact_bytes == artifact.size());
        CHECK(metadata.fixed_message_cells == kFixedMessageCellCount);
        CHECK(metadata.data_levels == parameters.fresh_rns_limbs);
        CHECK(metadata.level_representations ==
              original_stats.level_representations);
        CHECK(metadata.ntt_coefficient_bytes ==
              original_stats.ntt_coefficient_bytes);
        PublicSetup public_setup;
        public_setup.shape = payload::PayloadShape::wide(kSlots);
        EvaluationSetup<SealBackend> evaluation =
            make_evaluation_setup<SealBackend>(
                std::move(public_setup), std::move(restored));
        CHECK(SealBackend::slot_count(evaluation.context) == kSlots);
        CHECK(SealBackend::plaintext_preprocessing_stats(
                  evaluation.context) ==
              original_stats);
        CHECK(SealBackend::serialize_fixed_message_cell_preprocessing(
                  evaluation.context) == artifact);

        SealBackend::reset_counts(evaluation.context);
        SealBackend::set_counting(evaluation.context, true);
        SealBackend::preprocess_fixed_message_cells(evaluation.context);
        CHECK(SealBackend::counts(evaluation.context)
                  .fixed_message_basis_setup_calls == 0);
        for (std::size_t cell = 0; cell < kFixedMessageCellCount; ++cell) {
            const auto selected =
                SealBackend::mul_plain_fixed_message_cell(
                    evaluation.context, encrypted, cell);
            SlotVector expected(kSlots, Fp::zero());
            expected[fixed_message_cell_slot(kSlots, cell)] = Fp::one();
            CHECK(SealBackend::decrypt(original.client, selected) ==
                  expected);
        }
        SealBackend::set_counting(evaluation.context, false);
    });

    runner.run("fixed message preprocessing import fails closed", [&] {
        const SealBackend::Contexts original =
            SealBackend::create(bundle_parameters());
        SealBackend::preprocess_fixed_message_cells(original.eval);
        const auto stats =
            SealBackend::plaintext_preprocessing_stats(original.eval);
        const std::vector<std::uint8_t> artifact =
            SealBackend::serialize_fixed_message_cell_preprocessing(
                original.eval);
        const Digest artifact_id =
            SealBackend::fixed_message_cell_preprocessing_artifact_id(
                artifact);
        const auto limits =
            SealFixedMessageCellPreprocessingDecodeLimits{
                artifact.size(), stats.ntt_coefficient_bytes};
        const std::vector<std::uint8_t> evaluation_bundle =
            SealBackend::serialize_evaluation_context_bundle(original.eval);
        SealBackend::EvalContext destination =
            SealBackend::deserialize_evaluation_context_bundle(
                evaluation_bundle);

        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::restore_fixed_message_cell_preprocessing(
                destination, artifact, artifact_id,
                SealFixedMessageCellPreprocessingDecodeLimits{
                    artifact.size() - 1U,
                    stats.ntt_coefficient_bytes});
        }));
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::restore_fixed_message_cell_preprocessing(
                destination, artifact, artifact_id,
                SealFixedMessageCellPreprocessingDecodeLimits{
                    artifact.size(),
                    stats.ntt_coefficient_bytes - 1U});
        }));
        Digest wrong_id = artifact_id;
        wrong_id.front() ^= 1U;
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::restore_fixed_message_cell_preprocessing(
                destination, artifact, wrong_id, limits);
        }));

        auto corrupt = artifact;
        corrupt[corrupt.size() / 2U] ^= 0x80U;
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::restore_fixed_message_cell_preprocessing(
                destination, corrupt,
                SealBackend::fixed_message_cell_preprocessing_artifact_id(
                    corrupt),
                limits);
        }));

        auto trailing = artifact;
        trailing.insert(trailing.end() -
                            static_cast<std::ptrdiff_t>(Digest{}.size()),
                        0);
        rewrite_fixed_message_cell_preprocessing_checksum(trailing);
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::restore_fixed_message_cell_preprocessing(
                destination, trailing,
                SealBackend::fixed_message_cell_preprocessing_artifact_id(
                    trailing),
                SealFixedMessageCellPreprocessingDecodeLimits{
                    trailing.size(), stats.ntt_coefficient_bytes});
        }));

        auto duplicate_cell = artifact;
        constexpr std::size_t kFirstCellOffset =
            8 + 1 + 1 + Digest{}.size() + 3 * 8;
        write_u64(duplicate_cell,
                  kFirstCellOffset +
                      fixed_message_cell_record_bytes(original.eval),
                  0);
        rewrite_fixed_message_cell_preprocessing_checksum(duplicate_cell);
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::restore_fixed_message_cell_preprocessing(
                destination, duplicate_cell,
                SealBackend::fixed_message_cell_preprocessing_artifact_id(
                    duplicate_cell),
                limits);
        }));

        const auto other = SealBackend::create(bundle_parameters());
        SealBackend::EvalContext other_destination =
            SealBackend::deserialize_evaluation_context_bundle(
                SealBackend::serialize_evaluation_context_bundle(
                    other.eval));
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::restore_fixed_message_cell_preprocessing(
                other_destination, artifact, artifact_id, limits);
        }));

        (void)SealBackend::preprocess_plaintext(destination, slots(7));
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::restore_fixed_message_cell_preprocessing(
                destination, artifact, artifact_id, limits);
        }));
    });

    runner.run("bundle parsing fails closed", [&] {
        const auto original = SealBackend::create(bundle_parameters());
        const std::vector<std::uint8_t> evaluation_bundle =
            SealBackend::serialize_evaluation_context_bundle(original.eval);
        const std::vector<std::uint8_t> client_bundle =
            SealBackend::serialize_client_context_bundle(original.client);

        auto truncated = evaluation_bundle;
        truncated.pop_back();
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_evaluation_context_bundle(
                truncated);
        }));

        auto trailing = client_bundle;
        trailing.push_back(0);
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_client_context_bundle(trailing);
        }));

        auto wrong_version = evaluation_bundle;
        wrong_version[8] = 2;
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_evaluation_context_bundle(
                wrong_version);
        }));

        auto wrong_flags = client_bundle;
        wrong_flags[9] = 1;
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_client_context_bundle(
                wrong_flags);
        }));

        auto corrupt = evaluation_bundle;
        corrupt[corrupt.size() / 2] ^= 0x80U;
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_evaluation_context_bundle(corrupt);
        }));

        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_evaluation_context_bundle(
                client_bundle);
        }));
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_client_context_bundle(
                evaluation_bundle);
        }));
    });

    runner.run("different and changed key material is rejected", [&] {
        const auto first = SealBackend::create(bundle_parameters());
        const auto second = SealBackend::create(bundle_parameters());
        const auto first_eval =
            SealBackend::serialize_evaluation_context_bundle(first.eval);
        const auto second_client =
            SealBackend::serialize_client_context_bundle(second.client);
        CHECK(SealBackend::storage_context_id(first.eval) !=
              SealBackend::storage_context_id(second.eval));
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_context_bundles(first_eval,
                                                           second_client);
        }));

        // Keep the first public key and identity but splice in a valid
        // same-parameter relinearization key from the second context. After
        // restoring the framing checksum, import must still reject the
        // changed evaluation-key identity.
        auto changed_eval_bundle = first_eval;
        const auto second_eval =
            SealBackend::serialize_evaluation_context_bundle(second.eval);
        const auto [first_relin_offset, first_relin_size] =
            relin_key_region(changed_eval_bundle);
        const auto [second_relin_offset, second_relin_size] =
            relin_key_region(second_eval);
        CHECK(first_relin_size == second_relin_size);
        std::copy_n(second_eval.begin() +
                        static_cast<std::ptrdiff_t>(second_relin_offset),
                    second_relin_size,
                    changed_eval_bundle.begin() +
                        static_cast<std::ptrdiff_t>(first_relin_offset));
        rewrite_bundle_checksum(changed_eval_bundle);
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_evaluation_context_bundle(
                changed_eval_bundle);
        }));

        const auto ciphertext = SealBackend::encrypt(first.client, slots(211));
        const auto persisted =
            SealBackend::serialize_for_storage(first.eval, ciphertext);
        const auto other_server =
            SealBackend::deserialize_evaluation_context_bundle(
                SealBackend::serialize_evaluation_context_bundle(
                    second.eval));
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_from_storage(other_server,
                                                        persisted);
        }));
        const auto other_client =
            SealBackend::deserialize_client_context_bundle(
                SealBackend::serialize_client_context_bundle(
                    second.client));
        CHECK(throws_invalid_argument([&] {
            (void)SealBackend::deserialize_from_storage(other_client,
                                                        persisted);
        }));

        // EvalContext and ClientContext are non-aggregate values whose
        // identity-bound parameter and key members are const. The compile-
        // time assertions above prevent pointer replacement or construction
        // of a forged context carrying a stale cached identity.
    });

    runner.run("omitted Galois keys remain omitted", [&] {
        const SealParameters parameters = bundle_parameters(false);
        const auto original = SealBackend::create(parameters);
        const auto evaluation_bundle =
            SealBackend::serialize_evaluation_context_bundle(original.eval);
        const auto client_bundle =
            SealBackend::serialize_client_context_bundle(original.client);
        const auto reloaded = SealBackend::deserialize_context_bundles(
            evaluation_bundle, client_bundle);
        check_parameters(reloaded.eval.parameters, parameters);
        check_parameters(reloaded.client.parameters, parameters);
        CHECK(reloaded.eval.galois_keys->data().empty());
    });

    return runner.summary();
}
