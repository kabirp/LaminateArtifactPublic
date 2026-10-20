#include "test_helpers.hpp"

#include "laminate/field/fpk.hpp"
#include "laminate/fhe/storage/ciphertext.hpp"
#include "laminate/fhe/mock_backend.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace {

using laminate::Fp;
using laminate::Fpk;
using laminate::fhe::deserialize_validated_private_ciphertext;
using laminate::fhe::MockBackend;
using laminate::fhe::MockParameters;
using laminate::fhe::PlainExtension;
using laminate::fhe::SlotVector;

static_assert(laminate::fhe::PersistableFheBackend<MockBackend>);
static_assert(laminate::fhe::CiphertextStorageContext<
              MockBackend, MockBackend::PublicVerifierContext>);
static_assert(!std::is_convertible_v<MockBackend::PublicVerifierContext,
                                     MockBackend::EvalContext>);

template <typename Context>
concept AuthorizesMockEvaluation = requires(
    const Context &context, const MockBackend::Ciphertext &ciphertext) {
    MockBackend::add(context, ciphertext, ciphertext);
};

static_assert(!AuthorizesMockEvaluation<
              MockBackend::PublicVerifierContext>);

MockBackend::Contexts make_contexts(std::size_t slot_count = 8) {
    return MockBackend::create(MockParameters{.slot_count = slot_count});
}

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

SlotVector sequence(std::size_t size, std::uint64_t offset = 0) {
    SlotVector result;
    result.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        result.emplace_back(offset + index);
    }
    return result;
}

std::vector<Fpk> extension_values(std::size_t size, std::uint64_t offset) {
    std::vector<Fpk> result;
    result.reserve(size);
    for (std::size_t slot = 0; slot < size; ++slot) {
        Fpk::Coefficients coefficients{};
        for (std::size_t degree = 0; degree < coefficients.size(); ++degree) {
            coefficients[degree] = Fp(offset + 13 * slot + 7 * degree + 1);
        }
        result.emplace_back(coefficients);
    }
    return result;
}

MockBackend::ExtCiphertext
encrypt_private_test_extension(const MockBackend::ClientContext &client,
                  const std::vector<Fpk> &values) {
    MockBackend::ExtCiphertext result{};
    for (std::size_t degree = 0; degree < laminate::kExtensionDegree;
         ++degree) {
        SlotVector coefficient;
        coefficient.reserve(values.size());
        for (const Fpk &value : values) {
            coefficient.push_back(value.coefficients()[degree]);
        }
        result[degree] = MockBackend::encrypt(client, coefficient);
    }
    return result;
}

PlainExtension encode_extension_plain(const std::vector<Fpk> &values) {
    PlainExtension result{};
    for (std::size_t degree = 0; degree < laminate::kExtensionDegree;
         ++degree) {
        result[degree].reserve(values.size());
        for (const Fpk &value : values) {
            result[degree].push_back(value.coefficients()[degree]);
        }
    }
    return result;
}

std::vector<Fpk>
decrypt_extension(const MockBackend::ClientContext &client,
                  const MockBackend::ExtCiphertext &ciphertext) {
    std::array<SlotVector, laminate::kExtensionDegree> coefficients{};
    for (std::size_t degree = 0; degree < laminate::kExtensionDegree;
         ++degree) {
        CHECK(ciphertext[degree].has_value());
        coefficients[degree] =
            MockBackend::decrypt(client, *ciphertext[degree]);
    }
    std::vector<Fpk> result(coefficients.front().size());
    for (std::size_t slot = 0; slot < result.size(); ++slot) {
        Fpk::Coefficients value{};
        for (std::size_t degree = 0; degree < laminate::kExtensionDegree;
             ++degree) {
            value[degree] = coefficients[degree][slot];
        }
        result[slot] = Fpk(value);
    }
    return result;
}

void test_context_validation_and_padding() {
    CHECK(throws_invalid_argument([] {
        (void)MockBackend::create(MockParameters{.slot_count = 6});
    }));

    auto contexts = make_contexts();
    const auto ciphertext =
        MockBackend::encrypt(contexts.client, {Fp(4), Fp(9), Fp(16)});
    const SlotVector decrypted =
        MockBackend::decrypt(contexts.client, ciphertext);
    CHECK(decrypted.size() == 8);
    CHECK(decrypted[0] == Fp(4));
    CHECK(decrypted[2] == Fp(16));
    CHECK(decrypted[3] == Fp::zero());
    CHECK(MockBackend::counts(contexts.eval).encrypt == 1);
    CHECK(MockBackend::counts(contexts.eval).decrypt == 1);

    CHECK(throws_invalid_argument([&] {
        (void)MockBackend::encrypt(contexts.client, sequence(9));
    }));
}

void test_base_arithmetic_and_lazy_relinearization() {
    auto contexts = make_contexts();
    const SlotVector left_values = sequence(8, 2);
    const SlotVector right_values = sequence(8, 11);
    const auto left = MockBackend::encrypt(contexts.client, left_values);
    const auto right = MockBackend::encrypt(contexts.client, right_values);
    MockBackend::reset_counts(contexts.eval);

    const auto sum = MockBackend::add(contexts.eval, left, right);
    const auto difference = MockBackend::sub(contexts.eval, sum, right);
    CHECK(MockBackend::decrypt(contexts.client, difference) == left_values);

    auto product = MockBackend::mul_no_relin(contexts.eval, left, right);
    CHECK(!product.relinearized);
    CHECK(product.rns_limbs == left.rns_limbs);
    CHECK(product.depth_half_levels == 2);
    CHECK(throws_invalid_argument(
        [&] { (void)MockBackend::mul_no_relin(contexts.eval, product, left); }));
    MockBackend::relinearize(contexts.eval, product);
    CHECK(product.relinearized);

    SlotVector expected(8);
    for (std::size_t slot = 0; slot < expected.size(); ++slot) {
        expected[slot] = left_values[slot] * right_values[slot];
    }
    CHECK(MockBackend::decrypt(contexts.client, product) == expected);
    CHECK(MockBackend::counts(contexts.eval).add == 1);
    CHECK(MockBackend::counts(contexts.eval).sub == 1);
    CHECK(MockBackend::counts(contexts.eval).mul_no_relin == 1);
    CHECK(MockBackend::counts(contexts.eval).relinearize == 1);
}

void test_generic_in_place_addition_fallback() {
    auto contexts = make_contexts();
    const SlotVector left_values = sequence(8, 2);
    const SlotVector right_values = sequence(8, 11);
    const auto left = MockBackend::encrypt(contexts.client, left_values);
    const auto right = MockBackend::encrypt(contexts.client, right_values);
    const auto expected = MockBackend::add(contexts.eval, left, right);
    auto actual = left;

    MockBackend::reset_counts(contexts.eval);
    laminate::fhe::add_assign<MockBackend>(contexts.eval, actual, right);
    CHECK(MockBackend::serialize(actual) ==
          MockBackend::serialize(expected));
    CHECK(MockBackend::decrypt(contexts.client, right) == right_values);
    CHECK(MockBackend::counts(contexts.eval).add == 1);
}

void test_plaintext_cost_classes() {
    auto contexts = make_contexts();
    const auto ciphertext =
        MockBackend::encrypt(contexts.client, sequence(8, 3));
    MockBackend::reset_counts(contexts.eval);

    const auto scalar = MockBackend::mul_plain(
        contexts.eval, ciphertext, SlotVector(8, Fp(7)));
    const auto scalar_api = MockBackend::mul_plain_scalar(
        contexts.eval, ciphertext, Fp(7));
    const auto scalar_add_vector = MockBackend::add_plain(
        contexts.eval, ciphertext, SlotVector(8, Fp(11)));
    const auto scalar_add_api = MockBackend::add_plain_scalar(
        contexts.eval, ciphertext, Fp(11));
    const auto vector =
        MockBackend::mul_plain(contexts.eval, ciphertext, sequence(8, 1));
    const auto zero = MockBackend::mul_plain(
        contexts.eval, ciphertext, SlotVector(8, Fp::zero()));
    CHECK(scalar.depth_half_levels == 1);
    CHECK(scalar_api.slots == scalar.slots);
    CHECK(scalar_api.depth_half_levels == scalar.depth_half_levels);
    CHECK(scalar_api.noise_loss_bits == scalar.noise_loss_bits);
    CHECK(scalar_add_api.slots == scalar_add_vector.slots);
    CHECK(vector.depth_half_levels == 2);
    CHECK(scalar.noise_loss_bits < vector.noise_loss_bits);
    CHECK(MockBackend::decrypt(contexts.client, zero) ==
          SlotVector(8, Fp::zero()));
    CHECK(MockBackend::counts(contexts.eval).mul_plain_scalar == 3);
    CHECK(MockBackend::counts(contexts.eval).mul_plain_vector == 1);
    CHECK(MockBackend::counts(contexts.eval).add_plain == 2);
    CHECK(MockBackend::counts(contexts.eval).add_plain_scalar_api_calls == 1);
    CHECK(MockBackend::counts(contexts.eval).add_plain_vector_api_calls == 1);
    CHECK(MockBackend::counts(contexts.eval).add_plain_vector_api_elements ==
          8);
    CHECK(MockBackend::counts(contexts.eval).mul_plain_scalar_api_calls == 1);
    CHECK(MockBackend::counts(contexts.eval).mul_plain_vector_api_calls == 3);
    CHECK(MockBackend::counts(contexts.eval).mul_plain_vector_api_elements ==
          24);
}

void test_grid_group_law() {
    constexpr std::size_t kSlots = 16;
    const SlotVector input = sequence(kSlots);
    for (std::size_t steps = 0; steps < kSlots; ++steps) {
        const SlotVector rotated = laminate::fhe::grid_rotate(input, steps);
        for (std::size_t destination = 0; destination < kSlots;
             ++destination) {
            CHECK(rotated[destination] ==
                  input[laminate::fhe::grid_source(kSlots, steps,
                                                   destination)]);
        }
        CHECK(laminate::fhe::grid_rotate(
                  rotated, laminate::fhe::grid_inverse(kSlots, steps)) ==
              input);
    }

    for (std::size_t first = 0; first < kSlots; ++first) {
        for (std::size_t second = 0; second < kSlots; ++second) {
            CHECK(laminate::fhe::grid_rotate(
                      laminate::fhe::grid_rotate(input, first), second) ==
                  laminate::fhe::grid_rotate(
                      input, laminate::fhe::grid_compose(kSlots, first,
                                                         second)));
        }
    }

    // In Z/2 x Z/4, shift 3 followed by shift 3 is shift 2, not shift 6
    // in a fictitious cyclic Z/8 layout.
    CHECK(laminate::fhe::grid_compose(8, 3, 3) == 2);
}

void test_fold_uses_both_rows() {
    auto contexts = make_contexts(16);
    const SlotVector input = sequence(16, 1);
    const auto ciphertext = MockBackend::encrypt(contexts.client, input);
    MockBackend::reset_counts(contexts.eval);
    const auto folded = MockBackend::fold(contexts.eval, ciphertext);
    const SlotVector result = MockBackend::decrypt(contexts.client, folded);

    Fp sum = Fp::zero();
    for (const Fp &value : input) {
        sum += value;
    }
    CHECK(result == SlotVector(16, sum));
    CHECK(MockBackend::counts(contexts.eval).rotate == 4);
    CHECK(MockBackend::counts(contexts.eval).add == 4);
}

void test_chain_position_is_separate_from_depth() {
    auto contexts = make_contexts();
    const auto left = MockBackend::encrypt(contexts.client, sequence(8, 1));
    const auto right = MockBackend::encrypt(contexts.client, sequence(8, 9));
    auto product = MockBackend::mul(contexts.eval, left, right);
    CHECK(product.rns_limbs == left.rns_limbs);
    CHECK(product.depth_half_levels == 2);
    const std::size_t depth_before_switch = product.depth_half_levels;
    MockBackend::mod_switch_to_next(contexts.eval, product);
    CHECK(product.rns_limbs + 1 == left.rns_limbs);
    CHECK(product.depth_half_levels == depth_before_switch);
}

void test_exact_rns_compaction_obeys_selected_ingress() {
    auto contexts = make_contexts();
    auto ciphertext =
        MockBackend::encrypt(contexts.client, sequence(8, 1));
    const std::size_t source_limbs = ciphertext.rns_limbs;
    CHECK(source_limbs > 3);

    MockBackend::reset_counts(contexts.eval);
    laminate::fhe::mod_switch_to_rns_limb_count<MockBackend>(
        contexts.eval, ciphertext, 3);
    CHECK(ciphertext.rns_limbs == 3);
    CHECK(MockBackend::counts(contexts.eval).mod_switch ==
          source_limbs - 3);

    laminate::fhe::mod_switch_to_rns_limb_count<MockBackend>(
        contexts.eval, ciphertext, 3);
    CHECK(MockBackend::counts(contexts.eval).mod_switch ==
          source_limbs - 3);
    CHECK(throws_invalid_argument([&] {
        laminate::fhe::mod_switch_to_rns_limb_count<MockBackend>(
            contexts.eval, ciphertext, 0);
    }));
    CHECK(throws_invalid_argument([&] {
        laminate::fhe::mod_switch_to_rns_limb_count<MockBackend>(
            contexts.eval, ciphertext, 4);
    }));
}

void test_transport_compaction_preserves_explicit_reserve() {
    auto contexts = make_contexts();
    auto reserved =
        MockBackend::encrypt(contexts.client, sequence(8, 1));
    auto decryption_only = reserved;
    laminate::fhe::compact_for_transport<MockBackend>(
        contexts.eval, reserved, 2);
    laminate::fhe::compact_for_transport<MockBackend>(
        contexts.eval, decryption_only);
    CHECK(MockBackend::remaining_mult_depth(contexts.eval, reserved) >= 2);
    CHECK(reserved.rns_limbs >= decryption_only.rns_limbs);
}

void test_extension_arithmetic() {
    auto contexts = make_contexts();
    const std::vector<Fpk> left_values = extension_values(8, 5);
    const std::vector<Fpk> right_values = extension_values(8, 101);
    const auto left =
        encrypt_private_test_extension(contexts.client, left_values);
    const auto right =
        encrypt_private_test_extension(contexts.client, right_values);

    const auto sum = MockBackend::ext_add(contexts.eval, left, right);
    const auto difference = MockBackend::ext_sub(contexts.eval, sum, right);
    CHECK(decrypt_extension(contexts.client, difference) == left_values);

    MockBackend::reset_counts(contexts.eval);
    auto lazy_product =
        MockBackend::ext_mul_no_relin(contexts.eval, left, right);
    CHECK(MockBackend::counts(contexts.eval).logical_ext_mul == 1);
    CHECK(MockBackend::counts(contexts.eval).mul_no_relin == 64);
    CHECK(MockBackend::counts(contexts.eval).relinearize == 0);
    MockBackend::ext_relinearize(contexts.eval, lazy_product);
    CHECK(MockBackend::counts(contexts.eval).relinearize == 8);

    std::vector<Fpk> expected_product(8);
    for (std::size_t slot = 0; slot < expected_product.size(); ++slot) {
        expected_product[slot] = left_values[slot] * right_values[slot];
    }
    CHECK(decrypt_extension(contexts.client, lazy_product) == expected_product);

    const auto plain_product = MockBackend::ext_mul_plain(
        contexts.eval, left, encode_extension_plain(right_values));
    CHECK(decrypt_extension(contexts.client, plain_product) ==
          expected_product);
}

void test_serialization_is_canonical_for_mock_state() {
    auto contexts = make_contexts();
    const auto ciphertext =
        MockBackend::encrypt(contexts.client, sequence(8, 1));
    CHECK(MockBackend::serialize(ciphertext) ==
          MockBackend::serialize(ciphertext));

    auto switched = ciphertext;
    MockBackend::mod_switch_to_next(contexts.eval, switched);
    CHECK(MockBackend::serialize(ciphertext) !=
          MockBackend::serialize(switched));

    auto lazy = MockBackend::mul_no_relin(contexts.eval, ciphertext,
                                          ciphertext);
    CHECK(MockBackend::serialize(ciphertext) != MockBackend::serialize(lazy));
}

void test_storage_roundtrip_preserves_mock_state() {
    auto contexts = make_contexts();
    std::vector<std::uint64_t> coordinates(16);
    for (std::size_t index = 0; index < coordinates.size(); ++index) {
        coordinates[index] = 101 + index;
    }
    MockBackend::Ciphertext ciphertext =
        MockBackend::encrypt(contexts.client, sequence(8, 31));
    ciphertext.rns_limbs = 3;
    ciphertext.relinearized = false;
    ciphertext.depth_half_levels = 7;
    ciphertext.noise_loss_bits = 29;
    ciphertext.coefficient_commitment_coordinates = coordinates;

    const std::vector<std::uint8_t> encoded =
        MockBackend::serialize_for_storage(contexts.eval, ciphertext);
    const MockBackend::Ciphertext decoded =
        MockBackend::deserialize_from_storage(contexts.eval, encoded);
    const MockBackend::Ciphertext private_decoded =
        deserialize_validated_private_ciphertext<MockBackend>(
            contexts.eval, encoded);
    CHECK(decoded.slots == ciphertext.slots);
    CHECK(private_decoded.slots == ciphertext.slots);
    CHECK(decoded.rns_limbs == ciphertext.rns_limbs);
    CHECK(decoded.relinearized == ciphertext.relinearized);
    CHECK(decoded.depth_half_levels == ciphertext.depth_half_levels);
    CHECK(decoded.noise_loss_bits == ciphertext.noise_loss_bits);
    CHECK(decoded.coefficient_commitment_coordinates ==
          ciphertext.coefficient_commitment_coordinates);
    CHECK(private_decoded.coefficient_commitment_coordinates ==
          ciphertext.coefficient_commitment_coordinates);
    CHECK(MockBackend::serialize_for_storage(contexts.eval, decoded) ==
          encoded);
}

void test_storage_rejects_corrupt_mock_encodings() {
    auto contexts = make_contexts();
    const auto ciphertext =
        MockBackend::encrypt(contexts.client, sequence(8, 5));
    const std::vector<std::uint8_t> encoded =
        MockBackend::serialize_for_storage(contexts.eval, ciphertext);

    auto truncated = encoded;
    truncated.pop_back();
    CHECK(throws_invalid_argument([&] {
        (void)MockBackend::deserialize_from_storage(contexts.eval,
                                                    truncated);
    }));

    auto trailing = encoded;
    trailing.push_back(0);
    CHECK(throws_invalid_argument([&] {
        (void)MockBackend::deserialize_from_storage(contexts.eval,
                                                    trailing);
    }));

    auto wrong_version = encoded;
    wrong_version[8] = 2;
    CHECK(throws_invalid_argument([&] {
        (void)MockBackend::deserialize_from_storage(contexts.eval,
                                                    wrong_version);
    }));

    auto noncanonical_boolean = encoded;
    constexpr std::size_t kRelinearizedOffset =
        8 + 1 + 32 + 6 * 8 + 8;
    noncanonical_boolean[kRelinearizedOffset] = 2;
    CHECK(throws_invalid_argument([&] {
        (void)MockBackend::deserialize_from_storage(
            contexts.eval, noncanonical_boolean);
    }));

    auto noncanonical_slot = encoded;
    constexpr std::size_t kFirstSlotOffset =
        kRelinearizedOffset + 1 + 3 * 8;
    noncanonical_slot[kFirstSlotOffset] = 1;
    noncanonical_slot[kFirstSlotOffset + 1] = 0;
    noncanonical_slot[kFirstSlotOffset + 2] = 1; // 65537, outside F_p.
    CHECK(throws_invalid_argument([&] {
        (void)MockBackend::deserialize_from_storage(contexts.eval,
                                                    noncanonical_slot);
    }));

    auto other_contexts = make_contexts(16);
    CHECK(throws_invalid_argument([&] {
        (void)MockBackend::deserialize_from_storage(other_contexts.eval,
                                                    encoded);
    }));

    const auto rejects_parameter_change = [&](MockParameters parameters) {
        auto incompatible = MockBackend::create(parameters);
        return throws_invalid_argument([&] {
            (void)MockBackend::deserialize_from_storage(incompatible.eval,
                                                        encoded);
        });
    };
    CHECK(rejects_parameter_change(MockParameters{
        .slot_count = 8,
        .fresh_rns_limbs = 6,
    }));
    CHECK(rejects_parameter_change(MockParameters{
        .slot_count = 8,
        .bits_per_limb = 61,
    }));
    CHECK(rejects_parameter_change(MockParameters{
        .slot_count = 8,
        .initial_noise_margin_bits = 21,
    }));
    CHECK(rejects_parameter_change(MockParameters{
        .slot_count = 8,
        .rotation_noise_bits = 2,
    }));
    CHECK(rejects_parameter_change(MockParameters{
        .slot_count = 8,
        .relinearization_noise_bits = 3,
    }));
}

void test_public_verifier_context_is_minimal_and_functional() {
    auto contexts = make_contexts();
    const auto from_eval =
        MockBackend::make_public_verifier_context(contexts.eval);
    const auto from_client =
        MockBackend::make_public_verifier_context(contexts.client);
    CHECK(MockBackend::slot_count(from_eval) == 8);
    CHECK(MockBackend::storage_context_id(from_eval) ==
          MockBackend::storage_context_id(from_client));
    CHECK(MockBackend::storage_context_id(from_eval) ==
          MockBackend::storage_context_id(contexts.eval));

    const SlotVector plaintext = sequence(8, 19);
    const auto eval_coefficients =
        MockBackend::encode_centered_plaintext_coefficients(
            contexts.eval, plaintext);
    CHECK(MockBackend::encode_centered_plaintext_coefficients(
              from_client, plaintext) == eval_coefficients);
    CHECK(MockBackend::decode_centered_plaintext_coefficients(
              from_client, eval_coefficients) == plaintext);
    CHECK(MockBackend::encode_lowest_plaintext_ntt_coordinates(
              from_client, eval_coefficients) ==
          MockBackend::encode_lowest_plaintext_ntt_coordinates(
              contexts.eval, eval_coefficients));

    const MockBackend::Ciphertext ciphertext =
        MockBackend::encrypt(contexts.client, plaintext);
    const std::vector<std::uint8_t> protocol =
        MockBackend::serialize(ciphertext);
    const MockBackend::Ciphertext protocol_decoded =
        MockBackend::deserialize_protocol(from_client, protocol);
    CHECK(MockBackend::serialize(protocol_decoded) == protocol);
    CHECK(MockBackend::rns_limb_count(from_client, protocol_decoded) ==
          ciphertext.rns_limbs);

    const std::vector<std::uint8_t> persisted =
        MockBackend::serialize_for_storage(contexts.eval, ciphertext);
    const MockBackend::Ciphertext storage_decoded =
        MockBackend::deserialize_from_storage(from_client, persisted);
    CHECK(MockBackend::serialize_for_storage(from_eval, storage_decoded) ==
          persisted);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_mock_backend");
    runner.run("context validation and slot padding",
               test_context_validation_and_padding);
    runner.run("base arithmetic and lazy relinearization",
               test_base_arithmetic_and_lazy_relinearization);
    runner.run("generic in-place addition has a backend fallback",
               test_generic_in_place_addition_fallback);
    runner.run("scalar and vector plaintext costs",
               test_plaintext_cost_classes);
    runner.run("2 x N/2 grid group law", test_grid_group_law);
    runner.run("fold covers both slot rows", test_fold_uses_both_rows);
    runner.run("chain position is separate from depth",
               test_chain_position_is_separate_from_depth);
    runner.run("exact RNS compaction obeys selected proof ingress",
               test_exact_rns_compaction_obeys_selected_ingress);
    runner.run("transport compaction preserves an outer-packing reserve",
               test_transport_compaction_preserves_explicit_reserve);
    runner.run("extension-field arithmetic", test_extension_arithmetic);
    runner.run("mock ciphertext serialization",
               test_serialization_is_canonical_for_mock_state);
    runner.run("mock storage roundtrip preserves backend state",
               test_storage_roundtrip_preserves_mock_state);
    runner.run("mock storage rejects corrupt encodings",
               test_storage_rejects_corrupt_mock_encodings);
    runner.run("public verifier context is minimal and functional",
               test_public_verifier_context_is_minimal_and_functional);
    return runner.summary();
}
