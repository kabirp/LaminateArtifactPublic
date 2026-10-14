/// @file test_fhe_value_codec.cpp
/// @brief Stable bytes, canonical decoding, and limits for `FheValue`.

#include "test_helpers.hpp"

#include "laminate/fhe/mock_backend.hpp"
#include "laminate/fhe/storage/value_codec.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;

namespace {

MockBackend::Contexts contexts() {
    return MockBackend::create(MockParameters{
        .slot_count = 4,
        .fresh_rns_limbs = 3,
        .bits_per_limb = 40,
    });
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

template <typename Function> bool rejects(Function &&function) {
    try {
        std::forward<Function>(function)();
        return false;
    } catch (const std::invalid_argument &) {
        return true;
    } catch (const std::runtime_error &) {
        return true;
    }
}

bool same_value(const MockBackend::EvalContext &eval,
                const FheValue<MockBackend> &left,
                const FheValue<MockBackend> &right) {
    if (left.is_public() || right.is_public()) {
        return left.is_public() && right.is_public() &&
               left.plaintext() == right.plaintext();
    }
    return MockBackend::serialize_for_storage(eval, left.ciphertext()) ==
           MockBackend::serialize_for_storage(eval, right.ciphertext());
}

void check_stable_record_bytes() {
    const auto backend = contexts();

    const auto scalar = FheValue<MockBackend>::public_scalar(Fp(0x1234));
    std::vector<std::uint8_t> expected_scalar{
        static_cast<std::uint8_t>(FheValueRecordTag::PublicScalar)};
    append_u64(expected_scalar, 0x1234);
    CHECK(encode_fhe_value_record<MockBackend>(backend.eval, scalar) ==
          expected_scalar);

    const auto slots = FheValue<MockBackend>::public_slots(
        SlotVector{Fp(1), Fp(2), Fp(3), Fp(4)});
    std::vector<std::uint8_t> expected_slots{
        static_cast<std::uint8_t>(FheValueRecordTag::PublicSlots)};
    append_u64(expected_slots, 4);
    append_u64(expected_slots, 1);
    append_u64(expected_slots, 2);
    append_u64(expected_slots, 3);
    append_u64(expected_slots, 4);
    CHECK(encode_fhe_value_record<MockBackend>(backend.eval, slots) ==
          expected_slots);

    const auto encrypted = FheValue<MockBackend>::from_ciphertext(
        MockBackend::encrypt(backend.client,
                             SlotVector{Fp(7), Fp(8), Fp(9), Fp(10)}));
    const auto ciphertext = MockBackend::serialize_for_storage(
        backend.eval, encrypted.ciphertext());
    std::vector<std::uint8_t> expected_record{
        static_cast<std::uint8_t>(FheValueRecordTag::Ciphertext)};
    expected_record.insert(expected_record.end(), ciphertext.begin(),
                           ciphertext.end());
    CHECK(encode_fhe_value_record<MockBackend>(backend.eval, encrypted) ==
          expected_record);

    std::vector<std::uint8_t> expected_wire{
        static_cast<std::uint8_t>(FheValueRecordTag::Ciphertext)};
    append_u64(expected_wire, ciphertext.size());
    expected_wire.insert(expected_wire.end(), ciphertext.begin(),
                         ciphertext.end());
    std::vector<std::uint8_t> actual_wire;
    append_self_delimiting_fhe_value<MockBackend>(
        actual_wire, backend.eval, encrypted);
    CHECK(actual_wire == expected_wire);

    std::vector<std::uint8_t> public_wire;
    append_self_delimiting_fhe_value<MockBackend>(
        public_wire, backend.eval, slots);
    CHECK(public_wire == expected_slots);
}

void check_record_and_sequence_round_trips() {
    const auto backend = contexts();
    const std::vector<FheValue<MockBackend>> values{
        FheValue<MockBackend>::public_zero(),
        FheValue<MockBackend>::public_slots(
            SlotVector{Fp(2), Fp(3), Fp(5), Fp(7)}),
        FheValue<MockBackend>::from_ciphertext(
            MockBackend::encrypt(
                backend.client,
                SlotVector{Fp(11), Fp(13), Fp(17), Fp(19)})),
    };

    std::vector<std::uint8_t> sequence;
    for (const auto &value : values) {
        const auto record =
            encode_fhe_value_record<MockBackend>(backend.eval, value);
        const auto decoded = decode_fhe_value_record<MockBackend>(
            backend.eval, record,
            [&](std::span<const std::uint8_t> ciphertext) {
                return MockBackend::deserialize_from_storage(
                    backend.eval, ciphertext);
            });
        CHECK(same_value(backend.eval, value, decoded));
        append_self_delimiting_fhe_value<MockBackend>(
            sequence, backend.eval, value);
    }

    std::size_t offset = 0;
    for (const auto &expected : values) {
        const auto decoded =
            decode_self_delimiting_fhe_value<MockBackend>(
                backend.eval,
                std::span<const std::uint8_t>(sequence).subspan(offset),
                MockBackend::storage_ciphertext_byte_limit(backend.eval),
                [&](std::span<const std::uint8_t> ciphertext) {
                    return MockBackend::deserialize_from_storage(
                        backend.eval, ciphertext);
                });
        CHECK(same_value(backend.eval, expected, decoded.value));
        offset += decoded.bytes_consumed;
    }
    CHECK(offset == sequence.size());
}

void check_noncanonical_encodings_and_limits_reject() {
    const auto backend = contexts();
    auto decode = [&](std::span<const std::uint8_t> ciphertext) {
        return MockBackend::deserialize_from_storage(backend.eval,
                                                     ciphertext);
    };

    std::vector<std::uint8_t> uniform_slots{
        static_cast<std::uint8_t>(FheValueRecordTag::PublicSlots)};
    append_u64(uniform_slots, 4);
    for (std::size_t slot = 0; slot < 4; ++slot) {
        append_u64(uniform_slots, 9);
    }
    CHECK(rejects([&] {
        (void)decode_fhe_value_record<MockBackend>(
            backend.eval, uniform_slots, decode);
    }));

    std::vector<std::uint8_t> outside_field{
        static_cast<std::uint8_t>(FheValueRecordTag::PublicScalar)};
    append_u64(outside_field, kBaseFieldOrder);
    CHECK(rejects([&] {
        (void)decode_fhe_value_record<MockBackend>(
            backend.eval, outside_field, decode);
    }));

    const auto encrypted = FheValue<MockBackend>::from_ciphertext(
        MockBackend::encrypt(backend.client, SlotVector(4, Fp(23))));
    std::vector<std::uint8_t> wire;
    append_self_delimiting_fhe_value<MockBackend>(wire, backend.eval,
                                                  encrypted);
    CHECK(rejects([&] {
        (void)decode_self_delimiting_fhe_value<MockBackend>(
            backend.eval, wire, 1, decode);
    }));

    wire.pop_back();
    CHECK(rejects([&] {
        (void)decode_self_delimiting_fhe_value<MockBackend>(
            backend.eval, wire,
            MockBackend::storage_ciphertext_byte_limit(backend.eval),
            decode);
    }));
}

} // namespace

int main() {
    test::Runner runner("test_fhe_value_codec");
    runner.run("trace v4 and delegation v4 value bytes stay stable",
               check_stable_record_bytes);
    runner.run("records and self-delimiting sequences round-trip",
               check_record_and_sequence_round_trips);
    runner.run("noncanonical values and resource violations reject",
               check_noncanonical_encodings_and_limits_reject);
    return runner.summary();
}
