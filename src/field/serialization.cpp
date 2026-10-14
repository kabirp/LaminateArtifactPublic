#include "laminate/field/serialization.hpp"

#include "laminate/params.hpp"

#include <algorithm>
#include <stdexcept>

namespace laminate {

SerializedFp serialize(const Fp &value) {
    const std::uint64_t word = value.value();
    return {
        static_cast<std::uint8_t>(word & 0xffU),
        static_cast<std::uint8_t>((word >> 8U) & 0xffU),
        static_cast<std::uint8_t>((word >> 16U) & 0xffU),
    };
}

SerializedFpk serialize(const Fpk &value) {
    SerializedFpk output{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        const SerializedFp encoded =
            serialize(value.coefficients()[coefficient]);
        std::copy(encoded.begin(), encoded.end(),
                  output.begin() + static_cast<std::ptrdiff_t>(
                                       coefficient * kSerializedFpBytes));
    }
    return output;
}

SerializedFq serialize(const Fq &value) {
    SerializedFq output{};
    const std::uint64_t word = value.value();
    for (std::size_t byte = 0; byte < output.size(); ++byte) {
        output[byte] = static_cast<std::uint8_t>(word >> (8U * byte));
    }
    return output;
}

SerializedFq2 serialize(const Fq2 &value) {
    SerializedFq2 output{};
    for (std::size_t coefficient = 0; coefficient < 2; ++coefficient) {
        const SerializedFq encoded =
            serialize(value.coefficients()[coefficient]);
        std::copy(encoded.begin(), encoded.end(),
                  output.begin() + static_cast<std::ptrdiff_t>(
                                       coefficient * kSerializedFqBytes));
    }
    return output;
}

Fp deserialize_fp(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != kSerializedFpBytes) {
        throw std::invalid_argument(
            "deserialize_fp: expected exactly three bytes");
    }
    const std::uint64_t word = static_cast<std::uint64_t>(bytes[0]) |
                               (static_cast<std::uint64_t>(bytes[1]) << 8U) |
                               (static_cast<std::uint64_t>(bytes[2]) << 16U);
    if (word >= kBaseFieldOrder) {
        throw std::invalid_argument("deserialize_fp: noncanonical value");
    }
    return Fp(word);
}

Fpk deserialize_fpk(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != kSerializedFpkBytes) {
        throw std::invalid_argument(
            "deserialize_fpk: incorrect extension-field length");
    }
    Fpk::Coefficients coefficients{};
    for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
         ++coefficient) {
        coefficients[coefficient] = deserialize_fp(bytes.subspan(
            coefficient * kSerializedFpBytes, kSerializedFpBytes));
    }
    return Fpk(coefficients);
}

Fq deserialize_fq(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != kSerializedFqBytes) {
        throw std::invalid_argument(
            "deserialize_fq: expected exactly eight bytes");
    }
    std::uint64_t word = 0;
    for (std::size_t byte = bytes.size(); byte > 0; --byte) {
        word = (word << 8U) | bytes[byte - 1];
    }
    if (word >= kOuterFieldOrder) {
        throw std::invalid_argument("deserialize_fq: noncanonical value");
    }
    return Fq(word);
}

Fq2 deserialize_fq2(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != kSerializedFq2Bytes) {
        throw std::invalid_argument(
            "deserialize_fq2: incorrect extension-field length");
    }
    return Fq2({deserialize_fq(bytes.first(kSerializedFqBytes)),
                deserialize_fq(bytes.subspan(kSerializedFqBytes))});
}

} // namespace laminate
