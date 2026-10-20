/// @file fq_ntt.cpp
/// @brief Scalar reference and production dispatch for native-Fq NTTs.

#include "laminate/field/fq_ntt.hpp"

#ifdef LAMINATE_NATIVE_FQ_HEXL
#include "seal/modulus.h"
#include "seal/util/ntt.h"
#endif

#include <algorithm>
#include <bit>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace laminate {
namespace {

constexpr std::size_t kMaximumSealNttLogSize = 17;
constexpr std::size_t kMaximumSealNttSize =
    std::size_t{1} << kMaximumSealNttLogSize;
#ifdef LAMINATE_NATIVE_FQ_HEXL
constexpr std::size_t kMinimumAutomaticHexlNttSize =
    std::size_t{1} << 16U;
#endif

bool intel_hexl_compiled() noexcept {
#ifdef LAMINATE_NATIVE_FQ_HEXL
    return true;
#else
    return false;
#endif
}

bool intel_hexl_supports_size(std::size_t size) noexcept {
    return size >= 2 && size <= kMaximumSealNttSize;
}

FqNttBackend select_backend(FqNttBackend requested, std::size_t size) {
    if (requested == FqNttBackend::Automatic) {
#ifdef LAMINATE_NATIVE_FQ_HEXL
        if (size >= kMinimumAutomaticHexlNttSize &&
            intel_hexl_supports_size(size)) {
            return FqNttBackend::IntelHexl;
        }
#endif
        return FqNttBackend::Scalar;
    }
    if (!fq_ntt_backend_available(requested)) {
        throw std::invalid_argument("requested Fq NTT backend is unavailable");
    }
    if (requested == FqNttBackend::IntelHexl &&
        !intel_hexl_supports_size(size)) {
        throw std::invalid_argument(
            "Intel HEXL Fq NTT size exceeds the supported SEAL range");
    }
    return requested;
}

#ifdef LAMINATE_NATIVE_FQ_HEXL

std::size_t reverse_low_bits(std::size_t value, std::size_t bit_count) {
    std::size_t result = 0;
    for (std::size_t bit = 0; bit < bit_count; ++bit) {
        result = (result << 1U) | ((value >> bit) & 1U);
    }
    return result;
}

std::size_t cyclic_root_exponent(std::size_t size, Fq selected_root,
                                 Fq seal_cyclic_root) {
    Fq power = Fq::one();
    for (std::size_t exponent = 0; exponent < size; ++exponent) {
        if (power == seal_cyclic_root) {
            return exponent;
        }
        power *= selected_root;
    }
    throw std::invalid_argument(
        "selected Fq NTT root does not generate the SEAL root subgroup");
}

std::size_t invert_odd_mod_power_of_two(std::size_t value,
                                        std::size_t modulus) {
    for (std::size_t candidate = 1; candidate < modulus; candidate += 2U) {
        if ((value * candidate & (modulus - 1U)) == 1U) {
            return candidate;
        }
    }
    throw std::invalid_argument("Fq NTT root exponent is not invertible");
}

struct IntelHexlState {
    IntelHexlState(std::size_t size, Fq selected_root)
        : tables(static_cast<int>(std::bit_width(size) - 1U),
                 seal::Modulus(kOuterFieldOrder)),
          input_twists(size), output_indices(size), buffer(size) {
        static_assert(kOuterFieldOrder < (std::uint64_t{1} << 62U),
                      "HEXL NTT requires a modulus below 2^62");
        const Fq seal_root(tables.get_root());
        const Fq seal_cyclic_root = seal_root * seal_root;
        const std::size_t root_exponent =
            cyclic_root_exponent(size, selected_root, seal_cyclic_root);
        if ((root_exponent & 1U) == 0) {
            throw std::invalid_argument("Fq NTT root is not primitive");
        }
        const std::size_t inverse_exponent =
            invert_odd_mod_power_of_two(root_exponent, size);
        const std::size_t log_size = std::bit_width(size) - 1U;
        for (std::size_t output = 0; output < size; ++output) {
            const std::size_t seal_frequency =
                output * inverse_exponent & (size - 1U);
            output_indices[output] =
                reverse_low_bits(seal_frequency, log_size);
        }

        const Fq inverse_seal_root = seal_root.inverse();
        Fq twist = Fq::one();
        for (Fq &entry : input_twists) {
            entry = twist;
            twist *= inverse_seal_root;
        }
    }

    void apply(std::span<Fq> values) {
        for (std::size_t index = 0; index < values.size(); ++index) {
            buffer[index] = (values[index] * input_twists[index]).value();
        }
        seal::util::ntt_negacyclic_harvey(buffer.data(), tables);
        for (std::size_t output = 0; output < values.size(); ++output) {
            values[output] = Fq(buffer[output_indices[output]]);
        }
    }

    seal::util::NTTTables tables;
    std::vector<Fq> input_twists;
    std::vector<std::size_t> output_indices;
    std::vector<std::uint64_t> buffer;
};

#endif

} // namespace

struct FqNttPlan::Impl {
    Impl(std::size_t selected_size, Fq selected_root,
         FqNttBackend requested_backend)
        : size(selected_size),
          backend(select_backend(requested_backend, selected_size)),
          twiddles(size == 0 ? 0 : size - 1U) {
        if (!std::has_single_bit(size)) {
            throw std::invalid_argument(
                "Fq NTT size must be a nonzero power of two");
        }
        for (std::size_t length = 2; length <= size; length <<= 1U) {
            Fq stage_root = selected_root;
            for (std::size_t order = length; order < size; order <<= 1U) {
                stage_root *= stage_root;
            }
            const std::size_t half = length / 2U;
            Fq twiddle = Fq::one();
            for (std::size_t offset = 0; offset < half; ++offset) {
                twiddles[half - 1U + offset] = twiddle;
                twiddle *= stage_root;
            }
        }
#ifdef LAMINATE_NATIVE_FQ_HEXL
        if (backend == FqNttBackend::IntelHexl) {
            intel_hexl =
                std::make_unique<IntelHexlState>(size, selected_root);
        }
#endif
    }

    void apply_scalar(std::span<Fq> values) const {
        if (values.size() != size) {
            throw std::invalid_argument("Fq NTT row has the wrong size");
        }
        for (std::size_t index = 1, reversed = 0; index < size; ++index) {
            std::size_t bit = size >> 1U;
            while ((reversed & bit) != 0) {
                reversed ^= bit;
                bit >>= 1U;
            }
            reversed ^= bit;
            if (index < reversed) {
                std::swap(values[index], values[reversed]);
            }
        }
        for (std::size_t length = 2; length <= size; length <<= 1U) {
            const std::size_t half = length / 2U;
            const Fq *stage_twiddles = twiddles.data() + half - 1U;
            for (std::size_t begin = 0; begin < size; begin += length) {
                for (std::size_t offset = 0; offset < half; ++offset) {
                    const Fq low = values[begin + offset];
                    const Fq high = values[begin + half + offset] *
                                    stage_twiddles[offset];
                    values[begin + offset] = low + high;
                    values[begin + half + offset] = low - high;
                }
            }
        }
    }

    std::size_t size = 0;
    FqNttBackend backend = FqNttBackend::Scalar;
    std::vector<Fq> twiddles;
#ifdef LAMINATE_NATIVE_FQ_HEXL
    std::unique_ptr<IntelHexlState> intel_hexl;
#endif
};

std::string_view fq_ntt_backend_name(FqNttBackend backend) noexcept {
    switch (backend) {
    case FqNttBackend::Automatic:
        return "automatic";
    case FqNttBackend::Scalar:
        return "scalar-montgomery";
    case FqNttBackend::IntelHexl:
        return "intel-hexl";
    case FqNttBackend::Avx512Ifma:
        return "avx512-ifma-montgomery";
    }
    return "unknown";
}

bool fq_ntt_backend_available(FqNttBackend backend) noexcept {
    switch (backend) {
    case FqNttBackend::Automatic:
    case FqNttBackend::Scalar:
        return true;
    case FqNttBackend::IntelHexl:
        return intel_hexl_compiled();
    case FqNttBackend::Avx512Ifma:
        // The native field is 60 bits. HEXL's IFMA kernels require a much
        // smaller modulus, so this backend must never be advertised.
        return false;
    }
    return false;
}

FqNttPlan::FqNttPlan(std::size_t size, Fq root,
                     FqNttBackend requested_backend)
    : impl_(std::make_unique<Impl>(size, root, requested_backend)) {}

FqNttPlan::~FqNttPlan() = default;
FqNttPlan::FqNttPlan(FqNttPlan &&) noexcept = default;
FqNttPlan &FqNttPlan::operator=(FqNttPlan &&) noexcept = default;

std::size_t FqNttPlan::size() const noexcept { return impl_->size; }
FqNttBackend FqNttPlan::backend() const noexcept { return impl_->backend; }

void FqNttPlan::apply(std::span<Fq> values) {
    if (values.size() != impl_->size) {
        throw std::invalid_argument("Fq NTT row has the wrong size");
    }
    apply_rows(values);
}

void FqNttPlan::apply_rows(std::span<Fq> values) {
    if (values.empty() || values.size() % impl_->size != 0) {
        throw std::invalid_argument("Fq NTT batch has a partial row");
    }
#ifdef LAMINATE_NATIVE_FQ_HEXL
    if (impl_->backend == FqNttBackend::IntelHexl) {
        for (std::size_t offset = 0; offset < values.size();
             offset += impl_->size) {
            impl_->intel_hexl->apply(values.subspan(offset, impl_->size));
        }
        return;
    }
#endif
    for (std::size_t offset = 0; offset < values.size();
         offset += impl_->size) {
        impl_->apply_scalar(values.subspan(offset, impl_->size));
    }
}

void FqNttPlan::apply_scalar_reference(std::span<Fq> values) const {
    impl_->apply_scalar(values);
}

} // namespace laminate
