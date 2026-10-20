#ifndef LAMINATE_FIELD_FQ_NTT_HPP
#define LAMINATE_FIELD_FQ_NTT_HPP

/// @file fq_ntt.hpp
/// @brief Backend-isolated power-of-two transforms over native Fq.

#include "laminate/field/fq.hpp"

#include <cstddef>
#include <memory>
#include <span>
#include <string_view>

namespace laminate {

enum class FqNttBackend {
    Automatic,
    Scalar,
    IntelHexl,
    Avx512Ifma,
};

std::string_view fq_ntt_backend_name(FqNttBackend backend) noexcept;
bool fq_ntt_backend_available(FqNttBackend backend) noexcept;

/// Reusable cyclic transform: output[k] = sum_j input[j] * root^(j*k).
/// The size must be a nonzero power of two, and the caller must supply a root
/// of exactly that order. An inverse transform uses root.inverse() followed
/// by multiplication by Fq(size).inverse().
///
/// `apply()` uses the selected backend; `apply_scalar_reference()` provides
/// the scalar comparison used by backend tests and diagnostics. A plan owns
/// backend scratch space and must not be used concurrently.
class FqNttPlan {
  public:
    FqNttPlan(std::size_t size, Fq root,
              FqNttBackend requested_backend = FqNttBackend::Automatic);
    ~FqNttPlan();

    FqNttPlan(const FqNttPlan &) = delete;
    FqNttPlan &operator=(const FqNttPlan &) = delete;
    FqNttPlan(FqNttPlan &&) noexcept;
    FqNttPlan &operator=(FqNttPlan &&) noexcept;

    std::size_t size() const noexcept;
    FqNttBackend backend() const noexcept;
    void apply(std::span<Fq> values);
    /// Apply the same transform independently to consecutive exact-size
    /// rows. Dispatch and shape validation occur once for the whole batch.
    void apply_rows(std::span<Fq> values);
    void apply_scalar_reference(std::span<Fq> values) const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace laminate

#endif // LAMINATE_FIELD_FQ_NTT_HPP
