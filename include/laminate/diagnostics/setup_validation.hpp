#ifndef LAMINATE_DIAGNOSTICS_SETUP_VALIDATION_HPP
#define LAMINATE_DIAGNOSTICS_SETUP_VALIDATION_HPP

/// @file setup_validation.hpp
/// @brief Opt-in observation of circuit-wide public-setup validation passes.

#include <cstddef>
#include <stdexcept>

namespace laminate::diagnostics {

/// Counter installed only by diagnostics and regression tests. Ordinary
/// execution pays one null check at the start of a circuit-wide setup scan.
struct PublicSetupValidationCounter {
    std::size_t scans = 0;
};

/// Counts complete `LayeredCircuit::validate()` passes independently of
/// public-setup validation. This catches static circuit rescans hidden behind
/// otherwise innocuous-looking geometry helpers.
struct LayeredCircuitValidationCounter {
    std::size_t scans = 0;
};

namespace detail {
inline thread_local PublicSetupValidationCounter
    *active_public_setup_validation_counter = nullptr;
inline thread_local LayeredCircuitValidationCounter
    *active_layered_circuit_validation_counter = nullptr;

inline void observe_public_setup_validation() noexcept {
    if (active_public_setup_validation_counter != nullptr) {
        ++active_public_setup_validation_counter->scans;
    }
}

inline void observe_layered_circuit_validation() noexcept {
    if (active_layered_circuit_validation_counter != nullptr) {
        ++active_layered_circuit_validation_counter->scans;
    }
}
} // namespace detail

/// Install one thread-local counter for a lexical scope. Nesting observers is
/// rejected so a test cannot accidentally hide validation from its parent.
class ObservePublicSetupValidation {
  public:
    explicit ObservePublicSetupValidation(
        PublicSetupValidationCounter &counter)
        : counter_(&counter) {
        if (detail::active_public_setup_validation_counter != nullptr) {
            throw std::logic_error(
                "public-setup validation observation is already active");
        }
        detail::active_public_setup_validation_counter = counter_;
    }

    ObservePublicSetupValidation(const ObservePublicSetupValidation &) =
        delete;
    ObservePublicSetupValidation &operator=(
        const ObservePublicSetupValidation &) = delete;

    ~ObservePublicSetupValidation() {
        detail::active_public_setup_validation_counter = nullptr;
    }

  private:
    PublicSetupValidationCounter *counter_ = nullptr;
};

/// Install a thread-local observer for complete layered-circuit validation.
class ObserveLayeredCircuitValidation {
  public:
    explicit ObserveLayeredCircuitValidation(
        LayeredCircuitValidationCounter &counter)
        : counter_(&counter) {
        if (detail::active_layered_circuit_validation_counter != nullptr) {
            throw std::logic_error(
                "layered-circuit validation observation is already active");
        }
        detail::active_layered_circuit_validation_counter = counter_;
    }

    ObserveLayeredCircuitValidation(
        const ObserveLayeredCircuitValidation &) = delete;
    ObserveLayeredCircuitValidation &operator=(
        const ObserveLayeredCircuitValidation &) = delete;

    ~ObserveLayeredCircuitValidation() {
        detail::active_layered_circuit_validation_counter = nullptr;
    }

  private:
    LayeredCircuitValidationCounter *counter_ = nullptr;
};

} // namespace laminate::diagnostics

#endif // LAMINATE_DIAGNOSTICS_SETUP_VALIDATION_HPP
