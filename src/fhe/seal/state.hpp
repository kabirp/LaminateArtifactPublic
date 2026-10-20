#ifndef LAMINATE_SRC_FHE_SEAL_STATE_HPP
#define LAMINATE_SRC_FHE_SEAL_STATE_HPP

/// @file state.hpp
/// @brief Private shared state for SEAL plaintext preprocessing.

#include "laminate/fhe/seal_backend.hpp"

#include <array>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace laminate::fhe {

struct SealBackend::PreparedPlaintextCache {
    struct Entry {
        SlotVector slots;
        std::map<seal::parms_id_type, seal::Plaintext> by_level;
        std::size_t ntt_coefficient_bytes = 0;
    };

    std::mutex mutex;
    std::unordered_map<std::uint64_t,
                       std::vector<std::shared_ptr<const Entry>>>
        by_hash;
    std::array<std::shared_ptr<const Entry>, kFixedMessageCellCount>
        fixed_message_cells{};
    PlaintextPreprocessingStats stats;
};

struct SealBackend::PreparedSlotBasis::Impl {
    Digest storage_id{};
    std::size_t slot_count = 0;
    bool zero = true;
    bool scalar = false;
    Fp scalar_value = Fp::zero();
    std::shared_ptr<const SealBackend::PreparedPlaintextCache::Entry> vector;
};

struct SealBackend::PreparedLevelSlotBasis::Impl {
    Digest storage_id{};
    seal::parms_id_type parms_id{};
    std::size_t slot_count = 0;
    bool zero = true;
    bool scalar = false;
    Fp scalar_value = Fp::zero();
    std::optional<seal::Plaintext> vector;
    std::size_t level_representations = 0;
    std::size_t ntt_coefficient_bytes = 0;
};

struct SealBackend::PreparedExtensionSlotBasis::Impl {
    struct Coefficient {
        bool zero = true;
        bool scalar = false;
        Fp scalar_value = Fp::zero();
        std::optional<seal::Plaintext> vector;
    };

    Digest storage_id{};
    seal::parms_id_type parms_id{};
    std::array<Coefficient, kExtensionDegree> coefficients;
    std::size_t slot_count = 0;
    std::size_t level_representations = 0;
    std::size_t ntt_coefficient_bytes = 0;
};

} // namespace laminate::fhe

#endif // LAMINATE_SRC_FHE_SEAL_STATE_HPP
