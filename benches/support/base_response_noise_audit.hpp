#ifndef LAMINATE_BENCHES_BASE_RESPONSE_NOISE_AUDIT_HPP
#define LAMINATE_BENCHES_BASE_RESPONSE_NOISE_AUDIT_HPP

#include "benchmark_support.hpp"
#include "laminate/delegation/base/transport/messages.hpp"
#include "laminate/fhe/seal_backend.hpp"

#include <algorithm>
#include <limits>
#include <string>

namespace laminate::bench {

// Client-secret-key diagnostics only. A positive budget is not proof of
// correct computation; zero indicates exhausted decryption headroom. Neither
// observation changes the verifier's decision or exposes plaintext values.
struct BaseResponseNoiseGroup {
    std::size_t ciphertexts = 0;
    std::size_t zero_budget_ciphertexts = 0;
    int minimum_budget_bits = std::numeric_limits<int>::max();
    std::size_t minimum_limbs = std::numeric_limits<std::size_t>::max();
    std::size_t maximum_limbs = 0;
    std::string minimum_location;
    std::string first_zero_location;

    void inspect(const fhe::SealBackend::ClientContext &context,
                 const fhe::FheValue<fhe::SealBackend> &value,
                 const std::string &location) {
        if (!value.is_encrypted()) return;
        const auto &ciphertext = value.ciphertext();
        const int budget = fhe::SealBackend::invariant_noise_budget(context, ciphertext);
        const auto limbs = fhe::SealBackend::data_coefficient_moduli(context, ciphertext).size();
        ++ciphertexts;
        minimum_limbs = std::min(minimum_limbs, limbs);
        maximum_limbs = std::max(maximum_limbs, limbs);
        if (budget < minimum_budget_bits) {
            minimum_budget_bits = budget;
            minimum_location = location;
        }
        if (budget == 0) {
            ++zero_budget_ciphertexts;
            if (first_zero_location.empty()) first_zero_location = location;
        }
    }

    void inspect_extension(const fhe::SealBackend::ClientContext &context,
                           const fhe::ExtensionValue<fhe::SealBackend> &value,
                           const std::string &location) {
        std::size_t coefficient = 0;
        for (const auto &coordinate : value)
            inspect(context, coordinate, location + ".coefficient." + std::to_string(coefficient++));
    }

    void emit(const Record &record, const std::string &prefix) const {
        record.integer(prefix + ".ciphertexts", ciphertexts);
        record.integer(prefix + ".zero_budget_ciphertexts", zero_budget_ciphertexts);
        if (ciphertexts != 0) {
            record.integer(prefix + ".minimum_budget_bits", minimum_budget_bits);
            record.integer(prefix + ".minimum_rns_limbs", minimum_limbs);
            record.integer(prefix + ".maximum_rns_limbs", maximum_limbs);
            record.text(prefix + ".minimum_location", minimum_location);
        }
        if (!first_zero_location.empty()) record.text(prefix + ".first_zero_location", first_zero_location);
    }
};

inline void audit_base_response_noise(
    const fhe::SealBackend::ClientContext &context,
    const delegation::BaseResponse<fhe::SealBackend> &response,
    std::size_t layer, const Record &record) {
    BaseResponseNoiseGroup outputs, rounds, terminals;
    for (std::size_t index = 0; index < response.output.values.size(); ++index)
        outputs.inspect(context, response.output.values[index], "output." + std::to_string(index));
    outputs.emit(record, "audit.noise.output");
    if (layer >= response.proof.reductions.size()) return;
    const auto prefix = "layer." + std::to_string(layer);
    record.integer("audit.noise.layer", layer);
    std::visit([&](const auto &reduction) {
        for (std::size_t round = 0; round < reduction.rounds.size(); ++round) {
            for (std::size_t endpoint = 0; endpoint < reduction.rounds[round].evaluations.size(); ++endpoint)
                rounds.inspect_extension(context, reduction.rounds[round].evaluations[endpoint],
                    prefix + ".round." + std::to_string(round) + ".evaluation." + std::to_string(endpoint));
        }
        if constexpr (requires { reduction.source_vector; }) {
            terminals.inspect_extension(context, reduction.source_vector, prefix + ".terminal");
        } else {
            for (std::size_t side = 0; side < reduction.source_vectors.size(); ++side)
                terminals.inspect_extension(context, reduction.source_vectors[side],
                    prefix + ".terminal." + std::to_string(side));
        }
    }, response.proof.reductions[layer]);
    rounds.emit(record, "audit.noise.rounds");
    terminals.emit(record, "audit.noise.terminal");
}

} // namespace laminate::bench

#endif
