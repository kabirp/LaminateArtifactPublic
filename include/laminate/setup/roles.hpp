#ifndef LAMINATE_SETUP_ROLES_HPP
#define LAMINATE_SETUP_ROLES_HPP

/// @file setup/roles.hpp
/// @brief Role-owned FHE setup types and checked factories.

#include "laminate/fhe/backend.hpp"
#include "laminate/fhe/layout/fixed_message.hpp"
#include "laminate/setup/public.hpp"

#include <cstddef>
#include <concepts>
#include <memory>
#include <stdexcept>
#include <utility>

namespace laminate {

/// Server-facing setup with evaluation material but no decryptor capability.
template <fhe::FheBackend Backend> struct EvaluationSetup {
    PublicSetup public_setup;
    typename Backend::EvalContext context;
    std::shared_ptr<const gates::GateTableProverKey> gate_mle_prover_key;
};

/// Client-facing setup that owns the backend's decryption capability.
template <fhe::FheBackend Backend> struct ClientSetup {
    PublicSetup public_setup;
    typename Backend::ClientContext context;
};

/// Client FHE setup paired with its key-free public verifier context.
template <fhe::PublicVerifierFheBackend Backend>
class PackedClientSetup;

template <fhe::PublicVerifierFheBackend Backend>
PackedClientSetup<Backend> make_packed_client_setup_from_verifier_context(
    ClientSetup<Backend> client,
    typename Backend::PublicVerifierContext verifier);

template <fhe::PublicVerifierFheBackend Backend>
class PackedClientSetup {
  public:
    PackedClientSetup(const PackedClientSetup &) = default;
    PackedClientSetup(PackedClientSetup &&) = default;

    const ClientSetup<Backend> &client_setup() const { return client_; }
    const PublicSetup &public_setup() const { return client_.public_setup; }
    const typename Backend::ClientContext &client_context() const {
        return client_.context;
    }
    const typename Backend::PublicVerifierContext &verifier_context() const {
        return verifier_;
    }

  private:
    PackedClientSetup(ClientSetup<Backend> client,
                      typename Backend::PublicVerifierContext verifier)
        : client_(std::move(client)), verifier_(std::move(verifier)) {}

    ClientSetup<Backend> client_;
    typename Backend::PublicVerifierContext verifier_;

    friend PackedClientSetup<Backend>
    make_packed_client_setup_from_verifier_context<Backend>(
        ClientSetup<Backend>, typename Backend::PublicVerifierContext);
};

template <fhe::FheBackend Backend>
EvaluationSetup<Backend>
make_evaluation_setup(PublicSetup public_setup,
                      typename Backend::EvalContext context,
                      std::shared_ptr<const gates::GateTableProverKey>
                          gate_mle_prover_key = {}) {
    if (Backend::slot_count(context) != public_setup.shape.slot_count) {
        throw std::invalid_argument(
            "make_evaluation_setup: backend and public slot counts differ");
    }
    const bool outsourced = public_setup.gate_mle_profile ==
                            GateMleProfile::OutsourcedBaseFold;
    if (outsourced != static_cast<bool>(gate_mle_prover_key)) {
        throw std::invalid_argument(
            "make_evaluation_setup: outsourced prover key presence "
            "disagrees with the public profile");
    }
    if (outsourced &&
        (!public_setup.outsourced_gate_mle ||
         !(gate_mle_prover_key->verifier ==
           *public_setup.outsourced_gate_mle))) {
        throw std::invalid_argument(
            "make_evaluation_setup: outsourced prover/verifier keys differ");
    }
    return EvaluationSetup<Backend>{
        std::move(public_setup), std::move(context),
        std::move(gate_mle_prover_key)};
}

/// Construct the packed server role and prepare its reusable alignment masks.
template <fhe::FheBackend Backend>
EvaluationSetup<Backend> make_packed_evaluation_setup(
    PublicSetup public_setup, typename Backend::EvalContext context,
    std::shared_ptr<const gates::GateTableProverKey>
        gate_mle_prover_key = {}) {
    EvaluationSetup<Backend> result = make_evaluation_setup<Backend>(
        std::move(public_setup), std::move(context),
        std::move(gate_mle_prover_key));
    if (Backend::slot_count(result.context) < fhe::kFixedMessageCellCount) {
        throw std::invalid_argument(
            "make_packed_evaluation_setup: too few SIMD slots");
    }
    Backend::preprocess_fixed_message_cells(result.context);
    return result;
}

template <fhe::FheBackend Backend>
ClientSetup<Backend> make_client_setup(PublicSetup public_setup,
                                       typename Backend::ClientContext context) {
    if (Backend::slot_count(context) != public_setup.shape.slot_count) {
        throw std::invalid_argument(
            "make_client_setup: backend and public slot counts differ");
    }
    return ClientSetup<Backend>{std::move(public_setup), std::move(context)};
}

/// Pair independently restored client and key-free verifier state.
template <fhe::PublicVerifierFheBackend Backend>
PackedClientSetup<Backend> make_packed_client_setup_from_verifier_context(
    ClientSetup<Backend> client,
    typename Backend::PublicVerifierContext verifier) {
    const std::size_t expected_slots = client.public_setup.shape.slot_count;
    if (Backend::slot_count(client.context) != expected_slots ||
        Backend::slot_count(verifier) != expected_slots) {
        throw std::invalid_argument(
            "make_packed_client_setup_from_verifier_context: public, client, "
            "and verifier slot counts differ");
    }
    if constexpr (requires {
                      {
                          Backend::storage_context_id(client.context)
                      } -> std::same_as<Digest>;
                      {
                          Backend::storage_context_id(verifier)
                      } -> std::same_as<Digest>;
                  }) {
        if (Backend::storage_context_id(client.context) !=
            Backend::storage_context_id(verifier)) {
            throw std::invalid_argument(
                "make_packed_client_setup_from_verifier_context: client and "
                "verifier context identities differ");
        }
    }
    return PackedClientSetup<Backend>{std::move(client),
                                      std::move(verifier)};
}

} // namespace laminate

#endif // LAMINATE_SETUP_ROLES_HPP
