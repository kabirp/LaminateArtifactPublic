#ifndef LAMINATE_PROTOCOL_PACKED_ONLINE_CLIENT_HPP
#define LAMINATE_PROTOCOL_PACKED_ONLINE_CLIENT_HPP

/// @file client.hpp
/// @brief Owning, authenticated Folded/Laned client state for recurring work.

#include "laminate/protocol/packed/preprocessing/client_static.hpp"
#include "laminate/protocol/packed/preprocessing/roles.hpp"

#include <filesystem>
#include <stdexcept>
#include <utility>

namespace laminate::protocol {

template <PackedRolePreprocessingBackend Backend>
class AuthenticatedPackedClientOnlineState;

template <PackedRolePreprocessingBackend Backend>
AuthenticatedPackedClientOnlineState<Backend>
make_authenticated_packed_client_online_state(
    OpenedPackedClientRoleState<Backend> &&opened,
    typename Backend::ClientContext client_context,
    typename Backend::PublicVerifierContext verifier_context);

template <PackedRolePreprocessingBackend Backend>
AuthenticatedPackedClientOnlineState<Backend>
make_authenticated_packed_client_online_state(
    CertifiedPackedClientStatic certified_static,
    typename Backend::ClientContext client_context,
    typename Backend::PublicVerifierContext verifier_context);

/// Complete client authority restored once before recurring requests.
///
/// `CertifiedPackedClientStatic` replaces repeated circuit-wide setup
/// validation and prevents online APIs from accepting its workload, protocol
/// counts, and verifier setup as independent values. This type additionally
/// owns the secret client context and key-free verifier context, so none of
/// its online accessors can dangle after preprocessing locals are destroyed.
template <PackedRolePreprocessingBackend Backend>
class AuthenticatedPackedClientOnlineState {
  public:
    AuthenticatedPackedClientOnlineState(
        const AuthenticatedPackedClientOnlineState &) = delete;
    AuthenticatedPackedClientOnlineState &operator=(
        const AuthenticatedPackedClientOnlineState &) = delete;
    AuthenticatedPackedClientOnlineState(
        AuthenticatedPackedClientOnlineState &&) noexcept = default;
    AuthenticatedPackedClientOnlineState &operator=(
        AuthenticatedPackedClientOnlineState &&) noexcept = default;

    PackingGkrVariant variant() const { return certified_static_.variant(); }
    std::size_t bhip_round_count() const {
        return certified_static_.bhip_round_count();
    }

    const CertifiedPackedClientStatic &certified_static() const {
        return certified_static_;
    }
    const CertifiedPackedWorkloadStatic &workload() const {
        return certified_static_.workload();
    }
    const typename Backend::ClientContext &client_context() const {
        return client_context_;
    }
    const typename Backend::PublicVerifierContext &verifier_context() const {
        return verifier_context_;
    }

    const FoldedVerifierSetup &folded_verifier_setup() const {
        return certified_static_.folded_verifier_setup();
    }
    const LanedVerifierSetup &laned_verifier_setup() const {
        return certified_static_.laned_verifier_setup();
    }
    const TranscriptPackingSpartanVerifierSetup &verifier_setup() const {
        return certified_static_.verifier_setup();
    }

  private:
    AuthenticatedPackedClientOnlineState(
        CertifiedPackedClientStatic certified_static,
        typename Backend::ClientContext client_context,
        typename Backend::PublicVerifierContext verifier_context)
        : certified_static_(std::move(certified_static)),
          client_context_(std::move(client_context)),
          verifier_context_(std::move(verifier_context)) {}

    friend AuthenticatedPackedClientOnlineState<Backend>
    make_authenticated_packed_client_online_state<Backend>(
        OpenedPackedClientRoleState<Backend> &&,
        typename Backend::ClientContext,
        typename Backend::PublicVerifierContext);

    friend AuthenticatedPackedClientOnlineState<Backend>
    make_authenticated_packed_client_online_state<Backend>(
        CertifiedPackedClientStatic,
        typename Backend::ClientContext,
        typename Backend::PublicVerifierContext);

    CertifiedPackedClientStatic certified_static_;
    typename Backend::ClientContext client_context_;
    typename Backend::PublicVerifierContext verifier_context_;
};

/// Transfer a completely validated static capability and matching restored
/// contexts into one owning online token. This overload is shared by
/// persistent role restoration and resident preprocessing used by tests.
template <PackedRolePreprocessingBackend Backend>
AuthenticatedPackedClientOnlineState<Backend>
make_authenticated_packed_client_online_state(
    CertifiedPackedClientStatic certified_static,
    typename Backend::ClientContext client_context,
    typename Backend::PublicVerifierContext verifier_context) {
    const Digest client_id = Backend::storage_context_id(client_context);
    if (client_id != Backend::storage_context_id(verifier_context) ||
        client_id != certified_static.fhe_context_storage_id()) {
        throw std::invalid_argument(
            "authenticated packed client contexts do not match the "
            "certified static authority");
    }
    const std::size_t slots =
        certified_static.workload().public_setup().shape.slot_count;
    if (Backend::slot_count(client_context) != slots ||
        Backend::slot_count(verifier_context) != slots) {
        throw std::invalid_argument(
            "authenticated packed client context geometry differs "
            "from the workload");
    }
    return AuthenticatedPackedClientOnlineState<Backend>(
        std::move(certified_static), std::move(client_context),
        std::move(verifier_context));
}

/// Certify the compact setup reconstructed by an authenticated role opening,
/// then transfer it and matching restored contexts into one online token.
/// This is setup/restoration work and is never part of a recurring request.
template <PackedRolePreprocessingBackend Backend>
AuthenticatedPackedClientOnlineState<Backend>
make_authenticated_packed_client_online_state(
    OpenedPackedClientRoleState<Backend> &&opened,
    typename Backend::ClientContext client_context,
    typename Backend::PublicVerifierContext verifier_context) {
    const PackingGkrVariant variant = opened.core().role_static.variant;
    const auto &role_static = opened.core().role_static;
    const auto &packing_verifier = opened.verifier_setup();
    if (packing_verifier.variant != variant ||
        packing_verifier.bhip_round_count !=
            role_static.bhip_round_count ||
        packing_verifier.parameters != role_static.parameters ||
        packing_verifier.basefold_parameters !=
            role_static.basefold_parameters ||
        packing_verifier.spartan.setup_digest !=
            role_static.spartan_setup_digest ||
        packing_verifier.spartan.factored_computation == nullptr ||
        !(packing_verifier.spartan.factored_computation->commitment ==
          role_static.factored_commitment) ||
        opened.workload().public_setup().shape.kind !=
            (variant == PackingGkrVariant::Folded
                 ? payload::PayloadKind::Wide
                 : payload::PayloadKind::Laned)) {
        throw std::invalid_argument(
            "authenticated packed client role has inconsistent "
            "protocol metadata");
    }

    CertifiedPackedWorkloadStatic workload = opened.workload();
    CertifiedPackedClientStatic certified_static =
        variant == PackingGkrVariant::Folded
            ? certify_packed_client_static(
                  std::move(workload), role_static.fhe_context_storage_id,
                  FoldedVerifierSetup{
                      .transcript_packing = opened.verifier_setup()})
            : certify_packed_client_static(
                  std::move(workload), role_static.fhe_context_storage_id,
                  LanedVerifierSetup{
                      .transcript_packing = opened.verifier_setup()});
    return make_authenticated_packed_client_online_state<Backend>(
        std::move(certified_static), std::move(client_context),
        std::move(verifier_context));
}

/// Restore, authenticate, and transfer the complete client authority in one
/// operation. The returned state owns both contexts; the temporary role
/// opening retains no references beyond this call.
template <PackedRolePreprocessingBackend Backend>
AuthenticatedPackedClientOnlineState<Backend>
open_authenticated_packed_client_online_state(
    const std::filesystem::path &shared_directory,
    const std::filesystem::path &client_directory,
    const Digest &expected_root_storage_identity,
    typename Backend::ClientContext client_context,
    typename Backend::PublicVerifierContext verifier_context,
    const PackedRolePreprocessingOpenLimits &limits) {
    OpenedPackedClientRoleState<Backend> opened =
        open_packed_client_role_state<Backend>(
            shared_directory, client_directory,
            expected_root_storage_identity, client_context,
            verifier_context, limits);
    return make_authenticated_packed_client_online_state<Backend>(
        std::move(opened), std::move(client_context),
        std::move(verifier_context));
}

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_ONLINE_CLIENT_HPP
