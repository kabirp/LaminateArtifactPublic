#ifndef LAMINATE_PROTOCOL_PACKED_PREPROCESSING_CLIENT_STATIC_HPP
#define LAMINATE_PROTOCOL_PACKED_PREPROCESSING_CLIENT_STATIC_HPP

/// @file client_static.hpp
/// @brief Immutable client authority for recurring packed verification.

#include "laminate/protocol/packed/preprocessing/workload.hpp"
#include "laminate/protocol/packed/setup.hpp"

#include <memory>

namespace laminate::protocol {

/// Workload, protocol geometry, and compact verifier preprocessing validated
/// together once before recurring client work. The private construction
/// boundary prevents an online caller from independently supplying a workload,
/// BhIP count, or transcript-packing verifier key that were never checked as
/// one setup.
class CertifiedPackedClientStatic {
  public:
    CertifiedPackedClientStatic(const CertifiedPackedClientStatic &) =
        default;
    CertifiedPackedClientStatic &operator=(
        const CertifiedPackedClientStatic &) = default;
    CertifiedPackedClientStatic(CertifiedPackedClientStatic &&) noexcept =
        default;
    CertifiedPackedClientStatic &operator=(
        CertifiedPackedClientStatic &&) noexcept = default;

    PackingGkrVariant variant() const;
    std::size_t bhip_round_count() const;
    const Digest &fhe_context_storage_id() const;
    const CertifiedPackedWorkloadStatic &workload() const;

    const FoldedVerifierSetup &folded_verifier_setup() const;
    const LanedVerifierSetup &laned_verifier_setup() const;
    const TranscriptPackingSpartanVerifierSetup &verifier_setup() const;

  private:
    struct State;
    explicit CertifiedPackedClientStatic(std::shared_ptr<const State> state);
    const State &state() const;

    std::shared_ptr<const State> state_;

    friend CertifiedPackedClientStatic certify_packed_client_static(
        CertifiedPackedWorkloadStatic, Digest, FoldedVerifierSetup);
    friend CertifiedPackedClientStatic certify_packed_client_static(
        CertifiedPackedWorkloadStatic, Digest, LanedVerifierSetup);
    friend CertifiedPackedClientStatic certify_packed_client_static(
        CertifiedPackedWorkloadStatic, Digest, const FoldedSetup &);
    friend CertifiedPackedClientStatic certify_packed_client_static(
        CertifiedPackedWorkloadStatic, Digest, const LanedSetup &);
};

/// Perform the complete static client validation for a Folded verifier setup
/// and bind it to the persistent FHE context identity.
CertifiedPackedClientStatic certify_packed_client_static(
    CertifiedPackedWorkloadStatic workload,
    Digest fhe_context_storage_id, FoldedVerifierSetup verifier_setup);

/// Laned counterpart of the Folded certification entry point.
CertifiedPackedClientStatic certify_packed_client_static(
    CertifiedPackedWorkloadStatic workload,
    Digest fhe_context_storage_id, LanedVerifierSetup verifier_setup);

/// Convenience overloads for resident preprocessing. They validate the full
/// prover/verifier setup before projecting the same immutable client
/// capability used by restored role preprocessing.
CertifiedPackedClientStatic certify_packed_client_static(
    CertifiedPackedWorkloadStatic workload,
    Digest fhe_context_storage_id, const FoldedSetup &setup);
CertifiedPackedClientStatic certify_packed_client_static(
    CertifiedPackedWorkloadStatic workload,
    Digest fhe_context_storage_id, const LanedSetup &setup);

} // namespace laminate::protocol

#endif // LAMINATE_PROTOCOL_PACKED_PREPROCESSING_CLIENT_STATIC_HPP
