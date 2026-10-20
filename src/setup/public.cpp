#include "laminate/setup/public.hpp"
#include "laminate/setup/gate_mle.hpp"

#include "encoding_detail.hpp"

#include "laminate/gates/canonical_tables.hpp"
#include "laminate/gates/outsourced.hpp"
#include "laminate/gkr/challenge_limits.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/diagnostics/setup_validation.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace laminate {
namespace {

DummyGateMleCommitment make_dummy_commitment(
    const Digest &layered_digest, std::size_t layer_index) {
    setup_detail::Bytes input;
    setup_detail::append_label(input, "LaminateImpl/DummyGateMle/v1");
    input.insert(input.end(), layered_digest.begin(), layered_digest.end());
    setup_detail::append_u64(input, layer_index);
    return DummyGateMleCommitment{layer_index, sha256(input)};
}

PublicSetup build_setup(const payload::PayloadCircuit &payload,
                        const payload::LayeredCircuit &layered,
                        GateMleProfile profile,
                        std::optional<gates::GateTableVerifierKey>
                            outsourced = std::nullopt) {
    payload::validate_compilation_pair(payload, layered);
    gkr::validate_challenge_dimensions(layered);
    PublicSetup result;
    result.gate_mle_profile = profile;
    result.shape = payload.shape;
    result.layer_count = layered.layers.size();
    const payload::CircuitPairDigests digests =
        payload::circuit_pair_digests(payload, layered);
    result.payload_digest = digests.payload;
    result.layered_digest = digests.layered;
    result.circuit_digest = digests.combined;
    result.outsourced_gate_mle = std::move(outsourced);
    if (profile == GateMleProfile::DummyCommittedDirect) {
        result.dummy_gate_commitments.reserve(layered.layers.size() - 1);
        for (std::size_t layer = 0; layer + 1 < layered.layers.size(); ++layer) {
            result.dummy_gate_commitments.push_back(
                make_dummy_commitment(result.layered_digest, layer));
        }
    }
    return result;
}

void validate_outsourced_key(
    const gates::GateTableVerifierKey &key,
    const payload::LayeredCircuit &layered,
    std::size_t target_security_bits) {
    const gates::GateTableLayout expected = gates::make_gate_table_layout(
        layered, key.layout.table_set, key.basefold_parameters);
    bool tables_are_valid = gates::valid_wide_public_index(key);
    for (std::size_t table = 0;
         tables_are_valid && table < key.tables.size(); ++table) {
        const gates::SparseTableCommitment &commitment = key.tables[table];
        const bool zero_root = std::all_of(
            commitment.root.begin(), commitment.root.end(),
            [](std::uint8_t byte) { return byte == 0; });
        tables_are_valid = !zero_root &&
            (commitment.wide_block_offset.has_value() ==
             (key.layout.table_set == gates::GateTableSet::Wide)) &&
            gates::valid_sparse_table_commitment(
                key.layout.tables[table], commitment,
                key.basefold_parameters);
    }
    if (!(key.layout == expected) ||
        key.layout_digest != gates::digest(expected) ||
        !tables_are_valid ||
        key.basefold_parameters.log_rate != kGateMleBaseFoldLogRate ||
        gate_mle_basefold_soundness_bits(key) < target_security_bits) {
        throw std::invalid_argument(
            "PublicSetup: malformed or under-strength outsourced gate key");
    }
}

} // namespace

void PublicSetup::validate(const payload::PayloadCircuit &payload,
                           const payload::LayeredCircuit &layered) const {
    diagnostics::detail::observe_public_setup_validation();
    validate_compilation_pair(payload, layered);
    gkr::validate_challenge_dimensions(layered);
    const payload::CircuitPairDigests digests =
        payload::circuit_pair_digests(payload, layered);
    if (!(shape == payload.shape) || layer_count != layered.layers.size() ||
        plaintext_modulus != kBaseFieldOrder ||
        extension_degree != kExtensionDegree ||
        target_security_bits != kTargetSecurityBits ||
        payload_digest != digests.payload ||
        layered_digest != digests.layered ||
        circuit_digest != digests.combined) {
        throw std::invalid_argument(
            "PublicSetup: public parameters or circuit digests disagree");
    }
    if (honest_base_proof_noise_assessment_digest &&
        !honest_payload_noise_schedule_digest) {
        throw std::invalid_argument(
            "PublicSetup: Base proof-noise binding lacks its payload "
            "schedule binding");
    }

    if (gate_mle_profile == GateMleProfile::Direct) {
        if (!dummy_gate_commitments.empty() || outsourced_gate_mle) {
            throw std::invalid_argument(
                "PublicSetup: direct profile carries commitment material");
        }
        return;
    }

    if (gate_mle_profile == GateMleProfile::OutsourcedBaseFold) {
        if (!dummy_gate_commitments.empty() || !outsourced_gate_mle) {
            throw std::invalid_argument(
                "PublicSetup: outsourced profile has wrong key material");
        }
        validate_outsourced_key(*outsourced_gate_mle, layered,
                                target_security_bits);
        return;
    }

    if (gate_mle_profile != GateMleProfile::DummyCommittedDirect ||
        outsourced_gate_mle) {
        throw std::invalid_argument(
            "PublicSetup: unknown gate-MLE profile");
    }
    if (dummy_gate_commitments.size() + 1 != layered.layers.size()) {
        throw std::invalid_argument(
            "PublicSetup: wrong dummy gate commitment count");
    }
    for (std::size_t layer = 0; layer < dummy_gate_commitments.size(); ++layer) {
        if (!(dummy_gate_commitments[layer] ==
              make_dummy_commitment(layered_digest, layer))) {
            throw std::invalid_argument(
                "PublicSetup: dummy gate commitment mismatch");
        }
    }
}

PublicSetup make_direct_setup(const payload::PayloadCircuit &payload,
                              const payload::LayeredCircuit &layered) {
    return build_setup(payload, layered, GateMleProfile::Direct);
}

PublicSetup make_dummy_committed_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered) {
    return build_setup(payload, layered,
                       GateMleProfile::DummyCommittedDirect);
}

PublicSetup make_outsourced_gate_setup(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &layered,
    gates::GateTableVerifierKey verifier_key) {
    gkr::validate_challenge_dimensions(layered);
    validate_outsourced_key(verifier_key, layered, kTargetSecurityBits);
    return build_setup(payload, layered,
                       GateMleProfile::OutsourcedBaseFold,
                       std::move(verifier_key));
}

} // namespace laminate
