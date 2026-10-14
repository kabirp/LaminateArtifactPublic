#include "laminate/setup/public.hpp"

#include "encoding_detail.hpp"

#include "laminate/gates/canonical_tables.hpp"
#include "laminate/gates/outsourced.hpp"

namespace laminate {

std::vector<std::uint8_t> encode_canonical(const PublicSetup &setup) {
    setup_detail::Bytes output;
    setup_detail::append_label(output, "LaminateImpl/PublicSetup/v4");
    output.push_back(static_cast<std::uint8_t>(setup.gate_mle_profile));
    output.push_back(static_cast<std::uint8_t>(setup.shape.kind));
    setup_detail::append_u64(output, setup.shape.slot_count);
    setup_detail::append_u64(output, setup.shape.lane_count);
    setup_detail::append_u64(output, setup.layer_count);
    setup_detail::append_u64(output, setup.plaintext_modulus);
    setup_detail::append_u64(output, setup.extension_degree);
    setup_detail::append_u64(output, setup.target_security_bits);
    output.insert(output.end(), setup.payload_digest.begin(),
                  setup.payload_digest.end());
    output.insert(output.end(), setup.layered_digest.begin(),
                  setup.layered_digest.end());
    output.insert(output.end(), setup.circuit_digest.begin(),
                  setup.circuit_digest.end());
    output.push_back(
        setup.honest_payload_noise_schedule_digest.has_value() ? 1U : 0U);
    if (setup.honest_payload_noise_schedule_digest) {
        output.insert(
            output.end(),
            setup.honest_payload_noise_schedule_digest->begin(),
            setup.honest_payload_noise_schedule_digest->end());
    }
    output.push_back(
        setup.honest_base_proof_noise_assessment_digest.has_value()
            ? 1U
            : 0U);
    if (setup.honest_base_proof_noise_assessment_digest) {
        output.insert(
            output.end(),
            setup.honest_base_proof_noise_assessment_digest->begin(),
            setup.honest_base_proof_noise_assessment_digest->end());
    }
    setup_detail::append_u64(output, setup.dummy_gate_commitments.size());
    for (const DummyGateMleCommitment &commitment :
         setup.dummy_gate_commitments) {
        setup_detail::append_u64(output, commitment.layer_index);
        output.insert(output.end(), commitment.value.begin(),
                      commitment.value.end());
    }
    output.push_back(setup.outsourced_gate_mle.has_value() ? 1U : 0U);
    if (setup.outsourced_gate_mle) {
        const setup_detail::Bytes key =
            gates::encode_canonical(*setup.outsourced_gate_mle);
        setup_detail::append_u64(output, key.size());
        output.insert(output.end(), key.begin(), key.end());
    }
    return output;
}

Digest setup_digest(const PublicSetup &setup) {
    const setup_detail::Bytes encoded = encode_canonical(setup);
    return sha256(encoded);
}

} // namespace laminate
