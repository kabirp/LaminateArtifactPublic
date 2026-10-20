#ifndef LAMINATE_TEST_BASE_CHECKPOINT_TEST_HELPERS_HPP
#define LAMINATE_TEST_BASE_CHECKPOINT_TEST_HELPERS_HPP

/// @file base_checkpoint_test_helpers.hpp
/// @brief Test-only adapter from a raw noise schedule to the certified API.

#include "laminate/delegation/base/server.hpp"

#include <utility>

namespace laminate::test {

template <fhe::PersistableFheBackend Backend, typename... Remaining>
auto evaluate_base_request_with_schedule(
    const payload::PayloadCircuit &payload,
    const payload::LayeredCircuit &circuit,
    const EvaluationSetup<Backend> &server,
    const delegation::BaseRequest<Backend> &request,
    const payload::HonestPayloadNoiseSchedule &schedule,
    Remaining &&...remaining) {
    const payload::CertifiedHonestPayloadSchedule certified =
        payload::certify_honest_payload_noise_schedule(circuit, schedule);
    return delegation::
        evaluate_base_request<Backend>(
            payload, circuit, server, request, certified,
            std::forward<Remaining>(remaining)...);
}

} // namespace laminate::test

#endif // LAMINATE_TEST_BASE_CHECKPOINT_TEST_HELPERS_HPP
