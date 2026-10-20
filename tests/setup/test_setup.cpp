#include "test_helpers.hpp"
#include "laminate/basefold/foldable_query_policy.hpp"
#include "packed_setup_fixture.hpp"

#include "laminate/delegation/base/server/capacity/workspace.hpp"
#include "laminate/delegation/base/statement/digest.hpp"
#include "laminate/delegation/packed/statement.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/gates/canonical_tables.hpp"
#include "laminate/gates/outsourced.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/payload/noise/honest_base_proof_noise.hpp"
#include "laminate/payload/noise/honest_noise_schedule.hpp"
#include "laminate/protocol/folded.hpp"
#include "laminate/protocol/laned.hpp"
#include "laminate/setup.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

namespace {

using laminate::Fp;
using laminate::Fq;
using laminate::Fq2;
using laminate::GateMleProfile;
using laminate::PublicSetup;
using laminate::fhe::MockBackend;
using laminate::fhe::MockParameters;
using laminate::fhe::HonestNoiseEnvelopeParameters;
using laminate::fhe::NaturalMagnitude;
using laminate::payload::LayeredCircuit;
using laminate::payload::PayloadBuilder;
using laminate::payload::PayloadCircuit;
using laminate::payload::PayloadShape;
using laminate::payload::HonestPayloadNoiseCalibration;
using laminate::payload::HonestPayloadNoiseSchedule;

template <typename Setup>
concept RetainsTranscriptPackingProverKey = requires(const Setup &setup) {
    setup.transcript_packing.spartan.prover_key;
};

static_assert(RetainsTranscriptPackingProverKey<
              laminate::protocol::FoldedSetup>);
static_assert(!RetainsTranscriptPackingProverKey<
              laminate::protocol::FoldedVerifierSetup>);
static_assert(RetainsTranscriptPackingProverKey<
              laminate::protocol::LanedSetup>);
static_assert(!RetainsTranscriptPackingProverKey<
              laminate::protocol::LanedVerifierSetup>);
static_assert(laminate::fhe::PublicVerifierFheBackend<MockBackend>);
static_assert(!std::is_convertible_v<
              laminate::PackedClientSetup<MockBackend>,
              laminate::EvaluationSetup<MockBackend>>);

template <typename Setup>
concept ExposesEvaluationContext = requires(const Setup &setup) {
    setup.eval_context();
};

static_assert(!ExposesEvaluationContext<
              laminate::PackedClientSetup<MockBackend>>);

bool throws_invalid_argument(const auto &body) {
    try {
        body();
    } catch (const std::invalid_argument &) {
        return true;
    }
    return false;
}

bool throws_logic_error(const auto &body) {
    try {
        body();
    } catch (const std::logic_error &) {
        return true;
    }
    return false;
}

bool throws_overflow_error(const auto &body) {
    try {
        body();
    } catch (const std::overflow_error &) {
        return true;
    }
    return false;
}

class TemporaryDirectory {
  public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            path_ = std::filesystem::temp_directory_path() /
                    ("laminate-packing-setup-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(path_)) {
                return;
            }
        }
        throw std::runtime_error("failed to create temporary directory");
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
};

laminate::protocol::TranscriptPackingPreprocessingOptions
artifact_preprocessing(const std::filesystem::path &directory) {
    return {
        .factored_tensor_artifact =
            laminate::spartan::FactoredMatrixArtifactOptions{
                .directory = directory,
                .limits = {
                    .max_total_bytes = 1ULL << 28U,
                    .min_free_bytes = 1,
                },
            },
    };
}

std::vector<Fq2> matrix_point(std::size_t variables,
                              std::uint64_t seed) {
    std::vector<Fq2> result;
    result.reserve(variables);
    for (std::size_t bit = 0; bit < variables; ++bit) {
        result.push_back(Fq2::from_base(Fq(seed + 2U * bit + 1U)));
    }
    return result;
}

PayloadCircuit make_payload(std::size_t rotation = 3) {
    PayloadBuilder builder(PayloadShape::wide(8), 2);
    const auto sum = builder.add(0, 1);
    const auto rotated = builder.rotate(sum, rotation);
    const auto output = builder.mul(sum, rotated);
    builder.set_outputs({output});
    return builder.finish();
}

PayloadCircuit make_propagated_public_zero_payload() {
    PayloadBuilder builder(PayloadShape::wide(8), 3);
    const std::size_t zero = builder.add_scalar_plaintext(Fp::zero());
    const auto z = builder.mul_plain(0, zero);
    const auto p = builder.mul(z, 1);
    builder.set_outputs({builder.mul(p, 2)});
    return builder.finish();
}

std::vector<std::uint64_t> honest_payload_chain() {
    return {
        laminate::kOuterFieldOrder,
        1'152'921'497'895'862'273ULL,
        53'687'910'401ULL,
        96'638'238'721ULL,
        98'785'755'137ULL,
    };
}

HonestPayloadNoiseCalibration honest_payload_calibration(
    std::size_t ctct_debit_bits = 40) {
    return HonestPayloadNoiseCalibration{
        .fresh_canonical_error_bound = 64,
        .ctct_relinearized_debit_bits = ctct_debit_bits,
        .plaintext_multiplication_debit_bits = 3,
        .rotation_debit_bits = 2,
        .maximum_switch_tax_bits = 10,
        .switch_rounding_error_bound = 649,
        .modeled_switch_events_upper_bound = 1'000,
        .switch_model_failure_budget_bits = 40,
        .proof_suffix_level_reserve = 2,
    };
}

HonestNoiseEnvelopeParameters honest_proof_noise_parameters(
    const LayeredCircuit &layered,
    const HonestPayloadNoiseSchedule &schedule) {
    const laminate::payload::HonestBaseProofNoiseCalibration calibration{
        .ctct_relinearized_debit_bits =
            schedule.calibration.ctct_relinearized_debit_bits,
        .plaintext_multiplication_debit_bits =
            schedule.calibration.plaintext_multiplication_debit_bits,
        .rotation_debit_bits =
            schedule.calibration.rotation_debit_bits,
    };
    return laminate::payload::derive_honest_base_proof_noise_parameters(
        layered, schedule, calibration);
}

laminate::payload::HonestBaseProofNoiseCalibration
honest_proof_noise_calibration() {
    const HonestPayloadNoiseCalibration payload =
        honest_payload_calibration();
    return {
        .ctct_relinearized_debit_bits =
            payload.ctct_relinearized_debit_bits,
        .plaintext_multiplication_debit_bits =
            payload.plaintext_multiplication_debit_bits,
        .rotation_debit_bits = payload.rotation_debit_bits,
    };
}

void test_canonical_encoding_and_digest_sensitivity() {
    const PayloadCircuit first = make_payload();
    const PayloadCircuit same = make_payload();
    const PayloadCircuit different = make_payload(4);
    const LayeredCircuit first_layered = laminate::payload::compile(first);
    const LayeredCircuit same_layered = laminate::payload::compile(same);
    const LayeredCircuit different_layered =
        laminate::payload::compile(different);

    CHECK(laminate::payload::encode_canonical(first) ==
          laminate::payload::encode_canonical(same));
    CHECK(laminate::payload::encode_canonical(first_layered) ==
          laminate::payload::encode_canonical(same_layered));
    CHECK(laminate::payload::combined_digest(first, first_layered) ==
          laminate::payload::combined_digest(same, same_layered));
    CHECK(laminate::payload::combined_digest(first, first_layered) !=
          laminate::payload::combined_digest(different,
                                              different_layered));
    const laminate::payload::CircuitPairDigests digests =
        laminate::payload::circuit_pair_digests(first, first_layered);
    CHECK(digests.payload == laminate::payload::digest(first));
    CHECK(digests.layered == laminate::payload::digest(first_layered));
    CHECK(digests.combined ==
          laminate::payload::combined_digest(first, first_layered));
}

void test_direct_and_dummy_profiles() {
    const PayloadCircuit payload = make_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const PublicSetup direct = laminate::make_direct_setup(payload, layered);
    const PublicSetup dummy =
        laminate::make_dummy_committed_setup(payload, layered);

    CHECK(direct.gate_mle_profile == GateMleProfile::Direct);
    CHECK(direct.dummy_gate_commitments.empty());
    CHECK(dummy.gate_mle_profile ==
          GateMleProfile::DummyCommittedDirect);
    CHECK(dummy.dummy_gate_commitments.size() + 1 == layered.layers.size());
    CHECK(dummy.circuit_digest == direct.circuit_digest);
    for (std::size_t layer = 0; layer < dummy.dummy_gate_commitments.size();
         ++layer) {
        CHECK(dummy.dummy_gate_commitments[layer].layer_index == layer);
        if (layer > 0) {
            CHECK(dummy.dummy_gate_commitments[layer].value !=
                  dummy.dummy_gate_commitments[layer - 1].value);
        }
    }
    direct.validate(payload, layered);
    dummy.validate(payload, layered);
}

void test_packed_client_setup_is_role_separated_and_identity_bound() {
    const PayloadCircuit payload = make_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const PublicSetup public_setup =
        laminate::make_direct_setup(payload, layered);
    auto contexts = MockBackend::create(MockParameters{
        .slot_count = public_setup.shape.slot_count,
        .fresh_rns_limbs = 8,
        .bits_per_limb = 53,
    });
    const auto client = laminate::make_client_setup<MockBackend>(
        public_setup, contexts.client);
    const auto verifier = MockBackend::make_public_verifier_context(
        contexts.eval);
    const auto packed =
        laminate::make_packed_client_setup_from_verifier_context<
            MockBackend>(client, verifier);
    CHECK(&packed.public_setup() ==
          &packed.client_setup().public_setup);
    CHECK(MockBackend::slot_count(packed.client_context()) ==
          public_setup.shape.slot_count);
    CHECK(MockBackend::slot_count(packed.verifier_context()) ==
          public_setup.shape.slot_count);
    CHECK(MockBackend::storage_context_id(packed.client_context()) ==
          MockBackend::storage_context_id(packed.verifier_context()));

    auto different = MockBackend::create(MockParameters{
        .slot_count = public_setup.shape.slot_count,
        .fresh_rns_limbs = 8,
        .bits_per_limb = 54,
    });
    CHECK(throws_invalid_argument([&] {
        (void)laminate::make_packed_client_setup_from_verifier_context<
            MockBackend>(client,
                         MockBackend::make_public_verifier_context(
                             different.eval));
    }));
}

void test_setup_mutations_reject() {
    const PayloadCircuit payload = make_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    PublicSetup setup =
        laminate::make_dummy_committed_setup(payload, layered);
    setup.dummy_gate_commitments[0].value[0] ^= 1;
    CHECK(throws_invalid_argument([&] { setup.validate(payload, layered); }));

    setup = laminate::make_dummy_committed_setup(payload, layered);
    setup.plaintext_modulus = 17;
    CHECK(throws_invalid_argument([&] { setup.validate(payload, layered); }));
}

void test_gkr_challenge_dimension_admission() {
    // Admission is checked before transcript mutation and before a caller
    // could allocate the exponentially large output domain.
    const auto check_point_sampler = [](const auto &sample) {
        laminate::Transcript transcript("gkr-dimension-admission");
        laminate::Transcript unchanged = transcript;
        CHECK(throws_invalid_argument([&] { (void)sample(transcript, 65); }));
        CHECK(transcript.challenge_fpk() == unchanged.challenge_fpk());
        CHECK(sample(transcript, 64).size() == 64);
    };
    const laminate::Digest statement{};
    check_point_sampler([&](laminate::Transcript &transcript, std::size_t n) {
        return laminate::delegation::derive_base_output_point(
            transcript, statement, n);
    });
    for (const auto variant : {
             laminate::delegation::PackedProtocolVariant::Folded,
             laminate::delegation::PackedProtocolVariant::Laned}) {
        check_point_sampler([&](laminate::Transcript &transcript,
                               std::size_t n) {
            return laminate::delegation::derive_packed_output_point(
                transcript, variant, statement, n);
        });
    }

    if constexpr (std::numeric_limits<std::size_t>::digits >= 64) {
        const auto rejected_dimension = [](const auto &body) {
            try {
                body();
            } catch (const std::invalid_argument &error) {
                return std::string(error.what()).find("64 coordinates") !=
                       std::string::npos;
            }
            return false;
        };
        for (const auto kind : {laminate::payload::PayloadKind::Wide,
                                laminate::payload::PayloadKind::Laned}) {
            const auto circuit_at = [&](std::size_t slot_bits) {
                const std::size_t slots = std::size_t{1} << slot_bits;
                PayloadCircuit payload;
                payload.shape = kind == laminate::payload::PayloadKind::Wide
                    ? PayloadShape::wide(slots)
                    : PayloadShape::laned(slots, slots);
                payload.input_count = 4;
                payload.outputs = {0, 1, 2, 3};
                return payload;
            };
            const PayloadCircuit admitted_payload = circuit_at(62);
            const LayeredCircuit admitted =
                laminate::payload::compile(admitted_payload);
            const PublicSetup setup =
                laminate::make_direct_setup(admitted_payload, admitted);
            setup.validate(admitted_payload, admitted);

            const PayloadCircuit rejected_payload = circuit_at(63);
            const LayeredCircuit rejected =
                laminate::payload::compile(rejected_payload);
            CHECK(rejected_dimension([&] {
                (void)laminate::make_direct_setup(rejected_payload, rejected);
            }));
            CHECK(rejected_dimension([&] {
                (void)laminate::make_dummy_committed_setup(
                    rejected_payload, rejected);
            }));
            CHECK(rejected_dimension([&] {
                setup.validate(rejected_payload, rejected);
            }));
            CHECK(rejected_dimension([&] {
                (void)laminate::preprocess_outsourced_gate_mle_setup(
                    rejected_payload, rejected,
                    kind == laminate::payload::PayloadKind::Wide
                        ? laminate::gates::GateTableSet::Wide
                        : laminate::gates::GateTableSet::Laned);
            }));
        }
    }
}

void test_honest_payload_schedule_binding() {
    const PayloadCircuit payload = make_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const HonestPayloadNoiseSchedule schedule =
        laminate::payload::derive_honest_payload_noise_schedule(
            layered, honest_payload_chain(),
            honest_payload_calibration());
    const auto certified =
        laminate::payload::certify_honest_payload_noise_schedule(
            layered, schedule);
    CHECK(schedule.payload_model_accepts());

    const PublicSetup unbound =
        laminate::make_direct_setup(payload, layered);
    CHECK(!unbound.honest_payload_noise_schedule_digest.has_value());
    CHECK(!unbound.honest_base_proof_noise_assessment_digest.has_value());
    CHECK(throws_invalid_argument([&] {
        unbound.validate_certified_payload_schedule(
            payload, layered, certified);
    }));

    const PublicSetup bound =
        laminate::bind_honest_payload_noise_schedule(
            unbound, payload, layered, schedule);
    CHECK(bound.honest_payload_noise_schedule_digest.has_value());
    CHECK(*bound.honest_payload_noise_schedule_digest ==
          laminate::payload::honest_payload_noise_schedule_digest(
              layered, schedule));
    CHECK(!bound.honest_base_proof_noise_assessment_digest.has_value());
    CHECK(laminate::setup_digest(bound) !=
          laminate::setup_digest(unbound));
    bound.validate_certified_payload_schedule(
        payload, layered, certified);

    PublicSetup altered_binding = bound;
    (*altered_binding.honest_payload_noise_schedule_digest)[0] ^= 1U;
    CHECK(throws_invalid_argument([&] {
        altered_binding.validate_certified_payload_schedule(
            payload, layered, certified);
    }));

    HonestPayloadNoiseSchedule altered_schedule = schedule;
    ++altered_schedule.layers_in_evaluation_order.front()
          .output_rns_limb_count;
    CHECK(throws_invalid_argument([&] {
        (void)laminate::bind_honest_payload_noise_schedule(
            unbound, payload, layered, altered_schedule);
    }));

    const HonestPayloadNoiseSchedule unaccepted =
        laminate::payload::derive_honest_payload_noise_schedule(
            layered, honest_payload_chain(),
            honest_payload_calibration(400));
    CHECK(!unaccepted.payload_model_accepts());
    CHECK(throws_invalid_argument([&] {
        (void)laminate::bind_honest_payload_noise_schedule(
            unbound, payload, layered, unaccepted);
    }));

    const HonestPayloadNoiseSchedule assessed =
        laminate::payload::attach_honest_base_proof_noise_assessment(
            layered, schedule,
            honest_proof_noise_parameters(layered, schedule));
    CHECK(throws_invalid_argument([&] {
        (void)laminate::bind_honest_payload_noise_schedule(
            unbound, payload, layered, assessed);
    }));
}

void test_honest_base_proof_noise_setup_binding() {
    const PayloadCircuit payload = make_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    std::vector<
        laminate::payload::HonestBaseProofIngressSelectionProgress>
        selection_progress;
    const auto certified =
        laminate::payload::select_certified_honest_base_proof_ingress(
            layered, honest_payload_chain(), honest_payload_calibration(),
            honest_proof_noise_calibration(), nullptr,
            [&](const auto &progress) {
                selection_progress.push_back(progress);
            });
    CHECK(!selection_progress.empty());
    CHECK(selection_progress.front().stage ==
          laminate::payload::HonestBaseProofIngressSelectionStage::
              ReserveCandidate);
    CHECK(std::ranges::any_of(
        selection_progress, [](const auto &progress) {
            return progress.stage ==
                   laminate::payload::
                       HonestBaseProofIngressSelectionStage::LimbProbe;
        }));
    CHECK(selection_progress.back().stage ==
          laminate::payload::HonestBaseProofIngressSelectionStage::
              FinalAssessment);
    for (const auto &progress : selection_progress) {
        CHECK(progress.reserve < progress.reserve_count);
        if (progress.stage ==
            laminate::payload::HonestBaseProofIngressSelectionStage::
                LimbProbe) {
            CHECK(progress.reduction < progress.reduction_count);
            CHECK(progress.candidate_limbs > 0);
            CHECK(progress.candidate_limbs <= progress.maximum_limbs);
        }
    }
    const HonestPayloadNoiseSchedule &assessed = certified.schedule();
    const auto without_progress =
        laminate::payload::select_certified_honest_base_proof_ingress(
            layered, honest_payload_chain(), honest_payload_calibration(),
            honest_proof_noise_calibration());
    const auto throwing_progress =
        laminate::payload::select_certified_honest_base_proof_ingress(
            layered, honest_payload_chain(), honest_payload_calibration(),
            honest_proof_noise_calibration(), nullptr,
            [](const auto &) {
                throw std::runtime_error("diagnostic callback failure");
            });
    CHECK(laminate::payload::honest_payload_noise_schedule_digest(
              layered, without_progress.schedule()) ==
          laminate::payload::honest_payload_noise_schedule_digest(
              layered, assessed));
    CHECK(laminate::payload::honest_payload_noise_schedule_digest(
              layered, throwing_progress.schedule()) ==
          laminate::payload::honest_payload_noise_schedule_digest(
              layered, assessed));
    CHECK(laminate::payload::honest_base_proof_noise_assessment_digest(
              *without_progress.schedule().base_proof_noise_assessment) ==
          laminate::payload::honest_base_proof_noise_assessment_digest(
              *assessed.base_proof_noise_assessment));
    CHECK(laminate::payload::honest_base_proof_noise_assessment_digest(
              *throwing_progress.schedule().base_proof_noise_assessment) ==
          laminate::payload::honest_base_proof_noise_assessment_digest(
              *assessed.base_proof_noise_assessment));
    HonestPayloadNoiseSchedule core = assessed;
    core.base_proof_noise_assessment.reset();
    const auto certified_assessed =
        laminate::payload::certify_honest_payload_noise_schedule(
            layered, assessed);
    const HonestNoiseEnvelopeParameters parameters =
        honest_proof_noise_parameters(layered, core);
    CHECK(assessed.base_proof_noise_assessment.has_value());
    CHECK(laminate::payload::honest_payload_noise_schedule_digest(
              layered, core) ==
          laminate::payload::honest_payload_noise_schedule_digest(
              layered, assessed));
    CHECK(laminate::payload::honest_base_end_to_end_model_accepts(
        layered, assessed, parameters));
    CHECK(laminate::payload::honest_base_proof_ingress_is_minimal(
        layered, assessed, parameters));

    const PublicSetup unbound =
        laminate::make_direct_setup(payload, layered);
    const PublicSetup payload_bound =
        laminate::bind_honest_payload_noise_schedule(
            unbound, payload, layered, core);
    const PublicSetup bound =
        laminate::bind_honest_base_proof_noise_assessment(
            unbound, payload, layered, assessed, parameters);
    const PublicSetup certified_bound =
        laminate::bind_certified_honest_base_proof_noise_assessment(
            unbound, payload, layered, certified);
    CHECK(laminate::setup_digest(certified_bound) ==
          laminate::setup_digest(bound));
    CHECK(bound.honest_payload_noise_schedule_digest.has_value());
    CHECK(bound.honest_base_proof_noise_assessment_digest.has_value());
    CHECK(*bound.honest_payload_noise_schedule_digest ==
          laminate::payload::honest_payload_noise_schedule_digest(
              layered, core));
    CHECK(*bound.honest_base_proof_noise_assessment_digest ==
          laminate::payload::honest_base_proof_noise_assessment_digest(
              *assessed.base_proof_noise_assessment));
    CHECK(laminate::setup_digest(bound) !=
          laminate::setup_digest(unbound));
    CHECK(laminate::setup_digest(bound) !=
          laminate::setup_digest(payload_bound));
    bound.validate_certified_payload_schedule(
        payload, layered, certified_assessed);

    const HonestPayloadNoiseSchedule overprovisioned_core =
        laminate::payload::derive_honest_payload_noise_schedule(
            layered, honest_payload_chain(), honest_payload_calibration());
    const HonestNoiseEnvelopeParameters overprovisioned_parameters =
        honest_proof_noise_parameters(layered, overprovisioned_core);
    const HonestPayloadNoiseSchedule overprovisioned =
        laminate::payload::attach_honest_base_proof_noise_assessment(
            layered, overprovisioned_core, overprovisioned_parameters);
    CHECK(laminate::payload::honest_base_end_to_end_model_accepts(
        layered, overprovisioned, overprovisioned_parameters));
    CHECK(!laminate::payload::honest_base_proof_ingress_is_minimal(
        layered, overprovisioned, overprovisioned_parameters));
    CHECK(throws_invalid_argument([&] {
        (void)laminate::bind_honest_base_proof_noise_assessment(
            unbound, payload, layered, overprovisioned,
            overprovisioned_parameters);
    }));

    HonestPayloadNoiseSchedule enlarged_vector_core = assessed;
    enlarged_vector_core.base_proof_noise_assessment.reset();
    std::vector<std::size_t> enlarged_vector =
        enlarged_vector_core.evaluation_plan
            .proof_ingress_mult_depth_by_layer;
    std::size_t enlarged_layer = layered.layers.size();
    for (std::size_t layer = 1; layer < layered.layers.size(); ++layer) {
        if (enlarged_vector[layer] <
            enlarged_vector_core.evaluation_plan.trace
                .required_mult_depth_by_layer[layer]) {
            ++enlarged_vector[layer];
            enlarged_layer = layer;
            break;
        }
    }
    CHECK(enlarged_layer < layered.layers.size());
    enlarged_vector_core =
        laminate::payload::apply_honest_base_proof_ingress_depths(
            layered, std::move(enlarged_vector_core), enlarged_vector);
    CHECK(laminate::payload::honest_payload_noise_schedule_digest(
              layered, enlarged_vector_core) !=
          laminate::payload::honest_payload_noise_schedule_digest(
              layered, core));
    const HonestNoiseEnvelopeParameters enlarged_vector_parameters =
        honest_proof_noise_parameters(layered, enlarged_vector_core);
    const HonestPayloadNoiseSchedule enlarged_vector_assessed =
        laminate::payload::attach_honest_base_proof_noise_assessment(
            layered, enlarged_vector_core, enlarged_vector_parameters);
    CHECK(laminate::payload::honest_base_end_to_end_model_accepts(
        layered, enlarged_vector_assessed, enlarged_vector_parameters));
    CHECK(!laminate::payload::honest_base_proof_ingress_is_minimal(
        layered, enlarged_vector_assessed, enlarged_vector_parameters));
    CHECK(throws_invalid_argument([&] {
        (void)laminate::bind_honest_base_proof_noise_assessment(
            unbound, payload, layered, enlarged_vector_assessed,
            enlarged_vector_parameters);
    }));

    HonestNoiseEnvelopeParameters altered_parameters = parameters;
    ++altered_parameters.rotation_debit_bits;
    CHECK(throws_invalid_argument([&] {
        (void)laminate::bind_honest_base_proof_noise_assessment(
            unbound, payload, layered, assessed, altered_parameters);
    }));

    HonestPayloadNoiseSchedule altered_report = assessed;
    auto &maximum = altered_report.base_proof_noise_assessment
                        ->reductions.front()
                        .families.front()
                        .maximum_pre_normalization_canonical_error_bound;
    maximum = NaturalMagnitude::add(maximum, NaturalMagnitude(1));
    CHECK(throws_invalid_argument([&] {
        (void)laminate::bind_honest_base_proof_noise_assessment(
            unbound, payload, layered, altered_report, parameters);
    }));

    PublicSetup altered_binding = bound;
    (*altered_binding.honest_base_proof_noise_assessment_digest)[0] ^= 1U;
    CHECK(laminate::setup_digest(altered_binding) !=
          laminate::setup_digest(bound));
    CHECK(throws_invalid_argument([&] {
        altered_binding.validate_certified_payload_schedule(
            payload, layered, certified_assessed);
    }));

    PublicSetup missing_binding = bound;
    missing_binding.honest_base_proof_noise_assessment_digest.reset();
    CHECK(throws_invalid_argument([&] {
        missing_binding.validate_certified_payload_schedule(
            payload, layered, certified_assessed);
    }));

    CHECK(throws_invalid_argument([&] {
        bound.validate_certified_payload_schedule(
            payload, layered,
            laminate::payload::certify_honest_payload_noise_schedule(
                layered, altered_report));
    }));
    CHECK(throws_invalid_argument([&] {
        bound.validate_certified_payload_schedule(
            payload, layered,
            laminate::payload::certify_honest_payload_noise_schedule(
                layered, core));
    }));
}

void test_public_only_base_proof_setup_binding() {
    const PayloadCircuit payload = make_propagated_public_zero_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const HonestPayloadNoiseSchedule core =
        laminate::payload::derive_honest_payload_noise_schedule(
            layered, honest_payload_chain(),
            honest_payload_calibration());
    const HonestNoiseEnvelopeParameters parameters =
        honest_proof_noise_parameters(layered, core);
    const HonestPayloadNoiseSchedule assessed =
        laminate::payload::attach_honest_base_proof_noise_assessment(
            layered, core, parameters);
    CHECK(assessed.base_proof_noise_assessment.has_value());
    CHECK(assessed.base_proof_noise_assessment->observed_switch_events <
          assessed.modeled_base_proof_switch_events);

    PublicSetup bound =
        laminate::make_direct_setup(payload, layered);
    bound.honest_payload_noise_schedule_digest =
        laminate::payload::honest_payload_noise_schedule_digest(
            layered, assessed);
    bound.honest_base_proof_noise_assessment_digest =
        laminate::payload::honest_base_proof_noise_assessment_digest(
            *assessed.base_proof_noise_assessment);
    bound.validate_certified_payload_schedule(
        payload, layered,
        laminate::payload::certify_honest_payload_noise_schedule(
            layered, assessed));
}

void test_noncanonical_compilation_rejects() {
    const PayloadCircuit payload = make_payload();
    LayeredCircuit layered = laminate::payload::compile(payload);
    auto &output = std::get<laminate::payload::AffineLayer>(layered.layers[0]);
    output.gates[0].terms[0].coefficient *= Fp(2);
    layered.validate();
    CHECK(throws_invalid_argument(
        [&] { (void)laminate::make_direct_setup(payload, layered); }));
}

void test_role_separated_fhe_setup() {
    const PayloadCircuit payload = make_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    const PublicSetup public_setup =
        laminate::make_dummy_committed_setup(payload, layered);
    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
    auto evaluation = laminate::make_evaluation_setup<MockBackend>(
        public_setup, contexts.eval);
    auto client = laminate::make_client_setup<MockBackend>(
        public_setup, contexts.client);

    const auto ciphertext =
        MockBackend::encrypt(client.context, {Fp(2), Fp(3)});
    const auto doubled =
        MockBackend::add(evaluation.context, ciphertext, ciphertext);
    CHECK(MockBackend::decrypt(client.context, doubled)[0] == Fp(4));
    CHECK(evaluation.public_setup.circuit_digest ==
          client.public_setup.circuit_digest);

    auto wrong_contexts =
        MockBackend::create(MockParameters{.slot_count = 16});
    CHECK(throws_invalid_argument([&] {
        (void)laminate::make_evaluation_setup<MockBackend>(
            public_setup, wrong_contexts.eval);
    }));
    CHECK(throws_invalid_argument([&] {
        (void)laminate::make_client_setup<MockBackend>(
            public_setup, wrong_contexts.client);
    }));
}

void test_outsourced_gate_setup() {
    const PayloadCircuit payload = make_payload();
    const LayeredCircuit layered = laminate::payload::compile(payload);
    auto prover_key =
        std::make_shared<laminate::gates::GateTableProverKey>(
            laminate::gates::preprocess_gate_tables(
                layered, laminate::gates::GateTableSet::Wide));
    const PublicSetup public_setup = laminate::make_outsourced_gate_setup(
        payload, layered, prover_key->verifier);
    CHECK(public_setup.gate_mle_profile ==
          GateMleProfile::OutsourcedBaseFold);
    CHECK(public_setup.outsourced_gate_mle.has_value());
    CHECK(public_setup.outsourced_gate_mle->basefold_parameters.log_rate ==
          3U);
    CHECK(public_setup.outsourced_gate_mle->basefold_parameters.num_queries ==
          laminate::kGateMleBaseFoldQueries);
    public_setup.validate(payload, layered);

    auto contexts = MockBackend::create(MockParameters{.slot_count = 8});
    const auto evaluation = laminate::make_evaluation_setup<MockBackend>(
        public_setup, contexts.eval, prover_key);
    CHECK(evaluation.gate_mle_prover_key == prover_key);
    const auto client = laminate::make_client_setup<MockBackend>(
        public_setup, contexts.client);
    CHECK(client.public_setup.outsourced_gate_mle ==
          public_setup.outsourced_gate_mle);

    PublicSetup bad = public_setup;
    bad.outsourced_gate_mle->layout_digest[0] ^= 1U;
    CHECK(throws_invalid_argument([&] { bad.validate(payload, layered); }));

    // Setup binds the rate and query count and rejects a weaker RBR policy.
    bad = public_setup;
    bad.outsourced_gate_mle->basefold_parameters.log_rate = 2;
    CHECK(laminate::setup_digest(bad) != laminate::setup_digest(public_setup));
    CHECK(throws_invalid_argument([&] { bad.validate(payload, layered); }));

    bad = public_setup;
    bad.outsourced_gate_mle->foldable_parameters.num_queries =
        laminate::basefold::foldable::minimum_queries(
            bad.outsourced_gate_mle->wide_public_commitment->m) - 1;
    CHECK(laminate::setup_digest(bad) != laminate::setup_digest(public_setup));
    CHECK(throws_invalid_argument([&] { bad.validate(payload, layered); }));

    bad = public_setup;
    ++bad.outsourced_gate_mle->foldable_parameters.num_queries;
    bad.validate(payload, layered);
    CHECK(laminate::setup_digest(bad) != laminate::setup_digest(public_setup));
    CHECK(throws_invalid_argument([&] {
        (void)laminate::make_evaluation_setup<MockBackend>(
            bad, contexts.eval, prover_key);
    }));
    CHECK(throws_invalid_argument([&] {
        (void)laminate::make_evaluation_setup<MockBackend>(
            public_setup, contexts.eval);
    }));

    const laminate::OutsourcedGateMleSetupArtifacts artifacts =
        laminate::preprocess_outsourced_gate_mle_setup(
            payload, layered, laminate::gates::GateTableSet::Wide);
    CHECK(artifacts.public_setup.outsourced_gate_mle ==
          public_setup.outsourced_gate_mle);
    const auto restored = laminate::restore_gate_mle_prover_key(
        layered, artifacts.public_setup);
    CHECK(restored != nullptr);
    CHECK(restored->verifier == artifacts.prover_key->verifier);
    const laminate::GateMleProverResourceBounds resources =
        laminate::gate_mle_prover_resource_bounds(restored->verifier);
    CHECK(resources.retained_prover_key_bytes > 0);
    CHECK(resources.opening_workspace_bytes > 0);
    CHECK(resources.proof_bytes_upper_bound > 0);
    CHECK(resources.retained_prover_key_disk_bytes > 0);
    CHECK(resources.opening_workspace_disk_bytes > 0);
    const auto empty_resources = laminate::gate_mle_prover_resource_bounds(
        laminate::gates::GateTableVerifierKey{});
    const auto empty_proof = laminate::gates::encode_canonical(
        laminate::gates::OutsourcedGateMleProof{});
    CHECK(!empty_proof.empty());
    CHECK(empty_proof.size() <= empty_resources.proof_bytes_upper_bound);
    auto malformed_key = public_setup.outsourced_gate_mle.value();
    malformed_key.tables.front().physical_width = 3;
    CHECK(laminate::gate_mle_basefold_soundness_bits(malformed_key) == 0);
    malformed_key.tables.clear();
    malformed_key.basefold_parameters.log_rate = 2;
    CHECK(laminate::gate_mle_basefold_soundness_bits(malformed_key) == 0);
    malformed_key.basefold_parameters.log_rate = 3;
    malformed_key.basefold_parameters.num_queries = 0;
    CHECK(laminate::gate_mle_basefold_soundness_bits(malformed_key) == 0);
    CHECK(laminate::delegation::base_server_detail::
              minimum_outsourced_gate_opening_ram(*restored) ==
          resources.opening_workspace_bytes);

    laminate::gates::GateTableVerifierKey resource_fixture{
        .layout = laminate::gates::GateTableLayout{
            .table_set = laminate::gates::GateTableSet::Laned,
            .tables = {laminate::gates::GateTableDescriptor{
                .layer_index = 0,
                .kind = laminate::gates::GateTableKind::LanedAffineWire,
                .selector = 0,
                .local_variables = 2,
                .support_size = 1,
            }}},
        .basefold_parameters = {.log_rate = 1, .num_queries = 3},
        .tables = {laminate::gates::SparseTableCommitment{
            .message_size = 1,
            .shard_size = 1,
            .shard_count = 1,
            .logical_width = 4,
            .physical_width = 4,
        }},
    };
    const laminate::GateMleProverResourceBounds fixture_resources =
        laminate::gate_mle_prover_resource_bounds(resource_fixture);
    constexpr std::uint64_t kAllocatorSlack = 256ULL << 20U;
    const std::uint64_t expected_product_and_basefold =
        (1U * 4U * 2U + 1U * 4U + 2U * 2U) * sizeof(laminate::Fpk);
    const std::uint64_t expected_target_and_linearization =
        4U * 2U * 2U * sizeof(laminate::Fpk);
    const std::uint64_t expected_query_leaves =
        3U * 4U * 2U * sizeof(laminate::Fp);
    const std::uint64_t expected_query_paths =
        3U * 2U * 1U * 1U * laminate::basefold::Digest{}.size();
    const std::uint64_t expected_query_objects =
        3U * sizeof(laminate::basefold::QueryOpening);
    const std::uint64_t expected_query_sampling =
        3U * sizeof(std::size_t) + 3U;
    CHECK(fixture_resources.opening_workspace_bytes ==
          kAllocatorSlack + expected_product_and_basefold +
              expected_target_and_linearization + expected_query_leaves +
              expected_query_paths + expected_query_objects +
              expected_query_sampling + fixture_resources.proof_bytes_upper_bound);

    auto more_queries = resource_fixture;
    more_queries.basefold_parameters.num_queries *= 2U;
    const auto larger_resources =
        laminate::gate_mle_prover_resource_bounds(more_queries);
    CHECK(larger_resources.retained_prover_key_bytes ==
          fixture_resources.retained_prover_key_bytes);
    CHECK(larger_resources.proof_bytes_upper_bound >
          fixture_resources.proof_bytes_upper_bound);
    CHECK(larger_resources.opening_workspace_bytes -
              fixture_resources.opening_workspace_bytes >=
          expected_query_leaves + expected_query_paths +
              expected_query_objects + expected_query_sampling);

    // Large interleaved tables need a proof cap above 512 MiB.
    auto large_fixture = resource_fixture;
    large_fixture.basefold_parameters.log_rate = 3U;
    large_fixture.basefold_parameters.num_queries =
        laminate::kGateMleBaseFoldQueries;
    large_fixture.layout.tables.front().local_variables = 26U;
    large_fixture.layout.tables.front().support_size = (1U << 25U) + 1U;
    auto &large_table = large_fixture.tables.front();
    large_table.message_size = 1U << 26U;
    large_table.shard_size = 8192U;
    large_table.shard_count = large_table.message_size / large_table.shard_size;
    large_table.logical_width = 32U;
    large_table.physical_width =
        large_table.shard_count * large_table.logical_width;
    CHECK(laminate::gates::valid_sparse_table_commitment(
        large_fixture.layout.tables.front(), large_table,
        large_fixture.basefold_parameters));
    CHECK(laminate::gate_mle_prover_resource_bounds(large_fixture)
              .proof_bytes_upper_bound > (512ULL << 20U));

    laminate::gates::GateTableVerifierKey overflowing = resource_fixture;
    overflowing.basefold_parameters.num_queries =
        std::numeric_limits<std::size_t>::max();
    CHECK(throws_overflow_error([&] {
        (void)laminate::gate_mle_prover_resource_bounds(overflowing);
    }));
    CHECK(laminate::restore_gate_mle_prover_key(
              layered, laminate::make_direct_setup(payload, layered)) ==
          nullptr);

    PublicSetup mismatched = artifacts.public_setup;
    mismatched.outsourced_gate_mle->tables.front().root.front() ^= 1U;
    CHECK(throws_invalid_argument([&] {
        (void)laminate::restore_gate_mle_prover_key(layered, mismatched);
    }));
}

PayloadCircuit make_packing_setup_payload(PayloadShape shape) {
    PayloadBuilder builder(shape, 2);
    builder.set_outputs({builder.add(0, 1)});
    return builder.finish();
}

void test_gate_preprocessing_plan() {
    const auto unused_parent = std::filesystem::temp_directory_path() /
        ("laminate-gate-plan-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    CHECK(!std::filesystem::exists(unused_parent));
    for (const auto table_set : {laminate::gates::GateTableSet::Wide,
                                  laminate::gates::GateTableSet::Laned}) {
        const auto shape = table_set == laminate::gates::GateTableSet::Wide
            ? PayloadShape::wide(32) : PayloadShape::laned(4, 32);
        const auto payload = make_packing_setup_payload(shape);
        const auto circuit = laminate::payload::compile(payload);
        laminate::gates::GateTableBuildOptions options;
        options.wide_scratch_parent = unused_parent;
        options.wide_max_disk_bytes = std::uint64_t{1} << 30;
        const auto plan = laminate::plan_gate_mle_preprocessing(
            circuit, table_set, options);
        CHECK(!std::filesystem::exists(unused_parent));
        // The actual build uses its ordinary bounded-reference parent, so the
        // planning path must remain absent throughout this comparison.
        options.wide_scratch_parent.clear();
        const auto actual = laminate::gates::preprocess_gate_tables(
            circuit, table_set, options);
        CHECK(plan.layout == actual.verifier.layout);
        CHECK(plan.resources ==
              laminate::gate_mle_prover_resource_bounds(actual.verifier));
        CHECK(plan.basefold_soundness_bits ==
              laminate::gate_mle_basefold_soundness_bits(actual.verifier));
        CHECK(plan.tables.size() == actual.verifier.tables.size());
        for (std::size_t i = 0; i < plan.tables.size(); ++i) {
            const auto &table = actual.verifier.tables[i];
            const laminate::gates::SparseTableShape actual_shape{
                table.message_size, table.shard_size, table.shard_count,
                table.logical_width, table.physical_width};
            CHECK(plan.tables[i] == actual_shape);
        }
        if (actual.verifier.wide_public_commitment) {
            CHECK(plan.wide_public_message_size ==
                  actual.verifier.wide_public_commitment->m);
            CHECK(plan.wide_public_width ==
                  actual.verifier.wide_public_commitment->width);
            CHECK(plan.commitment_peak_disk_bytes ==
                  plan.resources.retained_prover_key_disk_bytes);
            std::size_t sparse_entries = 0;
            for (const auto &table : plan.layout.tables)
                sparse_entries += table.support_size;
            CHECK(plan.commitment_peak_disk_bytes ==
                  laminate::basefold::foldable::commitment_disk_bound(
                      plan.wide_public_message_size, plan.wide_public_width) +
                      4096 + 11 * sparse_entries);
            options.wide_max_disk_bytes = plan.commitment_peak_disk_bytes - 1;
            bool rejected = false;
            try {
                (void)laminate::plan_gate_mle_preprocessing(
                    circuit, table_set, options);
            } catch (const std::length_error &) {
                rejected = true;
            }
            CHECK(rejected);
        } else {
            CHECK(plan.wide_public_message_size == 0);
            CHECK(plan.wide_public_width == 0);
            CHECK(plan.commitment_peak_disk_bytes == 0);
        }
        CHECK(!std::filesystem::exists(unused_parent));
    }

    const auto circuit = laminate::payload::compile(make_payload());
    for (const auto invalid_workers : {std::size_t{0}, std::size_t{257}}) {
        laminate::gates::GateTableBuildOptions options;
        options.wide_scratch_parent = unused_parent;
        options.preprocessing_threads = invalid_workers;
        CHECK(throws_invalid_argument([&] {
            (void)laminate::plan_gate_mle_preprocessing(
                circuit, laminate::gates::GateTableSet::Wide, options);
        }));
    }
    for (const auto invalid_block : {std::size_t{0}, std::size_t{65537}}) {
        laminate::gates::GateTableBuildOptions options;
        options.wide_scratch_parent = unused_parent;
        options.wide_resources.block_elements = invalid_block;
        CHECK(throws_invalid_argument([&] {
            (void)laminate::plan_gate_mle_preprocessing(
                circuit, laminate::gates::GateTableSet::Wide, options);
        }));
    }
    laminate::gates::GateTableBuildOptions invalid_queries;
    invalid_queries.foldable_parameters.num_queries = 0;
    CHECK(throws_invalid_argument([&] {
        (void)laminate::plan_gate_mle_preprocessing(
            circuit, laminate::gates::GateTableSet::Wide, invalid_queries);
    }));
    CHECK(!std::filesystem::exists(unused_parent));

    // Planning handles RS sharding without allocating the column payload.
    const laminate::gates::GateTableDescriptor sharded{
        .local_variables = 26, .support_size = (std::size_t{1} << 25) + 1};
    const auto rs = laminate::gates::plan_sparse_table_shape(
        sharded, laminate::gates::GateTableSet::Laned);
    CHECK(rs.message_size == (std::size_t{1} << 26));
    CHECK(rs.shard_size == 8192);
    CHECK(rs.shard_count == 8192);
    CHECK(rs.logical_width == 32);
    CHECK(rs.physical_width == 262144);
}

void test_protocol_spartan_setup() {
    const PayloadCircuit wide = make_packing_setup_payload(
        PayloadShape::wide(32));
    const LayeredCircuit folded_circuit = laminate::payload::compile(wide);
    auto folded_contexts =
        MockBackend::create(MockParameters{.slot_count = 32});
    const PublicSetup folded_public =
        laminate::make_direct_setup(wide, folded_circuit);
    const laminate::protocol::FoldedSetup folded =
        laminate::protocol::setup_folded_conservative<MockBackend>(
            wide, folded_circuit, folded_public, folded_contexts.eval);
    const auto &folded_packing = folded.transcript_packing;
    CHECK(folded_packing.basefold_parameters.log_rate == 3U);
    CHECK(folded_packing.basefold_parameters.query_count ==
          laminate::kTranscriptPackingBaseFoldQueries);
    CHECK(folded.conservative_proof_ingress_schedule.has_value());
    CHECK(folded.conservative_proof_ingress_schedule->digest() ==
          laminate::protocol::conservative_packed_proof_ingress_schedule_digest(
              laminate::protocol::PackingGkrVariant::Folded,
              folded_public.circuit_digest,
              laminate::setup_digest(folded_public),
              folded.proof_ingress_rns_limbs_by_layer));
    CHECK(folded_packing.variant ==
          laminate::protocol::PackingGkrVariant::Folded);
    CHECK(folded_packing.bhip_round_count ==
          laminate::protocol::folded_bhip_round_count(
              folded_circuit));
    CHECK(folded_packing.alignment_layout.placements.size() ==
          folded_packing.relation_plan.shape.aligned_ciphertexts);
    CHECK(folded_packing.spartan.prover_key.circuit->shape().constraints ==
          folded_packing.r1cs_ledger.matrix_rows);
    CHECK(folded_packing.spartan_options.matrix_evaluation ==
          laminate::spartan::MatrixEvaluationMode::CommittedFactored);
    CHECK(folded_packing.spartan.prover_key.matrix_oracle != nullptr);
    CHECK(folded_packing.spartan.verifier_key.matrix_oracle == nullptr);
    CHECK(folded_packing.spartan.verifier_key.direct_matrix == nullptr);
    CHECK(folded_packing.spartan.prover_key.factored_computation != nullptr);
    CHECK(folded_packing.spartan.verifier_key.factored_computation !=
          nullptr);
    const auto &folded_tensors = folded_packing.spartan.verifier_key
                                      .factored_computation->commitment.tensors;
    CHECK(!folded_tensors.empty());
    for (const auto &tensor : folded_tensors) {
        CHECK(tensor.columns.log_rate == 3U);
        CHECK(tensor.columns.query_count ==
              laminate::kTranscriptPackingBaseFoldQueries);
    }
    CHECK(folded_packing.factored_storage.has_value());
    CHECK(folded_packing.factored_storage->source ==
          laminate::spartan::FactoredTensorColumnSource::Resident);
    CHECK(folded_packing.factored_storage
              ->retained_raw_column_payload_bytes > 0);
    CHECK(folded_packing.factored_storage->artifact_physical_bytes == 0);
    const auto &factored_oracle =
        folded_packing.spartan.prover_key.matrix_oracle;
    const std::vector<Fq2> factored_row_point = matrix_point(
        factored_oracle->row_variables(), 17U);
    const std::vector<Fq2> factored_column_point = matrix_point(
        factored_oracle->column_variables(), 53U);
    CHECK(throws_logic_error([&] {
        (void)factored_oracle->evaluate_matrices(
            factored_row_point, factored_column_point);
    }));
    CHECK(folded_packing.spartan.verifier_key.setup_digest ==
          folded_packing.spartan.prover_key.setup_digest);
    const laminate::protocol::FoldedVerifierSetup folded_verifier =
        laminate::protocol::verifier_setup(folded);
    CHECK(folded_verifier.transcript_packing.variant ==
          folded_packing.variant);
    CHECK(folded_verifier.transcript_packing.alignment_layout ==
          folded_packing.alignment_layout);
    CHECK(folded_verifier.transcript_packing.relation_plan.shape.ring_degree ==
          folded_packing.relation_plan.shape.ring_degree);
    CHECK(folded_verifier.transcript_packing.relation_plan.constraints.total ==
          folded_packing.relation_plan.constraints.total);
    CHECK(folded_verifier.transcript_packing.spartan.setup_digest ==
          folded_packing.spartan.verifier_key.setup_digest);
    CHECK(folded_verifier.transcript_packing.spartan.direct_matrix ==
          nullptr);
    CHECK(folded_verifier.transcript_packing.spartan.matrix_oracle ==
          nullptr);
    CHECK(folded_verifier.transcript_packing.spartan.factored_computation !=
          nullptr);
    laminate::protocol::FoldedSetup noncompact = folded;
    noncompact.transcript_packing.spartan.verifier_key.options
        .matrix_evaluation = laminate::spartan::MatrixEvaluationMode::Direct;
    CHECK(throws_invalid_argument([&] {
        (void)laminate::protocol::verifier_setup(noncompact);
    }));

    const PayloadCircuit laned = make_packing_setup_payload(
        PayloadShape::laned(4, 32));
    const LayeredCircuit laned_circuit = laminate::payload::compile(laned);
    auto laned_contexts =
        MockBackend::create(MockParameters{.slot_count = 32});
    const PublicSetup laned_public =
        laminate::make_direct_setup(laned, laned_circuit);
    const laminate::protocol::LanedSetup laned_setup =
        laminate::protocol::setup_laned_conservative<MockBackend>(
            laned, laned_circuit, laned_public, laned_contexts.eval);
    const auto &laned_packing = laned_setup.transcript_packing;
    CHECK(laned_packing.basefold_parameters.log_rate == 3U);
    CHECK(laned_packing.basefold_parameters.query_count ==
          laminate::kTranscriptPackingBaseFoldQueries);
    for (const auto &tensor : laned_packing.spartan.verifier_key
                                  .factored_computation->commitment.tensors) {
        CHECK(tensor.columns.log_rate == 3U);
        CHECK(tensor.columns.query_count ==
              laminate::kTranscriptPackingBaseFoldQueries);
    }
    CHECK(laned_setup.conservative_proof_ingress_schedule.has_value());
    CHECK(laned_packing.variant ==
          laminate::protocol::PackingGkrVariant::Laned);
    CHECK(laned_packing.bhip_round_count ==
          laminate::protocol::laned_bhip_round_count(
              laned_circuit));
    CHECK(laned_packing.fixed_matrix_statistics.complete);
    CHECK(laned_packing.r1cs_ledger.total_poseidon_constraints > 0);
    CHECK(laned_packing.r1cs_ledger.total_public_inputs ==
          laned_packing.r1cs_ledger.total_logical_inputs);
    CHECK(laned_packing.spartan.prover_key.circuit->digest() ==
          laned_packing.spartan.verifier_key.circuit_metadata.digest());
    CHECK(laned_packing.factored_storage.has_value());
    CHECK(laned_packing.factored_storage->source ==
          laminate::spartan::FactoredTensorColumnSource::Resident);
    const laminate::protocol::LanedVerifierSetup laned_verifier =
        laminate::protocol::verifier_setup(laned_setup);
    CHECK(laned_verifier.transcript_packing.variant ==
          laned_packing.variant);
    CHECK(laned_verifier.transcript_packing.bhip_round_count ==
          laned_packing.bhip_round_count);
    CHECK(laned_verifier.transcript_packing.spartan.setup_digest ==
          laned_packing.spartan.verifier_key.setup_digest);
}

void test_top_level_factored_artifact_setup() {
    const PayloadCircuit wide = make_packing_setup_payload(
        PayloadShape::wide(32));
    const LayeredCircuit folded_circuit = laminate::payload::compile(wide);
    auto folded_contexts =
        MockBackend::create(MockParameters{.slot_count = 32});
    const laminate::protocol::FoldedSetup resident =
        laminate::protocol::make_folded_setup_fixture<MockBackend>(
            folded_circuit, folded_contexts.eval,
            {.log_rate = 1, .query_count = 1});
    TemporaryDirectory folded_directory;
    const laminate::protocol::FoldedSetup folded =
        laminate::protocol::make_folded_setup_fixture<MockBackend>(
            folded_circuit, folded_contexts.eval,
            {.log_rate = 1, .query_count = 1},
            {.matrix_evaluation =
                 laminate::spartan::MatrixEvaluationMode::CommittedFactored},
            artifact_preprocessing(folded_directory.path()));

    const auto &folded_packing = folded.transcript_packing;
    const auto &folded_factored =
        folded_packing.spartan.prover_key.factored_computation;
    CHECK(folded_factored != nullptr);
    CHECK(folded_factored->commitment ==
          resident.transcript_packing.spartan.prover_key
              .factored_computation->commitment);
    CHECK(folded_packing.spartan.prover_key.setup_digest ==
          resident.transcript_packing.spartan.prover_key.setup_digest);
    CHECK(folded_factored->tensor_column_source ==
          laminate::spartan::FactoredTensorColumnSource::Artifact);
    CHECK(folded_factored->tensor_columns_artifact != nullptr);
    for (const auto &tensor : folded_factored->tensors) {
        CHECK(tensor.columns.empty());
    }
    CHECK(folded_packing.factored_storage.has_value());
    CHECK(folded_packing.factored_storage->source ==
          laminate::spartan::FactoredTensorColumnSource::Artifact);
    CHECK(folded_packing.factored_storage
              ->logical_column_payload_bytes > 0);
    CHECK(folded_packing.factored_storage
              ->retained_raw_column_payload_bytes == 0);
    CHECK(folded_packing.factored_storage->artifact_physical_bytes ==
          folded_factored->tensor_columns_artifact->physical_bytes());
    CHECK(folded_packing.factored_storage->artifact_physical_bytes >
          folded_packing.factored_storage
              ->logical_column_payload_bytes);
    const auto reopened =
        laminate::spartan::open_factored_matrix_artifact(
            folded_directory.path(), folded_factored->commitment);
    CHECK(reopened->identity() ==
          folded_factored->tensor_columns_artifact->identity());
    CHECK(reopened->arrays() ==
          folded_factored->tensor_columns_artifact->arrays());

    const PayloadCircuit laned = make_packing_setup_payload(
        PayloadShape::laned(4, 32));
    const LayeredCircuit laned_circuit = laminate::payload::compile(laned);
    auto laned_contexts =
        MockBackend::create(MockParameters{.slot_count = 32});
    TemporaryDirectory laned_directory;
    const laminate::protocol::LanedSetup laned_setup =
        laminate::protocol::make_laned_setup_fixture<MockBackend>(
            laned_circuit, laned_contexts.eval,
            {.log_rate = 1, .query_count = 1},
            {.matrix_evaluation =
                 laminate::spartan::MatrixEvaluationMode::CommittedFactored},
            artifact_preprocessing(laned_directory.path()));
    const auto &laned_factored =
        laned_setup.transcript_packing.spartan.prover_key
            .factored_computation;
    CHECK(laned_factored != nullptr);
    CHECK(laned_factored->tensor_column_source ==
          laminate::spartan::FactoredTensorColumnSource::Artifact);
    CHECK(laned_factored->tensor_columns_artifact->directory() ==
          laned_directory.path());

    TemporaryDirectory rejected_directory;
    CHECK(throws_invalid_argument([&] {
        (void)laminate::protocol::make_folded_setup_fixture<MockBackend>(
            folded_circuit, folded_contexts.eval, {},
            {.matrix_evaluation =
                 laminate::spartan::MatrixEvaluationMode::Direct},
            artifact_preprocessing(rejected_directory.path()));
    }));
    CHECK(std::filesystem::is_empty(rejected_directory.path()));
}

void test_transcript_packing_matrix_retention_modes() {
    const PayloadCircuit wide = make_packing_setup_payload(
        PayloadShape::wide(32));
    const LayeredCircuit circuit = laminate::payload::compile(wide);
    auto contexts = MockBackend::create(MockParameters{.slot_count = 32});

    const laminate::protocol::FoldedSetup direct =
        laminate::protocol::make_folded_setup_fixture<MockBackend>(
            circuit, contexts.eval, {},
            laminate::spartan::Options{
                .matrix_evaluation =
                    laminate::spartan::MatrixEvaluationMode::Direct});
    CHECK(direct.transcript_packing.spartan.prover_key.matrix_oracle ==
          nullptr);
    CHECK(direct.transcript_packing.spartan.verifier_key.direct_matrix !=
          nullptr);
    CHECK(!direct.transcript_packing.factored_storage.has_value());

    const laminate::protocol::FoldedSetup uniform =
        laminate::protocol::make_folded_setup_fixture<MockBackend>(
            circuit, contexts.eval, {},
            laminate::spartan::Options{
                .matrix_evaluation =
                    laminate::spartan::MatrixEvaluationMode::Uniform});
    CHECK(uniform.transcript_packing.spartan.prover_key.matrix_oracle !=
          nullptr);
    CHECK(uniform.transcript_packing.spartan.verifier_key.matrix_oracle !=
          nullptr);
    CHECK(uniform.transcript_packing.spartan.verifier_key.direct_matrix ==
          nullptr);
    CHECK(!uniform.transcript_packing.factored_storage.has_value());

    const auto &direct_matrix =
        direct.transcript_packing.spartan.verifier_key.direct_matrix;
    const auto &uniform_oracle =
        uniform.transcript_packing.spartan.verifier_key.matrix_oracle;
    CHECK(direct_matrix->digest() == uniform_oracle->circuit_digest());
    const std::vector<Fq2> row_point = matrix_point(
        direct_matrix->row_variables(), 17U);
    const std::vector<Fq2> column_point = matrix_point(
        direct_matrix->column_variables(), 53U);
    const auto uniform_values = uniform_oracle->evaluate_matrices(
        row_point, column_point);
    for (std::size_t matrix = 0; matrix < 3; ++matrix) {
        CHECK(uniform_values[matrix] ==
              direct_matrix->evaluate_matrix(
                  static_cast<laminate::spartan::Matrix>(matrix),
                  row_point, column_point));
    }
}

} // namespace

int main() {
    laminate::test::Runner runner("test_setup");
    runner.run("canonical circuit encoding and digest sensitivity",
               test_canonical_encoding_and_digest_sensitivity);
    runner.run("direct and typed dummy setup profiles",
               test_direct_and_dummy_profiles);
    runner.run("setup mutations reject", test_setup_mutations_reject);
    runner.run("GKR challenge blocks enforce the admitted dimensions",
               test_gkr_challenge_dimension_admission);
    runner.run("accepted honest payload schedule is bound into setup",
               test_honest_payload_schedule_binding);
    runner.run("accepted Base proof-noise report is bound separately",
               test_honest_base_proof_noise_setup_binding);
    runner.run("public-only Base work stays below its setup envelope",
               test_public_only_base_proof_setup_binding);
    runner.run("noncanonical compilation rejects",
               test_noncanonical_compilation_rejects);
    runner.run("role-separated FHE setup", test_role_separated_fhe_setup);
    runner.run("packed client setup is key-role separated and identity bound",
               test_packed_client_setup_is_role_separated_and_identity_bound);
    runner.run("deterministic outsourced gate setup",
               test_outsourced_gate_setup);
    runner.run("GateMLE setup plans match committed resources without artifacts",
               test_gate_preprocessing_plan);
    runner.run("Folded and Laned setup compile packing R1CS into Spartan",
               test_protocol_spartan_setup);
    runner.run("transcript packing setup retains only selected matrix state",
               test_transcript_packing_matrix_retention_modes);
    runner.run("top-level factored setup uses caller-owned artifacts",
               test_top_level_factored_artifact_setup);
    return runner.summary();
}
