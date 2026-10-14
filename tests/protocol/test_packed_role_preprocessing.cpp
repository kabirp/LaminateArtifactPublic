/// @file test_packed_role_preprocessing.cpp
/// @brief Persistent packed-role setup lifecycle and authentication tests.

#include "test_helpers.hpp"
#include "packed_setup_fixture.hpp"

#include "laminate/delegation/folded/reference/server.hpp"
#include "laminate/delegation/packed/client.hpp"
#include "laminate/delegation/laned/reference/server.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/protocol/packed/preprocessing/roles.hpp"
#include "laminate/diagnostics/setup_validation.hpp"
#include "laminate/verification_profile.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::delegation;
using namespace laminate::fhe;
using namespace laminate::packing;
using namespace laminate::payload;
using namespace laminate::protocol;

namespace {

template <typename State>
concept ExposesEvaluationContext = requires(const State &state) {
    state.evaluation_context();
};

static_assert(PackedRolePreprocessingBackend<MockBackend>);
static_assert(!ExposesEvaluationContext<
              OpenedPackedClientRoleState<MockBackend>>);
static_assert(!ExposesEvaluationContext<
              AuthenticatedPackedClientOnlineState<MockBackend>>);
static_assert(!ExposesEvaluationContext<CertifiedPackedClientStatic>);
static_assert(!std::is_copy_constructible_v<
              AuthenticatedPackedClientOnlineState<MockBackend>>);
static_assert(std::is_copy_constructible_v<CertifiedPackedClientStatic>);
static_assert(!std::is_default_constructible_v<CertifiedPackedClientStatic>);

template <typename Action> bool rejects(Action &&action) {
    try {
        action();
        return false;
    } catch (const std::exception &) {
        return true;
    }
}

class TemporaryTree {
  public:
    TemporaryTree() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        for (std::size_t attempt = 0; attempt < 100; ++attempt) {
            root_ = std::filesystem::temp_directory_path() /
                    ("laminate-packed-role-setup-" +
                     std::to_string(stamp) + "-" +
                     std::to_string(attempt));
            if (std::filesystem::create_directory(root_)) {
                make_private(root_);
                return;
            }
        }
        throw std::runtime_error("failed to create packed-role test tree");
    }

    ~TemporaryTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    std::filesystem::path make_directory(std::string_view name) const {
        const std::filesystem::path result = root_ / name;
        if (!std::filesystem::create_directory(result)) {
            throw std::runtime_error(
                "failed to create packed-role test directory");
        }
        make_private(result);
        return result;
    }

    static void make_private(const std::filesystem::path &path) {
        std::filesystem::permissions(
            path, std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace);
    }

  private:
    std::filesystem::path root_;
};

struct PublicationPaths {
    std::filesystem::path container;
    std::filesystem::path shared;
    std::filesystem::path server;
    std::filesystem::path client;
    std::filesystem::path work;

    PackedRolePreprocessingDirectories directories() const {
        return {shared, server, client, work};
    }
};

PublicationPaths make_publication_paths(const TemporaryTree &tree,
                                        std::string_view name) {
    PublicationPaths result;
    result.container = tree.make_directory(name);
    for (const auto &selected : std::array{
             std::pair{"shared", &result.shared},
             std::pair{"server", &result.server},
             std::pair{"client", &result.client},
             std::pair{"work", &result.work},
         }) {
        *selected.second = result.container / selected.first;
        if (!std::filesystem::create_directory(*selected.second)) {
            throw std::runtime_error(
                "failed to create packed-role publication root");
        }
        TemporaryTree::make_private(*selected.second);
    }
    return result;
}

PayloadCircuit make_payload(PackingGkrVariant variant) {
    PayloadBuilder builder(
        variant == PackingGkrVariant::Folded
            ? PayloadShape::wide(32)
            : PayloadShape::laned(4, 32),
        2);
    const WireId product = builder.mul(0, 1);
    builder.set_outputs({builder.add(product, 0)});
    return builder.finish();
}

CertifiedPackedWorkloadStatic make_workload(PackingGkrVariant variant) {
    PayloadCircuit payload = make_payload(variant);
    LayeredCircuit circuit = compile(payload);
    PublicSetup setup = make_direct_setup(payload, circuit);
    return certify_packed_workload_static(
        std::move(payload), std::move(circuit), std::move(setup));
}

TranscriptPackingExternalPreprocessingSpecification make_specification(
    PackingGkrVariant variant,
    const CertifiedPackedWorkloadStatic &workload,
    std::size_t repetitions,
    gkr::CiphertextCommitmentPolicy commitment_policy =
        gkr::CiphertextCommitmentPolicy::poseidon_v2()) {
    LazyTernaryParameters parameters =
        selected_lazy_ternary_parameters();
    parameters.repetitions = repetitions;
    return {
        .variant = variant,
        .ciphertext_commitment_policy = commitment_policy,
        .ring_degree = 32,
        .bhip_round_count =
            variant == PackingGkrVariant::Folded
                ? folded_bhip_round_count(workload.circuit())
                : laned_bhip_round_count(workload.circuit()),
        .parameters = parameters,
        .basefold_parameters = {.log_rate = 1, .query_count = 1},
        .staging_block_elements = 7,
        .canonical_copy_block_elements = 7,
        .basefold_block_elements = 7,
    };
}

TranscriptPackingExternalPreprocessingLimits external_limits(
    const TranscriptPackingExternalPreprocessingPlan &plan) {
    TranscriptPackingExternalPreprocessingLimits result{
        .staging_artifact = {
            .max_total_bytes = plan.staging.artifact_physical_bytes,
            .min_free_bytes = 1,
        },
        .max_staging_working_bytes = plan.staging.peak_working_bytes,
        .canonical_tensor_artifact = {
            .max_total_bytes =
                plan.factored.canonical_artifact_physical_bytes,
            .min_free_bytes = 1,
        },
        .max_live_physical_bytes =
            plan.factored.conservative_peak_live_physical_bytes,
        .max_copy_working_field_bytes =
            plan.factored.peak_copy_working_field_bytes,
    };
    for (const auto &tensor : plan.factored.tensors) {
        result.tensors.push_back({
            .max_final_physical_bytes =
                tensor.commitment.final_physical_bytes,
            .max_scratch_physical_bytes =
                tensor.commitment.scratch_peak_physical_bytes,
            .min_free_bytes = 1,
            .max_working_field_bytes =
                tensor.commitment.peak_working_field_bytes,
        });
    }
    return result;
}

PackedRolePreprocessingPublishLimits publication_limits(
    const CertifiedPackedWorkloadStatic &workload,
    const PackedRolePreprocessingPublicationPlan &plan) {
    const std::uint64_t role_bytes = std::max(
        plan.server_role_static_bytes, plan.client_role_static_bytes);
    return {
        .storage = {
            .max_workload_bytes =
                plan.workload_decode_requirements.max_artifact_bytes,
            .max_role_artifact_bytes = role_bytes,
            .max_manifest_bytes = 1ULL << 20U,
            .min_free_bytes = 1,
            .max_artifact_tree_files =
                plan.server_artifacts.file_count,
            .max_artifact_tree_directories =
                plan.server_artifacts.directory_count,
            .max_artifact_tree_depth = 2,
            .max_artifact_tree_relative_path_bytes = 256,
            .max_artifact_tree_file_bytes =
                plan.server_artifacts.serialized_bytes,
            .max_artifact_tree_bytes =
                plan.server_artifacts.serialized_bytes,
            .workload_decode = plan.workload_decode_requirements,
        },
        .role_static = {
            .max_encoded_bytes = role_bytes,
            .max_ingress_layers = workload.circuit().layers.size(),
            .max_factored_tensors =
                plan.transcript_packing.factored.tensors.size(),
            .max_relative_path_bytes = 64,
        },
        .transcript_packing = external_limits(plan.transcript_packing),
    };
}

struct Fixture {
    PackingGkrVariant variant;
    CertifiedPackedWorkloadStatic workload;
    MockBackend::Contexts contexts;
    MockBackend::PublicVerifierContext verifier_context;
    TranscriptPackingExternalPreprocessingSpecification specification;
    PackedRolePreprocessingPublicationPlan plan;

    explicit Fixture(PackingGkrVariant selected,
                     std::size_t repetitions = 2,
                     gkr::CiphertextCommitmentPolicy commitment_policy =
                         gkr::CiphertextCommitmentPolicy::poseidon_v2())
        : variant(selected), workload(make_workload(selected)),
          contexts(MockBackend::create({
              .slot_count = 32,
              .fresh_rns_limbs = 14,
              .bits_per_limb = 300,
          })),
          verifier_context(MockBackend::make_public_verifier_context(
              contexts.client)),
          specification(make_specification(
              selected, workload, repetitions, commitment_policy)),
          plan(plan_packed_role_preprocessing_publication(
              workload, specification,
              MockBackend::storage_context_id(contexts.eval))) {
        MockBackend::preprocess_fixed_message_cells(contexts.eval);
    }
};

PackedRolePreprocessingResult<MockBackend> publish_fixture(
    Fixture &fixture, const PublicationPaths &paths) {
    return publish_packed_role_preprocessing<MockBackend>(
        fixture.workload, fixture.specification, fixture.contexts.eval,
        fixture.contexts.client, fixture.verifier_context,
        paths.directories(),
        publication_limits(fixture.workload, fixture.plan));
}

auto open_fixture_roles(
    Fixture &fixture, const PublicationPaths &paths,
    const Digest &root_storage_identity) {
    const auto opening = packed_role_preprocessing_open_limits(
        publication_limits(fixture.workload, fixture.plan));
    auto server = open_packed_server_role_state<MockBackend>(
        paths.shared, paths.server, root_storage_identity,
        fixture.contexts.eval, opening);
    auto client = open_packed_client_role_state<MockBackend>(
        paths.shared, paths.client, root_storage_identity,
        fixture.contexts.client, fixture.verifier_context, opening);
    return std::pair{std::move(server), std::move(client)};
}

SlotVector sequence(std::size_t count, std::uint64_t seed) {
    SlotVector result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.emplace_back(seed + 3U * index + index * index);
    }
    return result;
}

FoldedClientNonce folded_nonce(std::uint8_t seed) {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(seed + index);
    }
    return make_folded_client_nonce(bytes);
}

LanedClientNonce laned_nonce(std::uint8_t seed) {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>(seed + index);
    }
    return make_laned_client_nonce(bytes);
}

TranscriptPackingSpartanSetup make_resident_packing_setup(
    const Fixture &fixture) {
    return make_transcript_packing_spartan_setup(
        fixture.variant, fixture.specification.ring_degree,
        fixture.specification.bhip_round_count,
        {
            .centered_coefficients =
                [&fixture](const SlotVector &slots) {
                    return MockBackend::
                        encode_centered_plaintext_coefficients(
                            fixture.contexts.eval, slots);
                },
            .native_ntt =
                [&fixture](
                    std::span<const std::int64_t> coefficients) {
                    return MockBackend::
                        encode_lowest_plaintext_ntt_coordinates(
                            fixture.contexts.eval, coefficients);
                },
        },
        fixture.specification.parameters,
        fixture.specification.basefold_parameters,
        spartan::Options{
            .matrix_evaluation =
                spartan::MatrixEvaluationMode::CommittedFactored});
}

PackedProofDecodeLimits proof_decode_limits(std::size_t proof_bytes) {
    return {
        .max_proof_bytes = proof_bytes,
        .max_ciphertexts = 1U << 14U,
        .max_ciphertext_bytes = proof_bytes,
        .max_total_ciphertext_bytes = proof_bytes,
        .max_collection_elements = 1U << 18U,
        .max_total_field_elements = 1U << 22U,
        .max_total_digests = 1U << 20U,
    };
}

void check_same_request(
    const FoldedEvaluationRequest<MockBackend> &left,
    const FoldedEvaluationRequest<MockBackend> &right) {
    CHECK(left.setup_id == right.setup_id);
    CHECK(left.session_id == right.session_id);
    CHECK(left.circuit_id == right.circuit_id);
    CHECK(left.trace_id == right.trace_id);
    CHECK(left.encrypted_inputs.size() == right.encrypted_inputs.size());
    for (std::size_t index = 0; index < left.encrypted_inputs.size();
         ++index) {
        CHECK(left.encrypted_inputs[index].identity ==
              right.encrypted_inputs[index].identity);
    }
}

void check_same_request(
    const LanedEvaluationRequest<MockBackend> &left,
    const LanedEvaluationRequest<MockBackend> &right) {
    CHECK(left.setup_id == right.setup_id);
    CHECK(left.session_id == right.session_id);
    CHECK(left.circuit_id == right.circuit_id);
    CHECK(left.trace_id == right.trace_id);
    CHECK(left.encrypted_inputs.size() == right.encrypted_inputs.size());
    for (std::size_t index = 0; index < left.encrypted_inputs.size();
         ++index) {
        CHECK(left.encrypted_inputs[index].identity ==
              right.encrypted_inputs[index].identity);
    }
}

std::filesystem::path first_regular_file(
    const std::filesystem::path &root) {
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) {
            return entry.path();
        }
    }
    throw std::runtime_error("test artifact tree contains no file");
}

void flip_first_byte(const std::filesystem::path &path) {
    std::fstream file(path, std::ios::in | std::ios::out |
                               std::ios::binary);
    char byte = 0;
    file.read(&byte, 1);
    if (!file) {
        throw std::runtime_error("failed to read tamper target");
    }
    byte ^= 1;
    file.seekp(0);
    file.write(&byte, 1);
    file.close();
    if (!file) {
        throw std::runtime_error("failed to modify tamper target");
    }
}

void check_folded_lifecycle_and_relocation() {
    TemporaryTree tree;
    Fixture fixture(PackingGkrVariant::Folded);
    PublicationPaths paths = make_publication_paths(tree, "published");
    Digest root_identity{};
    PackedRolePreprocessingOpenLimits opening;
    {
        auto result = publish_fixture(fixture, paths);
        root_identity = result.root.storage_identity;
        opening = packed_role_preprocessing_open_limits(
            publication_limits(fixture.workload, fixture.plan));
        auto roles = open_fixture_roles(fixture, paths, root_identity);
        auto &server = roles.first;
        auto &client = roles.second;
        CHECK(std::filesystem::is_empty(paths.work));
        std::vector<std::string> expected_paths{"tensor-columns"};
        for (std::size_t tensor = 0;
             tensor < fixture.plan.transcript_packing.factored.tensors.size();
             ++tensor) {
            expected_paths.push_back(
                packed_server_basefold_state_relative_path(tensor));
        }
        CHECK(server.core().role_static.artifact_relative_paths ==
              expected_paths);
        CHECK(client.core().role_static.artifact_relative_paths.empty());
        CHECK(encode_packed_role_static(
                  client.core().role_static).size() ==
              fixture.plan.client_role_static_bytes);
        CHECK(server.core().publication.role.artifact_tree.file_count ==
              fixture.plan.server_artifacts.file_count);
        CHECK(server.core().publication.role.artifact_tree
                  .directory_count ==
              fixture.plan.server_artifacts.directory_count);
        CHECK(server.core().publication.role.artifact_tree
                  .serialized_bytes ==
              fixture.plan.server_artifacts.serialized_bytes);
        CHECK(client.core().publication.role.artifact_tree.entries.empty());
        CHECK(&server.evaluation_context() == &fixture.contexts.eval);
        CHECK(&client.client_context() == &fixture.contexts.client);
        CHECK(&client.verifier_context() == &fixture.verifier_context);
        CHECK(server.prover_setup().transcript_packing()
                  .spartan_key().setup_digest ==
              client.verifier_setup().spartan.setup_digest);
        auto online =
            make_authenticated_packed_client_online_state<MockBackend>(
                std::move(client), fixture.contexts.client,
                fixture.verifier_context);
        CHECK(online.workload().semantic_identity() ==
              fixture.workload.semantic_identity());
        CHECK(online.verifier_setup().spartan.setup_digest ==
              server.prover_setup().transcript_packing()
                  .spartan_key().setup_digest);
    }

    const std::filesystem::path relocated = paths.container.parent_path() /
                                             "relocated";
    std::filesystem::rename(paths.container, relocated);
    const auto server = open_packed_server_role_state<MockBackend>(
        relocated / "shared", relocated / "server", root_identity,
        fixture.contexts.eval, opening);
    auto client = open_packed_client_role_state<MockBackend>(
        relocated / "shared", relocated / "client", root_identity,
        fixture.contexts.client, fixture.verifier_context, opening);
    CHECK(std::filesystem::equivalent(
        server.core().publication.role.directory,
        relocated / "server"));
    CHECK(std::filesystem::equivalent(
        client.core().publication.role.directory,
        relocated / "client"));
    CHECK(server.prover_setup().transcript_packing()
              .spartan_key().setup_digest ==
          client.verifier_setup().spartan.setup_digest);
    auto online = make_authenticated_packed_client_online_state<MockBackend>(
        std::move(client), fixture.contexts.client,
        fixture.verifier_context);
    CHECK(online.workload().semantic_identity() ==
          fixture.workload.semantic_identity());
}

void check_laned_lifecycle_and_role_context_rejection() {
    TemporaryTree tree;
    Fixture fixture(PackingGkrVariant::Laned);
    const PublicationPaths paths =
        make_publication_paths(tree, "published");
    auto result = publish_fixture(fixture, paths);
    const Digest root_identity = result.root.storage_identity;
    const auto opening = packed_role_preprocessing_open_limits(
        publication_limits(fixture.workload, fixture.plan));
    const auto server = open_packed_server_role_state<MockBackend>(
        paths.shared, paths.server, root_identity, fixture.contexts.eval,
        opening);
    CHECK(server.core().role_static.variant ==
          PackingGkrVariant::Laned);
    CHECK(rejects([&] {
        (void)open_packed_server_role_state<MockBackend>(
            paths.shared, paths.client, root_identity,
            fixture.contexts.eval, opening);
    }));
    CHECK(rejects([&] {
        (void)open_packed_client_role_state<MockBackend>(
            paths.shared, paths.server, root_identity,
            fixture.contexts.client, fixture.verifier_context, opening);
    }));

    auto other = MockBackend::create({
        .slot_count = 32,
        .fresh_rns_limbs = 13,
        .bits_per_limb = 300,
    });
    const auto other_verifier =
        MockBackend::make_public_verifier_context(other.client);
    CHECK(rejects([&] {
        (void)open_packed_server_role_state<MockBackend>(
            paths.shared, paths.server, root_identity, other.eval,
            opening);
    }));
    CHECK(rejects([&] {
        (void)open_packed_client_role_state<MockBackend>(
            paths.shared, paths.client, root_identity, other.client,
            other_verifier, opening);
    }));
}

void check_folded_authenticated_online_path_has_no_static_rescan() {
    Fixture fixture(PackingGkrVariant::Folded, 1);
    FoldedSetup packing_setup{
        make_resident_packing_setup(fixture),
        std::vector<std::size_t>(
            fixture.workload.circuit().layers.size(),
            kFoldedFixtureProofIngressRnsLimbs)};
    CertifiedPackedClientStatic certified_static =
        certify_packed_client_static(
            fixture.workload,
            MockBackend::storage_context_id(fixture.contexts.client),
            packing_setup);
    FoldedSetup malformed = packing_setup;
    ++malformed.transcript_packing.relation_plan.constraints.total;
    CHECK(rejects([&] {
        (void)certify_packed_client_static(
            fixture.workload,
            MockBackend::storage_context_id(fixture.contexts.client),
            malformed);
    }));
    auto other_contexts = MockBackend::create({
        .slot_count = 32,
        .fresh_rns_limbs = 13,
        .bits_per_limb = 300,
    });
    auto other_verifier =
        MockBackend::make_public_verifier_context(other_contexts.client);
    CHECK(rejects([&] {
        (void)make_authenticated_packed_client_online_state<MockBackend>(
            certified_static, other_contexts.client, other_verifier);
    }));
    auto online = make_authenticated_packed_client_online_state<MockBackend>(
        std::move(certified_static), fixture.contexts.client,
        fixture.verifier_context);
    CHECK(online.verifier_setup().spartan.setup_digest ==
          verifier_setup(packing_setup)
              .transcript_packing.spartan.setup_digest);
    EvaluationSetup<MockBackend> server =
        make_packed_evaluation_setup<MockBackend>(
            fixture.workload.public_setup(), fixture.contexts.eval);
    PackedClientSetup<MockBackend> ordinary_client =
        make_packed_client_setup_from_verifier_context<MockBackend>(
            make_client_setup<MockBackend>(
                fixture.workload.public_setup(), fixture.contexts.client),
            fixture.verifier_context);
    const std::vector<SlotVector> inputs{sequence(32, 7),
                                         sequence(32, 29)};

    diagnostics::PublicSetupValidationCounter certified_scans;
    diagnostics::LayeredCircuitValidationCounter certified_circuit_scans;
    std::vector<MockBackend::Ciphertext> ordinary_ciphertexts;
    FoldedClientRequestStart<MockBackend> authenticated = [&] {
        diagnostics::ObservePublicSetupValidation observe(certified_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            certified_circuit_scans);
        auto encrypted =
            encrypt_folded_request_inputs<MockBackend>(online, inputs);
        ordinary_ciphertexts = encrypted;
        return bind_folded_request_session<MockBackend>(
            online, inputs, std::move(encrypted), folded_nonce(17));
    }();

    diagnostics::PublicSetupValidationCounter ordinary_scans;
    diagnostics::LayeredCircuitValidationCounter ordinary_circuit_scans;
    FoldedClientRequestStart<MockBackend> ordinary = [&] {
        diagnostics::ObservePublicSetupValidation observe(ordinary_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            ordinary_circuit_scans);
        folded_client_detail::validate_evaluation_start(
            fixture.workload.payload(), fixture.workload.circuit(),
            ordinary_client.client_setup());
        return folded_client_detail::
            bind_validated_request_session<MockBackend>(
                fixture.workload.payload(), fixture.workload.circuit(),
                ordinary_client.client_setup(), inputs,
                std::move(ordinary_ciphertexts), folded_nonce(17));
    }();
    check_same_request(authenticated.request, ordinary.request);

    auto evaluated = delegation::reference::evaluate_folded_request_resident_reference<MockBackend>(
        fixture.workload.payload(), fixture.workload.circuit(), server,
        authenticated.request,
        apply_packed_proof_ingress_schedule(
            fixture.workload.circuit(),
            FheEvaluationPlan::without_payload_switches(
                fixture.workload.circuit(), 9),
            packing_setup));
    constexpr std::string_view kDomain =
        "test/packed-client-online/folded/v1";
    Transcript prover(kDomain);
    const FoldedResponse<MockBackend> response =
        delegation::reference::prove_folded_request_resident_reference<MockBackend>(
            fixture.workload.payload(), fixture.workload.circuit(), server,
            packing_setup, std::move(evaluated), prover);
    auto encoded = encode_folded_response_with_size<MockBackend>(
        fixture.contexts.eval, response);
    const FoldedWireDecodeLimits wire_limits{
        .max_message_bytes = encoded.bytes.size(),
        .max_ciphertexts = 1U << 14U,
        .max_ciphertext_bytes = encoded.bytes.size(),
        .max_total_ciphertext_bytes = encoded.bytes.size(),
        .max_proof_bytes = encoded.proof_size.total_bytes,
    };

    verification_profile::VerificationBreakdown breakdown;
    Fpk certified_next_challenge;
    Fpk ordinary_next_challenge;
    std::optional<std::vector<SlotVector>> certified_outputs;
    {
        diagnostics::ObservePublicSetupValidation observe(certified_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            certified_circuit_scans);
        auto decoded = decode_folded_response<MockBackend>(
            online, encoded.bytes, wire_limits,
            proof_decode_limits(encoded.proof_size.total_bytes),
            TraceProvenance::FheEvaluated);
        Transcript transcript(kDomain);
        {
            verification_profile::ScopedVerificationSession session(breakdown);
            const auto decryptions_before =
                MockBackend::counts(fixture.contexts.eval).decrypt;
            auto opened = open_folded_response<MockBackend>(
                online, std::move(authenticated.state), decoded, transcript);
            CHECK(opened.has_value());
            CHECK(MockBackend::counts(fixture.contexts.eval).decrypt ==
                  decryptions_before + decoded.output.values.size());
            CHECK(breakdown.phase_entries(
                      verification_profile::Category::OutputDecryption) == 1U);
            FoldedVerifierTimings timings;
            certified_outputs =
                verify_opened_folded_response_profiled<MockBackend>(
                    online, std::move(*opened), decoded, transcript, timings);
        }
        certified_next_challenge = transcript.challenge_fpk();
    }
    CHECK(breakdown.phase_entries(
              verification_profile::Category::OutputDecryption) == 1U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::Recovery) > 0U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::TerminalInputMLE) == 1U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::PackingSNARK) > 0U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::WFNoise) == 1U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::GkrPlaintext) > 0U);

    std::optional<std::vector<SlotVector>> ordinary_outputs;
    {
        diagnostics::ObservePublicSetupValidation observe(ordinary_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            ordinary_circuit_scans);
        Transcript transcript(kDomain);
        auto opened = open_folded_response<MockBackend>(
            fixture.workload.payload(), fixture.workload.circuit(),
            ordinary_client, std::move(ordinary.state), response,
            transcript);
        CHECK(opened.has_value());
        FoldedVerifierTimings timings;
        ordinary_outputs =
            verify_opened_folded_response_profiled<MockBackend>(
                fixture.workload.payload(), fixture.workload.circuit(),
                verifier_setup(packing_setup), ordinary_client,
                std::move(*opened), response, transcript, timings);
        ordinary_next_challenge = transcript.challenge_fpk();
    }
    CHECK(certified_next_challenge == ordinary_next_challenge);
    CHECK(certified_outputs.has_value());
    CHECK(ordinary_outputs.has_value());
    CHECK(*certified_outputs == *ordinary_outputs);
    CHECK(ordinary_outputs->front().size() == 32);
    CHECK(certified_scans.scans == 0);
    CHECK(certified_circuit_scans.scans == 0);
    CHECK(ordinary_scans.scans >= 3);
    CHECK(ordinary_circuit_scans.scans > 0);
}

void check_laned_authenticated_online_path_has_no_static_rescan() {
    Fixture fixture(PackingGkrVariant::Laned, 1);
    LanedSetup packing_setup{
        make_resident_packing_setup(fixture),
        std::vector<std::size_t>(
            fixture.workload.circuit().layers.size(),
            kLanedFixtureProofIngressRnsLimbs)};
    CertifiedPackedClientStatic certified_static =
        certify_packed_client_static(
            fixture.workload,
            MockBackend::storage_context_id(fixture.contexts.client),
            packing_setup);
    LanedSetup malformed = packing_setup;
    malformed.transcript_packing.variant = PackingGkrVariant::Folded;
    CHECK(rejects([&] {
        (void)certify_packed_client_static(
            fixture.workload,
            MockBackend::storage_context_id(fixture.contexts.client),
            malformed);
    }));
    auto online = make_authenticated_packed_client_online_state<MockBackend>(
        std::move(certified_static), fixture.contexts.client,
        fixture.verifier_context);
    CHECK(online.verifier_setup().spartan.setup_digest ==
          verifier_setup(packing_setup)
              .transcript_packing.spartan.setup_digest);
    EvaluationSetup<MockBackend> server =
        make_packed_evaluation_setup<MockBackend>(
            fixture.workload.public_setup(), fixture.contexts.eval);
    PackedClientSetup<MockBackend> ordinary_client =
        make_packed_client_setup_from_verifier_context<MockBackend>(
            make_client_setup<MockBackend>(
                fixture.workload.public_setup(), fixture.contexts.client),
            fixture.verifier_context);
    const std::vector<SlotVector> inputs{sequence(4, 7), sequence(4, 29)};

    diagnostics::PublicSetupValidationCounter certified_scans;
    diagnostics::LayeredCircuitValidationCounter certified_circuit_scans;
    std::vector<MockBackend::Ciphertext> ordinary_ciphertexts;
    LanedClientRequestStart<MockBackend> authenticated = [&] {
        diagnostics::ObservePublicSetupValidation observe(certified_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            certified_circuit_scans);
        auto encrypted =
            encrypt_laned_request_inputs<MockBackend>(online, inputs);
        ordinary_ciphertexts = encrypted;
        return bind_laned_request_session<MockBackend>(
            online, inputs, std::move(encrypted), laned_nonce(23));
    }();

    diagnostics::PublicSetupValidationCounter ordinary_scans;
    diagnostics::LayeredCircuitValidationCounter ordinary_circuit_scans;
    LanedClientRequestStart<MockBackend> ordinary = [&] {
        diagnostics::ObservePublicSetupValidation observe(ordinary_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            ordinary_circuit_scans);
        laned_client_detail::validate_evaluation_start(
            fixture.workload.payload(), fixture.workload.circuit(),
            ordinary_client.client_setup());
        return laned_client_detail::
            bind_validated_request_session<MockBackend>(
                fixture.workload.payload(), fixture.workload.circuit(),
                ordinary_client.client_setup(), inputs,
                std::move(ordinary_ciphertexts), laned_nonce(23));
    }();
    check_same_request(authenticated.request, ordinary.request);

    auto evaluated = delegation::reference::evaluate_laned_request_resident_reference<MockBackend>(
        fixture.workload.payload(), fixture.workload.circuit(), server,
        authenticated.request,
        apply_packed_proof_ingress_schedule(
            fixture.workload.circuit(),
            FheEvaluationPlan::without_payload_switches(
                fixture.workload.circuit(), 9),
            packing_setup));
    constexpr std::string_view kDomain =
        "test/packed-client-online/laned/v1";
    Transcript prover(kDomain);
    const LanedResponse<MockBackend> response =
        delegation::reference::prove_laned_request_resident_reference<MockBackend>(
            fixture.workload.payload(), fixture.workload.circuit(), server,
            packing_setup, std::move(evaluated), prover);
    auto encoded = encode_laned_response_with_size<MockBackend>(
        fixture.contexts.eval, response);
    const LanedWireDecodeLimits wire_limits{
        .max_message_bytes = encoded.bytes.size(),
        .max_ciphertexts = 1U << 14U,
        .max_ciphertext_bytes = encoded.bytes.size(),
        .max_total_ciphertext_bytes = encoded.bytes.size(),
        .max_proof_bytes = encoded.proof_size.total_bytes,
    };

    verification_profile::VerificationBreakdown breakdown;
    Fpk certified_next_challenge;
    Fpk ordinary_next_challenge;
    std::optional<std::vector<SlotVector>> certified_outputs;
    {
        diagnostics::ObservePublicSetupValidation observe(certified_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            certified_circuit_scans);
        auto decoded = decode_laned_response<MockBackend>(
            online, encoded.bytes, wire_limits,
            proof_decode_limits(encoded.proof_size.total_bytes),
            TraceProvenance::FheEvaluated);
        Transcript transcript(kDomain);
        {
            verification_profile::ScopedVerificationSession session(breakdown);
            const auto decryptions_before =
                MockBackend::counts(fixture.contexts.eval).decrypt;
            auto opened = open_laned_response<MockBackend>(
                online, std::move(authenticated.state), decoded, transcript);
            CHECK(opened.has_value());
            CHECK(MockBackend::counts(fixture.contexts.eval).decrypt ==
                  decryptions_before + decoded.output.values.size());
            CHECK(breakdown.phase_entries(
                      verification_profile::Category::OutputDecryption) == 1U);
            LanedVerifierTimings timings;
            certified_outputs =
                verify_opened_laned_response_profiled<MockBackend>(
                    online, std::move(*opened), decoded, transcript, timings);
        }
        certified_next_challenge = transcript.challenge_fpk();
    }
    CHECK(breakdown.phase_entries(
              verification_profile::Category::OutputDecryption) == 1U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::Recovery) > 0U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::TerminalInputMLE) == 1U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::PackingSNARK) > 0U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::WFNoise) == 1U);
    CHECK(breakdown.phase_entries(
              verification_profile::Category::GkrPlaintext) > 0U);

    std::optional<std::vector<SlotVector>> ordinary_outputs;
    {
        diagnostics::ObservePublicSetupValidation observe(ordinary_scans);
        diagnostics::ObserveLayeredCircuitValidation observe_circuit(
            ordinary_circuit_scans);
        Transcript transcript(kDomain);
        auto opened = open_laned_response<MockBackend>(
            fixture.workload.payload(), fixture.workload.circuit(),
            ordinary_client, std::move(ordinary.state), response,
            transcript);
        CHECK(opened.has_value());
        LanedVerifierTimings timings;
        ordinary_outputs =
            verify_opened_laned_response_profiled<MockBackend>(
                fixture.workload.payload(), fixture.workload.circuit(),
                verifier_setup(packing_setup), ordinary_client,
                std::move(*opened), response, transcript, timings);
        ordinary_next_challenge = transcript.challenge_fpk();
    }
    CHECK(certified_next_challenge == ordinary_next_challenge);
    CHECK(certified_outputs.has_value());
    CHECK(ordinary_outputs.has_value());
    CHECK(*certified_outputs == *ordinary_outputs);
    CHECK(ordinary_outputs->front().size() == 4);
    CHECK(certified_scans.scans == 0);
    CHECK(certified_circuit_scans.scans == 0);
    CHECK(ordinary_scans.scans >= 3);
    CHECK(ordinary_circuit_scans.scans > 0);
}

void check_role_static_codec_is_bounded_and_canonical() {
    TemporaryTree tree;
    Fixture fixture(PackingGkrVariant::Folded);
    const PublicationPaths paths =
        make_publication_paths(tree, "published");
    const auto result = publish_fixture(fixture, paths);
    const auto server = open_packed_server_role_state<MockBackend>(
        paths.shared, paths.server, result.root.storage_identity,
        fixture.contexts.eval,
        packed_role_preprocessing_open_limits(
            publication_limits(fixture.workload, fixture.plan)));
    const PackedRoleStatic &state = server.core().role_static;
    const std::vector<std::uint8_t> encoded =
        encode_packed_role_static(state);
    const auto limits = publication_limits(
        fixture.workload, fixture.plan).role_static;
    CHECK(encoded.size() == fixture.plan.server_role_static_bytes);
    CHECK(decode_authenticated_packed_role_static(
              encoded, PackedPreprocessingRole::Server, sha256(encoded),
              state.semantic_identity, limits) == state);
    CHECK(rejects([&] {
        (void)decode_authenticated_packed_role_static(
            encoded, PackedPreprocessingRole::Client, sha256(encoded),
            state.semantic_identity, limits);
    }));

    auto tampered = encoded;
    tampered[tampered.size() / 2U] ^= 1U;
    CHECK(rejects([&] {
        (void)decode_authenticated_packed_role_static(
            tampered, PackedPreprocessingRole::Server, sha256(tampered),
            state.semantic_identity, limits);
    }));
    auto trailing = encoded;
    trailing.push_back(0);
    auto larger = limits;
    larger.max_encoded_bytes += 1U;
    CHECK(rejects([&] {
        (void)decode_authenticated_packed_role_static(
            trailing, PackedPreprocessingRole::Server, sha256(trailing),
            state.semantic_identity, larger);
    }));
    auto too_small = limits;
    too_small.max_encoded_bytes = encoded.size() - 1U;
    CHECK(rejects([&] {
        (void)decode_authenticated_packed_role_static(
            encoded, PackedPreprocessingRole::Server, sha256(encoded),
            state.semantic_identity, too_small);
    }));
    PackedRoleStatic path_escape = state;
    path_escape.artifact_relative_paths.front() = "../tensor-columns";
    CHECK(rejects([&] {
        (void)encode_packed_role_static(path_escape);
    }));
}

void check_diagnostic_commitment_policy_is_persisted_and_restored() {
    const auto policy = gkr::CiphertextCommitmentPolicy::
        diagnostic_simple_ct_hash_v2();
    TemporaryTree tree;
    Fixture fixture(PackingGkrVariant::Folded, 2, policy);
    const PublicationPaths paths =
        make_publication_paths(tree, "diagnostic-policy");
    const auto result = publish_fixture(fixture, paths);
    auto roles = open_fixture_roles(
        fixture, paths, result.root.storage_identity);
    CHECK(roles.first.core().role_static
              .ciphertext_commitment_policy == policy);
    CHECK(roles.second.core().role_static
              .ciphertext_commitment_policy == policy);
    CHECK(roles.first.prover_setup()
              .transcript_packing()
              .relation()
              .relation_plan.shape.ciphertext_commitment_policy == policy);
    CHECK(roles.second.verifier_setup()
              .relation_plan.shape.ciphertext_commitment_policy == policy);
    const PackedRoleStatic &server_state =
        roles.first.core().role_static;
    PackedRoleStatic mismatched_state = server_state;
    mismatched_state.ciphertext_commitment_policy =
        gkr::CiphertextCommitmentPolicy::poseidon_v2();
    CHECK(rejects([&] {
        (void)encode_packed_role_static(mismatched_state);
    }));

    // magic || version || flags || role || variant precedes the canonical
    // policy u64. Replacing only that word must fail authentication even when
    // the caller supplies the changed file digest.
    std::vector<std::uint8_t> mismatched_encoding =
        encode_packed_role_static(server_state);
    constexpr std::size_t kPolicyOffset = 5U * sizeof(std::uint64_t);
    std::fill_n(mismatched_encoding.begin() + kPolicyOffset,
                sizeof(std::uint64_t), std::uint8_t{0});
    mismatched_encoding[kPolicyOffset] = static_cast<std::uint8_t>(
        gkr::CiphertextCommitmentPolicy::poseidon_v2().wire_code());
    CHECK(rejects([&] {
        (void)decode_authenticated_packed_role_static(
            mismatched_encoding, PackedPreprocessingRole::Server,
            sha256(mismatched_encoding), server_state.semantic_identity,
            publication_limits(fixture.workload, fixture.plan)
                .role_static);
    }));
    CHECK(rejects([] {
        (void)gkr::CiphertextCommitmentPolicy::from_wire_code(0);
    }));
    CHECK(rejects([] {
        (void)gkr::CiphertextCommitmentPolicy::from_wire_code(5);
    }));
}

void check_affine4_policy_is_persisted_and_restored() {
    TemporaryTree tree;
    Fixture fixture(PackingGkrVariant::Folded);
    fixture.specification.proof_ingress_policy =
        ConservativePackedProofIngressPolicy::FoldedAffine4;
    fixture.plan = plan_packed_role_preprocessing_publication(
        fixture.workload, fixture.specification,
        MockBackend::storage_context_id(fixture.contexts.eval));
    const auto paths = make_publication_paths(tree, "affine4-policy");
    const auto published = publish_fixture(fixture, paths);
    auto roles = open_fixture_roles(fixture, paths, published.root.storage_identity);
    const auto expected = derive_conservative_packed_proof_ingress_schedule(
        PackingGkrVariant::Folded, fixture.workload.payload(),
        fixture.workload.circuit(), fixture.workload.public_setup(),
        ConservativePackedProofIngressPolicy::FoldedAffine4);
    CHECK(roles.first.prover_setup().proof_ingress_schedule() == expected);
    for (const auto *state : {&roles.first.core().role_static,
                              &roles.second.core().role_static}) {
        CHECK(state->proof_ingress_policy == kConservativePackedProofIngressPolicyV4);
        CHECK(state->proof_ingress_schedule_digest == expected.digest());
        CHECK(std::ranges::equal(state->proof_ingress_rns_limbs_by_layer,
                                expected.rns_limbs_by_layer()));
        const auto encoded = encode_packed_role_static(*state);
        CHECK(decode_authenticated_packed_role_static(encoded, state->role,
            sha256(encoded), state->semantic_identity,
            publication_limits(fixture.workload, fixture.plan).role_static) == *state);
        auto tampered = *state;
        tampered.proof_ingress_policy = kConservativePackedProofIngressPolicyV1;
        CHECK(rejects([&] { (void)encode_packed_role_static(tampered); }));
    }
}

void check_tree_and_role_file_tamper_fail_closed() {
    {
        TemporaryTree tree;
        Fixture fixture(PackingGkrVariant::Folded);
        const PublicationPaths paths =
            make_publication_paths(tree, "role-tamper");
        const auto result = publish_fixture(fixture, paths);
        const auto opening = packed_role_preprocessing_open_limits(
            publication_limits(fixture.workload, fixture.plan));
        flip_first_byte(paths.server / kPackedRoleStaticFilename);
        CHECK(rejects([&] {
            (void)open_packed_server_role_state<MockBackend>(
                paths.shared, paths.server, result.root.storage_identity,
                fixture.contexts.eval, opening);
        }));
    }
    {
        TemporaryTree tree;
        Fixture fixture(PackingGkrVariant::Folded);
        const PublicationPaths paths =
            make_publication_paths(tree, "tree-tamper");
        const auto result = publish_fixture(fixture, paths);
        const auto opening = packed_role_preprocessing_open_limits(
            publication_limits(fixture.workload, fixture.plan));
        flip_first_byte(first_regular_file(
            paths.server / kPackedRoleArtifactTreeDirectory));
        CHECK(rejects([&] {
            (void)open_packed_server_role_state<MockBackend>(
                paths.shared, paths.server, result.root.storage_identity,
                fixture.contexts.eval, opening);
        }));
    }
}

void check_formula_admission_and_profile_sizes() {
    Fixture fixture(PackingGkrVariant::Folded, 4);
    const Digest context_id =
        MockBackend::storage_context_id(fixture.contexts.eval);
    std::array<PackedRolePreprocessingPublicationPlan, 3> plans;
    const std::array<std::size_t, 3> repetitions{4, 15, 120};
    for (std::size_t index = 0; index < plans.size(); ++index) {
        const auto specification = make_specification(
            fixture.variant, fixture.workload, repetitions[index]);
        plans[index] = plan_packed_role_preprocessing_publication(
            fixture.workload, specification, context_id);
        // Pin the canonical role-certificate sizes used by publication and
        // the one-byte-too-small admission test below.
        CHECK(plans[index].server_role_static_bytes == 1981U);
        CHECK(plans[index].client_role_static_bytes == 1694U);
        CHECK(plans[index].server_artifacts.file_count == 155U);
        CHECK(plans[index].server_artifacts.directory_count == 12U);
        CHECK(plans[index].server_artifacts.serialized_bytes == 117258U);
        CHECK(plans[index].client_artifacts ==
              PackedRoleArtifactTreePlan{});
        CHECK(plans[index].server_artifacts.directory_count ==
              1U + plans[index].transcript_packing.factored.tensors.size());
        CHECK(plans[index].server_artifacts.serialized_bytes ==
              plans[index].transcript_packing.factored
                  .persistent_output_physical_bytes);
        std::uint64_t expected_files = 1;
        for (const auto &tensor :
             plans[index].transcript_packing.factored.tensors) {
            expected_files += 3U * tensor.shape.column_count + 2U;
        }
        CHECK(plans[index].server_artifacts.file_count == expected_files);
    }
    // T is encoded as a fixed-width integer. For this compact profile fixture,
    // all three selected values remain within the same padded tensor geometry.
    CHECK(plans[0].server_role_static_bytes ==
          plans[1].server_role_static_bytes);
    CHECK(plans[1].server_role_static_bytes ==
          plans[2].server_role_static_bytes);
    CHECK(plans[0].server_artifacts == plans[1].server_artifacts);
    CHECK(plans[1].server_artifacts == plans[2].server_artifacts);

    TemporaryTree tree;
    const PublicationPaths paths =
        make_publication_paths(tree, "preflight-failure");
    auto limits = publication_limits(fixture.workload, fixture.plan);
    limits.role_static.max_encoded_bytes =
        fixture.plan.server_role_static_bytes - 1U;
    CHECK(rejects([&] {
        (void)publish_packed_role_preprocessing<MockBackend>(
            fixture.workload, fixture.specification,
            fixture.contexts.eval, fixture.contexts.client,
            fixture.verifier_context, paths.directories(), limits);
    }));
    CHECK(std::filesystem::is_empty(paths.shared));
    CHECK(std::filesystem::is_empty(paths.server));
    CHECK(std::filesystem::is_empty(paths.client));
    CHECK(std::filesystem::is_empty(paths.work));

    const auto reject_decode_limit =
        [&](std::string_view name, auto lower_limit) {
            const PublicationPaths decode_paths =
                make_publication_paths(tree, name);
            auto decode_limits =
                publication_limits(fixture.workload, fixture.plan);
            lower_limit(decode_limits.storage.workload_decode,
                        fixture.plan.workload_decode_requirements);
            CHECK(rejects([&] {
                (void)publish_packed_role_preprocessing<MockBackend>(
                    fixture.workload, fixture.specification,
                    fixture.contexts.eval, fixture.contexts.client,
                    fixture.verifier_context, decode_paths.directories(),
                    decode_limits);
            }));
            CHECK(std::filesystem::is_empty(decode_paths.shared));
            CHECK(std::filesystem::is_empty(decode_paths.server));
            CHECK(std::filesystem::is_empty(decode_paths.client));
            CHECK(std::filesystem::is_empty(decode_paths.work));
        };
    reject_decode_limit(
        "layer-gate-preflight-failure",
        [](PackedWorkloadStaticDecodeLimits &limits,
           const PackedWorkloadStaticDecodeLimits &requirements) {
            CHECK(requirements.max_layer_gates > 0);
            limits.max_layer_gates = requirements.max_layer_gates - 1U;
        });
    reject_decode_limit(
        "affine-term-preflight-failure",
        [](PackedWorkloadStaticDecodeLimits &limits,
           const PackedWorkloadStaticDecodeLimits &requirements) {
            CHECK(requirements.max_affine_terms > 0);
            limits.max_affine_terms = requirements.max_affine_terms - 1U;
        });
    reject_decode_limit(
        "storage-entry-preflight-failure",
        [](PackedWorkloadStaticDecodeLimits &limits,
           const PackedWorkloadStaticDecodeLimits &requirements) {
            CHECK(requirements.max_storage_entries > 0);
            limits.max_storage_entries =
                requirements.max_storage_entries - 1U;
        });
}

#ifndef _WIN32
void check_symlinked_fixed_artifact_fails_closed() {
    TemporaryTree tree;
    Fixture fixture(PackingGkrVariant::Folded);
    const PublicationPaths paths =
        make_publication_paths(tree, "symlink-tamper");
    const auto result = publish_fixture(fixture, paths);
    const auto opening = packed_role_preprocessing_open_limits(
        publication_limits(fixture.workload, fixture.plan));
    const std::filesystem::path state =
        paths.server / kPackedRoleArtifactTreeDirectory /
        packed_server_basefold_state_relative_path(0);
    const std::filesystem::path moved = state.string() + ".moved";
    std::filesystem::rename(state, moved);
    std::filesystem::create_directory_symlink(moved, state);
    CHECK(rejects([&] {
        (void)open_packed_server_role_state<MockBackend>(
            paths.shared, paths.server, result.root.storage_identity,
            fixture.contexts.eval, opening);
    }));
}
#endif

} // namespace

int main() {
    laminate::test::Runner runner("packed role preprocessing");
    runner.run("publishes, destroys, reopens, and relocates Folded state",
               check_folded_lifecycle_and_relocation);
    runner.run("restores Laned state with strict role and context binding",
               check_laned_lifecycle_and_role_context_rejection);
    runner.run("runs Folded online work without rescanning static setup",
               check_folded_authenticated_online_path_has_no_static_rescan);
    runner.run("runs Laned online work without rescanning static setup",
               check_laned_authenticated_online_path_has_no_static_rescan);
    runner.run("uses a bounded canonical role-static codec",
               check_role_static_codec_is_bounded_and_canonical);
    runner.run("persists and restores the diagnostic commitment policy",
               check_diagnostic_commitment_policy_is_persisted_and_restored);
    runner.run("persists and restores explicitly selected affine4 ingress",
               check_affine4_policy_is_persisted_and_restored);
    runner.run("rejects role-static and external artifact tamper",
               check_tree_and_role_file_tamper_fail_closed);
    runner.run("derives profile sizes and rejects caps before publication",
               check_formula_admission_and_profile_sizes);
#ifndef _WIN32
    runner.run("rejects a symlinked fixed artifact root",
               check_symlinked_fixed_artifact_fails_closed);
#endif
    return runner.summary();
}
