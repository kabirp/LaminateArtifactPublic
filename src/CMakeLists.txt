find_package(Threads REQUIRED)

add_library(laminate
    basefold/basefold.cpp
    basefold/commitment.cpp
    basefold/common.cpp
    basefold/folding.cpp
    basefold/foldable.cpp
    basefold/foldable_query_policy.cpp
    basefold/foldable_io.cpp
    basefold/foldable_storage.cpp
    basefold/merkle.cpp
    basefold/proof_io.cpp
    basefold/query.cpp
    basefold/reed_solomon.cpp
    basefold/reduction.cpp
    basefold/sumcheck.cpp
    bench/schedule_cost.cpp
    bench/base_schedule_cost.cpp
    bench/packed_checkpoint_replay.cpp
    bench/target_cost.cpp
    gates/action_sumcheck.cpp
    gates/canonical_layout.cpp
    gates/canonical_tables.cpp
    gates/prover_key_storage.cpp
    gates/gate_mle.cpp
    gates/wide_program.cpp
    gates/masked_action.cpp
    gates/outsourced.cpp
    gates/outsourced_io.cpp
    gates/sparse_product.cpp
    gates/quadratic_product.cpp
    gates/wide_opening.cpp
    gkr/claims.cpp
    gkr/layer_reductions.cpp
    gkr/dense_multiplication/file_source.cpp
    gkr/proof.cpp
    gkr/layer_reduction_sumcheck.cpp
    field/fp.cpp
    field/fpk.cpp
    field/fq.cpp
    field/fq_ntt.cpp
    field/fq_transform_kernels.cpp
    field/fq2.cpp
    field/serialization.cpp
    fhe/noise/deterministic.cpp
    fhe/noise/honest_envelope_backend.cpp
    fhe/noise/modulus_switch_policy.cpp
    fhe/mock_backend.cpp
    fhe/noise/envelope_backend.cpp
    fhe/layout/slot_grid.cpp
    payload/circuit.cpp
    payload/checkpoint/problem.cpp
    payload/checkpoint/selection.cpp
    payload/compiler.cpp
    payload/reference/evaluator.cpp
    payload/storage/format/files.cpp
    payload/storage/format/layer_format.cpp
    payload/storage/format/layer_validation.cpp
    payload/storage/format/manifest.cpp
    payload/storage/format/retirement.cpp
    payload/storage/format/schema.cpp
    payload/storage/store/descriptor.cpp
    payload/storage/store/open.cpp
    payload/storage/store/private_alias.cpp
    payload/storage/store/publication.cpp
    payload/storage/store/readers.cpp
    payload/storage/store/reclamation.cpp
    payload/storage/store/retirement_journal.cpp
    payload/storage/store/writer.cpp
    payload/noise/honest_base_proof_noise_binding.cpp
    payload/noise/honest_base_proof_noise_assessor.cpp
    payload/noise/honest_base_proof_noise.cpp
    payload/noise/honest_noise_schedule.cpp
    payload/ir/layered.cpp
    payload/trace/trace_wire_support.cpp
    payload/reference/trace.cpp
    payload/setup/encoding.cpp
    packing/alignment/affine_weight.cpp
    packing/alignment/layout.cpp
    packing/analysis/honest_finalization.cpp
    packing/analysis/operator.cpp
    packing/evaluation/signed_digits.cpp
    packing/evaluation/well_formedness.cpp
    packing/outer_relation/assignment.cpp
    packing/outer_relation/constraints.cpp
    packing/outer_relation/evaluator.cpp
    packing/outer_relation/operator.cpp
    packing/outer_relation/packing_r1cs.cpp
    packing/outer_relation/plan.cpp
    packing/outer_relation/r1cs.cpp
    packing/outer_relation/tensor.cpp
    packing/proof/r1cs/layout.cpp
    packing/proof/matrix/oracle.cpp
    packing/proof/matrix/products.cpp
    packing/proof/r1cs.cpp
    packing/proof/spartan_external.cpp
    packing/proof/matrix/metadata.cpp
    packing/proof/matrix/tensor_staging.cpp
    packing/proof/matrix/wiring.cpp
    protocol/setup/base_client.cpp
    protocol/storage/base_preprocessing.cpp
    protocol/storage/base_capacity.cpp
    protocol/storage/packed_preprocessing.cpp
    protocol/storage/server.cpp
    protocol/analysis/packing_completeness.cpp
    protocol/analysis/noise_completeness.cpp
    protocol/analysis/packing_prerequisites.cpp
    protocol/packed/setup.cpp
    protocol/packed/preprocessing/client_static.cpp
    protocol/packed/preprocessing/roles.cpp
    protocol/packed/preprocessing/workload.cpp
    protocol/packed/external/prover.cpp
    protocol/packed/external/transcript_packing.cpp
    protocol/packed/external/preprocessing.cpp
    setup/encoding.cpp
    setup/gate_mle.cpp
    setup/noise_binding.cpp
    setup/public.cpp
    spartan/basefold_external_commit.cpp
    spartan/basefold_pcs.cpp
    spartan/factored.cpp
    spartan/ipcs.cpp
    spartan/r1cs.cpp
    spartan/bcs16.cpp
    spartan/sumcheck.cpp
    spartan/wiring_artifact.cpp
    spartan/uniform.cpp
    storage/native_field_artifact.cpp
    storage/external_record_sort.cpp
    transcript/hash.cpp
    crypto/poseidon.cpp
    transcript/transcript.cpp
)

target_include_directories(laminate
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_options(laminate PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(laminate PRIVATE Threads::Threads)

if(BUILD_TESTING OR BUILD_BENCHMARKS)
    add_library(
        laminate_payload_fixture_support
        payload/fixtures/workloads.cpp)
    target_link_libraries(
        laminate_payload_fixture_support PUBLIC laminate)
    target_compile_options(
        laminate_payload_fixture_support
        PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(TARGET OpenSSL::Crypto)
    target_link_libraries(laminate PRIVATE OpenSSL::Crypto)
    target_compile_definitions(
        laminate PRIVATE LAMINATE_SHA256_OPENSSL=1)
endif()

if(LAMINATE_WITH_SEAL)
    target_sources(
        laminate PRIVATE
        fhe/seal/arithmetic.cpp
        fhe/seal/ciphertext_codec.cpp
        fhe/seal/coefficient_commitment.cpp
        fhe/seal/context.cpp
        fhe/seal/context_bundle.cpp
        fhe/seal/plaintext_basis.cpp
        fhe/seal/telemetry.cpp
        fhe/noise/seal_envelope.cpp)
    target_link_libraries(laminate PUBLIC SEAL::seal)
    target_compile_definitions(laminate PUBLIC LAMINATE_WITH_SEAL=1)
    if(LAMINATE_SEAL_HEXL_ENABLED)
        target_compile_definitions(
            laminate PRIVATE LAMINATE_NATIVE_FQ_HEXL=1)
        message(STATUS
            "Laminate native-Fq NTT: Intel HEXL through SEAL dispatch")
    else()
        message(STATUS
            "Laminate native-Fq NTT: scalar fallback (SEAL has no HEXL)")
    endif()
endif()
