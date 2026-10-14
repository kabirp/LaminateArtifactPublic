function(laminate_add_test source)
    get_filename_component(name "${source}" NAME_WE)
    add_executable(${name} "${source}")
    target_link_libraries(
        ${name} PRIVATE laminate_payload_fixture_support)
    target_include_directories(
        ${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/support")
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

function(laminate_add_seal_test source)
    laminate_add_test("${source}")
    get_filename_component(name "${source}" NAME_WE)
    set_tests_properties(${name} PROPERTIES LABELS "seal;smoke")
endfunction()

# The setup scheduler is backend independent; keep its bounded dependency
# regressions available in both Mock and real-SEAL builds.
laminate_add_test(payload/noise/test_honest_payload_wire_schedule.cpp)
laminate_add_test(gkr/test_base_affine_target_geometry.cpp)

# A SEAL build selects real-backend and accelerated-field coverage. The
# general backend-independent suite belongs to the smaller Mock build, so
# enabling SEAL alone does not run the complete test inventory.
if(LAMINATE_WITH_SEAL)
    set(LAMINATE_SEAL_TEST_SOURCES
        test_base_seal.cpp
        delegation/test_folded_statement_seal.cpp
        delegation/test_base_wire.cpp
        delegation/test_wide_gate_wire_seal.cpp
        fhe/test_seal_backend.cpp
        fhe/test_seal_context_bundle.cpp
        field/test_fq_ntt.cpp
        gkr/test_base_prover_file_backed_seal.cpp
        gkr/test_laned_prover_file_backed_seal.cpp
        packing/evaluation/test_lazy_ternary_seal.cpp
        packing/outer_relation/test_outer_relation_seal.cpp
        payload/fixtures/test_workloads_seal.cpp
        payload/checkpoint/test_checkpoint_replay_execution_seal.cpp
        payload/noise/test_honest_payload_wire_schedule_seal.cpp
        payload/evaluation/test_laned_fhe_evaluator_seal.cpp
        payload/evaluation/test_wide_fhe_evaluator_seal.cpp)

    if(LAMINATE_EXTENDED_TESTS)
        list(APPEND LAMINATE_SEAL_TEST_SOURCES
            gkr/test_base_affine_file_backed_seal.cpp
            gkr/test_laned_affine_file_backed_seal.cpp
            gkr/test_laned_multiplication_file_backed_seal.cpp
            packing/analysis/test_operator_seal.cpp
            payload/storage/test_file_trace_values_seal.cpp)
    endif()

    foreach(source IN LISTS LAMINATE_SEAL_TEST_SOURCES)
        laminate_add_seal_test("${source}")
    endforeach()
    # Check a complete target dependency cone without evaluating every gate.
    add_test(NAME base_target_noise_seal
        COMMAND test_base_prover_file_backed_seal
                --target-balanced-cones 1095233372161)
    set_tests_properties(base_target_noise_seal PROPERTIES
        LABELS "seal;target-noise" TIMEOUT 600 RUN_SERIAL TRUE)
    # Exercise the pyramid's original masks/rotations through all eight
    # multiplication stages and ordinary Base verification. The final sum
    # deliberately stresses 3,766 correlated copies of this exact cone.
    add_test(NAME base_target_pyramid_proof_seal
        COMMAND test_base_prover_file_backed_seal
                --target-pyramid-production-proof)
    set_tests_properties(base_target_pyramid_proof_seal PROPERTIES
        LABELS "seal;target-noise" TIMEOUT 900 RUN_SERIAL TRUE)
    # Keep the corresponding Folded payload, proof-source normalization and
    # output normalization covered under its current production profile.
    add_test(NAME folded_target_pyramid_noise_seal
        COMMAND test_base_prover_file_backed_seal
                --target-folded-pyramid-cone 1042862)
    set_tests_properties(folded_target_pyramid_noise_seal PROPERTIES
        LABELS "seal;target-noise" TIMEOUT 600 RUN_SERIAL TRUE)
    foreach(profile IN ITEMS balancedLaned mulHeavyPyramid)
        add_test(NAME no_integrity_target_${profile}_noise_seal
            COMMAND test_checkpoint_replay_execution_seal
                    --no-integrity-target-noise target-${profile})
        set_tests_properties(no_integrity_target_${profile}_noise_seal PROPERTIES
            LABELS "seal;target-noise" TIMEOUT 900 RUN_SERIAL TRUE)
    endforeach()
    return()
endif()

add_test(
    NAME cmake_seal_dependency_policy
    COMMAND ${CMAKE_COMMAND}
            -DMODULE=${PROJECT_SOURCE_DIR}/cmake/SealDependency.cmake
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/test_seal_dependency.cmake)

add_test(
    NAME cmake_seal_feature_export
    COMMAND ${CMAKE_COMMAND}
            -S ${CMAKE_CURRENT_SOURCE_DIR}/cmake/seal_feature_export
            -B ${CMAKE_CURRENT_BINARY_DIR}/cmake_seal_feature_export
            -DMODULE=${PROJECT_SOURCE_DIR}/cmake/SealDependency.cmake
            -DFAKE_SEAL_DIR=${CMAKE_CURRENT_SOURCE_DIR}/cmake/fake_seal)

# This independent certificate uses Python's arbitrary-precision integers.
# Keep Python optional for users building the C++ artifact alone.
find_package(Python3 QUIET COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(
        NAME poseidon_parameter_certificate
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/crypto/check_poseidon_parameters.py)
    add_test(
        NAME foldable_query_certificate
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/basefold/check_foldable_query_certificate.py)
endif()

# Default coverage keeps the protocol boundaries, selected proof stack,
# file-backed paths, and deployment cost/storage invariants.
set(LAMINATE_MOCK_TEST_SOURCES
    test_base.cpp
    test_verification_profile.cpp
    test_folded.cpp
    test_folded_delegation.cpp
    test_laned.cpp
    test_laned_delegation.cpp
    test_packed_gkr.cpp
    basefold/test_basefold.cpp
    basefold/test_basefold_soundness.cpp
    basefold/test_foldable.cpp
    basefold/test_foldable_query_policy.cpp
    cost_model/test_packed_checkpoint_policy.cpp
    cost_model/test_packed_checkpoint_replay.cpp
    cost_model/test_packed_process_profile.cpp
    cost_model/test_packed_setup_admission.cpp
    cost_model/test_schedule_cost.cpp
    cost_model/test_setup_execution.cpp
    fhe/test_fhe_extension.cpp
    fhe/test_fhe_value.cpp
    fhe/test_mock_backend.cpp
    fhe/test_modulus_switch_policy.cpp
    fhe/test_noise_envelope_protocol.cpp
    field/test_field.cpp
    field/test_fq_ntt.cpp
    gates/test_action_sumcheck.cpp
    gates/test_gate_mle.cpp
    gates/test_wide_program.cpp
    gates/test_masked_action.cpp
    gates/test_outsourced_gate_mle.cpp
    gates/test_sparse_product.cpp
    gkr/test_committed_message_codec.cpp
    gkr/test_dense_paired_source.cpp
    gkr/test_base_prover_file_backed.cpp
    gkr/test_folded_prover.cpp
    gkr/test_laned_prover_file_backed.cpp
    gkr/test_packed_dense_multiplication_verifier.cpp
    gkr/test_packed_proof_schema.cpp
    gkr/test_sumcheck.cpp
    packing/analysis/test_operator.cpp
    packing/evaluation/test_well_formedness.cpp
    packing/outer_relation/test_outer_relation.cpp
    packing/proof/test_r1cs.cpp
    payload/checkpoint/test_checkpoint_replay_execution.cpp
    payload/storage/test_file_trace_store.cpp
    payload/reference/test_payload.cpp
    payload/evaluation/test_wide_fhe_evaluator.cpp
    poly/test_poly.cpp
    protocol/test_packed_gkr_transcript.cpp
    protocol/test_packed_preprocessing_storage.cpp
    protocol/test_packed_role_preprocessing.cpp
    protocol/test_packed_external.cpp
    protocol/test_packed_server_online.cpp
    protocol/test_server_storage.cpp
    protocol/test_transcript_packing_external.cpp
    protocol/test_transcript_packing_external_preprocessing.cpp
    spartan/test_basefold_pcs.cpp
    spartan/test_factored.cpp
    spartan/test_spartan.cpp
    spartan/test_spartan_sumcheck.cpp
    transcript/test_transcript.cpp)

if(LAMINATE_EXTENDED_TESTS)
    list(APPEND LAMINATE_MOCK_TEST_SOURCES
        delegation/test_base_checkpoint_delegation.cpp
        delegation/test_base_delegation.cpp
        delegation/test_base_wire.cpp
        delegation/test_wire.cpp
        fhe/test_deterministic_noise.cpp
        fhe/test_fhe_value_codec.cpp
        fhe/test_honest_noise_envelope_backend.cpp
        fhe/test_noise_envelope_backend.cpp
        gates/test_gate_tables.cpp
        gkr/test_base_affine_file_backed.cpp
        gkr/test_claims.cpp
        gkr/test_laned_affine_file_backed.cpp
        gkr/test_laned_multiplication_source_store.cpp
        gkr/test_laned_multiplication_file_backed.cpp
        gkr/test_layer_reductions.cpp
        gkr/test_proof.cpp
        packing/alignment/test_affine_weight.cpp
        packing/analysis/test_honest_finalization.cpp
        packing/evaluation/test_lazy_ternary.cpp
        packing/evaluation/test_signed_digits.cpp
        packing/outer_relation/test_outer_relation_assignment.cpp
        packing/outer_relation/test_outer_relation_constraints.cpp
        packing/outer_relation/test_outer_relation_packing_r1cs.cpp
        packing/outer_relation/test_outer_relation_r1cs.cpp
        packing/outer_relation/test_packing_tensor.cpp
        packing/proof/matrix/test_tensor_staging.cpp
        packing/proof/matrix/test_matrix_products.cpp
        packing/proof/matrix/test_wiring.cpp
        payload/checkpoint/test_checkpoint_replay.cpp
        payload/trace/test_encrypted_trace.cpp
        payload/storage/test_file_trace_values.cpp
        payload/noise/test_honest_base_proof_noise.cpp
        payload/noise/test_honest_base_proof_noise_assessor.cpp
        payload/reference/test_layering.cpp
        payload/reference/test_trace.cpp
        payload/trace/test_trace_wire_support.cpp
        payload/fixtures/test_workloads.cpp
        protocol/test_base_preprocessing_storage.cpp
        protocol/test_base_server_capacity.cpp
        setup/test_setup.cpp
        spartan/test_wiring_artifact.cpp
        storage/test_native_field_artifact.cpp)
endif()

foreach(source IN LISTS LAMINATE_MOCK_TEST_SOURCES)
    laminate_add_test("${source}")
endforeach()
