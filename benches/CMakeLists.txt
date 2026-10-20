find_package(Git QUIET)

# Standalone diagnostic builds tolerate missing Git metadata. The process
# benchmark executables additionally refresh their full revision at build
# time, and run_gcp.sh requires that revision to match a clean source snapshot.
# An extracted artifact therefore needs a local snapshot commit before the
# measured build; no remote repository is involved in that provenance check.
set(LAMINATE_BENCH_GIT_COMMIT "unknown")
set(LAMINATE_BENCH_GIT_DIRTY "unknown")
set(LAMINATE_BENCH_GIT_REVISION_AVAILABLE FALSE)
if(Git_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short=12 HEAD
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        RESULT_VARIABLE LAMINATE_BENCH_GIT_REVISION_RESULT
        OUTPUT_VARIABLE LAMINATE_BENCH_GIT_REVISION
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} status --porcelain --untracked-files=normal
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        RESULT_VARIABLE LAMINATE_BENCH_GIT_STATUS_RESULT
        OUTPUT_VARIABLE LAMINATE_BENCH_GIT_STATUS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    string(LENGTH "${LAMINATE_BENCH_GIT_REVISION}"
           LAMINATE_BENCH_GIT_REVISION_LENGTH)
    if(LAMINATE_BENCH_GIT_REVISION_RESULT EQUAL 0 AND
       LAMINATE_BENCH_GIT_STATUS_RESULT EQUAL 0 AND
       LAMINATE_BENCH_GIT_REVISION_LENGTH EQUAL 12 AND
       LAMINATE_BENCH_GIT_REVISION MATCHES "^[0-9a-f]+$")
        set(LAMINATE_BENCH_GIT_REVISION_AVAILABLE TRUE)
        set(LAMINATE_BENCH_GIT_COMMIT
            "${LAMINATE_BENCH_GIT_REVISION}")
        if(LAMINATE_BENCH_GIT_STATUS STREQUAL "")
            set(LAMINATE_BENCH_GIT_DIRTY "false")
        else()
            set(LAMINATE_BENCH_GIT_DIRTY "true")
        endif()
    endif()
endif()

function(laminate_add_benchmark target)
    add_executable(${target} ${ARGN})
    target_link_libraries(
        ${target} PRIVATE laminate_payload_fixture_support)
    target_include_directories(
        ${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/support")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
endfunction()

function(laminate_add_recorded_benchmark target)
    laminate_add_benchmark(${target} ${ARGN})
    target_compile_definitions(
        ${target} PRIVATE
        LAMINATE_GIT_COMMIT="${LAMINATE_BENCH_GIT_COMMIT}"
        LAMINATE_GIT_DIRTY="${LAMINATE_BENCH_GIT_DIRTY}"
        LAMINATE_BUILD_TYPE="$<CONFIG>"
        LAMINATE_COMPILER="${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}"
        LAMINATE_SEAL_VERSION="${LAMINATE_SEAL_VERSION}"
        LAMINATE_SEAL_ACCELERATION="${LAMINATE_SEAL_ACCELERATION}"
        LAMINATE_SHA256_ACCELERATION="${LAMINATE_SHA256_ACCELERATION}")
endfunction()

# Gate-only diagnostics isolate public-index setup and opening work from FHE.
laminate_add_recorded_benchmark(laminate_gate_mle_bench gates/gate_mle_benchmark.cpp)
if(BUILD_TESTING)
    add_test(NAME test_gate_mle_diagnostic_plan COMMAND laminate_gate_mle_bench --profile tiny --mode plan)
    add_test(NAME test_gate_mle_diagnostic_prove COMMAND laminate_gate_mle_bench --profile tiny --mode prove)
endif()

# The local comparison is intentionally not linked to liblaminate: a SEAL
# build makes that library transitively carry the accelerated FHE backend.
# Compile only the small payload IR/fixture surface it needs. Allow the
# compiler to optimize the scalar F_65537 implementation, including SIMD,
# and target the build host's instruction set for x86-64 benchmark runs.
add_executable(
    laminate_local_payload_bench
    protocol/local_payload_benchmark.cpp
    payload/local_scalar_evaluator.cpp
    ${PROJECT_SOURCE_DIR}/src/field/fp.cpp
    ${PROJECT_SOURCE_DIR}/src/fhe/layout/slot_grid.cpp
    ${PROJECT_SOURCE_DIR}/src/payload/circuit.cpp
    ${PROJECT_SOURCE_DIR}/src/payload/fixtures/workloads.cpp)
target_include_directories(
    laminate_local_payload_bench PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/payload"
    "${CMAKE_CURRENT_SOURCE_DIR}/support"
    "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(LAMINATE_LOCAL_PAYLOAD_ARCHITECTURE "non-x86-64")
set(LAMINATE_LOCAL_PAYLOAD_CPU_TARGET "compiler-default")
if(LAMINATE_TARGET_IS_X86_64)
    set(LAMINATE_LOCAL_PAYLOAD_ARCHITECTURE "x86-64")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set(LAMINATE_LOCAL_PAYLOAD_CPU_TARGET "native")
    endif()
endif()
set(LAMINATE_LOCAL_PAYLOAD_VECTORIZATION "unsupported-compiler")
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR
   CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(LAMINATE_LOCAL_PAYLOAD_VECTORIZATION "enabled")
endif()
target_compile_definitions(
    laminate_local_payload_bench PRIVATE
    LAMINATE_BUILD_TYPE="$<CONFIG>"
    LAMINATE_COMPILER="${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}"
    LAMINATE_LOCAL_PAYLOAD_ARCHITECTURE="${LAMINATE_LOCAL_PAYLOAD_ARCHITECTURE}"
    LAMINATE_LOCAL_PAYLOAD_CPU_TARGET="${LAMINATE_LOCAL_PAYLOAD_CPU_TARGET}"
    LAMINATE_LOCAL_PAYLOAD_VECTORIZATION="${LAMINATE_LOCAL_PAYLOAD_VECTORIZATION}")
target_compile_options(
    laminate_local_payload_bench PRIVATE -Wall -Wextra -Wpedantic)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(
        laminate_local_payload_bench PRIVATE
        -ftree-vectorize -ftree-slp-vectorize)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(
        laminate_local_payload_bench PRIVATE
        -fvectorize -fslp-vectorize)
endif()
if(LAMINATE_TARGET_IS_X86_64 AND
   CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(
        laminate_local_payload_bench PRIVATE
        -march=native -mtune=native)
endif()

set(LOCAL_PAYLOAD_GIT_STATE_HEADER
    "${CMAKE_CURRENT_BINARY_DIR}/generated/local_payload_git_state.hpp")
add_custom_target(
    laminate_local_payload_git_state
    COMMAND ${CMAKE_COMMAND}
            "-DGIT_EXECUTABLE=${GIT_EXECUTABLE}"
            "-DSOURCE_DIRECTORY=${PROJECT_SOURCE_DIR}"
            "-DOUTPUT_HEADER=${LOCAL_PAYLOAD_GIT_STATE_HEADER}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/support/write_local_payload_git_state.cmake
    BYPRODUCTS "${LOCAL_PAYLOAD_GIT_STATE_HEADER}"
    VERBATIM)
add_dependencies(laminate_local_payload_bench
                 laminate_local_payload_git_state)

laminate_add_recorded_benchmark(
    laminate_protocol_bench
    protocol/protocol_benchmark.cpp
    support/benchmark_support.hpp
    support/completed_result_report.hpp
    support/gate_mle_benchmark.hpp
    support/protocol_progress.hpp)
set(PROTOCOL_BENCHMARK_GIT_STATE_HEADER
    "${CMAKE_CURRENT_BINARY_DIR}/generated/protocol_git_state.hpp")
add_custom_target(
    laminate_protocol_benchmark_git_state
    COMMAND ${CMAKE_COMMAND}
            "-DGIT_EXECUTABLE=${GIT_EXECUTABLE}"
            "-DSOURCE_DIRECTORY=${PROJECT_SOURCE_DIR}"
            "-DOUTPUT_HEADER=${PROTOCOL_BENCHMARK_GIT_STATE_HEADER}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/support/write_protocol_git_state.cmake
    BYPRODUCTS "${PROTOCOL_BENCHMARK_GIT_STATE_HEADER}"
    VERBATIM)
add_dependencies(laminate_protocol_bench
                 laminate_protocol_benchmark_git_state)
target_include_directories(
    laminate_protocol_bench PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/generated")

laminate_add_benchmark(
    laminate_target_cost_report
    reports/target_cost_report.cpp
    support/benchmark_support.hpp)

laminate_add_benchmark(
    laminate_packing_relation_size_report
    reports/packing_relation_size_report.cpp)

laminate_add_benchmark(
    laminate_base_report_summary
    reports/base_report_summary.cpp
    support/run_lifecycle_lock.hpp)

add_executable(
    laminate_benchmark_cleanup
    tools/benchmark_cleanup.cpp
    support/run_lifecycle_lock.hpp)
target_include_directories(
    laminate_benchmark_cleanup PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/support")
target_compile_options(
    laminate_benchmark_cleanup PRIVATE -Wall -Wextra -Wpedantic)

if(BUILD_TESTING)
    find_program(LAMINATE_PYTHON3_EXECUTABLE python3)
    if(LAMINATE_PYTHON3_EXECUTABLE)
        add_test(
            NAME benchmark_safe_stop
            COMMAND ${LAMINATE_PYTHON3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_stop_benchmark_run.py)
        set_tests_properties(benchmark_safe_stop PROPERTIES TIMEOUT 30)
    endif()
    add_test(
        NAME benchmark_operator_tools
        COMMAND ${CMAKE_COMMAND}
                -DRENDERER=$<TARGET_FILE:laminate_base_report_summary>
                "-DCONCISE_RENDERER=${CMAKE_CURRENT_SOURCE_DIR}/support/render_concise_summary.py"
                -DCLEANUP=$<TARGET_FILE:laminate_benchmark_cleanup>
                -DFIXTURE=${CMAKE_CURRENT_SOURCE_DIR}/reports/testdata/split-quick
                -DTARGET_FIXTURE=${CMAKE_CURRENT_SOURCE_DIR}/reports/testdata/split-target-balancedLaned
                -P ${CMAKE_CURRENT_SOURCE_DIR}/reports/test_benchmark_operator_tools.cmake)
    find_program(LAMINATE_BASH_EXECUTABLE bash)
    if(LAMINATE_BASH_EXECUTABLE)
        function(laminate_add_build_info_schema_test runner_kind target)
            add_test(
                NAME ${runner_kind}_build_info_schema
                COMMAND ${LAMINATE_BASH_EXECUTABLE}
                        ${CMAKE_CURRENT_SOURCE_DIR}/support/test_checkpoint_build_info_schema.sh
                        ${CMAKE_CURRENT_SOURCE_DIR}/support/checkpoint_build_info.sh
                        ${runner_kind}
                        $<TARGET_FILE:${target}>)
            set_tests_properties(${runner_kind}_build_info_schema
                                 PROPERTIES TIMEOUT 30)
        endfunction()
        laminate_add_build_info_schema_test(local laminate_local_payload_bench)
        add_test(
            NAME local_payload_benchmark
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_local_payload_benchmark.sh
                    $<TARGET_FILE:laminate_local_payload_bench>
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/render_local_payload_summary.py
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/render_concise_summary.py)
        add_test(
            NAME setup_heartbeat
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_setup_heartbeat.sh
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/setup_heartbeat.sh)
        add_test(
            NAME gcp_profile_contract
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_gcp_profile_contract.sh
                    ${CMAKE_CURRENT_SOURCE_DIR}/run_gcp.sh
                    ${PROJECT_SOURCE_DIR}/docs/GCP_BENCHMARKS.md)
        add_test(
            NAME target_storage_contract
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_target_storage_contract.sh
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/target_storage_contract.sh)
        add_test(
            NAME local_ssd_preparation_contract
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_local_ssd_preparation_contract.sh
                    ${CMAKE_CURRENT_SOURCE_DIR}/prepare_gcp_local_ssds.sh)
        add_test(
            NAME hyperdisk_preparation_contract
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_hyperdisk_preparation_contract.sh
                    ${CMAKE_CURRENT_SOURCE_DIR}/prepare_gcp_hyperdisk.sh)
        add_test(
            NAME root_storage_preparation_contract
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_root_storage_preparation_contract.sh
                    ${CMAKE_CURRENT_SOURCE_DIR}/prepare_gcp_root_storage.sh)
        add_test(
            NAME completed_run_archive
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_archive_completed_run.sh
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/archive_completed_run.sh)
    endif()
endif()

laminate_add_benchmark(
    laminate_protocol_report_summary
    reports/protocol_report_summary.cpp)

laminate_add_recorded_benchmark(
    laminate_spartan_scaling_bench
    reports/spartan_scaling_benchmark.cpp
    support/benchmark_support.hpp)

laminate_add_recorded_benchmark(
    laminate_basefold_native_kernels_bench
    reports/basefold_native_kernels_benchmark.cpp
    support/benchmark_support.hpp)

laminate_add_recorded_benchmark(
    laminate_basefold_rate_tradeoff_bench
    reports/basefold_rate_tradeoff_benchmark.cpp
    support/benchmark_support.hpp)

if(BUILD_TESTING)
    add_test(
        NAME basefold_native_kernels_benchmark_smoke
        COMMAND laminate_basefold_native_kernels_bench
                --log-elements 10
                --max-log-ntt 10
                --iterations 1
                --working-directory ${CMAKE_CURRENT_BINARY_DIR})
    add_test(
        NAME basefold_rate_tradeoff_benchmark_smoke
        COMMAND laminate_basefold_rate_tradeoff_bench
                --log-elements 8
                --iterations 1)
    set_tests_properties(basefold_rate_tradeoff_benchmark_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION
            "target.inverse_rate_eight_queries_150.rbr_error_bits=110")
endif()

laminate_add_recorded_benchmark(
    laminate_hybrid_tensor_bench
    reports/hybrid_tensor_benchmark.cpp
    support/benchmark_support.hpp)

laminate_add_recorded_benchmark(
    laminate_plaintext_payload_bench
    payload/plaintext_payload_benchmark.cpp
    support/benchmark_support.hpp)

laminate_add_recorded_benchmark(
    laminate_payload_storage_bench
    storage/file_trace_store_benchmark.cpp)

laminate_add_recorded_benchmark(
    laminate_payload_storage_duplex_bench
    storage/file_trace_store_duplex_benchmark.cpp)

if(BUILD_TESTING)
    add_test(
        NAME payload_storage_duplex_benchmark_smoke
        COMMAND laminate_payload_storage_duplex_bench
                --directory
                ${CMAKE_CURRENT_BINARY_DIR}/payload-storage-duplex-smoke
                --transfer-mib 1
                --source-mib 8
                --record-kib 1024
                --writeback-mib 0)
endif()

laminate_add_recorded_benchmark(
    laminate_outer_relation_rows_bench
    packing/outer_relation_rows_benchmark.cpp
    support/benchmark_support.hpp)

laminate_add_recorded_benchmark(
    laminate_outer_relation_assignment_bench
    packing/outer_relation_assignment_benchmark.cpp
    support/benchmark_support.hpp)

if(LAMINATE_WITH_SEAL)
    laminate_add_recorded_benchmark(
        laminate_no_integrity_bench
        protocol/no_integrity_benchmark.cpp
        support/benchmark_support.hpp
        support/completed_result_report.hpp
        support/protocol_progress.hpp
        support/run_lifecycle_lock.hpp)
    set(NO_INTEGRITY_GIT_STATE_HEADER
        "${CMAKE_CURRENT_BINARY_DIR}/generated/no_integrity_git_state.hpp")
    add_custom_target(
        laminate_no_integrity_git_state
        COMMAND ${CMAKE_COMMAND}
                "-DGIT_EXECUTABLE=${GIT_EXECUTABLE}"
                "-DSOURCE_DIRECTORY=${PROJECT_SOURCE_DIR}"
                "-DOUTPUT_HEADER=${NO_INTEGRITY_GIT_STATE_HEADER}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/support/write_no_integrity_git_state.cmake
        BYPRODUCTS "${NO_INTEGRITY_GIT_STATE_HEADER}"
        VERBATIM)
    add_dependencies(laminate_no_integrity_bench
                     laminate_no_integrity_git_state)
    target_include_directories(
        laminate_no_integrity_bench PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated")
    if(BUILD_TESTING AND Git_FOUND)
        add_test(
            NAME no_integrity_build_info
            COMMAND ${CMAKE_COMMAND}
                    -DBENCHMARK=$<TARGET_FILE:laminate_no_integrity_bench>
                    -DGIT_EXECUTABLE=${GIT_EXECUTABLE}
                    -DSOURCE_DIRECTORY=${PROJECT_SOURCE_DIR}
                    -DEXPECTED_BUILD_TYPE=$<CONFIG>
                    -DEXPECTED_ACCELERATION=${LAMINATE_SEAL_ACCELERATION}
                    -DEXPECTED_SHA256_ACCELERATION=${LAMINATE_SHA256_ACCELERATION}
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/support/test_no_integrity_build_info.cmake)
    endif()
    if(BUILD_TESTING AND LAMINATE_BASH_EXECUTABLE)
        laminate_add_build_info_schema_test(noIntegrity laminate_no_integrity_bench)
        add_test(
            NAME no_integrity_live_status
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_no_integrity_live_status.sh
                    $<TARGET_FILE:laminate_no_integrity_bench>)
        add_test(
            NAME no_integrity_summary_renderer
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_no_integrity_summary_renderer.sh
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/render_no_integrity_summary.py
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/render_concise_summary.py)
    endif()

    laminate_add_recorded_benchmark(
        laminate_packed_checkpoint_bench
        protocol/packed_checkpoint_benchmark.cpp
        support/benchmark_support.hpp
        support/completed_result_report.hpp
        support/protocol_progress.hpp
        support/run_lifecycle_lock.hpp)
    set(PACKED_CHECKPOINT_GIT_STATE_HEADER
        "${CMAKE_CURRENT_BINARY_DIR}/generated/packed_checkpoint_git_state.hpp")
    add_custom_target(
        laminate_packed_checkpoint_git_state
        COMMAND ${CMAKE_COMMAND}
                "-DGIT_EXECUTABLE=${GIT_EXECUTABLE}"
                "-DSOURCE_DIRECTORY=${PROJECT_SOURCE_DIR}"
                "-DOUTPUT_HEADER=${PACKED_CHECKPOINT_GIT_STATE_HEADER}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/support/write_packed_checkpoint_git_state.cmake
        BYPRODUCTS "${PACKED_CHECKPOINT_GIT_STATE_HEADER}"
        VERBATIM)
    add_dependencies(laminate_packed_checkpoint_bench
                     laminate_packed_checkpoint_git_state)
    target_include_directories(
        laminate_packed_checkpoint_bench PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated")
    if(BUILD_TESTING)
        laminate_add_recorded_benchmark(
            laminate_packed_setup_accounting_test
            support/test_packed_setup_accounting.cpp)
        target_include_directories(laminate_packed_setup_accounting_test PRIVATE
            "${CMAKE_CURRENT_BINARY_DIR}/generated"
            "${PROJECT_SOURCE_DIR}/tests/support")
        add_dependencies(laminate_packed_setup_accounting_test
            laminate_packed_checkpoint_git_state)
        add_test(NAME packed_setup_accounting
            COMMAND laminate_packed_setup_accounting_test)
        set_tests_properties(packed_setup_accounting PROPERTIES TIMEOUT 60)
    endif()
    if(BUILD_TESTING AND Git_FOUND)
        add_test(
            NAME packed_checkpoint_build_info
            COMMAND ${CMAKE_COMMAND}
                    -DBENCHMARK=$<TARGET_FILE:laminate_packed_checkpoint_bench>
                    -DGIT_EXECUTABLE=${GIT_EXECUTABLE}
                    -DSOURCE_DIRECTORY=${PROJECT_SOURCE_DIR}
                    -DEXPECTED_BUILD_TYPE=$<CONFIG>
                    -DEXPECTED_ACCELERATION=${LAMINATE_SEAL_ACCELERATION}
                    -DEXPECTED_SHA256_ACCELERATION=${LAMINATE_SHA256_ACCELERATION}
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/support/test_packed_checkpoint_build_info.cmake)
    endif()
    if(BUILD_TESTING AND LAMINATE_BASH_EXECUTABLE)
        laminate_add_build_info_schema_test(packed laminate_packed_checkpoint_bench)
        add_test(
            NAME packed_checkpoint_live_status
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_packed_live_status.sh
                    $<TARGET_FILE:laminate_packed_checkpoint_bench>)
        add_test(
            NAME packed_checkpoint_summary_renderer
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_packed_summary_renderer.sh
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/render_packed_checkpoint_summary.py
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/render_concise_summary.py)
    endif()

    laminate_add_recorded_benchmark(
        laminate_base_checkpoint_bench
        protocol/base_checkpoint_benchmark.cpp
        support/benchmark_support.hpp
        support/completed_result_report.hpp
        support/protocol_progress.hpp
        support/run_lifecycle_lock.hpp)
    set(BASE_CHECKPOINT_GIT_STATE_HEADER
        "${CMAKE_CURRENT_BINARY_DIR}/generated/base_checkpoint_git_state.hpp")
    add_custom_target(
        laminate_base_checkpoint_git_state
        COMMAND ${CMAKE_COMMAND}
                "-DGIT_EXECUTABLE=${GIT_EXECUTABLE}"
                "-DSOURCE_DIRECTORY=${PROJECT_SOURCE_DIR}"
                "-DOUTPUT_HEADER=${BASE_CHECKPOINT_GIT_STATE_HEADER}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/support/write_base_checkpoint_git_state.cmake
        BYPRODUCTS "${BASE_CHECKPOINT_GIT_STATE_HEADER}"
        VERBATIM)
    add_dependencies(laminate_base_checkpoint_bench
                     laminate_base_checkpoint_git_state)
    target_include_directories(
        laminate_base_checkpoint_bench PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated")
    if(BUILD_TESTING AND CMAKE_BUILD_TYPE STREQUAL "Release")
        # Recovery intentionally accepts only recorded Release preprocessing.
        laminate_add_recorded_benchmark(
            laminate_base_setup_recovery_test
            support/test_base_setup_recovery.cpp)
        target_include_directories(laminate_base_setup_recovery_test PRIVATE
            "${CMAKE_CURRENT_BINARY_DIR}/generated"
            "${PROJECT_SOURCE_DIR}/tests/support")
        add_dependencies(laminate_base_setup_recovery_test
            laminate_base_checkpoint_git_state)
        add_test(NAME base_setup_recovery
            COMMAND laminate_base_setup_recovery_test)
        set_tests_properties(base_setup_recovery PROPERTIES TIMEOUT 180)
        laminate_add_recorded_benchmark(
            laminate_base_saved_response_verification_test
            support/test_base_saved_response_verification.cpp)
        target_include_directories(laminate_base_saved_response_verification_test PRIVATE
            "${CMAKE_CURRENT_BINARY_DIR}/generated"
            "${PROJECT_SOURCE_DIR}/tests/support")
        add_dependencies(laminate_base_saved_response_verification_test
            laminate_base_checkpoint_git_state)
        add_test(NAME base_saved_response_verification
            COMMAND laminate_base_saved_response_verification_test)
        set_tests_properties(base_saved_response_verification PROPERTIES TIMEOUT 180)
        laminate_add_recorded_benchmark(
            laminate_base_target_noise_preflight_test
            support/test_base_target_noise_preflight.cpp)
        target_include_directories(laminate_base_target_noise_preflight_test PRIVATE
            "${CMAKE_CURRENT_BINARY_DIR}/generated")
        add_dependencies(laminate_base_target_noise_preflight_test
            laminate_base_checkpoint_git_state)
        laminate_add_recorded_benchmark(
            laminate_folded_target_noise_preflight_test
            support/test_folded_target_noise_preflight.cpp)
        add_test(NAME folded_target_pyramid_live_key_preflight_seal
            COMMAND laminate_folded_target_noise_preflight_test)
        set_tests_properties(folded_target_pyramid_live_key_preflight_seal PROPERTIES
            LABELS "seal;target-noise" TIMEOUT 1200 RUN_SERIAL TRUE)
        add_test(NAME base_target_pyramid_noise_seal
            COMMAND laminate_base_target_noise_preflight_test current)
        add_test(NAME base_target_pyramid_insufficient_noise_rejection
            COMMAND laminate_base_target_noise_preflight_test insufficient-noise)
        set_tests_properties(base_target_pyramid_noise_seal
            base_target_pyramid_insufficient_noise_rejection PROPERTIES
            LABELS "seal;target-noise" TIMEOUT 600 RUN_SERIAL TRUE)
    endif()
    if(BUILD_TESTING)
        laminate_add_recorded_benchmark(
            laminate_base_setup_resource_test
            protocol/base_checkpoint_benchmark.cpp)
        target_compile_definitions(laminate_base_setup_resource_test
            PRIVATE LAMINATE_BASE_CAPACITY_TEST=1)
        target_include_directories(laminate_base_setup_resource_test
            PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
        add_dependencies(laminate_base_setup_resource_test
            laminate_base_checkpoint_git_state)
        foreach(profile quick target-balancedLaned target-mulHeavyPyramid)
            add_test(NAME base_setup_capacity_${profile}
                COMMAND laminate_base_setup_resource_test ${profile})
            set_tests_properties(base_setup_capacity_${profile}
                PROPERTIES TIMEOUT 180)
        endforeach()
        laminate_add_recorded_benchmark(
            laminate_packed_setup_resource_test
            protocol/packed_checkpoint_benchmark.cpp)
        target_compile_definitions(laminate_packed_setup_resource_test
            PRIVATE LAMINATE_PACKED_CAPACITY_TEST=1)
        target_include_directories(laminate_packed_setup_resource_test
            PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
        add_dependencies(laminate_packed_setup_resource_test
            laminate_packed_checkpoint_git_state)
        function(laminate_add_packed_capacity_test name variant tier lanes)
            add_test(NAME packed_setup_capacity_${name}
                COMMAND laminate_packed_setup_resource_test ${variant} ${tier} ${lanes})
            set_tests_properties(packed_setup_capacity_${name} PROPERTIES TIMEOUT 300)
        endfunction()
        laminate_add_packed_capacity_test(folded_quick folded 0 0)
        laminate_add_packed_capacity_test(folded_balanced folded 1 0)
        laminate_add_packed_capacity_test(folded_pyramid folded 2 0)
        foreach(lanes 1 128 16384)
            laminate_add_packed_capacity_test(laned_quick_${lanes} laned 0 ${lanes})
            laminate_add_packed_capacity_test(laned_balanced_${lanes} laned 1 ${lanes})
        endforeach()
    endif()
    if(BUILD_TESTING AND Git_FOUND)
        add_test(
            NAME base_checkpoint_build_info
            COMMAND ${CMAKE_COMMAND}
                    -DBENCHMARK=$<TARGET_FILE:laminate_base_checkpoint_bench>
                    -DGIT_EXECUTABLE=${GIT_EXECUTABLE}
                    -DSOURCE_DIRECTORY=${PROJECT_SOURCE_DIR}
                    -DEXPECTED_BUILD_TYPE=$<CONFIG>
                    -DEXPECTED_ACCELERATION=${LAMINATE_SEAL_ACCELERATION}
                    -DEXPECTED_SHA256_ACCELERATION=${LAMINATE_SHA256_ACCELERATION}
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/support/test_base_checkpoint_build_info.cmake)
    endif()
    if(BUILD_TESTING AND LAMINATE_BASH_EXECUTABLE)
        laminate_add_build_info_schema_test(base laminate_base_checkpoint_bench)
        add_test(
            NAME base_live_status
            COMMAND ${LAMINATE_BASH_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/support/test_base_live_status.sh
                    $<TARGET_FILE:laminate_base_checkpoint_bench>)
    endif()

    laminate_add_recorded_benchmark(
        laminate_laned_payload_bench
        payload/laned_payload_benchmark.cpp
        support/benchmark_support.hpp)

    laminate_add_recorded_benchmark(
        laminate_laned_source_packing_bench
        reports/laned_source_packing_benchmark.cpp
        support/benchmark_support.hpp)
    set(LANED_SOURCE_PACKING_GIT_STATE_HEADER
        "${CMAKE_CURRENT_BINARY_DIR}/generated/laned_source_packing_git_state.hpp")
    add_custom_target(
        laminate_laned_source_packing_git_state
        COMMAND ${CMAKE_COMMAND}
                "-DGIT_EXECUTABLE=${GIT_EXECUTABLE}"
                "-DSOURCE_DIRECTORY=${PROJECT_SOURCE_DIR}"
                "-DOUTPUT_HEADER=${LANED_SOURCE_PACKING_GIT_STATE_HEADER}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/support/write_protocol_git_state.cmake
        BYPRODUCTS "${LANED_SOURCE_PACKING_GIT_STATE_HEADER}"
        VERBATIM)
    add_dependencies(laminate_laned_source_packing_bench
                     laminate_laned_source_packing_git_state)
    target_include_directories(
        laminate_laned_source_packing_bench PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated")

    if(BUILD_TESTING)
        add_test(
            NAME laned_source_packing_benchmark_smoke
            COMMAND laminate_laned_source_packing_bench
                    --slots 1024
                    --lanes 1
                    --source-values 8
                    --natural-rns-limbs 7
                    --ingress-rns-limbs 5
                    --packed-rns-limbs 4
                    --iterations 1)
    endif()

    laminate_add_recorded_benchmark(
        laminate_seal_honest_noise_calibration
        reports/seal_honest_noise_calibration.cpp
        support/benchmark_support.hpp)

    laminate_add_recorded_benchmark(
        laminate_seal_preprocessing_ownership
        reports/seal_preprocessing_ownership.cpp
        support/benchmark_support.hpp)


    laminate_add_benchmark(
        laminate_packing_capacity_report
        packing/packing_capacity_report.cpp)

    laminate_add_recorded_benchmark(
        laminate_outer_relation_packing_matrix_bench
        packing/outer_relation_packing_matrix_benchmark.cpp
        support/benchmark_support.hpp)
endif()
