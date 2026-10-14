cmake_policy(SET CMP0057 NEW)

if(NOT DEFINED BENCHMARK OR NOT DEFINED GIT_EXECUTABLE OR
   NOT DEFINED SOURCE_DIRECTORY OR NOT DEFINED EXPECTED_BUILD_TYPE OR
   NOT DEFINED EXPECTED_ACCELERATION OR
   NOT DEFINED EXPECTED_SHA256_ACCELERATION)
    message(FATAL_ERROR "packed build-info test inputs are incomplete")
endif()

execute_process(
    COMMAND "${BENCHMARK}" build_info
    RESULT_VARIABLE benchmark_status
    OUTPUT_VARIABLE build_info
    ERROR_VARIABLE benchmark_error
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT benchmark_status EQUAL 0)
    message(FATAL_ERROR "build_info failed: ${benchmark_error}")
endif()

execute_process(
    COMMAND "${GIT_EXECUTABLE}" rev-parse --verify HEAD
    WORKING_DIRECTORY "${SOURCE_DIRECTORY}"
    RESULT_VARIABLE revision_status
    OUTPUT_VARIABLE source_commit
    ERROR_VARIABLE revision_error
    OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(
    COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=normal
    WORKING_DIRECTORY "${SOURCE_DIRECTORY}"
    RESULT_VARIABLE source_status
    OUTPUT_VARIABLE source_changes
    ERROR_VARIABLE status_error
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT revision_status EQUAL 0)
    message(FATAL_ERROR "cannot read source revision: ${revision_error}")
endif()
if(NOT source_status EQUAL 0)
    message(FATAL_ERROR "cannot inspect source status: ${status_error}")
endif()
if(source_changes STREQUAL "")
    set(source_dirty false)
else()
    set(source_dirty true)
endif()

set(required
    "format=laminate-packed-checkpoint-build-info-v1"
    "environment.git_commit=${source_commit}"
    "environment.git_dirty=${source_dirty}"
    "environment.build_type=${EXPECTED_BUILD_TYPE}"
    "environment.seal_acceleration=${EXPECTED_ACCELERATION}"
    "environment.sha256_acceleration=${EXPECTED_SHA256_ACCELERATION}"
    "protocol.variants=folded,laned"
    "protocol.exchange=one-request-one-response"
    "protocol.fiat_shamir=single-transcript-gkr-then-packing-v1"
    "protocol.gkr_claim_transition=selector-interpolation-v1"
    "protocol.gkr_multiplication=gruen-stripped-h0-v1"
    "schedule.policy=committed-conservative-no-search"
    "campaign.target-balancedLaned.variants=folded,laned"
    "campaign.target-mulHeavyPyramid.variants=folded"
    "campaign.laned.lanes=1,128,16384"
    "profile.quick.packing_repetitions=4"
    "profile.target-balancedLaned.packing_repetitions=120"
    "profile.target-mulHeavyPyramid.packing_repetitions=120"
    "profile.quick.basefold_queries=4"
    "profile.target-balancedLaned.basefold_queries=150"
    "profile.target-mulHeavyPyramid.basefold_queries=150"
    "profile.basefold_log_rate=3"
    "profile.gate_mle=folded:wide-local-adjoint-foldable,laned:structured-sparse-basefold"
    "profile.quick.ciphertext_hash=simpleCTHash/v2"
    "profile.target-balancedLaned.ciphertext_hash=poseidon/v2"
    "profile.target-mulHeavyPyramid.ciphertext_hash=poseidon/v2"
    "profile.target-balancedLaned.admitted=true"
    "profile.target-mulHeavyPyramid.admitted=true")

string(REPLACE "\n" ";" lines "${build_info}")
list(LENGTH lines line_count)
list(LENGTH required required_count)
if(NOT line_count EQUAL required_count)
    message(FATAL_ERROR
            "build_info emitted ${line_count} lines; expected ${required_count}:\n${build_info}")
endif()
foreach(expected IN LISTS required)
    set(matches 0)
    foreach(line IN LISTS lines)
        if(line STREQUAL expected)
            math(EXPR matches "${matches} + 1")
        endif()
    endforeach()
    if(NOT matches EQUAL 1)
        message(FATAL_ERROR
                "build_info must emit exactly once: ${expected}\n${build_info}")
    endif()
endforeach()

# Folded admits both targets. Every Laned width must reject mulHeavy before
# creating artifacts, even when the caller bypasses the shell wrapper.
foreach(action IN ITEMS setup run_client run_server)
    foreach(lanes IN ITEMS 1 128 16384)
        set(selector "laned-${lanes}")
        set(variant laned)
        set(profile target-mulHeavyPyramid)
        set(lane_arguments --lanes "${lanes}")
        set(rejected_run "${CMAKE_CURRENT_BINARY_DIR}/packed-off-campaign-${action}-${selector}")
        execute_process(
            COMMAND "${BENCHMARK}" "${action}" --variant "${variant}"
                    --profile "${profile}" --run-dir "${rejected_run}" ${lane_arguments}
            RESULT_VARIABLE rejected_status OUTPUT_VARIABLE rejected_output
            ERROR_VARIABLE rejected_error)
        if(rejected_status EQUAL 0 OR
           NOT "${rejected_output}${rejected_error}" MATCHES "current benchmark campaign" OR
           EXISTS "${rejected_run}")
            message(FATAL_ERROR
                    "${selector} ${action} did not reject off-campaign execution before artifacts: ${rejected_output}${rejected_error}")
        endif()
    endforeach()
endforeach()
