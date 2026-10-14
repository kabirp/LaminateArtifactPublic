if(NOT DEFINED BENCHMARK OR NOT DEFINED GIT_EXECUTABLE OR
   NOT DEFINED SOURCE_DIRECTORY OR NOT DEFINED EXPECTED_BUILD_TYPE OR
   NOT DEFINED EXPECTED_ACCELERATION OR
   NOT DEFINED EXPECTED_SHA256_ACCELERATION)
    message(FATAL_ERROR
            "benchmark build-info test inputs are incomplete")
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

set(required_keys
    format
    protocol.gkr_claim_transition
    protocol.gkr_multiplication
    environment.git_commit
    environment.git_dirty
    environment.build_type
    environment.seal_acceleration
    environment.sha256_acceleration
    campaign.target-balancedLaned.variants
    campaign.target-mulHeavyPyramid.variants
    profile.gate_mle)
foreach(key IN LISTS required_keys)
    string(MAKE_C_IDENTIFIER "${key}" identifier)
    set("count_${identifier}" 0)
endforeach()

string(REPLACE "\n" ";" build_info_lines "${build_info}")
foreach(line IN LISTS build_info_lines)
    if(NOT line MATCHES "^([^=]+)=(.*)$")
        message(FATAL_ERROR "malformed build_info line: ${line}")
    endif()
    set(key "${CMAKE_MATCH_1}")
    set(value "${CMAKE_MATCH_2}")
    list(FIND required_keys "${key}" required_key_index)
    if(required_key_index EQUAL -1)
        message(FATAL_ERROR "unexpected build_info key: ${key}")
    endif()
    string(MAKE_C_IDENTIFIER "${key}" identifier)
    math(EXPR "count_${identifier}" "${count_${identifier}} + 1")
    set("value_${identifier}" "${value}")
endforeach()

foreach(key IN LISTS required_keys)
    string(MAKE_C_IDENTIFIER "${key}" identifier)
    if(NOT count_${identifier} EQUAL 1)
        message(FATAL_ERROR
                "build_info must report ${key} exactly once")
    endif()
endforeach()

if(NOT value_format STREQUAL "laminate-base-checkpoint-build-info-v1")
    message(FATAL_ERROR "unexpected build_info format: ${value_format}")
endif()
if(NOT value_protocol_gkr_multiplication STREQUAL "gruen-stripped-h0-v1")
    message(FATAL_ERROR "unexpected GKR multiplication identity")
endif()
if(NOT value_protocol_gkr_claim_transition STREQUAL "selector-interpolation-v1")
    message(FATAL_ERROR "unexpected GKR claim transition")
endif()
if(NOT "${value_environment_git_commit}" STREQUAL "${source_commit}")
    message(FATAL_ERROR
            "executable commit ${value_environment_git_commit} does not match source ${source_commit}")
endif()
if(NOT "${value_environment_git_dirty}" STREQUAL "${source_dirty}")
    message(FATAL_ERROR
            "executable dirty=${value_environment_git_dirty} does not match source dirty=${source_dirty}")
endif()
if(NOT "${value_environment_build_type}" STREQUAL
       "${EXPECTED_BUILD_TYPE}")
    message(FATAL_ERROR
            "executable build type ${value_environment_build_type} does not match ${EXPECTED_BUILD_TYPE}")
endif()
if(NOT "${value_environment_seal_acceleration}" STREQUAL
       "${EXPECTED_ACCELERATION}")
    message(FATAL_ERROR
            "executable SEAL acceleration ${value_environment_seal_acceleration} does not match ${EXPECTED_ACCELERATION}")
endif()
if(NOT "${value_environment_sha256_acceleration}" STREQUAL
       "${EXPECTED_SHA256_ACCELERATION}")
    message(FATAL_ERROR
            "executable SHA-256 acceleration ${value_environment_sha256_acceleration} does not match ${EXPECTED_SHA256_ACCELERATION}")
endif()
if(NOT "${value_profile_gate_mle}" STREQUAL
       "wide-local-adjoint-foldable")
    message(FATAL_ERROR
            "unexpected GateMLE profile: ${value_profile_gate_mle}")
endif()
if(NOT "${value_campaign_target_balancedLaned_variants}" STREQUAL "base" OR
   NOT "${value_campaign_target_mulHeavyPyramid_variants}" STREQUAL "base")
    message(FATAL_ERROR "unexpected Base target campaign matrix")
endif()

# A valid profile must reach ordinary argument validation without starting a
# target setup. Both workloads must be admitted.
foreach(profile IN ITEMS target-balancedLaned target-mulHeavyPyramid
)
    execute_process(
        COMMAND "${BENCHMARK}" setup --variant base
                --profile "${profile}" --run-dir relative-path
        RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(status EQUAL 0 OR
       NOT "${output}${error}" MATCHES "absolute path below the filesystem root")
        message(FATAL_ERROR "Base rejected an admitted profile: ${output}${error}")
    endif()
endforeach()
