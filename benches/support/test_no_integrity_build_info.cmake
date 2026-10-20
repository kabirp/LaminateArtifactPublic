cmake_policy(SET CMP0057 NEW)

if(NOT DEFINED BENCHMARK OR NOT DEFINED GIT_EXECUTABLE OR
   NOT DEFINED SOURCE_DIRECTORY OR NOT DEFINED EXPECTED_BUILD_TYPE OR
   NOT DEFINED EXPECTED_ACCELERATION OR
   NOT DEFINED EXPECTED_SHA256_ACCELERATION)
    message(FATAL_ERROR "noIntegrity build-info test inputs are incomplete")
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
    "format=laminate-no-integrity-build-info-v1"
    "environment.git_commit=${source_commit}"
    "environment.git_dirty=${source_dirty}"
    "environment.build_type=${EXPECTED_BUILD_TYPE}"
    "environment.seal_acceleration=${EXPECTED_ACCELERATION}"
    "environment.sha256_acceleration=${EXPECTED_SHA256_ACCELERATION}"
    "benchmark.variant=noIntegrity"
    "protocol.integrity=none"
    "protocol.exchange=one-request-one-response"
    "fhe.switch_policy=one-after-each-ctct-multiplication-layer"
    "fhe.target_data_limbs=9")

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
