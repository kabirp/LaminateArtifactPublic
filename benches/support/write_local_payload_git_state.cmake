if(NOT DEFINED SOURCE_DIRECTORY OR NOT DEFINED OUTPUT_HEADER)
    message(FATAL_ERROR "missing local-payload git-state input")
endif()

set(commit "unknown")
set(dirty "unknown")
if(DEFINED GIT_EXECUTABLE AND NOT GIT_EXECUTABLE STREQUAL "")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --verify HEAD
        WORKING_DIRECTORY "${SOURCE_DIRECTORY}"
        RESULT_VARIABLE revision_result
        OUTPUT_VARIABLE revision
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" status --porcelain
                --untracked-files=normal
        WORKING_DIRECTORY "${SOURCE_DIRECTORY}"
        RESULT_VARIABLE status_result
        OUTPUT_VARIABLE status
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    string(LENGTH "${revision}" revision_length)
    if(revision_result EQUAL 0 AND status_result EQUAL 0 AND
       (revision_length EQUAL 40 OR revision_length EQUAL 64) AND
       revision MATCHES "^[0-9a-f]+$")
        set(commit "${revision}")
        if(status STREQUAL "")
            set(dirty "false")
        else()
            set(dirty "true")
        endif()
    endif()
endif()

set(contents
    "#define LAMINATE_LOCAL_PAYLOAD_GIT_COMMIT \"${commit}\"\n#define LAMINATE_LOCAL_PAYLOAD_GIT_DIRTY \"${dirty}\"\n")
get_filename_component(output_directory "${OUTPUT_HEADER}" DIRECTORY)
file(MAKE_DIRECTORY "${output_directory}")
set(previous "")
if(EXISTS "${OUTPUT_HEADER}")
    file(READ "${OUTPUT_HEADER}" previous)
endif()
if(NOT previous STREQUAL contents)
    file(WRITE "${OUTPUT_HEADER}" "${contents}")
endif()
