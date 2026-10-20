# Use the ordinary synthetic role records, replacing only the client with a
# separately measured, authenticated saved-response result.
set(saved_root "${CMAKE_CURRENT_BINARY_DIR}/base-saved-summary-fixtures")
file(REMOVE_RECURSE "${saved_root}")
foreach(saved_profile IN ITEMS quick target-balancedLaned)
    set(saved_source "${saved_root}/${saved_profile}-source")
    set(saved_diagnostic "${saved_root}/${saved_profile}-diagnostic")
    file(MAKE_DIRECTORY "${saved_source}" "${saved_diagnostic}")
    if(saved_profile STREQUAL quick)
        file(COPY "${source_fixture}/" DESTINATION "${saved_source}")
        set(saved_run_id "report-renderer-fixture")
    else()
        file(COPY "${source_target_fixture}/" DESTINATION "${saved_source}")
        set(saved_run_id "target-report-renderer-fixture")
    endif()
    file(READ "${saved_source}/client/result.txt" saved_client)
    string(REPLACE "format=laminate-benchmark-client-v2"
                   "format=laminate-base-saved-response-diagnostic-v1"
                   saved_client "${saved_client}")
    string(REPLACE "environment.git_commit=0123456789ab"
                   "environment.git_commit=fedcba9876543210"
                   saved_client "${saved_client}")
    string(REGEX REPLACE
        "timing\\.client\\.(started_unix_ms|request_published_unix_ms|finished_unix_ms|process_total\\.[^=\n]+|wait_for_response\\.[^=\n]+|bind_session\\.[^=\n]+|encode_request\\.[^=\n]+|publish_request\\.[^=\n]+)=[^\n]*\n"
        "" saved_client "${saved_client}")
    string(REGEX REPLACE "parameters\\.[^=\n]+=[^\n]*\n" "" saved_client "${saved_client}")
    file(REMOVE "${saved_source}/client/result.txt")
    file(WRITE "${saved_source}/client/process-exit.txt" "process.exit_status=1\n")
    file(WRITE "${saved_source}/client/failure.txt"
        "FAILED: decode_base_response: Wide public target values exceed limit\n")
    file(WRITE "${saved_source}/shared/lifecycle.lock" "")
    file(WRITE "${saved_source}/shared/setup.bin" "synthetic setup\n")
    file(MAKE_DIRECTORY "${saved_source}/shared/transcript")
    file(WRITE "${saved_source}/shared/transcript/cli-to-srv-request.bin" "synthetic request\n")
    file(WRITE "${saved_source}/shared/transcript/srv-to-cli-response.bin" "synthetic response\n")
    file(WRITE "${saved_source}/shared/run-binding.txt"
        "format=laminate-benchmark-run-v1\nrun.variant=base\nrun.profile=${saved_profile}\nrun.id=${saved_run_id}\n")
    file(SHA256 "${saved_source}/shared/setup.bin" saved_setup_hash)
    file(SHA256 "${saved_source}/shared/transcript/cli-to-srv-request.bin" saved_request_hash)
    file(SHA256 "${saved_source}/shared/transcript/srv-to-cli-response.bin" saved_response_hash)
    string(APPEND saved_client
        "recovery.kind=saved-response-client-remeasurement-v1\n"
        "source.run_id=${saved_run_id}\n"
        "diagnostic.result=PASS\n"
        "request.sha256=${saved_request_hash}\nresponse.sha256=${saved_response_hash}\n")
    file(WRITE "${saved_diagnostic}/result.txt" "${saved_client}")
    file(WRITE "${saved_diagnostic}/process-exit.txt" "process.exit_status=0\n")
    file(WRITE "${saved_diagnostic}/provenance.txt"
        "format=laminate-base-saved-response-diagnostic-v1\n"
        "source.run_directory=${saved_source}\nsource.run_id=${saved_run_id}\n"
        "source.profile=${saved_profile}\nsource.git_commit=0123456789ab\n"
        "source.setup_sha256=${saved_setup_hash}\n")
    file(CHMOD_RECURSE "${saved_root}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
    file(CHMOD "${saved_source}/shared/lifecycle.lock" PERMISSIONS OWNER_READ OWNER_WRITE)
    file(GLOB_RECURSE saved_before_files RELATIVE "${saved_source}" "${saved_source}/*")
    set(saved_before_hashes "")
    foreach(saved_file IN LISTS saved_before_files)
        file(SHA256 "${saved_source}/${saved_file}" saved_hash)
        string(APPEND saved_before_hashes "${saved_file}:${saved_hash}\n")
    endforeach()
    execute_process(COMMAND "${RENDERER}" --run-dir "${saved_source}"
        --saved-response-dir "${saved_diagnostic}" --variant base --profile "${saved_profile}"
        --output "${saved_diagnostic}/summary.full.md"
        RESULT_VARIABLE saved_status ERROR_VARIABLE saved_error)
    if(NOT saved_status EQUAL 0)
        message(FATAL_ERROR "saved-response summary failed: ${saved_error}")
    endif()
    file(READ "${saved_diagnostic}/summary.full.md" saved_full)
    foreach(required IN ITEMS "<!-- laminate-base-saved-response-v1 -->"
        "## Client computation" "## Server FHE operation ledger"
        "| Client process elapsed (including response wait) | not reported |"
        "| Request-to-verification elapsed | not reported |"
        "| Observed run span | not reported; includes any operator gap")
        string(FIND "${saved_full}" "${required}" saved_found)
        if(saved_found EQUAL -1)
            message(FATAL_ERROR "saved-response summary missing ${required}")
        endif()
    endforeach()
    # The quick fixture includes the full layer/round ledger required by the
    # concise report. The target fixture checks geometry and capacity.
    if(saved_profile STREQUAL quick)
    execute_process(COMMAND python3 "${CONCISE_RENDERER}"
        --input "${saved_diagnostic}/summary.full.md" --output "${saved_diagnostic}/summary.md"
        --run-dir "${saved_source}" --variant base --profile "${saved_profile}"
        RESULT_VARIABLE saved_status ERROR_VARIABLE saved_error)
    if(NOT saved_status EQUAL 0)
        message(FATAL_ERROR "saved-response concise summary failed: ${saved_error}")
    endif()
    file(READ "${saved_diagnostic}/summary.md" saved_concise)
    foreach(required IN ITEMS "**PASS** — setup, server, and client completed"
        "## Highlights" "## Client computation" "## Client verifier details"
        "## Server layer reductions" "## Server FHE operation ledger")
        string(FIND "${saved_concise}" "${required}" saved_found)
        if(saved_found EQUAL -1)
            message(FATAL_ERROR "saved-response concise summary missing ${required}")
        endif()
    endforeach()
    if(saved_concise MATCHES "##[^\n]*[Rr]ecover|Original run remains")
        message(FATAL_ERROR "saved-response summary changed the normal presentation")
    endif()
    endif()
    # A normal invocation still rejects the failed source. The explicit mode
    # must reject a changed transcript and must never publish into the source.
    execute_process(COMMAND "${RENDERER}" --run-dir "${saved_source}"
        RESULT_VARIABLE saved_status OUTPUT_QUIET ERROR_QUIET)
    if(saved_status EQUAL 0)
        message(FATAL_ERROR "ordinary renderer accepted the failed original client")
    endif()
    foreach(mutation IN ITEMS transcript identity nonzero-exit historical-timing)
        if(mutation STREQUAL transcript)
            file(APPEND "${saved_source}/shared/transcript/srv-to-cli-response.bin" "changed\n")
        elseif(mutation STREQUAL identity)
            string(REPLACE "source.run_id=${saved_run_id}" "source.run_id=other"
                           saved_mutated "${saved_client}")
            file(WRITE "${saved_diagnostic}/result.txt" "${saved_mutated}")
        elseif(mutation STREQUAL nonzero-exit)
            file(WRITE "${saved_diagnostic}/process-exit.txt" "process.exit_status=1\n")
        else()
            file(APPEND "${saved_diagnostic}/result.txt" "timing.client.finished_unix_ms=99999999\n")
        endif()
        execute_process(COMMAND "${RENDERER}" --run-dir "${saved_source}"
            --saved-response-dir "${saved_diagnostic}" --output "${saved_diagnostic}/summary.full.md"
            RESULT_VARIABLE saved_status OUTPUT_QUIET ERROR_QUIET)
        if(saved_status EQUAL 0)
            message(FATAL_ERROR "saved-response renderer accepted ${mutation}")
        endif()
        file(WRITE "${saved_source}/shared/transcript/srv-to-cli-response.bin" "synthetic response\n")
        file(WRITE "${saved_diagnostic}/result.txt" "${saved_client}")
        file(WRITE "${saved_diagnostic}/process-exit.txt" "process.exit_status=0\n")
    endforeach()
    execute_process(COMMAND "${RENDERER}" --run-dir "${saved_source}"
        --saved-response-dir "${saved_diagnostic}" --output "${saved_source}/summary.md"
        RESULT_VARIABLE saved_status OUTPUT_QUIET ERROR_QUIET)
    if(saved_status EQUAL 0)
        message(FATAL_ERROR "saved-response renderer wrote into the source")
    endif()
    execute_process(COMMAND python3 "${CONCISE_RENDERER}"
        --input "${saved_diagnostic}/summary.full.md" --output "${saved_source}/summary.md"
        --run-dir "${saved_source}" --variant base --profile "${saved_profile}"
        RESULT_VARIABLE saved_status OUTPUT_QUIET ERROR_QUIET)
    if(saved_status EQUAL 0)
        message(FATAL_ERROR "saved-response concise renderer wrote into the source")
    endif()
    file(GLOB_RECURSE saved_after_files RELATIVE "${saved_source}" "${saved_source}/*")
    set(saved_after_hashes "")
    foreach(saved_file IN LISTS saved_after_files)
        file(SHA256 "${saved_source}/${saved_file}" saved_hash)
        string(APPEND saved_after_hashes "${saved_file}:${saved_hash}\n")
    endforeach()
    if(NOT saved_before_hashes STREQUAL saved_after_hashes)
        message(FATAL_ERROR "saved-response summary modified its original source")
    endif()
endforeach()
file(REMOVE_RECURSE "${saved_root}")
