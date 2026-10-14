if(NOT DEFINED RENDERER OR NOT DEFINED CONCISE_RENDERER OR NOT DEFINED CLEANUP OR
   NOT DEFINED FIXTURE OR NOT DEFINED TARGET_FIXTURE)
    message(FATAL_ERROR
            "RENDERER, CONCISE_RENDERER, CLEANUP, FIXTURE, and TARGET_FIXTURE are required")
endif()

# Render private build-tree copies so fixtures gain a lifecycle lock
# without changing tracked source files.
set(report_fixture_root
    "${CMAKE_CURRENT_BINARY_DIR}/benchmark-operator-report-fixtures")
set(source_fixture "${FIXTURE}")
set(source_target_fixture "${TARGET_FIXTURE}")
set(FIXTURE "${report_fixture_root}/quick")
set(explicit_per_request_fixture
    "${report_fixture_root}/quick-explicit-per-request")
set(TARGET_FIXTURE "${report_fixture_root}/target")
file(REMOVE_RECURSE "${report_fixture_root}")
file(MAKE_DIRECTORY "${FIXTURE}"
                    "${explicit_per_request_fixture}" "${TARGET_FIXTURE}")
file(COPY "${source_fixture}/" DESTINATION "${FIXTURE}")
file(COPY "${source_fixture}/" DESTINATION "${explicit_per_request_fixture}")
file(COPY "${source_target_fixture}/" DESTINATION "${TARGET_FIXTURE}")
file(CHMOD_RECURSE "${report_fixture_root}"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

set(explicit_setup_result
    "${explicit_per_request_fixture}/shared/setup-result.txt")
file(READ "${explicit_setup_result}" explicit_setup)
string(REPLACE "timing.setup.total.wall_ms=800"
               "timing.setup.total.wall_ms=812"
               explicit_setup "${explicit_setup}")
string(REPLACE "timing.setup.total.cpu_ms=640"
               "timing.setup.total.cpu_ms=651"
               explicit_setup "${explicit_setup}")
string(APPEND explicit_setup
       "timing.setup.client_static_preprocessing.wall_ms=12\n"
       "timing.setup.client_static_preprocessing.cpu_ms=11\n")
file(WRITE "${explicit_setup_result}" "${explicit_setup}")

execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${FIXTURE}"
            --variant base
            --profile quick
    RESULT_VARIABLE status
    OUTPUT_VARIABLE summary
    ERROR_VARIABLE error)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "summary renderer failed: ${error}")
endif()
if(NOT EXISTS "${FIXTURE}/shared/lifecycle.lock")
    message(FATAL_ERROR
            "summary renderer did not enroll a run in lifecycle locking")
endif()

foreach(required IN ITEMS
        "<!-- laminate-base-summary-v1 -->"
        "Laminate Base benchmark summary: quick"
        "Microsoft SEAL BGV"
        "file-backed-checkpoint-replay"
        "Exact data-prime schedule"
        "q0=1053858393162252289 (60 bits)"
        "Setup CPU affinity"
        "All active CPU (setup + server + client)"
        "Online server (active; idle excluded)"
        "Client process elapsed (including response wait)"
        "Request-to-verification elapsed"
        "Setup peak RSS"
        "Server peak RSS"
        "Client peak RSS"
        "Runtime breakdown"
        "Payload evaluation"
        "Payload storage pipeline"
        "Forward evaluation"
        "Reverse replay"
        "GKR source"
        "Record output submission"
        "not reported for read-only source diagnostics"
        "11.44 MiB (12,000,000 bytes)"
        "5.72 MiB (6,000,000 bytes)"
        "Page-cache prefetch advice"
        "Setup-selected dense multiplication alias-cache peak"
        "Selected replay resident peak"
        "1.00 GiB (1,073,741,824 bytes)"
        "Writeback-enabled / submit-only / fallback files"
        "Writeback submission attempts / successes"
        "Foreground wait attempts / successes"
        "Largest successful writeback range hint"
        "Configured writeback range-hint ceiling"
        "successful range-hint bytes without explicit wait"
        "16.00 MiB (16,777,216 bytes)"
        "Foreground drains / deliberately skipped drains"
        "Prefetch requests / fallbacks / seek disables"
        "256.00 MiB (268,435,456 bytes) / 8.00 MiB (8,388,608 bytes)"
        "linux-submit-only-with-buffered-portable-fallback"
        "BDI read-ahead geometry"
        "no explicit foreground wait or layer-end drain"
        "Identity affine storage aliases"
        "100.00 MiB (104,857,600 bytes)"
        "4.00 KiB (4,096 bytes)"
        "Server layer reductions"
        "Sumcheck rounds (individual)"
        "1/14"
        "16,384"
        "Per-request client computation"
        "230.000 ms (230.000000 ms)"
        "Prepare GKR input claim and bind encrypted request"
        "Read response file"
        "Decode response"
        "Check response binding, derive GKR challenge, decrypt output, and form output-MLE claim"
        "Verify GKR proof using the certified setup"
        "Client GKR verifier detail"
        "Decrypt and unpack proof messages"
        "Verify layer reduction 2"
        "Finish Gate-MLE opening"
        "contains the affine gate-opening checks"
        "Decryption overlaps the layer spans"
        "cli-to-srv-request.bin"
        "srv-to-cli-response.bin"
        "There is no second claim/proof round trip"
        "Encrypted-output statement (metadata and ciphertext)"
        "no plaintext output claim is transmitted"
        "Evidence and warnings"
        "Synthetic test fixture")
    string(FIND "${summary}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "summary is missing: ${required}")
    endif()
endforeach()

# Parallel preprocessing must not change the online measurement contract.
set(parallel_fixture "${report_fixture_root}/parallel-setup")
file(COPY "${FIXTURE}/" DESTINATION "${parallel_fixture}")
set(parallel_setup_path "${parallel_fixture}/shared/setup-result.txt")
file(READ "${parallel_setup_path}" parallel_setup)
string(REPLACE "environment.threading=single-cpu-process"
               "environment.threading=setup-worker-pool"
               parallel_setup "${parallel_setup}")
string(REGEX REPLACE "environment.pinned_cpu=[^\n]*\n" ""
                     parallel_setup "${parallel_setup}")
string(APPEND parallel_setup
       "environment.worker_threads=3\nenvironment.cpu_affinity=0,1,3\n")
file(WRITE "${parallel_setup_path}" "${parallel_setup}")
execute_process(COMMAND "${RENDERER}" --run-dir "${parallel_fixture}"
                        --variant base --profile quick
                RESULT_VARIABLE parallel_status OUTPUT_VARIABLE parallel_summary
                ERROR_VARIABLE parallel_error)
if(NOT parallel_status EQUAL 0 OR
   NOT parallel_summary MATCHES "Setup workers.*3" OR
   NOT parallel_summary MATCHES "Setup CPU affinity.*0,1,3")
    message(FATAL_ERROR "parallel setup report failed: ${parallel_error}")
endif()
string(REPLACE "environment.worker_threads=3" "environment.worker_threads=4"
               inconsistent_setup "${parallel_setup}")
file(WRITE "${parallel_setup_path}" "${inconsistent_setup}")
execute_process(COMMAND "${RENDERER}" --run-dir "${parallel_fixture}"
                        --variant base --profile quick
                RESULT_VARIABLE parallel_status OUTPUT_QUIET ERROR_VARIABLE parallel_error)
if(parallel_status EQUAL 0 OR NOT parallel_error MATCHES
   "setup worker count and CPU affinity are inconsistent")
    message(FATAL_ERROR "renderer accepted inconsistent setup CPU allocation")
endif()
file(WRITE "${parallel_setup_path}" "${parallel_setup}")
foreach(online_role IN ITEMS server client)
    set(online_path "${parallel_fixture}/${online_role}/result.txt")
    file(READ "${online_path}" online_serial)
    foreach(mutation IN ITEMS pool workers)
        if(mutation STREQUAL pool)
            string(REPLACE "environment.threading=single-cpu-process"
                           "environment.threading=setup-worker-pool"
                           online_parallel "${online_serial}")
        else()
            set(online_parallel "${online_serial}environment.worker_threads=2\n")
        endif()
        file(WRITE "${online_path}" "${online_parallel}")
        execute_process(COMMAND "${RENDERER}" --run-dir "${parallel_fixture}"
                                --variant base --profile quick
                        RESULT_VARIABLE parallel_status OUTPUT_QUIET ERROR_VARIABLE parallel_error)
        if(parallel_status EQUAL 0 OR NOT parallel_error MATCHES "single-CPU execution")
            message(FATAL_ERROR "renderer accepted parallel ${online_role}: ${parallel_error}")
        endif()
    endforeach()
    file(WRITE "${online_path}" "${online_serial}")
endforeach()

set(invalid_replay_storage_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-invalid-replay-storage")
file(REMOVE_RECURSE "${invalid_replay_storage_fixture}")
file(COPY "${FIXTURE}/" DESTINATION "${invalid_replay_storage_fixture}")
set(invalid_replay_storage_server
    "${invalid_replay_storage_fixture}/server/result.txt")
file(READ "${invalid_replay_storage_server}"
     invalid_replay_storage_contents)
string(REPLACE
       "work.replay.forward.storage.maximum_prefetch_request_bytes=8388608"
       "work.replay.forward.storage.maximum_prefetch_request_bytes=10000001"
       invalid_replay_storage_contents
       "${invalid_replay_storage_contents}")
file(WRITE "${invalid_replay_storage_server}"
     "${invalid_replay_storage_contents}")
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${invalid_replay_storage_fixture}"
            --variant base
            --profile quick
    RESULT_VARIABLE invalid_replay_storage_status
    OUTPUT_QUIET
    ERROR_VARIABLE invalid_replay_storage_error)
if(invalid_replay_storage_status EQUAL 0 OR
   NOT invalid_replay_storage_error MATCHES
       "inconsistent replay storage telemetry for forward")
    message(FATAL_ERROR
            "Base renderer accepted an impossible replay I/O ledger")
endif()
file(REMOVE_RECURSE "${invalid_replay_storage_fixture}")

execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${explicit_per_request_fixture}"
            --variant base
            --profile quick
    RESULT_VARIABLE explicit_timing_status
    OUTPUT_VARIABLE explicit_timing_summary
    ERROR_VARIABLE explicit_timing_error)
if(NOT explicit_timing_status EQUAL 0)
    message(FATAL_ERROR
            "explicit per-request summary renderer failed: ${explicit_timing_error}")
endif()
foreach(required IN ITEMS
        "230.000 ms (230.000000 ms)"
        "Build authenticated client-static preprocessing"
        "Check response binding, derive GKR challenge, decrypt output, and form output-MLE claim")
    string(FIND "${explicit_timing_summary}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
                "explicit per-request summary is missing: ${required}")
    endif()
endforeach()

foreach(forbidden IN ITEMS
        "Reconstruct workload and compile circuit"
        "Certify static client setup once"
        "Open response: check dynamic bindings"
        "All four protocol messages"
        "Claim-request codec"
        "Other active client/server work is held at its measured time"
        "exact one-round response formula ratio"
        "exact persistent Base proof formula ratio")
    string(FIND "${summary}" "${forbidden}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "summary retained stale text: ${forbidden}")
    endif()
endforeach()

execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${FIXTURE}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE mismatch_status
    OUTPUT_QUIET
    ERROR_VARIABLE mismatch_error)
if(mismatch_status EQUAL 0 OR
   NOT mismatch_error MATCHES "--profile disagrees")
    message(FATAL_ERROR "profile mismatch did not fail closed")
endif()

execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${TARGET_FIXTURE}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE target_status
    OUTPUT_VARIABLE target_summary
    ERROR_VARIABLE target_error)
if(NOT target_status EQUAL 0)
    message(FATAL_ERROR "target summary renderer failed: ${target_error}")
endif()
foreach(required IN ITEMS
        "Target storage provenance"
        "google-local-ssd-raid0"
        "/dev/md127 on /mnt/disks/laminate-storage"
        "3,221,225,472,000 bytes"
        "Available at setup start"
        "Available at server start"
        "Host-derived planner budget"
        "Observed available disk"
        "Gross live-artifact budget"
        "Persistent client preprocessing reserve"
        "Server checkpoint/replay budget"
        "Observed physical RAM"
        "Gross resident budget after host reserve"
        "Concurrent client resident reserve"
        "Net server resident cap"
        "RAID0 chunk"
        "524,288 bytes"
        "nvme0n1,nvme1n1,nvme2n1,nvme3n1,nvme4n1,nvme5n1,nvme6n1,nvme7n1")
    string(FIND "${target_summary}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
                "target summary omitted storage provenance: ${required}")
    endif()
endforeach()

set(local_ssd_root_mount_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-local-ssd-root-mount")
file(REMOVE_RECURSE "${local_ssd_root_mount_fixture}")
file(COPY "${TARGET_FIXTURE}/" DESTINATION "${local_ssd_root_mount_fixture}")
set(local_ssd_root_mount_server
    "${local_ssd_root_mount_fixture}/shared/storage-provenance.server-start.txt")
file(READ "${local_ssd_root_mount_server}" local_ssd_root_mount_contents)
string(REPLACE
       "storage.mount_target=/mnt/disks/laminate-storage"
       "storage.mount_target=/"
       local_ssd_root_mount_contents "${local_ssd_root_mount_contents}")
file(WRITE "${local_ssd_root_mount_server}"
     "${local_ssd_root_mount_contents}")
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${local_ssd_root_mount_fixture}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE local_ssd_root_mount_status
    OUTPUT_QUIET
    ERROR_VARIABLE local_ssd_root_mount_error)
if(local_ssd_root_mount_status EQUAL 0 OR
   NOT local_ssd_root_mount_error MATCHES
       "requires an absolute storage.mount_target")
    message(FATAL_ERROR
            "target summary allowed mount_target=/ for Local SSD storage")
endif()
file(REMOVE_RECURSE "${local_ssd_root_mount_fixture}")

# The same target report accepts a dedicated whole block device (for example,
# a provisioned Hyperdisk) and renders its topology instead of RAID rows.
set(dedicated_storage_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-dedicated-target-storage")
file(REMOVE_RECURSE "${dedicated_storage_fixture}")
file(COPY "${TARGET_FIXTURE}/" DESTINATION "${dedicated_storage_fixture}")
foreach(phase IN ITEMS setup-start server-start)
    if(phase STREQUAL "setup-start")
        set(captured_at "2026-09-03T01:00:00Z")
        set(available 3170000000000)
    else()
        set(captured_at "2026-09-03T02:00:00Z")
        set(available 3120000000000)
    endif()
    file(WRITE
        "${dedicated_storage_fixture}/shared/storage-provenance.${phase}.txt"
        "format=laminate-storage-provenance-v2\n"
        "storage.capture_phase=${phase}\n"
        "storage.captured_at_utc=${captured_at}\n"
        "storage.artifact_root=/mnt/disks/laminate-storage/laminate-bench\n"
        "storage.mount_source=/dev/nvme0n2\n"
        "storage.mount_target=/mnt/disks/laminate-storage\n"
        "storage.filesystem_type=ext4\n"
        "storage.mount_options=rw,noatime,nodiratime\n"
        "storage.filesystem_total_bytes=3221225472000\n"
        "storage.filesystem_available_bytes=${available}\n"
        "storage.backend=dedicated-block\n"
        "storage.dedicated_block.device=/dev/nvme0n2\n"
        "storage.dedicated_block.device_type=disk\n"
        "storage.dedicated_block.device_ancestry=nvme0n2\n"
        "storage.dedicated_block.protected_ancestry=nvme0n1,nvme0n1p1\n")
endforeach()
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${dedicated_storage_fixture}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE dedicated_storage_status
    OUTPUT_VARIABLE dedicated_storage_summary
    ERROR_VARIABLE dedicated_storage_error)
if(NOT dedicated_storage_status EQUAL 0)
    message(FATAL_ERROR
            "dedicated-block target summary failed: ${dedicated_storage_error}")
endif()
foreach(required IN ITEMS
        "dedicated-block"
        "Dedicated whole block device"
        "/dev/nvme0n2"
        "Device ancestry"
        "Protected root/boot ancestry")
    string(FIND "${dedicated_storage_summary}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
                "dedicated-block summary omitted provenance: ${required}")
    endif()
endforeach()

set(corrupt_storage_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-corrupt-target-storage")
file(REMOVE_RECURSE "${corrupt_storage_fixture}")
file(COPY "${dedicated_storage_fixture}/"
     DESTINATION "${corrupt_storage_fixture}")
set(corrupt_server
    "${corrupt_storage_fixture}/shared/storage-provenance.server-start.txt")
file(READ "${corrupt_server}" corrupt_server_contents)
string(REPLACE
       "storage.dedicated_block.device=/dev/nvme0n2"
       "storage.dedicated_block.device=/dev/nvme9n9"
       corrupt_server_contents "${corrupt_server_contents}")
file(WRITE "${corrupt_server}" "${corrupt_server_contents}")
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${corrupt_storage_fixture}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE corrupt_storage_status
    OUTPUT_QUIET
    ERROR_VARIABLE corrupt_storage_error)
if(corrupt_storage_status EQUAL 0 OR
   NOT corrupt_storage_error MATCHES "dedicated whole block device")
    message(FATAL_ERROR
            "target summary accepted a dedicated device/mount mismatch")
endif()

# A deliberately configured fallback may place the benchmark below a
# dedicated directory on the root filesystem. It remains admissible only when
# provenance explicitly records that the benchmark and OS share filesystem
# capacity and I/O.
set(shared_root_storage_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-shared-root-target-storage")
file(REMOVE_RECURSE "${shared_root_storage_fixture}")
file(COPY "${TARGET_FIXTURE}/" DESTINATION "${shared_root_storage_fixture}")
foreach(phase IN ITEMS setup-start server-start)
    if(phase STREQUAL "setup-start")
        set(captured_at "2026-09-03T01:00:00Z")
        set(available 3170000000000)
    else()
        set(captured_at "2026-09-03T02:00:00Z")
        set(available 3120000000000)
    endif()
    file(WRITE
        "${shared_root_storage_fixture}/shared/storage-provenance.${phase}.txt"
        "format=laminate-storage-provenance-v2\n"
        "storage.capture_phase=${phase}\n"
        "storage.captured_at_utc=${captured_at}\n"
        "storage.artifact_root=/var/lib/laminate-storage/laminate-bench\n"
        "storage.mount_source=/dev/nvme0n1p1\n"
        "storage.mount_target=/\n"
        "storage.filesystem_type=ext4\n"
        "storage.mount_options=rw,relatime\n"
        "storage.filesystem_total_bytes=3221225472000\n"
        "storage.filesystem_available_bytes=${available}\n"
        "storage.backend=shared-root-filesystem\n"
        "storage.shared_root.directory=/var/lib/laminate-storage\n"
        "storage.shared_root.shares_os=true\n")
endforeach()
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${shared_root_storage_fixture}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE shared_root_storage_status
    OUTPUT_VARIABLE shared_root_storage_summary
    ERROR_VARIABLE shared_root_storage_error)
if(NOT shared_root_storage_status EQUAL 0)
    message(FATAL_ERROR
            "shared-root target summary failed: ${shared_root_storage_error}")
endif()
foreach(required IN ITEMS
        "shared-root-filesystem"
        "Shared storage directory"
        "/var/lib/laminate-storage"
        "Shares OS filesystem and I/O"
        "benchmark artifacts and the operating system share the root filesystem and I/O path"
        "rw,relatime")
    string(FIND "${shared_root_storage_summary}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
                "shared-root summary omitted provenance: ${required}")
    endif()
endforeach()

set(corrupt_shared_root_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-corrupt-shared-root-storage")
file(REMOVE_RECURSE "${corrupt_shared_root_fixture}")
file(COPY "${shared_root_storage_fixture}/"
     DESTINATION "${corrupt_shared_root_fixture}")
set(corrupt_shared_root_server
    "${corrupt_shared_root_fixture}/shared/storage-provenance.server-start.txt")
file(READ "${corrupt_shared_root_server}" corrupt_shared_root_contents)
string(REPLACE
       "storage.shared_root.shares_os=true"
       "storage.shared_root.shares_os=false"
       corrupt_shared_root_contents "${corrupt_shared_root_contents}")
file(WRITE "${corrupt_shared_root_server}" "${corrupt_shared_root_contents}")
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${corrupt_shared_root_fixture}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE corrupt_shared_root_status
    OUTPUT_QUIET
    ERROR_VARIABLE corrupt_shared_root_error)
if(corrupt_shared_root_status EQUAL 0 OR
   NOT corrupt_shared_root_error MATCHES
       "does not acknowledge shared OS filesystem and I/O")
    message(FATAL_ERROR
            "target summary accepted false shared-root OS provenance")
endif()

set(outside_shared_root_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-outside-shared-root-storage")
file(REMOVE_RECURSE "${outside_shared_root_fixture}")
file(COPY "${shared_root_storage_fixture}/"
     DESTINATION "${outside_shared_root_fixture}")
set(outside_shared_root_server
    "${outside_shared_root_fixture}/shared/storage-provenance.server-start.txt")
file(READ "${outside_shared_root_server}" outside_shared_root_contents)
string(REPLACE
       "storage.artifact_root=/var/lib/laminate-storage/laminate-bench"
       "storage.artifact_root=/var/lib/other-storage/laminate-bench"
       outside_shared_root_contents "${outside_shared_root_contents}")
file(WRITE "${outside_shared_root_server}" "${outside_shared_root_contents}")
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${outside_shared_root_fixture}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE outside_shared_root_status
    OUTPUT_QUIET
    ERROR_VARIABLE outside_shared_root_error)
if(outside_shared_root_status EQUAL 0 OR
   NOT outside_shared_root_error MATCHES
       "must be exactly STORAGE/laminate-bench")
    message(FATAL_ERROR
            "target summary accepted artifacts outside shared-root storage")
endif()

set(wrong_shared_root_layout_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-wrong-shared-root-layout")
file(REMOVE_RECURSE "${wrong_shared_root_layout_fixture}")
file(COPY "${shared_root_storage_fixture}/"
     DESTINATION "${wrong_shared_root_layout_fixture}")
foreach(phase IN ITEMS setup-start server-start)
    set(layout_snapshot
        "${wrong_shared_root_layout_fixture}/shared/storage-provenance.${phase}.txt")
    file(READ "${layout_snapshot}" layout_contents)
    string(REPLACE
           "/var/lib/laminate-storage"
           "/mnt/disks/laminate-storage"
           layout_contents "${layout_contents}")
    file(WRITE "${layout_snapshot}" "${layout_contents}")
endforeach()
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${wrong_shared_root_layout_fixture}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE wrong_shared_root_layout_status
    OUTPUT_QUIET
    ERROR_VARIABLE wrong_shared_root_layout_error)
if(wrong_shared_root_layout_status EQUAL 0 OR
   NOT wrong_shared_root_layout_error MATCHES
       "must use /var/lib/laminate-storage")
    message(FATAL_ERROR
            "target summary accepted shared-root storage outside /var/lib")
endif()

file(REMOVE_RECURSE "${dedicated_storage_fixture}"
                    "${corrupt_storage_fixture}"
                    "${shared_root_storage_fixture}"
                    "${corrupt_shared_root_fixture}"
                    "${outside_shared_root_fixture}"
                    "${wrong_shared_root_layout_fixture}")

set(corrupt_budget_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-corrupt-target-budget")
file(REMOVE_RECURSE "${corrupt_budget_fixture}")
file(COPY "${TARGET_FIXTURE}/" DESTINATION "${corrupt_budget_fixture}")
set(corrupt_setup "${corrupt_budget_fixture}/shared/setup-result.txt")
file(READ "${corrupt_setup}" corrupt_setup_contents)
string(REPLACE
       "storage.host_budget.max_live_disk_bytes=3000000000000"
       "storage.host_budget.max_live_disk_bytes=2999999999999"
       corrupt_setup_contents "${corrupt_setup_contents}")
file(WRITE "${corrupt_setup}" "${corrupt_setup_contents}")
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${corrupt_budget_fixture}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE corrupt_budget_status
    OUTPUT_QUIET
    ERROR_VARIABLE corrupt_budget_error)
if(corrupt_budget_status EQUAL 0 OR
   NOT corrupt_budget_error MATCHES "host-derived disk and RAM policy")
    message(FATAL_ERROR
            "target summary accepted a non-derived resource budget")
endif()
file(REMOVE_RECURSE "${corrupt_budget_fixture}")

set(missing_storage_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-missing-target-storage")
file(REMOVE_RECURSE "${missing_storage_fixture}")
file(COPY "${TARGET_FIXTURE}/" DESTINATION "${missing_storage_fixture}")
file(REMOVE
    "${missing_storage_fixture}/shared/storage-provenance.server-start.txt")
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${missing_storage_fixture}"
            --variant base
            --profile target-balancedLaned
    RESULT_VARIABLE missing_storage_status
    OUTPUT_QUIET
    ERROR_VARIABLE missing_storage_error)
if(missing_storage_status EQUAL 0 OR
   NOT missing_storage_error MATCHES
       "storage-provenance.server-start.txt")
    message(FATAL_ERROR
            "target summary did not fail closed on missing storage provenance")
endif()
file(REMOVE_RECURSE "${missing_storage_fixture}")

execute_process(
    COMMAND "${RENDERER}" --input "${FIXTURE}/server/result.txt"
    RESULT_VARIABLE unsupported_option_status
    OUTPUT_QUIET
    ERROR_VARIABLE unsupported_option_error)
if(unsupported_option_status EQUAL 0 OR NOT unsupported_option_error MATCHES "unknown option: --input")
    message(FATAL_ERROR "renderer accepted unsupported --input option")
endif()

set(output_directory
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-summary-atomic")
set(output_file "${output_directory}/summary.md")
set(human_file "${output_directory}/human-notes.md")
file(REMOVE_RECURSE "${output_directory}")
file(MAKE_DIRECTORY "${output_directory}")

foreach(pass RANGE 1 2)
    execute_process(
        COMMAND "${RENDERER}"
                --run-dir "${TARGET_FIXTURE}"
                --variant base
                --profile target-balancedLaned
                --output "${output_file}"
        RESULT_VARIABLE output_status
        ERROR_VARIABLE output_error)
    if(NOT output_status EQUAL 0)
        message(FATAL_ERROR
                "atomic summary publication pass ${pass} failed: ${output_error}")
    endif()
endforeach()
file(READ "${output_file}" published LIMIT 64)
if(NOT published MATCHES "^<!-- laminate-base-summary-v1 -->")
    message(FATAL_ERROR "published summary lacks its renderer marker")
endif()

file(WRITE "${human_file}" "human notes; do not replace\n")
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${TARGET_FIXTURE}"
            --variant base
            --profile target-balancedLaned
            --output "${human_file}"
    RESULT_VARIABLE human_status
    OUTPUT_QUIET
    ERROR_VARIABLE human_error)
if(human_status EQUAL 0 OR
   NOT human_error MATCHES "was not generated by this summary renderer")
    message(FATAL_ERROR "renderer did not protect a human-owned output file")
endif()
file(READ "${human_file}" human_contents)
if(NOT human_contents STREQUAL "human notes; do not replace\n")
    message(FATAL_ERROR "renderer changed a human-owned output file")
endif()

file(GLOB partials "${output_file}.partial.*" "${human_file}.partial.*")
if(partials)
    message(FATAL_ERROR "summary renderer left partial files: ${partials}")
endif()
file(REMOVE_RECURSE "${output_directory}")

find_program(SUMMARY_PYTHON_EXECUTABLE python3 REQUIRED)
execute_process(
    COMMAND "${SUMMARY_PYTHON_EXECUTABLE}"
            "${CMAKE_CURRENT_LIST_DIR}/test_base_recovery_summary.py"
            "${RENDERER}" "${CONCISE_RENDERER}" "${FIXTURE}" "${TARGET_FIXTURE}"
    RESULT_VARIABLE recovery_summary_status
    ERROR_VARIABLE recovery_summary_error)
if(NOT recovery_summary_status EQUAL 0)
    message(FATAL_ERROR "Base recovered summary fixture failed: ${recovery_summary_error}")
endif()
set(concise_fixture
    "${CMAKE_CURRENT_BINARY_DIR}/base-report-summary-concise")
file(REMOVE_RECURSE "${concise_fixture}")
file(COPY "${FIXTURE}/" DESTINATION "${concise_fixture}")
file(MAKE_DIRECTORY "${concise_fixture}/shared/report")
set(concise_source "${concise_fixture}/shared/report/verbose.md")
set(concise_output "${concise_fixture}/shared/report/summary.md")
execute_process(
    COMMAND "${RENDERER}"
            --run-dir "${concise_fixture}"
            --variant base
            --profile quick
            --output "${concise_source}"
    RESULT_VARIABLE concise_source_status
    ERROR_VARIABLE concise_source_error)
if(NOT concise_source_status EQUAL 0)
    message(FATAL_ERROR
            "Base concise fixture source failed: ${concise_source_error}")
endif()
execute_process(
    COMMAND "${SUMMARY_PYTHON_EXECUTABLE}" "${CONCISE_RENDERER}"
            --input "${concise_source}"
            --output "${concise_output}"
            --run-dir "${concise_fixture}"
            --variant base
            --profile quick
    RESULT_VARIABLE concise_status
    ERROR_VARIABLE concise_error)
if(NOT concise_status EQUAL 0)
    message(FATAL_ERROR "Base concise render failed: ${concise_error}")
endif()
file(READ "${concise_output}" concise_contents)
execute_process(
    COMMAND "${SUMMARY_PYTHON_EXECUTABLE}" -c
            [=[from pathlib import Path; import re,sys; p=Path(sys.argv[1]); s=p.read_text(); s=re.sub(r'\n## Client computation\n.*?(?=\n#{1,3} )', '', s, flags=re.S); p.write_text(s)]=]
            "${concise_source}"
    RESULT_VARIABLE incomplete_source_status)
execute_process(
    COMMAND "${SUMMARY_PYTHON_EXECUTABLE}" "${CONCISE_RENDERER}"
            --input "${concise_source}" --output "${concise_fixture}/incomplete-concise.md"
    RESULT_VARIABLE incomplete_concise_status ERROR_VARIABLE incomplete_concise_error)
if(NOT incomplete_source_status EQUAL 0 OR incomplete_concise_status EQUAL 0)
    message(FATAL_ERROR "Base concise renderer accepted missing client computation")
endif()
foreach(required IN ITEMS
        "<!-- laminate-benchmark-summary-v2 -->"
        "Laminate variant | Base"
        "Payload profile | `quick`"
        "Scalar gates | 218,087,424"
        "Plaintext modulus | 65,537"
        "VCoED server wall time"
        "VCoED proof verification"
        "## Server layer reductions"
        "## Sumcheck round details"
        "## Client verifier details"
        "## Server FHE operation ledger"
        "## Protocol artifacts"
        "## Memory and storage"
        "## Provenance")
    string(FIND "${concise_contents}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
                "Base concise summary omitted: ${required}")
    endif()
endforeach()
foreach(forbidden IN ITEMS
        "Payload storage pipeline"
        "Online server"
        "Identity affine storage aliases"
        "Evidence and warnings"
        "Git commit"
        "Git revision"
        "sec_level_type::none"
        "Client process total"
        "Process exits"
        "FHE backend"
        "Exact data-prime schedule"
        "q0="
        "Setup wall time"
        "Run ID"
        "Exact role commands"
        "summary.csv")
    string(FIND "${concise_contents}" "${forbidden}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
                "Base concise summary retained: ${forbidden}")
    endif()
endforeach()
if(EXISTS "${concise_fixture}/shared/report/summary.csv")
    message(FATAL_ERROR "Base concise render produced summary.csv")
endif()
file(REMOVE_RECURSE "${concise_fixture}")

set(cleanup_root "${CMAKE_CURRENT_BINARY_DIR}/benchmark-cleanup")
set(runs "${cleanup_root}/runs")
set(keep "${runs}/current quick")
set(old_a "${runs}/old-a")
set(old_b "${runs}/old-b")
set(other_profile "${runs}/target-stays")
set(unrecognized "${runs}/unrecognized-stays")
set(unbound "${runs}/unbound-stays")
set(prefix_collision
    "${runs}/.laminate-cleanup-base-quick-run-unrecognized-stays")
include("${CMAKE_CURRENT_LIST_DIR}/test_saved_response_summary.cmake")

file(REMOVE_RECURSE "${cleanup_root}")
file(MAKE_DIRECTORY "${runs}" "${keep}" "${old_a}" "${old_b}"
                    "${other_profile}" "${unrecognized}" "${unbound}"
                    "${prefix_collision}")
file(COPY "${FIXTURE}/" DESTINATION "${keep}")
file(COPY "${FIXTURE}/" DESTINATION "${old_a}")
file(COPY "${FIXTURE}/" DESTINATION "${old_b}")
file(COPY "${TARGET_FIXTURE}/" DESTINATION "${other_profile}")
file(COPY "${FIXTURE}/" DESTINATION "${unbound}")
file(REMOVE "${unbound}/shared/run-binding.txt")
file(CHMOD_RECURSE "${cleanup_root}"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

execute_process(
    COMMAND "${CLEANUP}"
            --variant base
            --profile quick
            --keep-run "${keep}"
    RESULT_VARIABLE cleanup_status
    OUTPUT_VARIABLE cleanup_output
    ERROR_VARIABLE cleanup_error)
if(NOT cleanup_status EQUAL 0)
    message(FATAL_ERROR "old-run cleanup failed: ${cleanup_error}")
endif()
if(NOT IS_DIRECTORY "${keep}" OR EXISTS "${old_a}" OR EXISTS "${old_b}" OR
   NOT IS_DIRECTORY "${other_profile}" OR NOT IS_DIRECTORY "${unrecognized}" OR
   NOT IS_DIRECTORY "${unbound}" OR
   NOT IS_DIRECTORY "${prefix_collision}")
    message(FATAL_ERROR
            "cleanup did not preserve/delete the intended run directories")
endif()

# A durable record, not a guessable directory prefix, authorizes recovery of
# an interrupted deletion. The partial tombstone deliberately lacks shared/.
set(partial_tombstone
    "${runs}/.laminate-cleanup-base-quick-run-interrupted")
set(partial_record
    "${runs}/.laminate-cleanup-base-quick-record-interrupted.record")
file(MAKE_DIRECTORY "${partial_tombstone}")
file(WRITE "${partial_tombstone}/leftover.bin" "partially deleted\n")
file(WRITE "${partial_record}"
     "format=laminate-benchmark-cleanup-v1\n"
     "run.variant=base\n"
     "run.profile=quick\n"
     "run.id=report-renderer-fixture\n"
     "original.name=interrupted-original\n"
     "tombstone.name=.laminate-cleanup-base-quick-run-interrupted\n")
file(CHMOD_RECURSE "${partial_tombstone}" "${partial_record}"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
execute_process(
    COMMAND "${CLEANUP}"
            --variant base
            --profile quick
            --keep-run "${keep}"
    RESULT_VARIABLE recovery_status
    OUTPUT_VARIABLE recovery_output
    ERROR_VARIABLE recovery_error)
if(NOT recovery_status EQUAL 0 OR EXISTS "${partial_tombstone}" OR
   EXISTS "${partial_record}" OR NOT IS_DIRECTORY "${prefix_collision}" OR
   NOT recovery_output MATCHES "CLEANUP COMPLETE: removed 1 matching run")
    message(FATAL_ERROR
            "interrupted cleanup recovery failed: ${recovery_error}")
endif()

# An explicit keep decision wins over a transaction that crashed after
# journaling its intent but before renaming the run.
set(keep_record
    "${runs}/.laminate-cleanup-base-quick-record-keep.record")
file(WRITE "${keep_record}"
     "format=laminate-benchmark-cleanup-v1\n"
     "run.variant=base\n"
     "run.profile=quick\n"
     "run.id=report-renderer-fixture\n"
     "original.name=current quick\n"
     "tombstone.name=.laminate-cleanup-base-quick-run-never-created\n")
file(CHMOD "${keep_record}"
     PERMISSIONS OWNER_READ OWNER_WRITE)
execute_process(
    COMMAND "${CLEANUP}"
            --variant base
            --profile quick
            --keep-run "${keep}"
    RESULT_VARIABLE keep_record_status
    OUTPUT_VARIABLE keep_record_output
    ERROR_VARIABLE keep_record_error)
if(NOT keep_record_status EQUAL 0 OR EXISTS "${keep_record}" OR
   NOT IS_DIRECTORY "${keep}" OR
   NOT keep_record_output MATCHES
       "cancelled interrupted cleanup intent for kept run")
    message(FATAL_ERROR
            "explicit keep did not cancel stale cleanup intent: ${keep_record_error}")
endif()
foreach(required IN ITEMS
        "runs to remove: 2"
        "CLEANUP COMPLETE: removed 2 matching runs"
        "preserved unrecognized directory")
    string(FIND "${cleanup_output}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "cleanup output is missing: ${required}")
    endif()
endforeach()

execute_process(
    COMMAND "${CLEANUP}"
            --variant base
            --profile quick
            --keep-run "${keep}"
    RESULT_VARIABLE empty_cleanup_status
    OUTPUT_VARIABLE empty_cleanup_output
    ERROR_VARIABLE empty_cleanup_error)
if(NOT empty_cleanup_status EQUAL 0 OR
   NOT empty_cleanup_output MATCHES "Nothing to remove")
    message(FATAL_ERROR
            "zero-target cleanup failed: ${empty_cleanup_error}")
endif()

set(valid_old "${runs}/valid-old-must-survive")
set(malformed "${runs}/malformed-must-block")
file(MAKE_DIRECTORY "${valid_old}" "${malformed}/shared")
file(COPY "${FIXTURE}/" DESTINATION "${valid_old}")
file(WRITE "${malformed}/shared/run-binding.txt"
     "format=laminate-benchmark-run-v1\nrun.variant=base\n")
file(CHMOD_RECURSE "${valid_old}" "${malformed}"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
execute_process(
    COMMAND "${CLEANUP}"
            --variant base
            --profile quick
            --keep-run "${keep}"
    RESULT_VARIABLE malformed_status
    OUTPUT_QUIET
    ERROR_VARIABLE malformed_error)
if(malformed_status EQUAL 0 OR
   NOT malformed_error MATCHES "missing run.profile" OR
   NOT IS_DIRECTORY "${valid_old}")
    message(FATAL_ERROR
            "cleanup did not fail closed before deleting a valid candidate")
endif()

execute_process(
    COMMAND "${CLEANUP}"
            --variant base
            --profile quick
            --keep-run "${other_profile}"
    RESULT_VARIABLE mismatch_cleanup_status
    OUTPUT_QUIET
    ERROR_VARIABLE mismatch_cleanup_error)
if(mismatch_cleanup_status EQUAL 0 OR
   NOT mismatch_cleanup_error MATCHES
       "--keep-run is not bound to the requested variant/profile")
    message(FATAL_ERROR "cleanup accepted a mismatched current run")
endif()

# Packed setup results have a richer format. Cleanup uses the canonical
# run-binding and requires every duplicated packed identity field to agree.
set(packed_cleanup_root
    "${CMAKE_CURRENT_BINARY_DIR}/benchmark-packed-cleanup")
set(packed_runs "${packed_cleanup_root}/runs")
set(packed_keep "${packed_runs}/folded-quick-keep")
set(packed_old "${packed_runs}/folded-quick-old")
set(packed_other_profile "${packed_runs}/folded-target-balancedLaned-stays")
file(REMOVE_RECURSE "${packed_cleanup_root}")
file(MAKE_DIRECTORY "${packed_keep}/shared" "${packed_old}/shared"
                    "${packed_other_profile}/shared")
foreach(directory IN ITEMS "${packed_keep}" "${packed_old}")
    get_filename_component(run_name "${directory}" NAME)
    file(WRITE "${directory}/shared/run-binding.txt"
         "format=laminate-benchmark-run-v1\n"
         "run.variant=folded\n"
         "run.profile=quick\n"
         "run.id=${run_name}\n")
    file(WRITE "${directory}/shared/setup-result.txt"
         "format=laminate-packed-benchmark-setup-v1\n"
         "protocol.variant=folded\n"
         "benchmark.profile=quick\n"
         "geometry.B=0\n"
         "run.id=${run_name}\n"
         "setup.result=PASS\n")
endforeach()
file(WRITE "${packed_other_profile}/shared/run-binding.txt"
     "format=laminate-benchmark-run-v1\n"
     "run.variant=folded\n"
     "run.profile=target-balancedLaned\n"
     "run.id=folded-target-balancedLaned-stays\n")
file(WRITE "${packed_other_profile}/shared/setup-result.txt"
     "format=laminate-packed-benchmark-setup-v1\n"
     "protocol.variant=folded\n"
     "benchmark.profile=target-balancedLaned\n"
     "geometry.B=0\n"
     "run.id=folded-target-balancedLaned-stays\n"
     "setup.result=PASS\n")
file(CHMOD_RECURSE "${packed_cleanup_root}"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

execute_process(
    COMMAND "${CLEANUP}"
            --variant folded
            --profile quick
            --keep-run "${packed_keep}"
    RESULT_VARIABLE packed_cleanup_status
    OUTPUT_VARIABLE packed_cleanup_output
    ERROR_VARIABLE packed_cleanup_error)
if(NOT packed_cleanup_status EQUAL 0 OR
   NOT IS_DIRECTORY "${packed_keep}" OR EXISTS "${packed_old}" OR
   NOT IS_DIRECTORY "${packed_other_profile}" OR
   NOT packed_cleanup_output MATCHES
       "CLEANUP COMPLETE: removed 1 matching run")
    message(FATAL_ERROR
            "packed-format old-run cleanup failed: ${packed_cleanup_error}")
endif()

set(packed_mismatch "${packed_runs}/folded-quick-mismatch")
file(MAKE_DIRECTORY "${packed_mismatch}/shared")
file(WRITE "${packed_mismatch}/shared/run-binding.txt"
     "format=laminate-benchmark-run-v1\n"
     "run.variant=folded\n"
     "run.profile=quick\n"
     "run.id=folded-quick-mismatch\n")
file(WRITE "${packed_mismatch}/shared/setup-result.txt"
     "format=laminate-packed-benchmark-setup-v1\n"
     "protocol.variant=folded\n"
     "benchmark.profile=quick\n"
     "geometry.B=0\n"
     "run.id=different-packed-run-id\n"
     "setup.result=PASS\n")
file(CHMOD_RECURSE "${packed_mismatch}"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
execute_process(
    COMMAND "${CLEANUP}"
            --variant folded
            --profile quick
            --keep-run "${packed_keep}"
    RESULT_VARIABLE packed_mismatch_status
    OUTPUT_QUIET
    ERROR_VARIABLE packed_mismatch_error)
if(packed_mismatch_status EQUAL 0 OR
   NOT packed_mismatch_error MATCHES
       "run-binding.txt disagrees with packed setup-result.txt" OR
   NOT IS_DIRECTORY "${packed_mismatch}")
    message(FATAL_ERROR
            "packed cleanup did not fail closed on identity disagreement")
endif()

# Laned cleanup is scoped by B. Cleaning B=128 must not invalidate another
# lane count's independently scoped current run.
set(laned_cleanup_root
    "${CMAKE_CURRENT_BINARY_DIR}/benchmark-laned-cleanup")
set(laned_runs "${laned_cleanup_root}/runs")
file(REMOVE_RECURSE "${laned_cleanup_root}")
set(laned_keep "${laned_runs}/laned-quick-b128-keep")
set(laned_old "${laned_runs}/laned-quick-b128-old")
set(laned_other_b "${laned_runs}/laned-quick-b1-stays")
foreach(directory IN ITEMS "${laned_keep}" "${laned_old}" "${laned_other_b}")
    file(MAKE_DIRECTORY "${directory}/shared")
    get_filename_component(run_name "${directory}" NAME)
    if("${directory}" STREQUAL "${laned_other_b}")
        set(run_lanes 1)
    else()
        set(run_lanes 128)
    endif()
    file(WRITE "${directory}/shared/run-binding.txt"
         "format=laminate-benchmark-run-v1\n"
         "run.variant=laned\n"
         "run.profile=quick\n"
         "run.id=${run_name}\n")
    file(WRITE "${directory}/shared/setup-result.txt"
         "format=laminate-packed-benchmark-setup-v1\n"
         "protocol.variant=laned\n"
         "benchmark.profile=quick\n"
         "geometry.B=${run_lanes}\n"
         "run.id=${run_name}\n"
         "setup.result=PASS\n")
endforeach()
file(CHMOD_RECURSE "${laned_cleanup_root}"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
execute_process(
    COMMAND "${CLEANUP}"
            --variant laned
            --profile quick
            --keep-run "${laned_keep}"
            --lanes 128
    RESULT_VARIABLE laned_cleanup_status
    OUTPUT_VARIABLE laned_cleanup_output
    ERROR_VARIABLE laned_cleanup_error)
if(NOT laned_cleanup_status EQUAL 0 OR
   NOT IS_DIRECTORY "${laned_keep}" OR EXISTS "${laned_old}" OR
   NOT IS_DIRECTORY "${laned_other_b}" OR
   NOT laned_cleanup_output MATCHES
       "CLEANUP COMPLETE: removed 1 matching run")
    message(FATAL_ERROR
            "Laned B-scoped cleanup failed: ${laned_cleanup_error}")
endif()

# Local cleanup uses the common immutable run binding but has no server role.
# Its namespace must remain disjoint from both other profiles and variants.
set(local_cleanup_root
    "${CMAKE_CURRENT_BINARY_DIR}/benchmark-local-cleanup")
set(local_runs "${local_cleanup_root}/runs")
set(local_keep "${local_runs}/local-quick-keep")
set(local_old "${local_runs}/local-quick-old")
set(local_other_profile
    "${local_runs}/local-target-balancedLaned-stays")
set(local_other_variant "${local_runs}/base-quick-stays")
file(REMOVE_RECURSE "${local_cleanup_root}")
foreach(directory IN ITEMS
        "${local_keep}" "${local_old}" "${local_other_profile}"
        "${local_other_variant}")
    file(MAKE_DIRECTORY "${directory}/shared" "${directory}/client")
    get_filename_component(run_name "${directory}" NAME)
    if("${directory}" STREQUAL "${local_other_profile}")
        set(run_variant local)
        set(run_profile target-balancedLaned)
    elseif("${directory}" STREQUAL "${local_other_variant}")
        set(run_variant base)
        set(run_profile quick)
    else()
        set(run_variant local)
        set(run_profile quick)
    endif()
    file(WRITE "${directory}/shared/run-binding.txt"
         "format=laminate-benchmark-run-v1\n"
         "run.variant=${run_variant}\n"
         "run.profile=${run_profile}\n"
         "run.id=${run_name}\n")
    file(WRITE "${directory}/shared/setup-result.txt"
         "format=laminate-benchmark-setup-v1\n"
         "run.variant=${run_variant}\n"
         "run.profile=${run_profile}\n"
         "run.id=${run_name}\n"
         "setup.result=PASS\n")
    file(WRITE "${directory}/shared/lifecycle.lock" "")
endforeach()
file(CHMOD_RECURSE "${local_cleanup_root}"
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
execute_process(
    COMMAND "${CLEANUP}"
            --variant local
            --profile quick
            --keep-run "${local_keep}"
    RESULT_VARIABLE local_cleanup_status
    OUTPUT_VARIABLE local_cleanup_output
    ERROR_VARIABLE local_cleanup_error)
if(NOT local_cleanup_status EQUAL 0 OR
   NOT IS_DIRECTORY "${local_keep}" OR EXISTS "${local_old}" OR
   NOT IS_DIRECTORY "${local_other_profile}" OR
   NOT IS_DIRECTORY "${local_other_variant}" OR
   NOT local_cleanup_output MATCHES
       "CLEANUP COMPLETE: removed 1 matching run")
    message(FATAL_ERROR
            "Local client-only cleanup failed: ${local_cleanup_error}")
endif()
execute_process(
    COMMAND "${CLEANUP}"
            --variant local
            --profile quick
            --keep-run "${local_keep}"
            --lanes 1
    RESULT_VARIABLE local_lanes_status
    OUTPUT_QUIET
    ERROR_VARIABLE local_lanes_error)
if(local_lanes_status EQUAL 0 OR
   NOT local_lanes_error MATCHES "--lanes is valid only for Laned cleanup")
    message(FATAL_ERROR "Local cleanup accepted a Laned width")
endif()

# Client computation is a disjoint cryptographic ledger, independent of
# reusable preprocessing loading and response transport diagnostics.
set(computation_fixture "${report_fixture_root}/client-computation")
file(MAKE_DIRECTORY "${computation_fixture}")
file(COPY "${explicit_per_request_fixture}/" DESTINATION "${computation_fixture}")
set(computation_setup_path "${computation_fixture}/shared/setup-result.txt")
file(READ "${computation_setup_path}" computation_setup)
set(computation_path "${computation_fixture}/client/result.txt")
file(READ "${computation_path}" computation_client)
file(MAKE_DIRECTORY "${computation_fixture}/shared/report")
set(computation_summary_path "${computation_fixture}/shared/report/computation.md")
execute_process(COMMAND "${RENDERER}" --run-dir "${computation_fixture}"
                --variant base --profile quick --output "${computation_summary_path}"
                RESULT_VARIABLE computation_status ERROR_VARIABLE computation_error
                OUTPUT_VARIABLE computation_summary)
if(NOT computation_status EQUAL 0)
    message(FATAL_ERROR "Base computation renderer failed: ${computation_error}")
endif()
file(READ "${computation_summary_path}" computation_summary)
foreach(required IN ITEMS
        "Per-request client computation | 230.000 ms" "Output decryption | 30.000 ms"
        "VCoED proof verification | 100.000 ms" "GKR proof verification | 90.000 ms"
        "Transcript recovery (FS, decryption, plaintext assembly) | 40.000 ms"
        "Plaintext GKR and affine gate-opening checks | 50.000 ms"
        "Terminal input MLE | 10.000 ms" "reusable RAM load; excluded from computation")
    string(FIND "${computation_summary}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Base computation summary omitted: ${required}")
    endif()
endforeach()
# A report must use the selected affine gate-opening policy.
string(REPLACE "parameters.gate_mle_basefold_queries=300\n"
               "parameters.gate_mle_basefold_queries=350\n"
               invalid_gate_setup "${computation_setup}")
file(WRITE "${computation_setup_path}" "${invalid_gate_setup}")
execute_process(COMMAND "${RENDERER}" --run-dir "${computation_fixture}"
                --variant base --profile quick
                RESULT_VARIABLE invalid_gate_status ERROR_VARIABLE invalid_gate_error
                OUTPUT_QUIET)
if(invalid_gate_status EQUAL 0 OR NOT invalid_gate_error MATCHES
   "unsupported affine gate-opening policy")
    message(FATAL_ERROR "Base accepted an unsupported gate policy: ${invalid_gate_error}")
endif()
file(WRITE "${computation_setup_path}" "${computation_setup}")
if(computation_summary MATCHES "Transcript-packing SNARK|Well-formedness noise checks")
    message(FATAL_ERROR "Base summary invented packed-only work")
endif()
execute_process(COMMAND "${SUMMARY_PYTHON_EXECUTABLE}" "${CONCISE_RENDERER}"
                --input "${computation_summary_path}" --output "${computation_fixture}/concise.md"
                RESULT_VARIABLE computation_concise_status ERROR_VARIABLE computation_concise_error)
if(NOT computation_concise_status EQUAL 0)
    message(FATAL_ERROR "Base concise computation failed: ${computation_concise_error}")
endif()
file(READ "${computation_fixture}/concise.md" computation_concise)
if(NOT computation_concise MATCHES "Per-request client computation \\| 230.000 ms" OR
   NOT computation_concise MATCHES "Terminal input MLE \\| 10.000 ms")
    message(FATAL_ERROR "Base concise summary omitted the computation hierarchy")
endif()
foreach(mutation IN ITEMS missing mixed unknown)
    if(mutation STREQUAL "missing")
        string(REPLACE "protocol.gkr_claim_transition=selector-interpolation-v1\n" ""
               transition_client "${computation_client}")
    elseif(mutation STREQUAL "mixed")
        string(REPLACE "selector-interpolation-v1" "invalid-transition"
               transition_client "${computation_client}")
    else()
        string(REPLACE "selector-interpolation-v1" "unknown"
               transition_client "${computation_client}")
    endif()
    file(WRITE "${computation_path}" "${transition_client}")
    execute_process(COMMAND "${RENDERER}" --run-dir "${computation_fixture}"
                    --variant base --profile quick
                    RESULT_VARIABLE transition_status OUTPUT_QUIET
                    ERROR_VARIABLE transition_error)
    if(transition_status EQUAL 0 OR NOT transition_error MATCHES "protocol.gkr_claim_transition")
        message(FATAL_ERROR "Base renderer accepted ${mutation} transition identity: ${transition_error}")
    endif()
endforeach()
file(WRITE "${computation_path}" "${computation_client}")
# Multiplication metadata must agree across all roles.
foreach(mutation IN ITEMS missing mixed)
    if(mutation STREQUAL "missing")
        string(REPLACE "protocol.gkr_multiplication=gruen-stripped-h0-v1\n" ""
               multiplication_client "${computation_client}")
    else()
        string(REPLACE "gruen-stripped-h0-v1" "unknown"
               multiplication_client "${computation_client}")
    endif()
    file(WRITE "${computation_path}" "${multiplication_client}")
    execute_process(COMMAND "${RENDERER}" --run-dir "${computation_fixture}"
                    --variant base --profile quick
                    RESULT_VARIABLE multiplication_status OUTPUT_QUIET
                    ERROR_VARIABLE multiplication_error)
    if(multiplication_status EQUAL 0 OR NOT multiplication_error MATCHES "protocol.gkr_multiplication")
        message(FATAL_ERROR "Base renderer accepted ${mutation} multiplication identity: ${multiplication_error}")
    endif()
endforeach()
file(WRITE "${computation_path}" "${computation_client}")
foreach(role_path IN ITEMS shared/setup-result.txt server/result.txt client/result.txt)
    file(READ "${computation_fixture}/${role_path}" multiplication_record)
    file(WRITE "${computation_fixture}/${role_path}.multiplication" "${multiplication_record}")
    string(REPLACE "protocol.gkr_multiplication=gruen-stripped-h0-v1\n" ""
           multiplication_record "${multiplication_record}")
    file(WRITE "${computation_fixture}/${role_path}" "${multiplication_record}")
endforeach()
execute_process(COMMAND "${RENDERER}" --run-dir "${computation_fixture}"
                --variant base --profile quick
                RESULT_VARIABLE multiplication_status OUTPUT_VARIABLE multiplication_summary
                ERROR_VARIABLE multiplication_error)
if(multiplication_status EQUAL 0 OR NOT multiplication_error MATCHES
   "protocol.gkr_multiplication")
    message(FATAL_ERROR "Base accepted missing multiplication metadata: ${multiplication_error}")
endif()
foreach(role_path IN ITEMS shared/setup-result.txt server/result.txt client/result.txt)
    file(READ "${computation_fixture}/${role_path}.multiplication" multiplication_record)
    file(WRITE "${computation_fixture}/${role_path}" "${multiplication_record}")
endforeach()

# Transition metadata is required even when every role omits it.
foreach(role_path IN ITEMS shared/setup-result.txt server/result.txt client/result.txt)
    file(READ "${computation_fixture}/${role_path}" transition_record)
    file(WRITE "${computation_fixture}/${role_path}.current" "${transition_record}")
    string(REPLACE "protocol.gkr_claim_transition=selector-interpolation-v1\n" ""
           transition_record "${transition_record}")
    file(WRITE "${computation_fixture}/${role_path}" "${transition_record}")
endforeach()
execute_process(COMMAND "${RENDERER}" --run-dir "${computation_fixture}"
                --variant base --profile quick
                RESULT_VARIABLE transition_status OUTPUT_VARIABLE transition_summary
                ERROR_VARIABLE transition_error)
if(transition_status EQUAL 0 OR NOT transition_error MATCHES
   "protocol.gkr_claim_transition")
    message(FATAL_ERROR "Base accepted missing transition metadata: ${transition_error}")
endif()
foreach(role_path IN ITEMS shared/setup-result.txt server/result.txt client/result.txt)
    file(READ "${computation_fixture}/${role_path}.current" transition_record)
    file(WRITE "${computation_fixture}/${role_path}" "${transition_record}")
endforeach()
string(REPLACE "timing.client.load_preprocessing.wall_ms=35"
               "timing.client.load_preprocessing.wall_ms=10000"
               changed_loading "${computation_client}")
string(REPLACE "timing.client.encode_request.wall_ms=20"
               "timing.client.encode_request.wall_ms=10000"
               changed_loading "${changed_loading}")
file(WRITE "${computation_path}" "${changed_loading}")
execute_process(COMMAND "${RENDERER}" --run-dir "${computation_fixture}"
                --variant base --profile quick RESULT_VARIABLE changed_loading_status
                OUTPUT_VARIABLE changed_loading_summary ERROR_VARIABLE changed_loading_error)
if(NOT changed_loading_status EQUAL 0 OR
   NOT changed_loading_summary MATCHES "Per-request client computation \\| 230.000 ms")
    message(FATAL_ERROR "Loading or transport changed client computation: ${changed_loading_error}")
endif()
foreach(mutation IN ITEMS
        "verify.gkr.plaintext.wall_ms=50|verify.gkr.plaintext.wall_ms=51"
        "verify.vcoed.cpu_ms=95|verify.vcoed.cpu_ms=96"
        "computation_total.wall_ms=230|computation_total.wall_ms=231"
        "per_request_total.wall_ms=230|per_request_total.wall_ms=231"
        "verify.terminal_input_mle.cpu_ms=10|verify.terminal_input_mle.cpu_ms=-1"
        "verify.transcript_packing_snark.wall_ms=0|verify.transcript_packing_snark.wall_ms=1"
        "computation.schema=vcoed-client-computation-v1|computation.schema=unknown")
    string(REPLACE "|" ";" parts "${mutation}")
    list(GET parts 0 before)
    list(GET parts 1 after)
    string(REPLACE "timing.client.${before}" "timing.client.${after}"
           mutated_client "${computation_client}")
    file(WRITE "${computation_path}" "${mutated_client}")
    execute_process(COMMAND "${RENDERER}" --run-dir "${computation_fixture}"
                    --variant base --profile quick RESULT_VARIABLE mutation_status
                    OUTPUT_QUIET ERROR_VARIABLE mutation_error)
    if(mutation_status EQUAL 0)
        message(FATAL_ERROR "Base accepted malformed computation ledger: ${mutation}")
    endif()
endforeach()
foreach(missing IN ITEMS "computation.schema" "verify.gkr.plaintext.cpu_ms")
    string(REGEX REPLACE "timing.client.${missing}=[^\n]*\n" ""
           partial_client "${computation_client}")
    file(WRITE "${computation_path}" "${partial_client}")
    execute_process(COMMAND "${RENDERER}" --run-dir "${computation_fixture}"
                    --variant base --profile quick RESULT_VARIABLE partial_status
                    OUTPUT_QUIET ERROR_VARIABLE partial_error)
    if(partial_status EQUAL 0)
        message(FATAL_ERROR "Base accepted incomplete computation ledger: ${missing}")
    endif()
endforeach()
file(WRITE "${computation_path}" "${computation_client}")

file(REMOVE_RECURSE "${cleanup_root}")
file(REMOVE_RECURSE "${packed_cleanup_root}")
file(REMOVE_RECURSE "${laned_cleanup_root}")
file(REMOVE_RECURSE "${local_cleanup_root}")
file(REMOVE_RECURSE "${report_fixture_root}")
