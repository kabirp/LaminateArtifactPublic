include_guard(GLOBAL)

function(laminate_processor_is_x86_64 output processor)
    string(TOLOWER "${processor}" normalized_processor)
    if(normalized_processor MATCHES "^(amd64|x86_64|x64)$")
        set(${output} TRUE PARENT_SCOPE)
    else()
        set(${output} FALSE PARENT_SCOPE)
    endif()
endfunction()

function(laminate_classify_seal_acceleration output processor hexl_enabled)
    laminate_processor_is_x86_64(is_x86_64 "${processor}")
    if(is_x86_64 AND hexl_enabled)
        set(mode "intel-hexl-runtime-dispatch")
    elseif(is_x86_64)
        set(mode "portable-seal-x86-64")
    elseif(hexl_enabled)
        set(mode "unsupported-intel-hexl-non-x86")
    else()
        set(mode "portable-seal-non-x86")
    endif()
    set(${output} "${mode}" PARENT_SCOPE)
endfunction()

function(laminate_find_seal version_output acceleration_output hexl_output)
    if(LAMINATE_SEAL_DIR)
        find_package(SEAL 4.1 CONFIG QUIET HINTS "${LAMINATE_SEAL_DIR}")
    else()
        find_package(SEAL 4.1 CONFIG QUIET)
    endif()
    if(NOT TARGET SEAL::seal)
        message(FATAL_ERROR
            "LAMINATE_WITH_SEAL=ON requires Microsoft SEAL 4.1. "
            "Set LAMINATE_SEAL_DIR to the directory containing SEALConfig.cmake.")
    endif()
    if(NOT DEFINED SEAL_USE_INTEL_HEXL)
        message(FATAL_ERROR
            "The selected SEAL package does not report SEAL_USE_INTEL_HEXL. "
            "Use an official Microsoft SEAL 4.1 package.")
    endif()

    laminate_processor_is_x86_64(is_x86_64 "${CMAKE_SYSTEM_PROCESSOR}")
    laminate_classify_seal_acceleration(
        acceleration "${CMAKE_SYSTEM_PROCESSOR}" "${SEAL_USE_INTEL_HEXL}")

    if(LAMINATE_REQUIRE_SEAL_HEXL AND NOT is_x86_64)
        message(FATAL_ERROR
            "LAMINATE_REQUIRE_SEAL_HEXL=ON is only valid for an x86-64 target; "
            "${CMAKE_SYSTEM_PROCESSOR} cannot execute Intel AVX-512 kernels.")
    endif()
    if(LAMINATE_REQUIRE_SEAL_HEXL AND NOT SEAL_USE_INTEL_HEXL)
        message(FATAL_ERROR
            "This x86-64 build requires a SEAL package configured with "
            "-DSEAL_USE_INTEL_HEXL=ON. Rebuild SEAL; the option cannot be "
            "enabled after linking a prebuilt SEAL library.")
    endif()
    if(acceleration STREQUAL "unsupported-intel-hexl-non-x86")
        message(FATAL_ERROR
            "The selected SEAL package enables Intel HEXL but the target is "
            "${CMAKE_SYSTEM_PROCESSOR}.")
    endif()

    if(SEAL_DEBUG)
        message(WARNING
            "The selected SEAL package is a Debug build; benchmark timings "
            "will not represent optimized execution.")
    endif()
    if(acceleration STREQUAL "intel-hexl-runtime-dispatch")
        message(STATUS
            "Laminate SEAL acceleration: Intel HEXL enabled. HEXL selects "
            "AVX-512 kernels at runtime when the CPU supports them.")
    elseif(acceleration STREQUAL "portable-seal-x86-64")
        message(WARNING
            "Laminate SEAL acceleration: portable x86-64 kernels. Intel HEXL "
            "is disabled, so this build is not suitable for headline x86 "
            "benchmarks.")
    else()
        message(STATUS
            "Laminate SEAL acceleration: portable non-x86 kernels; Intel "
            "HEXL and AVX-512 are unavailable for ${CMAKE_SYSTEM_PROCESSOR}.")
    endif()

    # Package variables set by find_package() are local to this function.
    # Export every feature consumed by a later directory explicitly; otherwise
    # SEAL can use HEXL while Laminate silently compiles its native-Fq fallback.
    set(${version_output} "${SEAL_VERSION}" PARENT_SCOPE)
    set(${acceleration_output} "${acceleration}" PARENT_SCOPE)
    set(${hexl_output} "${SEAL_USE_INTEL_HEXL}" PARENT_SCOPE)
endfunction()
