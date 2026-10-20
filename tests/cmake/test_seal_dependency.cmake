include("${MODULE}")

function(expect_mode processor hexl_enabled expected)
    laminate_classify_seal_acceleration(
        actual "${processor}" "${hexl_enabled}")
    if(NOT actual STREQUAL expected)
        message(FATAL_ERROR
            "${processor}, HEXL=${hexl_enabled}: expected ${expected}, got ${actual}")
    endif()
endfunction()

expect_mode("x86_64" ON "intel-hexl-runtime-dispatch")
expect_mode("AMD64" OFF "portable-seal-x86-64")
expect_mode("arm64" OFF "portable-seal-non-x86")
expect_mode("aarch64" ON "unsupported-intel-hexl-non-x86")
