set(SEAL_VERSION "4.1.2")
set(SEAL_USE_INTEL_HEXL ON)
set(SEAL_DEBUG OFF)

if(NOT TARGET SEAL::seal)
    add_library(SEAL::seal INTERFACE IMPORTED)
endif()
