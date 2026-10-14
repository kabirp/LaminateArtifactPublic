#ifndef LAMINATE_FHE_EXTENSION_HPP
#define LAMINATE_FHE_EXTENSION_HPP

/// @file extension.hpp
/// @brief Canonical facade for backend-generic extension-ciphertext helpers.
///
/// Most consumers should include this file. The responsibility-specific
/// headers underneath `fhe/extension/` are independently includable when a
/// narrow dependency is useful.

#include "laminate/fhe/extension/prepared_basis.hpp"
#include "laminate/fhe/extension/accumulator.hpp"
#include "laminate/fhe/extension/arithmetic.hpp"
#include "laminate/fhe/extension/folding.hpp"
#include "laminate/fhe/extension/packing.hpp"
#include "laminate/fhe/extension/io.hpp"

#endif // LAMINATE_FHE_EXTENSION_HPP
