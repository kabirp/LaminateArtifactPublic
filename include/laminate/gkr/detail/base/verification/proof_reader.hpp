#ifndef LAMINATE_GKR_DETAIL_BASE_VERIFICATION_PROOF_READER_HPP
#define LAMINATE_GKR_DETAIL_BASE_VERIFICATION_PROOF_READER_HPP

/// @file proof_reader.hpp
/// @brief Decrypt Base proof messages behind a small typed interface.

#include "laminate/gkr/base.hpp"

#include <vector>

namespace laminate::gkr::base_detail {

/// Typed boundary between Base verification and extension-field decoding.
template <fhe::FheBackend Backend> class ProofReader {
  public:
    explicit ProofReader(const typename Backend::ClientContext &client)
        : client_(client) {}

    std::vector<Fpk> read(
        const fhe::ExtensionValue<Backend> &value) const {
        return fhe::read_extension_value<Backend>(client_, value);
    }

  private:
    const typename Backend::ClientContext &client_;
};

} // namespace laminate::gkr::base_detail

#endif // LAMINATE_GKR_DETAIL_BASE_VERIFICATION_PROOF_READER_HPP
