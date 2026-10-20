#ifndef LAMINATE_GKR_DETAIL_SHARED_PACKED_MESSAGE_READER_HPP
#define LAMINATE_GKR_DETAIL_SHARED_PACKED_MESSAGE_READER_HPP

/// @file message_reader.hpp
/// @brief Decrypt fixed-size protocol messages behind a typed API.

#include "laminate/gkr/base.hpp"

namespace laminate::gkr::detail {

/// Reads logical extension-field values from one public-or-encrypted fixed
/// message produced by `fhe::pack_replicated_extension_values`.
template <fhe::FheBackend Backend> class FixedMessageReader {
  public:
    explicit FixedMessageReader(
        const typename Backend::ClientContext &client)
        : client_(client) {}

    /// Materialize or decrypt exactly `value_count` extension scalars.
    std::vector<Fpk> read(const fhe::FheValue<Backend> &packed,
                          std::size_t value_count) const {
        return fhe::unpack_extension_scalars<Backend>(
            client_, packed, value_count);
    }

  private:
    const typename Backend::ClientContext &client_;
};

} // namespace laminate::gkr::detail

#endif // LAMINATE_GKR_DETAIL_SHARED_PACKED_MESSAGE_READER_HPP
