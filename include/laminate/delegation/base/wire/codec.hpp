#ifndef LAMINATE_DELEGATION_BASE_WIRE_CODEC_HPP
#define LAMINATE_DELEGATION_BASE_WIRE_CODEC_HPP

/// @file codec.hpp
/// @brief Public navigation header for Base request and response transport.
///
/// The Base process boundary is one `BaseRequest` followed by one
/// `BaseResponse`. Request framing lives in `request.hpp`; setup-shaped proof
/// decoding and response framing live in `response.hpp`. Internal field and
/// proof codecs are deliberately hidden under `wire/detail/`.

#include "laminate/delegation/base/wire/request.hpp"
#include "laminate/delegation/base/wire/response.hpp"

#endif // LAMINATE_DELEGATION_BASE_WIRE_CODEC_HPP
