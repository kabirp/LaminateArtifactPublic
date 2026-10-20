#ifndef LAMINATE_DELEGATION_DETAIL_FILE_TRACE_AND_OUTPUT_SINK_HPP
#define LAMINATE_DELEGATION_DETAIL_FILE_TRACE_AND_OUTPUT_SINK_HPP

/// @file file_trace_and_output_sink.hpp
/// @brief Persist an encrypted trace while retaining its output response.

#include "laminate/payload/storage/file_trace_store.hpp"

#include <cstddef>
#include <filesystem>
#include <limits>
#include <utility>

namespace laminate::delegation::server_storage_detail {

template <fhe::PersistableFheBackend Backend, typename Output>
struct FileTraceAndOutputResult {
    payload::FileTraceStoreWriteResult trace_store;
    Output output;
};

/// Compact sink used by both packed variants. Every trace value is streamed
/// to disk; only layer zero is copied into the one server response.
template <fhe::PersistableFheBackend Backend, typename Output>
class FileTraceAndOutputSink {
  public:
    static constexpr bool stores_only_live_wires = true;

    FileTraceAndOutputSink(const typename Backend::EvalContext &eval,
                           std::filesystem::path directory,
                           payload::FileTraceStoreOptions options)
        : inner_(eval, std::move(directory), options) {}

    Digest storage_context_id() const {
        return inner_.storage_context_id();
    }

    void begin_trace(const payload::PayloadShape &shape,
                     payload::TraceProvenance provenance,
                     const Digest &circuit_id, const Digest &trace_id,
                     std::size_t layer_count) {
        inner_.begin_trace(shape, provenance, circuit_id, trace_id,
                           layer_count);
    }

    void begin_layer(std::size_t layer_index,
                     payload::TraceLayerLayout layout,
                     const payload::LayerDimensions &dimensions,
                     std::size_t required_mult_depth,
                     std::size_t value_count) {
        active_layer_ = layer_index;
        if (layer_index == 0) {
            output_.dimensions = dimensions;
            output_.values.clear();
            output_.values.reserve(value_count);
        }
        inner_.begin_layer(layer_index, layout, dimensions,
                           required_mult_depth, value_count);
    }

    void append_value(fhe::FheValue<Backend> value) {
        if (active_layer_ == 0) {
            output_.values.push_back(value);
        }
        inner_.append_value(std::move(value));
    }

    void finish_layer() {
        inner_.finish_layer();
        active_layer_ = no_active_layer();
    }

    FileTraceAndOutputResult<Backend, Output> finish() && {
        return FileTraceAndOutputResult<Backend, Output>{
            std::move(inner_).finish(), std::move(output_)};
    }

  private:
    static constexpr std::size_t no_active_layer() {
        return std::numeric_limits<std::size_t>::max();
    }

    payload::FileEncryptedTraceSink<Backend> inner_;
    std::size_t active_layer_ = no_active_layer();
    Output output_;
};

} // namespace laminate::delegation::server_storage_detail

#endif // LAMINATE_DELEGATION_DETAIL_FILE_TRACE_AND_OUTPUT_SINK_HPP
