#include "laminate/fhe/layout/slot_grid.hpp"

#include <stdexcept>
#include <string>

namespace laminate::fhe {
namespace {

void validate_slot_count(std::size_t slot_count, const char *operation) {
    if (slot_count < 2 || (slot_count & (slot_count - 1)) != 0) {
        throw std::invalid_argument(std::string(operation) +
                                    ": slot count must be a power of two >= 2");
    }
}

} // namespace

std::size_t grid_source(std::size_t slot_count, std::size_t steps,
                        std::size_t destination) {
    validate_slot_count(slot_count, "grid_source");
    if (destination >= slot_count) {
        throw std::invalid_argument("grid_source: destination is out of range");
    }

    const std::size_t normalized = steps % slot_count;
    const std::size_t half = slot_count / 2;
    const std::size_t shift = normalized % half;
    const bool swap_rows = normalized >= half;
    const std::size_t row = destination / half;
    const std::size_t column = destination % half;
    const std::size_t source_row = swap_rows ? 1 - row : row;
    return source_row * half + ((column + shift) % half);
}

SlotVector grid_rotate(std::span<const Fp> slots, std::size_t steps) {
    validate_slot_count(slots.size(), "grid_rotate");
    SlotVector result(slots.size());
    for (std::size_t destination = 0; destination < slots.size();
         ++destination) {
        result[destination] =
            slots[grid_source(slots.size(), steps, destination)];
    }
    return result;
}

std::size_t grid_compose(std::size_t slot_count, std::size_t first,
                         std::size_t second) {
    validate_slot_count(slot_count, "grid_compose");
    const std::size_t half = slot_count / 2;
    const std::size_t shift =
        ((first % slot_count) % half + (second % slot_count) % half) % half;
    const bool swap_rows = ((first % slot_count) >= half) ^
                           ((second % slot_count) >= half);
    return (swap_rows ? half : 0) + shift;
}

std::size_t grid_inverse(std::size_t slot_count, std::size_t steps) {
    validate_slot_count(slot_count, "grid_inverse");
    const std::size_t half = slot_count / 2;
    const std::size_t normalized = steps % slot_count;
    const std::size_t shift = normalized % half;
    const bool swap_rows = normalized >= half;
    return (swap_rows ? half : 0) + ((half - shift) % half);
}

} // namespace laminate::fhe
