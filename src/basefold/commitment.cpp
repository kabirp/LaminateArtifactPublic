#include "laminate/basefold/commitment.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/basefold/reed_solomon.hpp"

#include <stdexcept>
#include <utility>

namespace laminate::basefold {

Commitment::Commitment(
    std::size_t message_length, std::size_t inverse_rate_log,
    std::vector<std::vector<Fp>> message_columns,
    std::vector<std::vector<Fp>> encoded_columns,
    MerkleTree commitment_tree)
    : m(message_length), log_rate(inverse_rate_log),
      width(message_columns.size()), columns(std::move(message_columns)),
      codewords(std::move(encoded_columns)), tree(std::move(commitment_tree)),
      root(tree.root()) {}

Commitment commit(std::vector<std::vector<Fp>> columns,
                  std::size_t log_rate) {
    if (columns.empty() || (columns.size() & (columns.size() - 1)) != 0 ||
        columns.front().empty()) {
        throw std::invalid_argument(
            "basefold::commit: width and length must be powers of two");
    }

    const std::size_t m = columns.front().size();
    const std::size_t encoded_size = codeword_length(m, log_rate);
    std::vector<std::vector<Fp>> codewords(columns.size());
    for (std::size_t column = 0; column < columns.size(); ++column) {
        if (columns[column].size() != m) {
            throw std::invalid_argument(
                "basefold::commit: columns must have equal length");
        }
        codewords[column] = reed_solomon_encode(
            evaluations_to_coefficients(columns[column]), log_rate);
    }

    std::vector<std::vector<std::uint8_t>> leaves(encoded_size);
    for (std::size_t position = 0; position < encoded_size; ++position) {
        std::vector<Fp> leaf;
        leaf.reserve(columns.size());
        for (const std::vector<Fp> &codeword : codewords) {
            leaf.push_back(codeword[position]);
        }
        leaves[position] = serialize_values(leaf);
    }
    MerkleTree tree(leaves);
    return Commitment(m, log_rate, std::move(columns), std::move(codewords),
                      std::move(tree));
}

} // namespace laminate::basefold
