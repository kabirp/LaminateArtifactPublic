/// @file test_committed_message_codec.cpp
/// @brief Canonical public packed messages and their exact transcript digest.

#include "test_helpers.hpp"

#include "laminate/fhe/extension/packing.hpp"
#include "laminate/fhe/mock_backend.hpp"
#include "laminate/protocol/detail/packing/committed_gkr_encoding.hpp"
#include "laminate/protocol/packed/wire/detail/committed_gkr.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace laminate;
using namespace laminate::fhe;
using namespace laminate::gkr;
namespace decode = protocol::detail::packed_proof_decode_detail;

namespace {

std::vector<std::uint8_t> encode(const CommittedPackedMessage &message) {
    std::vector<std::uint8_t> result;
    append_committed_packed_message(result, message);
    return result;
}

CommittedPackedMessage decode_message(
    const std::vector<std::uint8_t> &bytes, std::size_t slots,
    std::size_t field_budget = 20000) {
    const auto contexts = MockBackend::create(MockParameters{.slot_count = slots});
    const protocol::PackedProofDecodeLimits limits{
        .max_collection_elements = 20000,
        .max_total_field_elements = field_budget,
        .max_total_digests = 1};
    const auto base = decode::base_limits(limits);
    decode::DecodeBudget budget(base, "test committed message");
    decode::Reader reader(bytes, "test committed message");
    auto result = decode::read_committed_message<MockBackend>(
        reader, contexts.eval, budget, limits, "test committed message");
    reader.require_end();
    return result;
}

template <typename Function> bool rejects(Function &&function) {
    try {
        std::forward<Function>(function)();
        return false;
    } catch (const std::invalid_argument &) {
        return true;
    } catch (const std::runtime_error &) {
        return true;
    }
}

void write_u64(std::vector<std::uint8_t> &bytes, std::size_t offset,
               std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        bytes.at(offset + byte) =
            static_cast<std::uint8_t>(value >> (8U * byte));
    }
}

CommittedPackedMessage public_slots(SlotVector slots) {
    return CommittedPackedMessage::public_message(
        PublicPlaintext::from_slots(std::move(slots)));
}

std::vector<std::uint8_t> sparse_fixture() {
    SlotVector slots(64, Fp::zero());
    slots[3] = Fp(19);
    slots[9] = Fp(29);
    return encode(public_slots(std::move(slots)));
}

} // namespace

int main() {
    test::Runner runner("test_committed_message_codec");

    runner.run("commitment policies bind six canonical field elements", [] {
        const auto poseidon = CiphertextCommitmentPolicy::poseidon_v2();
        const auto diagnostic =
            CiphertextCommitmentPolicy::diagnostic_simple_ct_hash_v2();
        CHECK(poseidon.wire_code() == 3);
        CHECK(diagnostic.wire_code() == 4);
        CHECK(CiphertextCommitmentPolicy::from_wire_code(3) == poseidon);
        CHECK(CiphertextCommitmentPolicy::from_wire_code(4) == diagnostic);
        for (const std::uint64_t reserved : {0U, 1U, 2U, 5U}) {
            CHECK(rejects([&] {
                (void)CiphertextCommitmentPolicy::from_wire_code(reserved);
            }));
        }
        const auto fields = diagnostic_simple_ct_hash_output_fields(Fq(7));
        CHECK(fields.size() == 6);
        for (std::size_t index = 0; index < fields.size(); ++index) {
            CHECK(fields[index] == Fq(7) +
                  Fq(kDiagnosticSimpleCtHashOutputDomains[index]));
        }
        CHECK(PoseidonDigest{}.size() == 48);
        auto malformed = PoseidonDigest{};
        for (std::size_t byte = 0; byte < 8; ++byte) {
            malformed[5 * 8 + byte] = static_cast<std::uint8_t>(
                kOuterFieldOrder >> (8U * byte));
        }
        CHECK(rejects([&] {
            (void)poseidon_digest_field_elements(malformed);
        }));
    });

    runner.run("scalar dense sparse and encrypted forms round trip", [] {
        const auto scalar = CommittedPackedMessage::public_message(
            PublicPlaintext::from_scalar(Fp(17)));
        CHECK(encode(scalar).size() == 10);
        CHECK(decode_message(encode(scalar), 64).plaintext() == scalar.plaintext());

        const auto dense = public_slots({Fp(1), Fp(0), Fp(2), Fp(3)});
        const auto dense_bytes = encode(dense);
        CHECK(dense_bytes.size() == 42);
        CHECK(dense_bytes[1] == 1);
        CHECK(decode_message(dense_bytes, 4).plaintext() == dense.plaintext());

        // 18+16*2 == 10+8*5: equal-size representations must use dense.
        const auto tie = public_slots({Fp(1), Fp(0), Fp(2), Fp(0), Fp(0)});
        CHECK(encode(tie)[1] == 1);
        CHECK(!committed_public_uses_sparse(5, 2));

        const auto sparse = sparse_fixture();
        CHECK(sparse.size() == 50);
        CHECK(sparse[1] == 2);
        CHECK(encode(decode_message(sparse, 64)) == sparse);

        PackedMessageCommitment commitment{};
        commitment.digest.fill(23);
        const auto encrypted = CommittedPackedMessage::encrypted_message(commitment);
        CHECK(encode(encrypted).size() == 1 + commitment.digest.size());
        CHECK(decode_message(encode(encrypted), 64).commitment() == commitment);
    });

    runner.run("sparse decoder rejects alternate forms and malformed entries", [] {
        const auto original = sparse_fixture();
        const auto bad_u64 = [&](std::size_t offset, std::uint64_t value) {
            auto bytes = original;
            write_u64(bytes, offset, value);
            CHECK(rejects([&] { (void)decode_message(bytes, 64); }));
        };
        bad_u64(2, 128); // Context slot count differs.
        bad_u64(10, 0); // Public zero belongs in scalar form.
        bad_u64(10, 32); // Sparse must be strictly shorter than dense.
        bad_u64(18, 64); // First index is out of range.
        bad_u64(34, 3); // Duplicate index.
        bad_u64(34, 2); // Decreasing index.
        bad_u64(26, 0); // Sparse entries are nonzero.
        bad_u64(26, kBaseFieldOrder); // No modular reduction of wire fields.
        auto bytes = original;
        bytes.pop_back();
        CHECK(rejects([&] { (void)decode_message(bytes, 64); }));
        bytes = original;
        bytes.push_back(0);
        CHECK(rejects([&] { (void)decode_message(bytes, 64); }));
        bytes = original;
        bytes[1] = 3;
        CHECK(rejects([&] { (void)decode_message(bytes, 64); }));
        CHECK(rejects([&] { (void)decode_message(original, 64, 63); }));

        bytes.assign(10 + 8 * 64, 0);
        bytes[1] = 1;
        write_u64(bytes, 2, 64);
        write_u64(bytes, 10 + 8 * 3, 19);
        CHECK(rejects([&] { (void)decode_message(bytes, 64); }));
        for (std::size_t slot = 0; slot < 64; ++slot) {
            write_u64(bytes, 10 + 8 * slot, 1);
        }
        CHECK(rejects([&] { (void)decode_message(bytes, 64); }));
    });

    runner.run("streamed digest hashes exactly the canonical bytes", [] {
        for (const auto variant : {ProtocolVariant::LaminateFolded,
                                   ProtocolVariant::LaminateLaned}) {
            CommittedFoldedGkrProof proof;
            proof.header.profile.variant = variant;
            CommittedFoldedAffineLayerReduction reduction;
            reduction.rounds.push_back({decode_message(sparse_fixture(), 64)});
            reduction.rounds.push_back({public_slots({Fp(1), Fp(2), Fp(3)})});
            reduction.packed_terminal_value = CommittedPackedMessage::public_message(
                PublicPlaintext::from_scalar(Fp(7)));
            proof.reductions.emplace_back(std::move(reduction));
            const auto bytes = protocol::detail::encode_committed_gkr(proof);
            CHECK(bytes[16] == '3');
            CHECK(protocol::detail::committed_gkr_encoding_digest(proof) == sha256(bytes));
        }
    });

    runner.run("public fixed messages retain at most sixteen occupied cells", [] {
        for (const std::size_t slots : {16U, 32U, 64U, 16384U}) {
            const auto contexts = MockBackend::create(MockParameters{.slot_count = slots});
            std::array<ExtensionValue<MockBackend>, 2> values{};
            for (std::size_t value = 0; value < values.size(); ++value) {
                for (std::size_t coefficient = 0; coefficient < kExtensionDegree;
                     ++coefficient) {
                    // Nonuniform values cover public intermediate results, too.
                    SlotVector source(slots, Fp::zero());
                    for (std::size_t slot = 0; slot < slots; ++slot) {
                        source[slot] = Fp(1 + slot + coefficient + 8 * value);
                    }
                    values[value][coefficient] =
                        FheValue<MockBackend>::public_slots(std::move(source));
                }
            }
            const auto packed = pack_replicated_extension_values<MockBackend>(
                contexts.eval, values);
            CHECK(packed.is_public());
            const auto materialized = packed.plaintext().materialize(slots);
            std::vector<bool> allowed(slots, false);
            for (std::size_t cell = 0; cell < kFixedMessageCellCount; ++cell) {
                allowed[fixed_message_cell_slot(slots, cell)] = true;
            }
            for (std::size_t slot = 0; slot < slots; ++slot) {
                CHECK(allowed[slot] || materialized[slot] == Fp::zero());
            }
            CHECK(committed_public_nonzero_count(materialized) == 16);
            const auto bytes = encode(commit_packed_message<MockBackend>(packed));
            CHECK(bytes.size() <= kCommittedPublicSparseHeaderBytes +
                                      kFixedMessageCellCount * kCommittedPublicSparseEntryBytes);
            CHECK(decode_message(bytes, slots).plaintext() == packed.plaintext());
            if (slots >= 64) {
                CHECK(bytes.size() == 274);
            }
        }
    });
    return runner.summary();
}
