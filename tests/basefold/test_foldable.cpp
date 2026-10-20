#include "test_helpers.hpp"
#include "laminate/basefold/foldable.hpp"
#include "laminate/basefold/common.hpp"
#include "laminate/basefold/foldable_query_policy.hpp"
#include "laminate/basefold/reed_solomon.hpp"
#include "laminate/transcript/transcript.hpp"
#include <filesystem>
#include <fstream>
#include <limits>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>

using namespace laminate;
namespace fb = laminate::basefold::foldable;
namespace {
struct Scratch {
    std::filesystem::path path =
        std::filesystem::temp_directory_path() /
        ("laminate-foldable-test-" + std::to_string(::getpid()));
    Scratch() {
        std::filesystem::remove_all(path);
        std::filesystem::create_directories(path);
    }
    ~Scratch() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
};
std::vector<Fpk> table(std::size_t n) {
    std::vector<Fpk> values(n);
    for (std::size_t i = 0; i < n; ++i) {
        Fpk::Coefficients c{};
        c[0] = Fp(i * i + 31 * i + 7);
        c[1] = Fp(5 * i + 19);
        c[7] = Fp(i + 1);
        values[i] = Fpk(c);
    }
    return values;
}
bool throws(const std::function<void()> &f) {
    try {
        f();
        return false;
    } catch (const std::exception &) {
        return true;
    }
}
Fpk dot(std::span<const Fpk> a, std::span<const Fpk> b) {
    Fpk sum;
    for (std::size_t i = 0; i < a.size(); ++i)
        sum += a[i] * b[i];
    return sum;
}
std::vector<Fpk> block_table(const fb::BlockOperand &operand, std::size_t m) {
    std::vector<Fpk> result(m);
    const auto rows = std::size_t{1} << operand.point_lsb.size();
    for (std::size_t column = 0; column < operand.column_weights.size();
         ++column)
        for (std::size_t row = 0; row < rows; ++row)
            result[operand.offset + column * rows + row] =
                operand.column_weights[column] *
                basefold::equality_evaluation(row, operand.point_lsb);
    return result;
}
// Mirror the transparent preamble so a generic prover can serve as an
// independent dense reference and construct false residual claims below.
void bind_blocks(std::span<const fb::BlockOperand> operands, PublicCoin &coin) {
    coin.observe("foldable/block-operands/version", std::uint64_t{1});
    coin.observe("foldable/block-operands/count", operands.size());
    for (const auto &operand : operands) {
        coin.observe("foldable/block-operands/offset", operand.offset);
        coin.observe("foldable/block-operands/row-variables",
                     operand.point_lsb.size());
        coin.observe("foldable/block-operands/point",
                     basefold::serialize_values(operand.point_lsb));
        coin.observe("foldable/block-operands/columns",
                     operand.column_weights.size());
        coin.observe("foldable/block-operands/weights",
                     basefold::serialize_values(operand.column_weights));
    }
}
}
int main() {
    test::Runner runner("test_foldable");
    Scratch scratch;
    runner.run("canonical disk storage bounds and exclusive creation", [&] {
        const auto path = scratch.path / "array";
        auto array = fb::ScalarArray::create(path, 19);
        CHECK(array.get(18) == Fpk::zero());
        auto values = table(19);
        array.write(0, values);
        std::vector<Fpk> read(19);
        array.read(0, read);
        CHECK(read == values);
        CHECK(throws([&] { array.read(18, read); }));
        CHECK(throws([&] { fb::ScalarArray::create(path, 1); }));
        {
            auto alias = array;
            array = {};
            CHECK(alias.get(3) == values[3]);
        }
        CHECK(!std::filesystem::exists(path));
        auto malformed =
            fb::ScalarArray::create(scratch.path / "noncanonical", 1);
        {
            std::fstream file(malformed.path(),
                              std::ios::binary | std::ios::in | std::ios::out);
            const char bad[3] = {-1, -1, -1};
            file.write(bad, 3);
        }
        CHECK(throws([&] { (void)malformed.get(0); }));
    });
    runner.run("persisted commitments survive scratch cleanup and preserve proofs", [&] {
        for (const auto width : std::array<std::size_t, 2>{1, 2}) {
            const auto original_path = scratch.path / ("original-" + std::to_string(width));
            const auto saved_path = scratch.path / ("saved-" + std::to_string(width));
            const auto values = table(32), operand = table(32);
            const std::array<fb::ValueSource, 2> columns{
                fb::source(values), fb::source(values)};
            auto original = fb::commit(std::span(columns).first(width), original_path);
            const auto metadata = original.metadata;
            const std::array<fb::ValueSource, 1> operands{fb::source(operand)};
            const std::vector<Fpk> weights(width, Fpk::one());
            const std::array<Fpk, 1> targets{dot(values, operand) * Fp(width)};
            const auto premise = width == 1
                ? fb::CommitmentPremise::ArbitrarySingleColumn
                : fb::CommitmentPremise::HonestCodewordColumns;
            Transcript before_coin("persistent-foldable-test");
            const auto before = fb::prove(original, operands, weights, targets,
                before_coin, scratch.path, premise);
            fb::export_commitment(original, saved_path);
            CHECK(throws([&] { fb::export_commitment(original, saved_path); }));
            original = {};
            std::filesystem::remove_all(original_path);
            {
                auto reopened = fb::reopen_commitment(saved_path, metadata);
                CHECK(reopened.metadata == metadata);
                CHECK(reopened.columns.front().get(7) == values[7]);
                CHECK(throws([&] { reopened.columns.front().set(0, Fpk::zero()); }));
                CHECK(throws([&] { reopened.codewords.front().set(0, Fpk::zero()); }));
                Transcript after_coin("persistent-foldable-test");
                const auto after = fb::prove(reopened, operands, weights, targets,
                    after_coin, scratch.path, premise);
                CHECK(fb::encode_canonical(before.proof) == fb::encode_canonical(after.proof));
                CHECK(before_coin.challenge_fpk() == after_coin.challenge_fpk());
                Transcript verifier("persistent-foldable-test");
                CHECK(fb::verify(metadata, 1, weights, targets, after.proof,
                                 verifier, premise).has_value());
            }
            CHECK(std::filesystem::exists(saved_path / "column-0"));
            CHECK(fb::reopen_commitment(saved_path, metadata).metadata == metadata);
        }
    });
    runner.run("persisted commitment rejects mismatches, truncation and special files", [&] {
        const auto values = table(8);
        const std::array<fb::ValueSource, 1> columns{fb::source(values)};
        auto original = fb::commit(columns, scratch.path);
        const auto saved = scratch.path / "tamper-source";
        fb::export_commitment(original, saved);
        auto bad_metadata = original.metadata;
        bad_metadata.root[0] ^= 1;
        CHECK(throws([&] { fb::reopen_commitment(saved, bad_metadata); }));
        bad_metadata = original.metadata;
        bad_metadata.m *= 2;
        CHECK(throws([&] { fb::reopen_commitment(saved, bad_metadata); }));
        std::size_t serial = 0;
        const auto tamper = [&](const auto &change) {
            const auto path = scratch.path / ("tamper-" + std::to_string(serial++));
            std::filesystem::copy(saved, path, std::filesystem::copy_options::recursive);
            change(path);
            CHECK(throws([&] { fb::reopen_commitment(path, original.metadata); }));
        };
        tamper([](const auto &p) { std::filesystem::resize_file(p / "manifest", 1); });
        tamper([](const auto &p) { std::ofstream(p / "manifest", std::ios::app).put('x'); });
        tamper([](const auto &p) { std::filesystem::resize_file(p / "column-0", 1); });
        tamper([](const auto &p) { std::filesystem::resize_file(p / "codeword-0", 1); });
        tamper([](const auto &p) { std::filesystem::resize_file(p / "tree", 1); });
        tamper([](const auto &p) {
            std::fstream file(p / "tree", std::ios::binary | std::ios::in | std::ios::out);
            file.seekg(-1, std::ios::end);
            char byte{}; file.get(byte);
            file.seekp(-1, std::ios::end); file.put(byte ^ 1);
        });
        for (const auto *name : {"manifest", "column-0", "codeword-0", "tree"}) {
            tamper([&](const auto &p) {
                std::filesystem::remove(p / name);
                std::filesystem::create_symlink(saved / name, p / name);
            });
            tamper([&](const auto &p) {
                std::filesystem::remove(p / name);
                CHECK(::mkfifo((p / name).c_str(), 0600) == 0);
            });
        }
        const auto directory_link = scratch.path / "saved-directory-link";
        std::filesystem::create_directory_symlink(saved, directory_link);
        CHECK(throws([&] { fb::reopen_commitment(directory_link, original.metadata); }));
        // A canonical-size file can still contain invalid field bytes. Reads
        // reject those lazily; reopening does not scan large tables.
        const auto lazy = scratch.path / "noncanonical-saved";
        std::filesystem::copy(saved, lazy, std::filesystem::copy_options::recursive);
        std::fstream file(lazy / "column-0", std::ios::binary | std::ios::in | std::ios::out);
        const char bad[3]{-1, -1, -1}; file.write(bad, 3); file.close();
        auto reopened = fb::reopen_commitment(lazy, original.metadata);
        CHECK(throws([&] { (void)reopened.columns.front().get(0); }));
    });
    runner.run("resident authentication levels reopen with exact shape and root", [&] {
        const std::vector<std::vector<std::uint8_t>> leaves{{1}, {2}, {3}, {4}};
        const basefold::MerkleTree original(leaves);
        const auto reopened = basefold::MerkleTree::from_levels(original.levels(), original.root());
        CHECK(reopened.open(2) == original.open(2));
        CHECK(basefold::MerkleTree::verify(reopened.root(), leaves.size(),
            2, leaves[2], reopened.open(2)));
        CHECK(throws([&] { basefold::MerkleTree::from_levels({}, original.root()); }));
        auto incomplete = original.levels(); incomplete.pop_back();
        CHECK(throws([&] { basefold::MerkleTree::from_levels(incomplete, original.root()); }));
        auto extra = original.levels(); extra.push_back({original.root()});
        CHECK(throws([&] { basefold::MerkleTree::from_levels(extra, original.root()); }));
        auto malformed = original.levels(); malformed.front().pop_back();
        CHECK(throws([&] { basefold::MerkleTree::from_levels(malformed, original.root()); }));
        auto wrong_root = original.root(); wrong_root[0] ^= 1;
        CHECK(throws([&] { basefold::MerkleTree::from_levels(original.levels(), wrong_root); }));
    });
    runner.run(
        "integer admission certificate and full-field universal diagonal", [] {
            CHECK(fb::distance_certificate());
            CHECK(fb::valid_shape(fb::Metadata{{}, std::size_t{1} << 40, 1}));
            CHECK(!fb::valid_shape(fb::Metadata{{}, std::size_t{1} << 41, 1}));
            CHECK(!fb::valid_shape(fb::Metadata{{}, 8, 1},
                                   fb::Parameters{fb::minimum_queries(8) - 1}));
            const auto t = fb::diagonal(14, 3);
            CHECK(!t.is_zero());
            CHECK(t == fb::diagonal(14, 3));
            CHECK(t != fb::diagonal(14, 4));
            bool extension = false;
            for (std::size_t i = 1; i < 8; ++i)
                extension |= !t.coefficients()[i].is_zero();
            CHECK(extension);
        });
    runner.run("diagonal prefix reuse preserves the original oracle transcript", [] {
        for (const auto level : std::array<std::size_t, 5>{14, 15, 21, 28, 40}) {
            const auto last = (std::size_t{1} << (level + fb::kLogRate - 1)) - 1;
            for (const auto index : std::array<std::size_t, 3>{0, 3, last}) {
                Transcript reference("Laminate/FoldableGateCode/UniversalDiagonal/v1");
                reference.observe("version", fb::kHierarchyVersion);
                reference.observe("level", level);
                reference.observe("index", index);
                Fpk expected;
                do { expected = reference.challenge_fpk(); } while (expected.is_zero());
                CHECK(fb::diagonal(level, index) == expected);
            }
        }
    });
    runner.run("RS base matches existing encoder without variable permutation",
               [&] {
                   auto values = table(32);
                   const auto expected = basefold::reed_solomon_encode(
                       basefold::evaluations_to_coefficients(values), 3);
                   auto encoded = fb::encode(fb::source(values), scratch.path);
                   std::vector<Fpk> actual(encoded.size());
                   encoded.read(0, actual);
                   CHECK(actual == expected);
               });
    runner.run("base-field RS fast path matches the generic extension encoder", [&] {
        for (const auto size : std::array<std::size_t, 2>{32, 8192}) {
            auto values = table(size);
            for (auto &value : values)
                value = Fpk::from_base(value.coefficients()[0]);
            const auto expected = basefold::reed_solomon_encode(
                basefold::evaluations_to_coefficients(values), fb::kLogRate);
            auto encoded = fb::encode(fb::source(values), scratch.path);
            std::vector<Fpk> actual(encoded.size());
            encoded.read(0, actual);
            CHECK(actual == expected);
        }
    });
    runner.run(
        "random level binds the least significant multilinear variable", [&] {
            auto values = table(16384);
            auto encoded = fb::encode(fb::source(values), scratch.path);
            Transcript coin("foldable-fold-test");
            const auto r = coin.challenge_fpk();
            const auto folded = basefold::fold_evaluations(values, r);
            const auto expected = basefold::reed_solomon_encode(
                basefold::evaluations_to_coefficients(folded), 3);
            const auto inv2 = Fp(2).inverse();
            // Cover boundaries, both Fourier halves, and noncontiguous locations.
            for (auto i : std::array<std::size_t, 9>{0, 1, 2, 31, 8191, 8192,
                                                     32767, 32768, 65535}) {
                const auto lo = encoded.get(i), hi = encoded.get(i + 65536);
                CHECK((lo + hi +
                       r * ((lo - hi) * fb::diagonal(14, i).inverse())) *
                          inv2 ==
                      expected[i]);
            }
        });
    runner.run("parallel commitment preserves codewords, roots and proofs", [&] {
        // A non-power-of-two block crosses worker partitions and final chunks.
        // The larger case also exercises the random-diagonal hierarchy.
        const fb::Options options{.block_elements = 257};
        for (const auto m : std::array<std::size_t, 2>{32, 16384}) {
            auto values = table(m);
            auto second = table(m);
            for (auto &value : second)
                value += Fpk::one();
            const std::size_t width = m == 32 ? 2 : 1;
            std::array<fb::ValueSource, 2> all_columns{
                fb::source(values), fb::source(second)};
            const auto columns = std::span(all_columns).first(width);
            const auto caller = std::this_thread::get_id();
            for (auto &column : columns) {
                const auto read = column.read;
                column.read = [read, caller](std::size_t offset,
                                             std::span<Fpk> output) {
                    CHECK(std::this_thread::get_id() == caller);
                    read(offset, output);
                };
            }
            auto uncached_options = options;
            uncached_options.diagonal_cache_bytes = 0;
            auto serial = fb::commit(columns, scratch.path, uncached_options);
            auto parallel = fb::commit(columns, scratch.path, options, 3);
            CHECK(serial.metadata == parallel.metadata);
            for (std::size_t c = 0; c < width; ++c) {
                std::vector<Fpk> expected(serial.codewords[c].size());
                std::vector<Fpk> actual(expected.size());
                serial.codewords[c].read(0, expected);
                parallel.codewords[c].read(0, actual);
                CHECK(actual == expected);
                actual.resize(m);
                parallel.columns[c].read(0, actual);
                CHECK(actual == (c == 0 ? values : second));
            }

            const auto operand = table(m);
            const std::array<fb::ValueSource, 1> operands{fb::source(operand)};
            const std::array<Fpk, 2> all_weights{Fpk::one(), Fpk::one()};
            const auto weights = std::span(all_weights).first(width);
            const std::array<Fpk, 1> targets{
                dot(values, operand) +
                (width == 2 ? dot(second, operand) : Fpk::zero())};
            const auto premise = width == 1
                ? fb::CommitmentPremise::ArbitrarySingleColumn
                : fb::CommitmentPremise::HonestCodewordColumns;
            Transcript serial_coin("parallel-commitment-proof");
            Transcript parallel_coin("parallel-commitment-proof");
            const auto expected = fb::prove(
                serial, operands, weights, targets, serial_coin,
                scratch.path, premise, {}, options);
            const auto actual = fb::prove(
                parallel, operands, weights, targets, parallel_coin,
                scratch.path, premise, {}, options);
            CHECK(fb::encode_canonical(actual.proof) ==
                  fb::encode_canonical(expected.proof));
            Transcript verifier("parallel-commitment-proof");
            const auto reduced = fb::verify(parallel.metadata, 1, weights,
                targets, actual.proof, verifier, premise);
            CHECK(reduced.has_value());
            CHECK(reduced->operand_evaluations[0] ==
                  basefold::evaluate_multilinear(operand, reduced->point));
            const auto next = verifier.challenge_fpk();
            CHECK(serial_coin.challenge_fpk() == next);
            CHECK(parallel_coin.challenge_fpk() == next);
        }
    });
    runner.run("invalid worker counts fail before creating storage", [&] {
        const auto values = table(32);
        const std::array<fb::ValueSource, 1> columns{fb::source(values)};
        for (const auto workers : std::array<std::size_t, 2>{0, 257}) {
            const auto directory = scratch.path / "invalid-workers";
            CHECK(throws([&] { fb::commit(columns, directory, {}, workers); }));
            CHECK(!std::filesystem::exists(directory));
        }
    });
    runner.run("parallel preprocessing joins workers and cleans failed sources", [&] {
        const auto directory = scratch.path / "parallel-failure";
        std::filesystem::create_directory(directory);
        const auto values = table(16384);
        const std::array<fb::ValueSource, 2> columns{
            fb::source(values),
            fb::ValueSource{values.size(), [](std::size_t, std::span<Fpk>) {
                throw std::runtime_error("injected second-column failure");
            }}};
        CHECK(throws([&] {
            fb::commit(columns, directory, {.block_elements = 257}, 3);
        }));
        CHECK(std::filesystem::is_empty(directory));
        // Another commitment must succeed after the failed pool has joined.
        {
            const std::array<fb::ValueSource, 1> retry{fb::source(values)};
            const auto result = fb::commit(retry, directory, {}, 2);
            CHECK(result.metadata.m == values.size());
        }
        CHECK(std::filesystem::is_empty(directory));
    });
    runner.run(
        "single malicious-column PCS, operand batch, canonical paths and transcript",
        [&] {
            auto values = table(16), a = table(16), b = table(16);
            for (auto &v : b)
                v += Fpk::one();
            std::array<fb::ValueSource, 1> columns{fb::source(values)};
            auto commitment = fb::commit(columns, scratch.path);
            std::array<fb::ValueSource, 2> operands{fb::source(a),
                                                    fb::source(b)};
            std::array<Fpk, 1> weights{Fpk::one()};
            std::array<Fpk, 2> targets{dot(values, a), dot(values, b)};
            Transcript prover("foldable-proof-test");
            auto result = fb::prove(commitment, operands, weights, targets,
                                    prover, scratch.path);
            Transcript verifier("foldable-proof-test");
            auto reduction = fb::verify(commitment.metadata, 2, weights,
                                        targets, result.proof, verifier);
            CHECK(reduction.has_value());
            CHECK(reduction->operand_evaluations[0] ==
                  basefold::evaluate_multilinear(a, reduction->point));
            CHECK(reduction->operand_evaluations[1] ==
                  basefold::evaluate_multilinear(b, reduction->point));
            CHECK(prover.challenge_fpk() == verifier.challenge_fpk());
            const auto bytes = fb::encode_canonical(result.proof);
            CHECK(bytes.size() <= fb::proof_size_bound(commitment.metadata, 2));
            const auto decoded =
                fb::decode_canonical(bytes, commitment.metadata, 2);
            CHECK(fb::encode_canonical(decoded) == bytes);
            Transcript decoded_coin("foldable-proof-test");
            CHECK(fb::verify(commitment.metadata, 2, weights, targets, decoded,
                             decoded_coin));
            auto extra = bytes;
            extra.push_back(0);
            CHECK(throws(
                [&] { fb::decode_canonical(extra, commitment.metadata, 2); }));
            auto noncanonical = bytes;
            noncanonical[16] = 255;
            noncanonical[17] = 255;
            noncanonical[18] = 255;
            CHECK(throws([&] {
                fb::decode_canonical(noncanonical, commitment.metadata, 2);
            }));
            CHECK(throws([&] {
                fb::decode_canonical(std::span(bytes).first(bytes.size() - 1),
                                     commitment.metadata, 2);
            }));
            auto reject = [&](const fb::Proof &proof) {
                Transcript t("foldable-proof-test");
                return !fb::verify(commitment.metadata, 2, weights, targets,
                                   proof, t)
                            .has_value();
            };
            auto bad = result.proof;
            bad.initial.values[0] += Fpk::one();
            CHECK(reject(bad));
            bad = result.proof;
            bad.initial.values.push_back(Fpk::one());
            CHECK(reject(bad));
            bad = result.proof;
            bad.initial.frontier.push_back({});
            CHECK(reject(bad));
            bad = result.proof;
            bad.folded[0].values[0] += Fpk::one();
            CHECK(reject(bad));
            bad = result.proof;
            bad.roots[0][0] ^= 1;
            CHECK(reject(bad));
            bad = result.proof;
            bad.final_codeword[0] += Fpk::one();
            CHECK(reject(bad));
            bad = result.proof;
            bad.sumcheck.rounds[0][2] += Fpk::one();
            CHECK(reject(bad));
            auto wrong = targets;
            wrong[1] += Fpk::one();
            Transcript changed("foldable-proof-test");
            CHECK(!fb::verify(commitment.metadata, 2, weights, wrong,
                              result.proof, changed));
            auto wrong_meta = commitment.metadata;
            ++wrong_meta.hierarchy_version;
            Transcript badmeta("foldable-proof-test");
            CHECK(!fb::verify(wrong_meta, 2, weights, targets, result.proof,
                              badmeta));
        });
    runner.run("transparent block values agree with dense LSB evaluation", [] {
        Transcript coin("block-analytic");
        const auto point = coin.challenge_vector(7);
        const std::array<fb::BlockOperand, 4> operands{
            {{32, coin.challenge_vector(2), table(8)},
             {96, {Fpk::zero(), Fpk::one(), Fpk::zero()}, table(2)},
             {127, {}, {}},
             {0, coin.challenge_vector(7), {Fpk::one()}}}};
        for (std::size_t i = 0; i < operands.size(); ++i) {
            auto operand = operands[i];
            if (i == 2)
                operand.column_weights = {Fpk::from_base(Fp(9))};
            CHECK(fb::evaluate_block_operand(operand, 128, point) ==
                  basefold::evaluate_multilinear(block_table(operand, 128),
                                                 point));
        }
        // The maximum dimension is checked analytically, without allocating
        // or scanning a 2^40-entry vector.
        fb::BlockOperand huge{0, std::vector<Fpk>(40), {Fpk::one()}};
        const auto large_point = coin.challenge_vector(40);
        Fpk expected = Fpk::one();
        for (const auto &r : large_point)
            expected *= Fpk::one() - r;
        CHECK(fb::block_operand_size(huge) == (std::size_t{1} << 40));
        CHECK(fb::evaluate_block_operand(huge, std::size_t{1} << 40,
                                         large_point) == expected);
        ++huge.offset;
        CHECK(throws([&] {
            fb::evaluate_block_operand(huge, std::size_t{1} << 40, large_point);
        }));
        huge.offset = 0;
        huge.point_lsb.push_back(Fpk::zero());
        CHECK(throws([&] { fb::block_operand_size(huge); }));
        fb::BlockOperand bad{0, {}, std::vector<Fpk>(3)};
        CHECK(throws([&] { fb::block_operand_size(bad); }));
        bad.column_weights.clear();
        CHECK(throws([&] { fb::block_operand_size(bad); }));
        bad.column_weights.resize(512);
        CHECK(throws([&] { fb::block_operand_size(bad); }));
        bad.column_weights = {Fpk::one()};
        bad.point_lsb.resize(33);
        bad.column_weights.resize(256);
        CHECK(throws([&] { fb::block_operand_size(bad); }));
    });
    runner.run(
        "transparent block batching matches dense proof with overlapping supports",
        [&] {
            auto values = table(128);
            Transcript points("block-operand-points");
            const std::vector<fb::BlockOperand> operands{
                {0, points.challenge_vector(3), table(4)},
                {32, points.challenge_vector(4), {Fpk::one()}},
                {40, {Fpk::zero()}, table(4)},
                {56, {Fpk::one()}, table(4)},
                {0, points.challenge_vector(5), table(2)},
                {95, {}, table(1)},
                {112, points.challenge_vector(2), table(4)}};
            std::vector<std::vector<Fpk>> dense;
            std::vector<fb::ValueSource> sources;
            std::vector<Fpk> targets;
            for (const auto &o : operands) {
                dense.push_back(block_table(o, values.size()));
                targets.push_back(dot(values, dense.back()));
            }
            for (const auto &o : dense)
                sources.push_back(fb::source(o));
            const std::array<fb::ValueSource, 1> columns{fb::source(values)};
            const std::array<Fpk, 1> weights{Fpk::one()};
            fb::Options options;
            options.block_elements = 7;
            const auto commitment = fb::commit(columns, scratch.path, options);
            // An explicit query count may exceed the default.
            const fb::Parameters policy{350};
            Transcript prover("block-proof"), dense_prover("block-proof");
            const auto result = fb::prove_blocks(
                commitment, operands, weights, targets, prover, scratch.path,
                fb::CommitmentPremise::ArbitrarySingleColumn, policy, options);
            bind_blocks(operands, dense_prover);
            const auto dense_result = fb::prove(
                commitment, sources, weights, targets, dense_prover,
                scratch.path, fb::CommitmentPremise::ArbitrarySingleColumn,
                policy, options);
            const auto bytes = fb::encode_canonical(result.proof);
            CHECK(bytes == fb::encode_canonical(dense_result.proof));
            const auto proof = fb::decode_canonical(bytes, commitment.metadata,
                                                    operands.size(), policy);
            Transcript verifier("block-proof");
            const auto reduction = fb::verify_blocks(
                commitment.metadata, operands, weights, targets, proof,
                verifier, fb::CommitmentPremise::ArbitrarySingleColumn, policy);
            CHECK(reduction);
            CHECK(reduction->point == result.reduction.point);
            for (std::size_t i = 0; i < operands.size(); ++i)
                CHECK(
                    reduction->operand_evaluations[i] ==
                    basefold::evaluate_multilinear(dense[i], reduction->point));
            const auto tail = prover.challenge_fpk();
            CHECK(tail == dense_prover.challenge_fpk());
            CHECK(tail == verifier.challenge_fpk());
            auto reject = [&](const auto &changed, const fb::Proof &candidate) {
                Transcript coin("block-proof");
                return !fb::verify_blocks(
                    commitment.metadata, changed, weights, targets, candidate,
                    coin, fb::CommitmentPremise::ArbitrarySingleColumn, policy);
            };
            auto changed = operands;
            changed[0].offset = 64;
            CHECK(reject(changed, proof));
            changed = operands;
            changed[0].point_lsb[0] += Fpk::one();
            CHECK(reject(changed, proof));
            changed = operands;
            changed[0].column_weights[0] += Fpk::one();
            CHECK(reject(changed, proof));
            changed = operands;
            changed[0].point_lsb.resize(2);
            changed[0].column_weights.resize(8);
            CHECK(reject(changed, proof));
            changed = operands;
            changed[0].offset = 1;
            CHECK(reject(changed, proof));
            Transcript malformed("block-proof");
            CHECK(throws([&] {
                fb::prove_blocks(commitment, changed, weights, targets,
                                 malformed, scratch.path);
            }));
            changed = operands;
            changed[0].offset = std::numeric_limits<std::size_t>::max();
            CHECK(reject(changed, proof));
            changed = operands;
            changed[0].offset = 128;
            CHECK(reject(changed, proof));
            auto bad = proof;
            bad.sumcheck.operand_evaluations[0] += Fpk::one();
            CHECK(reject(operands, bad));
            Transcript wrong_target("block-proof");
            auto incorrect = targets;
            incorrect[0] += Fpk::one();
            CHECK(!fb::verify_blocks(
                commitment.metadata, operands, weights, incorrect, proof,
                wrong_target, fb::CommitmentPremise::ArbitrarySingleColumn,
                policy));
        });
    runner.run(
        "transparent verifier rejects a valid PCS with false residual operands",
        [&] {
            auto values = table(16), wrong_operand = table(16);
            const std::array<fb::ValueSource, 1> columns{fb::source(values)},
                sources{fb::source(wrong_operand)};
            const auto commitment = fb::commit(columns, scratch.path);
            const std::array<fb::BlockOperand, 1> descriptors{
                {{8, {Fpk::zero()}, table(4)}}};
            const std::array<Fpk, 1> weights{Fpk::one()},
                targets{dot(values, wrong_operand)};
            Transcript malicious("block-residual");
            bind_blocks(descriptors, malicious);
            const auto result = fb::prove(commitment, sources, weights, targets,
                                          malicious, scratch.path);
            Transcript generic("block-residual");
            bind_blocks(descriptors, generic);
            CHECK(fb::verify(commitment.metadata, 1, weights, targets,
                             result.proof, generic));
            Transcript transparent("block-residual");
            CHECK(!fb::verify_blocks(commitment.metadata, descriptors, weights,
                                     targets, result.proof, transparent));
        });
    runner.run("transparent block constant case and empty point", [&] {
        const auto values = table(1);
        const std::array<fb::ValueSource, 1> columns{fb::source(values)};
        const auto commitment = fb::commit(columns, scratch.path);
        const std::array<fb::BlockOperand, 1> operands{{{0, {}, table(1)}}};
        const std::array<Fpk, 1> weights{Fpk::one()},
            targets{values[0] * operands[0].column_weights[0]};
        Transcript prover("block-constant"), verifier("block-constant");
        const auto result = fb::prove_blocks(commitment, operands, weights,
                                             targets, prover, scratch.path);
        CHECK(fb::verify_blocks(commitment.metadata, operands, weights, targets,
                                result.proof, verifier));
        CHECK(prover.challenge_fpk() == verifier.challenge_fpk());
    });
    runner.run(
        "honest column premise is explicit and tiny constant case works", [&] {
            auto a = table(1), b = table(1);
            b[0] += Fpk::one();
            std::array<fb::ValueSource, 2> columns{fb::source(a),
                                                   fb::source(b)};
            auto commitment = fb::commit(columns, scratch.path);
            std::array<fb::ValueSource, 1> operands{fb::source(a)};
            const std::array<Fpk, 2> weights{Fpk::one(), Fpk::from_base(Fp(3))};
            const std::array<Fpk, 1> targets{a[0] * (a[0] + weights[1] * b[0])};
            Transcript rejected("foldable-honest");
            CHECK(throws([&] {
                fb::prove(commitment, operands, weights, targets, rejected,
                          scratch.path);
            }));
            Transcript prover("foldable-honest");
            auto result = fb::prove(
                commitment, operands, weights, targets, prover, scratch.path,
                fb::CommitmentPremise::HonestCodewordColumns);
            Transcript verifier("foldable-honest");
            CHECK(fb::verify(commitment.metadata, 1, weights, targets,
                             result.proof, verifier,
                             fb::CommitmentPremise::HonestCodewordColumns));
        });
    runner.run("complete random-level PCS with irregular disk chunks", [&] {
        auto values = table(16384);
        Transcript points("foldable-large-operand");
        const auto point = points.challenge_vector(14);
        const auto operand = basefold::equality_evaluations(point);
        const std::array<fb::ValueSource, 1> columns{fb::source(values)},
            operands{fb::source(operand)};
        fb::Options options;
        options.block_elements = 257;
        const auto commitment = fb::commit(columns, scratch.path, options);
        const std::array<Fpk, 1> weights{Fpk::one()},
            targets{basefold::evaluate_multilinear(values, point)};
        Transcript prover("foldable-large-proof");
        const auto result = fb::prove(
            commitment, operands, weights, targets, prover, scratch.path,
            fb::CommitmentPremise::ArbitrarySingleColumn, {}, options);
        const auto bytes = fb::encode_canonical(result.proof);
        const auto proof = fb::decode_canonical_bounded(bytes, 32768, 1, 2);
        Transcript verifier("foldable-large-proof");
        const auto reduction = fb::verify(commitment.metadata, 1, weights,
                                          targets, proof, verifier);
        CHECK(reduction);
        CHECK(reduction->operand_evaluations[0] ==
              basefold::evaluate_multilinear(operand, reduction->point));
        CHECK(prover.challenge_fpk() == verifier.challenge_fpk());
        CHECK(bytes.size() <= fb::proof_size_bound(commitment.metadata, 1));
        CHECK(throws([&] { fb::decode_canonical_bounded(bytes, 8192, 1, 1); }));
        auto bad = proof;
        CHECK(!bad.initial.frontier.empty());
        bad.initial.frontier[0][0] ^= 1;
        Transcript tamper("foldable-large-proof");
        CHECK(
            !fb::verify(commitment.metadata, 1, weights, targets, bad, tamper));
    });
    return runner.summary();
}
