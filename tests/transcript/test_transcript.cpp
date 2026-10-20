#include "test_helpers.hpp"

#include "laminate/basefold/digest.hpp"
#include "laminate/crypto/poseidon.hpp"
#include "laminate/params.hpp"
#include "laminate/spartan/ipcs.hpp"
#include "laminate/transcript/hash.hpp"
#include "laminate/transcript/transcript.hpp"

#include <concepts>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace {

using laminate::Digest;
using laminate::Fpk;
using laminate::PoseidonDigest;
using laminate::Transcript;

static_assert(Digest{}.size() == 32);
static_assert(PoseidonDigest{}.size() == 48);
static_assert(laminate::basefold::Digest{}.size() == 40);
static_assert(laminate::spartan::PcsDigest{}.size() == 40);
static_assert(std::derived_from<Transcript, laminate::PublicCoin>);

std::vector<std::uint8_t> bytes(std::string_view value) {
    return std::vector<std::uint8_t>(value.begin(), value.end());
}

template <std::size_t Size>
std::string hexadecimal(
    const std::array<std::uint8_t, Size> &digest) {
    constexpr std::string_view kDigits = "0123456789abcdef";
    std::string output;
    output.reserve(2 * digest.size());
    for (std::uint8_t byte : digest) {
        output.push_back(kDigits[byte >> 4U]);
        output.push_back(kDigits[byte & 0x0fU]);
    }
    return output;
}

void test_sha256_vectors() {
    static constexpr std::string_view kEmptyDigest =
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855";
    CHECK(hexadecimal(laminate::sha256(bytes(""))) == kEmptyDigest);
    CHECK(hexadecimal(laminate::sha256(bytes("abc"))) ==
          "ba7816bf8f01cfea414140de5dae2223"
          "b00361a396177a9cb410ff61f20015ad");
    const std::vector<std::uint8_t> multi_block = bytes(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    static constexpr std::string_view kMultiBlockDigest =
        "248d6a61d20638b8e5c026930c3e6039"
        "a33ce45964ff2167f6ecedd419db06c1";
    CHECK(hexadecimal(laminate::sha256(multi_block)) ==
          kMultiBlockDigest);

    laminate::Sha256Hasher empty_incremental;
    empty_incremental.update({});
    CHECK(hexadecimal(empty_incremental.finish()) == kEmptyDigest);

    laminate::Sha256Hasher chunked;
    const std::span<const std::uint8_t> input(multi_block);
    chunked.update(input.first(1));
    chunked.update(input.subspan(1, 7));
    chunked.update(input.subspan(8));
    CHECK(hexadecimal(chunked.finish()) == kMultiBlockDigest);
}

void test_poseidon_vectors_and_domains() {
    const PoseidonDigest empty = laminate::poseidon_hash(
        bytes(""), laminate::PoseidonDomain::CiphertextCommitment);
    const PoseidonDigest abc = laminate::poseidon_hash(
        bytes("abc"), laminate::PoseidonDomain::CiphertextCommitment);
    CHECK(hexadecimal(empty) ==
          "988947425a689b0bb3053b54a56073014b57753c1ef04501d7866f83d7af9f0d"
          "65d145ed03521b0c42c6255b3be3d101");
    CHECK(hexadecimal(abc) ==
          "f8142a61a3035a0813a78a501216f609ca3a64bc4f83770dd9c99a3e94108205"
          "797681a8baca0405a8c12a0178f30302");
    CHECK(abc == laminate::poseidon_hash(
                     bytes("abc"),
                     laminate::PoseidonDomain::CiphertextCommitment));
    CHECK(empty != abc);

    const std::vector<laminate::Fq> fields{
        laminate::Fq(1), laminate::Fq(2), laminate::Fq(3)};
    CHECK(laminate::poseidon_hash_fields(
              fields, laminate::PoseidonDomain::CiphertextCommitment, 3) !=
          laminate::poseidon_hash_fields(
              fields, laminate::PoseidonDomain::CiphertextCommitment, 4));
    const PoseidonDigest statement = laminate::poseidon_hash_fields(
        fields, laminate::PoseidonDomain::CiphertextCommitment,
        fields.size());
    const auto decoded =
        laminate::poseidon_digest_field_elements(statement);
    for (const laminate::Fq &element : decoded) {
        CHECK(element.value() < laminate::kOuterFieldOrder);
    }
    // Fixed vectors independently computed with integer arithmetic from the
    // Grain/Cauchy parameter construction. Test both sides of a rate boundary
    // and an exact multiple, where padding requires a further permutation.
    const std::array<std::size_t, 4> lengths{9, 10, 11, 20};
    const std::array<std::string_view, 4> expected{
        "a377d2b534aa17060ebbd11639f1b1059fcc82586c080c0af1a9001fb197350c"
        "d7110d5ae637b3085836251eccf1bc08",
        "d331b8135701710e2ddecfe5759bdf042d413d03d45db408ea8559b433019c0d"
        "7b125b51eab1b200303b9845bd1fef0d",
        "b3ef6501afbfd30968230c7c06a91e09d4e58d5bcd2ccc07a4e39d1cc5e14800"
        "37b0398141cd1606ef23da6b9031ea0d",
        "ab1c546d3fd8fc0da87469a6f91c0c074d211e0138fea3012ba62539d4aa090e"
        "ad242ef41a020705070ecc7daf98a501",
    };
    for (std::size_t index = 0; index < lengths.size(); ++index) {
        std::vector<laminate::Fq> input;
        for (std::size_t value = 1; value <= lengths[index]; ++value) {
            input.emplace_back(value);
        }
        CHECK(hexadecimal(laminate::poseidon_hash_fields(
                  input, laminate::PoseidonDomain::CiphertextCommitment,
                  input.size())) == expected[index]);
    }

}

void test_poseidon_ciphertext_constraint_budget() {
    constexpr std::uint64_t coordinates = 2ULL * (1ULL << 14);
    constexpr std::uint64_t metadata_elements = 4;
    const std::uint64_t constraints =
        laminate::poseidon_r1cs_constraints_for_field_elements(
            coordinates + metadata_elements);
    CHECK(constraints == 1'504'602);
    CHECK(constraints < 2'000'000);

    // The canonical byte interface also fits this S-box constraint budget.
    // Checkpoint equalities and digest equalities are counted by the R1CS ledger.
    CHECK(laminate::poseidon_r1cs_constraints_for_bytes(262'257) <
          2'000'000);
}

void test_determinism_and_freshness() {
    Transcript left("laminate/test/v0");
    Transcript right("laminate/test/v0");
    left.observe("message", bytes("hello"));
    left.observe("count", std::uint64_t{42});
    right.observe("message", bytes("hello"));
    right.observe("count", std::uint64_t{42});

    const Fpk first = left.challenge_fpk();
    CHECK(first == right.challenge_fpk());
    const Fpk second = left.challenge_fpk();
    CHECK(second == right.challenge_fpk());
    CHECK(!(first == second));
}

void test_domain_label_and_order_sensitivity() {
    Transcript domain_a("laminate/test/v0");
    Transcript domain_b("laminate/test/v1");
    domain_a.observe("message", bytes("same"));
    domain_b.observe("message", bytes("same"));
    CHECK(!(domain_a.challenge_fpk() == domain_b.challenge_fpk()));

    Transcript order_a("laminate/test/v0");
    Transcript order_b("laminate/test/v0");
    order_a.observe("message", bytes("ab"));
    order_a.observe("message", bytes("c"));
    order_b.observe("message", bytes("a"));
    order_b.observe("message", bytes("bc"));
    CHECK(!(order_a.challenge_fpk() == order_b.challenge_fpk()));
}

void test_label_and_byte_sensitivity() {
    Transcript label_a("laminate/test/v0");
    Transcript label_b("laminate/test/v0");
    label_a.observe("left", bytes("payload"));
    label_b.observe("right", bytes("payload"));
    CHECK(!(label_a.challenge_fpk() == label_b.challenge_fpk()));

    Transcript byte_a("laminate/test/v0");
    Transcript byte_b("laminate/test/v0");
    byte_a.observe("message", bytes("hello"));
    byte_b.observe("message", bytes("hellp"));
    CHECK(!(byte_a.challenge_fpk() == byte_b.challenge_fpk()));
}

void test_challenge_vectors() {
    Transcript transcript("laminate/test/v0");
    transcript.observe("seed", bytes("tau"));
    const std::vector<Fpk> challenges = transcript.challenge_vector(8);
    CHECK(challenges.size() == 8);

    std::set<std::string> distinct;
    for (const Fpk &challenge : challenges) {
        std::string key;
        for (const laminate::Fp &coefficient : challenge.coefficients()) {
            CHECK(coefficient.value() < laminate::kBaseFieldOrder);
            key += std::to_string(coefficient.value()) + ',';
        }
        distinct.insert(std::move(key));
    }
    CHECK(distinct.size() == challenges.size());
}

void test_native_extension_challenges() {
    Transcript left("laminate/native-challenge/v1");
    Transcript right("laminate/native-challenge/v1");
    left.observe("seed", bytes("quadratic"));
    right.observe("seed", bytes("quadratic"));
    const std::vector<laminate::Fq2> lhs = left.challenge_fq2_vector(16);
    const std::vector<laminate::Fq2> rhs = right.challenge_fq2_vector(16);
    CHECK(lhs == rhs);
    std::set<std::string> distinct;
    for (const laminate::Fq2 &challenge : lhs) {
        distinct.insert(
            std::to_string(challenge.coefficients()[0].value()) + ',' +
            std::to_string(challenge.coefficients()[1].value()));
    }
    CHECK(distinct.size() == lhs.size());
}

void test_challenge_bits() {
    Transcript left("laminate/test/v0");
    Transcript right("laminate/test/v0");
    left.observe("seed", bytes("bits"));
    right.observe("seed", bytes("bits"));
    const std::vector<bool> left_bits = left.challenge_bits(1000);
    const std::vector<bool> right_bits = right.challenge_bits(1000);
    CHECK(left_bits == right_bits);

    std::size_t ones = 0;
    for (bool bit : left_bits) {
        ones += bit ? 1U : 0U;
    }
    CHECK(ones > 400 && ones < 600);
}

} // namespace

int main() {
    laminate::test::Runner runner("test_transcript");
    runner.run("SHA-256 known-answer vectors", test_sha256_vectors);
    runner.run("Poseidon vectors and domains", test_poseidon_vectors_and_domains);
    runner.run("Poseidon ciphertext R1CS budget",
               test_poseidon_ciphertext_constraint_budget);
    runner.run("transcript determinism and freshness",
               test_determinism_and_freshness);
    runner.run("domain and observation-order sensitivity",
               test_domain_label_and_order_sensitivity);
    runner.run("label and byte sensitivity", test_label_and_byte_sensitivity);
    runner.run("extension challenge vectors", test_challenge_vectors);
    runner.run("native extension challenges",
               test_native_extension_challenges);
    runner.run("bit challenges", test_challenge_bits);
    return runner.summary();
}
