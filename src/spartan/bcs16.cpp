/// @file bcs16.cpp
/// @brief SHA-256 BCS16 compilation of Spartan + an IPCS.

#include "laminate/spartan/spartan.hpp"

#include "laminate/field/serialization.hpp"

#include <array>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace laminate::spartan {
namespace {

constexpr std::string_view kSetupLabel = "laminate/spartan/setup/v2";
constexpr std::string_view kPublicInputLabel =
    "laminate/spartan/public-input/v1";
constexpr std::string_view kWitnessCommitmentLabel =
    "laminate/spartan/witness-commitment/v1";
constexpr std::string_view kConstraintTerminalLabel =
    "laminate/spartan/constraint-terminal/v1";
constexpr std::string_view kWiringTerminalLabel =
    "laminate/spartan/wiring-terminal/v1";

/// State produced by the first Spartan phase and consumed by both sumchecks.
struct CommittedAssignment {
    std::vector<Fq> assignment;
    IPCS::CommitOutput witness;
};

/// ConstraintCheck output plus the challenge used to batch A, B, and C.
struct ConstraintPhase {
    ConstraintSumcheckOutput sumcheck;
    Fq2 matrix_batching_challenge{};
};

void validate_setup_inputs(
    const R1csInstance &circuit, const Options &options,
    const std::shared_ptr<const MatrixEvaluationOracle> &matrix_oracle,
    const std::shared_ptr<const FactoredMatrixProverKey> &factored_prover,
    const std::shared_ptr<const FactoredMatrixVerifierKey> &factored_verifier,
    const IPCS &pcs);
void validate_prover_key_impl(const ProverKey &key, const IPCS &pcs);
void validate_external_setup_inputs(
    const R1csMetadata &circuit,
    const std::shared_ptr<const FactoredMatrixProverKey> &factored_prover,
    const std::shared_ptr<const FactoredMatrixVerifierKey> &factored_verifier,
    const IPCS &pcs);
void validate_external_prover_key_impl(const ExternalProverKey &key,
                                       const IPCS &pcs);
bool valid_verifier_key(const VerifierKey &key, const IPCS &pcs);
Digest make_setup_digest(const R1csMetadata &circuit,
                         std::uint64_t pcs_scheme,
                         const Options &options,
                         const MatrixEvaluationOracle *matrix_oracle,
                         const FactoredMatrixCommitment *factored_commitment);
void bind_statement(const Digest &setup_digest,
                    std::span<const Fq> public_inputs,
                    PublicCoin &transcript);
CommittedAssignment commit_assignment(
    const R1csInstance &circuit, const R1csAssignment &assignment,
    const IPCS &pcs, PublicCoin &transcript);
ConstraintPhase prove_constraints(
    const ProverKey &key, std::span<const Fq> padded_assignment,
    Proof &proof, PublicCoin &transcript);
WiringSumcheckOutput prove_wiring(
    const ProverKey &key, std::vector<Fq> padded_assignment,
    const ConstraintPhase &constraint, Proof &proof,
    PublicCoin &transcript);
void prove_matrix_evaluation(
    const ProverKey &key, const ConstraintPhase &constraint,
    const WiringSumcheckOutput &wiring, Proof &proof, const IPCS &pcs,
    PublicCoin &transcript);
PcsOpeningProof open_witness(
    const R1csInstance &circuit, const R1csAssignment &assignment,
    const IPCS::CommitOutput &committed,
    const WiringSumcheckOutput &wiring, const Proof &proof,
    const IPCS &pcs, PublicCoin &transcript);
bool verify_protocol(const VerifierKey &key,
                     std::span<const Fq> public_inputs,
                     const Proof &proof, const IPCS &pcs,
                     PublicCoin &transcript);
void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value);

} // namespace

Setup setup(R1csInstance circuit, const IPCS &pcs,
            const Options &options,
            std::shared_ptr<const MatrixEvaluationOracle> matrix_oracle,
            std::shared_ptr<const FactoredMatrixProverKey> factored_prover,
            std::shared_ptr<const FactoredMatrixVerifierKey> factored_verifier) {
    return setup(std::make_shared<const R1csInstance>(std::move(circuit)),
                 pcs, options, std::move(matrix_oracle),
                 std::move(factored_prover), std::move(factored_verifier));
}

Setup setup(std::shared_ptr<const R1csInstance> circuit, const IPCS &pcs,
            const Options &options,
            std::shared_ptr<const MatrixEvaluationOracle> matrix_oracle,
            std::shared_ptr<const FactoredMatrixProverKey> factored_prover,
            std::shared_ptr<const FactoredMatrixVerifierKey> factored_verifier) {
    if (circuit == nullptr) {
        throw std::invalid_argument("Spartan setup circuit is absent");
    }
    validate_setup_inputs(*circuit, options, matrix_oracle,
                          factored_prover, factored_verifier, pcs);
    const R1csMetadata metadata = circuit->metadata();
    const Digest digest = make_setup_digest(
        metadata, pcs.scheme_identifier(), options,
        options.matrix_evaluation == MatrixEvaluationMode::Uniform
            ? matrix_oracle.get()
            : nullptr,
        factored_verifier == nullptr
            ? nullptr
            : &factored_verifier->commitment);
    return Setup{
        .prover_key = ProverKey{
            .circuit = circuit,
            .setup_digest = digest,
            .pcs_scheme = pcs.scheme_identifier(),
            .options = options,
            .matrix_oracle = matrix_oracle,
            .factored_computation = std::move(factored_prover),
        },
        .verifier_key = VerifierKey{
            .circuit_metadata = metadata,
            .setup_digest = digest,
            .pcs_scheme = pcs.scheme_identifier(),
            .options = options,
            .direct_matrix =
                options.matrix_evaluation == MatrixEvaluationMode::Direct
                    ? std::move(circuit)
                    : nullptr,
            .matrix_oracle =
                options.matrix_evaluation == MatrixEvaluationMode::Uniform
                    ? std::move(matrix_oracle)
                    : nullptr,
            .factored_computation = std::move(factored_verifier),
        },
    };
}

ExternalSetup setup_external_committed_factored(
    R1csMetadata circuit_metadata, const IPCS &pcs,
    std::shared_ptr<const FactoredMatrixProverKey> factored_prover,
    std::shared_ptr<const FactoredMatrixVerifierKey> factored_verifier) {
    validate_external_setup_inputs(
        circuit_metadata, factored_prover, factored_verifier, pcs);
    const Options options{
        .matrix_evaluation = MatrixEvaluationMode::CommittedFactored,
    };
    const Digest digest = make_setup_digest(
        circuit_metadata, pcs.scheme_identifier(), options, nullptr,
        &factored_verifier->commitment);
    ExternalSetup result{
        .prover_key = ExternalProverKey{
            .circuit_metadata = circuit_metadata,
            .setup_digest = digest,
            .pcs_scheme = pcs.scheme_identifier(),
            .options = options,
            .factored_computation = std::move(factored_prover),
        },
        .verifier_key = VerifierKey{
            .circuit_metadata = std::move(circuit_metadata),
            .setup_digest = digest,
            .pcs_scheme = pcs.scheme_identifier(),
            .options = options,
            .direct_matrix = nullptr,
            .matrix_oracle = nullptr,
            .factored_computation = std::move(factored_verifier),
        },
    };
    validate_external_prover_key_impl(result.prover_key, pcs);
    if (!valid_verifier_key(result.verifier_key, pcs)) {
        throw std::logic_error(
            "external Spartan setup produced an invalid verifier key");
    }
    return result;
}

Proof prove(const ProverKey &key, const R1csAssignment &assignment,
            const IPCS &pcs, Transcript &transcript) {
    validate_prover_key_impl(key, pcs);
    const R1csInstance &circuit = *key.circuit;
    bind_statement(key.setup_digest, assignment.public_inputs, transcript);

    // Step 1: commit to the private half of z=(1, public, witness).
    CommittedAssignment committed = commit_assignment(
        circuit, assignment, pcs, transcript);
    Proof proof;
    proof.witness_commitment = committed.witness.commitment;

    // Step 2: ConstraintCheck reduces Az o Bz = Cz to three claims at r_x.
    const ConstraintPhase constraint = prove_constraints(
        key, committed.assignment, proof, transcript);

    // Step 3: WiringCheck reduces the batched A/B/C claim to M(r_x,r_y)z(r_y).
    const WiringSumcheckOutput wiring = prove_wiring(
        key, std::move(committed.assignment), constraint, proof,
        transcript);

    // Step 4: authenticate the terminal matrix evaluation in committed mode.
    prove_matrix_evaluation(
        key, constraint, wiring, proof, pcs, transcript);

    // Step 5: open the committed witness at the private part of r_y.
    proof.witness_opening = open_witness(
        circuit, assignment, committed.witness, wiring, proof, pcs,
        transcript);
    return proof;
}

bool verify(const VerifierKey &key,
            std::span<const Fq> public_inputs, const Proof &proof,
            const IPCS &pcs, Transcript &transcript) {
    try {
        return verify_protocol(key, public_inputs, proof, pcs, transcript);
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    } catch (const std::domain_error &) {
        return false;
    } catch (const std::overflow_error &) {
        return false;
    } catch (const std::runtime_error &) {
        return false;
    }
}

void append_encoded_proof(const Proof &proof,
                          std::vector<std::uint8_t> &output) {
    const std::vector<std::uint8_t> witness_commitment =
        encode_pcs_commitment(proof.witness_commitment);
    output.insert(output.end(), witness_commitment.begin(),
                  witness_commitment.end());
    for (const auto &round : proof.constraint_sumcheck.rounds) {
        for (const Fq2 &value :
             std::array<Fq2, 2>{round.endpoint, round.at_two}) {
            const SerializedFq2 encoded = serialize(value);
            output.insert(output.end(), encoded.begin(), encoded.end());
        }
    }
    for (const Fq2 &value : std::array<Fq2, 3>{
             proof.az_evaluation, proof.bz_evaluation,
             proof.cz_evaluation}) {
        const SerializedFq2 encoded = serialize(value);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
    for (const auto &round : proof.wiring_sumcheck.rounds) {
        for (const Fq2 &value :
             std::array<Fq2, 2>{round.at_one, round.at_two}) {
            const SerializedFq2 encoded = serialize(value);
            output.insert(output.end(), encoded.begin(), encoded.end());
        }
    }
    for (const Fq2 &value : std::array<Fq2, 2>{
             proof.matrix_evaluation, proof.assignment_evaluation}) {
        const SerializedFq2 encoded = serialize(value);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
    const std::size_t factored_bytes =
        proof.factored_evaluation.has_value()
            ? factored_matrix_evaluation_proof_size_bytes(
                  *proof.factored_evaluation)
            : 0U;
    append_u64(output, factored_bytes);
    const std::size_t factored_start = output.size();
    if (proof.factored_evaluation.has_value()) {
        append_factored_matrix_evaluation_proof(
            *proof.factored_evaluation, output);
    }
    if (output.size() - factored_start != factored_bytes) {
        throw std::logic_error("Spartan factored proof size mismatch");
    }
    if (proof.witness_opening.bytes.empty() ||
        proof.witness_opening.bytes.size() >
            std::numeric_limits<std::uint64_t>::max()) {
        throw std::invalid_argument(
            "Spartan witness opening has an invalid encoded size");
    }
    append_u64(output, static_cast<std::uint64_t>(
                           proof.witness_opening.bytes.size()));
    output.insert(output.end(), proof.witness_opening.bytes.begin(),
                  proof.witness_opening.bytes.end());
}

std::vector<std::uint8_t> encode_proof(const Proof &proof) {
    std::vector<std::uint8_t> result;
    result.reserve(proof_size_bytes(proof));
    append_encoded_proof(proof, result);
    return result;
}

std::size_t proof_size_bytes(const Proof &proof) {
    std::size_t result =
        encode_pcs_commitment(proof.witness_commitment).size();
    const auto add = [&](std::size_t bytes) {
        if (bytes > std::numeric_limits<std::size_t>::max() - result) {
            throw std::overflow_error("Spartan proof size overflows size_t");
        }
        result += bytes;
    };
    const auto add_extension_values = [&](std::size_t count) {
        if (count > std::numeric_limits<std::size_t>::max() /
                        kSerializedFq2Bytes) {
            throw std::overflow_error("Spartan proof size overflows size_t");
        }
        add(count * kSerializedFq2Bytes);
    };
    const auto add_round_values = [&](std::size_t rounds,
                                      std::size_t values_per_round) {
        if (rounds > std::numeric_limits<std::size_t>::max() /
                         values_per_round) {
            throw std::overflow_error("Spartan proof size overflows size_t");
        }
        add_extension_values(rounds * values_per_round);
    };
    add_round_values(proof.constraint_sumcheck.rounds.size(), 2U);
    add_extension_values(3);
    add_round_values(proof.wiring_sumcheck.rounds.size(), 2U);
    add_extension_values(2);
    add(8U);
    if (proof.factored_evaluation.has_value()) {
        add(factored_matrix_evaluation_proof_size_bytes(
            *proof.factored_evaluation));
    }
    add(8U);
    add(proof.witness_opening.bytes.size());
    return result;
}

std::vector<std::uint8_t>
encode_public_inputs(std::span<const Fq> public_inputs) {
    std::vector<std::uint8_t> output;
    if (public_inputs.size() >
        (std::numeric_limits<std::size_t>::max() - 8U) /
            kSerializedFqBytes) {
        throw std::overflow_error("Spartan public input encoding overflows");
    }
    output.reserve(8U + public_inputs.size() * kSerializedFqBytes);
    const std::uint64_t count =
        static_cast<std::uint64_t>(public_inputs.size());
    for (std::size_t byte = 0; byte < 8U; ++byte) {
        output.push_back(
            static_cast<std::uint8_t>(count >> (8U * byte)));
    }
    for (const Fq &value : public_inputs) {
        const SerializedFq encoded = serialize(value);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
    return output;
}

namespace {

template <std::size_t Count>
std::vector<std::uint8_t>
encode_extension_tuple(const std::array<Fq2, Count> &values) {
    std::vector<std::uint8_t> output;
    output.reserve(Count * kSerializedFq2Bytes);
    for (const Fq2 &value : values) {
        const SerializedFq2 encoded = serialize(value);
        output.insert(output.end(), encoded.begin(), encoded.end());
    }
    return output;
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    }
}

void bind_statement(const Digest &setup_digest,
                    std::span<const Fq> public_inputs,
                    PublicCoin &transcript) {
    transcript.observe(kSetupLabel, setup_digest);
    transcript.observe(kPublicInputLabel,
                       encode_public_inputs(public_inputs));
}

Digest make_setup_digest(const R1csMetadata &circuit,
                         std::uint64_t pcs_scheme,
                         const Options &options,
                         const MatrixEvaluationOracle *matrix_oracle,
                         const FactoredMatrixCommitment *factored_commitment) {
    std::vector<std::uint8_t> bytes;
    constexpr std::string_view domain = "LaminateImpl/SpartanSetup/v5";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    bytes.insert(bytes.end(), circuit.digest().begin(),
                 circuit.digest().end());
    append_u64(bytes, circuit.shape().constraints);
    append_u64(bytes, circuit.shape().public_inputs);
    append_u64(bytes, circuit.shape().witness_variables);
    append_u64(bytes, circuit.padded_constraints());
    append_u64(bytes, circuit.assignment_half_size());
    append_u64(bytes, pcs_scheme);
    append_u64(bytes,
               static_cast<std::uint64_t>(options.matrix_evaluation));
    if (matrix_oracle == nullptr) {
        append_u64(bytes, 0);
    } else {
        append_u64(bytes, matrix_oracle->oracle_digest().size());
        bytes.insert(bytes.end(), matrix_oracle->oracle_digest().begin(),
                     matrix_oracle->oracle_digest().end());
    }
    if (factored_commitment == nullptr) {
        append_u64(bytes, 0);
    } else {
        const std::vector<std::uint8_t> encoded =
            encode_factored_matrix_commitment(*factored_commitment);
        append_u64(bytes, encoded.size());
        bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    }
    return sha256(bytes);
}

bool matching_matrix_oracle(
    const R1csMetadata &circuit,
    const std::shared_ptr<const MatrixEvaluationOracle> &matrix_oracle) {
    return matrix_oracle != nullptr &&
           matrix_oracle->circuit_digest() == circuit.digest() &&
           matrix_oracle->row_variables() == circuit.row_variables() &&
           matrix_oracle->column_variables() == circuit.column_variables();
}

bool valid_setup_matrix_oracle(
    const R1csMetadata &circuit, MatrixEvaluationMode mode,
    const std::shared_ptr<const MatrixEvaluationOracle> &matrix_oracle) {
    switch (mode) {
    case MatrixEvaluationMode::Direct:
        return matrix_oracle == nullptr;
    case MatrixEvaluationMode::Uniform:
        return matching_matrix_oracle(circuit, matrix_oracle);
    case MatrixEvaluationMode::CommittedFactored:
        return matrix_oracle == nullptr ||
               matching_matrix_oracle(circuit, matrix_oracle);
    }
    return false;
}

bool matching_factored_commitment(
    const R1csMetadata &circuit,
    const FactoredMatrixVerifierKey &key, const IPCS &pcs) {
    return key.structure != nullptr &&
           key.commitment.circuit_digest == circuit.digest() &&
           key.commitment.row_variables == circuit.row_variables() &&
           key.commitment.column_variables == circuit.column_variables() &&
           valid_factored_matrix_commitment(
               key.commitment, *key.structure, pcs);
}

bool matching_factored_commitment(
    const R1csMetadata &circuit,
    const FactoredMatrixProverKey &key, const IPCS &pcs) {
    return key.structure != nullptr &&
           key.commitment.circuit_digest == circuit.digest() &&
           key.commitment.row_variables == circuit.row_variables() &&
           key.commitment.column_variables == circuit.column_variables() &&
           valid_factored_matrix_commitment(
               key.commitment, *key.structure, pcs);
}

bool matching_factored_preprocessing(
    const R1csMetadata &circuit,
    const std::shared_ptr<const FactoredMatrixProverKey> &factored_prover,
    const std::shared_ptr<const FactoredMatrixVerifierKey> &factored_verifier,
    const IPCS &pcs) {
    return factored_prover != nullptr && factored_verifier != nullptr &&
           factored_prover->commitment == factored_verifier->commitment &&
           matching_factored_commitment(
               circuit, *factored_prover, pcs) &&
           matching_factored_commitment(
               circuit, *factored_verifier, pcs);
}

void validate_external_setup_inputs(
    const R1csMetadata &circuit,
    const std::shared_ptr<const FactoredMatrixProverKey> &factored_prover,
    const std::shared_ptr<const FactoredMatrixVerifierKey> &factored_verifier,
    const IPCS &pcs) {
    if (!circuit.is_well_formed() || pcs.scheme_identifier() == 0 ||
        !matching_factored_preprocessing(
            circuit, factored_prover, factored_verifier, pcs)) {
        throw std::invalid_argument(
            "external Spartan factored preprocessing does not match the "
            "circuit metadata");
    }
}

void validate_setup_inputs(
    const R1csInstance &circuit, const Options &options,
    const std::shared_ptr<const MatrixEvaluationOracle> &matrix_oracle,
    const std::shared_ptr<const FactoredMatrixProverKey> &factored_prover,
    const std::shared_ptr<const FactoredMatrixVerifierKey> &factored_verifier,
    const IPCS &pcs) {
    if (!valid_setup_matrix_oracle(
            circuit.metadata(), options.matrix_evaluation,
            matrix_oracle)) {
        throw std::invalid_argument(
            "Spartan matrix evaluator does not match the circuit");
    }
    const bool factored_selected =
        options.matrix_evaluation ==
        MatrixEvaluationMode::CommittedFactored;
    const bool factored_valid = factored_selected
        ? matching_factored_preprocessing(
              circuit.metadata(), factored_prover, factored_verifier, pcs)
        : factored_prover == nullptr && factored_verifier == nullptr;
    if (!factored_valid) {
        throw std::invalid_argument(
            "Spartan factored computation commitment does not match the circuit");
    }
}

void validate_prover_key_impl(const ProverKey &key, const IPCS &pcs) {
    if (key.circuit == nullptr || key.pcs_scheme == 0 ||
        key.pcs_scheme != pcs.scheme_identifier()) {
        throw std::invalid_argument("Spartan prover key is invalid");
    }
    const R1csMetadata metadata = key.circuit->metadata();
    const bool source_valid = valid_setup_matrix_oracle(
        metadata, key.options.matrix_evaluation, key.matrix_oracle);
    const bool factored_valid =
        key.options.matrix_evaluation ==
                MatrixEvaluationMode::CommittedFactored
            ? key.factored_computation != nullptr &&
                  matching_factored_commitment(
                      metadata, *key.factored_computation, pcs)
            : key.factored_computation == nullptr;
    const FactoredMatrixCommitment *factored_commitment =
        key.factored_computation == nullptr
            ? nullptr
            : &key.factored_computation->commitment;
    if (!source_valid || !factored_valid ||
        key.setup_digest != make_setup_digest(
                                metadata, key.pcs_scheme, key.options,
                                key.options.matrix_evaluation ==
                                        MatrixEvaluationMode::Uniform
                                    ? key.matrix_oracle.get()
                                    : nullptr,
                                factored_commitment)) {
        throw std::invalid_argument("Spartan prover key is invalid");
    }
}

void validate_external_prover_key_impl(const ExternalProverKey &key,
                                       const IPCS &pcs) {
    const FactoredMatrixCommitment *factored_commitment =
        key.factored_computation == nullptr
            ? nullptr
            : &key.factored_computation->commitment;
    if (!key.circuit_metadata.is_well_formed() ||
        key.pcs_scheme == 0 ||
        key.pcs_scheme != pcs.scheme_identifier() ||
        key.options.matrix_evaluation !=
            MatrixEvaluationMode::CommittedFactored ||
        key.factored_computation == nullptr ||
        !matching_factored_commitment(
            key.circuit_metadata, *key.factored_computation, pcs) ||
        key.setup_digest != make_setup_digest(
                                key.circuit_metadata, key.pcs_scheme,
                                key.options, nullptr, factored_commitment)) {
        throw std::invalid_argument(
            "external Spartan prover key is invalid");
    }
}

bool valid_verifier_key(const VerifierKey &key, const IPCS &pcs) {
    const bool direct_matrix_valid =
        key.options.matrix_evaluation == MatrixEvaluationMode::Direct
            ? key.direct_matrix != nullptr &&
                  key.direct_matrix->metadata() == key.circuit_metadata
            : key.direct_matrix == nullptr;
    const bool oracle_valid =
        key.options.matrix_evaluation == MatrixEvaluationMode::Uniform
            ? matching_matrix_oracle(
                  key.circuit_metadata, key.matrix_oracle)
            : key.matrix_oracle == nullptr;
    const bool factored_valid =
        key.options.matrix_evaluation ==
                MatrixEvaluationMode::CommittedFactored
            ? key.factored_computation != nullptr &&
                  matching_factored_commitment(
                      key.circuit_metadata, *key.factored_computation, pcs)
            : key.factored_computation == nullptr;
    const MatrixEvaluationOracle *bound_oracle =
        key.options.matrix_evaluation == MatrixEvaluationMode::Uniform
            ? key.matrix_oracle.get()
            : nullptr;
    const FactoredMatrixCommitment *bound_factored =
        key.factored_computation == nullptr
            ? nullptr
            : &key.factored_computation->commitment;
    return key.circuit_metadata.is_well_formed() &&
           key.pcs_scheme != 0 &&
           key.pcs_scheme == pcs.scheme_identifier() &&
           direct_matrix_valid && oracle_valid && factored_valid &&
           key.setup_digest == make_setup_digest(
                                   key.circuit_metadata, key.pcs_scheme,
                                   key.options, bound_oracle, bound_factored);
}

CommittedAssignment commit_assignment(
    const R1csInstance &circuit, const R1csAssignment &assignment,
    const IPCS &pcs, PublicCoin &transcript) {
    CommittedAssignment result;
    result.assignment = circuit.padded_assignment(assignment);
    const std::size_t half = circuit.assignment_half_size();
    result.witness = pcs.commit(
        std::span<const Fq>(result.assignment).subspan(half, half));
    if (result.witness.commitment.evaluation_count !=
            circuit.assignment_half_size() ||
        result.witness.commitment.width != 1 ||
        result.witness.commitment.scheme != pcs.scheme_identifier()) {
        throw std::logic_error("PCS returned inconsistent commitment metadata");
    }
    bind_witness_commitment(result.witness.commitment, transcript);
    return result;
}

ConstraintPhase prove_constraints(
    const ProverKey &key, std::span<const Fq> padded_assignment,
    Proof &proof, PublicCoin &transcript) {
    const R1csInstance &circuit = *key.circuit;
    const std::vector<Fq2> tau =
        transcript.challenge_fq2_vector(circuit.row_variables());
    std::vector<Fq> az = circuit.multiply(Matrix::A, padded_assignment);
    std::vector<Fq> bz = circuit.multiply(Matrix::B, padded_assignment);
    std::vector<Fq> cz = circuit.multiply(Matrix::C, padded_assignment);
    ConstraintPhase result{
        .sumcheck = prove_constraint_sumcheck(
            tau, std::move(az), std::move(bz), std::move(cz),
            transcript),
    };
    proof.constraint_sumcheck = result.sumcheck.proof;
    proof.az_evaluation = result.sumcheck.az_evaluation;
    proof.bz_evaluation = result.sumcheck.bz_evaluation;
    proof.cz_evaluation = result.sumcheck.cz_evaluation;
    bind_constraint_terminal(
        proof.az_evaluation, proof.bz_evaluation,
        proof.cz_evaluation, transcript);
    result.matrix_batching_challenge = transcript.challenge_fq2();
    return result;
}

WiringSumcheckOutput prove_wiring(
    const ProverKey &key, std::vector<Fq> padded_assignment,
    const ConstraintPhase &constraint, Proof &proof,
    PublicCoin &transcript) {
    const Fq2 gamma = constraint.matrix_batching_challenge;
    const Fq2 wiring_claim =
        proof.az_evaluation + gamma * proof.bz_evaluation +
        (gamma * gamma) * proof.cz_evaluation;
    std::vector<Fq2> matrix =
        key.matrix_oracle
            ? key.matrix_oracle->batched_wiring_table(
                  constraint.sumcheck.point, gamma)
            : key.circuit->batched_wiring_table(
                  constraint.sumcheck.point, gamma);
    WiringSumcheckOutput result = prove_wiring_sumcheck(
        std::move(matrix), std::move(padded_assignment), wiring_claim,
        transcript);
    proof.wiring_sumcheck = result.proof;
    proof.matrix_evaluation = result.matrix_evaluation;
    proof.assignment_evaluation = result.assignment_evaluation;
    bind_wiring_terminal(proof.matrix_evaluation,
                         proof.assignment_evaluation, transcript);
    return result;
}

void prove_matrix_evaluation(
    const ProverKey &key, const ConstraintPhase &constraint,
    const WiringSumcheckOutput &wiring, Proof &proof, const IPCS &pcs,
    PublicCoin &transcript) {
    proof.factored_evaluation.reset();
    if (key.options.matrix_evaluation ==
        MatrixEvaluationMode::CommittedFactored) {
        if (key.factored_computation == nullptr) {
            throw std::invalid_argument(
                "Spartan prover key has no factored computation commitment");
        }
        proof.factored_evaluation = prove_factored_matrix_evaluation(
            *key.factored_computation, constraint.sumcheck.point,
            wiring.point, constraint.matrix_batching_challenge,
            proof.matrix_evaluation, pcs, transcript);
    }
}

Fq2 evaluate_public_subtree(
    std::span<const Fq> public_inputs, std::size_t first_index,
    std::span<const Fq2> point) {
    const std::size_t live_values = public_inputs.size() + 1;
    if (first_index >= live_values) {
        return Fq2::zero();
    }
    if (point.empty()) {
        return first_index == 0
                   ? Fq2::one()
                   : Fq2::from_base(public_inputs[first_index - 1]);
    }

    // The public half is z_public = (1, x_1, ..., x_P, 0, ..., 0).
    // Recursing through its prefix tree evaluates
    //
    //   z_public(r) = (1-r_0) z_left(r_tail)
    //               + r_0 z_right(r_tail)
    //
    // in O(P + log H), instead of rebuilding eq(r,i) in O(log H) for every
    // public input.
    const std::size_t right_offset =
        std::size_t{1} << (point.size() - 1);
    const Fq2 left = evaluate_public_subtree(
        public_inputs, first_index, point.subspan(1));
    const Fq2 right = evaluate_public_subtree(
        public_inputs, first_index + right_offset, point.subspan(1));
    return left + point.front() * (right - left);
}

Fq2 evaluate_public_input_mle_impl(std::span<const Fq> public_inputs,
                                   std::size_t half_size,
                                   std::span<const Fq2> point) {
    if (point.size() >= std::numeric_limits<std::size_t>::digits ||
        (std::size_t{1} << point.size()) != half_size ||
        public_inputs.size() + 1 > half_size) {
        throw std::invalid_argument("public assignment half is malformed");
    }
    return evaluate_public_subtree(public_inputs, 0, point);
}

Fq2 derive_witness_evaluation(
    const Fq2 &assignment_evaluation, const Fq2 &half_selector,
    const Fq2 &public_evaluation) {
    if (half_selector.is_zero()) {
        throw std::domain_error(
            "Spartan witness selector challenge is zero");
    }
    // z(r_y)=(1-r_0)z_public(r_tail)+r_0 z_witness(r_tail).
    return (assignment_evaluation -
            (Fq2::one() - half_selector) * public_evaluation) /
           half_selector;
}

PcsOpeningProof open_witness(
    const R1csInstance &circuit, const R1csAssignment &assignment,
    const IPCS::CommitOutput &committed,
    const WiringSumcheckOutput &wiring, const Proof &proof,
    const IPCS &pcs, PublicCoin &transcript) {
    if (wiring.point.empty()) {
        throw std::logic_error("Spartan assignment point has no half selector");
    }
    const std::span<const Fq2> witness_point =
        std::span<const Fq2>(wiring.point).subspan(1);
    const Fq2 witness_evaluation = derive_witness_opening_evaluation(
        assignment.public_inputs, circuit.metadata(), wiring.point,
        proof.assignment_evaluation);
    return pcs.open(committed.prover_state, witness_point,
                    witness_evaluation, transcript);
}

Fq2 equality_evaluation(std::span<const Fq2> left,
                        std::span<const Fq2> right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument("equality points have different sizes");
    }
    Fq2 result = Fq2::one();
    for (std::size_t variable = 0; variable < left.size(); ++variable) {
        result *= (Fq2::one() - left[variable]) *
                      (Fq2::one() - right[variable]) +
                  left[variable] * right[variable];
    }
    return result;
}

bool verify_matrix_claim(
    const VerifierKey &key, const Proof &proof,
    std::span<const Fq2> row_point, std::span<const Fq2> column_point,
    const Fq2 &gamma) {
    std::array<Fq2, 3> expected{};
    if (key.options.matrix_evaluation == MatrixEvaluationMode::Direct) {
        expected = {
            key.direct_matrix->evaluate_matrix(
                Matrix::A, row_point, column_point),
            key.direct_matrix->evaluate_matrix(
                Matrix::B, row_point, column_point),
            key.direct_matrix->evaluate_matrix(
                Matrix::C, row_point, column_point),
        };
    } else if (key.options.matrix_evaluation ==
               MatrixEvaluationMode::Uniform) {
        expected = key.matrix_oracle->evaluate_matrices(
            row_point, column_point);
    } else {
        return false;
    }
    return proof.matrix_evaluation ==
           expected[0] + gamma * expected[1] +
               (gamma * gamma) * expected[2];
}

bool verify_protocol(const VerifierKey &key,
                     std::span<const Fq> public_inputs,
                     const Proof &proof, const IPCS &pcs,
                     PublicCoin &transcript) {
    if (!valid_verifier_key(key, pcs) ||
        public_inputs.size() !=
            key.circuit_metadata.shape().public_inputs ||
        proof.witness_commitment.scheme != key.pcs_scheme ||
        proof.witness_commitment.evaluation_count !=
            key.circuit_metadata.assignment_half_size() ||
        proof.witness_commitment.width != 1 ||
        proof.factored_evaluation.has_value() !=
            (key.options.matrix_evaluation ==
             MatrixEvaluationMode::CommittedFactored)) {
        return false;
    }
    const R1csMetadata &circuit = key.circuit_metadata;
    bind_statement(key.setup_digest, public_inputs, transcript);

    // Step 1: bind the witness commitment and derive the row point tau.
    bind_witness_commitment(proof.witness_commitment, transcript);
    const std::vector<Fq2> tau =
        transcript.challenge_fq2_vector(circuit.row_variables());

    // Step 2: verify ConstraintCheck and its Az, Bz, Cz terminal equation.
    const SumcheckVerification constraint = verify_constraint_sumcheck(
        proof.constraint_sumcheck, Fq2::zero(), tau, transcript);
    if (!constraint.accepts ||
        constraint.final_claim !=
            equality_evaluation(tau, constraint.point) *
                (proof.az_evaluation * proof.bz_evaluation -
                 proof.cz_evaluation)) {
        return false;
    }
    bind_constraint_terminal(
        proof.az_evaluation, proof.bz_evaluation,
        proof.cz_evaluation, transcript);
    const Fq2 gamma = transcript.challenge_fq2();

    // Step 3: verify WiringCheck and bind its terminal claims.
    const Fq2 wiring_claim =
        proof.az_evaluation + gamma * proof.bz_evaluation +
        (gamma * gamma) * proof.cz_evaluation;
    if (proof.wiring_sumcheck.rounds.size() !=
        circuit.column_variables()) {
        return false;
    }
    const SumcheckVerification wiring = verify_wiring_sumcheck(
        proof.wiring_sumcheck, wiring_claim, transcript);
    if (!wiring.accepts || wiring.point.empty() ||
        wiring.final_claim !=
            proof.matrix_evaluation * proof.assignment_evaluation) {
        return false;
    }
    bind_wiring_terminal(proof.matrix_evaluation,
                         proof.assignment_evaluation, transcript);

    // Step 4: authenticate the A/B/C evaluation. The selected committed mode
    // verifies the factored proof without traversing an expanded R1CS matrix.
    if (key.options.matrix_evaluation ==
        MatrixEvaluationMode::CommittedFactored) {
        if (!verify_factored_matrix_evaluation(
                *key.factored_computation, constraint.point, wiring.point,
                gamma, proof.matrix_evaluation,
                *proof.factored_evaluation, pcs, transcript)) {
            return false;
        }
    } else if (!verify_matrix_claim(
                   key, proof, constraint.point, wiring.point, gamma)) {
        return false;
    }

    // Step 5: separate the public/private halves of z(r_y) and open witness.
    const std::span<const Fq2> witness_point =
        std::span<const Fq2>(wiring.point).subspan(1);
    const Fq2 witness_evaluation = derive_witness_opening_evaluation(
        public_inputs, circuit, wiring.point,
        proof.assignment_evaluation);
    return pcs.verify(proof.witness_commitment, witness_point,
                      witness_evaluation, proof.witness_opening, transcript);
}

} // namespace

Fq2 evaluate_public_input_mle(std::span<const Fq> public_inputs,
                              std::size_t half_size,
                              std::span<const Fq2> point) {
    return evaluate_public_input_mle_impl(public_inputs, half_size, point);
}

void bind_public_statement(const Digest &setup_digest,
                           std::span<const Fq> public_inputs,
                           PublicCoin &public_coin) {
    bind_statement(setup_digest, public_inputs, public_coin);
}

void validate_prover_key(const ProverKey &key, const IPCS &pcs) {
    validate_prover_key_impl(key, pcs);
}

void validate_external_prover_key(const ExternalProverKey &key,
                                  const IPCS &pcs) {
    validate_external_prover_key_impl(key, pcs);
}

void validate_verifier_key(const VerifierKey &key, const IPCS &pcs) {
    if (!valid_verifier_key(key, pcs)) {
        throw std::invalid_argument("invalid Spartan verifier key");
    }
}

void bind_witness_commitment(const PcsCommitment &commitment,
                             PublicCoin &public_coin) {
    public_coin.observe(kWitnessCommitmentLabel,
                        encode_pcs_commitment(commitment));
}

void bind_constraint_terminal(const Fq2 &az, const Fq2 &bz,
                              const Fq2 &cz, PublicCoin &public_coin) {
    public_coin.observe(
        kConstraintTerminalLabel,
        encode_extension_tuple(std::array<Fq2, 3>{az, bz, cz}));
}

void bind_wiring_terminal(const Fq2 &matrix_evaluation,
                          const Fq2 &assignment_evaluation,
                          PublicCoin &public_coin) {
    public_coin.observe(
        kWiringTerminalLabel,
        encode_extension_tuple(std::array<Fq2, 2>{
            matrix_evaluation, assignment_evaluation}));
}

Fq2 derive_witness_opening_evaluation(
    std::span<const Fq> public_inputs, const R1csMetadata &metadata,
    std::span<const Fq2> wiring_point,
    const Fq2 &assignment_evaluation) {
    if (!metadata.is_well_formed() || wiring_point.empty() ||
        wiring_point.size() != metadata.column_variables() ||
        public_inputs.size() != metadata.shape().public_inputs) {
        throw std::invalid_argument(
            "Spartan witness opening inputs are malformed");
    }
    const std::span<const Fq2> witness_point = wiring_point.subspan(1);
    const Fq2 public_evaluation = evaluate_public_input_mle_impl(
        public_inputs, metadata.assignment_half_size(), witness_point);
    return derive_witness_evaluation(
        assignment_evaluation, wiring_point.front(), public_evaluation);
}

} // namespace laminate::spartan
