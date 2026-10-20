#ifndef LAMINATE_PACKING_PROOF_MATRIX_ORACLE_HPP
#define LAMINATE_PACKING_PROOF_MATRIX_ORACLE_HPP

/// @file oracle.hpp
/// @brief Reference/prover-only structured A/B/C evaluator.

#include "laminate/packing/proof/r1cs.hpp"
#include "laminate/packing/outer_relation/tensor.hpp"
#include "laminate/spartan/factored.hpp"
#include "laminate/spartan/matrix_oracle.hpp"

#include <memory>
#include <span>
#include <vector>

namespace laminate::packing {

/// Construct the reference/prover-only matrix oracle for one packing relation.
///
/// Arguments:
/// - `plan`, `layout`, and `native_packing_operator` are the public compact
///   description used to evaluate A/B/C;
/// - `reference_circuit` fixes the exact circuit digest and supplies the
///   prover's linear matrix products until those paths are also specialized.
///
/// Preconditions: every argument describes the same relation. Postcondition:
/// `evaluate_matrices` is independent of expanded sparse entries and agrees
/// with `reference_circuit->evaluate_matrix` at every point. The selected
/// factored verifier retains compact regular formulas, not this general
/// reference/prover oracle.
std::shared_ptr<const spartan::MatrixEvaluationOracle>
make_proof_of_packing_matrix_oracle(
    OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
    NativePackingOperator native_packing_operator,
    std::shared_ptr<const spartan::R1csInstance> reference_circuit);

/// Construct the prover-only matrix engine for committed factored evaluation.
///
/// The returned object delegates matrix products and wiring-table generation
/// to `reference_circuit`, but deliberately does not retain the native packing
/// coefficients used to build the committed tensors. Consequently,
/// `evaluate_matrices` is unavailable on this object; the factored terminal
/// protocol evaluates the regular formulas and committed tensors instead.
std::shared_ptr<const spartan::MatrixEvaluationOracle>
make_proof_of_packing_factored_prover_oracle(
    OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
    std::shared_ptr<const spartan::R1csInstance> reference_circuit);

/// Construct the compact verifier-visible decomposition used by the selected
/// factored matrix computation commitment. The returned structure owns only
/// public layout geometry and ordered owner lists; it does not retain packing
/// coefficients, an expanded R1CS, or a PCS prover state.
std::shared_ptr<const spartan::FactoredMatrixStructure>
make_proof_of_packing_factored_structure(
    OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
    std::span<const PackingTensor> tensors,
    const spartan::R1csMetadata &circuit);

/// Coefficient-free counterpart of the overload above.  The mappings carry
/// only canonical tensor geometry and owner order; exact columns are bound by
/// the factored preprocessing commitment.
std::shared_ptr<const spartan::FactoredMatrixStructure>
make_proof_of_packing_factored_structure(
    OuterRelationPlan plan, ProofOfPackingR1csLayout layout,
    std::span<const PackingTensorMapping> mappings,
    const spartan::R1csMetadata &circuit);

/// Recover and validate the small owner map from a packing factored
/// structure. Passing another FactoredMatrixStructure implementation throws.
std::vector<PackingTensorMapping>
proof_of_packing_factored_tensor_mappings(
    const spartan::FactoredMatrixStructure &structure);

} // namespace laminate::packing

#endif // LAMINATE_PACKING_PROOF_MATRIX_ORACLE_HPP
