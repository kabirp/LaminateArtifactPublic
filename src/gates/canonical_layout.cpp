#include "laminate/gates/canonical_tables.hpp"

#include "laminate/basefold/common.hpp"
#include "laminate/params.hpp"

#include <bit>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>

namespace laminate::gates {
namespace {

using Bytes = std::vector<std::uint8_t>;

std::size_t variables(std::size_t dimension) {
    return basefold::log2_exact(dimension);
}

std::size_t checked_add(std::size_t left, std::size_t right,
                        const char *operation) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::overflow_error(operation);
    }
    return left + right;
}

void append_u64(Bytes &output, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("gate table encoding size exceeds u64");
    }
    const auto word = static_cast<std::uint64_t>(value);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        output.push_back(static_cast<std::uint8_t>(
            (word >> (8U * byte)) & std::uint64_t{0xff}));
    }
}

void append_label(Bytes &output, std::string_view label) {
    append_u64(output, label.size());
    output.insert(output.end(), label.begin(), label.end());
}

std::size_t affine_support(const payload::AffineLayer &layer) {
    std::size_t support = 0;
    for (const payload::AffineGate &gate : layer.gates) {
        std::map<std::pair<std::size_t, std::size_t>, Fp> combined;
        for (const payload::AffineTerm &term : gate.terms) {
            combined[{term.source, term.rotation}] += term.coefficient;
        }
        for (const auto &[address, coefficient] : combined) {
            (void)address;
            support = checked_add(
                support, !coefficient.is_zero(),
                "sparse affine support overflows");
        }
    }
    return support;
}

std::pair<std::size_t, std::size_t>
constant_support(const payload::AffineLayer &layer) {
    std::size_t uniform = 0;
    std::size_t slot = 0;
    for (const payload::AffineGate &gate : layer.gates) {
        if (const auto *scalar = std::get_if<Fp>(&gate.constant)) {
            uniform = checked_add(
                uniform, !scalar->is_zero(),
                "uniform affine-constant support overflows");
            continue;
        }
        for (const Fp &value : std::get<fhe::SlotVector>(gate.constant)) {
            slot = checked_add(
                slot, !value.is_zero(),
                "slot affine-constant support overflows");
        }
    }
    return {uniform, slot};
}

void append_table(GateTableLayout &layout, std::size_t layer,
                  GateTableKind kind, std::size_t local_variables,
                  std::size_t support_size) {
    if (support_size == 0) {
        return;
    }
    layout.tables.push_back(GateTableDescriptor{
        layer, kind, layout.tables.size(), local_variables, support_size});
}

void append_affine_tables(GateTableLayout &layout,
                          const payload::LayeredCircuit &circuit,
                          std::size_t layer_index) {
    const auto &layer =
        std::get<payload::AffineLayer>(circuit.layers[layer_index]);
    const std::size_t output_variables =
        variables(layer.dimensions.padded_size);
    const std::size_t source_variables = variables(
        payload::layer_dimensions(circuit.layers[layer_index + 1])
            .padded_size);
    const std::size_t slot_variables =
        variables(circuit.shape.value_width());
    const std::size_t coefficient_support = affine_support(layer);
    if (layout.table_set == GateTableSet::Wide) {
        append_table(
            layout, layer_index, GateTableKind::WideAffineWeight,
            checked_add(checked_add(output_variables, source_variables,
                                    "wide affine address overflows"),
                        slot_variables, "wide affine address overflows"),
            coefficient_support);
    } else {
        append_table(layout, layer_index,
                     GateTableKind::LanedAffineWire,
                     checked_add(output_variables, source_variables,
                                 "laned affine address overflows"),
                     coefficient_support);
    }

    const auto [uniform_support, slot_support] = constant_support(layer);
    append_table(layout, layer_index,
                 GateTableKind::AffineConstantUniform,
                 output_variables, uniform_support);
    append_table(layout, layer_index,
                 GateTableKind::AffineConstantSlot,
                 checked_add(output_variables, slot_variables,
                             "affine constant address overflows"),
                 slot_support);
}

} // namespace

GateTableLayout make_gate_table_layout(
    const payload::LayeredCircuit &circuit, GateTableSet table_set,
    const basefold::Parameters &parameters) {
    circuit.validate();
    if (parameters.log_rate == 0 || parameters.num_queries == 0 ||
        parameters.log_rate > kBaseFieldTwoAdicity) {
        throw std::invalid_argument(
            "make_gate_table_layout: invalid BaseFold parameters");
    }
    if ((table_set == GateTableSet::Wide) !=
        (circuit.shape.kind == payload::PayloadKind::Wide)) {
        throw std::invalid_argument(
            "make_gate_table_layout: table set and payload shape disagree");
    }

    GateTableLayout layout;
    layout.table_set = table_set;
    if (table_set == GateTableSet::Wide) {
        const auto masks = WideMaskDictionary::build(circuit);
        layout.wide_masks = {masks->slots(), masks->size(),
                             masks->padded_size(), masks->digest()};
        for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
            if (payload::layer_kind(circuit.layers[layer]) !=
                payload::LayerKind::Affine) continue;
            const auto program = WideProgram::build(circuit, layer, masks);
            const auto &d = program.dimensions();
            layout.wide_layers.push_back(
                {layer, program.nodes().size(), d, program.digest()});
            const auto add = [&](WidePublicTable source, GateTableKind kind,
                                 std::size_t domain) {
                std::size_t support = 0;
                program.visit_entries(source, [&](const auto &) {
                    support = checked_add(support, 1, "Wide support overflows");
                });
                append_table(layout, layer, kind, variables(domain), support);
            };
            add(WidePublicTable::UniformEdges,
                GateTableKind::WideLocalUniformEdges, d.uniform_edge_domain);
            add(WidePublicTable::MaskEdges,
                GateTableKind::WideLocalMaskEdges, d.mask_edge_domain);
            add(WidePublicTable::UniformConstants,
                GateTableKind::AffineConstantUniform, d.uniform_constant_domain);
            add(WidePublicTable::SlotConstants,
                GateTableKind::AffineConstantSlot, d.slot_constant_domain);
        }
        std::size_t support = 0;
        masks->visit_entries([&](const auto &) {
            support = checked_add(support, 1, "Wide dictionary support overflows");
        });
        append_table(layout, 0, GateTableKind::WideMaskDictionary,
                     variables(masks->padded_size()) + variables(masks->slots()),
                     support);
        return layout;
    }
    for (std::size_t layer = 0; layer + 1 < circuit.layers.size(); ++layer) {
        if (payload::layer_kind(circuit.layers[layer]) ==
            payload::LayerKind::Affine) {
            append_affine_tables(layout, circuit, layer);
        }
    }
    return layout;
}

std::vector<std::uint8_t>
encode_canonical(const GateTableLayout &layout) {
    Bytes output;
    append_label(output, "LaminateImpl/GateTableLayout/v4");
    output.push_back(static_cast<std::uint8_t>(layout.table_set));
    append_u64(output, layout.tables.size());
    for (const GateTableDescriptor &table : layout.tables) {
        append_u64(output, table.layer_index);
        output.push_back(static_cast<std::uint8_t>(table.kind));
        append_u64(output, table.selector);
        append_u64(output, table.local_variables);
        append_u64(output, table.support_size);
    }
    append_u64(output, layout.wide_layers.size());
    for (const auto &layer : layout.wide_layers) {
        append_u64(output, layer.layer_index);
        append_u64(output, layer.node_count);
        const auto &d = layer.dimensions;
        for (const auto value : {d.slots, d.input_width, d.output_width,
             d.internal_width, d.row_width, d.source_width, d.mask_width,
             d.internal_scalars, d.uniform_edge_domain, d.mask_edge_domain,
             d.uniform_constant_domain, d.slot_constant_domain,
             d.dictionary_domain}) append_u64(output, value);
        output.insert(output.end(), layer.program_digest.begin(),
                      layer.program_digest.end());
    }
    append_u64(output, layout.wide_masks.slots);
    append_u64(output, layout.wide_masks.mask_count);
    append_u64(output, layout.wide_masks.mask_width);
    output.insert(output.end(), layout.wide_masks.dictionary_digest.begin(),
                  layout.wide_masks.dictionary_digest.end());
    return output;
}

Digest digest(const GateTableLayout &layout) {
    return sha256(encode_canonical(layout));
}

const GateTableDescriptor *find_table_if(
    const GateTableLayout &layout, std::size_t layer_index,
    GateTableKind kind) {
    for (const GateTableDescriptor &table : layout.tables) {
        if (table.layer_index == layer_index && table.kind == kind) {
            return &table;
        }
    }
    return nullptr;
}

const GateTableDescriptor &find_table(
    const GateTableLayout &layout, std::size_t layer_index,
    GateTableKind kind) {
    const GateTableDescriptor *table =
        find_table_if(layout, layer_index, kind);
    if (table == nullptr) {
        throw std::invalid_argument(
            "find_table: sparse polynomial is absent from this layout");
    }
    return *table;
}

} // namespace laminate::gates
