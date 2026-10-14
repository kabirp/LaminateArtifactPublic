// Exercise the process runner's accounting against real persisted GateMLE
// caches, without constructing full benchmark FHE or packing preprocessing.
#define main laminate_packed_benchmark_main
#include "../protocol/packed_checkpoint_benchmark.cpp"
#undef main

#include "test_helpers.hpp"

namespace {

class AccountingDirectory {
  public:
    AccountingDirectory() {
        std::string pattern = (std::filesystem::temp_directory_path() /
                               "laminate-packed-accounting-XXXXXX").string();
        std::vector<char> name(pattern.begin(), pattern.end());
        name.push_back('\0');
        const auto result = ::mkdtemp(name.data());
        if (!result) throw std::runtime_error("cannot create accounting fixture");
        path = result;
    }
    ~AccountingDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path path;
};

template <class F> bool accounting_rejects(F &&call) {
    try { call(); } catch (const std::exception &) { return true; }
    return false;
}

void accounting_file(const std::filesystem::path &path, std::size_t bytes) {
    std::filesystem::create_directories(path.parent_path());
    publish_private_file(path, std::vector<std::uint8_t>(bytes, 7));
}

void check_persisted_accounting(gates::GateTableSet table_set) {
    AccountingDirectory fixture;
    ProcessCommand command;
    command.run_directory = fixture.path / "run";
    const auto shared = command.run_directory / "shared" / "preprocessing";
    const auto server = command.run_directory / "server" / "preprocessing";
    accounting_file(shared / "packed-shared" / "manifest.bin", 11);
    accounting_file(server / "packed-server" / "manifest.bin", 13);
    accounting_file(server / "evaluation-context.bin", 17);
    accounting_file(server / "fixed-message-basis.bin", 19);

    const auto shape = table_set == gates::GateTableSet::Wide
        ? PayloadShape::wide(32) : PayloadShape::laned(4, 32);
    PayloadBuilder builder(shape, 2);
    builder.set_outputs({builder.mul(builder.add(0, 1), 1)});
    const auto payload = builder.finish();
    const auto circuit = compile(payload);
    const auto setup = preprocess_outsourced_gate_mle_setup(
        payload, circuit, table_set,
        {.wide_scratch_parent = fixture.path / "gate-scratch",
         .prover_key_directory = server / "gate-mle"});
    const auto gate_resources = gate_mle_prover_resource_bounds(
        *setup.public_setup.outsourced_gate_mle);
    const auto cache_bytes = regular_file_bytes(server / "gate-mle");
    CHECK(cache_bytes != 0);

    ProcessSetupRecord record;
    record.evaluation_bundle.bytes = 17;
    record.fixed_message_basis.bytes = 19;
    record.gate_mle_retained_prover_key_disk_bytes =
        gate_resources.retained_prover_key_disk_bytes;
    record.gate_mle_opening_workspace_disk_bytes =
        gate_resources.opening_workspace_disk_bytes;
    record.request_wire_bytes = 23;
    record.response_wire_bytes = 29;
    const auto complete_tree_bytes =
        regular_file_bytes(shared) + regular_file_bytes(server);
    const auto persistent = packed_server_persistent_bytes(command, record);
    // Proving-key accounting includes every persistent cache file.
    CHECK(persistent == complete_tree_bytes);
    CHECK(persistent == 60 + cache_bytes);

    const auto reserved = packed_server_reserved_bytes(record, persistent);
    const auto online_only = record.gate_mle_opening_workspace_disk_bytes +
        record.request_wire_bytes + record.response_wire_bytes +
        kOnlineMetadataDiskReserve;
    CHECK(reserved - complete_tree_bytes == online_only);
    record.replay_budgets.reserved_live_scratch_bytes = reserved;
    require_packed_server_reserve_binding(record, persistent);
    ++record.replay_budgets.reserved_live_scratch_bytes;
    CHECK(accounting_rejects([&] {
        require_packed_server_reserve_binding(record, persistent);
    }));

    // Admission must credit the physical cache, even when its conservative
    // bound is larger; the unused bound remains in the additional demand.
    PackedRolePreprocessingPublicationPlan plan;
    PackedRolePreprocessingPublishLimits limits;
    BundleBinding evaluation, client, verifier, basis;
    evaluation.bytes = 17;
    client.bytes = 31;
    verifier.bytes = 37;
    basis.bytes = 19;
    auto padded_gate_resources = gate_resources;
    padded_gate_resources.retained_prover_key_disk_bytes = cache_bytes + 4096;
    const auto demand = packed_setup_prepublication_demand(
        evaluation, client, verifier, basis, 0, plan, limits,
        padded_gate_resources, cache_bytes);
    const auto bound_filled_demand = packed_setup_prepublication_demand(
        evaluation, client, verifier, basis, 0, plan, limits,
        padded_gate_resources, cache_bytes + 4096);
    CHECK(demand.already_present_persistent_bytes == 104 + cache_bytes);
    CHECK(demand.final_persistent_bytes == bound_filled_demand.final_persistent_bytes);
    CHECK(demand.peak_live_bytes == bound_filled_demand.peak_live_bytes);
    CHECK(bound_filled_demand.already_present_persistent_bytes -
              demand.already_present_persistent_bytes == 4096);

    record.gate_mle_retained_prover_key_disk_bytes = cache_bytes - 1;
    CHECK(accounting_rejects([&] {
        (void)packed_server_persistent_bytes(command, record);
    }));
    CHECK(accounting_rejects([&] {
        (void)packed_setup_prepublication_demand(
            evaluation, client, verifier, basis, 0, plan, limits,
            padded_gate_resources, cache_bytes + 4097);
    }));
}

} // namespace

int main() {
    laminate::test::Runner runner("packed setup accounting");
    runner.run("Folded persistence and admission", [] {
        check_persisted_accounting(gates::GateTableSet::Wide);
    });
    runner.run("Laned persistence and admission", [] {
        check_persisted_accounting(gates::GateTableSet::Laned);
    });
    return runner.summary();
}
