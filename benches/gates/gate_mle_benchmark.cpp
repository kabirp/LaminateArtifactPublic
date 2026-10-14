/// Gate-only structural admission and measured preprocessing/proof diagnostics.
/// No FHE setup, encryption, payload execution, or runtime extrapolation.
#include "laminate/basefold/common.hpp"
#include "laminate/bench/payload_profile.hpp"
#include "laminate/gates/outsourced.hpp"
#include "laminate/payload/compiler.hpp"
#include "laminate/setup/gate_mle.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <thread>
#include <unistd.h>

using namespace laminate;
namespace {
using Clock = std::chrono::steady_clock;
struct Options {
    std::string profile = "tiny", mode = "plan";
    payload::WorkloadKind workload = payload::WorkloadKind::Diamond;
    std::filesystem::path scratch = std::filesystem::temp_directory_path();
    std::size_t slots = 8, depth = 2, width = 8, threads = 1;
    std::uint64_t ram = 1ULL << 30, disk = 2ULL << 30;
    bool custom_geometry = false, mixed_actions = false;
};
std::uint64_t number(std::string_view text) {
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value == 0)
        throw std::invalid_argument("expected a positive decimal integer");
    return value;
}
Options parse(int argc, char **argv) {
    Options result;
    for (int i = 1; i < argc; ++i) {
        const std::string_view name(argv[i]);
        if (name == "--help") {
            std::cout << "laminate_gate_mle_bench [--profile tiny|quick|target-balancedLaned|target-mulHeavyPyramid] "
                "[--mode plan|preprocess|prove] [--scratch-parent DIR] [--threads N] "
                "[--max-ram-bytes N] [--max-disk-bytes N] "
                "[--workload diamond|fanoutHeavy|rotationHeavy|deepSnake|mixedActions --slots N --depth D --width W (tiny only)]\n";
            std::exit(0);
        }
        if (++i == argc) throw std::invalid_argument("option needs a value");
        const std::string_view value(argv[i]);
        if (name == "--profile") result.profile = value;
        else if (name == "--mode") result.mode = value;
        else if (name == "--scratch-parent") result.scratch = value;
        else if (name == "--workload") {
            result.custom_geometry = true;
            if (value == "diamond") result.workload = payload::WorkloadKind::Diamond;
            else if (value == "fanoutHeavy") result.workload = payload::WorkloadKind::FanoutHeavy;
            else if (value == "rotationHeavy") result.workload = payload::WorkloadKind::RotationHeavy;
            else if (value == "deepSnake") result.workload = payload::WorkloadKind::DeepSnake;
            else if (value == "mixedActions") result.mixed_actions = true;
            else throw std::invalid_argument("unknown tiny workload");
        }
        else if (name == "--threads") result.threads = number(value);
        else if (name == "--max-ram-bytes") result.ram = number(value);
        else if (name == "--max-disk-bytes") result.disk = number(value);
        else if (name == "--slots") { result.slots = number(value); result.custom_geometry = true; }
        else if (name == "--depth") { result.depth = number(value); result.custom_geometry = true; }
        else if (name == "--width") { result.width = number(value); result.custom_geometry = true; }
        else throw std::invalid_argument("unknown option: " + std::string(name));
    }
    if (result.mode != "plan" && result.mode != "preprocess" && result.mode != "prove")
        throw std::invalid_argument("mode must be plan, preprocess, or prove");
    if (result.profile != "tiny") {
        if (result.custom_geometry) throw std::invalid_argument("geometry overrides require profile tiny");
        (void)bench::benchmark_payload_profile(result.profile);
        result.slots = kDefaultPolyModulusDegree;
    }
    if (result.threads > 256) throw std::invalid_argument("threads must be at most 256");
    return result;
}
std::uint64_t sum(std::uint64_t a, std::uint64_t b) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a)
        throw std::overflow_error("diagnostic resource sum overflow");
    return a + b;
}
std::uint64_t rss() {
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage)) throw std::runtime_error("cannot read peak RSS");
#ifdef __APPLE__
    return usage.ru_maxrss;
#else
    return static_cast<std::uint64_t>(usage.ru_maxrss) * 1024;
#endif
}
template<class Function> auto phase(std::string_view name, Function &&action) {
    std::cout << "phase=" << name << std::endl;
    const auto start = Clock::now();
    auto result = action();
    std::cout << "seconds." << name << '='
              << std::chrono::duration<double>(Clock::now() - start).count() << '\n';
    std::cout << "peak_rss_bytes." << name << '=' << rss() << std::endl;
    return result;
}
class Scratch {
  public:
    explicit Scratch(const std::filesystem::path &parent) {
        auto pattern = (parent / "laminate-gate-diagnostic-XXXXXX").string();
        if (!mkdtemp(pattern.data())) throw std::runtime_error("cannot create scratch directory");
        path = pattern;
    }
    ~Scratch() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
    std::filesystem::path path;
};
struct Query {
    std::size_t layer;
    std::vector<Fpk> output, input;
};
}

int main(int argc, char **argv) {
    try {
        const auto options = parse(argc, argv);
        std::cout << std::setprecision(9)
            << "format=laminate-gate-mle-diagnostic-v1\n"
            << "scope=gate-only-no-fhe\nprofile=" << options.profile
            << "\nmode=" << options.mode << "\nslots=" << options.slots
            << "\npreprocessing_threads=" << options.threads
            << "\nmax_ram_bytes=" << options.ram << "\nmax_disk_bytes=" << options.disk
            << "\nenvironment.git_commit=" << LAMINATE_GIT_COMMIT
            << "\nenvironment.git_dirty=" << LAMINATE_GIT_DIRTY
            << "\nenvironment.build_type=" << LAMINATE_BUILD_TYPE
            << "\nenvironment.compiler=" << LAMINATE_COMPILER
            << "\nenvironment.hardware_threads=" << std::thread::hardware_concurrency() << '\n';
        const auto spec = options.profile == "tiny"
            ? payload::WorkloadSpec{.kind = options.workload,
                .shape = payload::PayloadShape::wide(options.slots),
                .multiplicative_depth = options.depth, .width = options.width, .seed = 1}
            : bench::benchmark_payload_workload_spec(
                bench::benchmark_payload_profile(options.profile), payload::PayloadShape::wide(options.slots));
        std::cout << "workload=" << (options.mixed_actions ? "mixed-actions" : payload::workload_name(spec.kind))
                  << "\ndepth=" << spec.multiplicative_depth << "\nwidth=" << spec.width << std::endl;
        const auto payload_circuit = phase("payload", [&] {
            if (!options.mixed_actions) return payload::make_payload_circuit(spec);
            // A generic fallback family: masked rotated branches cannot be
            // represented as a single supported boundary action. All sizes
            // are caller parameters; no target payload name affects the path.
            payload::PayloadBuilder builder(spec.shape, 2);
            fhe::SlotVector values(options.slots);
            for (std::size_t i = 0; i < values.size(); ++i) values[i] = Fp(2 * i + 3);
            const auto mask = builder.add_plaintext(std::move(values));
            auto state = payload::WireId{0};
            for (std::size_t depth = 0; depth < options.depth; ++depth) {
                auto combined = payload::kNoWire;
                for (std::size_t j = 0; j < options.width; ++j) {
                    const auto branch = builder.mul_plain(builder.rotate(state, (j + 1) % options.slots), mask);
                    combined = combined == payload::kNoWire ? branch : builder.add(combined, branch);
                }
                state = builder.mul(combined, 1);
            }
            builder.set_outputs({state});
            return builder.finish();
        });
        const auto circuit = phase("compile", [&] { return payload::compile(payload_circuit); });
        gates::GateTableBuildOptions build;
        build.max_message_entries = std::numeric_limits<std::size_t>::max();
        // Planning records the requirement without treating the caller's cap
        // as implicit authorization to materialize this public index.
        build.wide_scratch_parent = options.scratch;
        build.wide_max_disk_bytes = std::numeric_limits<std::uint64_t>::max();
        build.wide_resources.min_free_bytes = 64ULL << 20;
        build.preprocessing_threads = options.threads;
        const auto plan = phase("plan", [&] {
            return plan_gate_mle_preprocessing(circuit, gates::GateTableSet::Wide, build);
        });
        const auto preparation_ram = affine_gate_preparation_workspace_bytes(circuit);
        const auto ram = sum(plan.resources.retained_prover_key_bytes,
            sum(plan.resources.opening_workspace_bytes, preparation_ram));
        const auto disk = std::max({plan.commitment_peak_disk_bytes,
            sum(plan.resources.retained_prover_key_disk_bytes, plan.resources.retained_prover_key_disk_bytes),
            sum(plan.resources.retained_prover_key_disk_bytes, plan.resources.opening_workspace_disk_bytes)});
        std::size_t support = 0, internal = 0, layers_with_adjoint = 0;
        for (const auto &table : plan.layout.tables) support += table.support_size;
        for (const auto &layer : plan.layout.wide_layers) {
            if (layer.node_count) { internal += layer.dimensions.internal_scalars; ++layers_with_adjoint; }
        }
        std::cout << "plan.affine_layers=" << plan.layout.wide_layers.size()
            << "\nplan.layers_with_adjoint=" << layers_with_adjoint
            << "\nplan.internal_scalars=" << internal
            << "\nplan.sparse_entries=" << support
            << "\nplan.public_rows=" << plan.wide_public_message_size
            << "\nplan.public_columns=" << plan.wide_public_width
            << "\nplan.key_ram_bytes=" << plan.resources.retained_prover_key_bytes
            << "\nplan.opening_ram_bytes=" << plan.resources.opening_workspace_bytes
            << "\nplan.affine_preparation_ram_bytes=" << preparation_ram
            << "\nplan.key_disk_bytes=" << plan.resources.retained_prover_key_disk_bytes
            << "\nplan.opening_disk_bytes=" << plan.resources.opening_workspace_disk_bytes
            << "\nplan.commitment_peak_disk_bytes=" << plan.commitment_peak_disk_bytes
            << "\nplan.proof_bytes_upper_bound=" << plan.resources.proof_bytes_upper_bound
            << "\nplan.local_pcs_soundness_bits=" << plan.basefold_soundness_bits
            << "\nadmission.required_ram_bytes=" << ram
            << "\nadmission.required_disk_bytes=" << disk
            << "\nadmission.ram_within_cap=" << (ram <= options.ram ? "true" : "false")
            << "\nadmission.disk_within_cap=" << (disk <= options.disk ? "true" : "false") << std::endl;
        if (options.mode == "plan") { std::cout << "status=PLAN_ONLY\n"; return 0; }
        if (ram > options.ram || disk > options.disk)
            throw std::runtime_error("planned GateMLE resources exceed explicit diagnostic caps");
        const auto available = std::filesystem::space(options.scratch).available;
        if (sum(disk, build.wide_resources.min_free_bytes) > available)
            throw std::runtime_error("scratch filesystem lacks planned GateMLE disk and reserve");
        Scratch scratch(options.scratch);
        build.wide_scratch_parent = scratch.path;
        build.wide_max_disk_bytes = options.disk;
        auto key = phase("preprocess", [&] {
            return gates::preprocess_gate_tables(circuit, gates::GateTableSet::Wide, build);
        });
        const auto expected = key.verifier;
        phase("persist", [&] {
            gates::export_gate_table_prover_key(key, scratch.path / "cached-key");
            return true;
        });
        key = {}; // Drop setup state before measuring server restoration.
        std::cout << "measurement.reopen_cache_state=warm-after-export\n";
        key = phase("reopen", [&] {
            return gates::reopen_gate_table_prover_key(expected, scratch.path / "cached-key", build);
        });
        if (options.mode == "preprocess") { std::cout << "status=PASS\n"; return 0; }
        Transcript point_coin("Laminate/GateDiagnostic/Points/v1");
        std::vector<Query> queries;
        for (const auto &layer : key.verifier.layout.wide_layers)
            queries.push_back({layer.layer_index,
                point_coin.challenge_vector(basefold::log2_exact(layer.dimensions.output_width * options.slots)),
                point_coin.challenge_vector(basefold::log2_exact(layer.dimensions.input_width * options.slots))});
        Transcript prover_coin("Laminate/GateDiagnostic/Proof/v1");
        gates::observe_gate_table_key(key.verifier, prover_coin);
        gates::GateClaimProver prover(circuit, key.verifier.layout, prover_coin);
        phase("record_queries", [&] {
            for (const auto &q : queries) {
                (void)prover.evaluate_affine_constant(q.layer, q.output);
                (void)prover.evaluate(gates::GateMleQuery{gates::AffineQuery{q.layer, q.output, q.input}});
            }
            return true;
        });
        const auto proof = phase("prove", [&] { return prover.finish(key); });
        const auto bytes = gates::encode_canonical(proof);
        const auto verified = phase("verify", [&] {
            Transcript coin("Laminate/GateDiagnostic/Proof/v1");
            gates::observe_gate_table_key(key.verifier, coin);
            gates::GateClaimVerifier verifier(key.verifier, proof, coin);
            for (const auto &q : queries) {
                (void)verifier.evaluate_affine_constant(q.layer, q.output);
                (void)verifier.evaluate(gates::GateMleQuery{gates::AffineQuery{q.layer, q.output, q.input}});
            }
            return verifier.finish() && coin.challenge_fpk() == prover_coin.challenge_fpk();
        });
        std::cout << "proof.claims=" << proof.claimed_values.size()
            << "\nproof.bytes=" << bytes.size()
            << "\nproof.public_operands=" << proof.wide->public_column_targets.size()
            << "\nproof.adjoint_groups=" << proof.wide->adjoint_groups.size()
            << "\nproof.verified=" << (verified ? "true" : "false") << '\n';
        if (!verified) throw std::runtime_error("GateMLE diagnostic verification failed");
        std::cout << "status=PASS\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "FAILED: " << error.what() << '\n';
        return 1;
    }
}
