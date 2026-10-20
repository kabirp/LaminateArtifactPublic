/// @file protocol_report_summary.cpp
/// @brief Render a completed Folded or Laned benchmark as readable Markdown.

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <locale>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

constexpr std::uintmax_t kMaximumReportBytes = 64ULL << 20U;

struct Options {
    std::filesystem::path input;
    std::optional<std::filesystem::path> output;
};

void print_usage(std::ostream &output) {
    output << "Usage: laminate_protocol_report_summary --input result.txt "
              "[--output summary.md]\n";
}

std::optional<Options> parse_options(int argc, char **argv) {
    Options options;
    bool input_seen = false;
    bool output_seen = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help") {
            print_usage(std::cout);
            return std::nullopt;
        }
        if (index + 1 >= argc) {
            throw std::invalid_argument(std::string(argument) +
                                        " expects a path");
        }
        const std::filesystem::path value(argv[++index]);
        if (value.empty()) {
            throw std::invalid_argument(std::string(argument) +
                                        " expects a nonempty path");
        }
        if (argument == "--input") {
            if (input_seen) {
                throw std::invalid_argument("--input was specified twice");
            }
            input_seen = true;
            options.input = value;
        } else if (argument == "--output") {
            if (output_seen) {
                throw std::invalid_argument("--output was specified twice");
            }
            output_seen = true;
            options.output = value;
        } else {
            throw std::invalid_argument("unknown option: " +
                                        std::string(argument));
        }
    }
    if (!input_seen) {
        throw std::invalid_argument("--input is required");
    }
    return options;
}

bool valid_key(std::string_view key) {
    if (key.empty()) {
        return false;
    }
    return std::all_of(key.begin(), key.end(), [](unsigned char character) {
        return (character >= 'a' && character <= 'z') ||
               (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') || character == '.' ||
               character == '_' || character == '-';
    });
}

class Report {
  public:
    void insert(std::string key, std::string value, std::size_t line) {
        if (!fields_.emplace(std::move(key), std::move(value)).second) {
            throw std::runtime_error("duplicate key on line " +
                                     std::to_string(line));
        }
    }

    std::optional<std::string_view> find(std::string_view key) const {
        const auto found = fields_.find(key);
        if (found == fields_.end()) {
            return std::nullopt;
        }
        return found->second;
    }

    std::string_view require(std::string_view key) const {
        const auto value = find(key);
        if (!value) {
            throw std::runtime_error("missing required report field: " +
                                     std::string(key));
        }
        return *value;
    }

    std::optional<std::uint64_t> integer(std::string_view key) const {
        const auto raw = find(key);
        if (!raw) {
            return std::nullopt;
        }
        std::uint64_t value = 0;
        const auto parsed = std::from_chars(raw->data(),
                                            raw->data() + raw->size(), value);
        if (parsed.ec != std::errc{} ||
            parsed.ptr != raw->data() + raw->size()) {
            throw std::runtime_error("invalid unsigned integer in field: " +
                                     std::string(key));
        }
        return value;
    }

    std::uint64_t require_integer(std::string_view key) const {
        const auto value = integer(key);
        if (!value) {
            throw std::runtime_error("missing required integer field: " +
                                     std::string(key));
        }
        return *value;
    }

    std::optional<double> real(std::string_view key) const {
        const auto raw = find(key);
        if (!raw) {
            return std::nullopt;
        }
        std::istringstream input{std::string(*raw)};
        input.imbue(std::locale::classic());
        double value = 0;
        input >> std::noskipws >> value;
        if (!input.eof() || input.fail() || !std::isfinite(value)) {
            throw std::runtime_error("invalid real number in field: " +
                                     std::string(key));
        }
        return value;
    }

    double require_real(std::string_view key) const {
        const auto value = real(key);
        if (!value) {
            throw std::runtime_error("missing required real field: " +
                                     std::string(key));
        }
        return *value;
    }

  private:
    std::map<std::string, std::string, std::less<>> fields_;
};

Report read_report(const std::filesystem::path &path) {
    std::error_code error;
    const std::uintmax_t size = std::filesystem::file_size(path, error);
    if (error) {
        throw std::runtime_error("cannot inspect input report: " +
                                 error.message());
    }
    if (size > kMaximumReportBytes) {
        throw std::runtime_error("input report exceeds the 64 MiB limit");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open input report");
    }

    Report report;
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::size_t separator = line.find('=');
        if (line.empty() || separator == std::string::npos || separator == 0) {
            throw std::runtime_error("expected key=value on line " +
                                     std::to_string(line_number));
        }
        const std::string key = line.substr(0, separator);
        if (!valid_key(key)) {
            throw std::runtime_error("invalid key on line " +
                                     std::to_string(line_number));
        }
        std::string value = line.substr(separator + 1);
        if (value.find('\0') != std::string::npos) {
            throw std::runtime_error("NUL byte on line " +
                                     std::to_string(line_number));
        }
        report.insert(key, std::move(value), line_number);
    }
    if (input.bad()) {
        throw std::runtime_error("failed while reading input report");
    }
    if (line_number == 0) {
        throw std::runtime_error("input report is empty");
    }
    if (report.require("format") != "laminate-benchmark-v9") {
        throw std::runtime_error(
            "input is not a laminate-benchmark-v9 report");
    }
    if (report.require("verification.result") != "ACCEPT") {
        throw std::runtime_error(
            "completed protocol report does not contain verification ACCEPT");
    }
    const std::string_view protocol =
        report.require("classification.protocol");
    if (protocol != "folded" && protocol != "laned") {
        throw std::runtime_error(
            "report protocol must be Folded or Laned");
    }
    return report;
}

std::string comma_integer(std::uint64_t value) {
    std::string digits = std::to_string(value);
    for (std::ptrdiff_t index =
             static_cast<std::ptrdiff_t>(digits.size()) - 3;
         index > 0; index -= 3) {
        digits.insert(static_cast<std::size_t>(index), 1, ',');
    }
    return digits;
}

std::string fixed(double value, int precision) {
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << std::fixed << std::setprecision(precision) << value;
    return output.str();
}

std::string format_bytes(std::uint64_t bytes) {
    static constexpr const char *units[]{"bytes", "KiB", "MiB", "GiB",
                                          "TiB"};
    long double scaled = static_cast<long double>(bytes);
    std::size_t unit = 0;
    while (scaled >= 1024.0L && unit + 1 < std::size(units)) {
        scaled /= 1024.0L;
        ++unit;
    }
    if (unit == 0) {
        return comma_integer(bytes) + (bytes == 1 ? " byte" : " bytes");
    }
    return fixed(static_cast<double>(scaled), 2) + ' ' + units[unit] +
           " (" + comma_integer(bytes) + " bytes)";
}

std::string format_duration(double milliseconds) {
    if (!std::isfinite(milliseconds) || milliseconds < 0) {
        throw std::runtime_error("duration is not a finite nonnegative value");
    }
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << std::fixed << std::setprecision(3);
    if (milliseconds < 1000.0) {
        output << milliseconds << " ms";
        return output.str();
    }
    const double seconds = milliseconds / 1000.0;
    const auto whole_seconds = static_cast<std::uint64_t>(seconds);
    const std::uint64_t hours = whole_seconds / 3600;
    const std::uint64_t minutes = (whole_seconds % 3600) / 60;
    const double remainder =
        seconds - static_cast<double>(hours * 3600 + minutes * 60);
    if (hours != 0) {
        output << hours << "h ";
    }
    if (hours != 0 || minutes != 0) {
        output << minutes << "m ";
    }
    output << remainder << 's';
    return output.str();
}

std::string markdown_escape(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const char character : value) {
        if (character == '|' || character == '\\') {
            result.push_back('\\');
        }
        result.push_back(character);
    }
    return result;
}

std::string text_or_missing(const Report &report, std::string_view key) {
    const auto value = report.find(key);
    return value ? markdown_escape(*value) : "not reported";
}

std::string integer_or_missing(const Report &report, std::string_view key) {
    const auto value = report.integer(key);
    return value ? comma_integer(*value) : "not reported";
}

std::string quantity_or_missing(const Report &report, std::string_view key) {
    const auto raw = report.find(key);
    if (!raw) {
        return "not reported";
    }
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(raw->data(),
                                        raw->data() + raw->size(), value);
    if (parsed.ec == std::errc{} &&
        parsed.ptr == raw->data() + raw->size()) {
        return comma_integer(value);
    }
    return markdown_escape(*raw);
}

std::string bytes_or_missing(const Report &report, std::string_view key) {
    const auto value = report.integer(key);
    return value ? format_bytes(*value) : "not reported";
}

std::string duration_or_missing(const Report &report, std::string_view key) {
    const auto value = report.real(key);
    return value ? format_duration(*value) : "not reported";
}

std::string bits_at_checkpoint_or_missing(
    const Report &report, std::string_view bits_key,
    std::string_view checkpoint_key) {
    if (!report.find(bits_key) || !report.find(checkpoint_key)) {
        return "not reported";
    }
    return quantity_or_missing(report, bits_key) + " bits at " +
           text_or_missing(report, checkpoint_key);
}

std::string cpu_ratio_or_missing(const Report &report,
                                 std::string_view wall_key,
                                 std::string_view cpu_key) {
    const auto wall = report.real(wall_key);
    const auto cpu = report.real(cpu_key);
    if (!wall || !cpu || *wall <= 0) {
        return "not reported";
    }
    return fixed(100.0 * *cpu / *wall, 2) + '%';
}

using Row = std::vector<std::string>;

void table(std::ostream &output, const std::vector<std::string> &headings,
           const std::vector<Row> &rows) {
    output << '|';
    for (const std::string &heading : headings) {
        output << ' ' << heading << " |";
    }
    output << "\n|";
    for (std::size_t index = 0; index < headings.size(); ++index) {
        output << " --- |";
    }
    output << '\n';
    for (const Row &row : rows) {
        if (row.size() != headings.size()) {
            throw std::logic_error("Markdown table row has wrong width");
        }
        output << '|';
        for (const std::string &cell : row) {
            output << ' ' << cell << " |";
        }
        output << '\n';
    }
    output << '\n';
}

std::optional<std::uint64_t>
checked_sum(std::initializer_list<std::optional<std::uint64_t>> values,
            std::string_view description) {
    std::uint64_t total = 0;
    for (const auto value : values) {
        if (!value) {
            return std::nullopt;
        }
        if (*value > std::numeric_limits<std::uint64_t>::max() - total) {
            throw std::overflow_error(std::string(description) +
                                      " overflows");
        }
        total += *value;
    }
    return total;
}

std::uint64_t payload_operations(const Report &report) {
    const auto operations = checked_sum(
        {report.integer("workload.gates.add"),
         report.integer("workload.gates.add_plain"),
         report.integer("workload.gates.mul"),
         report.integer("workload.gates.mul_plain"),
         report.integer("workload.gates.rotate")},
        "payload operation count");
    if (!operations) {
        throw std::runtime_error(
            "payload operation count requires all five gate counts");
    }
    return *operations;
}

std::string protocol_name(const Report &report) {
    return report.require("classification.protocol") == "folded" ? "Folded"
                                                                  : "Laned";
}

std::string geometry(const Report &report, std::uint64_t operations) {
    std::vector<std::string> values;
    const auto append = [&](std::string_view name,
                            std::optional<std::uint64_t> value) {
        if (value) {
            values.push_back(std::string(name) + '=' + comma_integer(*value));
        }
    };
    append("N", report.integer("parameters.N"));
    if (report.require("classification.protocol") == "laned") {
        append("B", report.integer("parameters.lane_count_B"));
    }
    append("D", report.integer("workload.requested_depth"));
    append("W", report.integer("workload.requested_width"));
    append("I", report.integer("workload.input_count"));
    append("O", report.integer("workload.output_count"));
    values.push_back("n_FHE=" + comma_integer(operations));
    std::ostringstream output;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            output << ", ";
        }
        output << values[index];
    }
    return output.str();
}

std::string data_modulus(const Report &report) {
    if (const auto bits =
            report.integer("parameters.fresh_ciphertext_modulus_bits")) {
        std::string value = comma_integer(*bits) + " bits";
        if (const auto limbs = report.integer("parameters.fresh_rns_limbs")) {
            value += " across " + comma_integer(*limbs) + " data primes";
        }
        return value;
    }
    const auto limbs = report.integer("parameters.fresh_rns_limbs");
    const auto bits = report.integer("parameters.bits_per_limb");
    if (limbs && bits &&
        *limbs <= std::numeric_limits<std::uint64_t>::max() / *bits) {
        return comma_integer(*limbs * *bits) +
               " modeled bits (Mock backend)";
    }
    return "not reported";
}

std::string key_modulus(const Report &report) {
    const auto bits = report.integer("parameters.key_modulus_bits");
    return bits ? comma_integer(*bits) +
                      " bits including the special prime"
                : "not reported";
}

std::string revision(const Report &report) {
    return text_or_missing(report, "environment.git_commit") + " (dirty=" +
           text_or_missing(report, "environment.git_dirty") + ')';
}

struct TimingKeys {
    std::string wall;
    std::string cpu;
};

struct SpanTiming {
    std::size_t samples = 0;
    double wall_ms = 0;
    double cpu_ms = 0;
};

struct NamedSpanTiming {
    std::string name;
    SpanTiming timing;
};

std::vector<NamedSpanTiming> aggregate_named_spans(
    const Report &report, std::string_view name_fragment) {
    const std::uint64_t count =
        report.require_integer("telemetry.completed_spans");
    std::map<std::string, SpanTiming, std::less<>> grouped;
    for (std::uint64_t index = 0; index < count; ++index) {
        const std::string prefix =
            "telemetry.span." + std::to_string(index);
        const std::string name(report.require(prefix + ".name"));
        if (name.find(name_fragment) == std::string::npos) {
            continue;
        }
        SpanTiming &timing = grouped[name];
        ++timing.samples;
        timing.wall_ms += report.require_real(prefix + ".wall_ms");
        timing.cpu_ms += report.require_real(prefix + ".cpu_ms");
    }
    std::vector<NamedSpanTiming> result;
    result.reserve(grouped.size());
    for (auto &[name, timing] : grouped) {
        result.push_back(NamedSpanTiming{std::move(name), timing});
    }
    return result;
}

std::optional<SpanTiming> aggregate_span(
    const Report &report, std::string_view expected_name) {
    const auto count = report.integer("telemetry.completed_spans");
    if (!count) {
        return std::nullopt;
    }
    SpanTiming result;
    for (std::uint64_t index = 0; index < *count; ++index) {
        const std::string prefix =
            "telemetry.span." + std::to_string(index);
        const auto name = report.find(prefix + ".name");
        if (!name || *name != expected_name) {
            continue;
        }
        const auto wall = report.real(prefix + ".wall_ms");
        const auto cpu = report.real(prefix + ".cpu_ms");
        if (!wall || !cpu) {
            throw std::runtime_error(
                "telemetry span is missing its timing fields: " +
                std::string(expected_name));
        }
        ++result.samples;
        result.wall_ms += *wall;
        result.cpu_ms += *cpu;
    }
    return result.samples == 0 ? std::nullopt
                               : std::optional<SpanTiming>(result);
}

Row span_timing_row(const Report &report, std::string label,
                    std::string_view name) {
    const auto timing = aggregate_span(report, name);
    if (!timing) {
        return Row{std::move(label), "not reported", "not reported",
                   "not reported"};
    }
    const double divisor = static_cast<double>(timing->samples);
    return Row{std::move(label),
               format_duration(timing->wall_ms / divisor),
               format_duration(timing->cpu_ms / divisor),
               comma_integer(timing->samples)};
}

void require_text(const Report &report, std::string_view key,
                  std::string_view expected) {
    const std::string_view actual = report.require(key);
    if (actual != expected) {
        throw std::runtime_error(std::string(key) + " must be " +
                                 std::string(expected) + ", not " +
                                 std::string(actual));
    }
}

bool has_span_prefix(const Report &report, std::string_view prefix) {
    const std::uint64_t count =
        report.require_integer("telemetry.completed_spans");
    for (std::uint64_t index = 0; index < count; ++index) {
        const std::string key =
            "telemetry.span." + std::to_string(index) + ".name";
        const std::string_view name = report.require(key);
        if (name.starts_with(prefix)) {
            return true;
        }
    }
    return false;
}

void validate_evidence_contract(const Report &report) {
    require_text(
        report, "classification.transport",
        "one-round-compatible-encrypted-statement;canonical-packed-proof-"
        "bounded-outer-decode-and-direct-verification");
    require_text(
        report, "protocol.output_point_derivation",
        "complete-encrypted-request-and-output-statement");
    (void)report.require("protocol.session_id");
    (void)report.require("protocol.request_commitment");
    (void)report.require("protocol.encrypted_statement_digest");
    require_text(
        report, "classification.verifier_setup",
        "compact-packed-verifier-setup-no-prover-preprocessing");
    require_text(
        report, "wire.verification_boundary",
        "bounded-outer-decode-then-direct-semantic-verification;"
        "opaque-basefold-openings-parsed-once");
    require_text(report, "telemetry.schema",
                 "laminate-protocol-progress-v1");

    const std::string_view logging_status =
        report.require("telemetry.logging_status");
    if (logging_status != "complete" && logging_status != "stderr-only") {
        throw std::runtime_error(
            "accepted report has incomplete progress telemetry");
    }
    const std::uint64_t requested_iterations =
        report.require_integer("benchmark.iterations");
    const std::uint64_t completed_iterations =
        report.require_integer("benchmark.completed_iterations");
    if (requested_iterations == 0 ||
        completed_iterations != requested_iterations) {
        throw std::runtime_error(
            "accepted report did not complete every requested proof "
            "iteration");
    }
    (void)report.require_real("timing.proof_decoding.wall_ms.mean");
    (void)report.require_real("timing.proof_decoding.cpu_ms.mean");
    (void)report.require_real("headline.server_total_ms");
    (void)report.require_real("headline.client_total_ms");
    (void)report.require_integer("wire.canonical_proof_bytes");

    const std::uint64_t repetitions = report.require_integer(
        "parameters.transcript_packing_repetitions");
    const std::uint64_t selected_repetitions = report.require_integer(
        "parameters.selected_transcript_packing_repetitions");
    if (repetitions == 0 || selected_repetitions == 0) {
        throw std::runtime_error(
            "packed benchmark repetition counts must be nonzero");
    }
    const std::string_view integrity =
        report.require("classification.transcript_packing_integrity");
    if ((repetitions == selected_repetitions &&
         integrity != "selected-120-repetition-profile") ||
        (repetitions != selected_repetitions &&
         integrity !=
             "diagnostic-nonselected-repetitions-no-security-claim")) {
        throw std::runtime_error(
            "transcript-packing integrity classification disagrees with "
            "the actual and selected repetition counts");
    }

    static constexpr std::string_view packing_stages[]{
        "transcript_packing.reveal_evaluation",
        "transcript_packing.assignment",
        "transcript_packing.spartan_prove",
        "transcript_packing.verifier_statement",
        "transcript_packing.spartan_verify",
        "transcript_packing.threshold_checks",
        "transcript_packing.unpack",
    };
    for (const std::string_view stage : packing_stages) {
        if (!aggregate_span(report, stage)) {
            throw std::runtime_error(
                "accepted report is missing telemetry stage: " +
                std::string(stage));
        }
    }
    const std::string_view variant =
        report.require("classification.protocol");
    const std::string reduction = std::string(variant) + ".reduction";
    const std::string affine_round =
        std::string(variant) + ".affine.sumcheck_round";
    const std::string multiplication_round =
        std::string(variant) + ".multiplication.sumcheck_round";
    if (!has_span_prefix(report, reduction) ||
        (!has_span_prefix(report, affine_round) &&
         !has_span_prefix(report, multiplication_round))) {
        throw std::runtime_error(
            "accepted report is missing detailed encrypted-GKR telemetry");
    }
}

TimingKeys direct_timing(std::string_view name) {
    const std::string prefix = "timing." + std::string(name);
    return TimingKeys{prefix + ".wall_ms", prefix + ".cpu_ms"};
}

TimingKeys mean_timing(std::string_view name) {
    const std::string prefix = "timing." + std::string(name);
    return TimingKeys{prefix + ".wall_ms.mean", prefix + ".cpu_ms.mean"};
}

Row timing_row(const Report &report, std::string label,
               std::string accounting, const TimingKeys &keys) {
    return Row{std::move(label), std::move(accounting),
               duration_or_missing(report, keys.wall),
               duration_or_missing(report, keys.cpu),
               cpu_ratio_or_missing(report, keys.wall, keys.cpu)};
}

void validate_proof_breakdown(const Report &report) {
    const std::uint64_t packing_components = *checked_sum(
        {report.require_integer("proof.well_formedness_reveal_bytes"),
         report.require_integer("proof.digit_packing_ciphertext_bytes"),
         report.require_integer("proof.spartan_packing_proof_bytes")},
        "transcript-packing proof bytes");
    const std::uint64_t packing_total =
        report.require_integer("proof.transcript_packing_bytes");
    if (packing_components != packing_total) {
        throw std::runtime_error(
            "transcript-packing subtotal disagrees with its components");
    }
    const std::uint64_t complete_components = *checked_sum(
        {report.require_integer("proof.statement_and_metadata_bytes"),
         report.require_integer("proof.round_message_bytes"),
         report.require_integer("proof.terminal_message_bytes"),
         report.require_integer("proof.partial_gate_mle_bytes"),
         report.require_integer("proof.gate_mle_opening_bytes"),
         report.require_integer("proof.gkr_commitment_bytes"), packing_total},
        "complete proof bytes");
    const std::uint64_t total =
        report.require_integer("proof.total_bytes");
    if (complete_components != total) {
        throw std::runtime_error(
            "complete proof total disagrees with its additive components");
    }
    const std::uint64_t wire =
        report.require_integer("wire.canonical_proof_bytes");
    if (wire != total) {
        throw std::runtime_error(
            "encoded proof length disagrees with proof.total_bytes");
    }
}

void render_headline(std::ostream &output, const Report &report,
                     std::uint64_t operations) {
    output << "# Laminate " << protocol_name(report)
           << " benchmark summary\n\n"
           << "**ACCEPT** — the verifier accepted the proof reconstructed "
              "from its canonical byte encoding.\n\n";
    table(output, {"Headline metric", "Result"},
          {{"Protocol", protocol_name(report)},
           {"Backend", text_or_missing(report, "classification.backend")},
           {"Run tier", text_or_missing(report, "classification.run_tier")},
           {"Workload", geometry(report, operations)},
           {"Transcript-packing repetitions",
            integer_or_missing(
                report, "parameters.transcript_packing_repetitions")},
           {"Selected integrity-profile repetitions",
            integer_or_missing(
                report,
                "parameters.selected_transcript_packing_repetitions")},
           {"Output-point statement",
            text_or_missing(report, "protocol.output_point_derivation")},
           {"Offline setup", duration_or_missing(report,
                                                   "timing.setup.wall_ms")},
           {"Online server", duration_or_missing(
                                 report, "headline.server_total_ms")},
           {"Online client", duration_or_missing(
                                 report, "headline.client_total_ms")},
           {"Initial ciphertext data modulus", data_modulus(report)},
           {"Key modulus", key_modulus(report)},
           {"Canonical proof", bytes_or_missing(report, "proof.total_bytes")},
           {"Whole-process peak RSS",
            bytes_or_missing(report, "environment.peak_rss_bytes")},
           {"Revision", revision(report)},
           {"Build and SEAL acceleration",
            text_or_missing(report, "environment.build_type") + "; " +
                text_or_missing(report, "environment.seal_acceleration")}});

    if (report.require_integer(
            "parameters.transcript_packing_repetitions") !=
        report.require_integer(
            "parameters.selected_transcript_packing_repetitions")) {
        output << "> **Integrity warning:** this run deliberately uses a "
                  "reduced transcript-packing repetition count for "
                  "implementation stress testing. It makes no "
                  "transcript-packing integrity claim.\n\n";
    }

    output << "> **Scope warning:** this driver runs resident client and "
              "server roles in one process and performs no whole-run "
              "resource admission. It serializes the proof, strictly "
              "decodes it with the compact verifier setup, checks canonical "
              "re-encoding, and verifies the decoded object. The output "
              "point is bound to the exact encrypted request and output, "
              "matching the selected one-request/one-response statement. "
              "This exercises the proof boundary but not an OS process "
              "boundary, a network transport, or bounded-memory transcript "
              "packing.\n\n";
    if (report.require("classification.backend") == "mock") {
        output << "> **Mock warning:** ACCEPT covers functional protocol "
                  "execution only. Mock timings are not FHE performance and "
                  "the run provides no cryptographic security evidence.\n\n";
    }
}

void render_timings(std::ostream &output, const Report &report) {
    output << "## Runtime breakdown\n\n"
              "Totals and subtotals are labeled explicitly; do not add a "
              "subtotal to the components nested beneath it.\n\n"
              "### Offline setup\n\n";
    std::vector<Row> setup_rows;
    setup_rows.push_back(timing_row(report, "Setup total", "aggregate",
                                    direct_timing("setup")));
    setup_rows.push_back(timing_row(report, "↳ FHE context and keys",
                                    "component", direct_timing("fhe_setup")));
    setup_rows.push_back(timing_row(
        report, "↳ Gate-MLE preprocessing", "component",
        direct_timing("gate_mle_preprocessing")));
    setup_rows.push_back(timing_row(
        report, "↳ Fixed plaintext preprocessing", "component",
        direct_timing("plaintext_preprocessing")));
    setup_rows.push_back(timing_row(
        report, "↳ Transcript-packing preprocessing", "component",
        direct_timing("packing_preprocessing")));
    table(output, {"Component", "Accounting", "Wall time", "CPU time",
                   "CPU/wall"},
          setup_rows);

    output << "### Online server\n\n";
    std::vector<Row> server_rows{
        {"Online server total", "aggregate",
         duration_or_missing(report, "headline.server_total_ms"),
         "not reported", "not reported"},
        timing_row(report, "Payload FHE evaluation", "component",
                   direct_timing("payload_fhe_evaluation")),
        timing_row(report, "Proof generation total", "subtotal",
                   mean_timing("prove")),
        timing_row(report, "↳ Encrypted GKR", "subtotal component",
                   direct_timing("gkr_proving")),
        timing_row(report, "↳ Transcript packing", "subtotal component",
                   mean_timing("transcript_packing")),
        timing_row(report, "Proof serialization", "component",
                   mean_timing("proof_serialization")),
    };
    table(output, {"Component", "Accounting", "Wall time", "CPU time",
                   "CPU/wall"},
          server_rows);

    output << "### Encrypted-GKR reductions\n\n"
              "Each row is one complete prover reduction and includes its "
              "nested sumcheck rounds. Rows are not additive with the "
              "encrypted-GKR subtotal above.\n\n";
    const std::uint64_t layer_count =
        report.require_integer("circuit.layer_count");
    if (layer_count < 2) {
        throw std::runtime_error(
            "accepted packed report has no circuit reduction");
    }
    std::vector<Row> reduction_rows;
    reduction_rows.reserve(static_cast<std::size_t>(layer_count - 1U));
    for (std::uint64_t layer = 0; layer + 1U < layer_count; ++layer) {
        const std::string prefix =
            "timing.prove.layer." + std::to_string(layer);
        const std::string wall = prefix + ".wall_ms.mean";
        const std::string cpu = prefix + ".cpu_ms.mean";
        reduction_rows.push_back(
            {"Reduction " + comma_integer(layer),
             markdown_escape(report.require(prefix + ".kind")),
             format_duration(report.require_real(wall)),
             format_duration(report.require_real(cpu)),
             cpu_ratio_or_missing(report, wall, cpu)});
    }
    table(output, {"Reduction", "Kind", "Mean wall time",
                   "Mean CPU time", "CPU/wall"},
          reduction_rows);

    std::vector<NamedSpanTiming> sumcheck_rounds =
        aggregate_named_spans(report, ".sumcheck_round");
    std::sort(sumcheck_rounds.begin(), sumcheck_rounds.end(),
              [](const NamedSpanTiming &left,
                 const NamedSpanTiming &right) {
                  return left.timing.wall_ms /
                             static_cast<double>(left.timing.samples) >
                         right.timing.wall_ms /
                             static_cast<double>(right.timing.samples);
              });
    const std::size_t displayed_rounds =
        std::min<std::size_t>(12, sumcheck_rounds.size());
    output << "### Slowest encrypted-GKR sumcheck rounds\n\n"
           << "Showing " << displayed_rounds << " of "
           << sumcheck_rounds.size()
           << " distinct rounds. The progress JSONL retains every round.\n\n";
    std::vector<Row> round_rows;
    round_rows.reserve(displayed_rounds);
    for (std::size_t index = 0; index < displayed_rounds; ++index) {
        const NamedSpanTiming &entry = sumcheck_rounds[index];
        const double samples =
            static_cast<double>(entry.timing.samples);
        round_rows.push_back(
            {markdown_escape(entry.name),
             format_duration(entry.timing.wall_ms / samples),
             format_duration(entry.timing.cpu_ms / samples),
             comma_integer(entry.timing.samples)});
    }
    table(output, {"Canonical stage", "Mean wall time", "Mean CPU time",
                   "Samples"},
          round_rows);

    if (report.integer("telemetry.completed_spans")) {
        output << "### Transcript-packing prover detail\n\n"
                  "These rows are disjoint substages of the transcript-"
                  "packing subtotal above. Times are means when the proof "
                  "iteration count is greater than one.\n\n";
        table(output, {"Substage", "Mean wall time", "Mean CPU time",
                       "Samples"},
              {span_timing_row(
                   report, "Challenge and reveal evaluation",
                   "transcript_packing.reveal_evaluation"),
               span_timing_row(report, "R1CS assignment construction",
                               "transcript_packing.assignment"),
               span_timing_row(report, "Spartan, factored argument, and "
                                       "BaseFold",
                               "transcript_packing.spartan_prove")});
    }

    output << "### Online client\n\n";
    std::vector<Row> client_rows{
        {"Online client total", "aggregate",
         duration_or_missing(report, "headline.client_total_ms"),
         "not reported", "not reported"},
        timing_row(report, "Input encryption", "component",
                   direct_timing("payload_input_encryption")),
        timing_row(report, "Output decryption", "component",
                   direct_timing("payload_output_decryption")),
        timing_row(report, "Bounded proof decoding", "component",
                   mean_timing("proof_decoding")),
        timing_row(report, "Proof verification including decryption",
                   "component and subtotal",
                   mean_timing("verify_including_decryption")),
        timing_row(report, "↳ Packed-message verification and recovery",
                   "subtotal component",
                   mean_timing("client_packed_message_verification")),
        timing_row(report, "↳ Gate-MLE opening verification",
                   "subtotal component",
                   mean_timing("gate_mle_opening.verify")),
        timing_row(report, "↳ Remaining plaintext verification",
                   "subtotal component",
                   mean_timing("plaintext_verification")),
    };
    table(output, {"Component", "Accounting", "Wall time", "CPU time",
                   "CPU/wall"},
          client_rows);

    if (report.integer("telemetry.completed_spans")) {
        output << "### Transcript-packing verifier detail\n\n"
                  "These rows are disjoint substages inside packed-message "
                  "verification.\n\n";
        table(output, {"Substage", "Mean wall time", "Mean CPU time",
                       "Samples"},
              {span_timing_row(
                   report, "Public-statement reconstruction",
                   "transcript_packing.verifier_statement"),
               span_timing_row(report, "Spartan and opening verification",
                               "transcript_packing.spartan_verify"),
               span_timing_row(report, "Well-formedness thresholds",
                               "transcript_packing.threshold_checks"),
               span_timing_row(report, "Digit decryption and unpacking",
                               "transcript_packing.unpack")});
    }

    output << "The secret-key-assisted payload-output error diagnostic is "
              "excluded from online client time: "
           << duration_or_missing(
                  report, "timing.payload_output_error_diagnostic.wall_ms")
           << ".\n\n";
}

std::string operation_calls(const Report &report, std::string_view stage,
                            std::string_view operation) {
    const std::string prefix = "operations." + std::string(stage) + '.' +
                               std::string(operation);
    if (report.find(prefix + ".calls")) {
        return integer_or_missing(report, prefix + ".calls");
    }
    return integer_or_missing(report, prefix);
}

std::string operation_limb_work(const Report &report,
                                std::string_view stage,
                                std::string_view operation) {
    return integer_or_missing(
        report, "operations." + std::string(stage) + '.' +
                    std::string(operation) + ".limb_operations");
}

void render_operation_ledger(std::ostream &output, const Report &report) {
    struct OperationRow {
        std::string_view label;
        std::string_view key;
    };
    static constexpr OperationRow operations[]{
        {"Encryptions (server phases)", "encrypt"},
        {"Decryptions (must be zero)", "decrypt"},
        {"Ciphertext additions", "add"},
        {"Ciphertext subtractions", "sub"},
        {"Ciphertext multiplications", "mul_no_relin"},
        {"Relinearizations", "relinearize"},
        {"Scalar plaintext multiplications", "mul_plain_scalar"},
        {"Vector plaintext multiplications", "mul_plain_vector"},
        {"Rotations", "rotate"},
        {"Modulus switches", "mod_switch"},
        {"Logical extension additions", "logical_ext_add"},
        {"Logical extension subtractions", "logical_ext_sub"},
        {"Logical extension multiplications", "logical_ext_mul"},
        {"Logical extension/plain multiplications",
         "logical_ext_mul_plain"},
    };

    output << "## Server FHE operation ledger\n\n"
              "Calls count backend operations. Limb work is the sum of the "
              "active RNS-prime counts at those calls and is available for "
              "SEAL runs. Logical extension rows describe protocol-level "
              "degree-eight operations; do not add them to the physical "
              "kernel rows. Counts describe one deterministic proof "
              "iteration. Complete proving includes inner GKR and transcript "
              "packing; the GKR columns isolate the pre-packing boundary.\n\n";
    std::vector<Row> rows;
    rows.reserve(std::size(operations));
    for (const OperationRow &operation : operations) {
        rows.push_back(
            {std::string(operation.label),
             operation_calls(report, "payload_fhe_evaluation",
                             operation.key),
             operation_limb_work(report, "payload_fhe_evaluation",
                                 operation.key),
             operation_calls(report, "gkr_proving", operation.key),
             operation_limb_work(report, "gkr_proving", operation.key),
             operation_calls(report, "prove", operation.key),
             operation_limb_work(report, "prove", operation.key)});
    }
    table(output,
          {"Operation", "Payload calls", "Payload limb work", "GKR calls",
           "GKR limb work", "Complete proving calls",
           "Complete proving limb work"},
          rows);
}

void render_proof(std::ostream &output, const Report &report) {
    output << "## Proof size breakdown\n\n"
              "The transcript-packing row is a subtotal. Its three nested "
              "rows explain that subtotal and are not added a second time. "
              "The GKR commitment is separate from that subtotal.\n\n";
    table(output, {"Proof component", "Accounting", "Size"},
          {{"Complete canonical proof", "total",
            bytes_or_missing(report, "proof.total_bytes")},
           {"Statement and metadata", "additive component",
            bytes_or_missing(report, "proof.statement_and_metadata_bytes")},
           {"GKR round messages", "additive component",
            bytes_or_missing(report, "proof.round_message_bytes")},
           {"GKR terminal messages", "additive component",
            bytes_or_missing(report, "proof.terminal_message_bytes")},
           {"Partial Gate-MLE values", "additive component",
            bytes_or_missing(report, "proof.partial_gate_mle_bytes")},
           {"Gate-MLE opening", "additive component",
            bytes_or_missing(report, "proof.gate_mle_opening_bytes")},
           {"GKR transcript commitment", "additive component",
            bytes_or_missing(report, "proof.gkr_commitment_bytes")},
           {"Transcript-packing argument", "additive subtotal",
            bytes_or_missing(report, "proof.transcript_packing_bytes")},
           {"↳ Well-formedness reveals", "subtotal component",
            bytes_or_missing(report, "proof.well_formedness_reveal_bytes")},
           {"↳ Digit-packed ciphertexts", "subtotal component",
            bytes_or_missing(
                report, "proof.digit_packing_ciphertext_bytes")},
           {"↳ Spartan/factored/BaseFold proof", "subtotal component",
            bytes_or_missing(report, "proof.spartan_packing_proof_bytes")}});

    table(output, {"Transport fact", "Value"},
          {{"Encoded proof bytes",
            bytes_or_missing(report, "wire.canonical_proof_bytes")},
           {"Verification boundary",
            text_or_missing(report, "wire.verification_boundary")},
           {"Verifier setup",
            text_or_missing(report, "classification.verifier_setup")},
           {"Logical GKR messages",
            integer_or_missing(report, "proof.logical_messages")},
           {"Serialized base ciphertexts",
            integer_or_missing(report, "proof.base_ciphertexts")}});
}

void render_checks(std::ostream &output, const Report &report) {
    output << "## Noise, output, and reveal checks\n\n";
    table(output, {"Check", "Result"},
          {{"Overall verification",
            text_or_missing(report, "verification.result")},
           {"Transcript-packing integrity classification",
            text_or_missing(
                report, "classification.transcript_packing_integrity")},
           {"Configured well-formedness repetitions",
            integer_or_missing(
                report, "parameters.transcript_packing_repetitions")},
           {"Selected integrity-profile repetitions",
            integer_or_missing(
                report,
                "parameters.selected_transcript_packing_repetitions")},
           {"Reveal threshold result",
            text_or_missing(
                report,
                "verification.transcript_packing_threshold.result")},
           {"Reveal norm threshold",
            integer_or_missing(
                report,
                "verification.transcript_packing_threshold.configured")},
           {"Maximum observed reveal norm",
            integer_or_missing(
                report,
                "verification.transcript_packing_threshold.maximum_observed_norm")},
           {"Expected / observed / checked reveals",
            integer_or_missing(
                report,
                "verification.transcript_packing_threshold.expected_reveals") +
                " / " +
                integer_or_missing(
                    report,
                    "verification.transcript_packing_threshold.observed_reveals") +
                " / " +
                integer_or_missing(
                    report,
                    "verification.transcript_packing_threshold.checked_reveals")},
           {"Failing reveals",
            integer_or_missing(
                report,
                "verification.transcript_packing_threshold.failing_reveals")},
           {"First failing reveal",
            text_or_missing(
                report,
                "verification.transcript_packing_threshold."
                "first_failing_reveal_index")},
           {"Encrypted payload outputs",
            integer_or_missing(report,
                               "noise.payload_output_encrypted_values")},
           {"Payload outputs at q0",
            text_or_missing(report, "noise.payload_outputs_at_q0")},
           {"Payload-output error gate",
            text_or_missing(report, "noise.payload_output_error_gate")},
           {"Payload-output canonical error norm",
            quantity_or_missing(
                report, "noise.payload_output_canonical_error_norm")},
           {"Payload-output canonical error bits",
            quantity_or_missing(
                report, "noise.payload_output_canonical_error_bits")},
           {"Exclusive output-error threshold",
            integer_or_missing(
                report, "noise.payload_output_error_exclusive_threshold")},
           {"Payload-output error claim",
            text_or_missing(report, "noise.payload_output_error_claim")},
           {"Minimum measured proof noise",
            bits_at_checkpoint_or_missing(
                report, "noise.proof_minimum_measured_invariant_bits",
                "noise.proof_minimum_measured_checkpoint")},
           {"Minimum public proof-noise estimate",
            bits_at_checkpoint_or_missing(
                report, "noise.proof_minimum_public_estimate_bits",
                "noise.proof_minimum_checkpoint")},
           {"Noise measurement claim",
            text_or_missing(report, "noise.measurement_claim")}});
}

void render_provenance(std::ostream &output, const Report &report,
                       const std::filesystem::path &input_path) {
    output << "## Provenance\n\n";
    table(output, {"Field", "Value"},
          {{"Canonical report", markdown_escape(input_path.string())},
           {"Report format", text_or_missing(report, "format")},
           {"Protocol", protocol_name(report)},
           {"Result kind",
            text_or_missing(report, "classification.result_kind")},
           {"Timing validity",
            text_or_missing(report, "classification.timing_validity")},
           {"Process topology",
            text_or_missing(report, "classification.process_topology")},
           {"Transport classification",
            text_or_missing(report, "classification.transport")},
           {"Verifier setup boundary",
            text_or_missing(report, "classification.verifier_setup")},
           {"Storage classification",
            text_or_missing(report, "classification.storage")},
           {"Resource admission",
            text_or_missing(report, "classification.resource_admission")},
           {"FHE parameter security",
            text_or_missing(report,
                            "classification.fhe_parameter_security")},
           {"UTC", text_or_missing(report, "environment.date_utc")},
           {"Git commit", text_or_missing(report, "environment.git_commit")},
           {"Git dirty", text_or_missing(report, "environment.git_dirty")},
           {"Iterations completed",
            integer_or_missing(report, "benchmark.completed_iterations")},
           {"Thread count",
            integer_or_missing(report, "environment.thread_count")},
           {"Build type", text_or_missing(report, "environment.build_type")},
           {"Compiler", text_or_missing(report, "environment.compiler")},
           {"SEAL", text_or_missing(report, "environment.seal_version")},
           {"SEAL acceleration",
            text_or_missing(report, "environment.seal_acceleration")},
           {"SHA-256 acceleration",
            text_or_missing(report, "environment.sha256_acceleration")},
           {"Operating system", text_or_missing(report, "environment.os")},
           {"CPU", text_or_missing(report, "environment.cpu")}});
    output << "Exact command:\n\n    "
           << text_or_missing(report, "environment.command") << "\n";
}

std::string render(const Report &report,
                   const std::filesystem::path &input_path) {
    validate_evidence_contract(report);
    validate_proof_breakdown(report);
    const std::uint64_t operations = payload_operations(report);
    std::ostringstream output;
    output.imbue(std::locale::classic());
    render_headline(output, report, operations);
    render_timings(output, report);
    render_operation_ledger(output, report);
    render_proof(output, report);
    render_checks(output, report);
    render_provenance(output, report, input_path);
    return output.str();
}

void write_summary(const std::optional<std::filesystem::path> &path,
                   std::string_view summary,
                   const std::filesystem::path &input_path) {
    if (!path) {
        std::cout << summary;
        return;
    }
    const std::filesystem::path normalized_input =
        std::filesystem::absolute(input_path).lexically_normal();
    const std::filesystem::path normalized_output =
        std::filesystem::absolute(*path).lexically_normal();
    if (normalized_input == normalized_output) {
        throw std::invalid_argument(
            "--output must not replace the canonical input report");
    }
    std::error_code error;
    if (std::filesystem::exists(*path, error)) {
        if (error) {
            throw std::runtime_error("cannot inspect output path: " +
                                     error.message());
        }
        throw std::invalid_argument("--output must not already exist");
    }
    const std::filesystem::path parent =
        path->parent_path().empty() ? std::filesystem::path(".")
                                    : path->parent_path();
    if (!std::filesystem::is_directory(parent, error) || error) {
        throw std::invalid_argument(
            "--output parent must be an existing directory");
    }
    std::ofstream output(*path, std::ios::binary | std::ios::out);
    if (!output) {
        throw std::runtime_error("cannot create output summary");
    }
    output.write(summary.data(), static_cast<std::streamsize>(summary.size()));
    output.close();
    if (!output) {
        std::filesystem::remove(*path, error);
        throw std::runtime_error("failed to write output summary");
    }
}

} // namespace

int main(int argc, char **argv) {
    try {
        const std::optional<Options> options = parse_options(argc, argv);
        if (!options) {
            return 0;
        }
        const Report report = read_report(options->input);
        write_summary(options->output, render(report, options->input),
                      options->input);
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        print_usage(std::cerr);
        return 1;
    }
}
