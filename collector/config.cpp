#include <Windows.h>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <stdexcept>
#include "json_value.hpp"
#include "rules.hpp"

namespace {
std::wstring Wide(const std::string& value) {
    if (value.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (!n) throw std::runtime_error("Config contains invalid UTF-8");
    std::wstring out(n, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), out.data(), n))
        throw std::runtime_error("Config contains invalid UTF-8");
    return out;
}
const JsonValue& Member(const JsonValue::Object& o, const char* key) {
    auto it = o.find(key);
    if (it == o.end()) throw std::runtime_error(std::string("Missing config property: ") + key);
    return it->second;
}
double Number(const JsonValue& v, const char* name, double low, double high) {
    if (!v.isNumber() || v.number() < low || v.number() > high)
        throw std::runtime_error(std::string("Invalid numeric config property: ") + name);
    return v.number();
}
long long Integer(const JsonValue& v, const char* name, long long low, long long high) {
    double n = Number(v, name, static_cast<double>(low), static_cast<double>(high));
    if (std::floor(n) != n) throw std::runtime_error(std::string("Expected integer config property: ") + name);
    return static_cast<long long>(n);
}
// Values are kept as written. Matching is case-insensitive at compare time.
std::vector<std::wstring> StringList(const JsonValue& value, const char* name, const wchar_t* forbidden = L"") {
    if (!value.isArray()) throw std::runtime_error(std::string("Expected array: ") + name);
    std::vector<std::wstring> out;
    for (const auto& item : value.array()) {
        if (!item.isString() || item.string().empty())
            throw std::runtime_error(std::string("Expected non-empty strings in: ") + name);
        auto text = Wide(item.string());
        if (text.find_first_of(forbidden) != std::wstring::npos)
            throw std::runtime_error(std::string("Invalid character in: ") + name);
        out.push_back(std::move(text));
    }
    return out;
}
const JsonValue::Object& Object(const JsonValue& value, const char* name) {
    if (!value.isObject()) throw std::runtime_error(std::string("Expected object: ") + name);
    return value.object();
}
void CheckKeys(const JsonValue::Object& o, std::initializer_list<const char*> valid, const char* name) {
    for (const auto& p : o) {
        bool found = false;
        for (auto k : valid) if (p.first == k) found = true;
        if (!found) throw std::runtime_error(std::string("Unknown ") + name + " property: " + p.first);
    }
}
}

Rules LoadRules(const std::wstring& path) {
    std::ifstream f(std::filesystem::path(path), std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open rules configuration");
    std::string text((std::istreambuf_iterator<char>(f)), {});
    if (text.size() > 1024 * 1024) throw std::runtime_error("Rules configuration exceeds 1 MiB");
    if (text.size() >= 3 && text.compare(0, 3, "\xEF\xBB\xBF") == 0) text.erase(0, 3);
    int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!text.empty() && !chars) throw std::runtime_error("Rules configuration is not valid UTF-8");
    JsonValue root = JsonParser(text).parse();
    const auto& o = Object(root, "root");
    CheckKeys(o, {"allow_stream_names", "allow_process_paths", "executable_extensions", "system_host_prefixes",
                  "entropy_threshold", "entropy_min_bytes", "stream_size_limit_bytes", "queue_capacity",
                  "parent_hash_max_bytes",
                  "thresholds", "weights"}, "root");
    Rules r;
    // Stream names are the bare name, e.g. "Zone.Identifier": no colon, no path.
    r.allowStreamNames = StringList(Member(o, "allow_stream_names"), "allow_stream_names", L":\\/");
    r.allowProcessPaths = StringList(Member(o, "allow_process_paths"), "allow_process_paths");
    r.executableExtensions = StringList(Member(o, "executable_extensions"), "executable_extensions", L":\\/");
    for (const auto& ext : r.executableExtensions)
        if (ext.front() != L'.') throw std::runtime_error("executable_extensions entries must start with '.'");
    r.systemHostPrefixes = StringList(Member(o, "system_host_prefixes"), "system_host_prefixes");
    r.entropyThreshold = Number(Member(o, "entropy_threshold"), "entropy_threshold", 0.0, 8.0);
    r.entropyMinBytes = static_cast<std::uint64_t>(Integer(Member(o, "entropy_min_bytes"), "entropy_min_bytes", 1, 1024LL * 1024 * 1024));
    r.sizeLimit = static_cast<std::uint64_t>(Integer(Member(o, "stream_size_limit_bytes"), "stream_size_limit_bytes", 1, 1024LL * 1024 * 1024));
    r.parentHashLimit = static_cast<std::uint64_t>(Integer(Member(o, "parent_hash_max_bytes"), "parent_hash_max_bytes", 0, 1024LL * 1024 * 1024));
    r.queueCapacity = static_cast<std::size_t>(Integer(Member(o, "queue_capacity"), "queue_capacity", 1, 65536));
    const auto& thresholds = Object(Member(o, "thresholds"), "thresholds");
    CheckKeys(thresholds, {"low", "medium", "high"}, "thresholds");
    r.low = static_cast<int>(Integer(Member(thresholds, "low"), "thresholds.low", 0, 10000));
    r.medium = static_cast<int>(Integer(Member(thresholds, "medium"), "thresholds.medium", 0, 10000));
    r.high = static_cast<int>(Integer(Member(thresholds, "high"), "thresholds.high", 0, 10000));
    if (!(r.low <= r.medium && r.medium <= r.high))
        throw std::runtime_error("Severity thresholds must be ordered low <= medium <= high");
    const auto& weights = Object(Member(o, "weights"), "weights");
    CheckKeys(weights, {"named_stream", "pe_header", "high_entropy", "executable_extension", "system_binary_host"}, "weights");
    r.namedWeight = static_cast<int>(Integer(Member(weights, "named_stream"), "weights.named_stream", 0, 1000));
    r.peWeight = static_cast<int>(Integer(Member(weights, "pe_header"), "weights.pe_header", 0, 1000));
    r.entropyWeight = static_cast<int>(Integer(Member(weights, "high_entropy"), "weights.high_entropy", 0, 1000));
    r.executableWeight = static_cast<int>(Integer(Member(weights, "executable_extension"), "weights.executable_extension", 0, 1000));
    r.systemHostWeight = static_cast<int>(Integer(Member(weights, "system_binary_host"), "weights.system_binary_host", 0, 1000));
    return r;
}
