#pragma once
// Pure analysis helpers shared by the collector and the unit tests.
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "rules.hpp"

bool EqualsNoCase(std::wstring_view a, std::wstring_view b);
bool StartsWithNoCase(std::wstring_view s, std::wstring_view prefix);
bool EndsWithNoCase(std::wstring_view s, std::wstring_view suffix);

// Returns the stream name from a stream component such as ":name:$DATA" or
// ":name". Returns an empty string for the default stream ("::$DATA").
std::wstring StreamNameFromComponent(std::wstring_view component);

// Splits a full stream path into the stream component. When the host file
// path is known and is a prefix, it is used; otherwise the first colon after
// the last backslash starts the component.
std::wstring StreamComponent(std::wstring_view streamPath, std::wstring_view filePath);

// Maps an NT device path to a DOS path using (device, drive) pairs such as
// (L"\\Device\\HarddiskVolume3", L"C:"). Requires a path separator or the end
// of the string after the device so that Volume1 does not match Volume10.
std::wstring MapDevicePath(std::wstring_view path,
                           const std::vector<std::pair<std::wstring, std::wstring>>& devices);

enum class PeResult { Pe, NotPe, Unknown };

// Checks for an MZ header with an in-bounds e_lfanew that points at "PE\0\0".
// prefix holds the first bytes of the stream; wholeStream says whether the
// prefix is the entire stream. Unknown means the bytes needed were not read.
PeResult DetectPe(const std::vector<unsigned char>& prefix, bool wholeStream);

// Incremental byte statistics and SHA-256.
class ContentAccumulator {
public:
    static constexpr std::size_t kPrefixLimit = 64 * 1024;
    ContentAccumulator();
    ~ContentAccumulator();
    ContentAccumulator(const ContentAccumulator&) = delete;
    ContentAccumulator& operator=(const ContentAccumulator&) = delete;
    void Add(const unsigned char* data, std::size_t size);
    std::uint64_t Bytes() const { return bytes_; }
    const std::vector<unsigned char>& Prefix() const { return prefix_; }
    // Shannon entropy in bits per byte, or nullopt below minBytes.
    std::optional<double> Entropy(std::uint64_t minBytes) const;
    // Hex SHA-256 of everything added, or nullopt if hashing is unavailable.
    std::optional<std::string> FinishSha256();
    bool HashAvailable() const { return hash_ != nullptr; }
private:
    std::array<std::uint64_t, 256> counts_{};
    std::vector<unsigned char> prefix_;
    std::uint64_t bytes_ = 0;
    void* alg_ = nullptr;
    void* hash_ = nullptr;
    std::vector<unsigned char> hashObject_;
};

struct Findings {
    bool allowlisted = false;
    int score = 0;
    std::string severity;
    std::vector<std::string> reasons;
};

struct ScoreInput {
    std::wstring streamName;     // without colons
    std::wstring hostDosPath;    // host file in DOS form
    std::wstring processDosPath; // empty if unknown
    std::optional<double> entropy;
    PeResult pe = PeResult::Unknown;
    bool contentComplete = false;
    bool contentAvailable = false;
    bool processAvailable = false;
    bool processApplicable = true; // false for --scan, where no process is involved
};

// Allow-lists remove the name-based weights (named stream, executable
// extension, system host). Content findings (PE header, high entropy)
// always add score, so an allow-listed name cannot hide a payload.
Findings Score(const ScoreInput& in, const Rules& rules);
