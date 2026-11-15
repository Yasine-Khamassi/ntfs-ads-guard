#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include "analysis.hpp"

namespace {
bool OrdinalEqualNoCase(const wchar_t* a, std::size_t an, const wchar_t* b, std::size_t bn) {
    if (an != bn) return false;
    if (an == 0) return true;
    // CompareStringOrdinal with IgnoreCase uses the operating system's
    // uppercase table, which matches how NTFS compares names.
    return CompareStringOrdinal(a, static_cast<int>(an), b, static_cast<int>(bn), TRUE) == CSTR_EQUAL;
}
}

bool EqualsNoCase(std::wstring_view a, std::wstring_view b) {
    return OrdinalEqualNoCase(a.data(), a.size(), b.data(), b.size());
}
bool StartsWithNoCase(std::wstring_view s, std::wstring_view prefix) {
    return s.size() >= prefix.size() && OrdinalEqualNoCase(s.data(), prefix.size(), prefix.data(), prefix.size());
}
bool EndsWithNoCase(std::wstring_view s, std::wstring_view suffix) {
    return s.size() >= suffix.size() &&
           OrdinalEqualNoCase(s.data() + (s.size() - suffix.size()), suffix.size(), suffix.data(), suffix.size());
}

std::wstring StreamNameFromComponent(std::wstring_view component) {
    if (component.empty() || component.front() != L':') return {};
    component.remove_prefix(1);
    auto colon = component.find(L':');
    if (colon != std::wstring_view::npos) component = component.substr(0, colon);
    return std::wstring(component);
}

std::wstring StreamComponent(std::wstring_view streamPath, std::wstring_view filePath) {
    if (!filePath.empty() && streamPath.size() > filePath.size() &&
        streamPath.compare(0, filePath.size(), filePath) == 0 && streamPath[filePath.size()] == L':')
        return std::wstring(streamPath.substr(filePath.size()));
    auto slash = streamPath.find_last_of(L'\\');
    auto colon = streamPath.find(L':', slash == std::wstring_view::npos ? 0 : slash + 1);
    if (colon == std::wstring_view::npos) return {};
    return std::wstring(streamPath.substr(colon));
}

std::wstring MapDevicePath(std::wstring_view path,
                           const std::vector<std::pair<std::wstring, std::wstring>>& devices) {
    for (const auto& [device, drive] : devices) {
        if (device.empty() || path.size() < device.size()) continue;
        if (!EqualsNoCase(path.substr(0, device.size()), device)) continue;
        if (path.size() > device.size() && path[device.size()] != L'\\') continue;
        return drive + std::wstring(path.substr(device.size()));
    }
    return std::wstring(path);
}

PeResult DetectPe(const std::vector<unsigned char>& prefix, bool wholeStream) {
    if (prefix.size() < 2) return wholeStream ? PeResult::NotPe : PeResult::Unknown;
    if (prefix[0] != 'M' || prefix[1] != 'Z') return PeResult::NotPe;
    if (prefix.size() < 0x40) return wholeStream ? PeResult::NotPe : PeResult::Unknown;
    std::uint32_t lfanew = 0;
    std::memcpy(&lfanew, prefix.data() + 0x3c, sizeof(lfanew));
    // 64-bit arithmetic: e_lfanew is attacker controlled and may be near 4 GiB.
    const std::uint64_t end = static_cast<std::uint64_t>(lfanew) + 4;
    if (end > prefix.size()) return wholeStream ? PeResult::NotPe : PeResult::Unknown;
    return prefix[lfanew] == 'P' && prefix[lfanew + 1] == 'E' && prefix[lfanew + 2] == 0 && prefix[lfanew + 3] == 0
        ? PeResult::Pe : PeResult::NotPe;
}

ContentAccumulator::ContentAccumulator() {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) return;
    alg_ = alg;
    DWORD objectLength = 0, got = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength),
                                          sizeof(objectLength), &got, 0)))
        return;
    hashObject_.resize(objectLength);
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, hashObject_.data(), objectLength, nullptr, 0, 0))) hash_ = hash;
}

ContentAccumulator::~ContentAccumulator() {
    if (hash_) BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hash_));
    if (alg_) BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(alg_), 0);
}

void ContentAccumulator::Add(const unsigned char* data, std::size_t size) {
    for (std::size_t i = 0; i < size; ++i) ++counts_[data[i]];
    if (prefix_.size() < kPrefixLimit) {
        auto take = (std::min)(size, kPrefixLimit - prefix_.size());
        prefix_.insert(prefix_.end(), data, data + take);
    }
    if (hash_ && size) {
        if (!BCRYPT_SUCCESS(BCryptHashData(static_cast<BCRYPT_HASH_HANDLE>(hash_), const_cast<PUCHAR>(data),
                                           static_cast<ULONG>(size), 0))) {
            BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hash_));
            hash_ = nullptr;
        }
    }
    bytes_ += size;
}

std::optional<double> ContentAccumulator::Entropy(std::uint64_t minBytes) const {
    if (bytes_ == 0 || bytes_ < minBytes) return std::nullopt;
    double entropy = 0;
    for (auto count : counts_) {
        if (!count) continue;
        double p = static_cast<double>(count) / static_cast<double>(bytes_);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

std::optional<std::string> ContentAccumulator::FinishSha256() {
    if (!hash_) return std::nullopt;
    unsigned char digest[32];
    auto status = BCryptFinishHash(static_cast<BCRYPT_HASH_HANDLE>(hash_), digest, sizeof(digest), 0);
    BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hash_));
    hash_ = nullptr;
    if (!BCRYPT_SUCCESS(status)) return std::nullopt;
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (unsigned char b : digest) { out.push_back(hex[b >> 4]); out.push_back(hex[b & 15]); }
    return out;
}

Findings Score(const ScoreInput& in, const Rules& rules) {
    Findings f;
    bool streamAllowed = false, processAllowed = false;
    for (const auto& name : rules.allowStreamNames)
        if (EqualsNoCase(in.streamName, name)) streamAllowed = true;
    if (!in.processDosPath.empty())
        for (const auto& path : rules.allowProcessPaths)
            if (EqualsNoCase(in.processDosPath, path)) processAllowed = true;
    f.allowlisted = streamAllowed || processAllowed;
    if (streamAllowed) f.reasons.emplace_back("allowlisted_stream_name");
    if (processAllowed) f.reasons.emplace_back("allowlisted_process");

    if (!f.allowlisted) {
        f.score += rules.namedWeight;
        f.reasons.emplace_back("non_default_named_stream");
        for (const auto& ext : rules.executableExtensions) {
            if (EndsWithNoCase(in.streamName, ext)) {
                f.score += rules.executableWeight;
                f.reasons.emplace_back("executable_extension");
                break;
            }
        }
        for (const auto& prefix : rules.systemHostPrefixes) {
            if (StartsWithNoCase(in.hostDosPath, prefix)) {
                f.score += rules.systemHostWeight;
                f.reasons.emplace_back("system_binary_host");
                break;
            }
        }
    }
    if (in.pe == PeResult::Pe) { f.score += rules.peWeight; f.reasons.emplace_back("pe_header"); }
    if (in.entropy && *in.entropy >= rules.entropyThreshold) {
        f.score += rules.entropyWeight;
        f.reasons.emplace_back("high_entropy");
    }
    if (!in.contentAvailable) f.reasons.emplace_back("content_unavailable");
    else if (!in.contentComplete) f.reasons.emplace_back("content_inspection_partial");
    if (in.processApplicable && !in.processAvailable) f.reasons.emplace_back("process_metadata_unavailable");

    f.severity = f.score >= rules.high ? "high" : f.score >= rules.medium ? "medium"
               : f.score >= rules.low ? "low" : "informational";
    return f;
}
