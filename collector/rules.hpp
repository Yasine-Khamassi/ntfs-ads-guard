#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Detection settings loaded from config/rules.json. Every field is required
// in the file; the defaults here only document typical values.
struct Rules {
    // Exact stream names (no colon, no ":$DATA"), compared case-insensitively.
    std::vector<std::wstring> allowStreamNames{L"Zone.Identifier"};
    // Exact process image paths in DOS form, compared case-insensitively.
    std::vector<std::wstring> allowProcessPaths;
    // Stream name endings that look executable, e.g. ".exe".
    std::vector<std::wstring> executableExtensions{L".exe", L".dll", L".scr"};
    // Host file path prefixes that are unusual places for named streams.
    std::vector<std::wstring> systemHostPrefixes{L"C:\\Windows\\"};
    double entropyThreshold = 7.0;
    std::uint64_t entropyMinBytes = 512;
    std::uint64_t sizeLimit = 16 * 1024 * 1024;
    std::size_t queueCapacity = 1024;
    int low = 20, medium = 40, high = 70;
    int namedWeight = 10, peWeight = 50, entropyWeight = 25, executableWeight = 20, systemHostWeight = 15;
};

Rules LoadRules(const std::wstring& path);
