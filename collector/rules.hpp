#pragma once
#include <cstdint>
#include <set>
#include <string>

struct Rules {
    std::set<std::wstring> streamSuffixes{L":Zone.Identifier"};
    std::set<std::wstring> processPaths;
    double entropyThreshold = 7.0;
    std::uint64_t sizeLimit = 16 * 1024 * 1024;
    int low = 20, medium = 40, high = 70;
    int namedWeight = 10, peWeight = 50, entropyWeight = 25, executableWeight = 20, systemHostWeight = 15;
};

Rules LoadRules(const std::wstring& path);
