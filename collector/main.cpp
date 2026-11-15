#include <Windows.h>
#include <fltuser.h>
#include <array>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <cwctype>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include "Protocol.h"
#include "rules.hpp"

struct Message { FILTER_MESSAGE_HEADER header; ADSG_EVENT event; };

static std::wstring Lower(std::wstring s) {
    for (auto& c : s) c = static_cast<wchar_t>(towlower(c));
    return s;
}
static std::string Utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(n > 0 ? n : 0, '\0');
    if (n > 0) { WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr); out.resize(n - 1); }
    return out;
}
static std::string Json(const std::string& s) {
    std::ostringstream o; o << '"';
    for (unsigned char c : s) {
        switch (c) { case '"': o << "\\\""; break; case '\\': o << "\\\\"; break;
        case '\n': o << "\\n"; break; case '\r': o << "\\r"; break; case '\t': o << "\\t"; break;
        default: if (c < 0x20) o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c) << std::dec << std::setfill(' '); else o << c; }
    }
    o << '"'; return o.str();
}
static std::wstring DeviceToDos(std::wstring path) {
    wchar_t drives[512]{}; GetLogicalDriveStringsW(512, drives);
    for (const wchar_t* d = drives; *d; d += wcslen(d) + 1) {
        wchar_t name[3] = {d[0], L':', 0}; wchar_t target[1024]{};
        if (QueryDosDeviceW(name, target, 1024) && path.rfind(target, 0) == 0)
            return std::wstring(d, 2) + path.substr(wcslen(target));
    }
    return path;
}
static std::wstring ProcessPath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"";
    std::vector<wchar_t> buf(32768); DWORD n = static_cast<DWORD>(buf.size());
    std::wstring out; if (QueryFullProcessImageNameW(h, 0, buf.data(), &n)) out.assign(buf.data(), n);
    CloseHandle(h); return out;
}
struct Content {
    double entropy = 0;
    bool entropyKnown = false;
    bool pe = false;
    bool peKnown = false;
    std::uint64_t bytes = 0;
    DWORD error = ERROR_SUCCESS;
    std::string status = "unavailable";
};
static Content Inspect(const std::wstring& path, std::uint64_t limit, std::uint64_t expectedSize) {
    Content c; HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { c.error = GetLastError(); return c; }
    std::array<unsigned long long, 256> counts{};
    std::array<unsigned char, 65536> b{}; DWORD n = 0; std::vector<unsigned char> prefix;
    bool readFailed = false;
    while (c.bytes < limit) {
        if (!ReadFile(h, b.data(), static_cast<DWORD>(std::min<std::uint64_t>(b.size(), limit-c.bytes)), &n, nullptr)) {
            c.error = GetLastError(); readFailed = true; break;
        }
        if (!n) break;
        if (prefix.size() < 4096) {
            auto take = std::min<std::size_t>(n, 4096 - prefix.size());
            prefix.insert(prefix.end(), b.begin(), b.begin() + take);
        }
        for (DWORD i=0;i<n;++i) ++counts[b[i]];
        c.bytes += n;
    }
    CloseHandle(h);
    if (c.bytes >= expectedSize) c.status = "complete";
    else if (c.bytes >= limit) c.status = "size_limit";
    else if (readFailed && c.bytes) c.status = "partial";
    else if (readFailed) c.status = "unavailable";
    else c.status = "partial";
    if (c.bytes) c.entropyKnown = true;
    if (prefix.size() >= 64 && prefix[0] == 'M' && prefix[1] == 'Z') {
        std::uint32_t peOffset = 0;
        std::memcpy(&peOffset, prefix.data() + 0x3c, sizeof(peOffset));
        if (peOffset <= prefix.size() - 4) {
            c.peKnown = true;
            c.pe = prefix[peOffset] == 'P' && prefix[peOffset+1] == 'E' &&
                   prefix[peOffset+2] == 0 && prefix[peOffset+3] == 0;
        }
    } else if (prefix.size() >= 64 || c.bytes >= expectedSize) {
        c.peKnown = true;
    }
    if (c.bytes) for (auto count : counts) if (count) { double p = double(count)/double(c.bytes); c.entropy -= p * std::log2(p); }
    return c;
}
static std::string Timestamp(std::uint64_t t) {
    FILETIME ft{static_cast<DWORD>(t), static_cast<DWORD>(t >> 32)}; SYSTEMTIME st{};
    FileTimeToSystemTime(&ft, &st); char b[40];
    sprintf_s(b, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond,st.wMilliseconds);
    return b;
}
static void Emit(const ADSG_EVENT& e, const Rules& rules, std::ofstream& out) {
    // Content inspection opens the same ADS. Discard our own open notifications
    // before inspecting them to prevent recursive self-observation.
    if (e.ProcessId == GetCurrentProcessId()) return;
    std::wstring stream(e.StreamName), file(e.FileName), proc = ProcessPath(e.ProcessId);
    std::wstring lowerStream = Lower(stream), lowerProc = Lower(proc);
    auto dataType = lowerStream.rfind(L":$data");
    if (dataType != lowerStream.npos) lowerStream.resize(dataType);
    bool allow = false;
    for (auto& suffix : rules.streamSuffixes) if (lowerStream.size() >= suffix.size() && lowerStream.substr(lowerStream.size()-suffix.size()) == suffix) allow = true;
    if (rules.processPaths.count(lowerProc)) allow = true;
    auto dosStream = DeviceToDos(stream);
    Content content{};
    if (e.Flags & ADSG_FLAG_SIZE_UNAVAILABLE) {
        content.status = "size_unavailable";
    } else {
        content = Inspect(dosStream, rules.sizeLimit, e.StreamSize);
    }
    std::vector<std::string> reasons; int score = 0;
    if (proc.empty()) reasons.emplace_back("process_metadata_unavailable");
    if (!allow) { score += rules.namedWeight; reasons.emplace_back("non_default_named_stream"); }
    if (!content.entropyKnown) reasons.emplace_back("content_unavailable");
    else if (content.status != "complete") reasons.emplace_back("content_inspection_partial");
    if (content.peKnown && content.pe) { score += rules.peWeight; reasons.emplace_back("pe_header"); }
    if (content.entropyKnown && content.entropy >= rules.entropyThreshold && e.StreamSize > 0) { score += rules.entropyWeight; reasons.emplace_back("high_entropy"); }
    auto colon = lowerStream.rfind(L':'); auto suffix = colon == lowerStream.npos ? L"" : lowerStream.substr(colon);
    if (suffix.find(L".exe") != suffix.npos || suffix.find(L".dll") != suffix.npos || suffix.find(L".scr") != suffix.npos) {
        score += rules.executableWeight; reasons.emplace_back("executable_extension");
    }
    auto lowerFile = Lower(DeviceToDos(file));
    if (lowerFile.find(L"\\windows\\system32\\") != lowerFile.npos && score > 0) { score += rules.systemHostWeight; reasons.emplace_back("system_binary_host"); }
    if (allow) { score = 0; reasons.clear(); reasons.emplace_back("allowlisted_suppressed"); }
    const char* severity = score >= rules.high ? "high" : score >= rules.medium ? "medium" : score >= rules.low ? "low" : "informational";
    std::ostringstream json;
    json << "{\"schema_version\":1,\"timestamp\":" << Json(Timestamp(e.Timestamp100ns))
         << ",\"operation\":" << Json(e.Operation == AdsGuardWrite ? "write" : e.Operation == AdsGuardOpen ? "open" : "create")
         << ",\"process_id\":" << e.ProcessId << ",\"process\":" << Json(Utf8(proc))
         << ",\"process_available\":" << (!proc.empty() ? "true" : "false")
         << ",\"file\":" << Json(Utf8(DeviceToDos(file))) << ",\"stream\":" << Json(Utf8(dosStream))
         << ",\"size\":" << ((e.Flags & ADSG_FLAG_SIZE_UNAVAILABLE) ? "null" : std::to_string(e.StreamSize))
         << ",\"size_query_status\":" << e.SizeQueryStatus << ",\"inspection_status\":" << Json(content.status)
         << ",\"inspection_bytes\":" << content.bytes << ",\"inspection_error\":" << content.error
         << ",\"entropy\":" << (content.entropyKnown ? std::to_string(content.entropy) : "null")
         << ",\"pe_header\":" << (content.peKnown ? (content.pe ? "true" : "false") : "null")
         << ",\"path_truncated\":" << ((e.Flags & ADSG_FLAG_PATH_TRUNCATED) ? "true" : "false")
         << ",\"allowlisted\":" << (allow ? "true" : "false") << ",\"score\":" << score
         << ",\"severity\":" << Json(severity) << ",\"reasons\":[";
    for (size_t i=0;i<reasons.size();++i) { if (i) json << ','; json << Json(reasons[i]); }
    json << "]}"; out << json.str() << std::endl;
    if (!out) throw std::runtime_error("Telemetry output write failed");
}
int wmain(int argc, wchar_t** argv) {
    std::wstring config = L"config\\rules.json", output = L"events.jsonl";
    bool checkConfig = false;
    try {
        for (int i=1;i<argc;++i) {
            if (wcscmp(argv[i],L"--help")==0) {
                std::wcout << L"Usage: ads-guard-collector.exe [--config rules.json] [--output events.jsonl] [--check-config]\n"; return 0;
            }
            if (wcscmp(argv[i],L"--check-config")==0) { checkConfig=true; continue; }
            if (i + 1 >= argc) throw std::runtime_error("Missing command-line option value");
            if (wcscmp(argv[i],L"--config")==0) config=argv[++i];
            else if (wcscmp(argv[i],L"--output")==0) output=argv[++i];
            else throw std::runtime_error("Unknown command-line option");
        }
        Rules rules = LoadRules(config);
        if (checkConfig) { std::wcout << L"Rules configuration is valid.\n"; return 0; }
        std::ofstream out(std::filesystem::path(output), std::ios::app);
        if (!out) throw std::runtime_error("Cannot open telemetry output file");
        HANDLE port = INVALID_HANDLE_VALUE;
        HRESULT hr;
        while ((hr = FilterConnectCommunicationPort(ADSG_PORT_NAME, 0, nullptr, 0, nullptr, &port)) != S_OK) {
            std::wcerr << L"Waiting for AdsGuard minifilter port (" << std::hex << hr << L")\n"; Sleep(2000);
        }
        std::wcout << L"Connected. Writing JSONL to " << output << L"\n";
        for (;;) {
            Message m{}; OVERLAPPED ov{}; ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!ov.hEvent) { std::wcerr << L"CreateEvent failed: " << GetLastError() << L"\n"; break; }
            hr = FilterGetMessage(port, &m.header, sizeof(m), &ov);
            DWORD transferred = 0;
            if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                if (WaitForSingleObject(ov.hEvent, INFINITE) != WAIT_OBJECT_0) {
                    CancelIoEx(port, &ov); WaitForSingleObject(ov.hEvent, INFINITE);
                    CloseHandle(ov.hEvent); break;
                }
                if (!GetOverlappedResult(port, &ov, &transferred, FALSE)) {
                    DWORD err=GetLastError(); CloseHandle(ov.hEvent);
                    if (err==ERROR_OPERATION_ABORTED || err==ERROR_INVALID_HANDLE) break;
                    continue;
                }
            } else if (FAILED(hr)) { CloseHandle(ov.hEvent); break; }
            else transferred = sizeof(m);
            CloseHandle(ov.hEvent);
            if (transferred < sizeof(m.header) + sizeof(m.event)) continue;
            try { if (m.event.Version == ADSG_PROTOCOL_VERSION && m.event.Size == sizeof(ADSG_EVENT)) Emit(m.event, rules, out); }
            catch (const std::exception& ex) { std::cerr << "Collector processing error: " << ex.what() << "\n"; }
        }
        CloseHandle(port);
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Configuration or startup error: " << ex.what() << "\n";
        return 2;
    }
}
