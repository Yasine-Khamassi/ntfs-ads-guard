// ads-guard-collector: receives events from AdsGuard.sys, inspects the named
// stream, scores it, and writes one JSON object per line.
//
// Threads: a reader pulls messages off the Filter Manager port as fast as it
// can into a bounded queue; a worker inspects and writes records. When the
// queue is full the message is dropped and counted, and the count is written
// as an events_lost record. Every record is written by a mutex-protected sink.

#include <Windows.h>
#include <fltuser.h>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>
#include "Protocol.h"
#include "analysis.hpp"
#include "rules.hpp"

namespace {

constexpr int kSchemaVersion = 3;

struct Message {
    FILTER_MESSAGE_HEADER header;
    ADSG_EVENT event;
};

HANDLE gStop = nullptr;

BOOL WINAPI OnConsoleCtrl(DWORD) {
    if (gStop) SetEvent(gStop);
    return TRUE;
}

// ---- formatting ------------------------------------------------------------

std::string Utf8(std::wstring_view s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::string Json(std::string_view s) {
    std::string o;
    o.reserve(s.size() + 2);
    o.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (c < 0x20) {
                char b[8];
                std::snprintf(b, sizeof(b), "\\u%04x", c);
                o += b;
            } else {
                o.push_back(static_cast<char>(c));
            }
        }
    }
    o.push_back('"');
    return o;
}
std::string JsonW(std::wstring_view s) { return Json(Utf8(s)); }
std::string JsonOrNull(const std::optional<std::string>& s) { return s ? Json(*s) : "null"; }
template <typename T> std::string NumOrNull(const std::optional<T>& v) { return v ? std::to_string(*v) : "null"; }
std::string Hex32(ULONG v) {
    char b[16];
    std::snprintf(b, sizeof(b), "\"0x%08lX\"", v);
    return b;
}

std::uint64_t NowFileTime() {
    FILETIME ft{};
    GetSystemTimePreciseAsFileTime(&ft);
    return (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

// ISO 8601 UTC with 100 ns precision, or null for 0 / unconvertible values.
std::string TimeJson(std::uint64_t t) {
    if (t == 0) return "null";
    FILETIME ft{static_cast<DWORD>(t), static_cast<DWORD>(t >> 32)};
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) return "null";
    char b[48];
    std::snprintf(b, sizeof(b), "\"%04u-%02u-%02uT%02u:%02u:%02u.%07lluZ\"", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, static_cast<unsigned long long>(t % 10000000ULL));
    return b;
}

// Milliseconds from an earlier to a later FILETIME, or null if either is
// missing or they are out of order.
std::string MillisJson(std::uint64_t from, std::uint64_t to) {
    if (from == 0 || to == 0 || to < from) return "null";
    char b[32];
    std::snprintf(b, sizeof(b), "%.3f", static_cast<double>(to - from) / 10000.0);
    return b;
}

std::wstring Bounded(const WCHAR* s, std::size_t capacity) { return std::wstring(s, wcsnlen(s, capacity)); }

// ---- output ----------------------------------------------------------------

class Sink {
public:
    explicit Sink(const std::wstring& path) {
        if (path == L"-") return;
        file_.open(std::filesystem::path(path), std::ios::app | std::ios::binary);
        if (!file_) throw std::runtime_error("Cannot open telemetry output file");
    }
    void Write(const std::string& line) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostream& out = file_.is_open() ? static_cast<std::ostream&>(file_) : std::cout;
        out << line << '\n';
        out.flush();
        if (!out) throw std::runtime_error("Telemetry output write failed");
    }
private:
    std::ofstream file_;
    std::mutex mutex_;
};

std::string RecordHeader(const char* type) {
    return std::string("{\"record_type\":") + Json(type) + ",\"schema_version\":" + std::to_string(kSchemaVersion) +
           ",\"collected_at\":" + TimeJson(NowFileTime());
}

void WriteLost(Sink& sink, const char* source, std::uint64_t count) {
    sink.Write(RecordHeader("events_lost") + ",\"source\":" + Json(source) + ",\"count\":" + std::to_string(count) + "}");
}

void WriteError(Sink& sink, const char* error, const std::string& detail) {
    std::cerr << "collector: " << error << ": " << detail << "\n";
    try {
        sink.Write(RecordHeader("collector_error") + ",\"error\":" + Json(error) + ",\"detail\":" + Json(detail) + "}");
    } catch (const std::exception& ex) {
        std::cerr << "collector: cannot record error: " << ex.what() << "\n";
    }
}

// ---- path mapping ----------------------------------------------------------

const std::vector<std::pair<std::wstring, std::wstring>>& Devices() {
    static std::vector<std::pair<std::wstring, std::wstring>> map;
    static ULONGLONG built = 0;
    if (map.empty() || GetTickCount64() - built > 30000) {
        map.clear();
        wchar_t drives[512]{};
        DWORD n = GetLogicalDriveStringsW(511, drives);
        for (const wchar_t* d = drives; n && *d; d += wcslen(d) + 1) {
            wchar_t name[3] = {d[0], L':', 0};
            wchar_t target[1024]{};
            if (QueryDosDeviceW(name, target, 1024)) map.emplace_back(target, name);
        }
        built = GetTickCount64();
    }
    return map;
}
std::wstring ToDos(std::wstring_view nt) { return MapDevicePath(nt, Devices()); }

// ---- content inspection ----------------------------------------------------

struct Inspection {
    std::string status = "skipped"; // complete | size_limit | partial | unavailable | skipped_*
    DWORD error = 0;
    std::uint64_t bytes = 0;
    std::optional<double> entropy;
    PeResult pe = PeResult::Unknown;
    std::optional<std::string> sha256;
    std::string hashStatus = "skipped";
};

Inspection Inspect(const std::wstring& openPath, const Rules& rules) {
    Inspection r;
    HANDLE h = INVALID_HANDLE_VALUE;
    // The writer may still hold the handle for a moment after the cleanup
    // event; retry briefly on sharing violations.
    for (int attempt = 0; attempt < 5; ++attempt) {
        h = CreateFileW(openPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        r.error = GetLastError();
        if (r.error != ERROR_SHARING_VIOLATION) break;
        Sleep(20);
    }
    if (h == INVALID_HANDLE_VALUE) {
        r.status = "unavailable";
        r.hashStatus = "unavailable";
        return r;
    }
    r.error = ERROR_SUCCESS;
    ContentAccumulator acc;
    std::vector<unsigned char> buf(64 * 1024);
    bool eof = false, failed = false;
    while (acc.Bytes() < rules.sizeLimit) {
        DWORD want = static_cast<DWORD>((std::min<std::uint64_t>)(buf.size(), rules.sizeLimit - acc.Bytes()));
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), want, &got, nullptr)) { r.error = GetLastError(); failed = true; break; }
        if (got == 0) { eof = true; break; }
        acc.Add(buf.data(), got);
    }
    if (!eof && !failed) {
        // Exactly at the limit: one more read tells whether anything is left.
        unsigned char extra = 0;
        DWORD got = 0;
        if (ReadFile(h, &extra, 1, &got, nullptr) && got == 0) eof = true;
    }
    CloseHandle(h);

    r.bytes = acc.Bytes();
    if (eof) r.status = "complete";
    else if (failed) r.status = r.bytes ? "partial" : "unavailable";
    else r.status = "size_limit";
    r.entropy = acc.Entropy(rules.entropyMinBytes);
    r.pe = DetectPe(acc.Prefix(), eof && acc.Bytes() <= ContentAccumulator::kPrefixLimit);
    if (eof) {
        r.sha256 = acc.FinishSha256();
        r.hashStatus = r.sha256 ? "complete" : "error";
    } else {
        r.hashStatus = "skipped_incomplete";
    }
    return r;
}

// Hash of the host file's default stream, taken only for scored events.
struct ParentHash {
    std::string status = "not_scored"; // complete | not_scored | disabled | not_a_file | skipped_size_limit
                                       // | skipped_path_truncated | unavailable | error
    DWORD error = 0;
    std::optional<std::uint64_t> size;
    std::optional<std::string> sha256;
};

ParentHash HashParent(const std::wstring& openPath, std::uint64_t limit) {
    ParentHash r;
    if (limit == 0) { r.status = "disabled"; return r; }
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 5; ++attempt) {
        // Backup semantics only so that a directory host opens and can be
        // recognised; no privilege is requested.
        h = CreateFileW(openPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        r.error = GetLastError();
        if (r.error != ERROR_SHARING_VIOLATION) break;
        Sleep(20);
    }
    if (h == INVALID_HANDLE_VALUE) { r.status = "unavailable"; return r; }
    r.error = ERROR_SUCCESS;
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    if (!GetFileInformationByHandle(h, &info) || !GetFileSizeEx(h, &size)) {
        r.error = GetLastError();
        CloseHandle(h);
        r.status = "unavailable";
        return r;
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        CloseHandle(h);
        r.status = "not_a_file";
        return r;
    }
    r.size = static_cast<std::uint64_t>(size.QuadPart);
    if (*r.size > limit) {
        CloseHandle(h);
        r.status = "skipped_size_limit";
        return r;
    }
    ContentAccumulator acc;
    std::vector<unsigned char> buf(64 * 1024);
    bool eof = false;
    while (acc.Bytes() <= limit) {
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr)) { r.error = GetLastError(); break; }
        if (got == 0) { eof = true; break; }
        acc.Add(buf.data(), got);
    }
    CloseHandle(h);
    if (!eof) {
        // Either a read error or the file grew past the limit while reading.
        r.status = r.error ? "unavailable" : "skipped_size_limit";
        return r;
    }
    r.size = acc.Bytes();
    r.sha256 = acc.FinishSha256();
    r.status = r.sha256 ? "complete" : "error";
    return r;
}

// ---- event records ---------------------------------------------------------

struct EventRecord {
    const char* operation = "";
    std::uint64_t timestamp = 0;
    std::optional<ULONG> processId;
    std::uint64_t processCreateTime = 0;
    std::wstring process;
    const char* processSource = "unavailable";
    std::wstring fileDos, streamDos, streamName;
    std::optional<std::uint64_t> size, bytesWritten;
    std::optional<ULONG> sizeStatus, desiredAccess;
    std::optional<std::string> nameForm;
    std::optional<bool> writerDiffers;
    std::optional<std::string> writeSource;   // handle | paging, write events only
    std::uint64_t handleOpenTime = 0, firstWriteTime = 0, lastWriteTime = 0;
    bool reportsCleanup = false;              // handle write: timestamp is the cleanup time
    std::optional<std::string> setSizeClass;  // end_of_file | allocation, set_size only
    std::optional<std::uint64_t> requestedSize;
    bool pathTruncated = false;
    Inspection inspection;
    std::wstring parentOpenPath; // host file path to open for hashing, empty if it must not be opened
};

const char* PeJson(PeResult pe) {
    return pe == PeResult::Pe ? "true" : pe == PeResult::NotPe ? "false" : "null";
}

void WriteEvent(Sink& sink, const EventRecord& e, const Rules& rules, bool processApplicable) {
    ScoreInput in;
    in.streamName = e.streamName;
    in.hostDosPath = e.fileDos;
    in.processDosPath = e.process;
    in.entropy = e.inspection.entropy;
    in.pe = e.inspection.pe;
    in.contentComplete = e.inspection.status == "complete";
    in.contentAvailable = e.inspection.bytes > 0 || in.contentComplete;
    in.processAvailable = !e.process.empty();
    in.processApplicable = processApplicable;
    Findings f = Score(in, rules);

    ParentHash parent;
    if (f.severity != "informational") {
        if (e.parentOpenPath.empty()) parent.status = "skipped_path_truncated";
        else parent = HashParent(e.parentOpenPath, rules.parentHashLimit);
    }

    std::string entropy = "null";
    if (e.inspection.entropy) {
        char b[32];
        std::snprintf(b, sizeof(b), "%.4f", *e.inspection.entropy);
        entropy = b;
    }
    std::ostringstream j;
    j << RecordHeader("ads_event")
      << ",\"timestamp\":" << TimeJson(e.timestamp)
      << ",\"operation\":" << Json(e.operation)
      << ",\"process_id\":" << NumOrNull(e.processId)
      << ",\"process_create_time\":" << TimeJson(e.processCreateTime)
      << ",\"process\":" << (e.process.empty() ? "null" : JsonW(e.process))
      << ",\"process_source\":" << Json(e.processSource)
      << ",\"file\":" << JsonW(e.fileDos)
      << ",\"stream\":" << JsonW(e.streamDos)
      << ",\"stream_name\":" << JsonW(e.streamName)
      << ",\"desired_access\":" << (e.desiredAccess ? Hex32(*e.desiredAccess) : "null")
      << ",\"bytes_written\":" << NumOrNull(e.bytesWritten)
      << ",\"size\":" << NumOrNull(e.size)
      << ",\"size_query_status\":" << (e.sizeStatus ? Hex32(*e.sizeStatus) : "null")
      << ",\"inspection_status\":" << Json(e.inspection.status)
      << ",\"inspection_bytes\":" << e.inspection.bytes
      << ",\"inspection_error\":" << e.inspection.error
      << ",\"entropy\":" << entropy
      << ",\"pe_header\":" << PeJson(e.inspection.pe)
      << ",\"sha256\":" << JsonOrNull(e.inspection.sha256)
      << ",\"sha256_status\":" << Json(e.inspection.hashStatus)
      << ",\"path_truncated\":" << (e.pathTruncated ? "true" : "false")
      << ",\"name_form\":" << JsonOrNull(e.nameForm)
      << ",\"writer_differs\":" << (e.writerDiffers ? (*e.writerDiffers ? "true" : "false") : "null")
      << ",\"write_source\":" << JsonOrNull(e.writeSource)
      << ",\"handle_opened_at\":" << TimeJson(e.handleOpenTime)
      << ",\"first_write_at\":" << TimeJson(e.firstWriteTime)
      << ",\"last_write_at\":" << TimeJson(e.lastWriteTime)
      << ",\"handle_open_ms\":" << (e.reportsCleanup ? MillisJson(e.handleOpenTime, e.timestamp) : "null")
      << ",\"first_write_to_cleanup_ms\":" << (e.reportsCleanup ? MillisJson(e.firstWriteTime, e.timestamp) : "null")
      << ",\"set_size_class\":" << JsonOrNull(e.setSizeClass)
      << ",\"requested_size\":" << NumOrNull(e.requestedSize)
      << ",\"parent_size\":" << NumOrNull(parent.size)
      << ",\"parent_sha256\":" << JsonOrNull(parent.sha256)
      << ",\"parent_sha256_status\":" << Json(parent.status)
      << ",\"parent_error\":" << parent.error
      << ",\"allowlisted\":" << (f.allowlisted ? "true" : "false")
      << ",\"score\":" << f.score
      << ",\"severity\":" << Json(f.severity)
      << ",\"reasons\":[";
    for (std::size_t i = 0; i < f.reasons.size(); ++i) j << (i ? "," : "") << Json(f.reasons[i]);
    j << "]}";
    sink.Write(j.str());
}

const char* OperationName(ULONG op) {
    switch (op) {
    case AdsGuardOpen: return "open";
    case AdsGuardCreate: return "create";
    case AdsGuardWrite: return "write";
    case AdsGuardOverwrite: return "overwrite";
    case AdsGuardSetSize: return "set_size";
    default: return "unknown";
    }
}

std::uint64_t ProcessStartTime(HANDLE process) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

// The driver sends the image path. Fall back to a user-mode lookup only when
// it could not, and refuse the result if the PID now belongs to a process
// that started at a different time.
void ResolveProcess(const ADSG_EVENT& e, EventRecord& rec) {
    std::wstring image = Bounded(e.ProcessImage, ADSG_IMAGE_CHARS);
    if (!(e.Flags & ADSG_FLAG_IMAGE_UNAVAILABLE) && !image.empty()) {
        rec.process = ToDos(image);
        rec.processSource = (e.Flags & ADSG_FLAG_IMAGE_TRUNCATED) ? "kernel_truncated" : "kernel";
        return;
    }
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, e.ProcessId);
    if (!h) { rec.processSource = "unavailable"; return; }
    if (e.ProcessCreateTime && ProcessStartTime(h) != e.ProcessCreateTime) {
        CloseHandle(h);
        rec.processSource = "pid_reused";
        return;
    }
    std::vector<wchar_t> buf(32768);
    DWORD n = static_cast<DWORD>(buf.size());
    if (QueryFullProcessImageNameW(h, 0, buf.data(), &n)) {
        rec.process.assign(buf.data(), n);
        rec.processSource = "user_mode";
    } else {
        rec.processSource = "unavailable";
    }
    CloseHandle(h);
}

void HandleDriverEvent(const ADSG_EVENT& e, const Rules& rules, Sink& sink) {
    EventRecord rec;
    rec.operation = OperationName(e.Operation);
    rec.timestamp = e.Timestamp100ns;
    rec.processId = e.ProcessId;
    rec.processCreateTime = e.ProcessCreateTime;
    ResolveProcess(e, rec);

    std::wstring ntFile = Bounded(e.FileName, ADSG_NAME_CHARS);
    std::wstring ntStream = Bounded(e.StreamName, ADSG_NAME_CHARS);
    rec.fileDos = ToDos(ntFile);
    rec.streamDos = ToDos(ntStream);
    rec.streamName = StreamNameFromComponent(StreamComponent(ntStream, ntFile));
    rec.pathTruncated = (e.Flags & ADSG_FLAG_PATH_TRUNCATED) != 0;
    rec.nameForm = (e.Flags & ADSG_FLAG_NAME_OPENED_FORM) ? "opened" : "normalized";
    rec.desiredAccess = e.DesiredAccess;
    rec.sizeStatus = e.SizeQueryStatus;
    if (!(e.Flags & ADSG_FLAG_SIZE_UNAVAILABLE)) rec.size = e.StreamSize;
    if (e.Operation == AdsGuardWrite) {
        rec.bytesWritten = e.BytesWritten;
        rec.firstWriteTime = e.FirstWriteTime;
        rec.lastWriteTime = e.LastWriteTime;
        if (e.WriteSource == AdsGuardWritePaging) {
            rec.writeSource = "paging";
            rec.desiredAccess.reset(); // no handle is involved
        } else {
            rec.writeSource = "handle";
            rec.writerDiffers = (e.Flags & ADSG_FLAG_WRITER_DIFFERS) != 0;
            rec.handleOpenTime = e.HandleOpenTime;
            rec.reportsCleanup = true;
        }
    } else if (e.Operation == AdsGuardSetSize) {
        rec.handleOpenTime = e.HandleOpenTime;
        rec.requestedSize = e.RequestedSize;
        rec.setSizeClass = e.InfoClass == ADSG_INFO_END_OF_FILE ? "end_of_file"
                         : e.InfoClass == ADSG_INFO_ALLOCATION ? "allocation" : "unknown";
    }
    if (e.Flags & ADSG_FLAG_NAME_CACHED) rec.nameForm = "cached";

    if (rec.pathTruncated) {
        // A cut path may name a different file. Do not open it.
        rec.inspection.status = "skipped_path_truncated";
    } else {
        // Open through the NT device path so volumes without drive letters work.
        rec.inspection = Inspect(L"\\\\?\\GLOBALROOT" + ntStream, rules);
        rec.parentOpenPath = L"\\\\?\\GLOBALROOT" + ntFile;
    }
    WriteEvent(sink, rec, rules, true);
}

// ---- driver connection -----------------------------------------------------

class MessageQueue {
public:
    explicit MessageQueue(std::size_t capacity) : capacity_(capacity) {}
    void Push(std::unique_ptr<Message> m) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (items_.size() >= capacity_) { ++dropped_; return; }
            items_.push_back(std::move(m));
        }
        cv_.notify_one();
    }
    std::unique_ptr<Message> Pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [&] { return closed_ || !items_.empty(); });
        if (items_.empty()) return nullptr;
        auto m = std::move(items_.front());
        items_.pop_front();
        return m;
    }
    void Close() {
        { std::lock_guard<std::mutex> lock(mutex_); closed_ = true; }
        cv_.notify_all();
    }
    std::uint64_t TakeDropped() {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::exchange(dropped_, 0);
    }
private:
    std::size_t capacity_;
    std::deque<std::unique_ptr<Message>> items_;
    std::uint64_t dropped_ = 0;
    bool closed_ = false;
    std::mutex mutex_;
    std::condition_variable cv_;
};

void Worker(MessageQueue& queue, const Rules& rules, Sink& sink) {
    const ULONG self = GetCurrentProcessId();
    while (auto m = queue.Pop()) {
        try {
            if (auto lost = queue.TakeDropped()) WriteLost(sink, "collector_queue", lost);
            const ADSG_EVENT& e = m->event;
            if (e.Version != ADSG_PROTOCOL_VERSION || e.Size != sizeof(ADSG_EVENT)) {
                WriteError(sink, "protocol_mismatch",
                           "version " + std::to_string(e.Version) + " size " + std::to_string(e.Size) +
                           ", expected version " + std::to_string(ADSG_PROTOCOL_VERSION) + " size " +
                           std::to_string(sizeof(ADSG_EVENT)));
                continue;
            }
            if (e.DroppedEvents) WriteLost(sink, "driver", e.DroppedEvents);
            // The driver already skips this process; this is a second guard.
            if (e.ProcessId == self) continue;
            HandleDriverEvent(e, rules, sink);
        } catch (const std::exception& ex) {
            WriteError(sink, "processing_error", ex.what());
        }
    }
    if (auto lost = queue.TakeDropped()) {
        try { WriteLost(sink, "collector_queue", lost); } catch (const std::exception&) {}
    }
}

// Returns true when stopped by the user, false when the port failed.
bool ReadPort(HANDLE port, MessageQueue& queue, Sink& sink) {
    for (;;) {
        auto m = std::make_unique<Message>();
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) { WriteError(sink, "create_event_failed", std::to_string(GetLastError())); return false; }
        HRESULT hr = FilterGetMessage(port, &m->header, sizeof(Message), &ov);
        DWORD transferred = sizeof(Message);
        if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
            HANDLE waits[2] = {ov.hEvent, gStop};
            DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (w != WAIT_OBJECT_0) {
                CancelIoEx(port, &ov);
                GetOverlappedResult(port, &ov, &transferred, TRUE);
                CloseHandle(ov.hEvent);
                return w == WAIT_OBJECT_0 + 1;
            }
            if (!GetOverlappedResult(port, &ov, &transferred, FALSE)) {
                DWORD err = GetLastError();
                CloseHandle(ov.hEvent);
                WriteError(sink, "port_read_failed", "Win32 error " + std::to_string(err));
                if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_MORE_DATA) continue; // larger, unknown protocol
                return false;
            }
        } else if (FAILED(hr)) {
            CloseHandle(ov.hEvent);
            char b[16];
            std::snprintf(b, sizeof(b), "0x%08lX", static_cast<unsigned long>(hr));
            WriteError(sink, "port_read_failed", std::string("HRESULT ") + b);
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) continue;
            return false;
        }
        CloseHandle(ov.hEvent);
        if (transferred < sizeof(FILTER_MESSAGE_HEADER) + 2 * sizeof(ULONG)) {
            WriteError(sink, "short_message", std::to_string(transferred) + " bytes");
            continue;
        }
        queue.Push(std::move(m));
    }
}

int RunCollector(const Rules& rules, Sink& sink) {
    for (;;) {
        HANDLE port = INVALID_HANDLE_VALUE;
        HRESULT hr;
        bool announced = false;
        while ((hr = FilterConnectCommunicationPort(ADSG_PORT_NAME, 0, nullptr, 0, nullptr, &port)) != S_OK) {
            if (!announced) {
                std::wcerr << L"Waiting for the AdsGuard port (HRESULT 0x" << std::hex << static_cast<unsigned long>(hr)
                           << std::dec << L"). The driver must be loaded and this process elevated.\n";
                announced = true;
            }
            if (WaitForSingleObject(gStop, 2000) == WAIT_OBJECT_0) return 0;
        }
        std::wcerr << L"Connected to the AdsGuard port.\n";
        MessageQueue queue(rules.queueCapacity);
        std::thread worker(Worker, std::ref(queue), std::cref(rules), std::ref(sink));
        bool stopped = ReadPort(port, queue, sink);
        queue.Close();
        worker.join();
        CloseHandle(port);
        if (stopped) return 0;
        WriteError(sink, "port_disconnected", "reconnecting");
    }
}

// ---- scan mode -------------------------------------------------------------

std::wstring LongPath(const std::filesystem::path& p) {
    std::wstring s = std::filesystem::absolute(p).wstring();
    if (s.rfind(L"\\\\?\\", 0) == 0) return s;
    if (s.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + s.substr(2);
    return L"\\\\?\\" + s;
}

void ScanFile(const std::filesystem::path& path, const Rules& rules, Sink& sink) {
    std::wstring display = std::filesystem::absolute(path).wstring();
    std::wstring open = LongPath(path);
    WIN32_FIND_STREAM_DATA data{};
    HANDLE find = FindFirstStreamW(open.c_str(), FindStreamInfoStandard, &data, 0);
    if (find == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err != ERROR_HANDLE_EOF) WriteError(sink, "scan_failed", Utf8(display) + ": Win32 error " + std::to_string(err));
        return;
    }
    do {
        std::wstring component = data.cStreamName;
        std::wstring name = StreamNameFromComponent(component);
        if (name.empty()) continue;
        EventRecord rec;
        rec.operation = "scan";
        rec.timestamp = NowFileTime();
        rec.processSource = "not_applicable";
        rec.fileDos = display;
        rec.streamDos = display + component;
        rec.streamName = name;
        rec.size = static_cast<std::uint64_t>(data.StreamSize.QuadPart);
        rec.inspection = Inspect(open + component, rules);
        rec.parentOpenPath = open;
        WriteEvent(sink, rec, rules, false);
    } while (FindNextStreamW(find, &data));
    DWORD err = GetLastError();
    FindClose(find);
    if (err != ERROR_HANDLE_EOF) WriteError(sink, "scan_failed", Utf8(display) + ": Win32 error " + std::to_string(err));
}

int RunScan(const std::wstring& target, bool recursive, const Rules& rules, Sink& sink) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path root(target);
    if (!fs::exists(root, ec)) throw std::runtime_error("Scan target does not exist");
    ScanFile(root, rules, sink); // the directory itself can carry streams
    if (!fs::is_directory(root, ec)) return 0;
    auto visit = [&](const fs::directory_entry& entry) {
        std::error_code typeError;
        if (entry.is_symlink(typeError)) return;
        ScanFile(entry.path(), rules, sink);
    };
    const auto options = fs::directory_options::skip_permission_denied;
    if (recursive) {
        for (fs::recursive_directory_iterator it(root, options, ec), end; !ec && it != end; it.increment(ec)) visit(*it);
    } else {
        for (fs::directory_iterator it(root, options, ec), end; !ec && it != end; it.increment(ec)) visit(*it);
    }
    if (ec) WriteError(sink, "scan_failed", "directory walk: " + ec.message());
    return 0;
}

const wchar_t kUsage[] =
    L"Usage:\n"
    L"  ads-guard-collector.exe [--config rules.json] [--output events.jsonl|-]\n"
    L"  ads-guard-collector.exe --scan PATH [--recursive] [--config rules.json] [--output FILE|-]\n"
    L"  ads-guard-collector.exe --check-config [--config rules.json]\n";

} // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring config = L"config\\rules.json", output = L"events.jsonl", scan;
    bool checkConfig = false, recursive = false;
    try {
        for (int i = 1; i < argc; ++i) {
            std::wstring_view arg = argv[i];
            if (arg == L"--help" || arg == L"-h") { std::wcout << kUsage; return 0; }
            if (arg == L"--check-config") { checkConfig = true; continue; }
            if (arg == L"--recursive") { recursive = true; continue; }
            if (i + 1 >= argc) throw std::runtime_error("Missing value for a command-line option");
            if (arg == L"--config") config = argv[++i];
            else if (arg == L"--output") output = argv[++i];
            else if (arg == L"--scan") scan = argv[++i];
            else throw std::runtime_error("Unknown command-line option");
        }
        Rules rules = LoadRules(config);
        if (checkConfig) { std::wcout << L"Rules configuration is valid.\n"; return 0; }
        gStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!gStop) throw std::runtime_error("CreateEvent failed");
        SetConsoleCtrlHandler(OnConsoleCtrl, TRUE);
        Sink sink(output);
        if (!scan.empty()) return RunScan(scan, recursive, rules, sink);
        return RunCollector(rules, sink);
    } catch (const std::exception& ex) {
        std::cerr << "Configuration or startup error: " << ex.what() << "\n";
        return 2;
    }
}
