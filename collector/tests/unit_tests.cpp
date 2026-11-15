// Unit tests for the pure analysis helpers. No framework: each CHECK prints
// the failing expression and the process exits non-zero if any failed.
#include <Windows.h>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "../analysis.hpp"
#include "../../driver/Protocol.h"

static int failures = 0;
#define CHECK(expr) \
    do { if (!(expr)) { std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (0)

static std::vector<unsigned char> MzWithPeAt(std::uint32_t offset, std::size_t size) {
    std::vector<unsigned char> b(size, 0);
    b[0] = 'M'; b[1] = 'Z';
    std::memcpy(b.data() + 0x3c, &offset, sizeof(offset));
    if (static_cast<std::uint64_t>(offset) + 4 <= size) { b[offset] = 'P'; b[offset + 1] = 'E'; }
    return b;
}

static void TestStreamNames() {
    CHECK(StreamNameFromComponent(L":payload.bin:$DATA") == L"payload.bin");
    CHECK(StreamNameFromComponent(L":payload.bin") == L"payload.bin");
    CHECK(StreamNameFromComponent(L"::$DATA").empty());
    CHECK(StreamNameFromComponent(L"").empty());
    CHECK(StreamComponent(L"\\Device\\HarddiskVolume3\\a\\b.txt:x:$DATA", L"\\Device\\HarddiskVolume3\\a\\b.txt") == L":x:$DATA");
    // Host path unknown or not a prefix: first colon after the last backslash.
    CHECK(StreamComponent(L"\\Device\\HarddiskVolume3\\a\\b.txt:x", L"") == L":x");
    CHECK(StreamComponent(L"C:\\a\\b.txt:x:$DATA", L"\\Device\\Other\\b.txt") == L":x:$DATA");
}

static void TestDeviceMapping() {
    std::vector<std::pair<std::wstring, std::wstring>> devices{
        {L"\\Device\\HarddiskVolume1", L"C:"}, {L"\\Device\\HarddiskVolume10", L"D:"}};
    CHECK(MapDevicePath(L"\\Device\\HarddiskVolume1\\x.txt", devices) == L"C:\\x.txt");
    // Volume1 must not claim Volume10.
    CHECK(MapDevicePath(L"\\Device\\HarddiskVolume10\\x.txt", devices) == L"D:\\x.txt");
    CHECK(MapDevicePath(L"\\Device\\HarddiskVolume1", devices) == L"C:");
    CHECK(MapDevicePath(L"\\Device\\Unknown\\x", devices) == L"\\Device\\Unknown\\x");
}

static void TestPe() {
    CHECK(DetectPe(MzWithPeAt(0x40, 1024), true) == PeResult::Pe);
    CHECK(DetectPe(MzWithPeAt(0x80, 1024), false) == PeResult::Pe);
    auto noSig = MzWithPeAt(0x40, 1024);
    noSig[0x40] = 'X';
    CHECK(DetectPe(noSig, true) == PeResult::NotPe);
    // e_lfanew past the end of a fully read stream: not a PE.
    CHECK(DetectPe(MzWithPeAt(5000, 1024), true) == PeResult::NotPe);
    // e_lfanew past what was read of a larger stream: cannot tell.
    CHECK(DetectPe(MzWithPeAt(5000, 1024), false) == PeResult::Unknown);
    // Huge e_lfanew must not overflow the bounds check.
    CHECK(DetectPe(MzWithPeAt(0xFFFFFFFFu, 1024), true) == PeResult::NotPe);
    CHECK(DetectPe(MzWithPeAt(0xFFFFFFFDu, 1024), false) == PeResult::Unknown);
    CHECK(DetectPe({'M', 'Z', 0}, false) == PeResult::Unknown);
    CHECK(DetectPe({'M', 'Z', 0}, true) == PeResult::NotPe);
    CHECK(DetectPe({'h', 'i'}, false) == PeResult::NotPe);
    CHECK(DetectPe({}, true) == PeResult::NotPe);
    CHECK(DetectPe({}, false) == PeResult::Unknown);
}

static void TestContent() {
    {
        ContentAccumulator acc;
        std::vector<unsigned char> zeros(4096, 0);
        acc.Add(zeros.data(), zeros.size());
        CHECK(acc.Entropy(512).has_value() && *acc.Entropy(512) == 0.0);
        CHECK(!acc.Entropy(8192).has_value());
    }
    {
        ContentAccumulator acc;
        std::vector<unsigned char> all(256 * 16);
        for (std::size_t i = 0; i < all.size(); ++i) all[i] = static_cast<unsigned char>(i);
        acc.Add(all.data(), 100);
        acc.Add(all.data() + 100, all.size() - 100);
        CHECK(acc.Bytes() == all.size());
        CHECK(std::fabs(*acc.Entropy(1) - 8.0) < 1e-9);
    }
    {
        ContentAccumulator acc;
        const char* abc = "abc";
        acc.Add(reinterpret_cast<const unsigned char*>(abc), 3);
        auto h = acc.FinishSha256();
        CHECK(h && *h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
    {
        ContentAccumulator acc;
        auto h = acc.FinishSha256();
        CHECK(h && *h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}

static Rules TestRules() {
    Rules r;
    r.allowStreamNames = {L"Zone.Identifier"};
    r.allowProcessPaths = {L"C:\\Tools\\Backup.exe"};
    r.executableExtensions = {L".exe", L".dll"};
    r.systemHostPrefixes = {L"C:\\Windows\\"};
    return r;
}

static void TestScoring() {
    Rules r = TestRules();
    ScoreInput in;
    in.contentAvailable = in.contentComplete = in.processAvailable = true;
    in.pe = PeResult::NotPe;

    in.streamName = L"zone.identifier";
    auto f = Score(in, r);
    CHECK(f.allowlisted && f.score == 0 && f.severity == "informational");

    // Anchored: a name that only ends in the allowed name is not allowed.
    in.streamName = L"evil.Zone.Identifier";
    f = Score(in, r);
    CHECK(!f.allowlisted && f.score == r.namedWeight);

    // Allow-listed name with a PE payload still scores the PE finding.
    in.streamName = L"Zone.Identifier";
    in.pe = PeResult::Pe;
    f = Score(in, r);
    CHECK(f.allowlisted && f.score == r.peWeight);

    in.pe = PeResult::NotPe;
    in.streamName = L"payload.EXE";
    f = Score(in, r);
    CHECK(f.score == r.namedWeight + r.executableWeight);
    in.streamName = L"payload.exe.txt";
    f = Score(in, r);
    CHECK(f.score == r.namedWeight);

    in.streamName = L"notes";
    in.hostDosPath = L"c:\\windows\\system32\\notepad.exe";
    f = Score(in, r);
    CHECK(f.score == r.namedWeight + r.systemHostWeight);

    in.hostDosPath = L"C:\\Users\\x\\a.txt";
    in.processDosPath = L"c:\\tools\\backup.exe";
    f = Score(in, r);
    CHECK(f.allowlisted && f.score == 0);

    in.processDosPath.clear();
    in.processAvailable = false;
    in.entropy = 7.5;
    f = Score(in, r);
    CHECK(f.score == r.namedWeight + r.entropyWeight);
    bool sawProcessReason = false;
    for (auto& reason : f.reasons) if (reason == "process_metadata_unavailable") sawProcessReason = true;
    CHECK(sawProcessReason);

    in.contentAvailable = false;
    in.contentComplete = false;
    in.entropy.reset();
    f = Score(in, r);
    bool sawContentReason = false;
    for (auto& reason : f.reasons) if (reason == "content_unavailable") sawContentReason = true;
    CHECK(sawContentReason);
}

static void TestProtocolLayout() {
    CHECK(sizeof(ADSG_EVENT) == 5208);
    CHECK(offsetof(ADSG_EVENT, FileName) == 72 + ADSG_IMAGE_CHARS * sizeof(WCHAR));
    CHECK(offsetof(ADSG_EVENT, StreamName) == 72 + (ADSG_IMAGE_CHARS + ADSG_NAME_CHARS) * sizeof(WCHAR));
}

int main() {
    TestStreamNames();
    TestDeviceMapping();
    TestPe();
    TestContent();
    TestScoring();
    TestProtocolLayout();
    if (failures) { std::printf("%d check(s) failed\n", failures); return 1; }
    std::printf("All unit tests passed.\n");
    return 0;
}
