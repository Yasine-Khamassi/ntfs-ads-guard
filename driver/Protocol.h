#pragma once

// Wire format shared by AdsGuard.sys and ads-guard-collector.exe.
// Both sides are x64 only. The layout uses natural alignment with explicit
// padding, and both compilers check the size and the first variable-length
// offset at build time. Bump ADSG_PROTOCOL_VERSION on any layout or meaning
// change; the collector rejects other versions and reports them.

#ifdef _KERNEL_MODE
#include <ntifs.h>
#define ADSG_STATIC_ASSERT(expr) C_ASSERT(expr)
#define ADSG_OFFSETOF(type, field) FIELD_OFFSET(type, field)
#else
#include <Windows.h>
#include <cstddef>
#define ADSG_STATIC_ASSERT(expr) static_assert(expr, #expr)
#define ADSG_OFFSETOF(type, field) offsetof(type, field)
#endif

#define ADSG_PROTOCOL_VERSION 3
#define ADSG_NAME_CHARS 1024
#define ADSG_IMAGE_CHARS 520
#define ADSG_PORT_NAME L"\\AdsGuardPort"

typedef enum _ADSG_OPERATION {
    AdsGuardOpen = 1,      // existing stream opened (FILE_OPENED)
    AdsGuardCreate = 2,    // new stream created (FILE_CREATED)
    AdsGuardWrite = 3,     // data written: see WriteSource
    AdsGuardOverwrite = 4, // FILE_OVERWRITTEN or FILE_SUPERSEDED at create
    AdsGuardSetSize = 5    // end of file or allocation size set, see InfoClass
} ADSG_OPERATION;

typedef enum _ADSG_WRITE_SOURCE {
    AdsGuardWriteNone = 0,   // not a write event
    AdsGuardWriteHandle = 1, // non-paging writes on one handle, sent at cleanup
    AdsGuardWritePaging = 2  // paging writes not issued by the lazy writer (mapped views)
} ADSG_WRITE_SOURCE;

#define ADSG_INFO_ALLOCATION  19 // FileAllocationInformation
#define ADSG_INFO_END_OF_FILE 20 // FileEndOfFileInformation

#define ADSG_FLAG_PATH_TRUNCATED    0x00000001  // FileName or StreamName was cut to fit
#define ADSG_FLAG_SIZE_UNAVAILABLE  0x00000002  // StreamSize is not valid, see SizeQueryStatus
#define ADSG_FLAG_IMAGE_UNAVAILABLE 0x00000004  // ProcessImage is empty, see ImageQueryStatus
#define ADSG_FLAG_IMAGE_TRUNCATED   0x00000008  // ProcessImage was cut to fit
#define ADSG_FLAG_NAME_OPENED_FORM  0x00000010  // normalized name failed, opened name used
#define ADSG_FLAG_WRITER_DIFFERS    0x00000020  // handle write: closing process is not the first writer
#define ADSG_FLAG_NAME_CACHED       0x00000040  // paging write: name cached at the first write-capable open

#pragma pack(push, 8)
typedef struct _ADSG_EVENT {
    ULONG Version;               // ADSG_PROTOCOL_VERSION
    ULONG Size;                  // sizeof(ADSG_EVENT)
    ULONG Operation;             // ADSG_OPERATION
    ULONG ProcessId;             // requestor, first writer (handle write) or last write-capable opener (paging write)
    ULONGLONG ProcessCreateTime; // process start time as FILETIME, 0 if unknown
    ULONGLONG Timestamp100ns;    // KeQuerySystemTimePrecise when the event was built (UTC FILETIME)
    ULONGLONG StreamSize;        // EndOfFile, valid unless ADSG_FLAG_SIZE_UNAVAILABLE
    ULONGLONG BytesWritten;      // write events: bytes from successful writes of the WriteSource kind
    ULONG SizeQueryStatus;       // NTSTATUS of FltQueryInformationFile
    ULONG ImageQueryStatus;      // NTSTATUS of SeLocateProcessImageName
    ULONG DesiredAccess;         // access mask requested at create (0 for paging writes)
    ULONG Flags;                 // ADSG_FLAG_*
    ULONG DroppedEvents;         // events the driver failed to deliver since the last delivered one
    ULONG WriteSource;           // ADSG_WRITE_SOURCE
    ULONGLONG HandleOpenTime;    // handle write and set size: when the handle was opened, 0 if unknown
    ULONGLONG FirstWriteTime;    // write events: first successful write in this report, 0 otherwise
    ULONGLONG LastWriteTime;     // write events: last successful write in this report, 0 otherwise
    ULONGLONG RequestedSize;     // set size: new EndOfFile or AllocationSize
    ULONG InfoClass;             // set size: ADSG_INFO_END_OF_FILE or ADSG_INFO_ALLOCATION
    ULONG Reserved;
    WCHAR ProcessImage[ADSG_IMAGE_CHARS]; // NT path of the process image
    WCHAR FileName[ADSG_NAME_CHARS];      // NT path of the host file, without the stream part
    WCHAR StreamName[ADSG_NAME_CHARS];    // NT path including the ":name[:$DATA]" part
} ADSG_EVENT, *PADSG_EVENT;
#pragma pack(pop)

ADSG_STATIC_ASSERT(ADSG_OFFSETOF(ADSG_EVENT, ProcessImage) == 112);
ADSG_STATIC_ASSERT(sizeof(ADSG_EVENT) == 112 + (ADSG_IMAGE_CHARS + 2 * ADSG_NAME_CHARS) * sizeof(WCHAR));
