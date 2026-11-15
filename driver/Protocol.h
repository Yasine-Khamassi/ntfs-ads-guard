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

#define ADSG_PROTOCOL_VERSION 2
#define ADSG_NAME_CHARS 1024
#define ADSG_IMAGE_CHARS 520
#define ADSG_PORT_NAME L"\\AdsGuardPort"

typedef enum _ADSG_OPERATION {
    AdsGuardOpen = 1,      // existing stream opened (FILE_OPENED)
    AdsGuardCreate = 2,    // new stream created (FILE_CREATED)
    AdsGuardWrite = 3,     // a handle that wrote data to the stream was cleaned up
    AdsGuardOverwrite = 4  // FILE_OVERWRITTEN or FILE_SUPERSEDED at create
} ADSG_OPERATION;

#define ADSG_FLAG_PATH_TRUNCATED    0x00000001  // FileName or StreamName was cut to fit
#define ADSG_FLAG_SIZE_UNAVAILABLE  0x00000002  // StreamSize is not valid, see SizeQueryStatus
#define ADSG_FLAG_IMAGE_UNAVAILABLE 0x00000004  // ProcessImage is empty, see ImageQueryStatus
#define ADSG_FLAG_IMAGE_TRUNCATED   0x00000008  // ProcessImage was cut to fit
#define ADSG_FLAG_NAME_OPENED_FORM  0x00000010  // normalized name failed, opened name used
#define ADSG_FLAG_WRITER_DIFFERS    0x00000020  // write event: closing process is not the first writer

#pragma pack(push, 8)
typedef struct _ADSG_EVENT {
    ULONG Version;               // ADSG_PROTOCOL_VERSION
    ULONG Size;                  // sizeof(ADSG_EVENT)
    ULONG Operation;             // ADSG_OPERATION
    ULONG ProcessId;             // requestor (open/create/overwrite) or first writer (write)
    ULONGLONG ProcessCreateTime; // process start time as FILETIME, 0 if unknown
    ULONGLONG Timestamp100ns;    // KeQuerySystemTimePrecise when the event was built (UTC FILETIME)
    ULONGLONG StreamSize;        // EndOfFile, valid unless ADSG_FLAG_SIZE_UNAVAILABLE
    ULONGLONG BytesWritten;      // write events: sum of successful non-paging writes on the handle
    ULONG SizeQueryStatus;       // NTSTATUS of FltQueryInformationFile
    ULONG ImageQueryStatus;      // NTSTATUS of SeLocateProcessImageName
    ULONG DesiredAccess;         // access mask requested at create
    ULONG Flags;                 // ADSG_FLAG_*
    ULONG DroppedEvents;         // events the driver failed to deliver since the last delivered one
    ULONG Reserved;
    WCHAR ProcessImage[ADSG_IMAGE_CHARS]; // NT path of the process image
    WCHAR FileName[ADSG_NAME_CHARS];      // NT path of the host file, without the stream part
    WCHAR StreamName[ADSG_NAME_CHARS];    // NT path including the ":name[:$DATA]" part
} ADSG_EVENT, *PADSG_EVENT;
#pragma pack(pop)

ADSG_STATIC_ASSERT(ADSG_OFFSETOF(ADSG_EVENT, ProcessImage) == 72);
ADSG_STATIC_ASSERT(sizeof(ADSG_EVENT) == 72 + (ADSG_IMAGE_CHARS + 2 * ADSG_NAME_CHARS) * sizeof(WCHAR));
