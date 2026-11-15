#pragma once

#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <Windows.h>
#endif

#define ADSG_PROTOCOL_VERSION 1
#define ADSG_NAME_CHARS 1024

typedef enum _ADSG_OPERATION {
    AdsGuardOpen = 1,
    AdsGuardCreate = 2,
    AdsGuardWrite = 3
} ADSG_OPERATION;

typedef struct _ADSG_EVENT {
    ULONG Version;
    ULONG Size;
    ULONG Operation;
    ULONG ProcessId;
    ULONGLONG Timestamp100ns;
    ULONGLONG StreamSize;
    ULONG SizeQueryStatus;
    ULONG Flags;
    WCHAR FileName[ADSG_NAME_CHARS];
    WCHAR StreamName[ADSG_NAME_CHARS];
} ADSG_EVENT, *PADSG_EVENT;

#define ADSG_FLAG_PATH_TRUNCATED 0x1
#define ADSG_FLAG_SIZE_UNAVAILABLE 0x2
#define ADSG_PORT_NAME L"\\AdsGuardPort"
