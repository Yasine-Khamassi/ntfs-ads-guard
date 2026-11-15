/*
 * AdsGuard.sys: Filter Manager minifilter that reports activity on named
 * NTFS $DATA streams to a single user-mode collector.
 *
 * Event sources and IRQL:
 *   PreCreate   (PASSIVE_LEVEL)   cheap name pre-filter, skips the collector.
 *   PostCreate  (PASSIVE_LEVEL)   create is synchronous, so name and size
 *                                 queries are allowed. Emits open, create or
 *                                 overwrite and attaches a stream handle
 *                                 context to handles opened for write.
 *   PreWrite    (<= APC_LEVEL)    looks up the handle context and records the
 *                                 first writer process.
 *   PostWrite   (<= DISPATCH)     only interlocked updates and FltReleaseContext.
 *   PreCleanup  (PASSIVE_LEVEL)   emits one write event per handle that wrote,
 *                                 with the handle open time and the first and
 *                                 last write times.
 *
 * Nothing in the write path queries names or sizes above PASSIVE_LEVEL, so no
 * deferred work items are needed.
 */

#include <fltKernel.h>
#include "Protocol.h"

#define ADSG_TAG 'gsdA'
#define ADSG_SEND_TIMEOUT_MS 10

typedef struct _ADSG_HANDLE_CONTEXT {
    volatile LONG Written;          // set by PostWrite, consumed by PreCleanup
    volatile LONG64 BytesWritten;   // successful non-paging bytes on this handle
    volatile LONG64 FirstWriteTime; // FILETIME of the first successful write, 0 if none
    volatile LONG64 LastWriteTime;  // FILETIME of the latest successful write
    PEPROCESS volatile Writer;      // first writer, referenced; released in cleanup callback
    LONGLONG OpenTime;              // FILETIME when PostCreate attached the context
    ACCESS_MASK DesiredAccess;
} ADSG_HANDLE_CONTEXT, *PADSG_HANDLE_CONTEXT;

static struct {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;         // synchronized by FltSendMessage/FltCloseClientPort
    HANDLE volatile CollectorPid; // events caused by this process are not reported
    volatile LONG DroppedEvents;  // failed deliveries while a collector is connected
} g;

DRIVER_INITIALIZE DriverEntry;

static BOOLEAN IsCollector(_In_ PFLT_CALLBACK_DATA Data)
{
    HANDLE pid = InterlockedCompareExchangePointer((PVOID volatile *)&g.CollectorPid, NULL, NULL);
    return pid != NULL && FltGetRequestorProcessId(Data) == HandleToULong(pid);
}

/* TRUE for ":name" and ":name:$DATA". Rejects "::$DATA" (the default stream)
 * and other attribute types such as ":$I30:$INDEX_ALLOCATION". */
static BOOLEAN IsNamedDataStream(_In_ PCUNICODE_STRING Stream)
{
    static const UNICODE_STRING dataType = RTL_CONSTANT_STRING(L"$DATA");
    USHORT chars = Stream->Length / sizeof(WCHAR);
    USHORT end = 1;
    UNICODE_STRING type;

    if (chars < 2 || Stream->Buffer[0] != L':')
        return FALSE;
    while (end < chars && Stream->Buffer[end] != L':')
        end++;
    if (end == 1)
        return FALSE;
    if (end == chars)
        return TRUE;
    type.Buffer = &Stream->Buffer[end + 1];
    type.Length = (USHORT)((chars - end - 1) * sizeof(WCHAR));
    type.MaximumLength = type.Length;
    return RtlEqualUnicodeString(&type, &dataType, TRUE);
}

/* Pre-create filter: only names that contain a colon can address a named
 * stream. Opens by file ID and empty relative reopens cannot be judged from
 * the name, so they go to the post-create check. */
static BOOLEAN MayTargetNamedStream(_In_ PFLT_CALLBACK_DATA Data, _In_ PFILE_OBJECT FileObject)
{
    PCUNICODE_STRING name = &FileObject->FileName;
    USHORT i;

    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID))
        return TRUE;
    if (name->Length == 0)
        return FileObject->RelatedFileObject != NULL;
    for (i = 0; i < name->Length / sizeof(WCHAR); i++) {
        if (name->Buffer[i] == L':')
            return TRUE;
    }
    return FALSE;
}

static NTSTATUS GetNameInfo(_In_ PFLT_CALLBACK_DATA Data,
                            _Outptr_ PFLT_FILE_NAME_INFORMATION *Info,
                            _Inout_ PULONG Flags)
{
    NTSTATUS status;

    PAGED_CODE();
    *Info = NULL;
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, Info);
    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, Info);
        if (NT_SUCCESS(status))
            *Flags |= ADSG_FLAG_NAME_OPENED_FORM;
    }
    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(*Info);
        if (!NT_SUCCESS(status)) {
            FltReleaseFileNameInformation(*Info);
            *Info = NULL;
        }
    }
    return status;
}

/* Copies up to Capacity-1 characters and terminates. Returns TRUE if cut. */
static BOOLEAN CopyName(_Out_writes_(Capacity) PWCHAR Dest, SIZE_T Capacity,
                        _In_reads_(Chars) PCWCH Src, SIZE_T Chars)
{
    SIZE_T n = Chars < Capacity - 1 ? Chars : Capacity - 1;
    if (n)
        RtlCopyMemory(Dest, Src, n * sizeof(WCHAR));
    Dest[n] = L'\0';
    return n < Chars;
}

/* Everything about an event except the names and the stream size. */
typedef struct _ADSG_EVENT_INFO {
    ULONG Operation;            // ADSG_OPERATION
    ULONG Flags;                // ADSG_FLAG_* known before the event is built
    ULONG WriteSource;          // ADSG_WRITE_SOURCE
    ULONG InfoClass;            // set size only
    PEPROCESS Process;          // optional; when NULL, FallbackPid and FallbackCreateTime are used
    ULONG FallbackPid;
    LONGLONG FallbackCreateTime;
    ULONGLONG BytesWritten;
    ACCESS_MASK Access;
    LONGLONG HandleOpenTime;
    LONGLONG FirstWriteTime;
    LONGLONG LastWriteTime;
    LONGLONG RequestedSize;
} ADSG_EVENT_INFO, *PADSG_EVENT_INFO;

static LONGLONG NowFileTime(VOID)
{
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now); /* callable at any IRQL */
    return now.QuadPart;
}

/* Host file length in characters for a parsed name. */
static SIZE_T HostChars(_In_ PFLT_FILE_NAME_INFORMATION Info)
{
    return (Info->Name.Length - Info->Stream.Length) / sizeof(WCHAR);
}

/* Builds and delivers one event. PASSIVE_LEVEL only. Name is the full stream
 * path and its first FileChars characters are the host file path. When
 * FltObjects is NULL (paging writes reported from a work item) the size is
 * not queried. Delivery waits at most ADSG_SEND_TIMEOUT_MS; anything not
 * delivered is counted and reported in the DroppedEvents field of the next
 * delivered event. */
static VOID SendEvent(_In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_ PCUNICODE_STRING Name, SIZE_T FileChars,
                      _In_ const ADSG_EVENT_INFO *In)
{
    PADSG_EVENT ev;
    FILE_STANDARD_INFORMATION standard = {0};
    LARGE_INTEGER timeout;
    PUNICODE_STRING image = NULL;
    ULONG returned = 0;
    LONG dropped;
    NTSTATUS status;

    PAGED_CODE();
    if (g.ClientPort == NULL)
        return; /* no collector connected: nothing to deliver, not counted */

    ev = (PADSG_EVENT)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*ev), ADSG_TAG);
    if (ev == NULL) {
        InterlockedIncrement(&g.DroppedEvents);
        return;
    }
    /* ExAllocatePool2 returns zeroed memory. */
    ev->Version = ADSG_PROTOCOL_VERSION;
    ev->Size = sizeof(*ev);
    ev->Operation = In->Operation;
    ev->Flags = In->Flags;
    ev->WriteSource = In->WriteSource;
    ev->InfoClass = In->InfoClass;
    ev->BytesWritten = In->BytesWritten;
    ev->DesiredAccess = In->Access;
    ev->HandleOpenTime = (ULONGLONG)In->HandleOpenTime;
    ev->FirstWriteTime = (ULONGLONG)In->FirstWriteTime;
    ev->LastWriteTime = (ULONGLONG)In->LastWriteTime;
    ev->RequestedSize = (ULONGLONG)In->RequestedSize;
    ev->Timestamp100ns = (ULONGLONG)NowFileTime();

    if (In->Process != NULL) {
        ev->ProcessId = HandleToULong(PsGetProcessId(In->Process));
        ev->ProcessCreateTime = (ULONGLONG)PsGetProcessCreateTimeQuadPart(In->Process);
        status = SeLocateProcessImageName(In->Process, &image);
        ev->ImageQueryStatus = (ULONG)status;
        if (NT_SUCCESS(status) && image != NULL) {
            if (CopyName(ev->ProcessImage, ADSG_IMAGE_CHARS, image->Buffer, image->Length / sizeof(WCHAR)))
                ev->Flags |= ADSG_FLAG_IMAGE_TRUNCATED;
            ExFreePool(image);
        } else {
            ev->Flags |= ADSG_FLAG_IMAGE_UNAVAILABLE;
        }
    } else {
        ev->ProcessId = In->FallbackPid;
        ev->ProcessCreateTime = (ULONGLONG)In->FallbackCreateTime;
        ev->ImageQueryStatus = (ULONG)STATUS_NOT_FOUND;
        ev->Flags |= ADSG_FLAG_IMAGE_UNAVAILABLE;
    }

    /* A non-NULL top-level IRP means the file system is already inside a
     * request on this thread; a nested query could deadlock. */
    if (FltObjects == NULL)
        status = STATUS_NOT_SUPPORTED;
    else if (IoGetTopLevelIrp() != NULL)
        status = STATUS_POSSIBLE_DEADLOCK;
    else
        status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject,
                     &standard, sizeof(standard), FileStandardInformation, &returned);
    ev->SizeQueryStatus = (ULONG)status;
    if (NT_SUCCESS(status))
        ev->StreamSize = (ULONGLONG)standard.EndOfFile.QuadPart;
    else
        ev->Flags |= ADSG_FLAG_SIZE_UNAVAILABLE;

    if (CopyName(ev->StreamName, ADSG_NAME_CHARS, Name->Buffer, Name->Length / sizeof(WCHAR)) |
        CopyName(ev->FileName, ADSG_NAME_CHARS, Name->Buffer, FileChars))
        ev->Flags |= ADSG_FLAG_PATH_TRUNCATED;

    dropped = InterlockedExchange(&g.DroppedEvents, 0);
    ev->DroppedEvents = (ULONG)dropped;
    timeout.QuadPart = -10LL * 1000 * ADSG_SEND_TIMEOUT_MS;
    status = FltSendMessage(g.Filter, &g.ClientPort, ev, sizeof(*ev), NULL, NULL, &timeout);
    /* STATUS_TIMEOUT is a success code, so compare exactly. */
    if (status != STATUS_SUCCESS)
        InterlockedAdd(&g.DroppedEvents, dropped + 1);
    ExFreePoolWithTag(ev, ADSG_TAG);
}

static VOID AttachHandleContext(_In_ PCFLT_RELATED_OBJECTS FltObjects, ACCESS_MASK Access)
{
    PADSG_HANDLE_CONTEXT ctx = NULL;
    NTSTATUS status;

    if (!FltSupportsStreamHandleContexts(FltObjects->FileObject))
        return;
    status = FltAllocateContext(g.Filter, FLT_STREAMHANDLE_CONTEXT, sizeof(*ctx),
                                NonPagedPoolNx, (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&g.DroppedEvents); /* writes on this handle will not be seen */
        return;
    }
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->DesiredAccess = Access;
    ctx->OpenTime = NowFileTime();
    (VOID)FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
                                    FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, NULL);
    FltReleaseContext(ctx);
}

static VOID FLTAPI HandleContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType)
{
    PADSG_HANDLE_CONTEXT ctx = (PADSG_HANDLE_CONTEXT)Context;
    UNREFERENCED_PARAMETER(ContextType);
    if (ctx->Writer != NULL)
        ObDereferenceObject(ctx->Writer);
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    *CompletionContext = NULL;
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) ||
        FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN) ||
        IsCollector(Data) ||
        !MayTargetNamedStream(Data, FltObjects->FileObject))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI PostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PFLT_FILE_NAME_INFORMATION info = NULL;
    ADSG_EVENT_INFO ev;
    ULONG nameFlags = 0;
    ACCESS_MASK access;

    UNREFERENCED_PARAMETER(CompletionContext);
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;
    /* Exact match: STATUS_REPARSE and other informational codes pass
     * NT_SUCCESS but do not leave an open stream on this volume. */
    if (Data->IoStatus.Status != STATUS_SUCCESS)
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(GetNameInfo(Data, &info, &nameFlags)))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (!IsNamedDataStream(&info->Stream)) {
        FltReleaseFileNameInformation(info);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (FlagOn(access, FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED))
        AttachHandleContext(FltObjects, access);

    RtlZeroMemory(&ev, sizeof(ev));
    switch (Data->IoStatus.Information) {
    case FILE_OPENED:      ev.Operation = AdsGuardOpen; break;
    case FILE_CREATED:     ev.Operation = AdsGuardCreate; break;
    default:               ev.Operation = AdsGuardOverwrite; break; /* FILE_OVERWRITTEN, FILE_SUPERSEDED */
    }
    ev.Flags = nameFlags;
    ev.Process = FltGetRequestorProcess(Data);
    ev.Access = access;
    SendEvent(FltObjects, &info->Name, HostChars(info), &ev);
    FltReleaseFileNameInformation(info);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI PreWrite(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    PADSG_HANDLE_CONTEXT ctx = NULL;
    PEPROCESS process;

    *CompletionContext = NULL;
    if (!NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
                                              (PFLT_CONTEXT *)&ctx)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (ctx->Writer == NULL) {
        process = FltGetRequestorProcess(Data);
        if (process != NULL) {
            ObReferenceObject(process);
            if (InterlockedCompareExchangePointer((PVOID volatile *)&ctx->Writer, process, NULL) != NULL)
                ObDereferenceObject(process);
        }
    }
    *CompletionContext = ctx; /* reference released in PostWrite */
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI PostWrite(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PADSG_HANDLE_CONTEXT ctx = (PADSG_HANDLE_CONTEXT)CompletionContext;

    UNREFERENCED_PARAMETER(FltObjects);
    if (ctx == NULL)
        return FLT_POSTOP_FINISHED_PROCESSING;
    /* May run at DISPATCH_LEVEL: interlocked updates only. The handle still
     * holds its own context reference, so this release is never the last. */
    if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) &&
        NT_SUCCESS(Data->IoStatus.Status) && Data->IoStatus.Information > 0) {
        LONGLONG now = NowFileTime();
        InterlockedAdd64(&ctx->BytesWritten, (LONG64)Data->IoStatus.Information);
        InterlockedCompareExchange64(&ctx->FirstWriteTime, now, 0);
        InterlockedExchange64(&ctx->LastWriteTime, now);
        InterlockedExchange(&ctx->Written, 1);
    }
    FltReleaseContext(ctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI PreCleanup(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    PADSG_HANDLE_CONTEXT ctx = NULL;
    PFLT_FILE_NAME_INFORMATION info = NULL;
    ADSG_EVENT_INFO ev;
    ULONG nameFlags = 0;

    *CompletionContext = NULL;
    if (!NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
                                              (PFLT_CONTEXT *)&ctx)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (InterlockedExchange(&ctx->Written, 0) != 0) {
        RtlZeroMemory(&ev, sizeof(ev));
        ev.Operation = AdsGuardWrite;
        ev.WriteSource = AdsGuardWriteHandle;
        ev.Process = ctx->Writer;
        ev.Access = ctx->DesiredAccess;
        ev.HandleOpenTime = ctx->OpenTime;
        ev.BytesWritten = (ULONGLONG)InterlockedExchange64(&ctx->BytesWritten, 0);
        ev.FirstWriteTime = InterlockedExchange64(&ctx->FirstWriteTime, 0);
        ev.LastWriteTime = InterlockedExchange64(&ctx->LastWriteTime, 0);
        if (FltGetRequestorProcess(Data) != ctx->Writer)
            nameFlags |= ADSG_FLAG_WRITER_DIFFERS;
        if (NT_SUCCESS(GetNameInfo(Data, &info, &nameFlags))) {
            ev.Flags = nameFlags;
            SendEvent(FltObjects, &info->Name, HostChars(info), &ev);
            FltReleaseFileNameInformation(info);
        } else if (g.ClientPort != NULL) {
            InterlockedIncrement(&g.DroppedEvents);
        }
    }
    FltReleaseContext(ctx);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS FLTAPI ConnectNotify(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    *ConnectionCookie = NULL;
    /* Runs in the connecting process. The port only admits one connection
     * and its descriptor only admits SYSTEM and Administrators. */
    InterlockedExchangePointer((PVOID volatile *)&g.CollectorPid, PsGetCurrentProcessId());
    InterlockedExchange(&g.DroppedEvents, 0);
    g.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

static VOID FLTAPI DisconnectNotify(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(g.Filter, &g.ClientPort);
    InterlockedExchangePointer((PVOID volatile *)&g.CollectorPid, NULL);
}

static NTSTATUS FLTAPI InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    return VolumeFilesystemType == FLT_FSTYPE_NTFS ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}

/* Present so that `fltmc detach` works; without it manual detach is refused. */
static NTSTATUS FLTAPI InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static NTSTATUS FLTAPI FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    /* Closing the server port blocks new connections. FltUnregisterFilter
     * then closes the client port, waits for in-flight callbacks and
     * completions, and frees all contexts. */
    FltCloseCommunicationPort(g.ServerPort);
    FltUnregisterFilter(g.Filter);
    return STATUS_SUCCESS;
}

static const FLT_CONTEXT_REGISTRATION Contexts[] = {
    { FLT_STREAMHANDLE_CONTEXT, 0, HandleContextCleanup, sizeof(ADSG_HANDLE_CONTEXT), ADSG_TAG },
    { FLT_CONTEXT_END }
};

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, PostCreate },
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreWrite, PostWrite },
    { IRP_MJ_CLEANUP, 0, PreCleanup, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    Contexts,
    Callbacks,
    FilterUnload,
    InstanceSetup,
    InstanceQueryTeardown,
    NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(ADSG_PORT_NAME);
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);
    status = FltRegisterFilter(DriverObject, &Registration, &g.Filter);
    if (!NT_SUCCESS(status))
        return status;

    /* The default descriptor grants FLT_PORT_ALL_ACCESS to SYSTEM and
     * Administrators only. MaxConnections is 1. */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        status = FltCreateCommunicationPort(g.Filter, &g.ServerPort, &oa, NULL,
                                            ConnectNotify, DisconnectNotify, NULL, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(g.Filter);
        if (!NT_SUCCESS(status))
            FltCloseCommunicationPort(g.ServerPort);
    }
    if (!NT_SUCCESS(status))
        FltUnregisterFilter(g.Filter);
    return status;
}
