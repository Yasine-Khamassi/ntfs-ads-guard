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
 *   PreWrite    (<= APC_LEVEL)    non-paging: looks up the handle context and
 *                                 records the first writer process.
 *                                 paging: skips lazy writer flushes, looks up
 *                                 the stream context.
 *   PostWrite   (<= DISPATCH)     interlocked updates, FltReleaseContext and,
 *                                 for paging writes, queueing one generic
 *                                 work item per burst.
 *   PagingWork  (PASSIVE_LEVEL)   sends one paging write event from the name
 *                                 cached in the stream context.
 *   PreSetInfo  (PASSIVE_LEVEL)   end of file and allocation changes on
 *                                 monitored handles; synchronized so that
 *   PostSetInfo (<= APC_LEVEL)    the post callback runs in the caller's
 *                                 thread and emits set_size at PASSIVE_LEVEL.
 *   PreCleanup  (PASSIVE_LEVEL)   emits one write event per handle that wrote,
 *                                 with the handle open time and the first and
 *                                 last write times.
 *
 * Nothing in the write path queries names or sizes above PASSIVE_LEVEL.
 *
 * Paging writes (memory-mapped views flushed by the mapped page writer, or by
 * FlushViewOfFile) have no handle context: they arrive on whatever file object
 * backs the section, often from a system thread. They are attributed through a
 * stream context, which Filter Manager keys on the stream itself, so every
 * file object for the stream finds it. The context holds a copy of the name
 * taken at the first write-capable open and the process that made the latest
 * one.
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

typedef struct _ADSG_STREAM_CONTEXT {
    UNICODE_STRING Name;              // paged copy of the stream path at the first write-capable open
    SIZE_T FileChars;                 // host file part of Name, in characters
    ULONG NameFlags;                  // ADSG_FLAG_NAME_OPENED_FORM if Name is the opened form
    volatile LONG MapperPid;          // last process that opened the stream for write
    volatile LONG64 MapperCreateTime; // its start time
    volatile LONG64 PagingBytes;      // paging bytes since the last report
    volatile LONG64 FirstPagingTime;  // first paging write since the last report
    volatile LONG64 LastPagingTime;   // latest paging write since the last report
    volatile LONG WorkQueued;         // 1 while a report work item is queued
} ADSG_STREAM_CONTEXT, *PADSG_STREAM_CONTEXT;

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

/* Functions that only run at PASSIVE_LEVEL live in the pageable section. */
static NTSTATUS GetNameInfo(_In_ PFLT_CALLBACK_DATA Data,
                            _Outptr_ PFLT_FILE_NAME_INFORMATION *Info,
                            _Inout_ PULONG Flags);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, GetNameInfo)
#endif

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

static VOID SendEvent(_In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_ PCUNICODE_STRING Name, SIZE_T FileChars,
                      _In_ const ADSG_EVENT_INFO *In);
static VOID TrackStreamForPaging(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                 _In_ PFLT_FILE_NAME_INFORMATION Info, ULONG NameFlags,
                                 _In_opt_ PEPROCESS Process);
static VOID FLTAPI PagingWork(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject, _In_opt_ PVOID Context);
static NTSTATUS FLTAPI FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SendEvent)
#pragma alloc_text(PAGE, TrackStreamForPaging)
#pragma alloc_text(PAGE, PagingWork)
#pragma alloc_text(PAGE, FilterUnload)
#endif

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

static VOID FLTAPI StreamContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType)
{
    PADSG_STREAM_CONTEXT ctx = (PADSG_STREAM_CONTEXT)Context;
    UNREFERENCED_PARAMETER(ContextType);
    if (ctx->Name.Buffer != NULL)
        ExFreePoolWithTag(ctx->Name.Buffer, ADSG_TAG);
}

/* Makes sure the stream carries a stream context and records the opening
 * process as the one paging writes are attributed to. PASSIVE_LEVEL. */
static VOID TrackStreamForPaging(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                 _In_ PFLT_FILE_NAME_INFORMATION Info, ULONG NameFlags,
                                 _In_opt_ PEPROCESS Process)
{
    PADSG_STREAM_CONTEXT ctx = NULL, existing = NULL;
    NTSTATUS status;

    PAGED_CODE();
    if (!FltSupportsStreamContexts(FltObjects->FileObject))
        return;
    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status)) {
        status = FltAllocateContext(g.Filter, FLT_STREAM_CONTEXT, sizeof(*ctx),
                                    NonPagedPoolNx, (PFLT_CONTEXT *)&ctx);
        if (!NT_SUCCESS(status))
            return;
        RtlZeroMemory(ctx, sizeof(*ctx));
        ctx->Name.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, Info->Name.Length, ADSG_TAG);
        if (ctx->Name.Buffer == NULL) {
            FltReleaseContext(ctx);
            return;
        }
        RtlCopyMemory(ctx->Name.Buffer, Info->Name.Buffer, Info->Name.Length);
        ctx->Name.Length = Info->Name.Length;
        ctx->Name.MaximumLength = Info->Name.Length;
        ctx->FileChars = HostChars(Info);
        ctx->NameFlags = NameFlags & ADSG_FLAG_NAME_OPENED_FORM;
        status = FltSetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                     FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, (PFLT_CONTEXT *)&existing);
        if (!NT_SUCCESS(status)) {
            FltReleaseContext(ctx); /* last reference: frees it and its name */
            if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED || existing == NULL)
                return;
            ctx = existing; /* another open won the race; already referenced */
        }
    }
    if (Process != NULL) {
        InterlockedExchange64(&ctx->MapperCreateTime, PsGetProcessCreateTimeQuadPart(Process));
        InterlockedExchange(&ctx->MapperPid, (LONG)HandleToULong(PsGetProcessId(Process)));
    }
    FltReleaseContext(ctx);
}

/* Reports the paging writes accumulated in a stream context. Runs in a system
 * worker thread at PASSIVE_LEVEL. Filter Manager keeps the instance from being
 * torn down until this returns. */
static VOID FLTAPI PagingWork(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject, _In_opt_ PVOID Context)
{
    PADSG_STREAM_CONTEXT ctx = (PADSG_STREAM_CONTEXT)Context;
    PEPROCESS process = NULL;
    ADSG_EVENT_INFO ev;

    UNREFERENCED_PARAMETER(FltObject);
    PAGED_CODE();
    if (ctx == NULL) {
        FltFreeGenericWorkItem(WorkItem);
        return;
    }
    /* Clear the flag first so that writes completing from here on queue a
     * new report instead of being lost. */
    InterlockedExchange(&ctx->WorkQueued, 0);
    RtlZeroMemory(&ev, sizeof(ev));
    ev.BytesWritten = (ULONGLONG)InterlockedExchange64(&ctx->PagingBytes, 0);
    ev.FirstWriteTime = InterlockedExchange64(&ctx->FirstPagingTime, 0);
    ev.LastWriteTime = InterlockedExchange64(&ctx->LastPagingTime, 0);
    if (ev.BytesWritten != 0) {
        ev.Operation = AdsGuardWrite;
        ev.WriteSource = AdsGuardWritePaging;
        ev.Flags = ctx->NameFlags | ADSG_FLAG_NAME_CACHED;
        ev.FallbackPid = (ULONG)InterlockedCompareExchange(&ctx->MapperPid, 0, 0);
        ev.FallbackCreateTime = InterlockedCompareExchange64(&ctx->MapperCreateTime, 0, 0);
        /* Use the live process for the image path only if the PID still
         * belongs to the process that opened the stream. */
        if (ev.FallbackPid != 0 &&
            NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(ev.FallbackPid), &process))) {
            if (PsGetProcessCreateTimeQuadPart(process) == ev.FallbackCreateTime)
                ev.Process = process;
        }
        SendEvent(NULL, &ctx->Name, ctx->FileChars, &ev);
        if (process != NULL)
            ObDereferenceObject(process);
    }
    FltReleaseContext(ctx);
    FltFreeGenericWorkItem(WorkItem);
}

/* PostWrite part for paging I/O. Runs at <= DISPATCH_LEVEL. */
static VOID AccountPagingWrite(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                               _In_ PADSG_STREAM_CONTEXT Ctx)
{
    PFLT_GENERIC_WORKITEM item;
    LONGLONG now;

    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Information == 0)
        return;
    now = NowFileTime();
    InterlockedAdd64(&Ctx->PagingBytes, (LONG64)Data->IoStatus.Information);
    InterlockedCompareExchange64(&Ctx->FirstPagingTime, now, 0);
    InterlockedExchange64(&Ctx->LastPagingTime, now);
    if (g.ClientPort == NULL || InterlockedCompareExchange(&Ctx->WorkQueued, 1, 0) != 0)
        return; /* nobody listening, or a report is already queued and will include these bytes */

    item = FltAllocateGenericWorkItem();
    if (item != NULL) {
        FltReferenceContext(Ctx); /* released by PagingWork */
        if (NT_SUCCESS(FltQueueGenericWorkItem(item, FltObjects->Instance, PagingWork,
                                               DelayedWorkQueue, Ctx)))
            return;
        FltReleaseContext(Ctx);
        FltFreeGenericWorkItem(item);
    }
    InterlockedExchange(&Ctx->WorkQueued, 0);
    InterlockedIncrement(&g.DroppedEvents);
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
    if (FlagOn(access, FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED)) {
        AttachHandleContext(FltObjects, access);
        TrackStreamForPaging(FltObjects, info, nameFlags, FltGetRequestorProcess(Data));
    }

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
    PADSG_STREAM_CONTEXT stream = NULL;
    PEPROCESS process;

    *CompletionContext = NULL;
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        /* The lazy writer flushing cached data marks the thread with
         * FSRTL_CACHE_TOP_LEVEL_IRP. Those bytes were already counted as
         * non-paging writes on the handle that wrote them. */
        if (IoGetTopLevelIrp() == (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        if (!NT_SUCCESS(FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                            (PFLT_CONTEXT *)&stream)))
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        *CompletionContext = stream; /* reference released in PostWrite */
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
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

    if (ctx == NULL)
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        /* CompletionContext is a stream context here, see PreWrite. The
         * stream holds its own reference, so this release is never the last. */
        if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
            AccountPagingWrite(Data, FltObjects, (PADSG_STREAM_CONTEXT)(PVOID)ctx);
        FltReleaseContext(ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
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

/* SetEndOfFile (truncation or extension) and allocation size changes
 * through NtSetInformationFile. Only handles that carry a
 * context (named stream opened for write) are considered. The lazy writer's
 * AdvanceOnly end-of-file updates and paging I/O are internal bookkeeping and
 * are skipped. */
static FLT_PREOP_CALLBACK_STATUS FLTAPI PreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    PADSG_HANDLE_CONTEXT ctx = NULL;
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    *CompletionContext = NULL;
    if (cls != FileEndOfFileInformation && cls != FileAllocationInformation)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (cls == FileEndOfFileInformation && Data->Iopb->Parameters.SetFileInformation.AdvanceOnly)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->Iopb->Parameters.SetFileInformation.Length < sizeof(LARGE_INTEGER) ||
        g.ClientPort == NULL || IsCollector(Data))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,
                                              (PFLT_CONTEXT *)&ctx)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    *CompletionContext = ctx; /* reference released in PostSetInformation */
    /* Synchronize: the post callback runs in this thread, after the file
     * system completed the request, at the IRQL of this callback. */
    return FLT_PREOP_SYNCHRONIZE;
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI PostSetInformation(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PADSG_HANDLE_CONTEXT ctx = (PADSG_HANDLE_CONTEXT)CompletionContext;
    PFLT_FILE_NAME_INFORMATION info = NULL;
    ADSG_EVENT_INFO ev;
    ULONG nameFlags = 0;

    if (ctx == NULL)
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) || !NT_SUCCESS(Data->IoStatus.Status)) {
        FltReleaseContext(ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    /* Name and size queries and FltSendMessage need PASSIVE_LEVEL. A
     * synchronized post callback runs at the pre callback's IRQL, which is
     * PASSIVE_LEVEL for requests from user mode; anything else is counted. */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        if (g.ClientPort != NULL)
            InterlockedIncrement(&g.DroppedEvents);
        FltReleaseContext(ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    RtlZeroMemory(&ev, sizeof(ev));
    ev.Operation = AdsGuardSetSize;
    ev.InfoClass = (ULONG)Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    /* FILE_END_OF_FILE_INFORMATION and FILE_ALLOCATION_INFORMATION are both
     * a single LARGE_INTEGER; the length was checked in the pre callback. */
    ev.RequestedSize = ((PLARGE_INTEGER)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->QuadPart;
    ev.Process = FltGetRequestorProcess(Data);
    ev.Access = ctx->DesiredAccess;
    ev.HandleOpenTime = ctx->OpenTime;
    FltReleaseContext(ctx);

    if (NT_SUCCESS(GetNameInfo(Data, &info, &nameFlags))) {
        if (IsNamedDataStream(&info->Stream)) {
            ev.Flags = nameFlags;
            SendEvent(FltObjects, &info->Name, HostChars(info), &ev);
        }
        FltReleaseFileNameInformation(info);
    } else if (g.ClientPort != NULL) {
        InterlockedIncrement(&g.DroppedEvents);
    }
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
    { FLT_STREAM_CONTEXT, 0, StreamContextCleanup, sizeof(ADSG_STREAM_CONTEXT), ADSG_TAG },
    { FLT_CONTEXT_END }
};

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, PostCreate },
    { IRP_MJ_WRITE, 0, PreWrite, PostWrite },
    { IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreSetInformation, PostSetInformation },
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
