#include <fltKernel.h>
#include <ntstrsafe.h>
#include "Protocol.h"

PFLT_FILTER gFilter;
PFLT_PORT gServerPort;
PFLT_PORT gClientPort;
EX_PUSH_LOCK gPortLock;
NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
static VOID FLTAPI PostWriteWorker(PFLT_DEFERRED_IO_WORKITEM WorkItem,
    PFLT_CALLBACK_DATA Data, PVOID Context);

static NTSTATUS ConnectNotify(PFLT_PORT ClientPort, PVOID ServerPortCookie,
                              PVOID ConnectionContext, ULONG SizeOfContext,
                              PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gPortLock);
    gClientPort = ClientPort;
    ExReleasePushLockExclusive(&gPortLock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

static VOID DisconnectNotify(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gPortLock);
    if (gClientPort) {
        FltCloseClientPort(gFilter, &gClientPort);
    }
    ExReleasePushLockExclusive(&gPortLock);
    KeLeaveCriticalRegion();
}

static NTSTATUS MessageNotify(PVOID ConnectionCookie, PVOID InputBuffer,
                              ULONG InputBufferLength, PVOID OutputBuffer,
                              ULONG OutputBufferLength, PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
}

static BOOLEAN IsNamedStream(PFLT_CALLBACK_DATA Data)
{
    PFLT_FILE_NAME_INFORMATION info = NULL;
    BOOLEAN named = FALSE;
    if (NT_SUCCESS(FltGetFileNameInformation(Data,
          FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &info))) {
        if (NT_SUCCESS(FltParseFileNameInformation(info))) {
            named = info->Stream.Length > sizeof(WCHAR) && info->Stream.Buffer[0] == L':' &&
                    info->Stream.Buffer[1] != L':';
        }
        FltReleaseFileNameInformation(info);
    }
    return named;
}

static VOID SendEvent(PFLT_CALLBACK_DATA Data, ULONG Operation)
{
    PFLT_FILE_NAME_INFORMATION info = NULL;
    FILE_STANDARD_INFORMATION standard = {0};
    LARGE_INTEGER now;
    ADSG_EVENT event = {0};
    ULONG returned = 0;
    ULONG lengthReturned = 0;
    NTSTATUS status;
    LARGE_INTEGER timeout;
    USHORT fileChars;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL || KeAreAllApcsDisabled())
        return;

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &info);
    if (!NT_SUCCESS(status)) return;
    status = FltParseFileNameInformation(info);
    if (!NT_SUCCESS(status) || info->Stream.Length == 0) {
        FltReleaseFileNameInformation(info);
        return;
    }

    event.Version = ADSG_PROTOCOL_VERSION;
    event.Size = sizeof(event);
    event.Operation = Operation;
    event.ProcessId = FltGetRequestorProcessId(Data);
    KeQuerySystemTimePrecise(&now);
    event.Timestamp100ns = now.QuadPart;
    status = IoGetTopLevelIrp() == NULL && !KeAreAllApcsDisabled()
        ? FltQueryInformationFile(Data->Iopb->TargetInstance,
            Data->Iopb->TargetFileObject, &standard, sizeof(standard),
            FileStandardInformation, &lengthReturned)
        : STATUS_INVALID_DEVICE_STATE;
    event.SizeQueryStatus = status;
    if (NT_SUCCESS(status)) event.StreamSize = (ULONGLONG)standard.EndOfFile.QuadPart;
    else event.Flags |= ADSG_FLAG_SIZE_UNAVAILABLE;

    fileChars = (USHORT)((info->Name.Length - info->Stream.Length) / sizeof(WCHAR));
    if (info->Name.Length / sizeof(WCHAR) >= ADSG_NAME_CHARS || fileChars >= ADSG_NAME_CHARS) {
        event.Flags |= ADSG_FLAG_PATH_TRUNCATED;
    }
    RtlStringCchCopyNW(event.StreamName, ADSG_NAME_CHARS, info->Name.Buffer,
                       info->Name.Length / sizeof(WCHAR));
    RtlStringCchCopyNW(event.FileName, ADSG_NAME_CHARS, info->Name.Buffer, fileChars);
    FltReleaseFileNameInformation(info);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gPortLock);
    if (gClientPort) {
        timeout.QuadPart = -100000;
        status = FltSendMessage(gFilter, &gClientPort, &event, sizeof(event),
            NULL, &returned, &timeout);
        UNREFERENCED_PARAMETER(status);
    }
    ExReleasePushLockShared(&gPortLock);
    KeLeaveCriticalRegion();
}

static FLT_PREOP_CALLBACK_STATUS PreCreate(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        // Report successful creates from the post callback, after the stream exists.
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS PostCreate(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (NT_SUCCESS(Data->IoStatus.Status) && IsNamedStream(Data))
        SendEvent(Data, Data->IoStatus.Information == FILE_OPENED ? AdsGuardOpen : AdsGuardCreate);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_POSTOP_CALLBACK_STATUS PostWrite(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    PFLT_DEFERRED_IO_WORKITEM workItem;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    // File name and information queries require PASSIVE_LEVEL. Process the
    // rare passive callback directly; defer eligible IRP completions otherwise.
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        if (IsNamedStream(Data)) SendEvent(Data, AdsGuardWrite);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!FLT_IS_IRP_OPERATION(Data))
        return FLT_POSTOP_FINISHED_PROCESSING;

    workItem = FltAllocateDeferredIoWorkItem();
    if (workItem == NULL) return FLT_POSTOP_FINISHED_PROCESSING;
    status = FltQueueDeferredIoWorkItem(workItem, Data, PostWriteWorker,
                                        DelayedWorkQueue, NULL);
    if (NT_SUCCESS(status)) return FLT_POSTOP_MORE_PROCESSING_REQUIRED;
    FltFreeDeferredIoWorkItem(workItem);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static VOID FLTAPI PostWriteWorker(PFLT_DEFERRED_IO_WORKITEM WorkItem,
    PFLT_CALLBACK_DATA Data, PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    if (NT_SUCCESS(Data->IoStatus.Status) && IsNamedStream(Data))
        SendEvent(Data, AdsGuardWrite);
    FltCompletePendedPostOperation(Data);
    FltFreeDeferredIoWorkItem(WorkItem);
}

static CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, PostCreate },
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, NULL, PostWrite },
    { IRP_MJ_OPERATION_END }
};

static NTSTATUS InstanceSetup(PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    return VolumeFilesystemType == FLT_FSTYPE_NTFS ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}

static CONST FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, Callbacks,
    DriverUnload, InstanceSetup, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    FltCloseCommunicationPort(gServerPort);
    FltUnregisterFilter(gFilter);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(ADSG_PORT_NAME);
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd = NULL;
    ExInitializePushLock(&gPortLock);
    status = FltRegisterFilter(DriverObject, &Registration, &gFilter);
    if (!NT_SUCCESS(status)) return status;
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) goto fail;
    InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, sd);
    status = FltCreateCommunicationPort(gFilter, &gServerPort, &oa, NULL,
        ConnectNotify, DisconnectNotify, MessageNotify, 1);
    FltFreeSecurityDescriptor(sd);
    if (!NT_SUCCESS(status)) goto fail;
    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        goto fail;
    }
    UNREFERENCED_PARAMETER(RegistryPath);
    return STATUS_SUCCESS;
fail:
    FltUnregisterFilter(gFilter);
    return status;
}
