#include <ntifs.h>
#include "Utils.h"

#include "DrvMemLoader.h"
#include "TestDrv.h"

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;

    DriverObject->DriverUnload = DriverUnload;

    DrvMemLoader loader;

    loader.InitDrv(data, sizeof(data));

    loader.FixReloc();

    loader.FixIAT();

    loader.FixSecurityCookie();

    loader.CallEntryPoint();

    return STATUS_UNSUCCESSFUL;
}