#include "Utils.h"

ULONG64 GetKernelModuleBase(const char* ModuleName, ULONG64& ModuleSize)
{
    if (ModuleName == nullptr)
    {
        ModuleSize = 0;
        return 0;
    }

    NTSTATUS status = STATUS_SUCCESS;
    RTL_PROCESS_MODULES modules = { 0 };
    PRTL_PROCESS_MODULES pModules = &modules;
    ULONG retLen = 0;

    bool isAllocated = false;

    status = ZwQuerySystemInformation(SystemModuleInformation, pModules, sizeof(RTL_PROCESS_MODULES), &retLen);
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        pModules = reinterpret_cast<PRTL_PROCESS_MODULES>(ExAllocatePool(PagedPool, retLen));
        if (pModules == nullptr)
        {
            return 0;
        }

        memset(pModules, 0, retLen);

        status = ZwQuerySystemInformation(SystemModuleInformation, pModules, retLen, &retLen);
        if (!NT_SUCCESS(status))
        {
            ExFreePool(pModules);
            return 0;
        }

        isAllocated = true;
    }

    ULONG64 moduleBase = 0;
    PCHAR tmpName = nullptr;

    do {

        ULONG64 moduleNameSize = strlen(ModuleName) + 1;
        tmpName = static_cast<PCHAR>(ExAllocatePool(PagedPool, moduleNameSize));

        memcpy(tmpName, ModuleName, moduleNameSize);

        for (ULONG64 i = 0; i < pModules->NumberOfModules; i++)
        {
            PRTL_PROCESS_MODULE_INFORMATION moduleInfo = &pModules->Modules[i];

            PCHAR name = _strupr(reinterpret_cast<char*>(moduleInfo->FullPathName));
            PCHAR targetName = _strupr(tmpName);

            if (strstr(name, targetName))
            {
                moduleBase = (ULONG64)moduleInfo->ImageBase;
                ModuleSize = moduleInfo->ImageSize;

                break;
            }

        }

    } while (false);

    if (isAllocated)
    {
        ExFreePool(pModules);
    }

    ExFreePool(tmpName);

    return moduleBase;
}