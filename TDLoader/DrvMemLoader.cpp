#include "DrvMemLoader.h"
#include "Utils.h"

bool DrvMemLoader::InitDrv(PUCHAR Data, ULONG64 Size)
{
    PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(Data);
    PIMAGE_NT_HEADERS pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(Data + pDos->e_lfanew);

    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }

    if (pNt->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    ULONG64 imageSize = pNt->OptionalHeader.SizeOfImage;

    m_imageBuffer = static_cast<PUCHAR>(ExAllocatePool(NonPagedPool, imageSize));

    memset(m_imageBuffer, 0, imageSize);
    memcpy(m_imageBuffer, Data, pNt->OptionalHeader.SizeOfHeaders);

    ULONG64 sectionNum = pNt->FileHeader.NumberOfSections;

    PIMAGE_SECTION_HEADER crtSection = IMAGE_FIRST_SECTION(pNt);

    for (ULONG64 i = 0; i < sectionNum; i++)
    {

        memcpy(m_imageBuffer + crtSection->VirtualAddress, Data + crtSection->PointerToRawData, crtSection->SizeOfRawData);

        crtSection++;
    }

    m_pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(m_imageBuffer);
    m_pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(m_imageBuffer + m_pDos->e_lfanew);

    return true;
}

void DrvMemLoader::FixReloc()
{
    if (m_imageBuffer == nullptr)
    {
        return;
    }

    typedef struct {
        UINT32 Offset : 12;
        UINT32 Type : 4;
    }RELOC_BLOCK, * PRELOC_BLOCK;

    PIMAGE_DATA_DIRECTORY pDir = &m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    PIMAGE_BASE_RELOCATION pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(m_imageBuffer + pDir->VirtualAddress);

    while (pReloc->VirtualAddress && pReloc->SizeOfBlock)
    {

        PRELOC_BLOCK blocks = reinterpret_cast<PRELOC_BLOCK>(m_imageBuffer + pReloc->VirtualAddress + sizeof(IMAGE_BASE_RELOCATION));

        UINT64 relocNum = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOC_BLOCK);

        for (size_t i = 0; i < relocNum; i++)
        {
            if (blocks[i].Type == IMAGE_REL_BASED_DIR64)
            {
                PINT64 address = reinterpret_cast<PINT64>(m_imageBuffer + pReloc->VirtualAddress + blocks[i].Offset);
                *address = reinterpret_cast<INT64>(m_imageBuffer + (*address - m_pNt->OptionalHeader.ImageBase));
            }
        }

        pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(m_imageBuffer + pReloc->SizeOfBlock);
    }
    

}

void DrvMemLoader::FixIAT()
{
    if (m_imageBuffer == nullptr)
    {
        return;
    }

    PIMAGE_DATA_DIRECTORY pDir = &m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(m_imageBuffer + pDir->VirtualAddress);

    bool isSuccess = true;

    for (; pImportDesc->Name; pImportDesc++)
    {

        isSuccess = true;

        PCHAR libName = reinterpret_cast<PCHAR>(m_imageBuffer + pImportDesc->Name);
        
        ULONG64 moduleSize = 0;

        ULONG64 moduleBase = GetKernelModuleBase(libName, moduleSize);
        if (moduleBase == 0) {
            break;
        }

        PIMAGE_THUNK_DATA pThunkName = reinterpret_cast<PIMAGE_THUNK_DATA>(m_imageBuffer + pImportDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pThunkFunc = reinterpret_cast<PIMAGE_THUNK_DATA>(m_imageBuffer + pImportDesc->FirstThunk);

        for (; pThunkName->u1.ForwarderString; pThunkName++, pThunkFunc++)
        {
            PIMAGE_IMPORT_BY_NAME funcName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(m_imageBuffer + pThunkName->u1.AddressOfData);
            ULONG64 funcVA = (ULONG64)RtlFindExportedRoutineByName((PVOID)moduleBase, funcName->Name);

            if (funcVA) 
            {
                pThunkFunc->u1.Function = funcVA;
            }
            else 
            {
                isSuccess = false;
                break;
            }
        }

        if (isSuccess) 
        {
            continue;
        }

    }

    return;
}

void DrvMemLoader::FixSecurityCookie()
{
    if (m_imageBuffer == nullptr)
    {
        return;
    }



    PIMAGE_DATA_DIRECTORY pDir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]);

    PIMAGE_LOAD_CONFIG_DIRECTORY pCfg = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>(m_imageBuffer + pDir->VirtualAddress);

    PINT64 pCookie = reinterpret_cast<PINT64>(m_imageBuffer + (pCfg->SecurityCookie & 0xFFFFFF));

    *pCookie ^= 0x39;
}

bool DrvMemLoader::CallEntryPoint(bool clear)
{

    DriverEntry_t entrypoint = 
        reinterpret_cast<DriverEntry_t>(m_imageBuffer + m_pNt->OptionalHeader.AddressOfEntryPoint);

    NTSTATUS status = entrypoint(nullptr, nullptr);

    if (clear) {
        memset(m_imageBuffer, 0, PAGE_SIZE);
    }

    return NT_SUCCESS(status);
}
