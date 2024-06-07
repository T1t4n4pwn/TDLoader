#pragma once
#include <ntifs.h>
#include <ntimage.h>

class DrvMemLoader {
public:

    typedef NTSTATUS(*DriverEntry_t)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

    DrvMemLoader() : m_imageBuffer(nullptr), m_pDos(nullptr), m_pNt(nullptr)
    {
        
    }

    ~DrvMemLoader() 
    {

    }

    bool InitDrv(PUCHAR Data, ULONG64 Size);

    void FixImageBase();

    void FixReloc();

    void FixIAT();

    void FixSecurityCookie();

    bool CallEntryPoint(bool clear = true);

    PUCHAR GetImageBuffer()
    {
        return m_imageBuffer;
    }

private:
    PUCHAR m_imageBuffer;
    PIMAGE_DOS_HEADER m_pDos;
    PIMAGE_NT_HEADERS m_pNt;
    size_t m_bufferSize;
};