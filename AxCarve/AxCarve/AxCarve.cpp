# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <eddy (dot) maaalou (at) gmail (dot) com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.   Fist0urs
# ----------------------------------------------------------------------------

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>

#define FILE_SHARE_VALID_FLAGS 0x00000007

HANDLE hHeap;
HANDLE hFile;

BOOL
IsFileWrittable (
_In_ TCHAR* myFile,
_Inout_ HANDLE* hdFile
)
{
    *hdFile = CreateFile(
        myFile,
        GENERIC_READ | GENERIC_WRITE,
        NULL,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
        );

    if (*hdFile == INVALID_HANDLE_VALUE)
    {
        DWORD dwError = GetLastError();
        return false;
    }
    else
        return true;
}

/* must delete buffer after use */
LPTSTR
CHARtoLPTSTR (_In_ CHAR* toConvert)
{
    DWORD swSizeInput = strlen(toConvert) + 1;
    DWORD size = swSizeInput * 2;
    DWORD ret = 0;
    size_t dwCharsWritten = 0;
    LPTSTR Buff = new TCHAR[size];

    ret = mbstowcs_s(&dwCharsWritten, Buff, size, (const CHAR*)toConvert, size);

    if (!ret && dwCharsWritten == swSizeInput)
        return Buff;
    else
        return NULL;
}

BOOL
WriteToMyFile (
_In_ HANDLE hdFile,
_In_ CONST CHAR* msg
)
{
    BOOL bReturn = FALSE;
    DWORD dwNumberOfBytesWritten;
    if (hdFile)
    {
        DWORD dwLen = strlen(msg);
        bReturn = WriteFile(
            hdFile,
            msg,
            dwLen,
            &dwNumberOfBytesWritten,
            NULL
            );
        DWORD dwError = GetLastError();
    }
    return bReturn;
}


DWORD
FindHashes (
_In_ BYTE* szDump,
_In_ DWORD dwSizeDump
)
{
    CHAR szHash[34];
    memset(szHash, 0, sizeof(szHash));

    for (DWORD i = 0; i <= dwSizeDump - 0x19; i++)
    {
        if (szDump[i] == '\x19' && !memcmp(szDump + i + 1, (BYTE*)("\x00\x00\x00\x00\x00\x00\x00"), 7))
        {
            DWORD j = 0;
            for (; j<16; j++)
                sprintf_s(szHash + j * 2, 3, "%02x", (CHAR *)szDump[i + j + 8]);
            szHash[32] = '\n';

            WriteToMyFile(hFile, szHash);

            i += 0x17;
        }
    }
    return true;
}


PTCHAR
RetrieveCache (_In_ TCHAR* szPhysicalDrivepath)
{
    HANDLE hDevice;

    DWORD dwError;

    BYTE* bBuffer = (BYTE *)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 1024 * 1024 + 1);

    DWORD dwBytesread;
    DWORD dwSizeDump;

    hDevice = CreateFile(szPhysicalDrivepath,
        GENERIC_READ,
        FILE_SHARE_VALID_FLAGS,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS| FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
        );

    if (hDevice == INVALID_HANDLE_VALUE)
        return NULL;

    dwError = SetFilePointer(hDevice, 0, NULL, FILE_BEGIN);

    while (true)
    {
        if (!ReadFile(hDevice, bBuffer, 512, &dwBytesread, NULL))
        {
            dwError = GetLastError();
            wprintf(L"error  %d", dwError);
            HeapFree(hHeap, HEAP_ZERO_MEMORY, bBuffer);
            CloseHandle(hDevice);
            return NULL;
        }

        /* search for signature */
        if(bBuffer[0]==0x39)
            if (!memcmp(bBuffer, "\x39\x00\x00\x00", 4)
                &&
                !memcmp(bBuffer + 16,
                "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                12)
                )
            {
                BYTE* bAxCryptCacheFile = (BYTE *)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 1024 * 1024 + 1);

                dwSizeDump = dwBytesread;
                memcpy(bAxCryptCacheFile, bBuffer, 512);

                ReadFile(hDevice, bBuffer, 1024 * 1024 - 512, &dwBytesread, NULL);
                memcpy(bAxCryptCacheFile + 512, bBuffer, 1024 * 1024 - 512);
                bAxCryptCacheFile[1024 * 1024] = '\0';

                dwSizeDump += dwBytesread;

                FindHashes(bAxCryptCacheFile, dwSizeDump);
                HeapFree(hHeap, HEAP_ZERO_MEMORY, bAxCryptCacheFile);
            }
    }

    HeapFree(hHeap, HEAP_ZERO_MEMORY, bBuffer);

    CloseHandle(hDevice);
}


BOOL
RetrieveComputerName (_Inout_ CHAR* szComputerNameNetBIOS)
{
    DWORD sizeComputer = MAX_COMPUTERNAME_LENGTH + 1;

    if (!GetComputerNameExA(ComputerNameNetBIOS, szComputerNameNetBIOS, &sizeComputer))
        return 0;

    return 1;
        
}


DWORD
main(VOID)
{
    hHeap = HeapCreate(0, 10, 0);

    TCHAR szTempDirectory[MAX_PATH];
    TCHAR szDestinationFile[MAX_PATH];

    DWORD dwError = ExpandEnvironmentStrings(
        _T("%TMP%"),
        szTempDirectory,
        MAX_PATH);

    CHAR ComputerNameNetBIOS[MAX_COMPUTERNAME_LENGTH + 1];
    if (!RetrieveComputerName(ComputerNameNetBIOS))
    {
        HeapDestroy(hHeap);
        return 1;
    }

    LPTSTR szComputerNameNetBIOS = CHARtoLPTSTR(ComputerNameNetBIOS);

    _snwprintf_s(szDestinationFile, 
                wcslen(szTempDirectory) + wcslen(szComputerNameNetBIOS) + 1 + 1 + 4, 
                _T("%s\\%s.txt"), 
                szTempDirectory, 
                szComputerNameNetBIOS);

    delete[] szComputerNameNetBIOS;

    if (IsFileWrittable(szDestinationFile, &hFile))
        RetrieveCache(_T("\\\\.\\PHYSICALDRIVE0"));
    else
    {
        HeapDestroy(hHeap);
        CloseHandle(hFile);
        return 1;
    }

    HeapDestroy(hHeap);
    CloseHandle(hFile);
    return 0;
}