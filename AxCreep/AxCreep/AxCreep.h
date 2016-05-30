# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <eddy (dot) maaalou (at) gmail (dot) com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.   Fist0urs
# ----------------------------------------------------------------------------

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define PH_LARGE_BUFFER_SIZE (256 * 1024 * 1024)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS 0x00000000L

typedef enum _FILE_INFORMATION_CLASS {
    FileNameInformation = 9,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;


typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS,
    MaxPoolType,
    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
} POOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING Name;
    ULONG ObjectCount;
    ULONG HandleCount;
    ULONG Reserved1[4];
    ULONG PeakObjectCount;
    ULONG PeakHandleCount;
    ULONG Reserved2[4];
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    UCHAR Unknown;
    BOOLEAN MaintainHandleDatabase;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectTypeInformation = 2,
} OBJECT_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemExtendedHandleInformation = 64,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

DWORD GetProcessList(VOID);

VOID printError (_In_ TCHAR* msg);

DWORD
FindHashes (
     _In_ BYTE* szDump, 
     _In_ DWORD dwSizeDump
     );

DWORD
FindFileCachedHandle (
        _In_ HANDLE hProcSource, 
        _In_ HANDLE hTestedHandle, 
        _In_ TCHAR* szNameHandleDesired
        );

NTSTATUS 
PhEnumHandlesEx (
      _Out_ PSYSTEM_HANDLE_INFORMATION_EX *Handles
      );

DWORD
PhEnumHandlesGeneric (
    _In_ HANDLE hTargetProcess,
    _Out_ PSYSTEM_HANDLE_INFORMATION_EX *Handles,
    _Out_ PBOOLEAN FilterNeeded
    );