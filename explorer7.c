/*
 * explorer7.c - In-place image-replacement loader for Explorer7 on Windows 10 (x64)
 * ---------------------------------------------------------------------------------
 * Replaces the in-memory image of explorer.exe with the Windows 7 explorer.exe
 * during DLL_PROCESS_VERIFIER, which fires inside LdrpInitializeProcess BEFORE the
 * loader snaps the main executable's imports (LdrpInitializeGraphRecurse). The
 * loader then walks the Win7 import descriptors and snaps the IAT for us.
 *
 * The process image path stays genuinely %windir%\explorer.exe at every level
 * (EPROCESS, PEB, NtQueryInformationProcess, WMI, Task Manager, shell pinning)
 * because the process WAS created from that file.
 *
 * REGISTRY SETUP:
 *   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
 *     Image File Execution Options\explorer.exe
 *       GlobalFlag    (REG_DWORD) = 0x100          ; FLG_APPLICATION_VERIFIER
 *       VerifierDlls  (REG_SZ)    = explorer7      ; -> explorer7.dll
 *       Explorer7Path (REG_SZ)    = C:\explorer7   ; folder holding Win7 explorer.exe
 *
 * FILE LAYOUT (under Explorer7Path):
 *   explorer.exe                - Windows 7 explorer (x64)
 *   en-US\explorer.exe.mui      - Windows 7 MUI resources  (see MUI note at bottom)
 *
 * DLL PLACEMENT:
 *   explorer7.dll -> %windir%\System32 (or anywhere on the DLL search path).
 *
 * COMPILE (x64 VS Developer Command Prompt) - self-contained, only needs the
 * Windows SDK (no phnt):
 *   cl /nologo /O2 /W3 /GS- /Zl explorer7.c /LD /Fe:explorer7.dll ^
 *      /link /NODEFAULTLIB /ENTRY:DllMain ntdll.lib
 *   (or just run build.bat, which finds MSVC for you.)
 *
 * WHY THE PREVIOUS ATTEMPT WAS BUGGY - the six things this file gets right:
 *   1. SizeOfImage fit-check. The kernel reserved exactly the *Win10* image's
 *      SizeOfImage at DllBase. If the Win7 image is larger, mapping its sections
 *      in place runs off the reservation and corrupts whatever follows. We read
 *      the live header first, compare, and only map in place when it fits; else
 *      we fail loudly (a silent overrun is the classic "random crash").
 *   2. Base relocations. Win7 explorer is based at 0x100000000 but the live image
 *      is at an ASLR base, so delta != 0. We process IMAGE_DIRECTORY_ENTRY_BASERELOC
 *      against (DllBase - 0x100000000). Assuming delta==0 crashes on the first
 *      absolute global.
 *   3. Bound imports. The shipped Win7 explorer HAS a non-empty Bound Import
 *      directory. If ntdll trusts a stale bind it will not snap correctly. We zero
 *      DIR[11] in the swapped-in optional header so the loader does a clean snap.
 *   4. LDR_DATA_TABLE_ENTRY fix-up. EntryPoint/SizeOfImage were cached from the
 *      Win10 header at map time. We repoint EntryPoint = DllBase + newEntryRVA and
 *      update SizeOfImage, else ntdll jumps into the Win7 image at the Win10 RVA.
 *   5. Section protections + i-cache. We map RW, copy, then restore RX/R/RW per
 *      section characteristics and flush the instruction cache over the region.
 *   6. No CRT / native-only. Uses ntdll native API and ntdll's exported memcpy/
 *      memset so it links with /NODEFAULTLIB and runs this early in process init.
 */

#include <windows.h>
#include <intrin.h>

/* ---------------------------------------------------------------------------
 * Self-contained native (NT) declarations.
 *
 * This loader runs at DLL_PROCESS_VERIFIER - long before the CRT or kernel32
 * are usable - so it talks only to ntdll. Instead of depending on the external
 * phnt package, we declare the small subset of NT types/prototypes we use.
 * Every struct here uses the documented, ABI-stable x64 (AMD64) layout.
 * -------------------------------------------------------------------------*/

#ifndef DLL_PROCESS_VERIFIER
#define DLL_PROCESS_VERIFIER 4
#endif

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentPeb()     ((PPEB)__readgsqword(0x60))

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define OBJ_CASE_INSENSITIVE 0x00000040L

/* NtCreateFile/NtOpenFile CreateOptions (from wdm.h, not in user-mode SDK). */
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE      0x00000040

#define InitializeObjectAttributes(p, n, a, r, s) do { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);           \
    (p)->RootDirectory = (r);                          \
    (p)->ObjectName = (n);                             \
    (p)->Attributes = (a);                             \
    (p)->SecurityDescriptor = (s);                     \
    (p)->SecurityQualityOfService = NULL;              \
} while (0)

typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS { FileStandardInformation = 5 } FILE_INFORMATION_CLASS;
typedef enum _KEY_VALUE_INFORMATION_CLASS { KeyValuePartialInformation = 2 } KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

/* --- PEB / loader structures (x64 offsets in comments) ------------------- */
typedef struct _PEB_LDR_DATA {
    BYTE       Reserved[0x10];         /* Length, Initialized, SsHandle */
    LIST_ENTRY InLoadOrderModuleList;  /* +0x10 */
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE          Reserved[0x18];      /* InheritedAddressSpace .. ImageBaseAddress */
    PPEB_LDR_DATA Ldr;                 /* +0x18 */
    PVOID         ProcessParameters;   /* +0x20 (RTL_USER_PROCESS_PARAMETERS) */
} PEB, *PPEB;

/* RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING) on x64. */
#define RTL_UPP_COMMANDLINE_OFFSET 0x70

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;          /* +0x00 */
    LIST_ENTRY     InMemoryOrderLinks;        /* +0x10 */
    LIST_ENTRY     InInitializationOrderLinks;/* +0x20 */
    PVOID          DllBase;                   /* +0x30 */
    PVOID          EntryPoint;                /* +0x38 */
    ULONG          SizeOfImage;               /* +0x40 */
    UNICODE_STRING FullDllName;               /* +0x48 */
    UNICODE_STRING BaseDllName;               /* +0x58 (remainder unused) */
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/* --- ntdll native prototypes (resolved via ntdll.lib) ------------------- */
NTSTATUS NTAPI NtClose(HANDLE Handle);
NTSTATUS NTAPI NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NTAPI NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName,
                               KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                               PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
NTSTATUS NTAPI NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                          POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
                          ULONG ShareAccess, ULONG OpenOptions);
NTSTATUS NTAPI NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                                      PVOID FileInformation, ULONG Length,
                                      FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS NTAPI NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
                          PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
                          PLARGE_INTEGER ByteOffset, PULONG Key);
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                       PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                   PSIZE_T RegionSize, ULONG FreeType);
NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
                                      ULONG NewProtect, PULONG OldProtect);
NTSTATUS NTAPI NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);
VOID     NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

NTSTATUS NTAPI LdrGetProcedureAddress(PVOID DllHandle, PANSI_STRING ProcedureName,
                                      ULONG ProcedureNumber, PVOID *ProcedureAddress);

/* --- CFG (Control Flow Guard) call-target marking -----------------------------
 * The process is created from the CFG-enabled Win10 explorer.exe (the on-disk
 * image opts into GUARD_CF), so the kernel enforces CFG and built the process
 * call-target bitmap from Win10's guard function table. After we swap in the
 * (non-CFG) Win7 image in place, guarded indirect calls from system DLLs into
 * Win7 code (window procedures, callbacks) target addresses whose bits are
 * clear in that bitmap and would fast-fail (FAST_FAIL_GUARD_ICALL_CHECK_FAILURE).
 * We re-mark the Win7 code as valid using the same ntdll syscall ntdll itself
 * uses (NtSetInformationVirtualMemory / VmCfgCallTargetInformation). Structs are
 * declared locally to keep this a self-contained, ntdll-only DLL. */
#define VmCfgCallTargetInformation 2
#define E7_CFG_CALL_TARGET_VALID   1
typedef struct _E7_MEMORY_RANGE_ENTRY {
    PVOID  VirtualAddress;
    SIZE_T NumberOfBytes;
} E7_MEMORY_RANGE_ENTRY, *PE7_MEMORY_RANGE_ENTRY;
typedef struct _E7_CFG_CALL_TARGET_INFO {
    ULONG_PTR Offset;
    ULONG_PTR Flags;
} E7_CFG_CALL_TARGET_INFO;
typedef struct _E7_CFG_CALL_TARGET_LIST_INFORMATION {
    ULONG                    NumberOfEntries;
    ULONG                    Reserved;
    PULONG                   NumberOfEntriesProcessed;
    E7_CFG_CALL_TARGET_INFO *CallTargetInfo;
    PVOID                    Section;
    ULONGLONG                FileOffset;
} E7_CFG_CALL_TARGET_LIST_INFORMATION;
NTSTATUS NTAPI NtSetInformationVirtualMemory(HANDLE ProcessHandle, ULONG VmInformationClass,
                                             ULONG_PTR NumberOfEntries, PE7_MEMORY_RANGE_ENTRY VirtualAddresses,
                                             PVOID VmInformation, ULONG InformationLength);

#ifdef _DEBUG
ULONG __cdecl DbgPrint(PCSTR Format, ...);
#endif

/* No CRT under /NODEFAULTLIB, and the SDK's ntdll.lib does not export
 * memcpy/memset as importable symbols. Provide our own. #pragma function
 * disables the intrinsic so /O2 loop-idiom recognition cannot turn the byte
 * loops below back into memcpy/memset calls (which would recurse / not link). */
#pragma function(memcpy, memset)
void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}
void *memset(void *dst, int v, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)v;
    return dst;
}

#ifdef _DEBUG
#define LOG(fmt, ...) DbgPrint("[explorer7] " fmt "\n", __VA_ARGS__)
#else
#define LOG(fmt, ...) ((void)0)
#endif

/* ---- Application Verifier provider descriptor -----------------------------
 * On DLL_PROCESS_VERIFIER, ntdll passes the address at which the provider must
 * store a pointer to its RTL_VERIFIER_PROVIDER_DESCRIPTOR. ntdll then walks
 * descriptor->ProviderDlls - an array of RTL_VERIFIER_DLL_DESCRIPTOR terminated
 * by an entry whose DllName is NULL - to chain thunks. ProviderDlls MUST point
 * at a valid array: a NULL ProviderDlls is dereferenced unconditionally in
 * AVrfpChainDuplicateVerificationLayers (it reads *ProviderDlls == the first
 * DllName) and crashes at process init. We want zero thunks, so we hand ntdll a
 * single all-zero terminator entry; its NULL DllName ends the walk before any
 * other field or thunk is read. (An all-zero descriptor with ProviderDlls==NULL
 * does NOT work - that was the startup crash this loader used to hit.)
 */
typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
    PWSTR DllName;    /* +0x00  NULL in this entry => array terminator */
    ULONG DllFlags;   /* +0x08 */
    PVOID DllAddress; /* +0x10 */
    PVOID DllThunks;  /* +0x18 */
} RTL_VERIFIER_DLL_DESCRIPTOR, *PRTL_VERIFIER_DLL_DESCRIPTOR;   /* stride 0x20 */

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
    ULONG Length;
    PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
    PVOID ProviderDllLoadCallback;
    PVOID ProviderDllUnloadCallback;
    PVOID VerifierImage;
    ULONG VerifierFlags;
    ULONG VerifierDebug;
    PVOID RtlpGetStackTraceAddress;
    PVOID RtlpDebugPageHeapCreate;
    PVOID RtlpDebugPageHeapDestroy;
    PVOID ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR;

/* One all-zero terminator: DllName==NULL ends ntdll's walk immediately, so the
 * provider registers with zero thunks. */
static RTL_VERIFIER_DLL_DESCRIPTOR g_ProviderDlls[1] = { { 0 } };

static RTL_VERIFIER_PROVIDER_DESCRIPTOR g_VerifierDescriptor = {
    sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR), /* Length == 0x50, required (ntdll checks == 80) */
    g_ProviderDlls                            /* ProviderDlls -> zeroed terminator (never NULL) */
};

/* Win7 x64 explorer preferred base - used only as a sanity assertion. */
#define WIN7_EXPLORER_IMAGEBASE 0x0000000100000000ULL

/* --------------------------------------------------------------------------
 * Read Explorer7Path from the IFEO key. Falls back to L"\\??\\C:\\explorer7".
 * Returns the number of WCHARs written to `out` (not counting NUL), 0 on failure.
 */
static ULONG ReadExplorer7Path(WCHAR *out, ULONG outCch)
{
    UNICODE_STRING keyName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS st;
    ULONG cch = 0;

    RtlInitUnicodeString(&keyName,
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        L"Image File Execution Options\\explorer.exe");
    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = NtOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
    if (NT_SUCCESS(st)) {
        UNICODE_STRING valName;
        BYTE buf[512];
        ULONG retLen = 0;
        RtlInitUnicodeString(&valName, L"Explorer7Path");
        st = NtQueryValueKey(hKey, &valName, KeyValuePartialInformation,
                             buf, sizeof(buf), &retLen);
        if (NT_SUCCESS(st)) {
            PKEY_VALUE_PARTIAL_INFORMATION pi = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
            if (pi->Type == REG_SZ && pi->DataLength >= sizeof(WCHAR)) {
                WCHAR *val = (WCHAR *)pi->Data;
                ULONG valCch = pi->DataLength / sizeof(WCHAR);
                /* "\??\" prefix so it is a valid NT object path. */
                const WCHAR *pfx = L"\\??\\";
                ULONG i = 0, j;
                for (j = 0; pfx[j] && cch < outCch - 1; j++) out[cch++] = pfx[j];
                for (i = 0; i < valCch && val[i] && cch < outCch - 1; i++)
                    out[cch++] = val[i];
                out[cch] = 0;
            }
        }
        NtClose(hKey);
    }

    if (cch == 0) {
        const WCHAR *def = L"\\??\\C:\\explorer7";
        while (def[cch] && cch < outCch - 1) { out[cch] = def[cch]; cch++; }
        out[cch] = 0;
    }
    return cch;
}

/* --------------------------------------------------------------------------
 * Read an entire file (NT path in `ntPath`) into a freshly committed buffer.
 * Returns base pointer + size, or NULL.
 */
static PVOID ReadWholeFile(const WCHAR *ntPath, SIZE_T *outSize)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS st;
    FILE_STANDARD_INFORMATION fsi;
    PVOID buf = NULL;
    SIZE_T size;

    RtlInitUnicodeString(&name, ntPath);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                    FILE_SHARE_READ,
                    FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(st)) { LOG("NtOpenFile 0x%08X", st); return NULL; }

    st = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi),
                                FileStandardInformation);
    if (!NT_SUCCESS(st)) { NtClose(hFile); return NULL; }

    size = (SIZE_T)fsi.EndOfFile.QuadPart;
    if (size == 0) { NtClose(hFile); return NULL; }

    {
        SIZE_T region = size;
        st = NtAllocateVirtualMemory(NtCurrentProcess(), &buf, 0, &region,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st)) { NtClose(hFile); return NULL; }
    }

    {
        LARGE_INTEGER off; off.QuadPart = 0;
        st = NtReadFile(hFile, NULL, NULL, NULL, &iosb, buf, (ULONG)size, &off, NULL);
        NtClose(hFile);
        if (!NT_SUCCESS(st) || iosb.Information != size) {
            SIZE_T z = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &buf, &z, MEM_RELEASE);
            return NULL;
        }
    }

    *outSize = size;
    return buf;
}

/* Locate the main-image LDR_DATA_TABLE_ENTRY (first in load order). */
static PLDR_DATA_TABLE_ENTRY GetMainModuleEntry(void)
{
    PPEB peb = NtCurrentPeb();
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    return CONTAINING_RECORD(head->Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
}

static ULONG SectionProtect(ULONG ch)
{
    BOOL x = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL w = (ch & IMAGE_SCN_MEM_WRITE)   != 0;
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x)      return PAGE_EXECUTE_READ;
    if (w)      return PAGE_READWRITE;
    return PAGE_READONLY;
}

/* ---- MUI / theme file redirection ----------------------------------------
 * The resource loader keys localized resources off the module's on-disk path,
 * which is genuinely %windir%\explorer.exe - so it opens
 * %windir%\<lang>\explorer.exe.mui, the *Win10* MUI. A .mui is checksum-bound to
 * its binary (the "MUI" resource in each carries a matching hash), so against
 * the swapped-in Win7 image that file fails verification and localized
 * resources come back empty. CTray::_SyncThreadProc then never publishes the
 * tray window, CreateDesktopAndTray() returns 0, and wWinMain exits(1) before
 * ever creating the desktop.
 *
 * Rather than change the module's identity, hook ntdll!NtOpenFile (the MUI open
 * happens inside ntdll itself, in LdrLoadAlternateResourceModuleEx ->
 * LdrMapAndVerifyResourceFile, so an IAT hook on the exe would not see it) and
 * rewrite just those opens to the Explorer7 directory. Same trick for the
 * inactive-msstyles "theme\" folder. Anything else passes straight through, and
 * a redirected open that fails falls back to the original path.
 */
typedef NTSTATUS (NTAPI *fn_NtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        PIO_STATUS_BLOCK, ULONG, ULONG);

static BYTE  *g_NtOpenFileTrampoline;
static WCHAR  g_WinDirNt[MAX_PATH];       static USHORT g_WinDirNtChars;
static WCHAR  g_WinThemeDirNt[MAX_PATH];  static USHORT g_WinThemeDirNtChars;
static WCHAR  g_Ex7DirNt[MAX_PATH];       static USHORT g_Ex7DirNtChars;
static WCHAR  g_Ex7ThemeDirNt[MAX_PATH];  static USHORT g_Ex7ThemeDirNtChars;
static const WCHAR  g_MuiFilename[] = L"explorer.exe.mui";
static const USHORT g_MuiFilenameChars = (USHORT)(sizeof(g_MuiFilename) / sizeof(WCHAR) - 1);

static WCHAR e7_upper(WCHAR c) { return (c >= L'a' && c <= L'z') ? (WCHAR)(c - L'a' + L'A') : c; }

static ULONG e7_wcslen(const WCHAR *s) { ULONG n = 0; while (s[n]) n++; return n; }

static BOOL e7_ends_with_i(const WCHAR *s, USHORT sChars, const WCHAR *suf, USHORT sufChars)
{
    USHORT i;
    if (sChars < sufChars) return FALSE;
    for (i = 0; i < sufChars; i++)
        if (e7_upper(s[sChars - sufChars + i]) != e7_upper(suf[i])) return FALSE;
    return TRUE;
}

static BOOL e7_starts_with_i(const WCHAR *s, USHORT sChars, const WCHAR *pfx, USHORT pfxChars)
{
    USHORT i;
    if (sChars <= pfxChars) return FALSE;
    for (i = 0; i < pfxChars; i++)
        if (e7_upper(s[i]) != e7_upper(pfx[i])) return FALSE;
    return TRUE;
}

/* Swap a matching <winPrefix> for <ex7Prefix>; returns FALSE if it doesn't match. */
static BOOL e7_Reprefix(PUNICODE_STRING name, const WCHAR *winPfx, USHORT winPfxChars,
                        const WCHAR *ex7Pfx, USHORT ex7PfxChars,
                        WCHAR *outBuf, USHORT outChars, PUNICODE_STRING outStr)
{
    USHORT nameChars = (USHORT)(name->Length / sizeof(WCHAR));
    USHORT suffixChars, totalChars, i;
    if (!e7_starts_with_i(name->Buffer, nameChars, winPfx, winPfxChars)) return FALSE;
    suffixChars = (USHORT)(nameChars - winPfxChars);
    totalChars  = (USHORT)(ex7PfxChars + suffixChars);
    if (totalChars >= outChars) return FALSE;
    for (i = 0; i < ex7PfxChars; i++) outBuf[i] = ex7Pfx[i];
    for (i = 0; i < suffixChars; i++) outBuf[ex7PfxChars + i] = name->Buffer[winPfxChars + i];
    outBuf[totalChars] = 0;
    outStr->Buffer        = outBuf;
    outStr->Length        = (USHORT)(totalChars * sizeof(WCHAR));
    outStr->MaximumLength = (USHORT)((totalChars + 1) * sizeof(WCHAR));
    return TRUE;
}

static NTSTATUS NTAPI Hook_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes,
                                      PIO_STATUS_BLOCK IoStatusBlock,
                                      ULONG ShareAccess, ULONG OpenOptions)
{
    fn_NtOpenFile orig = (fn_NtOpenFile)g_NtOpenFileTrampoline;

    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer && ObjectAttributes->ObjectName->Length)
    {
        PUNICODE_STRING nm = ObjectAttributes->ObjectName;
        USHORT nmChars = (USHORT)(nm->Length / sizeof(WCHAR));
        WCHAR rbuf[MAX_PATH * 2];
        UNICODE_STRING rstr;
        OBJECT_ATTRIBUTES roa;
        NTSTATUS st;

        /* ...\<lang>\explorer.exe.mui under %windir% -> Explorer7Path */
        if (e7_ends_with_i(nm->Buffer, nmChars, g_MuiFilename, g_MuiFilenameChars) &&
            e7_Reprefix(nm, g_WinDirNt, g_WinDirNtChars, g_Ex7DirNt, g_Ex7DirNtChars,
                        rbuf, ARRAYSIZE(rbuf), &rstr))
        {
            roa = *ObjectAttributes;
            roa.ObjectName = &rstr;
            roa.RootDirectory = NULL;
            st = orig(FileHandle, DesiredAccess, &roa, IoStatusBlock, ShareAccess, OpenOptions);
            if (NT_SUCCESS(st)) return st;   /* else fall through to the original path */
        }

        /* %windir%\theme\... -> Explorer7Path\theme\... */
        if (e7_Reprefix(nm, g_WinThemeDirNt, g_WinThemeDirNtChars,
                        g_Ex7ThemeDirNt, g_Ex7ThemeDirNtChars,
                        rbuf, ARRAYSIZE(rbuf), &rstr))
        {
            roa = *ObjectAttributes;
            roa.ObjectName = &rstr;
            roa.RootDirectory = NULL;
            st = orig(FileHandle, DesiredAccess, &roa, IoStatusBlock, ShareAccess, OpenOptions);
            if (NT_SUCCESS(st)) return st;
        }
    }

    return orig(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                ShareAccess, OpenOptions);
}

/* Build the NT-path prefixes. `ex7NtDir` is the Explorer7 dir as an NT path
 * (e.g. L"\??\C:\explorer7"), which is what ReadExplorer7Path already gives us. */
static void BuildRedirectPaths(const WCHAR *ex7NtDir)
{
    /* %windir% from KUSER_SHARED_DATA.NtSystemRoot (+0x30), e.g. "C:\Windows". */
    const WCHAR *sysRoot = (const WCHAR *)(0x7FFE0000 + 0x30);
    ULONG n = e7_wcslen(sysRoot), i;

    g_WinDirNtChars = 0;
    g_WinDirNt[g_WinDirNtChars++] = L'\\'; g_WinDirNt[g_WinDirNtChars++] = L'?';
    g_WinDirNt[g_WinDirNtChars++] = L'?';  g_WinDirNt[g_WinDirNtChars++] = L'\\';
    for (i = 0; i < n && g_WinDirNtChars < ARRAYSIZE(g_WinDirNt) - 8; i++)
        g_WinDirNt[g_WinDirNtChars++] = sysRoot[i];
    if (g_WinDirNt[g_WinDirNtChars - 1] != L'\\') g_WinDirNt[g_WinDirNtChars++] = L'\\';
    g_WinDirNt[g_WinDirNtChars] = 0;

    n = e7_wcslen(ex7NtDir);
    g_Ex7DirNtChars = 0;
    for (i = 0; i < n && g_Ex7DirNtChars < ARRAYSIZE(g_Ex7DirNt) - 8; i++)
        g_Ex7DirNt[g_Ex7DirNtChars++] = ex7NtDir[i];
    if (g_Ex7DirNt[g_Ex7DirNtChars - 1] != L'\\') g_Ex7DirNt[g_Ex7DirNtChars++] = L'\\';
    g_Ex7DirNt[g_Ex7DirNtChars] = 0;

    /* ...and the "theme\" variants of each. */
    {
        const WCHAR *t = L"theme\\";
        for (i = 0; i < g_WinDirNtChars; i++) g_WinThemeDirNt[i] = g_WinDirNt[i];
        g_WinThemeDirNtChars = g_WinDirNtChars;
        for (i = 0; t[i]; i++) g_WinThemeDirNt[g_WinThemeDirNtChars++] = t[i];
        g_WinThemeDirNt[g_WinThemeDirNtChars] = 0;

        for (i = 0; i < g_Ex7DirNtChars; i++) g_Ex7ThemeDirNt[i] = g_Ex7DirNt[i];
        g_Ex7ThemeDirNtChars = g_Ex7DirNtChars;
        for (i = 0; t[i]; i++) g_Ex7ThemeDirNt[g_Ex7ThemeDirNtChars++] = t[i];
        g_Ex7ThemeDirNt[g_Ex7ThemeDirNtChars] = 0;
    }
}

/* Inline-hook ntdll!NtOpenFile. The x64 stub is
 *   4C 8B D1  mov r10,rcx / B8 xx xx xx xx  mov eax,<syscall> / ... syscall; ret
 * We rebuild that as a trampoline and overwrite the first 12 bytes with
 *   48 B8 <imm64>  mov rax,Hook / FF E0  jmp rax                                */
static BOOL InstallOpenFileHook(void)
{
    PVOID ntdllBase = NULL;
    PVOID pNtOpenFile = NULL, tramp = NULL;
    ANSI_STRING fn;
    NTSTATUS st;
    BYTE *stub, *t;
    ULONG syscallNum, oldProt;
    SIZE_T sz;

    {   /* find ntdll via the loader list */
        PPEB_LDR_DATA pldr = NtCurrentPeb()->Ldr;
        PLIST_ENTRY head = &pldr->InLoadOrderModuleList, e;
        for (e = head->Flink; e != head; e = e->Flink) {
            PLDR_DATA_TABLE_ENTRY m = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            WCHAR *b = m->BaseDllName.Buffer;
            if (b && m->BaseDllName.Length >= 5 * sizeof(WCHAR) &&
                e7_upper(b[0]) == L'N' && e7_upper(b[1]) == L'T' && e7_upper(b[2]) == L'D' &&
                e7_upper(b[3]) == L'L' && e7_upper(b[4]) == L'L')
            { ntdllBase = m->DllBase; break; }
        }
    }
    if (!ntdllBase) { LOG("ntdll base not found"); return FALSE; }

    fn.Buffer = (PCHAR)"NtOpenFile"; fn.Length = 10; fn.MaximumLength = 11;
    st = LdrGetProcedureAddress(ntdllBase, &fn, 0, &pNtOpenFile);
    if (!NT_SUCCESS(st) || !pNtOpenFile) { LOG("resolve NtOpenFile failed 0x%08X", st); return FALSE; }

    stub = (BYTE *)pNtOpenFile;
    if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8) {
        LOG("unexpected NtOpenFile stub %02X %02X %02X %02X", stub[0], stub[1], stub[2], stub[3]);
        return FALSE;                       /* fail safe: no hook, no swap damage */
    }
    syscallNum = *(ULONG *)(stub + 4);

    sz = 0x1000;
    st = NtAllocateVirtualMemory(NtCurrentProcess(), &tramp, 0, &sz,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st)) { LOG("trampoline alloc failed 0x%08X", st); return FALSE; }

    t = (BYTE *)tramp;
    t[0] = 0x4C; t[1] = 0x8B; t[2] = 0xD1;              /* mov r10,rcx      */
    t[3] = 0xB8; *(ULONG *)(t + 4) = syscallNum;        /* mov eax,<num>    */
    t[8] = 0x0F; t[9] = 0x05;                           /* syscall          */
    t[10] = 0xC3;                                       /* ret              */
    g_NtOpenFileTrampoline = t;

    /* Drop the trampoline from RWX to RX (no reason to leave executable memory
     * writable) and flush the i-cache over the freshly written code. */
    {
        PVOID tp = tramp; SIZE_T tpsz = sz; ULONG oldT;
        NtProtectVirtualMemory(NtCurrentProcess(), &tp, &tpsz, PAGE_EXECUTE_READ, &oldT);
        NtFlushInstructionCache(NtCurrentProcess(), tramp, 16);
    }

    {
        PVOID hb = pNtOpenFile; SIZE_T hs = 12;
        st = NtProtectVirtualMemory(NtCurrentProcess(), &hb, &hs, PAGE_EXECUTE_READWRITE, &oldProt);
        if (!NT_SUCCESS(st)) { LOG("unprotect NtOpenFile failed 0x%08X", st); return FALSE; }
        stub[0] = 0x48; stub[1] = 0xB8;                 /* mov rax,imm64    */
        *(ULONGLONG *)(stub + 2) = (ULONGLONG)(ULONG_PTR)Hook_NtOpenFile;
        stub[10] = 0xFF; stub[11] = 0xE0;               /* jmp rax          */
        hb = pNtOpenFile; hs = 12;
        NtProtectVirtualMemory(NtCurrentProcess(), &hb, &hs, oldProt, &oldProt);
        /* Flush the i-cache over the patched export. */
        NtFlushInstructionCache(NtCurrentProcess(), pNtOpenFile, 12);
    }

    LOG("NtOpenFile hook installed (syscall 0x%X, trampoline %p)", syscallNum, tramp);
    return TRUE;
}

/* --------------------------------------------------------------------------
 * Is this process the SHELL instance, or just a folder window?
 *
 * The IFEO hook fires for *every* explorer.exe launch, not only the shell one.
 * Winlogon starts the shell with a bare command line ("C:\Windows\explorer.exe"),
 * whereas a folder launch always carries arguments ("...\explorer.exe C:\Windows",
 * or "/factory,{...}" when folder windows run in a separate process). Swapping a
 * second instance is worse than useless: the Win7 image sees the existing desktop
 * in IsDesktopWindowAlreadyPresent(), returns 0 from CreateDesktopAndTray(), and
 * exits(1) *without* handing the folder request to the running shell - so
 * `explorer.exe <path>` silently opens nothing. Leaving those instances as stock
 * Win10 explorer makes them behave normally.
 *
 * Returns TRUE when the command line has no arguments beyond the image path.
 */
static BOOL IsShellInstance(void)
{
    PPEB peb = NtCurrentPeb();
    PUNICODE_STRING cmd;
    const WCHAR *p, *end;

    if (!peb || !peb->ProcessParameters) return TRUE;   /* can't tell -> behave as before */
    cmd = (PUNICODE_STRING)((BYTE *)peb->ProcessParameters + RTL_UPP_COMMANDLINE_OFFSET);
    if (!cmd->Buffer || !cmd->Length) return TRUE;

    p   = cmd->Buffer;
    end = cmd->Buffer + (cmd->Length / sizeof(WCHAR));

    while (p < end && (*p == L' ' || *p == L'\t')) p++;
    if (p < end && *p == L'"') {                        /* quoted image path */
        p++;
        while (p < end && *p != L'"') p++;
        if (p < end) p++;                               /* skip closing quote */
    } else {                                            /* bare image path */
        while (p < end && *p != L' ' && *p != L'\t') p++;
    }
    while (p < end && (*p == L' ' || *p == L'\t')) p++;

    return (p >= end);                                  /* nothing left => shell */
}

/* --------------------------------------------------------------------------
 * The swap. Runs at DLL_PROCESS_VERIFIER, before the main image's imports snap.
 */
static void PerformImageReplacement(void)
{
    if (!IsShellInstance()) {
        LOG("not the shell instance (has args) - leaving stock explorer in place");
        return;
    }

    WCHAR path[600];
    ULONG cch = ReadExplorer7Path(path, ARRAYSIZE(path));
    const WCHAR *tail = L"\\explorer.exe";
    ULONG i;
    PVOID file = NULL;
    SIZE_T fileSize = 0;

    /* Set up the MUI/theme redirection strings from the Explorer7 directory
     * before we append "\explorer.exe" to `path`. This only fills static
     * buffers - it has no process-global side effect - so it is safe to do even
     * if we later abort. The actual NtOpenFile hook is installed further down,
     * only once the guest PE has been read and validated and we are committed to
     * swapping (do NOT plant a permanent global hook for a guest that fails to
     * load - that would leave stock Win10 explorer running with MUI opens
     * redirected at a non-existent Win7 image). */
    BuildRedirectPaths(path);

    for (i = 0; tail[i] && cch < ARRAYSIZE(path) - 1; i++) path[cch++] = tail[i];
    path[cch] = 0;

    file = ReadWholeFile(path, &fileSize);
    if (!file) { LOG("could not read Win7 explorer at %ws", path); return; }

    /* Parse the on-disk Win7 PE. Validate every field before trusting it: this
     * loader indexes into `file` and the live image using these header values,
     * so a malformed guest must abort cleanly HERE, before the NtOpenFile hook
     * is installed or a single byte of the live image is touched. */
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) { LOG("file too small"); return; }
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)file;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    /* Bounds-check e_lfanew before forming the NT header pointer. */
    if ((ULONG)dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        (ULONGLONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize) {
        LOG("e_lfanew 0x%X out of range", dos->e_lfanew);
        return;
    }
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE *)file + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) { LOG("not x64"); return; }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { LOG("not PE32+"); return; }
    if (nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
        LOG("short optional header"); return;
    }
    /* We index directories 5 (basereloc) and 11 (bound import) below. */
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
        LOG("too few data directories (%u)", nt->OptionalHeader.NumberOfRvaAndSizes);
        return;
    }

    ULONG  newSizeOfImage = nt->OptionalHeader.SizeOfImage;
    ULONG  newEntryRva    = nt->OptionalHeader.AddressOfEntryPoint;
    ULONG  sizeOfHeaders  = nt->OptionalHeader.SizeOfHeaders;

    /* Section table and header/size sanity, plus per-section range checks. */
    {
        BYTE *fileEnd = (BYTE *)file + fileSize;
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        WORD n = nt->FileHeader.NumberOfSections, s;
        IMAGE_DATA_DIRECTORY rd;

        if (n == 0 || n > 96) { LOG("bad section count %u", n); return; }
        if ((BYTE *)(sec + n) > fileEnd) { LOG("section table past EOF"); return; }
        if (sizeOfHeaders > fileSize) { LOG("SizeOfHeaders past EOF"); return; }
        if (newSizeOfImage < sizeOfHeaders) { LOG("SizeOfImage < headers"); return; }
        if (newEntryRva == 0 || newEntryRva >= newSizeOfImage) {
            LOG("entry RVA 0x%X out of range", newEntryRva); return;
        }
        for (s = 0; s < n; s++) {
            ULONG va  = sec[s].VirtualAddress;
            ULONG vsz = sec[s].Misc.VirtualSize;
            ULONG raw = sec[s].SizeOfRawData;
            ULONG ptr = sec[s].PointerToRawData;
            if ((ULONGLONG)va + vsz > newSizeOfImage) { LOG("section %u virt past image", s); return; }
            if (raw && (ULONGLONG)ptr + raw > fileSize) { LOG("section %u raw past EOF", s); return; }
        }
        rd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rd.Size && (ULONGLONG)rd.VirtualAddress + rd.Size > newSizeOfImage) {
            LOG("reloc dir out of range"); return;
        }
    }

    /* Live main image. */
    PLDR_DATA_TABLE_ENTRY ldr = GetMainModuleEntry();
    BYTE *base = (BYTE *)ldr->DllBase;
    PIMAGE_NT_HEADERS64 liveNt =
        (PIMAGE_NT_HEADERS64)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    ULONG oldSizeOfImage = liveNt->OptionalHeader.SizeOfImage;
    /* Captured BEFORE the copy: the kernel baked this RVA into the initial thread
     * context at process creation, so we need it to find & repoint that value. */
    ULONG oldEntryRva = liveNt->OptionalHeader.AddressOfEntryPoint;

    LOG("live base=%p oldSize=0x%X newSize=0x%X entryRVA=0x%X",
        base, oldSizeOfImage, newSizeOfImage, newEntryRva);

    /* FIX #1 - fit-check. Never overrun the kernel's reservation. */
    if (newSizeOfImage > oldSizeOfImage) {
        LOG("Win7 image (0x%X) larger than live reservation (0x%X) - aborting swap",
            newSizeOfImage, oldSizeOfImage);
        return;
    }

    /* Guest read and validated and the fit-check passed: we are now committed to
     * swapping, so install the permanent MUI/theme NtOpenFile redirect. Doing it
     * here (not before the read) means an abort above leaves stock Win10 explorer
     * running with no dangling global hook. */
    InstallOpenFileHook();

    /* Make the whole reservation writable for the copy. */
    {
        PVOID p = base; SIZE_T sz = oldSizeOfImage; ULONG old;
        NTSTATUS st = NtProtectVirtualMemory(NtCurrentProcess(), &p, &sz,
                                             PAGE_EXECUTE_READWRITE, &old);
        if (!NT_SUCCESS(st)) { LOG("unprotect failed 0x%08X", st); return; }
    }

    /* Copy headers, then each section body (raw -> RVA), zero-filling BSS tails. */
    memcpy(base, file, sizeOfHeaders);
    {
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        WORD n = nt->FileHeader.NumberOfSections;
        for (i = 0; i < n; i++) {
            BYTE *dst = base + sec[i].VirtualAddress;
            ULONG raw = sec[i].SizeOfRawData;
            ULONG vsz = sec[i].Misc.VirtualSize;
            if (raw) memcpy(dst, (BYTE *)file + sec[i].PointerToRawData, raw);
            if (vsz > raw) memset(dst + raw, 0, vsz - raw);
        }
    }

    /* Point NT headers at the freshly written copy (now living at `base`). */
    PIMAGE_NT_HEADERS64 hdr =
        (PIMAGE_NT_HEADERS64)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);

    /* FIX #2 - base relocations against the live ASLR delta. */
    {
        ULONGLONG delta = (ULONGLONG)(ULONG_PTR)base - hdr->OptionalHeader.ImageBase;
        IMAGE_DATA_DIRECTORY rd =
            hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (delta && rd.Size && rd.VirtualAddress) {
            BYTE *cur = base + rd.VirtualAddress;
            BYTE *end = cur + rd.Size;
            while (cur < end) {
                PIMAGE_BASE_RELOCATION blk = (PIMAGE_BASE_RELOCATION)cur;
                if (blk->SizeOfBlock < sizeof(*blk)) break;
                ULONG count = (blk->SizeOfBlock - sizeof(*blk)) / sizeof(WORD);
                WORD *ent = (WORD *)(blk + 1);
                for (i = 0; i < count; i++) {
                    WORD type = ent[i] >> 12;
                    WORD off  = ent[i] & 0x0FFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG *pv = (ULONGLONG *)(base + blk->VirtualAddress + off);
                        *pv += delta;
                    } /* IMAGE_REL_BASED_ABSOLUTE (0) is a no-op pad. */
                }
                cur += blk->SizeOfBlock;
            }
        }
    }

    /* FIX #3 - neutralize the stale Bound Import directory so ntdll snaps fresh. */
    hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

    /* FIX #4 - repoint the loader's cached entry-point and image size. */
    ldr->EntryPoint  = base + newEntryRva;
    ldr->SizeOfImage = newSizeOfImage;

    /* FIX #4b - MAIN THREAD entry trampoline. ldr->EntryPoint above only governs
     * DLL init; the main thread never reads it. At process creation the kernel
     * captured the ORIGINAL (Win10) AddressOfEntryPoint into the initial thread
     * context, and after loader init RtlUserThreadStart calls
     * EntryPoint(PebBaseAddress) with that cached value. Without this, control
     * lands at base+oldEntryRva in the *Win7* image - an unrelated function -
     * with rcx = PEB, and dies immediately (this was the real reason the swapped
     * shell never booted). So plant a 5-byte relative JMP at the old RVA that
     * hops to the real Win7 entry.
     * Tradeoff: this clobbers 5 bytes of whatever Win7 code occupies that RVA.
     * Must run HERE - before FIX #5 restores per-section protections - while the
     * image is still writable. */
    if (oldEntryRva != newEntryRva) {
        BYTE *stub = base + oldEntryRva;
        LONG rel = (LONG)(newEntryRva - (oldEntryRva + 5));
        stub[0] = 0xE9;                  /* jmp rel32 */
        *(LONG *)(stub + 1) = rel;
        LOG("entry trampoline: RVA 0x%X -> 0x%X", oldEntryRva, newEntryRva);
    }

    /* FIX #5 - restore per-section protections, then flush the i-cache.
     * A failed reprotect can leave a section at RWX; we cannot roll back a
     * half-swapped image at this point (the Win10 code is already overwritten),
     * so we cannot make it fatal, but we no longer swallow the result silently -
     * failures are logged so a bad restore is at least visible. */
    {
        BYTE *hp = base; SIZE_T hsz = sizeOfHeaders; ULONG old;
        NTSTATUS st = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID *)&hp, &hsz, PAGE_READONLY, &old);
        if (!NT_SUCCESS(st)) LOG("header reprotect failed 0x%08X", st);

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(hdr);
        WORD n = hdr->FileHeader.NumberOfSections;
        for (i = 0; i < n; i++) {
            PVOID p = base + sec[i].VirtualAddress;
            SIZE_T sz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize
                                                : sec[i].SizeOfRawData;
            ULONG prot = SectionProtect(sec[i].Characteristics), o;
            st = NtProtectVirtualMemory(NtCurrentProcess(), &p, &sz, prot, &o);
            if (!NT_SUCCESS(st)) LOG("section %u reprotect failed 0x%08X", i, st);
        }
    }

    /* FIX #5b - neutralize the stale Win10 tail. We made the whole
     * [base, base+oldSizeOfImage) reservation RWX for the copy but only wrote and
     * reprotected up to the Win7 image's SizeOfImage. The remainder still holds
     * Win10 bytes at RWX; with CFG off for the Win7 code, leaving stale code both
     * writable AND executable is exactly the hazard to remove, so drop the tail to
     * read-only. (The complete fix - zero the tail to PAGE_NOACCESS while mirroring
     * the guest unwind table at the host's cached RVA - is left as a follow-up;
     * NOACCESS here alone would turn the still-stale unwind cache's
     * Win10-directory reads into hard faults.) */
    if (oldSizeOfImage > newSizeOfImage) {
        PVOID tp = base + newSizeOfImage;
        SIZE_T tsz = (SIZE_T)oldSizeOfImage - newSizeOfImage;
        ULONG o;
        NTSTATUS st = NtProtectVirtualMemory(NtCurrentProcess(), &tp, &tsz, PAGE_READONLY, &o);
        if (!NT_SUCCESS(st)) LOG("tail reprotect failed 0x%08X", st);
    }
    {
        PVOID rgn = base; SIZE_T rsz = newSizeOfImage;
        NtFlushInstructionCache(NtCurrentProcess(), rgn, rsz);
    }

    /* FIX #6 - CFG. The kernel's call-target bitmap for this region was built
     * from the Win10 (CFG) image; we replaced the code with the Win7 (non-CFG)
     * image, so guarded indirect calls from system DLLs into Win7 code would
     * fast-fail. Mark every 16-byte slot of each executable section as a valid
     * call target. Offsets are per-page-range, so the same 256-entry table
     * (0,16,..,0xFF0) applies to every page. Failures are non-fatal - if CFG is
     * not actually enforced this is a harmless no-op. */
    {
        static E7_CFG_CALL_TARGET_INFO tgt[256]; /* static: keep it off the stack (avoid __chkstk under /NODEFAULTLIB) */
        ULONG k, pages = 0, failed = 0;
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(hdr);
        WORD n = hdr->FileHeader.NumberOfSections;
        for (k = 0; k < 256; k++) { tgt[k].Offset = (ULONG_PTR)k * 16; tgt[k].Flags = E7_CFG_CALL_TARGET_VALID; }
        for (i = 0; i < n; i++) {
            ULONG vsz, off;
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            vsz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            for (off = 0; off < vsz; off += 0x1000) {
                E7_MEMORY_RANGE_ENTRY range;
                E7_CFG_CALL_TARGET_LIST_INFORMATION info;
                ULONG processed = 0;
                NTSTATUS st;
                range.VirtualAddress = base + sec[i].VirtualAddress + off;
                range.NumberOfBytes  = 0x1000;
                info.NumberOfEntries = 256;
                info.Reserved = 0;
                info.NumberOfEntriesProcessed = &processed;
                info.CallTargetInfo = tgt;
                info.Section = NULL;
                info.FileOffset = 0;
                st = NtSetInformationVirtualMemory(NtCurrentProcess(), VmCfgCallTargetInformation,
                                                   1, &range, &info, sizeof(info));
                pages++;
                if (!NT_SUCCESS(st)) failed++;
            }
        }
        /* The on-disk Win10 explorer opts into GUARD_CF. explorer7_install.reg sets
         * CFG ALWAYS_OFF through MitigationOptions, which is what actually keeps
         * the Win7 code alive; this marking only covers a config without that
         * value. Surface a summary instead of ignoring every result. A high
         * failure count means guarded indirect calls into the Win7 code may
         * fast-fail. */
        LOG("CFG mark: %u pages, %u failures", pages, failed);
    }

    /* Release the temporary file buffer. */
    {
        SIZE_T z = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &file, &z, MEM_RELEASE);
    }

    LOG("swap complete; entry=%p", ldr->EntryPoint);
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_VERIFIER:
        /* Hand ntdll our (empty) provider descriptor, then do the swap while we
         * are still ahead of LdrpInitializeGraphRecurse for the main image. */
        if (reserved)
            *(PRTL_VERIFIER_PROVIDER_DESCRIPTOR *)reserved = &g_VerifierDescriptor;
        PerformImageReplacement();
        break;
    case DLL_PROCESS_ATTACH:
        /* Switch Application Verifier off for the rest of the process's life.
         *
         * We only ever wanted AppVerifier for its TIMING - DLL_PROCESS_VERIFIER is
         * the one hook point that runs before the loader snaps the main image's
         * imports. We do not want its instrumentation: verifier.dll interposes
         * thunks into every module's IAT (Reg*, CreateFileW, critical sections...),
         * which measured ~146-190ms per File Explorer window on this machine
         * (stock 170ms -> 316ms with AppVerifier alone, no swap and no hooks).
         * VerifierFlags=0 does NOT prevent this - thunk installation is driven by
         * the provider chain, not those flags.
         *
         * ntdll gates all post-snap thunking on PEB->NtGlobalFlag & FLG_APPLICATION_
         * VERIFIER: AVrfDllLoadNotification (the sole path from
         * LdrpSendPostSnapNotifications / LdrpCorProcessImports) returns immediately
         * when the bit is clear, as do AVrfDllUnloadNotification and
         * AVrfInternalHeapFreeNotification. LdrpInitializeProcess already tested the
         * bit to decide to call AVrfInitializeVerifier, so clearing it now is safe.
         *
         * Timing matters: do this at DLL_PROCESS_ATTACH, not DLL_PROCESS_VERIFIER.
         * verifier.dll is always first in the provider list, so its own attach runs
         * before ours - clearing the bit earlier would leave it initializing in a
         * state it does not expect. This still precedes the kernelbase/kernel32 load
         * and the whole Win7 dependency graph, so essentially nothing gets thunked.
         *
         * PEB+0xBC is ABI-stable across x64 Windows; no pattern scan required. */
        {
            PPEB peb = NtCurrentPeb();
            if (peb) {
                ULONG *ntGlobalFlag = (ULONG *)((BYTE *)peb + 0xBC);
                *ntGlobalFlag &= ~(ULONG)0x100;   /* FLG_APPLICATION_VERIFIER */
                LOG("AppVerifier disarmed (NtGlobalFlag now 0x%X)", *ntGlobalFlag);
            }
        }
        break;
    }
    return TRUE;
}
