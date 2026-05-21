#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <stdio.h>

#include <tchar.h>
#include <string>
#include <assert.h>

#include <strsafe.h>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <processsnapshot.h>
#include "Dbghelp.h"

#pragma comment (lib, "Dbghelp")

#include "look.h"
#include "ss_hooks.h"

DWORD ProcessNameToID(char* name);
HPSS TakeProcessSnapShot(HANDLE ProcessHandle);
static void LoadExcludePatterns();

struct SnapRegion {
    void*  base;
    void*  allocBase;
    size_t size;
    DWORD  state;
    DWORD  protect;
    DWORD  allocProtect;
    DWORD  type;
};

struct SavedFileHandle {
    HANDLE       value;
    std::wstring dosPath;
    LARGE_INTEGER position;
    DWORD        access;
};

std::vector<SavedFileHandle> RecordFileHandles(HANDLE targetProcess, HPSS snapshotHandle);
static void RestoreFileHandles(HANDLE targetProcess, const std::vector<SavedFileHandle>& saved,
                                const std::vector<SnapRegion>& snapRegions);
static void RestoreFileHandlesViaHooks(HANDLE targetProcess, SsHookState* state,
                                        const std::vector<SavedFileHandle>& saved);
void RestoreMemoryFromSnapshot(DWORD targetProcessID, HANDLE targetProcess,
                               HPSS snapshotHandle,
                               const std::vector<SavedFileHandle>& fileHandles,
                               SsHookState* hookState = nullptr);

BOOL CALLBACK MiniDumpWriteDumpCallback(
  __in     PVOID CallbackParam,
  __in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
  __inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
    switch (CallbackInput->CallbackType)
    {
        case 16: // IsProcessSnapshotCallback
            CallbackOutput->Status = 1;
            break;
    }
    return TRUE;
}


void PrintError(DWORD err)
{
    printf("(LastError:%lu)\n", err);
    LPVOID lpMsgBuf;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
    printf("%s\n", (LPCTSTR)lpMsgBuf);
    LocalFree(lpMsgBuf);
}

static void EnableDebugPrivilege()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
    LUID luid;
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid))
    {
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);
}

// ---- forward declarations for client management (defined after restore code) ----
int RunAutomatedTest(const char* targetExe);
static DWORD WINAPI PipeServerThread(LPVOID);
static DWORD WINAPI HotkeyThread(LPVOID);

static bool IsElevated()
{
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te;
        DWORD len = sizeof(te);
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &len))
            elevated = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return !!elevated;
}

static void RelaunchElevated(int argc, char** argv)
{
    // Rebuild the original command line from argv so flags like --test survive.
    char params[2048] = {};
    for (int i = 1; i < argc; i++) {
        if (i > 1) strcat_s(params, " ");
        // Quote each argument in case it contains spaces.
        strcat_s(params, "\"");
        strcat_s(params, argv[i]);
        strcat_s(params, "\"");
    }

    SHELLEXECUTEINFOA sei = {};
    sei.cbSize       = sizeof(sei);
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb       = "runas";
    sei.lpFile       = argv[0];
    sei.lpParameters = params;
    sei.nShow        = SW_SHOWNORMAL;

    if (!ShellExecuteExA(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED)
            printf("Elevation cancelled by user.\n");
        else
            printf("ShellExecuteEx failed: %lu\n", err);
    } else {
        // Wait for the elevated child so this console window stays open.
        if (sei.hProcess) {
            WaitForSingleObject(sei.hProcess, INFINITE);
            CloseHandle(sei.hProcess);
        }
    }
}

int main(int argc, char** argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (!IsElevated()) {
        printf("Not running as administrator — relaunching elevated...\n");
        RelaunchElevated(argc, argv);
        return 0;
    }

    EnableDebugPrivilege();
    LoadExcludePatterns();

    if (argc > 1 && strcmp(argv[1], "--test") == 0)
        return RunAutomatedTest(argc > 2 ? argv[2] : "test_target.exe");

    printf("Savestate server running. F5 = save, F9 = load.\n");
    printf("Waiting for clients to call SavestateProgramInit()...\n");

    HANDLE hPipe = CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);
    HANDLE hHkey = CreateThread(NULL, 0, HotkeyThread,    NULL, 0, NULL);

    WaitForSingleObject(hPipe, INFINITE);
    (void)hHkey;
    return 0;
}


HPSS TakeProcessSnapShot(HANDLE ProcessHandle)
{
    PSS_CAPTURE_FLAGS CaptureFlags = (PSS_CAPTURE_FLAGS)0
        | PSS_CAPTURE_VA_CLONE
        | PSS_CAPTURE_VA_SPACE
        | PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION
        | PSS_CAPTURE_HANDLES
        | PSS_CAPTURE_HANDLE_NAME_INFORMATION
        | PSS_CAPTURE_HANDLE_BASIC_INFORMATION
        | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
        | PSS_CAPTURE_HANDLE_TRACE
        | PSS_CAPTURE_THREADS
        | PSS_CAPTURE_THREAD_CONTEXT
        | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
        | PSS_CREATE_BREAKAWAY
        | PSS_CREATE_BREAKAWAY_OPTIONAL
        | PSS_CREATE_USE_VM_ALLOCATIONS
        | PSS_CREATE_RELEASE_SECTION
        ;
    HPSS SnapshotHandle;
    DWORD dwResultCode = PssCaptureSnapshot(ProcessHandle, CaptureFlags, CONTEXT_ALL, &SnapshotHandle);
    if (dwResultCode != ERROR_SUCCESS)
    {
        printf("Failed to capture snapshot: %lu\n", dwResultCode);
        PrintError(dwResultCode);
        return NULL;
    }
    return SnapshotHandle;
}

enum ThreadState : int { SUSPEND, RESUME };

void SuspendOrResumeProcessThreads(DWORD processId, ThreadState desiredThreadState)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te32 = {};
    te32.dwSize = sizeof(te32);
    if (!Thread32First(hSnap, &te32)) { CloseHandle(hSnap); return; }
    do {
        if (te32.th32OwnerProcessID == processId)
        {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread)
            {
                if (desiredThreadState == SUSPEND) SuspendThread(hThread);
                else                               ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnap, &te32));
    CloseHandle(hSnap);
}


// ---- restore implementation ----


static std::vector<SnapRegion> CollectSnapshotRegions(HPSS snapshotHandle)
{
    std::vector<SnapRegion> regions;
    HPSSWALK walker = NULL;
    if (PssWalkMarkerCreate(NULL, &walker) != ERROR_SUCCESS) return regions;
    PSS_VA_SPACE_ENTRY e;
    while (PssWalkSnapshot(snapshotHandle, PSS_WALK_VA_SPACE, walker, &e, sizeof(e)) == ERROR_SUCCESS)
        regions.push_back({ e.BaseAddress, e.AllocationBase, e.RegionSize,
                            e.State, e.Protect, e.AllocationProtect, e.Type });
    PssWalkMarkerFree(walker);
    return regions;
}

// Terminate threads in target that didn't exist at snapshot time.
// Must be called while threads are already suspended to avoid races.
// Needed so their stacks/TEBs can be freed as orphaned allocations.
static void TerminateExtraThreads(DWORD processID, HPSS snapshotHandle)
{
    std::set<DWORD> snapThreadIDs;
    HPSSWALK walker = NULL;
    if (PssWalkMarkerCreate(NULL, &walker) == ERROR_SUCCESS)
    {
        PSS_THREAD_ENTRY te;
        while (PssWalkSnapshot(snapshotHandle, PSS_WALK_THREADS, walker, &te, sizeof(te)) == ERROR_SUCCESS)
            snapThreadIDs.insert(te.ThreadId);
        PssWalkMarkerFree(walker);
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te32 = {};
    te32.dwSize = sizeof(te32);
    if (Thread32First(snap, &te32)) do {
        if (te32.th32OwnerProcessID == processID &&
            snapThreadIDs.find(te32.th32ThreadID) == snapThreadIDs.end())
        {
            HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, te32.th32ThreadID);
            if (hThread) { TerminateThread(hThread, 0); CloseHandle(hThread); }
        }
    } while (Thread32Next(snap, &te32));
    CloseHandle(snap);
}

// Free all target allocations that overlap [base, base+size).
// Returns false if any free fails.
static bool FreeOverlappingAllocations(HANDLE targetProcess, void* base, size_t size)
{
    char* scanEnd = (char*)base + size;
    char* scanAddr = (char*)base;
    std::set<void*> freed;
    MEMORY_BASIC_INFORMATION mbi = {};
    bool ok = true;
    while (scanAddr < scanEnd)
    {
        if (VirtualQueryEx(targetProcess, scanAddr, &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State != MEM_FREE && mbi.AllocationBase &&
            freed.find(mbi.AllocationBase) == freed.end())
        {
            freed.insert(mbi.AllocationBase);
            if (!VirtualFreeEx(targetProcess, mbi.AllocationBase, 0, MEM_RELEASE))
            {
                DWORD err = GetLastError();
                // ERROR_INVALID_PARAMETER means kernel-owned (CFG bitmap,
                // KUSER_SHARED_DATA, etc.) — silently skip but still signal
                // failure so the caller skips the subsequent VirtualAllocEx.
                if (err != ERROR_INVALID_PARAMETER)
                {
                    printf("VirtualFreeEx failed at %p: ", mbi.AllocationBase);
                    PrintError(err);
                }
                ok = false;
            }
            continue; // re-query same addr after free
        }
        char* next = (char*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= scanAddr) break;
        scanAddr = next;
    }
    return ok;
}

// Restore one allocation group: all snapshot sub-regions sharing an AllocationBase.
// Handles partially-committed allocations, protection restoration, and mixed RW/exec pages.
static void RestoreAllocation(HANDLE targetProcess, HANDLE snapshotProcess,
                              const std::vector<SnapRegion>& group)
{
    void* allocBase = group[0].allocBase;

    // Compute total extent of this allocation across all sub-regions
    size_t totalSize = 0;
    for (const auto& r : group)
    {
        size_t end = (size_t)((char*)r.base - (char*)allocBase) + r.size;
        if (end > totalSize) totalSize = end;
    }

    if (!FreeOverlappingAllocations(targetProcess, allocBase, totalSize))
    {
        // Kernel-managed or otherwise unfreeable region — skip entirely
        return;
    }

    // Reserve the full extent. Strip PAGE_GUARD — only valid at commit time.
    DWORD reserveProtect = group[0].allocProtect & ~PAGE_GUARD;
    if (!reserveProtect) reserveProtect = PAGE_READWRITE;

    if (!VirtualAllocEx(targetProcess, allocBase, totalSize, MEM_RESERVE, reserveProtect))
    {
        printf("MEM_RESERVE failed at %p size %zu: ", allocBase, totalSize);
        PrintError(GetLastError());
        return;
    }

    for (const auto& r : group)
    {
        if (r.state != MEM_COMMIT || r.type == MEM_IMAGE) continue;

        // Commit with a writable protection so WriteProcessMemory succeeds.
        // We'll VirtualProtectEx to the real protection afterward.
        bool isExec = (r.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        DWORD writeProtect = isExec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

        if (!VirtualAllocEx(targetProcess, r.base, r.size, MEM_COMMIT, writeProtect))
        {
            printf("MEM_COMMIT failed at %p size %zu: ", r.base, r.size);
            PrintError(GetLastError());
            continue;
        }

        const size_t PAGE = 4096;
        char* buf = (char*)malloc(r.size);
        memset(buf, 0, r.size);

        // Try bulk read first; fall back page-by-page (guard pages cause ERROR_PARTIAL_COPY)
        SIZE_T bytes;
        if (!ReadProcessMemory(snapshotProcess, r.base, buf, r.size, &bytes) || bytes != r.size)
        {
            for (size_t off = 0; off < r.size; off += PAGE)
            {
                size_t chunk = (r.size - off < PAGE) ? (r.size - off) : PAGE;
                ReadProcessMemory(snapshotProcess, (char*)r.base + off, buf + off, chunk, &bytes);
                // unreadable pages stay zero — guard pages will be restored by VirtualProtectEx
            }
        }

        if (!WriteProcessMemory(targetProcess, r.base, buf, r.size, &bytes))
        {
            printf("WriteProcessMemory failed at %p: ", r.base);
            PrintError(GetLastError());
        }
        free(buf);

        if (r.protect != writeProtect)
        {
            DWORD oldProt;
            if (!VirtualProtectEx(targetProcess, r.base, r.size, r.protect, &oldProt))
            {
                printf("VirtualProtectEx to %lu failed at %p: ", r.protect, r.base);
                PrintError(GetLastError());
            }
        }
    }
}

// ---- graphics-driver memory exclusion ----
// GPU drivers (NVIDIA OpenGL, D3D runtimes, etc.) maintain internal state that
// is split between CPU-side heaps and GPU-side resources.  Restoring the CPU-
// side memory to an older snapshot makes it inconsistent with the GPU's current
// resource state, causing crashes.  We skip those regions entirely, leaving the
// driver in its current (post-modification) state.  GL/D3D object handles are
// stable integers, so the app's restored handle values remain valid.
//
// To exclude additional modules, add substrings to g_excludeModulePatterns below
// or list them (one per line, # for comments) in snapshot_exclude.txt next to
// snapshot.exe.

// Substrings matched case-insensitively against module filenames.
// Add new entries here or via snapshot_exclude.txt.
static std::vector<std::string> g_excludeModulePatterns = {
    // NVIDIA
    "nvoglv", "nvd3d", "nvwgf", "nvcuvid", "nvenc", "nvcuda", "nvapi",
    // AMD
    "amdvlk", "amdxc", "atioglxx", "atidxx", "amdgfx",
    // Intel
    "ig4icd", "igdumd", "igd10", "intel_icd",
    // D3D / DXGI runtimes
    "d3d9", "d3d10", "d3d11", "d3d12", "dxgi", "dxcore",
    // API loaders
    "opengl32", "vulkan-1",
};

// Reads snapshot_exclude.txt from the same directory as snapshot.exe.
// Each non-empty, non-comment line is appended to g_excludeModulePatterns.
static void LoadExcludePatterns()
{
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exePath, sizeof(exePath));
    char* slash = strrchr(exePath, '\\');
    if (slash) *(slash + 1) = '\0';
    strncat_s(exePath, "snapshot_exclude.txt", MAX_PATH - strlen(exePath) - 1);

    FILE* f = nullptr;
    if (fopen_s(&f, exePath, "r") != 0 || !f) return;

    char line[256];
    int added = 0;
    while (fgets(line, sizeof(line), f)) {
        // strip trailing whitespace / newline
        int len = (int)strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' '))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;
        g_excludeModulePatterns.push_back(line);
        added++;
    }
    fclose(f);
    if (added)
        printf("[exclude] loaded %d pattern(s) from snapshot_exclude.txt\n", added);
}

static bool ContainsI(const char* haystack, const char* needle)
{
    size_t nl = strlen(needle);
    for (; *haystack; haystack++)
        if (_strnicmp(haystack, needle, nl) == 0) return true;
    return false;
}

static bool IsGfxModule(const char* filename)
{
    for (const auto& pat : g_excludeModulePatterns)
        if (ContainsI(filename, pat.c_str())) return true;
    return false;
}

// Returns a set of AllocationBases that must not be freed or overwritten
// during restore.  Covers:
//   1. All regions that fall inside a graphics module's MEM_IMAGE range.
//   2. Private regions immediately adjacent to those images in the live process
//      (driver per-context heaps are commonly allocated right next to the DLL).
static std::set<void*> BuildGfxSkipSet(HANDLE targetProcess,
                                        const std::vector<SnapRegion>& snapRegions)
{
    std::set<void*> skip;

    HMODULE mods[1024]; DWORD needed = 0;
    if (!EnumProcessModules(targetProcess, mods, sizeof(mods), &needed))
        return skip;

    struct GfxMod { char* base; size_t size; };
    std::vector<GfxMod> gfx;

    int n = (int)(needed / sizeof(HMODULE));
    for (int i = 0; i < n; i++) {
        char path[MAX_PATH] = {};
        if (!GetModuleFileNameExA(targetProcess, mods[i], path, sizeof(path))) continue;
        char* fname = strrchr(path, '\\'); fname = fname ? fname + 1 : path;
        if (!IsGfxModule(fname)) continue;
        MODULEINFO mi = {};
        if (!GetModuleInformation(targetProcess, mods[i], &mi, sizeof(mi))) continue;
        printf("  [gfx] skipping %s @ %p (+%lu KB)\n",
               fname, mi.lpBaseOfDll, mi.SizeOfImage / 1024);
        gfx.push_back({ (char*)mi.lpBaseOfDll, mi.SizeOfImage });
    }
    if (gfx.empty()) return skip;

    // 1. Snapshot regions that fall inside any gfx module image.
    for (const auto& r : snapRegions) {
        if (r.state == MEM_FREE || !r.allocBase) continue;
        for (const auto& gm : gfx) {
            if ((char*)r.base >= gm.base && (char*)r.base < gm.base + gm.size) {
                skip.insert(r.allocBase);
                break;
            }
        }
    }

    // 2. Private regions adjacent (no free gap) to each gfx module in the live
    //    process — these are typically the driver's per-context heap.
    for (const auto& gm : gfx) {
        // scan forward from end of image
        char* addr = gm.base + gm.size;
        MEMORY_BASIC_INFORMATION mbi = {};
        while (VirtualQueryEx(targetProcess, addr, &mbi, sizeof(mbi)) > 0) {
            if (mbi.State == MEM_FREE) break;
            if (mbi.Type == MEM_IMAGE && mbi.AllocationBase != gm.base) break;
            if (mbi.Type == MEM_PRIVATE) skip.insert(mbi.AllocationBase);
            char* next = (char*)mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
        // scan backward from start of image
        addr = gm.base;
        while (addr > (char*)0x10000) {
            MEMORY_BASIC_INFORMATION mbi2 = {};
            if (VirtualQueryEx(targetProcess, addr - 1, &mbi2, sizeof(mbi2)) == 0) break;
            if (mbi2.State == MEM_FREE) break;
            if (mbi2.Type == MEM_IMAGE && mbi2.AllocationBase != gm.base) break;
            if (mbi2.Type == MEM_PRIVATE) skip.insert(mbi2.AllocationBase);
            if (mbi2.BaseAddress >= addr) break;
            addr = (char*)mbi2.BaseAddress;
        }
    }

    return skip;
}

// Restore thread register state from snapshot.
// Threads must already be suspended.
static void RestoreThreadContexts(HPSS snapshotHandle)
{
    HPSSWALK walker = NULL;
    if (PssWalkMarkerCreate(NULL, &walker) != ERROR_SUCCESS) return;
    PSS_THREAD_ENTRY te;
    while (PssWalkSnapshot(snapshotHandle, PSS_WALK_THREADS, walker, &te, sizeof(te)) == ERROR_SUCCESS)
    {
        if (!te.ContextRecord) continue;
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.ThreadId);
        if (!hThread) continue;
        if (!SetThreadContext(hThread, te.ContextRecord))
        {
            printf("SetThreadContext failed for thread %lu: ", te.ThreadId);
            PrintError(GetLastError());
        }
        CloseHandle(hThread);
    }
    PssWalkMarkerFree(walker);
}

void RestoreMemoryFromSnapshot(DWORD targetProcessID, HANDLE targetProcess, HPSS snapshotHandle,
                               const std::vector<SavedFileHandle>& fileHandles,
                               SsHookState* hookState)
{
    // VA clone is a real process handle that mirrors the snapshot's memory
    PSS_VA_CLONE_INFORMATION cloneInfo = {};
    if (PssQuerySnapshot(snapshotHandle, PSS_QUERY_VA_CLONE_INFORMATION, &cloneInfo, sizeof(cloneInfo)) != ERROR_SUCCESS)
    {
        printf("Failed to get VA clone handle\n");
        return;
    }
    HANDLE snapshotProcess = cloneInfo.VaCloneHandle;

    SuspendOrResumeProcessThreads(targetProcessID, SUSPEND);
    TerminateExtraThreads(targetProcessID, snapshotHandle);

    auto snapRegions = CollectSnapshotRegions(snapshotHandle);

    // Build exclusion set for graphics-driver memory (must happen before threads
    // are fully suspended so EnumProcessModules can still run).
    auto gfxSkip = BuildGfxSkipSet(targetProcess, snapRegions);

    // Group non-image, non-free regions by AllocationBase
    std::map<void*, std::vector<SnapRegion>> allocGroups;
    for (const auto& r : snapRegions)
    {
        if (r.state == MEM_FREE || r.type == MEM_IMAGE || !r.allocBase) continue;
        if (r.type == MEM_MAPPED) continue;
        if (gfxSkip.count(r.allocBase)) continue; // leave driver memory alone
        allocGroups[r.allocBase].push_back(r);
    }

    // Free private target allocations not present in snapshot (created after snapshot)
    {
        std::set<void*> snapBases;
        for (const auto& kv : allocGroups) snapBases.insert(kv.first);

        std::set<void*> freed;
        MEMORY_BASIC_INFORMATION mbi = {};
        char* addr = (char*)0x10000; // skip first 64KB null region
        while (VirtualQueryEx(targetProcess, addr, &mbi, sizeof(mbi)) > 0)
        {
            if (mbi.State != MEM_FREE &&
                mbi.Type != MEM_IMAGE && mbi.Type != MEM_MAPPED &&
                mbi.AllocationBase &&
                freed.find(mbi.AllocationBase) == freed.end() &&
                snapBases.find(mbi.AllocationBase) == snapBases.end() &&
                !gfxSkip.count(mbi.AllocationBase)) // don't free driver memory
            {
                freed.insert(mbi.AllocationBase);
                if (!VirtualFreeEx(targetProcess, mbi.AllocationBase, 0, MEM_RELEASE))
                {
                    // ERROR_INVALID_PARAMETER means kernel-owned (CFG bitmap,
                    // KUSER_SHARED_DATA, etc.) — not freeable from user mode, skip.
                    if (GetLastError() != ERROR_INVALID_PARAMETER)
                    {
                        printf("Failed to free orphaned region at %p: ", mbi.AllocationBase);
                        PrintError(GetLastError());
                    }
                }
            }
            char* next = (char*)mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
    }

    // Restore each snapshot allocation group (MEM_PRIVATE)
    for (const auto& kv : allocGroups)
        RestoreAllocation(targetProcess, snapshotProcess, kv.second);

    // Restore writable MEM_IMAGE regions (PE .data / .bss copy-on-write pages).
    // These can't be re-allocated; we write directly with WriteProcessMemory.
    for (const auto& r : snapRegions)
    {
        if (r.state != MEM_COMMIT || r.type != MEM_IMAGE) continue;
        if (gfxSkip.count(r.allocBase)) continue; // skip driver .data sections
        // Skip purely read-only / execute-read pages — they never change
        const DWORD rwMask = PAGE_READWRITE | PAGE_WRITECOPY |
                             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if (!(r.protect & rwMask)) continue;

        const size_t PAGE = 4096;
        char* buf = (char*)malloc(r.size);
        memset(buf, 0, r.size);

        SIZE_T bytes;
        if (!ReadProcessMemory(snapshotProcess, r.base, buf, r.size, &bytes) || bytes != r.size)
        {
            for (size_t off = 0; off < r.size; off += PAGE)
            {
                size_t chunk = r.size - off < PAGE ? r.size - off : PAGE;
                ReadProcessMemory(snapshotProcess, (char*)r.base + off, buf + off, chunk, &bytes);
            }
        }

        // WriteProcessMemory bypasses read-only protection internally
        if (!WriteProcessMemory(targetProcess, r.base, buf, r.size, &bytes))
        {
            // Try page-by-page (some pages may be guarded)
            for (size_t off = 0; off < r.size; off += PAGE)
            {
                size_t chunk = r.size - off < PAGE ? r.size - off : PAGE;
                WriteProcessMemory(targetProcess, (char*)r.base + off, buf + off, chunk, &bytes);
            }
        }
        free(buf);
    }

    if (hookState)
        RestoreFileHandlesViaHooks(targetProcess, hookState, fileHandles);
    else
        RestoreFileHandles(targetProcess, fileHandles, snapRegions);
    RestoreThreadContexts(snapshotHandle);

    SuspendOrResumeProcessThreads(targetProcessID, RESUME);
    printf("Restore complete\n");
}


// ---- file handle record / restore ----

static std::wstring GetDosPathFromHandle(HANDLE h)
{
    wchar_t buf[MAX_PATH + 4] = {};
    DWORD len = GetFinalPathNameByHandleW(h, buf, MAX_PATH, FILE_NAME_NORMALIZED);
    if (!len) return {};
    std::wstring s(buf, len);
    // strip \\?\ prefix that GetFinalPathNameByHandleW adds
    if (s.size() > 4 && s.substr(0, 4) == L"\\\\?\\") s = s.substr(4);
    return s;
}

std::vector<SavedFileHandle> RecordFileHandles(HANDLE targetProcess, HPSS snapshotHandle)
{
    std::vector<SavedFileHandle> result;
    HPSSWALK walker = NULL;
    if (PssWalkMarkerCreate(NULL, &walker) != ERROR_SUCCESS) return result;

    PSS_HANDLE_ENTRY e;
    while (PssWalkSnapshot(snapshotHandle, PSS_WALK_HANDLES, walker, &e, sizeof(e)) == ERROR_SUCCESS)
    {
        // Identify file handles by type name string (no PSS_OBJECT_TYPE_FILE exists)
        if (!e.TypeName || e.TypeNameLength == 0) continue;
        if (wcsncmp(e.TypeName, L"File", e.TypeNameLength / sizeof(wchar_t)) != 0) continue;

        // Duplicate into controller to query path and position
        HANDLE dup = NULL;
        if (!DuplicateHandle(targetProcess, e.Handle, GetCurrentProcess(), &dup,
                             0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;

        std::wstring path = GetDosPathFromHandle(dup);
        if (path.empty()) { CloseHandle(dup); continue; } // pipes, devices, etc.

        LARGE_INTEGER pos = {}, zero = {};
        SetFilePointerEx(dup, zero, &pos, FILE_CURRENT);
        CloseHandle(dup);

        SavedFileHandle sfh;
        sfh.value   = e.Handle;
        sfh.dosPath = path;
        sfh.position = pos;
        sfh.access  = e.GrantedAccess;
        result.push_back(sfh);
        printf("  handle %p -> %ls @ %lld\n", sfh.value, sfh.dosPath.c_str(), sfh.position.QuadPart);
    }
    PssWalkMarkerFree(walker);

    std::sort(result.begin(), result.end(),
              [](const auto& a, const auto& b) { return (ULONG_PTR)a.value < (ULONG_PTR)b.value; });
    return result;
}

// Place srcHandle (from our process) into targetProc at desiredSlot if possible.
// Returns the actual slot used (may differ from desiredSlot on overshoot), or NULL on failure.
static HANDLE EnsureHandleAtValue(HANDLE targetProc, HANDLE srcHandle, HANDLE desiredSlot)
{
    // Clear the desired slot in case it's occupied by an orphan handle
    HANDLE clearDup = NULL;
    DuplicateHandle(targetProc, desiredSlot, GetCurrentProcess(), &clearDup, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    if (clearDup) CloseHandle(clearDup);

    std::vector<HANDLE> fillers;
    HANDLE actualSlot = NULL;

    for (;;)
    {
        HANDLE got = NULL;
        if (!DuplicateHandle(GetCurrentProcess(), srcHandle, targetProc, &got,
                             0, FALSE, DUPLICATE_SAME_ACCESS))
            break;

        if (got == desiredSlot)
        {
            actualSlot = got;
            break;
        }

        if ((ULONG_PTR)got > (ULONG_PTR)desiredSlot)
        {
            // Can't get exact slot; keep the overshot handle as-is and let caller patch memory
            actualSlot = got;
            break;
        }

        fillers.push_back(got);
    }

    // Close all filler handles
    for (auto h : fillers)
    {
        HANDLE fd = NULL;
        DuplicateHandle(targetProc, h, GetCurrentProcess(), &fd, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
        if (fd) CloseHandle(fd);
    }
    return actualSlot;
}

// Search target's writable IMAGE regions for oldVal and replace with newVal.
// Used when a file handle couldn't be placed at the exact snapshot slot.
static void PatchHandleInTargetMemory(HANDLE targetProcess,
                                       const std::vector<SnapRegion>& snapRegions,
                                       HANDLE oldVal, HANDLE newVal)
{
    const DWORD rwMask = PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    for (const auto& r : snapRegions)
    {
        if (r.state != MEM_COMMIT || r.type != MEM_IMAGE || !(r.protect & rwMask)) continue;

        char* buf = (char*)malloc(r.size);
        SIZE_T bytes;
        if (!ReadProcessMemory(targetProcess, r.base, buf, r.size, &bytes) || bytes < sizeof(HANDLE))
        {
            free(buf); continue;
        }

        bool patched = false;
        for (size_t off = 0; off + sizeof(HANDLE) <= bytes; off += sizeof(HANDLE))
        {
            HANDLE v;
            memcpy(&v, buf + off, sizeof(HANDLE));
            if (v == oldVal) { memcpy(buf + off, &newVal, sizeof(HANDLE)); patched = true; }
        }

        if (patched) WriteProcessMemory(targetProcess, r.base, buf, bytes, NULL);
        free(buf);
    }
}

static void RestoreFileHandles(HANDLE targetProcess, const std::vector<SavedFileHandle>& saved,
                                const std::vector<SnapRegion>& snapRegions)
{
    if (saved.empty()) return;

    for (const auto& sfh : saved)
    {
        // Check if the handle is currently valid and points to the right file
        HANDLE probe = NULL;
        bool needReopen = true;
        if (DuplicateHandle(targetProcess, sfh.value, GetCurrentProcess(), &probe,
                            0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            std::wstring cur = GetDosPathFromHandle(probe);
            CloseHandle(probe);
            if (!cur.empty() && _wcsicmp(cur.c_str(), sfh.dosPath.c_str()) == 0)
                needReopen = false;
        }

        HANDLE actualSlot = sfh.value;
        if (needReopen)
        {
            // GrantedAccess contains specific FILE_* bits, not GENERIC_* flags — use directly.
            DWORD access = sfh.access ? sfh.access : (GENERIC_READ | GENERIC_WRITE);
            HANDLE hFile = CreateFileW(sfh.dosPath.c_str(), access,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                printf("RestoreFileHandles: can't open %ls: ", sfh.dosPath.c_str());
                PrintError(GetLastError());
                continue;
            }

            actualSlot = EnsureHandleAtValue(targetProcess, hFile, sfh.value);
            CloseHandle(hFile);
            if (!actualSlot)
            {
                printf("RestoreFileHandles: failed to create handle for %ls\n", sfh.dosPath.c_str());
                continue;
            }

            // If we couldn't get the exact slot, patch all in-memory uses of the old handle value
            if (actualSlot != sfh.value)
            {
                printf("RestoreFileHandles: handle relocated %p -> %p, patching memory for %ls\n",
                       sfh.value, actualSlot, sfh.dosPath.c_str());
                PatchHandleInTargetMemory(targetProcess, snapRegions, sfh.value, actualSlot);
            }
        }

        // Restore file position (shared file object — setting on dup updates target's handle too)
        HANDLE dup = NULL;
        if (DuplicateHandle(targetProcess, actualSlot, GetCurrentProcess(), &dup,
                            0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            SetFilePointerEx(dup, sfh.position, NULL, FILE_BEGIN);
            CloseHandle(dup);
        }

        printf("Restored handle %p -> %ls @ %lld\n",
               actualSlot, sfh.dosPath.c_str(), sfh.position.QuadPart);
    }
}


// ---- DLL injection ----

// Inject dllPath (wide, absolute) into targetProc using a remote LoadLibraryW thread.
// Returns true if the remote thread exited with a non-zero module base.
static bool InjectDll(HANDLE targetProc, const wchar_t* dllPath)
{
    SIZE_T pathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(targetProc, NULL, pathBytes,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        printf("InjectDll: VirtualAllocEx failed: %lu\n", GetLastError());
        return false;
    }

    SIZE_T written;
    WriteProcessMemory(targetProc, remote, dllPath, pathBytes, &written);

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    auto fnLoad  = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(targetProc, NULL, 0, fnLoad, remote, 0, NULL);
    if (!hThread) {
        printf("InjectDll: CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(targetProc, remote, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, 10000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(targetProc, remote, 0, MEM_RELEASE);

    if (!exitCode) {
        printf("InjectDll: LoadLibraryW returned NULL in target\n");
        return false;
    }
    return true;
}

// ---- hook state shared memory ----

// Create (or open) the named shared memory section and return a mapped view.
// Caller must UnmapViewOfFile + CloseHandle the returned hMapping when done.
static SsHookState* OpenHookState(DWORD targetPID, HANDLE& hMappingOut)
{
    char name[64];
    sprintf_s(name, SS_HOOKSTATE_NAME_FMT, targetPID);
    hMappingOut = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                     0, (DWORD)sizeof(SsHookState), name);
    if (!hMappingOut) return nullptr;
    auto* s = (SsHookState*)MapViewOfFile(hMappingOut, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    return s;
}

// Write pre-snapshot file handle records into the shared hook state so that
// the DLL can populate its virtual table on load even for files opened before
// injection (CreateFile calls that the hooks didn't see).
static void PopulateHookState(SsHookState* state,
                               const std::vector<SavedFileHandle>& handles)
{
    state->count = 0;
    for (const auto& sfh : handles) {
        if (state->count >= SS_MAX_HANDLES) break;
        DWORD attrs = GetFileAttributesW(sfh.dosPath.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        SsHandleEntry& e = state->entries[state->count++];
        e.virt      = sfh.value;
        e.real      = sfh.value;   // virtual == real before first restore
        wcsncpy_s(e.path, sfh.dosPath.c_str(), MAX_PATH - 1);
        e.access    = sfh.access;
        e.shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        e.position  = sfh.position;
        e.active    = TRUE;
        e.objType   = SS_OBJ_FILE;
    }
}

// After memory + thread-context restore, update the real handle side of each
// active entry (reopen the file, dup it into the target).  The virtual handle
// value never changes, so target code that holds it continues to work.
static void RestoreFileHandlesViaHooks(HANDLE targetProc,
                                        SsHookState* state,
                                        const std::vector<SavedFileHandle>& saved)
{
    if (!state || saved.empty()) return;

    for (const auto& sfh : saved)
    {
        // Find the matching entry by virtual handle value.
        SsHandleEntry* e = nullptr;
        for (int i = 0; i < state->count; i++)
            if (state->entries[i].virt == sfh.value)
                { e = &state->entries[i]; break; }

        if (!e) {
            // Not in the hook table yet; add it.
            if (state->count >= SS_MAX_HANDLES) continue;
            e = &state->entries[state->count++];
            e->virt = sfh.value;
            wcsncpy_s(e->path, sfh.dosPath.c_str(), MAX_PATH - 1);
            e->access    = sfh.access;
            e->shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
            e->objType   = SS_OBJ_FILE;
        }

        // Close whatever the real handle slot currently is in the target (may be
        // stale from the modification phase or a previous restore).
        if (e->real && e->real != INVALID_HANDLE_VALUE) {
            HANDLE fd = NULL;
            if (DuplicateHandle(targetProc, e->real, GetCurrentProcess(),
                                &fd, 0, FALSE, DUPLICATE_CLOSE_SOURCE))
                CloseHandle(fd);
        }

        // Reopen the file in the controller, then dup into the target.
        DWORD access = sfh.access ? sfh.access : (GENERIC_READ | GENERIC_WRITE);
        DWORD attrs = GetFileAttributesW(sfh.dosPath.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            // Directory handle — nothing to restore; skip silently.
            e->active = FALSE;
            continue;
        }
        HANDLE hFile = CreateFileW(sfh.dosPath.c_str(), access,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            printf("RestoreHooks: can't open %ls: ", sfh.dosPath.c_str());
            PrintError(GetLastError());
            e->active = FALSE;
            continue;
        }

        // Restore file position before duping so the shared file object carries
        // the right offset into the target.
        SetFilePointerEx(hFile, sfh.position, NULL, FILE_BEGIN);

        HANDLE targetHandle = NULL;
        if (!DuplicateHandle(GetCurrentProcess(), hFile, targetProc,
                             &targetHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            printf("RestoreHooks: DuplicateHandle into target failed: ");
            PrintError(GetLastError());
            CloseHandle(hFile);
            e->active = FALSE;
            continue;
        }
        CloseHandle(hFile);

        e->real   = targetHandle;
        e->active = TRUE;
        printf("RestoreHooks: virt=%p -> real=%p (%ls)\n",
               sfh.value, targetHandle, sfh.dosPath.c_str());
    }
}

// ---- client registry ----

struct ClientRecord {
    DWORD    pid;
    HANDLE   process;
    HANDLE   hRequest;      // event: controller → client (request pending)
    HANDLE   hAtSafePoint;  // event: client → controller (at safe point)
    HANDLE   hDone;         // event: controller → client (op complete)
    HANDLE   hOpComplete;   // event: internal — fired when each op finishes
    SsControlBlock* ctrlBlock;
    HANDLE   hCtrlMap;
    SsHookState* hookState;
    HANDLE   hHookMap;
    HPSS     snapshot;
    std::vector<SavedFileHandle> fileHandles;
    bool     hasSnapshot;
    HANDLE   hWorkerThread;
};

static std::vector<ClientRecord*> g_clients;
static CRITICAL_SECTION           g_clientsLock;
static bool                       g_lockInit = false;

static void EnsureLock()
{
    if (!g_lockInit) { InitializeCriticalSection(&g_clientsLock); g_lockInit = true; }
}

static void EnqueueRequest(ClientRecord* c, SsRequestType req)
{
    InterlockedExchange(&c->ctrlBlock->pendingRequest, (LONG)req);
    SetEvent(c->hRequest);
}

// ---- per-client worker thread ----
// Waits for the client to reach a safe point, performs save or load, signals done.

static DWORD WINAPI ClientWorkerThread(LPVOID param)
{
    ClientRecord* c = (ClientRecord*)param;
    for (;;)
    {
        WaitForSingleObject(c->hAtSafePoint, INFINITE);

        LONG req = InterlockedExchange(&c->ctrlBlock->pendingRequest, SS_REQ_NONE);

        if (req == SS_REQ_SAVE)
        {
            printf("[%lu] Saving...\n", c->pid);
            if (c->snapshot) { PssFreeSnapshot(c->process, c->snapshot); c->snapshot = NULL; }
            c->snapshot     = TakeProcessSnapShot(c->process);
            c->fileHandles  = RecordFileHandles(c->process, c->snapshot);
            if (c->hookState) PopulateHookState(c->hookState, c->fileHandles);
            c->hasSnapshot  = true;
            InterlockedExchange(&c->ctrlBlock->lastCompletedOp, SS_REQ_SAVE);
            printf("[%lu] Save complete.\n", c->pid);
        }
        else if (req == SS_REQ_LOAD)
        {
            if (!c->hasSnapshot)
            {
                printf("[%lu] Load requested but no snapshot exists.\n", c->pid);
                InterlockedExchange(&c->ctrlBlock->lastCompletedOp, SS_REQ_NONE);
                SetEvent(c->hDone);
                SetEvent(c->hOpComplete);
                continue;
            }
            printf("[%lu] Loading...\n", c->pid);
            RestoreMemoryFromSnapshot(c->pid, c->process, c->snapshot,
                                      c->fileHandles, c->hookState);
            InterlockedExchange(&c->ctrlBlock->lastCompletedOp, SS_REQ_LOAD);
            printf("[%lu] Load complete.\n", c->pid);
        }
        else
        {
            printf("[%lu] Warning: safe-point signalled with no pending request.\n", c->pid);
        }

        SetEvent(c->hDone);
        SetEvent(c->hOpComplete);
    }
}

// ---- client setup ----
// Called after accepting a pipe connection.  Injects hooks, creates control block,
// writes setup-ack to hPipe, then spawns the per-client worker thread.

static ClientRecord* SetupClient(DWORD pid, HANDLE hPipe)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        printf("SetupClient: OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        DWORD ack = 0; DWORD n;
        WriteFile(hPipe, &ack, sizeof(ack), &n, NULL);
        return nullptr;
    }

    ClientRecord* c = new ClientRecord{};
    c->pid         = pid;
    c->process     = hProcess;
    c->hasSnapshot = false;
    c->snapshot    = NULL;

    // Control block (survives memory restore as MEM_MAPPED)
    char name[64];
    sprintf_s(name, SS_CONTROL_NAME_FMT, pid);
    c->hCtrlMap  = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                      0, (DWORD)sizeof(SsControlBlock), name);
    c->ctrlBlock = (SsControlBlock*)MapViewOfFile(c->hCtrlMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    memset(c->ctrlBlock, 0, sizeof(SsControlBlock));

    // Handshake events (client creates them before connecting)
    sprintf_s(name, SS_REQUEST_EVENT_FMT,   pid); c->hRequest     = OpenEventA(EVENT_ALL_ACCESS, FALSE, name);
    sprintf_s(name, SS_SAFEPOINT_EVENT_FMT, pid); c->hAtSafePoint = OpenEventA(EVENT_ALL_ACCESS, FALSE, name);
    sprintf_s(name, SS_DONE_EVENT_FMT,      pid); c->hDone        = OpenEventA(EVENT_ALL_ACCESS, FALSE, name);
    c->hOpComplete = CreateEventA(NULL, FALSE, FALSE, NULL);

    // Hook shared memory
    c->hookState = OpenHookState(pid, c->hHookMap);
    if (c->hookState) {
        c->hookState->targetPID      = pid;
        c->hookState->count          = 0;
        c->hookState->hooksInstalled = 0;
    }

    // Inject ss_hooks.dll (path relative to this exe)
    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(NULL, dllPath, MAX_PATH);
    wchar_t* slash = wcsrchr(dllPath, L'\\');
    if (slash) wcscpy_s(slash + 1, MAX_PATH - (slash - dllPath) - 1, L"ss_hooks.dll");

    char evName[64];
    sprintf_s(evName, SS_HOOKSREADY_NAME_FMT, pid);
    HANDLE hHooksReady = CreateEventA(NULL, FALSE, FALSE, evName);

    printf("[%lu] Injecting %ls...\n", pid, dllPath);
    bool injected = InjectDll(hProcess, dllPath);
    if (injected && hHooksReady) {
        if (WaitForSingleObject(hHooksReady, 5000) != WAIT_OBJECT_0)
            printf("[%lu] Warning: timed out waiting for hooks-ready.\n", pid);
        else
            printf("[%lu] Hooks installed.\n", pid);
    } else if (!injected) {
        printf("[%lu] Warning: DLL injection failed; file-handle restore degraded.\n", pid);
        if (c->hookState) { UnmapViewOfFile(c->hookState); c->hookState = nullptr; }
        if (c->hHookMap)  { CloseHandle(c->hHookMap);      c->hHookMap  = NULL;   }
    }
    if (hHooksReady) CloseHandle(hHooksReady);

    // Send setup-ack — unblocks client's SavestateProgramInit()
    DWORD ack = 1, n;
    WriteFile(hPipe, &ack, sizeof(ack), &n, NULL);

    // Register and start worker
    EnsureLock();
    EnterCriticalSection(&g_clientsLock);
    g_clients.push_back(c);
    LeaveCriticalSection(&g_clientsLock);

    c->hWorkerThread = CreateThread(NULL, 0, ClientWorkerThread, c, 0, NULL);
    printf("[%lu] Client ready.\n", pid);
    return c;
}

// ---- pipe server thread ----

// Create one named pipe instance with a null DACL so unelevated clients can
// connect even though snapshot.exe runs elevated.
static HANDLE CreateSavePipeInstance()
{
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE); // NULL DACL = allow everyone
    SECURITY_ATTRIBUTES sa = { sizeof(sa), &sd, FALSE };

    return CreateNamedPipeA(SS_PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        sizeof(DWORD), sizeof(DWORD), 0, &sa);
}

static DWORD WINAPI PipeServerThread(LPVOID)
{
    for (;;)
    {
        HANDLE hPipe = CreateSavePipeInstance();
        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("PipeServerThread: CreateNamedPipe failed: %lu\n", GetLastError());
            Sleep(1000); continue;
        }
        if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe); continue;
        }
        DWORD pid = 0, nRead = 0;
        ReadFile(hPipe, &pid, sizeof(pid), &nRead, NULL);
        if (pid && nRead == sizeof(DWORD))
            SetupClient(pid, hPipe);  // writes ack before returning
        CloseHandle(hPipe);
    }
}

// ---- hotkey thread ----

#define SS_HOTKEY_SAVE 1
#define SS_HOTKEY_LOAD 2

static DWORD WINAPI HotkeyThread(LPVOID)
{
    if (!RegisterHotKey(NULL, SS_HOTKEY_SAVE, MOD_NOREPEAT, VK_F5))
        printf("Warning: F5 hotkey registration failed (%lu)\n", GetLastError());
    if (!RegisterHotKey(NULL, SS_HOTKEY_LOAD, MOD_NOREPEAT, VK_F9))
        printf("Warning: F9 hotkey registration failed (%lu)\n", GetLastError());

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (msg.message != WM_HOTKEY) continue;
        SsRequestType req = (msg.wParam == SS_HOTKEY_SAVE) ? SS_REQ_SAVE : SS_REQ_LOAD;
        const char* label = (req == SS_REQ_SAVE) ? "Save" : "Load";

        EnsureLock();
        EnterCriticalSection(&g_clientsLock);
        if (g_clients.empty())
            printf("No clients connected.\n");
        else
            for (auto* c : g_clients) { EnqueueRequest(c, req); printf("[%lu] %s queued.\n", c->pid, label); }
        LeaveCriticalSection(&g_clientsLock);
    }
    return 0;
}

// ---- automated test runner ----

struct TestResults { int total; int passed; char log[4096]; int logPos; };

int RunAutomatedTest(const char* targetExe)
{
    DWORD myPID = GetCurrentProcessId();
    printf("=== Automated test (controller PID %lu) ===\n", myPID);
    EnsureLock();

    // Test-specific coordination events (keyed by our PID)
    char name[64];
    sprintf_s(name, "SS_Modified_%lu",  myPID); HANDLE hModified = CreateEventA(NULL, FALSE, FALSE, name);
    sprintf_s(name, "SS_TestDone_%lu",  myPID); HANDLE hTestDone = CreateEventA(NULL, FALSE, FALSE, name);

    sprintf_s(name, "SS_Results_%lu", myPID);
    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                     0, (DWORD)sizeof(TestResults), name);
    if (!hMap) { printf("CreateFileMappingA failed: %lu\n", GetLastError()); return 1; }
    TestResults* res = (TestResults*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    memset(res, 0, sizeof(*res));

    // Single pipe instance for this test run
    HANDLE hPipe = CreateSavePipeInstance();
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("CreateNamedPipe failed: %lu\n", GetLastError()); return 1;
    }

    // Spawn target with our PID for test coordination
    char cmdLine[512];
    sprintf_s(cmdLine, "\"%s\" %lu", targetExe, myPID);
    STARTUPINFOA si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to spawn %s: %lu\n", targetExe, GetLastError()); return 1;
    }
    CloseHandle(pi.hThread);
    printf("Spawned target PID %lu\n", pi.dwProcessId);

    // Accept connection, setup client (sends ack when done)
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("ConnectNamedPipe failed: %lu\n", GetLastError()); return 1;
    }
    DWORD targetPID = 0, nRead = 0;
    ReadFile(hPipe, &targetPID, sizeof(targetPID), &nRead, NULL);
    ClientRecord* c = SetupClient(targetPID, hPipe);
    CloseHandle(hPipe);
    if (!c) return 1;

    // Queue save — client services it at its first SavestateCheckpoint call
    printf("Queuing save...\n");
    EnqueueRequest(c, SS_REQ_SAVE);

    if (WaitForSingleObject(c->hOpComplete, 15000) != WAIT_OBJECT_0)
    { printf("Timed out waiting for save\n"); return 1; }

    // Wait for target to signal that it has trashed its state
    if (WaitForSingleObject(hModified, 15000) != WAIT_OBJECT_0)
    { printf("Timed out waiting for modifications\n"); return 1; }

    // Queue load — client services it at its next SavestateCheckpoint call
    printf("Queuing load...\n");
    EnqueueRequest(c, SS_REQ_LOAD);

    if (WaitForSingleObject(c->hOpComplete, 15000) != WAIT_OBJECT_0)
    { printf("Timed out waiting for load\n"); return 1; }

    // Wait for verification to complete
    if (WaitForSingleObject(hTestDone, 15000) != WAIT_OBJECT_0)
    { printf("Timed out waiting for test done\n"); return 1; }

    printf("\n--- Test Results (%d/%d passed) ---\n", res->passed, res->total);
    printf("%s", res->log);
    int passed = res->passed, total = res->total;
    printf("%s\n", (passed == total && total > 0) ? "ALL TESTS PASSED" : "TESTS FAILED");

    WaitForSingleObject(pi.hProcess, 5000);
    TerminateProcess(pi.hProcess, 0);
    if (c->snapshot) PssFreeSnapshot(c->process, c->snapshot);
    CloseHandle(pi.hProcess);
    if (c->hookState) UnmapViewOfFile(c->hookState);
    if (c->hHookMap)  CloseHandle(c->hHookMap);
    UnmapViewOfFile(res);
    CloseHandle(hMap);
    CloseHandle(hModified);
    CloseHandle(hTestDone);
    return (passed == total && total > 0) ? 0 : 1;
}


DWORD ProcessNameToID(char* name)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (_stricmp(entry.szExeFile, name) == 0)
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}
