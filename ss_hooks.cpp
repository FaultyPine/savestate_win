#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <psapi.h>
#include <stdio.h>
#include "ss_hooks.h"

#pragma comment(lib, "psapi.lib")

// ---- module-level state ----

static HANDLE       g_hMapping  = NULL;
static SsHookState* g_state     = NULL;
static DWORD        g_myPID     = 0;

// Real function pointers — captured from kernel32 before IAT patching.
// These live in .data (MEM_IMAGE writable), so they survive memory restore
// intact (they hold the pre-patch addresses at snapshot time, which is
// exactly what they should hold after restore).
static HANDLE (WINAPI *Real_CreateFileA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
static HANDLE (WINAPI *Real_CreateFileW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
static BOOL   (WINAPI *Real_CloseHandle)(HANDLE);
static BOOL   (WINAPI *Real_ReadFile)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
static BOOL   (WINAPI *Real_WriteFile)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
static BOOL   (WINAPI *Real_SetFilePointerEx)(HANDLE,LARGE_INTEGER,PLARGE_INTEGER,DWORD);
static BOOL   (WINAPI *Real_GetFileSizeEx)(HANDLE,PLARGE_INTEGER);
static BOOL   (WINAPI *Real_FlushFileBuffers)(HANDLE);
static BOOL   (WINAPI *Real_DuplicateHandle)(HANDLE,HANDLE,HANDLE,LPHANDLE,DWORD,BOOL,DWORD);


// ---- virtual handle table helpers ----

static SsHandleEntry* FindEntry(HANDLE virt)
{
    if (!g_state) return nullptr;
    for (int i = 0; i < g_state->count; i++)
        if (g_state->entries[i].active && g_state->entries[i].virt == virt)
            return &g_state->entries[i];
    return nullptr;
}

static SsHandleEntry* AllocEntry()
{
    if (!g_state || g_state->count >= SS_MAX_HANDLES) return nullptr;
    return &g_state->entries[g_state->count++];
}

// Translate virtual handle to real; passthrough if not tracked.
static HANDLE RealH(HANDLE virt)
{
    SsHandleEntry* e = FindEntry(virt);
    return e ? e->real : virt;
}


// ---- IAT patching ----

static void PatchOneIAT(HMODULE hMod, const char* importDll,
                        const char* funcName, void* hookFn)
{
    if (!hMod) return;
    __try {
        auto* dos = (PIMAGE_DOS_HEADER)hMod;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        auto* nt = (PIMAGE_NT_HEADERS)((char*)hMod + dos->e_lfanew);
        DWORD impRVA = nt->OptionalHeader
                          .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                          .VirtualAddress;
        if (!impRVA) return;
        auto* imp = (PIMAGE_IMPORT_DESCRIPTOR)((char*)hMod + impRVA);
        for (; imp->Name; imp++) {
            const char* dll = (const char*)((char*)hMod + imp->Name);
            if (_stricmp(dll, importDll) != 0) continue;
            if (!imp->OriginalFirstThunk || !imp->FirstThunk) continue;
            auto* orig = (PIMAGE_THUNK_DATA)((char*)hMod + imp->OriginalFirstThunk);
            auto* iat  = (PIMAGE_THUNK_DATA)((char*)hMod + imp->FirstThunk);
            for (; orig->u1.AddressOfData; orig++, iat++) {
                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;
                auto* byName = (PIMAGE_IMPORT_BY_NAME)(
                    (char*)hMod + orig->u1.AddressOfData);
                if (strcmp(byName->Name, funcName) != 0) continue;
                DWORD old;
                VirtualProtect(&iat->u1.Function, sizeof(ULONG_PTR),
                               PAGE_READWRITE, &old);
                iat->u1.Function = (ULONG_PTR)hookFn;
                VirtualProtect(&iat->u1.Function, sizeof(ULONG_PTR), old, &old);
                return;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

struct HookDef { const char* dll; const char* fn; void* hook; };

static void PatchModule(HMODULE hMod, const HookDef* defs, int n)
{
    for (int i = 0; i < n; i++)
        PatchOneIAT(hMod, defs[i].dll, defs[i].fn, defs[i].hook);
}


// ---- hook implementations ----

static HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpName, DWORD acc, DWORD share, LPSECURITY_ATTRIBUTES sec,
    DWORD disp, DWORD flags, HANDLE tmpl)
{
    HANDLE h = Real_CreateFileW(lpName, acc, share, sec, disp, flags, tmpl);
    if (h != INVALID_HANDLE_VALUE && g_state) {
        SsHandleEntry* e = AllocEntry();
        if (e) {
            e->virt     = h;
            e->real     = h;
            wcsncpy_s(e->path, lpName, MAX_PATH - 1);
            e->access   = acc;
            e->shareMode= share;
            e->position = {};
            e->active   = TRUE;
            e->objType  = SS_OBJ_FILE;
        }
    }
    return h;
}

static HANDLE WINAPI Hook_CreateFileA(
    LPCSTR lpName, DWORD acc, DWORD share, LPSECURITY_ATTRIBUTES sec,
    DWORD disp, DWORD flags, HANDLE tmpl)
{
    HANDLE h = Real_CreateFileA(lpName, acc, share, sec, disp, flags, tmpl);
    if (h != INVALID_HANDLE_VALUE && g_state) {
        SsHandleEntry* e = AllocEntry();
        if (e) {
            e->virt     = h;
            e->real     = h;
            MultiByteToWideChar(CP_ACP, 0, lpName, -1, e->path, MAX_PATH);
            e->access   = acc;
            e->shareMode= share;
            e->position = {};
            e->active   = TRUE;
            e->objType  = SS_OBJ_FILE;
        }
    }
    return h;
}

static BOOL WINAPI Hook_CloseHandle(HANDLE h)
{
    SsHandleEntry* e = FindEntry(h);
    if (e) {
        BOOL r = Real_CloseHandle(e->real);
        e->active = FALSE;
        return r;
    }
    return Real_CloseHandle(h);
}

static BOOL WINAPI Hook_ReadFile(
    HANDLE h, LPVOID buf, DWORD n, LPDWORD read, LPOVERLAPPED ov)
{
    return Real_ReadFile(RealH(h), buf, n, read, ov);
}

static BOOL WINAPI Hook_WriteFile(
    HANDLE h, LPCVOID buf, DWORD n, LPDWORD written, LPOVERLAPPED ov)
{
    return Real_WriteFile(RealH(h), buf, n, written, ov);
}

static BOOL WINAPI Hook_SetFilePointerEx(
    HANDLE h, LARGE_INTEGER dist, PLARGE_INTEGER newPos, DWORD method)
{
    return Real_SetFilePointerEx(RealH(h), dist, newPos, method);
}

static BOOL WINAPI Hook_GetFileSizeEx(HANDLE h, PLARGE_INTEGER size)
{
    return Real_GetFileSizeEx(RealH(h), size);
}

static BOOL WINAPI Hook_FlushFileBuffers(HANDLE h)
{
    return Real_FlushFileBuffers(RealH(h));
}

// Duplicate: if the source is a virtual handle in our table, use its real handle.
static BOOL WINAPI Hook_DuplicateHandle(
    HANDLE srcProc, HANDLE srcH, HANDLE dstProc,
    LPHANDLE dstH, DWORD acc, BOOL inherit, DWORD opts)
{
    HANDLE self = GetCurrentProcess();
    HANDLE realSrc = srcH;
    if (srcProc == self || srcProc == (HANDLE)(ULONG_PTR)-1) {
        SsHandleEntry* e = FindEntry(srcH);
        if (e) realSrc = e->real;
    }
    return Real_DuplicateHandle(srcProc, realSrc, dstProc, dstH, acc, inherit, opts);
}


// ---- install hooks in every loaded module ----

static void InstallAllHooks()
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return;

    // Capture real addresses before any patching.
#define GETFN(name) Real_##name = (decltype(Real_##name))GetProcAddress(k32, #name)
    GETFN(CreateFileA);
    GETFN(CreateFileW);
    GETFN(CloseHandle);
    GETFN(ReadFile);
    GETFN(WriteFile);
    GETFN(SetFilePointerEx);
    GETFN(GetFileSizeEx);
    GETFN(FlushFileBuffers);
    GETFN(DuplicateHandle);
#undef GETFN

    HookDef defs[] = {
        { "kernel32.dll", "CreateFileA",      Hook_CreateFileA      },
        { "kernel32.dll", "CreateFileW",      Hook_CreateFileW      },
        { "kernel32.dll", "CloseHandle",      Hook_CloseHandle      },
        { "kernel32.dll", "ReadFile",         Hook_ReadFile         },
        { "kernel32.dll", "WriteFile",        Hook_WriteFile        },
        { "kernel32.dll", "SetFilePointerEx", Hook_SetFilePointerEx },
        { "kernel32.dll", "GetFileSizeEx",    Hook_GetFileSizeEx    },
        { "kernel32.dll", "FlushFileBuffers", Hook_FlushFileBuffers },
        { "kernel32.dll", "DuplicateHandle",  Hook_DuplicateHandle  },
    };
    int nDefs = (int)(sizeof(defs) / sizeof(defs[0]));

    HMODULE mods[512];
    DWORD needed = 0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        int n = (int)(needed / sizeof(HMODULE));
        for (int i = 0; i < n; i++)
            PatchModule(mods[i], defs, nDefs);
    }
}


// ---- DLL-internal init (called from DllMain on injection) ----

static void SavestateDllInit(DWORD targetPID)
{
    if (g_state) return;  // already initialised (idempotent)
    if (targetPID == 0) targetPID = GetCurrentProcessId();
    g_myPID = targetPID;

    char mapName[64];
    sprintf_s(mapName, SS_HOOKSTATE_NAME_FMT, targetPID);

    // Open an existing mapping (created by the controller) or create one
    // for voluntary opt-in (program calls this itself before any file opens).
    g_hMapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, mapName);
    if (!g_hMapping)
        g_hMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                        PAGE_READWRITE, 0,
                                        (DWORD)sizeof(SsHookState), mapName);
    if (!g_hMapping) return;

    g_state = (SsHookState*)MapViewOfFile(g_hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!g_state) { CloseHandle(g_hMapping); g_hMapping = NULL; return; }

    if (g_state->targetPID == 0) {
        g_state->targetPID = targetPID;
        g_state->count     = 0;
    }

    InstallAllHooks();

    // Signal the controller (if it is waiting) that hooks are live.
    char evName[64];
    sprintf_s(evName, SS_HOOKSREADY_NAME_FMT, targetPID);
    HANDLE hEv = OpenEventA(EVENT_MODIFY_STATE, FALSE, evName);
    if (hEv) { SetEvent(hEv); CloseHandle(hEv); }

    InterlockedExchange(&g_state->hooksInstalled, 1);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        SavestateDllInit(0);
    return TRUE;
}
