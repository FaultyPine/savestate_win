#pragma once
#include <Windows.h>

#define SS_MAX_HANDLES          256
#define SS_HOOKSTATE_NAME_FMT   "SS_HookState_%lu"
#define SS_HOOKSREADY_NAME_FMT  "SS_HooksReady_%lu"
#define SS_CONTROL_NAME_FMT     "SS_Control_%lu"
#define SS_REQUEST_EVENT_FMT    "SS_Request_%lu"
#define SS_SAFEPOINT_EVENT_FMT  "SS_AtSafePoint_%lu"
#define SS_DONE_EVENT_FMT       "SS_Done_%lu"
#define SS_PIPE_NAME            "\\\\.\\pipe\\savestate"

enum SsRequestType { SS_REQ_NONE = 0, SS_REQ_SAVE = 1, SS_REQ_LOAD = 2 };

// Shared between controller and client. Lives in named file-mapping so it
// survives memory restore (MEM_MAPPED regions are not touched by restore).
struct SsControlBlock {
    volatile LONG pendingRequest;   // SsRequestType — set by controller
    volatile LONG lastCompletedOp;  // SsRequestType — written before signalling Done
};

enum SsObjType { SS_OBJ_FILE = 0 };

// One entry per tracked handle.  Shared between the hook DLL (inside the target
// process) and the controller (snapshot.exe).  The controller writes new real
// handle values here during restore; the DLL reads them transparently.
struct SsHandleEntry {
    HANDLE        virt;            // stable value that lives in target memory
    HANDLE        real;            // current OS handle value
    WCHAR         path[MAX_PATH];  // file path (DOS format)
    DWORD         access;
    DWORD         shareMode;
    LARGE_INTEGER position;        // file position at snapshot time
    BOOL          active;          // FALSE after CloseHandle, TRUE after re-open
    SsObjType     objType;
};

// Layout of the named shared-memory section "SS_HookState_<targetPID>".
// Shared between controller and the hook DLL.
struct SsHookState {
    DWORD         targetPID;
    volatile LONG hooksInstalled;  // DLL sets 1 after IAT patching completes
    int           count;           // total entries (active + inactive)
    SsHandleEntry entries[SS_MAX_HANDLES];
};

