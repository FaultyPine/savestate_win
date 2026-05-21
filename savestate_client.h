#pragma once
#include <windows.h>

// These match the definitions in ss_hooks.h; kept here so this header is
// self-contained (client programs only need to include savestate_client.h).
#ifndef SS_PIPE_NAME
#  define SS_REQUEST_EVENT_FMT   "SS_Request_%lu"
#  define SS_SAFEPOINT_EVENT_FMT "SS_AtSafePoint_%lu"
#  define SS_DONE_EVENT_FMT      "SS_Done_%lu"
#  define SS_CONTROL_NAME_FMT    "SS_Control_%lu"
#  define SS_PIPE_NAME           "\\\\.\\pipe\\savestate"
#  define SS_REQ_LOAD 2
#endif

// ---- types and declarations (always visible) ----

// Return value of SavestateCheckpoint().
typedef enum {
    SS_CHECKPOINT_NONE   = 0,  // no request pending; returned immediately
    SS_CHECKPOINT_SAVED  = 1,  // state was saved at this checkpoint
    SS_CHECKPOINT_LOADED = 2,  // state was loaded; execution resumed here
} SsCheckpointResult;

// Connect to the savestate controller and block until it has finished setup
// (hooks injected, control block created).  Safe to call before any file I/O.
// No-op if the controller is not running.
void SavestateProgramInit(void);

// Call at any safe point in your program's loop.  If a save or load request
// is pending, services it and blocks until complete.
//
// After a load the thread context is restored to inside this function; when it
// returns the caller sees SS_CHECKPOINT_LOADED and all process memory is back
// to the saved state.
SsCheckpointResult SavestateCheckpoint(void);

// ---- implementation (define SAVESTATE_CLIENT_IMPLEMENTATION in one .c/.cpp) ----
#ifdef SAVESTATE_CLIENT_IMPLEMENTATION

#include <stdio.h>

// Declared static so these globals live in the target's .data section and are
// restored along with all other process memory on a load.  The kernel objects
// they reference (events, file mapping) persist across memory restores, so the
// handle values remain valid after a load.
static HANDLE         _ss_hRequest     = NULL;
static HANDLE         _ss_hAtSafePoint = NULL;
static HANDLE         _ss_hDone        = NULL;
static volatile LONG* _ss_pLastOp      = NULL;  // &SsControlBlock::lastCompletedOp
static HANDLE         _ss_hCtrlMap     = NULL;

void SavestateProgramInit(void)
{
    DWORD pid = GetCurrentProcessId();
    char  name[64];

    // Create per-process handshake events. Controller opens them by name after
    // receiving our PID over the pipe.
    sprintf_s(name, sizeof(name), SS_REQUEST_EVENT_FMT,   pid);
    _ss_hRequest = CreateEventA(NULL, FALSE, FALSE, name);
    sprintf_s(name, sizeof(name), SS_SAFEPOINT_EVENT_FMT, pid);
    _ss_hAtSafePoint = CreateEventA(NULL, FALSE, FALSE, name);
    sprintf_s(name, sizeof(name), SS_DONE_EVENT_FMT,      pid);
    _ss_hDone = CreateEventA(NULL, FALSE, FALSE, name);

    // Connect to controller pipe, send PID, and block until the controller
    // sends back a setup-ack (written just before closing its pipe end).
    for (int i = 0; i < 40; i++) {
        HANDLE hPipe = CreateFileA(SS_PIPE_NAME,
                                   GENERIC_READ | GENERIC_WRITE,
                                   0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            DWORD n;
            WriteFile(hPipe, &pid, sizeof(pid), &n, NULL);
            DWORD ack = 0;
            ReadFile(hPipe, &ack, sizeof(ack), &n, NULL); // blocks until setup done
            CloseHandle(hPipe);
            break;
        }
        if (GetLastError() == ERROR_PIPE_BUSY)
            WaitNamedPipeA(SS_PIPE_NAME, 2000);
        else
            Sleep(500);
    }

    // Open control block created by the controller during setup.
    sprintf_s(name, sizeof(name), SS_CONTROL_NAME_FMT, pid);
    _ss_hCtrlMap = OpenFileMappingA(FILE_MAP_READ, FALSE, name);
    if (_ss_hCtrlMap) {
        LONG* base = (LONG*)MapViewOfFile(_ss_hCtrlMap, FILE_MAP_READ,
                                          0, 0, sizeof(LONG) * 2);
        if (base)
            _ss_pLastOp = &base[1]; // SsControlBlock::lastCompletedOp
    }
}

SsCheckpointResult SavestateCheckpoint(void)
{
    if (!_ss_hRequest) return SS_CHECKPOINT_NONE;
    if (WaitForSingleObject(_ss_hRequest, 0) != WAIT_OBJECT_0)
        return SS_CHECKPOINT_NONE;

    SetEvent(_ss_hAtSafePoint);
    WaitForSingleObject(_ss_hDone, INFINITE);

    if (_ss_pLastOp)
        return (*_ss_pLastOp == SS_REQ_LOAD) ? SS_CHECKPOINT_LOADED
                                             : SS_CHECKPOINT_SAVED;
    return SS_CHECKPOINT_SAVED;
}

#endif // SAVESTATE_CLIENT_IMPLEMENTATION
