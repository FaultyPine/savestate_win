#define SAVESTATE_CLIENT_IMPLEMENTATION
#include "savestate_client.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct TestResults {
    int  total;
    int  passed;
    char log[4096];
    int  logPos;
};

// ---- all test state is global so memory restore brings it back ----

static char  g_large[1024 * 1024];

#define N_HEAP 8
static char* g_heap[N_HEAP];

#define N_WORKERS 3
struct WorkerState { char buf[8192]; volatile int phase; };
static WorkerState g_workers[N_WORKERS];
static HANDLE      g_hWorkerHold;

static HANDLE        g_hFile = INVALID_HANDLE_VALUE;
static char          g_filePath[MAX_PATH];
static LARGE_INTEGER g_snapPos;

// ---- worker threads ----

static DWORD WINAPI WorkerThread(LPVOID param)
{
    int id = (int)(INT_PTR)param;
    for (int i = 0; i < (int)sizeof(g_workers[id].buf); i++)
        g_workers[id].buf[i] = (char)('a' + id + i % 19);
    g_workers[id].phase = 1;
    WaitForSingleObject(g_hWorkerHold, INFINITE);
    return 0;
}

static void Log(TestResults* r, const char* label, bool pass)
{
    r->total++;
    if (pass) r->passed++;
    int n = _snprintf_s(r->log + r->logPos, sizeof(r->log) - r->logPos, _TRUNCATE,
                        "  [%s] %s\n", pass ? "PASS" : "FAIL", label);
    if (n > 0) r->logPos += n;
}

int main(int argc, char** argv)
{
    // ctrlPID is passed by RunAutomatedTest for test-specific coordination.
    // In standalone / interactive use it is omitted.
    DWORD ctrlPID = (argc > 1) ? (DWORD)atoi(argv[1]) : 0;

    // Open test coordination objects (created by RunAutomatedTest)
    char name[64];
    HANDLE hModified = NULL, hTestDone = NULL;
    TestResults* res = NULL;
    HANDLE hResMap   = NULL;
    if (ctrlPID) {
        sprintf_s(name, "SS_Modified_%lu",  ctrlPID); hModified = OpenEventA(EVENT_ALL_ACCESS, FALSE, name);
        sprintf_s(name, "SS_TestDone_%lu",  ctrlPID); hTestDone = OpenEventA(EVENT_ALL_ACCESS, FALSE, name);
        sprintf_s(name, "SS_Results_%lu",   ctrlPID); hResMap   = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (hResMap) { res = (TestResults*)MapViewOfFile(hResMap, FILE_MAP_ALL_ACCESS, 0, 0, 0); memset(res, 0, sizeof(*res)); }
    }

    // Worker-hold event (manual-reset, starts unsignalled; restored with memory)
    sprintf_s(name, "SS_WorkerHold_%lu", GetCurrentProcessId());
    g_hWorkerHold = CreateEventA(NULL, TRUE, FALSE, name);

    // Connect to snapshotter — blocks until hooks are injected and control
    // block is ready.  Returns immediately if no controller is running.
    SavestateProgramInit();

    // ---- T1: large static buffer ----
    for (int i = 0; i < (int)sizeof(g_large); i++)
        g_large[i] = (char)((i * 7 + 3) % 251 + 1);

    // ---- T2: heap allocations ----
    for (int i = 0; i < N_HEAP; i++) {
        g_heap[i] = (char*)malloc(4096);
        for (int j = 0; j < 4096; j++)
            g_heap[i][j] = (char)('0' + (i + j) % 74);
    }

    // ---- T3: worker threads ----
    memset(g_workers, 0, sizeof(g_workers));
    for (int i = 0; i < N_WORKERS; i++)
        CloseHandle(CreateThread(NULL, 0, WorkerThread, (LPVOID)(INT_PTR)i, 0, NULL));
    for (int i = 0; i < N_WORKERS; i++)
        while (g_workers[i].phase == 0) Sleep(1);

    // ---- T4/T5: file handle ----
    GetTempPathA(MAX_PATH, g_filePath);
    strncat_s(g_filePath, "ss_test.tmp", MAX_PATH);
    g_hFile = CreateFileA(g_filePath, GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    const char sentinel[] = "SAVESTATE_SENTINEL_DATA";
    DWORD bw;
    WriteFile(g_hFile, sentinel, (DWORD)(sizeof(sentinel) - 1), &bw, NULL);
    LARGE_INTEGER zero = {};
    SetFilePointerEx(g_hFile, zero, &g_snapPos, FILE_CURRENT);

    // ---- T6: stack data ----
    char stackBuf[512];
    for (int i = 0; i < 512; i++) stackBuf[i] = (char)(i ^ 0xC3);

    // First checkpoint: controller has queued SS_REQ_SAVE, so this call saves
    // state and returns SS_CHECKPOINT_SAVED.  After a subsequent load the
    // thread context is restored to inside this call; it then returns
    // SS_CHECKPOINT_LOADED and we fall through to the verification block.
    SsCheckpointResult r = SavestateCheckpoint();

    if (r != SS_CHECKPOINT_LOADED)
    {
        // ---- MODIFICATION PHASE ----
        memset(g_large, 0xAA, sizeof(g_large));

        for (int i = 0; i < N_HEAP; i++) { free(g_heap[i]); g_heap[i] = NULL; }
        volatile char* orphan = (char*)malloc(32768);
        memset((void*)orphan, 0xBB, 32768);

        for (int i = 0; i < N_WORKERS; i++) {
            memset(g_workers[i].buf, 0xCC, sizeof(g_workers[i].buf));
            g_workers[i].phase = 99;
        }

        SetFilePointerEx(g_hFile, zero, NULL, FILE_BEGIN);
        const char bad[] = "TRASHED!!!";
        WriteFile(g_hFile, bad, (DWORD)(sizeof(bad) - 1), &bw, NULL);
        CloseHandle(g_hFile);
        g_hFile = INVALID_HANDLE_VALUE;

        memset(stackBuf, 0xDD, sizeof(stackBuf));

        // Signal test runner: state is trashed, please queue a load.
        if (hModified) SetEvent(hModified);

        // Second checkpoint: controller queues SS_REQ_LOAD here.
        // Spin briefly in case the controller hasn't queued it yet.
        SsCheckpointResult r2 = SS_CHECKPOINT_NONE;
        while (r2 == SS_CHECKPOINT_NONE)
        {
            r2 = SavestateCheckpoint();
            if (r2 == SS_CHECKPOINT_NONE) Sleep(1);
        }
        return 2; // unreachable after restore
    }

    // ---- VERIFICATION PHASE ----
    if (!res) return 0;

    // T1
    { bool ok = true;
      for (int i = 0; i < (int)sizeof(g_large) && ok; i++)
          if (g_large[i] != (char)((i * 7 + 3) % 251 + 1)) ok = false;
      Log(res, "T1: large static buffer", ok); }

    // T2
    { bool ok = true;
      for (int i = 0; i < N_HEAP && ok; i++) {
          if (!g_heap[i]) { ok = false; break; }
          for (int j = 0; j < 4096 && ok; j++)
              if (g_heap[i][j] != (char)('0' + (i + j) % 74)) ok = false;
      }
      Log(res, "T2: heap allocations", ok); }

    // T3
    { bool ok = true;
      for (int i = 0; i < N_WORKERS && ok; i++) {
          if (g_workers[i].phase != 1) { ok = false; break; }
          for (int j = 0; j < (int)sizeof(g_workers[i].buf) && ok; j++)
              if (g_workers[i].buf[j] != (char)('a' + i + j % 19)) ok = false;
      }
      Log(res, "T3: worker thread buffers", ok); }
    SetEvent(g_hWorkerHold);

    // T4
    { LARGE_INTEGER cur = {};
      bool valid = (g_hFile != INVALID_HANDLE_VALUE);
      bool posOk = false;
      if (valid) { SetFilePointerEx(g_hFile, zero, &cur, FILE_CURRENT); posOk = (cur.QuadPart == g_snapPos.QuadPart); }
      Log(res, "T4: file handle valid + position", valid && posOk); }

    // T5
    { bool ok = false;
      if (g_hFile != INVALID_HANDLE_VALUE) {
          const char probe[] = "RESTORED_OK";
          DWORD bw2, br;
          char readback[sizeof(probe)] = {};
          ok = WriteFile(g_hFile, probe, (DWORD)(sizeof(probe) - 1), &bw2, NULL)
               && bw2 == sizeof(probe) - 1;
          SetFilePointerEx(g_hFile, g_snapPos, NULL, FILE_BEGIN);
          ok = ok && ReadFile(g_hFile, readback, (DWORD)(sizeof(probe) - 1), &br, NULL)
               && br == sizeof(probe) - 1
               && memcmp(readback, probe, sizeof(probe) - 1) == 0;
      }
      Log(res, "T5: file handle R/W functional", ok); }

    // T6
    { bool ok = true;
      for (int i = 0; i < 512 && ok; i++)
          if (stackBuf[i] != (char)(i ^ 0xC3)) ok = false;
      Log(res, "T6: stack variable", ok); }

    if (hTestDone) SetEvent(hTestDone);
    Sleep(3000);
    return 0;
}
