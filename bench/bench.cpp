// EpsHook vs MinHook benchmark + functional test
//
// Measures per-call overhead of:
//   baseline  — unhooked
//   MinHook   — classic detour (jmp -> hook -> trampoline)
//   EpsHook   — classic detour (same shape)
//   EpsHook   — spy mode (full context save + dispatch + original)
// and reports install/remove cost for both engines.

#include <windows.h>
#include <cstdio>
#include <cstdint>

#include <MinHook.h>
#include "epshook.h"

static volatile uint64_t g_sink = 0;
static volatile uint64_t g_spyHits = 0;

typedef int (*Fn)(int);

__declspec(noinline) static int TargetFn(int x) {
    return x * 3 + 1;
}

static Fn g_origMH = nullptr;
static Fn g_origEP = nullptr;

__declspec(noinline) static int MH_Hook(int x) { return g_origMH(x); }
__declspec(noinline) static int EP_Hook(int x) { return g_origEP(x); }

static void EP_Spy(epshook::SavedRegs*) { g_spyHits++; }

static void EpsLog(const char* msg) { printf("  %s\n", msg); }

static double Sec() {
    LARGE_INTEGER f, t;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / f.QuadPart;
}

// returns ns per call
static double Bench(Fn f, int iters, uint64_t* outSum) {
    uint64_t acc = 0;
    double t0 = Sec();
    for (int i = 0; i < iters; i++) acc += (uint64_t)f(i);
    double t1 = Sec();
    g_sink += acc;
    *outSum = acc;
    return (t1 - t0) * 1e9 / iters;
}

static LONG WINAPI OnCrash(EXCEPTION_POINTERS* ep) {
    fprintf(stderr, "CRASH: code=0x%08lX addr=%p rip=%p rsp=%p\n",
        ep->ExceptionRecord->ExceptionCode,
        ep->ExceptionRecord->ExceptionAddress,
        (void*)ep->ContextRecord->Rip, (void*)ep->ContextRecord->Rsp);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    SetUnhandledExceptionFilter(OnCrash);
    printf("==============================\n");
    printf("  EpsHook v2 vs MinHook bench\n");
    printf("==============================\n\n");

    uint64_t sumBase = 0, sumMH = 0, sumEP = 0, sumSpy = 0;
    const int N = 100000000;
    const int NSPY = 10000000;
    const int NINSTALL = 50;

    // ── baseline ────────────────────────────────────────────────
    Fn target = TargetFn;
    printf("[*] sanity: target(5) = %d (expect 16)\n", target(5));
    if (target(5) != 16) { printf("[-] sanity failed\n"); return 1; }

    double base = Bench(target, N, &sumBase);
    printf("[+] baseline      %7.3f ns/call\n", base);

    // ── install cost: MinHook ───────────────────────────────────
    if (MH_Initialize() != MH_OK) { printf("[-] MH_Initialize failed\n"); return 1; }
    double t0 = Sec();
    for (int i = 0; i < NINSTALL; i++) {
        MH_CreateHook((void*)TargetFn, (void*)MH_Hook, (void**)&g_origMH);
        MH_EnableHook((void*)TargetFn);
        MH_DisableHook((void*)TargetFn);
        MH_RemoveHook((void*)TargetFn);
    }
    double mhInstall = (Sec() - t0) * 1e6 / NINSTALL;
    printf("[+] MinHook install+remove: %8.1f us/op\n", mhInstall);

    // ── install cost: EpsHook ───────────────────────────────────
    epshook::SetLog(EpsLog);   // show engine log once...
    epshook::Create((void*)TargetFn, (void*)EP_Hook, (void**)&g_origEP);
    epshook::Remove((void*)TargetFn);
    epshook::SetLog(nullptr);  // ...then stay quiet while timing
    t0 = Sec();
    for (int i = 0; i < NINSTALL; i++) {
        epshook::Status s = epshook::Create((void*)TargetFn, (void*)EP_Hook, (void**)&g_origEP);
        if (s != epshook::OK) { printf("[-] epshook create failed: %s\n", epshook::StatusString(s)); return 1; }
        epshook::Disable((void*)TargetFn);
        epshook::Remove((void*)TargetFn);
    }
    double epInstall = (Sec() - t0) * 1e6 / NINSTALL;
    printf("[+] EpsHook install+remove: %8.1f us/op\n\n", epInstall);

    // ── MinHook detour ──────────────────────────────────────────
    if (MH_CreateHook((void*)TargetFn, (void*)MH_Hook, (void**)&g_origMH) != MH_OK ||
        MH_EnableHook((void*)TargetFn) != MH_OK) {
        printf("[-] MH hook failed\n");
        return 1;
    }
    if (target(5) != 16) { printf("[-] MinHook result mismatch!\n"); return 1; }
    double mh = Bench(target, N, &sumMH);
    MH_DisableHook((void*)TargetFn);
    MH_RemoveHook((void*)TargetFn);
    printf("[+] MinHook detour %7.3f ns/call (x%.1f)\n", mh, mh / base);

    // ── EpsHook detour ──────────────────────────────────────────
    if (epshook::Create((void*)TargetFn, (void*)EP_Hook, (void**)&g_origEP) != epshook::OK) {
        printf("[-] epshook detour failed\n");
        return 1;
    }
    if (target(5) != 16) { printf("[-] EpsHook detour result mismatch!\n"); return 1; }
    double ep = Bench(target, N, &sumEP);
    epshook::Remove((void*)TargetFn);
    printf("[+] EpsHook detour %7.3f ns/call (x%.1f)\n", ep, ep / base);

    // ── EpsHook spy ─────────────────────────────────────────────
    if (epshook::CreateSpy((void*)TargetFn, EP_Spy) != epshook::OK) {
        printf("[-] epshook spy failed\n");
        return 1;
    }
    if (target(5) != 16) { printf("[-] EpsHook spy result mismatch!\n"); return 1; }
    g_spyHits = 0;
    double spy = Bench(target, NSPY, &sumSpy);
    uint64_t spyHits = g_spyHits;
    epshook::Remove((void*)TargetFn);
    printf("[+] EpsHook spy    %7.3f ns/call (x%.1f)  [%llu dispatches]\n",
           spy, spy / base, (unsigned long long)spyHits);

    // spy ran NSPY iterations — compare against an unhooked run of the same size
    uint64_t sumSpyRef = 0;
    Bench(target, NSPY, &sumSpyRef);

    // ── results consistency ─────────────────────────────────────
    printf("\n[*] result sums: base(N)=%llu mh(N)=%llu ep(N)=%llu spy(%d)=%llu ref(%d)=%llu\n",
           (unsigned long long)sumBase, (unsigned long long)sumMH,
           (unsigned long long)sumEP, NSPY, (unsigned long long)sumSpy,
           NSPY, (unsigned long long)sumSpyRef);
    bool ok = (sumBase == sumMH) && (sumBase == sumEP) &&
              (sumSpy == sumSpyRef) && (spyHits == (uint64_t)NSPY);
    printf(ok ? "[+] ALL RESULTS MATCH — functional test PASSED\n"
              : "[-] RESULT MISMATCH — functional test FAILED\n");

    MH_Uninitialize();
    return ok ? 0 : 1;
}
