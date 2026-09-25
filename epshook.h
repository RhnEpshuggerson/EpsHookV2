// EpsHook v2 — x64 detour + register-spy hook engine
// MIT License — free and open source
//
// Modes:
//   Create()      — classic detour: target JMP -> your hook, hook calls original()
//   CreateSpy()   — observer: saves all volatile regs + flags, calls your dispatch,
//                   then executes original code untouched (control flow unchanged)
//
// Safety contract:
//   - Original bytes are captured BEFORE any patching
//   - Stolen instructions are fully relocated (RIP-relative + relative branches)
//   - If relocation is impossible the hook FAILS CLEANLY — target is never patched
//   - All other threads are frozen and their IPs adjusted while patching

#pragma once
#include <cstdint>

namespace epshook {

struct SavedRegs {
    uint64_t rax, rcx, rdx, r8, r9, r10, r11;
};

enum Status {
    OK = 0,
    ERR_INVALID,     // null arguments
    ERR_ALREADY,     // target already hooked
    ERR_NOT_FOUND,   // target not hooked
    ERR_DECODE,      // could not decode >=5 bytes at target
    ERR_RELOCATE,    // stolen bytes can't be safely relocated
    ERR_MEMORY,      // VirtualAlloc failed
    ERR_PROTECT,     // VirtualProtect failed
    ERR_UNSUPPORTED, // instruction at target unsupported (e.g. VEX/EVEX)
};

// No global setup required; provided for MinHook familiarity.
Status Initialize();

// Optional logging sink (default: silent).
using LogFn = void(*)(const char* msg);
void SetLog(LogFn fn);

// Classic detour. original receives the trampoline (call it to run the real function).
// The hook is created ENABLED.
Status Create(void* target, void* hook, void** original);

// Register spy: dispatch receives the target's volatile registers at entry.
// After dispatch returns, the original instructions execute — flow is unchanged.
// The spy is created ENABLED.
Status CreateSpy(void* target, void (*dispatch)(SavedRegs*));

Status Enable(void* target);
Status Disable(void* target);
Status Remove(void* target);       // restore original bytes + free trampoline
void  RemoveAll();
int   Count();

const char* StatusString(Status s);

} // namespace epshook
