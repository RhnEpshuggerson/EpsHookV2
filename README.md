# EpsHook v2

A tiny, dependency-free **x64 hooking engine for Windows** with two modes:

- **Detour** — classic `jmp -> your hook -> trampoline` (MinHook-style)
- **Spy** — observe a function's full register context *without changing control flow*

MIT licensed. Free and open source.

```
┌─ detour ────────────────────────────┐   ┌─ spy ────────────────────────────────┐
│ target:  E9 ──────► relay ──► hook  │   │ target: E9 ──► stub                 │
│                                     │   │   save rflags, rax/rcx/rdx/r8-r11,  │
│ hook calls original()               │   │   xmm0-5                            │
│ original = trampoline               │   │   dispatch(SavedRegs*)              │
│   [relocated stolen bytes]          │   │   restore everything                │
│   E9 back to target+N               │   │   [relocated stolen bytes]          │
└─────────────────────────────────────┘   │   E9 back to target+N               │
                                          └──────────────────────────────────────┘
```

## Why

| | MinHook | EpsHook v2 |
|---|---|---|
| Detour mode | ✅ | ✅ |
| Register-spy mode (no control-flow change) | ❌ | ✅ |
| Original bytes captured before patching | ✅ | ✅ |
| Stolen-byte relocation (RIP-relative + branches) | ✅ | ✅ |
| Fail-clean when relocation is impossible | ✅ | ✅ |
| Threads frozen + IPs rewound during patch | ✅ | ✅ |
| x86 (32-bit) support | ✅ | ❌ x64 only |
| AVX/VEX instruction at hook entry | ✅ | ❌ (fails cleanly) |

**Spy mode is the reason this exists.** For game internals with unknown prototypes you
often can't call the original — you just need to *see* the arguments. MinHook would
require a handwritten detour per site; EpsHook gives you `SavedRegs` and lets the
original code continue untouched:

```cpp
void OnPacket(epshook::SavedRegs* r) {
    printf("rax=%llX rcx=%llX\n", r->rax, r->rcx);
}
epshook::CreateSpy((void*)0x1417E89CB, OnPacket);
```

## Benchmark

`bench/bench.cpp` — MSVC 2026 Release x64, 100 M calls (10 M for spy), the
target function computes `x*3+1`. Run it yourself: numbers vary with system load
and total thread count (both engines suspend all process threads while patching).

```
[+] baseline        1.076 ns/call
[+] MinHook detour   3.541 ns/call (x3.3)
[+] EpsHook detour   3.210 ns/call (x3.0)     <- ~10% faster than MinHook
[+] EpsHook spy     11.420 ns/call (x10.6)    [10000000 dispatches]
[+] ALL RESULTS MATCH — functional test PASSED
```

The bench is also a functional test: every mode must return identical results and
the spy must fire exactly once per call, or the process exits non-zero.

## API

```cpp
#include "epshook.h"

epshook::SetLog([](const char* m){ puts(m); });   // optional, default silent

// Detour: original receives a trampoline you can call.
void* orig;
epshook::Create(target, MyHook, &orig);

// Spy: dispatch sees the target's volatile registers; control flow unchanged.
epshook::CreateSpy(target, MyDispatch);

epshook::Disable(target);
epshook::Enable(target);
epshook::Remove(target);       // restore + free
epshook::RemoveAll();
```

## Safety design

1. **Decode** ≥5 bytes (enough for a 5-byte `jmp`, or 14 if the relay is out of
   `rel32` range). Unknown encodings (`VEX`/`EVEX`, invalid-in-x64 opcodes) abort
   with `ERR_UNSUPPORTED` / `ERR_DECODE` — the target is never touched.
2. **Build the trampoline first** — relative branches are re-targeted, RIP-relative
   operands re-based, `rel8` branches widen to `rel32` when out of range. Branches
   *into* the stolen window are refused (`ERR_RELOCATE`).
3. **Capture original bytes** before any write.
4. **Freeze every other thread**, rewind any instruction pointer inside the
   patch window (or trampoline, on remove), write, thaw.

## Limitations

- x64 only (no 32-bit).
- A `VEX`/`EVEX` instruction at the very hook entry refuses cleanly.
- Loops (`loop`/`jcxz`) exiting the stolen window must stay within ±128 bytes —
  otherwise the hook refuses (never silently breaks code).
- Spy mode preserves `rflags` + `xmm0-5`; XMM6-15 are callee-saved under Win64
  and therefore safe by ABI.

## Build

```bat
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
build\Release\bench.exe
```

The benchmark fetches MinHook automatically (FetchContent) for comparison.
Link `epshook.lib` (or add `epshook.cpp` directly — it's a single file pair).

## License

MIT — see [LICENSE](LICENSE). Free for commercial and personal use.
