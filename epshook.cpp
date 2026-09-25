// EpsHook v2 — x64 detour + register-spy hook engine
// MIT License
//
// Design notes:
//   * Decoder: full legacy prefix + REX handling, 1/2/3-byte opcode maps,
//     ModRM/SIB/disp/imm, RIP-relative detection, branch classification.
//     Unknown/unsupported encodings (VEX/EVEX at entry) fail CLEANLY.
//   * Trampoline: every stolen instruction is relocated — relative branches
//     are re-targeted, RIP-relative data operands are re-based, rel8 branches
//     widen to rel32 when out of range. If anything cannot be relocated the
//     hook is refused and the target is NEVER patched.
//   * Patching: original bytes are captured first; all other threads are
//     frozen and any instruction pointer sitting inside the patch/trampoline
//     region is rewound before the bytes change.
//   * Spy mode: preserves all volatile GPRs, XMM0-5 and RFLAGS across the
//     dispatch call, then runs the original instructions untouched.

#include "epshook.h"

#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <map>
#include <vector>

namespace epshook {

// ─── logging ──────────────────────────────────────────────────────────

static LogFn g_log = nullptr;

void SetLog(LogFn fn) { g_log = fn; }

static void Logf(const char* fmt, ...) {
    if (!g_log) return;
    char buf[512];
    va_list a;
    va_start(a, fmt);
    vsnprintf(buf, sizeof(buf), fmt, a);
    va_end(a);
    g_log(buf);
}

const char* StatusString(Status s) {
    switch (s) {
    case OK: return "OK";
    case ERR_INVALID: return "invalid arguments";
    case ERR_ALREADY: return "target already hooked";
    case ERR_NOT_FOUND: return "target not hooked";
    case ERR_DECODE: return "cannot decode enough bytes at target";
    case ERR_RELOCATE: return "stolen bytes cannot be relocated";
    case ERR_MEMORY: return "VirtualAlloc failed";
    case ERR_PROTECT: return "VirtualProtect failed";
    case ERR_UNSUPPORTED: return "unsupported instruction at target";
    }
    return "unknown";
}

Status Initialize() { return OK; }

// ─── instruction decoder ──────────────────────────────────────────────

enum BranchKind { BR_NONE = 0, BR_REL8, BR_REL32, BR_LOOP8 };

struct Insn {
    int len = 0;
    int dispOff = -1;
    int dispSize = 0;
    int opPos = 0;          // offset of the primary opcode byte
    bool ripRel = false;
    BranchKind br = BR_NONE;
    bool unsupported = false;
};

static int ReadModRM(const uint8_t* p, int pos, int avail, Insn& in, uint8_t* outModRM) {
    if (pos >= avail) return -1;
    uint8_t modrm = p[pos++];
    if (outModRM) *outModRM = modrm;
    uint8_t mod = modrm >> 6, rm = modrm & 7;
    bool hasSib = (mod != 3 && rm == 4);
    uint8_t sibByte = 0;
    if (hasSib) {
        if (pos >= avail) return -1;
        sibByte = p[pos++];
    }
    if (mod == 3) return pos;

    int dsize = 0;
    bool rip = false;
    if (!hasSib && rm == 5 && mod == 0) { dsize = 4; rip = true; }   // RIP-relative (x64)
    else if (hasSib && mod == 0 && (sibByte & 7) == 5) dsize = 4;    // SIB + disp32 (absolute)
    else if (mod == 1) dsize = 1;
    else if (mod == 2) dsize = 4;

    if (dsize) { in.dispOff = pos; in.dispSize = dsize; in.ripRel = rip; }
    pos += dsize;
    return pos <= avail ? pos : -1;
}

// Returns: >0 = instruction length, 0 = fail (decode), -1 = fail (unsupported)
static int DecodeOne(const uint8_t* p, int avail, Insn& in) {
    in = Insn();
    if (avail <= 0) return 0;
    int pos = 0;
    bool op16 = false, addr32 = false, rexW = false, pf3 = false;

    // legacy prefixes + optional trailing REX
    while (pos < avail) {
        uint8_t b = p[pos];
        if (b == 0x66) { op16 = true; pos++; }
        else if (b == 0x67) { addr32 = true; pos++; }
        else if (b == 0xF3) { pf3 = true; pos++; }
        else if (b == 0xF0 || b == 0xF2 ||
                 b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                 b == 0x64 || b == 0x65) { pos++; }
        else if (b >= 0x40 && b <= 0x4F) { rexW = (b & 8) != 0; pos++; }
        else break;
        if (pos > 6) return 0;
    }

    int opPos = pos;
    in.opPos = opPos;
    if (pos >= avail) return 0;
    uint8_t op = p[pos++];

    auto immz = [&]() { return op16 ? 2 : 4; };
    auto needModRM = [&](uint8_t* m = nullptr) {
        int r = ReadModRM(p, pos, avail, in, m);
        if (r < 0) return false;
        pos = r;
        return true;
    };
    auto needImm = [&](int n) {
        if (pos + n > avail) return false;
        pos += n;
        return true;
    };
    auto setLen = [&]() { in.len = pos; return pos; };

    // ── two-byte / three-byte escape ──────────────────────────────
    if (op == 0x0F) {
        if (pos >= avail) return 0;
        uint8_t op2 = p[pos++];

        if (op2 == 0x38 || op2 == 0x3A) {          // 0F 38 / 0F 3A maps
            if (pos >= avail) return 0;
            pos++;                                   // third opcode byte
            if (!needModRM()) return 0;
            if (op2 == 0x3A && !needImm(1)) return 0;
            return setLen();
        }

        if (op2 >= 0x80 && op2 <= 0x8F) {           // jcc rel32
            in.br = BR_REL32;
            if (pos + 4 > avail) return 0;
            in.dispOff = pos; in.dispSize = 4;
            pos += 4;
            return setLen();
        }

        switch (op2) {
        // no ModRM, no immediate
        case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B:
        case 0x0E: case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:
        case 0x77: case 0xA2: case 0xAA:
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF:
            return setLen();

        // ModRM + imm8
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0xA4: case 0xAC: case 0xBA:
        case 0xC2: case 0xC4: case 0xC5: case 0xC6:
        case 0x0F:                                    // 3DNow: trailing imm8
            if (!needModRM()) return 0;
            if (!needImm(1)) return 0;
            return setLen();

        // popcnt requires F3 prefix; otherwise unsupported
        case 0xB8:
            if (!pf3) { in.unsupported = true; return -1; }
            if (!needModRM()) return 0;
            return setLen();

        default:
            if (!needModRM()) return 0;
            return setLen();
        }
    }

    // ── one-byte map: 00-3F ───────────────────────────────────────
    if (op <= 0x3F) {
        uint8_t low = op & 7;
        if (low == 4) { if (!needImm(1)) return 0; }
        else if (low == 5) { if (!needImm(immz())) return 0; }
        else if (low >= 6) { in.unsupported = true; return -1; }  // invalid in x64
        else { if (!needModRM()) return 0; }
        return setLen();
    }

    // ── one-byte map: rest ────────────────────────────────────────
    switch (op) {
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
    case 0xC3: case 0xC9: case 0xCB: case 0xCC: case 0xCF:
    case 0xF1: case 0xF4: case 0xF5:
    case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD:
    case 0x6C: case 0x6D: case 0x6E: case 0x6F:
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
    case 0xEC: case 0xED: case 0xEE: case 0xEF:
        return setLen();

    case 0x60: case 0x61: case 0x9A: case 0xCE: case 0xD4: case 0xD5: case 0xEA:
    case 0x62: case 0xC4: case 0xC5:                      // EVEX / VEX
        in.unsupported = true;
        return -1;

    case 0x63: case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    case 0xFE: case 0xFF:
        if (!needModRM()) return 0;
        return setLen();

    case 0x68: if (!needImm(immz())) return 0; return setLen();
    case 0x69: if (!needModRM()) return 0; if (!needImm(immz())) return 0; return setLen();
    case 0x6A: if (!needImm(1)) return 0; return setLen();
    case 0x6B: if (!needModRM()) return 0; if (!needImm(1)) return 0; return setLen();

    case 0x80: if (!needModRM()) return 0; if (!needImm(1)) return 0; return setLen();
    case 0x81: if (!needModRM()) return 0; if (!needImm(immz())) return 0; return setLen();
    case 0x82: in.unsupported = true; return -1;
    case 0x83: if (!needModRM()) return 0; if (!needImm(1)) return 0; return setLen();

    case 0xA0: case 0xA1: case 0xA2: case 0xA3:            // moffs (address size)
        if (!needImm(addr32 ? 4 : 8)) return 0;
        return setLen();

    case 0xA8: if (!needImm(1)) return 0; return setLen();
    case 0xA9: if (!needImm(immz())) return 0; return setLen();

    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        if (!needImm(1)) return 0;
        return setLen();

    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        if (!needImm(rexW ? 8 : (op16 ? 2 : 4))) return 0;
        return setLen();

    case 0xC0: case 0xC1: if (!needModRM()) return 0; if (!needImm(1)) return 0; return setLen();
    case 0xC2: if (!needImm(2)) return 0; return setLen();
    case 0xC6: if (!needModRM()) return 0; if (!needImm(1)) return 0; return setLen();
    case 0xC7: if (!needModRM()) return 0; if (!needImm(immz())) return 0; return setLen();
    case 0xC8: if (!needImm(3)) return 0; return setLen();
    case 0xCA: if (!needImm(2)) return 0; return setLen();
    case 0xCD: if (!needImm(1)) return 0; return setLen();

    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        in.br = BR_REL8;
        if (pos + 1 > avail) return 0;
        in.dispOff = pos; in.dispSize = 1;
        pos += 1;
        return setLen();

    case 0xE0: case 0xE1: case 0xE2: case 0xE3:
        in.br = BR_LOOP8;
        if (pos + 1 > avail) return 0;
        in.dispOff = pos; in.dispSize = 1;
        pos += 1;
        return setLen();

    case 0xE4: case 0xE5: case 0xE6: case 0xE7:
        if (!needImm(1)) return 0;
        return setLen();

    case 0xE8: case 0xE9:
        in.br = BR_REL32;
        if (pos + 4 > avail) return 0;
        in.dispOff = pos; in.dispSize = 4;
        pos += 4;
        return setLen();

    case 0xEB:
        in.br = BR_REL8;
        if (pos + 1 > avail) return 0;
        in.dispOff = pos; in.dispSize = 1;
        pos += 1;
        return setLen();

    case 0xF6: case 0xF7: {
        uint8_t modrm = 0;
        if (!needModRM(&modrm)) return 0;
        uint8_t grp = (modrm >> 3) & 7;
        if (grp <= 1) {                                  // TEST r/m, imm
            if (!needImm(op == 0xF6 ? 1 : immz())) return 0;
        }
        return setLen();
    }

    default:
        return 0;
    }
}

// ─── memory helpers ───────────────────────────────────────────────────

static uint8_t* AllocNear(uintptr_t targetAddr, size_t size) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    uintptr_t base = targetAddr & ~(gran - 1);
    const uintptr_t kMaxDist = 0x70000000ull;
    for (uintptr_t off = gran; off < kMaxDist; off += gran) {
        if (base + off > off) {
            void* p = VirtualAlloc((void*)(base + off), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) return (uint8_t*)p;
        }
        if (base > off) {
            void* p = VirtualAlloc((void*)(base - off), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) return (uint8_t*)p;
        }
    }
    return nullptr;
}

static bool FitsI32(int64_t v) { return v >= INT32_MIN && v <= INT32_MAX; }
static bool FitsI8(int64_t v) { return v >= -128 && v <= 127; }

// ─── trampoline relocation ────────────────────────────────────────────

static bool Relocate(uint8_t* dst, size_t cap, size_t& dstLen,
                     const uint8_t* src, size_t srcLen,
                     uintptr_t srcAddr, uintptr_t dstAddr) {
    size_t s = 0;
    dstLen = 0;
    while (s < srcLen) {
        Insn in{};
        int r = DecodeOne(src + s, (int)(srcLen - s), in);
        if (r <= 0) return false;
        if (s + (size_t)in.len > srcLen) return false;

        uintptr_t srcEnd = srcAddr + s + in.len;
        uint8_t buf[48];
        if (in.len > (int)sizeof(buf)) return false;
        memcpy(buf, src + s, in.len);
        size_t newLen = in.len;

        if (in.br != BR_NONE) {
            int64_t oldDisp = (in.dispSize == 1)
                ? (int8_t)buf[in.dispOff]
                : *(int32_t*)(buf + in.dispOff);
            uintptr_t targetAbs = srcEnd + (uintptr_t)oldDisp;

            // branch into the stolen region itself — unsupported (would need
            // mapping to trampoline addresses; prologues never do this)
            if (targetAbs >= srcAddr && targetAbs < srcAddr + srcLen) return false;

            if (in.br == BR_LOOP8) {
                int64_t nd = (int64_t)targetAbs - (int64_t)(dstAddr + dstLen + in.len);
                if (!FitsI8(nd)) return false;
                *(int8_t*)(buf + in.dispOff) = (int8_t)nd;
            } else if (in.br == BR_REL8) {
                int64_t nd = (int64_t)targetAbs - (int64_t)(dstAddr + dstLen + in.len);
                if (FitsI8(nd)) {
                    *(int8_t*)(buf + in.dispOff) = (int8_t)nd;
                } else {
                    // widen rel8 -> rel32 (EB->E9, 7x->0F 8x)
                    uint8_t w[48];
                    int wl = 0;
                    for (int i = 0; i < in.opPos && i < in.len; i++) {
                        if (src[s + i] == 0x66) return false;   // can't carry 66 into rel32 branch
                        w[wl++] = src[s + i];
                    }
                    uint8_t opc = src[s + in.opPos];
                    if (opc == 0xEB) {
                        w[wl++] = 0xE9;
                        newLen = (size_t)wl + 4;
                        nd = (int64_t)targetAbs - (int64_t)(dstAddr + dstLen + newLen);
                        if (!FitsI32(nd)) return false;
                        *(int32_t*)(w + wl) = (int32_t)nd;
                        wl += 4;
                    } else {                                   // 0x7x -> 0F 8x
                        w[wl++] = 0x0F;
                        w[wl++] = (uint8_t)(0x80 | (opc & 0x0F));
                        newLen = (size_t)wl + 4;
                        nd = (int64_t)targetAbs - (int64_t)(dstAddr + dstLen + newLen);
                        if (!FitsI32(nd)) return false;
                        *(int32_t*)(w + wl) = (int32_t)nd;
                        wl += 4;
                    }
                    if (dstLen + (size_t)wl > cap) return false;
                    memcpy(dst + dstLen, w, wl);
                    dstLen += wl;
                    s += in.len;
                    continue;
                }
            } else {                                           // BR_REL32
                int64_t nd = (int64_t)targetAbs - (int64_t)(dstAddr + dstLen + in.len);
                if (!FitsI32(nd)) return false;
                *(int32_t*)(buf + in.dispOff) = (int32_t)nd;
            }
        } else if (in.ripRel) {
            int32_t old = *(int32_t*)(buf + in.dispOff);
            uintptr_t abs = srcEnd + (uintptr_t)(int64_t)old;
            int64_t nd = (int64_t)abs - (int64_t)(dstAddr + dstLen + in.len);
            if (!FitsI32(nd)) return false;
            *(int32_t*)(buf + in.dispOff) = (int32_t)nd;
        }

        if (dstLen + newLen > cap) return false;
        memcpy(dst + dstLen, buf, newLen);
        dstLen += newLen;
        s += in.len;
    }
    return true;
}

// ─── spy relay stub ───────────────────────────────────────────────────
// entry:  RSP ≡ 8 (mod 16)
// pushfq + 7 pushes -> RSP = R-64 (≡ 8)
// sub rsp, 0x88 (≡ 8) -> RSP ≡ 0 before call   [shadow | xmm0-5 | pad | regs | flags]
// struct SavedRegs lives at [rsp+0x88], flags at [rsp+0xC0]

static void BuildSpyStub(std::vector<uint8_t>& out, void (*dispatch)(SavedRegs*)) {
    static const uint8_t kHead[] = {
        0x9C,                                     // pushfq
        0x41, 0x53,                               // push r11
        0x41, 0x52,                               // push r10
        0x41, 0x51,                               // push r9
        0x41, 0x50,                               // push r8
        0x52,                                     // push rdx
        0x51,                                     // push rcx
        0x50,                                     // push rax
        0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, // sub rsp, 0x88
        0x0F, 0x7F, 0x44, 0x24, 0x20,             // movdqu [rsp+0x20], xmm0
        0x0F, 0x7F, 0x4C, 0x24, 0x30,             // xmm1
        0x0F, 0x7F, 0x54, 0x24, 0x40,             // xmm2
        0x0F, 0x7F, 0x5C, 0x24, 0x50,             // xmm3
        0x0F, 0x7F, 0x64, 0x24, 0x60,             // xmm4
        0x0F, 0x7F, 0x6C, 0x24, 0x70,             // xmm5
        0x48, 0x8D, 0x8C, 0x24, 0x88, 0x00, 0x00, 0x00, // lea rcx, [rsp+0x88]
        // + movabs rax, <dispatch> (rax is already saved on the stack)
        // + call rax
    };
    static const uint8_t kCall[] = {
        0xFF, 0xD0,                                     // call rax
    };
    static const uint8_t kTail[] = {
        0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00, // add rsp, 0x88
        0x0F, 0x6F, 0x44, 0x24, 0x20,             // movdqu xmm0, [rsp+0x20]
        0x0F, 0x6F, 0x4C, 0x24, 0x30,             // xmm1
        0x0F, 0x6F, 0x54, 0x24, 0x40,             // xmm2
        0x0F, 0x6F, 0x5C, 0x24, 0x50,             // xmm3
        0x0F, 0x6F, 0x64, 0x24, 0x60,             // xmm4
        0x0F, 0x6F, 0x6C, 0x24, 0x70,             // xmm5
        0x58,                                     // pop rax
        0x59,                                     // pop rcx
        0x5A,                                     // pop rdx
        0x41, 0x58,                               // pop r8
        0x41, 0x59,                               // pop r9
        0x41, 0x5A,                               // pop r10
        0x41, 0x5B,                               // pop r11
        0x9D,                                     // popfq
    };
    out.insert(out.end(), kHead, kHead + sizeof(kHead));
    uint64_t addr = (uint64_t)(uintptr_t)dispatch;
    uint8_t movabs[10] = { 0x48, 0xB8 };                 // movabs rax, imm64
    memcpy(movabs + 2, &addr, 8);
    out.insert(out.end(), movabs, movabs + 10);
    out.insert(out.end(), kCall, kCall + sizeof(kCall));
    out.insert(out.end(), kTail, kTail + sizeof(kTail));
}

// ─── hook bookkeeping ─────────────────────────────────────────────────

struct HookEntry {
    void* target = nullptr;
    void* hook = nullptr;
    void* original = nullptr;    // trampoline (detour mode)
    uint8_t* alloc = nullptr;
    size_t allocSize = 0;
    int patchLen = 0;            // bytes actually overwritten with the jump
    int stolenLen = 0;           // full decoded window (jump + NOPs)
    uint8_t origBytes[48]{};     // stolenLen bytes, captured before patching
    uint8_t winBytes[48]{};      // patch jump + NOP pad, written when enabled
    bool enabled = false;
    bool isSpy = false;
};

static std::map<void*, HookEntry> g_hooks;

// ─── thread freeze / IP adjustment ────────────────────────────────────

struct IPRewind {
    uintptr_t lo, hi, canon;
};

static void FreezeAll(std::vector<HANDLE>& out, DWORD selfTid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != GetCurrentProcessId()) continue;
            if (te.th32ThreadID == selfTid) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                  FALSE, te.th32ThreadID);
            if (!h) continue;
            if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); continue; }
            out.push_back(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static void ThawAll(std::vector<HANDLE>& threads, const std::vector<IPRewind>& rewrites) {
    for (HANDLE h : threads) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(h, &ctx)) {
            uintptr_t rip = (uintptr_t)ctx.Rip;
            for (const auto& rw : rewrites) {
                if (rip >= rw.lo && rip < rw.hi) {
                    ctx.Rip = rw.canon;
                    SetThreadContext(h, &ctx);
                    break;
                }
            }
        }
        ResumeThread(h);
        CloseHandle(h);
    }
}

// ─── patch writer ─────────────────────────────────────────────────────

static bool WriteBytes(void* addr, const uint8_t* bytes, int len, DWORD* outOldProt) {
    DWORD oldProt = 0;
    if (!VirtualProtect(addr, (SIZE_T)len, PAGE_EXECUTE_READWRITE, &oldProt)) return false;
    if (outOldProt) *outOldProt = oldProt;
    memcpy(addr, bytes, (size_t)len);
    DWORD tmp = 0;
    VirtualProtect(addr, (SIZE_T)len, oldProt, &tmp);
    FlushInstructionCache(GetCurrentProcess(), addr, (SIZE_T)len);
    return true;
}

// ─── core install ─────────────────────────────────────────────────────

static Status InstallImpl(void* target, void* hookOrDispatch, void** original, bool spy) {
    if (!target || !hookOrDispatch) return ERR_INVALID;
    if (g_hooks.count(target)) return ERR_ALREADY;

    uint8_t* code = (uint8_t*)target;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(code, &mbi, sizeof(mbi))) return ERR_DECODE;
    if (!(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return ERR_DECODE;

    uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    int window = (int)((regionEnd - (uintptr_t)code > 64) ? 64 : (regionEnd - (uintptr_t)code));
    if (window < 5) return ERR_DECODE;

    // pass 1: decode at least 5 bytes
    int total = 0;
    Status st = OK;
    auto decodeUpTo = [&](int need) -> Status {
        while (total < need) {
            if (total >= window) return ERR_DECODE;
            Insn in{};
            int r = DecodeOne(code + total, window - total, in);
            if (r == -1) return ERR_UNSUPPORTED;
            if (r <= 0) return ERR_DECODE;
            total += r;
            if (total > 48) break;
        }
        return total >= need ? OK : ERR_DECODE;
    };
    st = decodeUpTo(5);
    if (st != OK) { Logf("[epshook] decode5 failed: %s", StatusString(st)); return st; }

    // allocate relay/trampoline near the target
    const size_t kAlloc = 256;
    uint8_t* alloc = AllocNear((uintptr_t)target, kAlloc);
    if (!alloc) {
        alloc = (uint8_t*)VirtualAlloc(nullptr, kAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!alloc) return ERR_MEMORY;
    }

    // decide patch size (5-byte E9 if relay reachable, else 14-byte abs)
    int64_t rel5 = (int64_t)(uintptr_t)alloc - (int64_t)((uintptr_t)target + 5);
    int patchLen = FitsI32(rel5) ? 5 : 14;
    if (total < patchLen) {
        st = decodeUpTo(patchLen);
        if (st != OK) { VirtualFree(alloc, 0, MEM_RELEASE); return st; }
    }

    // build relay
    std::vector<uint8_t> relay;
    if (spy) {
        BuildSpyStub(relay, (void (*)(SavedRegs*))hookOrDispatch);
    } else {
        // FF 25 00 00 00 00 + abs64(hook)
        static const uint8_t kAbs[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
        relay.insert(relay.end(), kAbs, kAbs + 6);
        uint64_t addr = (uint64_t)(uintptr_t)hookOrDispatch;
        uint8_t b[8];
        memcpy(b, &addr, 8);
        relay.insert(relay.end(), b, b + 8);
    }
    size_t stolenOffset = relay.size();
    if (stolenOffset < 16) stolenOffset = 16;

    // relocate stolen bytes at their final address
    size_t trampLen = 0;
    if (!Relocate(alloc + stolenOffset, kAlloc - stolenOffset - 16, trampLen,
                  code, (size_t)total, (uintptr_t)target, (uintptr_t)(alloc + stolenOffset))) {
        Logf("[epshook] relocation refused at %p", target);
        VirtualFree(alloc, 0, MEM_RELEASE);
        return ERR_RELOCATE;
    }

    // jmp back to target+total
    int64_t back = (int64_t)((uintptr_t)target + total) -
                   (int64_t)((uintptr_t)(alloc + stolenOffset) + trampLen + 5);
    if (!FitsI32(back)) { VirtualFree(alloc, 0, MEM_RELEASE); return ERR_RELOCATE; }
    uint8_t jmpBack[5] = { 0xE9, 0, 0, 0, 0 };
    int32_t b32 = (int32_t)back;
    memcpy(jmpBack + 1, &b32, 4);
    memcpy(alloc + stolenOffset + trampLen, jmpBack, 5);

    // copy relay into alloc
    memcpy(alloc, relay.data(), relay.size());

    // build jump -> relay
    HookEntry e{};
    e.target = target;
    e.hook = hookOrDispatch;
    e.isSpy = spy;
    e.alloc = alloc;
    e.allocSize = kAlloc;
    e.patchLen = patchLen;
    e.stolenLen = total;
    e.original = alloc + stolenOffset;

    if (patchLen == 5) {
        e.winBytes[0] = 0xE9;
        int32_t r = (int32_t)rel5;
        memcpy(e.winBytes + 1, &r, 4);
    } else {
        static const uint8_t kAbs[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
        memcpy(e.winBytes, kAbs, 6);
        uint64_t a = (uint64_t)(uintptr_t)alloc;
        memcpy(e.winBytes + 6, &a, 8);
    }
    // NOP-pad the rest of the decoded window
    for (int i = patchLen; i < total; i++) e.winBytes[i] = 0x90;

    // capture ORIGINAL bytes before touching anything
    memcpy(e.origBytes, code, (size_t)total);

    // freeze, rewind any IP inside the patch window, patch the whole
    // window (jump + NOPs) in one write, thaw
    std::vector<HANDLE> frozen;
    FreezeAll(frozen, GetCurrentThreadId());
    std::vector<IPRewind> rewrites;
    rewrites.push_back({ (uintptr_t)target, (uintptr_t)target + (uintptr_t)total, (uintptr_t)target });

    DWORD oldProt = 0;
    bool wrote = WriteBytes(code, e.winBytes, total, &oldProt);
    ThawAll(frozen, rewrites);

    if (!wrote) {
        Logf("[epshook] VirtualProtect failed at %p (err=%lu)", target, GetLastError());
        VirtualFree(alloc, 0, MEM_RELEASE);
        return ERR_PROTECT;
    }

    e.enabled = true;
    g_hooks[target] = e;
    if (original) *original = spy ? nullptr : e.original;

    Logf("[epshook] %s hook %p -> relay %p (patch=%d, stolen=%d)",
         spy ? "spy" : "detour", target, alloc, patchLen, total);
    return OK;
}

// ─── public API ───────────────────────────────────────────────────────

Status Create(void* target, void* hook, void** original) {
    if (!original) return ERR_INVALID;
    return InstallImpl(target, hook, original, false);
}

Status CreateSpy(void* target, void (*dispatch)(SavedRegs*)) {
    return InstallImpl(target, (void*)dispatch, nullptr, true);
}

static Status SetEnabled(HookEntry& e, bool enable) {
    if (e.enabled == enable) return OK;
    const uint8_t* bytes = enable ? e.winBytes : e.origBytes;

    std::vector<HANDLE> frozen;
    FreezeAll(frozen, GetCurrentThreadId());
    std::vector<IPRewind> rewrites;
    rewrites.push_back({ (uintptr_t)e.target,
                         (uintptr_t)e.target + (uintptr_t)e.stolenLen,
                         (uintptr_t)e.target });
    DWORD oldProt = 0;
    bool ok = WriteBytes(e.target, bytes, e.stolenLen, &oldProt);
    ThawAll(frozen, rewrites);
    if (!ok) return ERR_PROTECT;
    e.enabled = enable;
    return OK;
}

Status Enable(void* target) {
    auto it = g_hooks.find(target);
    if (it == g_hooks.end()) return ERR_NOT_FOUND;
    return SetEnabled(it->second, true);
}

Status Disable(void* target) {
    auto it = g_hooks.find(target);
    if (it == g_hooks.end()) return ERR_NOT_FOUND;
    return SetEnabled(it->second, false);
}

Status Remove(void* target) {
    auto it = g_hooks.find(target);
    if (it == g_hooks.end()) return ERR_NOT_FOUND;
    HookEntry e = it->second;

    std::vector<HANDLE> frozen;
    FreezeAll(frozen, GetCurrentThreadId());
    std::vector<IPRewind> rewrites;
    // IP sitting in the patch window -> restart at target
    rewrites.push_back({ (uintptr_t)e.target,
                         (uintptr_t)e.target + (uintptr_t)e.patchLen,
                         (uintptr_t)e.target });
    // IP sitting inside the trampoline -> restart at target (before freeing)
    rewrites.push_back({ (uintptr_t)e.alloc, (uintptr_t)e.alloc + e.allocSize, (uintptr_t)e.target });

    if (e.enabled) {
        DWORD oldProt = 0;
        WriteBytes(e.target, e.origBytes, e.stolenLen, &oldProt);
    }
    ThawAll(frozen, rewrites);
    VirtualFree(e.alloc, 0, MEM_RELEASE);
    g_hooks.erase(it);
    Logf("[epshook] removed hook %p", target);
    return OK;
}

void RemoveAll() {
    std::vector<void*> targets;
    for (auto& kv : g_hooks) targets.push_back(kv.first);
    for (void* t : targets) Remove(t);
}

int Count() {
    return (int)g_hooks.size();
}

} // namespace epshook
