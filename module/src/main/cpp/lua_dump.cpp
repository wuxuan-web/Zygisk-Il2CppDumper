//
// Lua bytecode dump via hooking lua_loadfile + luaL_loadbuffer in libEngineDll.so
// Intercepts all Lua loads, calls luaU_dump to output standard Lua 5.1 bytecode
//

#include "lua_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dlfcn.h>

// Lua types (opaque pointers)
typedef struct lua_State lua_State;
typedef struct Proto Proto;

// Lua C API function pointers (resolved from libEngineDll.so)
// lua_loadfile is the main file loading path for ROK
static int (*orig_lua_loadfile)(lua_State *L, const char *filename) = nullptr;
static int (*orig_luaL_loadbuffer)(lua_State *L, const char *buff, size_t sz, const char *name) = nullptr;

// luaU_dump is the internal serializer - less likely to be disabled than lua_dump
static int (*p_luaU_dump)(lua_State *L, const Proto *f, void *writer, void *data, int strip) = nullptr;
static int (*p_lua_dump)(lua_State *L, void *writer, void *data) = nullptr;

// Stack manipulation
static int (*p_lua_gettop)(lua_State *L) = nullptr;
static void (*p_lua_settop)(lua_State *L, int index) = nullptr;
static int (*p_lua_type)(lua_State *L, int index) = nullptr;
static void (*p_lua_getfield)(lua_State *L, int index, const char *k) = nullptr;
static void (*p_lua_pushvalue)(lua_State *L, int index) = nullptr;
static const char *(*p_lua_tolstring)(lua_State *L, int index, size_t *len) = nullptr;
static int (*p_lua_pcall)(lua_State *L, int nargs, int nresults, int errfunc) = nullptr;

#define LUA_GLOBALSINDEX (-10002)
static void lua_getglobal(lua_State *L, const char *name) {
    p_lua_getfield(L, LUA_GLOBALSINDEX, name);
}

static char g_outDir[512] = {0};
static int g_dumpCount = 0;
static int g_fileCount = 0;

// Writer callback for lua_dump/luaU_dump: writes to FILE*
static int lua_writer(lua_State *L, const void *p, size_t sz, void *ud) {
    FILE *f = (FILE *)ud;
    if (sz == 0) return 0;
    return (fwrite(p, 1, sz, f) != sz) ? 1 : 0;
}

// Sanitize filename
static std::string sanitize_name(const char *name) {
    if (!name || !name[0]) return "unknown";
    std::string s(name);
    if (s[0] == '@') s = s.substr(1);
    // Get just the filename part
    auto last_slash = s.rfind('/');
    if (last_slash != std::string::npos) s = s.substr(last_slash + 1);
    // Remove extension
    auto dot = s.rfind('.');
    if (dot != std::string::npos) s = s.substr(0, dot);
    // Sanitize chars
    for (auto &c : s) {
        if (c == '/' || c == '\\' || c == ':' || c == ' ' || c == '[' || c == ']' || c == '=') c = '_';
    }
    if (s.empty()) return "unknown";
    return s;
}

// Try to dump the function at stack top
static void try_dump(lua_State *L, const char *name, size_t input_sz) {
    if (!g_outDir[0]) return;

    std::string safe_name = sanitize_name(name);

    char dir_path[768];
    snprintf(dir_path, sizeof(dir_path), "%s/lua_dump", g_outDir);
    mkdir(dir_path, 0777);

    char out_path[1024];
    snprintf(out_path, sizeof(out_path), "%s/%s.luac", dir_path, safe_name.c_str());

    FILE *f = fopen(out_path, "wb");
    if (!f) return;

    int dump_result = -1;

    // Patch lua_dump to skip ALL checks and go straight to dump logic:
    // Original layout:
    //   +00: LDR X8, [X0, #0x10]     ; L->top
    //   +04: LDUR W9, [X8, #-8]      ; type tag
    //   +08: CMP W9, #6              ; check function type
    //   +0C: B.NE +1C (error)        ; skip if not function
    //   +10: LDUR X8, [X8, #-0x10]   ; gc pointer
    //   +14: LDRB W9, [X8, #0x18]    ; isC check
    //   +18: CBZ W9, +24 (ok)        ; branch to dump
    //   +1C: MOV W0, #1; RET         ; error return
    //   +24: (dump logic starts)
    //
    // Patch +0C: replace B.NE with NOP (skip type check)
    // Patch +18: replace CBZ with B +24 (unconditional jump to dump)
    static bool patched = false;
    if (!patched && p_lua_dump) {
        uintptr_t func_addr = (uintptr_t)p_lua_dump;
        uintptr_t page = func_addr & ~0xFFFUL;
        if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            uint32_t nop = 0xD503201F;
            uint32_t branch = 0x14000003; // B +3 instructions (skip MOV+RET)

            // NOP the B.NE at +0C (skip type==6 check)
            memcpy((void *)(func_addr + 0x0C), &nop, 4);
            // Replace CBZ at +18 with unconditional B +24
            memcpy((void *)(func_addr + 0x18), &branch, 4);

            __builtin___clear_cache((char *)func_addr, (char *)(func_addr + 0x20));
            LOGI("lua_dump: patched +0C (NOP B.NE) and +18 (B +24) at %p", (void *)func_addr);
            patched = true;
        } else {
            LOGE("lua_dump: mprotect failed for lua_dump at %p", (void *)func_addr);
        }
    }

    if (p_lua_dump) {
        dump_result = p_lua_dump(L, (void *)lua_writer, f);
    }

    long file_size = ftell(f);
    fclose(f);

    // If dump failed or wrote 0 bytes, remove the empty file
    if (dump_result != 0 || file_size <= 0) {
        remove(out_path);
    }

    g_dumpCount++;
    if (g_dumpCount <= 30 || g_dumpCount % 200 == 0) {
        LOGI("Lua dump [%d]: %s (input=%zu) → result=%d size=%ld",
             g_dumpCount, name ? name : "?", input_sz, dump_result, file_size);
    }
}

// Copy a file from game data to our dump directory
static void copy_lua_file(const char *filename) {
    if (!filename || !g_outDir[0]) return;

    // Open source file
    FILE *src = fopen(filename, "rb");
    if (!src) return;

    fseek(src, 0, SEEK_END);
    long sz = ftell(src);
    fseek(src, 0, SEEK_SET);

    if (sz <= 0 || sz > 50 * 1024 * 1024) {
        fclose(src);
        return;
    }

    // Read file content
    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) { fclose(src); return; }
    fread(buf, 1, sz, src);
    fclose(src);

    // Create output directory
    char dir_path[768];
    snprintf(dir_path, sizeof(dir_path), "%s/lua_dump", g_outDir);
    mkdir(dir_path, 0777);

    // Sanitize filename
    std::string safe = sanitize_name(filename);

    // Save raw copy (encrypted)
    char out_path[1024];
    snprintf(out_path, sizeof(out_path), "%s/%s.ls", dir_path, safe.c_str());
    FILE *dst = fopen(out_path, "wb");
    if (dst) {
        fwrite(buf, 1, sz, dst);
        fclose(dst);
    }

    // Also save XOR 0x63 decrypted copy
    snprintf(out_path, sizeof(out_path), "%s/%s.luac", dir_path, safe.c_str());
    dst = fopen(out_path, "wb");
    if (dst) {
        // Byte 0 stays, rest XOR 0x63
        fwrite(buf, 1, 1, dst);
        for (long i = 1; i < sz; i++) {
            uint8_t b = buf[i] ^ 0x63;
            fwrite(&b, 1, 1, dst);
        }
        fclose(dst);
    }

    free(buf);
}

// Use Lua-level string.dump to serialize the loaded function
static void lua_level_dump(lua_State *L, const char *filename) {
    if (!p_lua_gettop || !g_outDir[0]) return;

    // Stack: [..., loaded_function]
    // We'll call: local ok, bc = pcall(string.dump, func)

    // Get string.dump function
    // lua_getglobal(L, "string") → lua_getfield(L, -1, "dump") → push func → pcall

    // Simpler: use luaL_dostring to execute dump code
    // But we need luaL_dostring... let's use loadbuffer + pcall

    // Actually simplest: just try calling lua_dump directly with our patched version
    // But lua_dump was blocked. Let's try a different path:
    // Use luaL_loadstring to compile "return string.dump(...)" and call it

    // For now, just save the raw file bytes (pre-decryption) -
    // we'll decode offline with the correct algorithm
    // This is actually what we need: the RAW .ls bytes before the VM touches them
}

static bool g_bulk_dump_done = false;
static lua_State *g_saved_L = nullptr;

// Bulk dump: use luaL_loadstring to run a Lua script that dumps ALL package.loaded
static void do_bulk_dump(lua_State *L) {
    if (g_bulk_dump_done) return;
    g_bulk_dump_done = true;

    if (!p_lua_pcall || !orig_lua_loadfile) {
        LOGE("lua_dump: missing pcall or lua_loadfile for bulk dump");
        return;
    }

    // Create output dir
    char dir_path[768];
    snprintf(dir_path, sizeof(dir_path), "%s/lua_dump", g_outDir);
    mkdir(dir_path, 0777);

    // Write Lua script to file, then load it (avoids snprintf format issues)
    char script_path[1024];
    snprintf(script_path, sizeof(script_path), "%s/lua_dump/_dump_script.lua", g_outDir);

    FILE *sf = fopen(script_path, "w");
    if (!sf) {
        LOGE("lua_dump: cannot create script file %s", script_path);
        return;
    }
    // Ultra-simple test: just write "hello" to a file. No function/if/for keywords.
    fprintf(sf, "local f = io.open('%s/test_ok.txt', 'w')\n", dir_path);
    fputs(
        "f:write('DUMP_WORKS')\n"
        "f:close()\n"
        "return 1\n"
    , sf);
    fclose(sf);

    // Read script back, XOR-encrypt it so luaL_loadbuffer's decrypt produces correct source
    // luaL_loadbuffer triggers xor_v1: key = buf[0] ^ 0x78, XOR from byte 1 in 16-byte blocks
    // We need to PRE-ENCRYPT the script so that after xor_v1 decrypt it becomes valid Lua source
    sf = fopen(script_path, "rb");
    if (!sf) {
        LOGE("lua_dump: cannot re-read script %s", script_path);
        return;
    }
    fseek(sf, 0, SEEK_END);
    long script_len = ftell(sf);
    fseek(sf, 0, SEEK_SET);
    char *script_buf = (char *)malloc(script_len + 1);
    fread(script_buf, 1, script_len, sf);
    script_buf[script_len] = 0;
    fclose(sf);

    LOGI("lua_dump: executing bulk dump script (%ld bytes)...", script_len);
    int load_result = orig_luaL_loadbuffer(L, script_buf, script_len, "=dump_script");
    free(script_buf);
    if (load_result != 0) {
        const char *err = p_lua_tolstring(L, -1, NULL);
        LOGE("lua_dump: load script failed: %s", err ? err : "?");
        p_lua_settop(L, p_lua_gettop(L) - 1);
        return;
    }

    int pcall_result = p_lua_pcall(L, 0, 1, 0);
    if (pcall_result != 0) {
        const char *err = p_lua_tolstring(L, -1, NULL);
        LOGE("lua_dump: pcall failed: %s", err ? err : "?");
    } else {
        LOGI("lua_dump: bulk dump complete!");
    }
    p_lua_settop(L, p_lua_gettop(L) - 1);
}

// Hooked lua_loadfile: log files, trigger bulk dump after 1100+ files loaded
static int hooked_lua_loadfile(lua_State *L, const char *filename) {
    int result = orig_lua_loadfile(L, filename);
    if (result == 0 && filename) {
        g_fileCount++;
        g_saved_L = L;

        if (g_fileCount <= 20 || g_fileCount % 100 == 0) {
            LOGI("Lua file [%d]: %s", g_fileCount, filename);
        }

        // After 1100+ files loaded, trigger bulk dump (game should be fully loaded)
        if (g_fileCount == 1100 && !g_bulk_dump_done) {
            LOGI("lua_dump: 1100 files loaded, triggering bulk dump...");
            // Pop the loaded function, do bulk dump, then re-load this file
            p_lua_settop(L, p_lua_gettop(L) - 1);
            do_bulk_dump(L);
            // Re-load the current file
            result = orig_lua_loadfile(L, filename);
        }
    }
    return result;
}

// Hooked luaL_loadbuffer: count calls, trigger bulk dump after delay
static int hooked_luaL_loadbuffer(lua_State *L, const char *buff, size_t sz, const char *name) {
    int result = orig_luaL_loadbuffer(L, buff, sz, name);

    g_dumpCount++;
    g_saved_L = L;

    if (g_dumpCount <= 20 || g_dumpCount % 500 == 0) {
        LOGI("Lua buffer [%d]: %s (%zu bytes)", g_dumpCount, name ? name : "?", sz);
    }

    // After enough calls, trigger bulk dump once
    // luaL_loadbuffer gets ~20 calls during startup, trigger at 30 to be safe
    if (g_dumpCount == 30 && !g_bulk_dump_done) {
        LOGI("lua_dump: 30 loadbuffer calls, waiting 10s for full load then dumping...");
        sleep(10);  // wait for all lua_loadfile calls to finish
        do_bulk_dump(L);
    }

    return result;
}

// Install inline hook on a function
// Returns pointer to trampoline (original function entry)
static void *install_inline_hook(void *target_func, void *hook_func) {
    uintptr_t target_addr = (uintptr_t)target_func;

    // Make page writable
    uintptr_t page_start = target_addr & ~0xFFFUL;
    if (mprotect((void *)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("lua_dump: mprotect failed for %p", target_func);
        return nullptr;
    }

    // Save original first 16 bytes
    uint8_t orig_bytes[16];
    memcpy(orig_bytes, target_func, 16);

    // Allocate trampoline
    uint8_t *trampoline = (uint8_t *)mmap(nullptr, 4096,
        PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!trampoline) {
        LOGE("lua_dump: trampoline mmap failed");
        return nullptr;
    }

    // Trampoline: original 16 bytes + jump back to target+16
    memcpy(trampoline, orig_bytes, 16);
    // Fix PC-relative instructions (ADRP, ADR, B, BL) in the copied bytes
    for (int i = 0; i < 4; i++) {
        uint32_t insn;
        memcpy(&insn, trampoline + i * 4, 4);
        uint32_t op = insn >> 24;
        // ADRP: 1xx1 0000 (top bits)
        if ((insn & 0x9F000000) == 0x90000000) {
            // ADRP instruction - recalculate for new PC
            int64_t imm = ((int64_t)((insn >> 29) & 3) << 12) | ((int64_t)((insn >> 5) & 0x7FFFF) << 14);
            if (insn & 0x00800000) imm |= ~0x1FFFFFFFFFLL; // sign extend
            uint64_t old_pc = target_addr + i * 4;
            uint64_t new_pc = (uintptr_t)(trampoline + i * 4);
            uint64_t target_page = (old_pc & ~0xFFF) + imm;
            int64_t new_imm = target_page - (new_pc & ~0xFFF);
            uint32_t immlo = (new_imm >> 12) & 3;
            uint32_t immhi = (new_imm >> 14) & 0x7FFFF;
            insn = (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
            memcpy(trampoline + i * 4, &insn, 4);
            LOGI("  Fixed ADRP at +%d: target_page=0x%lx", i*4, (unsigned long)target_page);
        }
        // B/BL: 00x1 01xx (unconditional branch)
        else if ((insn & 0x7C000000) == 0x14000000) {
            int32_t offset = (insn & 0x03FFFFFF);
            if (offset & 0x02000000) offset |= ~0x03FFFFFF; // sign extend
            uint64_t branch_target = target_addr + i * 4 + offset * 4;
            int64_t new_offset = (int64_t)(branch_target - ((uintptr_t)(trampoline + i * 4))) / 4;
            insn = (insn & 0xFC000000) | (new_offset & 0x03FFFFFF);
            memcpy(trampoline + i * 4, &insn, 4);
        }
    }

    // Jump back: LDR X16, [PC, #8]; BR X16; <continue_addr>
    uint32_t ldr_x16 = 0x58000050;
    uint32_t br_x16 = 0xD61F0200;
    uint64_t continue_addr = target_addr + 16;
    memcpy(trampoline + 16, &ldr_x16, 4);
    memcpy(trampoline + 20, &br_x16, 4);
    memcpy(trampoline + 24, &continue_addr, 8);

    // Patch target: LDR X16, [PC, #8]; BR X16; <hook_addr>
    uint64_t hook_addr = (uint64_t)hook_func;
    memcpy((void *)target_addr, &ldr_x16, 4);
    memcpy((void *)(target_addr + 4), &br_x16, 4);
    memcpy((void *)(target_addr + 8), &hook_addr, 8);

    __builtin___clear_cache((char *)target_addr, (char *)(target_addr + 16));
    __builtin___clear_cache((char *)trampoline, (char *)(trampoline + 32));

    LOGI("lua_dump: hooked %p → %p (trampoline %p)", target_func, hook_func, trampoline);
    return trampoline;
}

// Delayed dump: wait for game to load, then inject Lua code to dump all loaded modules
static void *delayed_dump_thread(void *arg) {
    // Wait for game to finish loading Lua scripts
    LOGI("lua_dump: delayed dump thread started, waiting 60s for game to load...");
    sleep(60);

    if (!p_lua_getfield || !p_lua_pcall || !p_lua_tolstring || !p_lua_settop || !p_lua_gettop) {
        LOGE("lua_dump: missing Lua API for delayed dump");
        return nullptr;
    }

    // We need a lua_State. Get one from the il2cpp side via the Lua API.
    // Use luaL_loadbuffer to compile a dump script, then pcall it.
    auto p_luaL_newstate = (lua_State *(*)())xdl_sym(xdl_open("libEngineDll.so", 0), "luaL_newstate", nullptr);
    auto p_luaL_openlibs = (void (*)(lua_State *))xdl_sym(xdl_open("libEngineDll.so", 0), "luaL_openlibs", nullptr);
    auto p_luaL_loadstring = (int (*)(lua_State *, const char *))xdl_sym(xdl_open("libEngineDll.so", 0), "luaL_loadstring", nullptr);

    // We can't create a new state easily. Instead, hook into the NEXT lua_loadfile call
    // and use THAT lua_State to run our dump script.
    // Set a flag that the next lua_loadfile hook will pick up.
    LOGI("lua_dump: delayed dump ready, will dump on next Lua file load");

    return nullptr;
}

static bool install_hooks() {
    void *engine = xdl_open("libEngineDll.so", 0);
    if (!engine) {
        LOGE("lua_dump: libEngineDll.so not found");
        return false;
    }

    // Resolve all needed functions
    auto p_lua_loadfile = (int (*)(lua_State *, const char *))xdl_sym(engine, "lua_loadfile", nullptr);
    auto p_luaL_loadbuffer_addr = (int (*)(lua_State *, const char *, size_t, const char *))
        xdl_sym(engine, "luaL_loadbuffer", nullptr);
    p_lua_dump = (decltype(p_lua_dump))xdl_sym(engine, "lua_dump", nullptr);
    p_luaU_dump = (decltype(p_luaU_dump))xdl_sym(engine, "luaU_dump", nullptr);
    p_lua_gettop = (decltype(p_lua_gettop))xdl_sym(engine, "lua_gettop", nullptr);
    p_lua_settop = (decltype(p_lua_settop))xdl_sym(engine, "lua_settop", nullptr);
    p_lua_type = (decltype(p_lua_type))xdl_sym(engine, "lua_type", nullptr);
    p_lua_getfield = (decltype(p_lua_getfield))xdl_sym(engine, "lua_getfield", nullptr);
    p_lua_pushvalue = (decltype(p_lua_pushvalue))xdl_sym(engine, "lua_pushvalue", nullptr);
    p_lua_tolstring = (decltype(p_lua_tolstring))xdl_sym(engine, "lua_tolstring", nullptr);
    p_lua_pcall = (decltype(p_lua_pcall))xdl_sym(engine, "lua_pcall", nullptr);

    LOGI("lua_dump: getfield=%p pushvalue=%p tolstring=%p pcall=%p",
         p_lua_getfield, p_lua_pushvalue, p_lua_tolstring, p_lua_pcall);

    LOGI("lua_dump: lua_loadfile=%p luaL_loadbuffer=%p lua_dump=%p luaU_dump=%p",
         p_lua_loadfile, p_luaL_loadbuffer_addr, p_lua_dump, p_luaU_dump);

    if (!p_lua_dump && !p_luaU_dump) {
        LOGE("lua_dump: neither lua_dump nor luaU_dump found");
        return false;
    }

    bool hooked = false;

    // Skip lua_loadfile hook - inline hook causes SIGSEGV due to ADRP relocation issues
    // The bulk dump will be triggered from luaL_loadbuffer instead
    orig_lua_loadfile = p_lua_loadfile;  // save for calling later
    LOGI("lua_dump: lua_loadfile saved (no hook, avoids ADRP crash)");

    // Hook luaL_loadbuffer (buffer/string loading path)
    if (p_luaL_loadbuffer_addr) {
        auto tramp = install_inline_hook((void *)p_luaL_loadbuffer_addr, (void *)hooked_luaL_loadbuffer);
        if (tramp) {
            orig_luaL_loadbuffer = (decltype(orig_luaL_loadbuffer))tramp;
            LOGI("lua_dump: luaL_loadbuffer hooked");
            hooked = true;
        }
    }

    return hooked;
}

void lua_dump_start(const char *outDir) {
    LOGI("lua_dump: starting, outDir=%s", outDir);
    snprintf(g_outDir, sizeof(g_outDir), "%s/files", outDir);

    for (int i = 0; i < 30; i++) {
        void *handle = xdl_open("libEngineDll.so", 0);
        if (handle) {
            LOGI("lua_dump: libEngineDll.so found");
            if (install_hooks()) {
                LOGI("lua_dump: hooks active, waiting for Lua loads...");
            }
            return;
        }
        sleep(2);
    }
    LOGE("lua_dump: libEngineDll.so not found after 60s");
}
