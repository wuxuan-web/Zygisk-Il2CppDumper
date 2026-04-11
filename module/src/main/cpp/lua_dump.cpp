//
// Lua bytecode dump via hooking luaL_loadbuffer in libEngineDll.so
// Intercepts Lua file loads, calls lua_dump to output standard Lua 5.1 bytecode
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
#include <pthread.h>

// Lua types (opaque pointers)
typedef struct lua_State lua_State;

// Lua C API function pointers (resolved from libEngineDll.so)
static int (*orig_luaL_loadbuffer)(lua_State *L, const char *buff, size_t sz, const char *name) = nullptr;
static int (*p_lua_dump)(lua_State *L, void *writer, void *data) = nullptr;
static int (*p_lua_pcall)(lua_State *L, int nargs, int nresults, int errfunc) = nullptr;
static void (*p_lua_settop)(lua_State *L, int index) = nullptr;
static int (*p_lua_gettop)(lua_State *L) = nullptr;
static const char *(*p_lua_tolstring)(lua_State *L, int index, size_t *len) = nullptr;

static char g_outDir[512] = {0};
static int g_dumpCount = 0;
static bool g_hookActive = false;

// Writer callback for lua_dump: writes to FILE*
static int lua_writer(lua_State *L, const void *p, size_t sz, void *ud) {
    FILE *f = (FILE *)ud;
    return (fwrite(p, 1, sz, f) != sz) ? 1 : 0;
}

// Sanitize filename: replace / with _ etc
static std::string sanitize_name(const char *name) {
    if (!name || !name[0]) return "unknown";
    std::string s(name);
    // Remove leading @./
    if (s[0] == '@') s = s.substr(1);
    if (s.substr(0, 2) == "./") s = s.substr(2);
    // Replace path separators
    for (auto &c : s) {
        if (c == '/' || c == '\\' || c == ':' || c == ' ') c = '_';
    }
    return s;
}

// Hooked luaL_loadbuffer: after loading, dump the bytecode in standard format
static int hooked_luaL_loadbuffer(lua_State *L, const char *buff, size_t sz, const char *name) {
    // Call original to let the game's custom Lua VM parse the bytecode
    int result = orig_luaL_loadbuffer(L, buff, sz, name);

    if (result != 0) {
        // Load failed - don't try to dump
        return result;
    }

    // Success: the compiled function is now on the Lua stack top
    // Use lua_dump to serialize it in STANDARD Lua 5.1 format
    if (p_lua_dump && g_outDir[0]) {
        std::string safe_name = sanitize_name(name);

        // Create output directory
        char dir_path[768];
        snprintf(dir_path, sizeof(dir_path), "%s/lua_dump", g_outDir);
        mkdir(dir_path, 0777);

        // Output path
        char out_path[1024];
        snprintf(out_path, sizeof(out_path), "%s/%s.luac", dir_path, safe_name.c_str());

        FILE *f = fopen(out_path, "wb");
        if (f) {
            int dump_result = p_lua_dump(L, (void *)lua_writer, f);
            fclose(f);

            g_dumpCount++;
            if (g_dumpCount <= 20 || g_dumpCount % 100 == 0) {
                LOGI("Lua dump [%d]: %s (%zu bytes) → %s (result=%d)",
                     g_dumpCount, name ? name : "?", sz, out_path, dump_result);
            }
        }
    }

    return result;
}

// Inline hook using PLT/GOT override (simple approach for exported functions)
// We use xdl to find the symbol and then patch the GOT entry
static bool install_hook() {
    void *engine = xdl_open("libEngineDll.so", 0);
    if (!engine) {
        LOGE("lua_dump: libEngineDll.so not found");
        return false;
    }

    // Resolve functions
    orig_luaL_loadbuffer = (decltype(orig_luaL_loadbuffer))xdl_sym(engine, "luaL_loadbuffer", nullptr);
    p_lua_dump = (decltype(p_lua_dump))xdl_sym(engine, "lua_dump", nullptr);
    p_lua_pcall = (decltype(p_lua_pcall))xdl_sym(engine, "lua_pcall", nullptr);
    p_lua_settop = (decltype(p_lua_settop))xdl_sym(engine, "lua_settop", nullptr);
    p_lua_gettop = (decltype(p_lua_gettop))xdl_sym(engine, "lua_gettop", nullptr);
    p_lua_tolstring = (decltype(p_lua_tolstring))xdl_sym(engine, "lua_tolstring", nullptr);

    LOGI("lua_dump: luaL_loadbuffer=%p lua_dump=%p lua_pcall=%p",
         orig_luaL_loadbuffer, p_lua_dump, p_lua_pcall);

    if (!orig_luaL_loadbuffer || !p_lua_dump) {
        LOGE("lua_dump: required Lua functions not found");
        return false;
    }

    // For a simple PLT hook, we need a hooking library.
    // Since we're in Zygisk, we can use the linker namespace trick or
    // just patch the function prologue with a trampoline.
    //
    // Simplest approach: use the fact that luaL_loadbuffer is called from
    // libil2cpp.so through PLT. We can patch il2cpp's GOT entry for this symbol.
    //
    // But actually, since libEngineDll.so exports luaL_loadbuffer and it's
    // called by other libs through dynamic linking, we need to hook at the
    // function entry point itself.

    // Use inline hook: overwrite first instructions with branch to our hook
    // Save original first 16 bytes, replace with:
    //   LDR X16, [PC, #8]
    //   BR X16
    //   <address of hooked_luaL_loadbuffer>

    void *target = (void *)orig_luaL_loadbuffer;
    uintptr_t target_addr = (uintptr_t)target;

    // Make the page writable
    uintptr_t page_start = target_addr & ~0xFFF;
    if (mprotect((void *)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("lua_dump: mprotect failed for 0x%lx", (unsigned long)page_start);
        return false;
    }

    // Save original bytes (first 16 bytes)
    static uint8_t orig_bytes[16];
    memcpy(orig_bytes, target, 16);

    // Allocate trampoline for calling original
    // The trampoline restores the original 16 bytes and jumps back
    static uint8_t *trampoline = nullptr;
    trampoline = (uint8_t *)mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!trampoline) {
        LOGE("lua_dump: trampoline mmap failed");
        return false;
    }

    // Build trampoline: execute original first 4 instructions (16 bytes), then jump to target+16
    memcpy(trampoline, orig_bytes, 16);
    // LDR X16, [PC, #8]
    uint32_t ldr_x16 = 0x58000050;  // LDR X16, #8
    uint32_t br_x16 = 0xD61F0200;   // BR X16
    memcpy(trampoline + 16, &ldr_x16, 4);
    memcpy(trampoline + 20, &br_x16, 4);
    uint64_t continue_addr = target_addr + 16;
    memcpy(trampoline + 24, &continue_addr, 8);

    // Update orig_luaL_loadbuffer to point to trampoline
    orig_luaL_loadbuffer = (decltype(orig_luaL_loadbuffer))trampoline;

    // Patch target function entry: LDR X16, [PC, #8]; BR X16; <hook_addr>
    uint64_t hook_addr = (uint64_t)hooked_luaL_loadbuffer;
    memcpy((void *)target_addr, &ldr_x16, 4);
    memcpy((void *)(target_addr + 4), &br_x16, 4);
    memcpy((void *)(target_addr + 8), &hook_addr, 8);

    // Clear instruction cache
    __builtin___clear_cache((char *)target_addr, (char *)(target_addr + 16));
    __builtin___clear_cache((char *)trampoline, (char *)(trampoline + 32));

    LOGI("lua_dump: hook installed at %p → %p (trampoline at %p)",
         target, (void *)hook_addr, trampoline);

    g_hookActive = true;
    return true;
}

void lua_dump_start(const char *outDir) {
    LOGI("lua_dump: starting, outDir=%s", outDir);
    snprintf(g_outDir, sizeof(g_outDir), "%s/files", outDir);

    // Wait for libEngineDll.so to load
    for (int i = 0; i < 30; i++) {
        void *handle = xdl_open("libEngineDll.so", 0);
        if (handle) {
            LOGI("lua_dump: libEngineDll.so found");
            if (install_hook()) {
                LOGI("lua_dump: hook active, waiting for Lua loads...");
            }
            return;
        }
        sleep(2);
    }
    LOGE("lua_dump: libEngineDll.so not found after 60s");
}
