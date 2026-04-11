#ifndef LUA_DUMP_H
#define LUA_DUMP_H

// Start Lua bytecode interception
// Call after il2cpp_dump is done and game is fully loaded
void lua_dump_start(const char *outDir);

#endif
