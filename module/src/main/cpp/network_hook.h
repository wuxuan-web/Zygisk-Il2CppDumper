//
// Network Hook for MONOPOLY GO
//

#ifndef NETWORK_HOOK_H
#define NETWORK_HOOK_H

#include <cstdint>

// Initialize network traffic hooks
// Requires a hooking library (shadowhook, dobby, etc.) to actually intercept calls
void init_network_hooks(uint64_t il2cpp_base, const char* output_dir);

#endif // NETWORK_HOOK_H
