//
// Network Hook for MONOPOLY GO
// Intercepts and logs decrypted network traffic
//

#include "network_hook.h"
#include "log.h"
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <string>
#include <fstream>

// Il2Cpp String structure
struct Il2CppString {
    void *klass;
    void *monitor;
    int32_t length;
    char16_t chars[0];
};

// Il2Cpp Array structure
struct Il2CppArray {
    void *klass;
    void *monitor;
    void *bounds;
    int32_t max_length;
    uint8_t data[0];
};

// Global variables
static uint64_t g_il2cpp_base = 0;
static const char* g_output_dir = nullptr;
static FILE* g_log_file = nullptr;

// RVA offsets (from IDA analysis)
#define RVA_GenerateSignatureHeader  0x4ea9bf4
#define RVA_ComputeSignature         0x4ee91b0
#define RVA_BuildMessageString       0x4ee9408
#define RVA_DeriveSigningKey         0x4ee97a0
#define RVA_Obfuscate                0x4ee4988
#define RVA_ObfuscatedStreamRead     0x4e8e5dc
#define RVA_ObfuscatedStreamWrite    0x4e8e6f4
#define RVA_JsonSerialize            0x4e8bb9c

// Original function pointers
typedef void* (*GenerateSignatureHeader_t)(void* networkRequest, void* queryParams, void* content, int contentLength);
typedef void* (*ComputeSignature_t)(void* signingKey, void* message);
typedef void* (*BuildMessageString_t)(void* methodType, void* uri, void* queryParams, int obfuscated, void* contentBytes, int offset, int length);
typedef void* (*DeriveSigningKey_t)(void* sessionToken, void* sharedSecret);
typedef void (*Obfuscate_t)(void* array, int offset, int count);
typedef int (*ObfuscatedStreamRead_t)(void* stream, void* buffer, int offset, int count);
typedef void (*ObfuscatedStreamWrite_t)(void* stream, void* buffer, int offset, int count);
typedef void* (*JsonSerialize_t)(void* obj, int pretty);

static GenerateSignatureHeader_t orig_GenerateSignatureHeader = nullptr;
static ComputeSignature_t orig_ComputeSignature = nullptr;
static BuildMessageString_t orig_BuildMessageString = nullptr;
static DeriveSigningKey_t orig_DeriveSigningKey = nullptr;
static Obfuscate_t orig_Obfuscate = nullptr;
static ObfuscatedStreamRead_t orig_ObfuscatedStreamRead = nullptr;
static ObfuscatedStreamWrite_t orig_ObfuscatedStreamWrite = nullptr;
static JsonSerialize_t orig_JsonSerialize = nullptr;

// Helper: Read Il2Cpp String
static std::string readIl2CppString(void* ptr) {
    if (!ptr) return "<null>";
    try {
        Il2CppString* str = (Il2CppString*)ptr;
        if (str->length <= 0 || str->length > 65535) return "<invalid>";
        std::string result;
        for (int i = 0; i < str->length; i++) {
            result += (char)str->chars[i];
        }
        return result;
    } catch (...) {
        return "<error>";
    }
}

// Helper: XOR deobfuscate
static void deobfuscate(uint8_t* data, int length) {
    for (int i = 0; i < length; i++) {
        data[i] ^= 0x45;
    }
}

// Helper: Log to file
static void logNetwork(const char* tag, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    char buffer[4096];
    vsnprintf(buffer, sizeof(buffer), format, args);
    
    LOGI("[NET/%s] %s", tag, buffer);
    
    if (g_log_file) {
        fprintf(g_log_file, "[%s] %s\n", tag, buffer);
        fflush(g_log_file);
    }
    
    va_end(args);
}

// Hook: ComputeSignature - captures the signing key and message
static void* hook_ComputeSignature(void* signingKey, void* message) {
    std::string key = readIl2CppString(signingKey);
    std::string msg = readIl2CppString(message);
    
    logNetwork("SIGN", "SigningKey: %s", key.c_str());
    logNetwork("SIGN", "Message: %s", msg.c_str());
    
    void* result = orig_ComputeSignature(signingKey, message);
    
    std::string sig = readIl2CppString(result);
    logNetwork("SIGN", "Signature: %s", sig.c_str());
    
    return result;
}

// Hook: DeriveSigningKey - captures session token and shared secret
static void* hook_DeriveSigningKey(void* sessionToken, void* sharedSecret) {
    std::string token = readIl2CppString(sessionToken);
    std::string secret = readIl2CppString(sharedSecret);
    
    logNetwork("KEY", "SessionToken: %s", token.c_str());
    logNetwork("KEY", "SharedSecret: %s", secret.c_str());
    
    void* result = orig_DeriveSigningKey(sessionToken, sharedSecret);
    
    std::string derived = readIl2CppString(result);
    logNetwork("KEY", "DerivedKey: %s", derived.c_str());
    
    return result;
}

// Hook: BuildMessageString - captures request details
static void* hook_BuildMessageString(void* methodType, void* uri, void* queryParams, 
                                      int obfuscated, void* contentBytes, int offset, int length) {
    std::string method = readIl2CppString(methodType);
    std::string uriStr = readIl2CppString(uri);
    std::string params = readIl2CppString(queryParams);
    
    logNetwork("REQ", "Method: %s, URI: %s", method.c_str(), uriStr.c_str());
    logNetwork("REQ", "QueryParams: %s, Obfuscated: %d, ContentLen: %d", 
               params.c_str(), obfuscated, length);
    
    return orig_BuildMessageString(methodType, uri, queryParams, obfuscated, contentBytes, offset, length);
}

// Hook: ObfuscatedStreamRead - captures decrypted response
static int hook_ObfuscatedStreamRead(void* stream, void* buffer, int offset, int count) {
    int result = orig_ObfuscatedStreamRead(stream, buffer, offset, count);
    
    if (result > 0 && buffer) {
        Il2CppArray* arr = (Il2CppArray*)buffer;
        
        // Create a copy and deobfuscate
        int len = result < 1024 ? result : 1024;
        uint8_t temp[1024];
        memcpy(temp, arr->data + offset, len);
        deobfuscate(temp, len);
        
        // Check if it looks like text
        bool isText = true;
        for (int i = 0; i < len && i < 20; i++) {
            if (temp[i] < 0x20 && temp[i] != '\r' && temp[i] != '\n' && temp[i] != '\t') {
                if (temp[i] != 0) isText = false;
                break;
            }
        }
        
        if (isText) {
            temp[len - 1] = 0;
            logNetwork("RESP", "(%d bytes) %s%s", result, (char*)temp, result > 1024 ? "..." : "");
        }
    }
    
    return result;
}

// Hook: ObfuscatedStreamWrite - captures decrypted request body
static void hook_ObfuscatedStreamWrite(void* stream, void* buffer, int offset, int count) {
    if (count > 0 && buffer) {
        Il2CppArray* arr = (Il2CppArray*)buffer;
        
        // The data is already XORed, so we deobfuscate to see plaintext
        int len = count < 1024 ? count : 1024;
        uint8_t temp[1024];
        memcpy(temp, arr->data + offset, len);
        deobfuscate(temp, len);
        
        bool isText = true;
        for (int i = 0; i < len && i < 20; i++) {
            if (temp[i] < 0x20 && temp[i] != '\r' && temp[i] != '\n' && temp[i] != '\t') {
                if (temp[i] != 0) isText = false;
                break;
            }
        }
        
        if (isText) {
            temp[len - 1] = 0;
            logNetwork("BODY", "(%d bytes) %s%s", count, (char*)temp, count > 1024 ? "..." : "");
        }
    }
    
    orig_ObfuscatedStreamWrite(stream, buffer, offset, count);
}

// Hook: JsonSerialize - captures JSON being serialized
static void* hook_JsonSerialize(void* obj, int pretty) {
    void* result = orig_JsonSerialize(obj, pretty);
    
    std::string json = readIl2CppString(result);
    if (json.length() > 10 && json[0] == '{') {
        if (json.length() > 500) {
            logNetwork("JSON", "%s...(truncated)", json.substr(0, 500).c_str());
        } else {
            logNetwork("JSON", "%s", json.c_str());
        }
    }
    
    return result;
}

// Simple inline hook (replace first instruction with branch)
// This is a simplified version - production code should use a proper hooking library
static bool inline_hook(void* target, void* hook, void** orig) {
    // For simplicity, we'll just log that we would hook here
    // In production, use libraries like: xhook, shadowhook, or dobby
    LOGI("Would hook %p -> %p", target, hook);
    *orig = target;  // This is a placeholder - real hook would save original
    return true;
}

// Initialize network hooks
void init_network_hooks(uint64_t il2cpp_base, const char* output_dir) {
    g_il2cpp_base = il2cpp_base;
    g_output_dir = output_dir;
    
    // Open log file
    std::string logPath = std::string(output_dir) + "/files/network_traffic.log";
    g_log_file = fopen(logPath.c_str(), "a");
    if (g_log_file) {
        LOGI("Network traffic log: %s", logPath.c_str());
        fprintf(g_log_file, "\n=== Session started ===\n");
        fflush(g_log_file);
    }
    
    LOGI("Initializing network hooks at base 0x%" PRIx64, il2cpp_base);
    
    // Note: These hooks require a proper inline hooking library
    // The addresses below are correct based on IDA analysis
    
    void* addr_ComputeSignature = (void*)(il2cpp_base + RVA_ComputeSignature);
    void* addr_DeriveSigningKey = (void*)(il2cpp_base + RVA_DeriveSigningKey);
    void* addr_BuildMessageString = (void*)(il2cpp_base + RVA_BuildMessageString);
    void* addr_ObfuscatedStreamRead = (void*)(il2cpp_base + RVA_ObfuscatedStreamRead);
    void* addr_ObfuscatedStreamWrite = (void*)(il2cpp_base + RVA_ObfuscatedStreamWrite);
    void* addr_JsonSerialize = (void*)(il2cpp_base + RVA_JsonSerialize);
    
    LOGI("Hook targets:");
    LOGI("  ComputeSignature: %p", addr_ComputeSignature);
    LOGI("  DeriveSigningKey: %p", addr_DeriveSigningKey);
    LOGI("  BuildMessageString: %p", addr_BuildMessageString);
    LOGI("  ObfuscatedStreamRead: %p", addr_ObfuscatedStreamRead);
    LOGI("  ObfuscatedStreamWrite: %p", addr_ObfuscatedStreamWrite);
    LOGI("  JsonSerialize: %p", addr_JsonSerialize);
    
    // To actually enable hooks, you need to integrate a hooking library
    // Options: shadowhook, dobby, xhook, or substrate
    // Example with shadowhook:
    // shadowhook_hook_func_addr(addr_ComputeSignature, (void*)hook_ComputeSignature, (void**)&orig_ComputeSignature);
    
    LOGI("Network hook initialization complete (hooks need hooking library)");
}
