//
// Created by Perfare on 2020/7/4.
//

#include "il2cpp_dump.h"
#include "game.h"
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"

// Metadata magic number: AF 1B B1 FA
#define METADATA_MAGIC 0xFAB11BAF

// Forward declaration
static void dump_metadata(const char *outDir);

#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API

static uint64_t il2cpp_base = 0;

void init_il2cpp_api(void *handle) {
#define DO_API(r, n, p) {                      \
    n = (r (*) p)xdl_sym(handle, #n, nullptr); \
    if(!n) {                                   \
        LOGW("api not found %s", #n);          \
    }                                          \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}

std::string get_method_modifier(uint32_t flags) {
    std::stringstream outPut;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access) {
        case METHOD_ATTRIBUTE_PRIVATE:
            outPut << "private ";
            break;
        case METHOD_ATTRIBUTE_PUBLIC:
            outPut << "public ";
            break;
        case METHOD_ATTRIBUTE_FAMILY:
            outPut << "protected ";
            break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
            outPut << "internal ";
            break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC) {
        outPut << "static ";
    }
    if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_FINAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "sealed override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT) {
            outPut << "virtual ";
        } else {
            outPut << "override ";
        }
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) {
        outPut << "extern ";
    }
    return outPut.str();
}

bool _il2cpp_type_is_byref(const Il2CppType *type) {
    auto byref = type->byref;
    if (il2cpp_type_is_byref) {
        byref = il2cpp_type_is_byref(type);
    }
    return byref;
}

std::string dump_method(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Methods\n";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        //TODO attribute
        if (method->methodPointer) {
            outPut << "\t// RVA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer - il2cpp_base;
            outPut << " VA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer;
        } else {
            outPut << "\t// RVA: 0x VA: 0x0";
        }
        /*if (method->slot != 65535) {
            outPut << " Slot: " << std::dec << method->slot;
        }*/
        outPut << "\n\t";
        uint32_t iflags = 0;
        auto flags = il2cpp_method_get_flags(method, &iflags);
        outPut << get_method_modifier(flags);
        //TODO genericContainerIndex
        auto return_type = il2cpp_method_get_return_type(method);
        if (_il2cpp_type_is_byref(return_type)) {
            outPut << "ref ";
        }
        auto return_class = il2cpp_class_from_type(return_type);
        outPut << il2cpp_class_get_name(return_class) << " " << il2cpp_method_get_name(method)
               << "(";
        auto param_count = il2cpp_method_get_param_count(method);
        for (int i = 0; i < param_count; ++i) {
            auto param = il2cpp_method_get_param(method, i);
            auto attrs = param->attrs;
            if (_il2cpp_type_is_byref(param)) {
                if (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN)) {
                    outPut << "out ";
                } else if (attrs & PARAM_ATTRIBUTE_IN && !(attrs & PARAM_ATTRIBUTE_OUT)) {
                    outPut << "in ";
                } else {
                    outPut << "ref ";
                }
            } else {
                if (attrs & PARAM_ATTRIBUTE_IN) {
                    outPut << "[In] ";
                }
                if (attrs & PARAM_ATTRIBUTE_OUT) {
                    outPut << "[Out] ";
                }
            }
            auto parameter_class = il2cpp_class_from_type(param);
            outPut << il2cpp_class_get_name(parameter_class) << " "
                   << il2cpp_method_get_param_name(method, i);
            outPut << ", ";
        }
        if (param_count > 0) {
            outPut.seekp(-2, outPut.cur);
        }
        outPut << ") { }\n";
        //TODO GenericInstMethod
    }
    return outPut.str();
}

std::string dump_property(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter)) {
        //TODO attribute
        auto prop = const_cast<PropertyInfo *>(prop_const);
        auto get = il2cpp_property_get_get_method(prop);
        auto set = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        outPut << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get) {
            outPut << get_method_modifier(il2cpp_method_get_flags(get, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_return_type(get));
        } else if (set) {
            outPut << get_method_modifier(il2cpp_method_get_flags(set, &iflags));
            auto param = il2cpp_method_get_param(set, 0);
            prop_class = il2cpp_class_from_type(param);
        }
        if (prop_class) {
            outPut << il2cpp_class_get_name(prop_class) << " " << prop_name << " { ";
            if (get) {
                outPut << "get; ";
            }
            if (set) {
                outPut << "set; ";
            }
            outPut << "}\n";
        } else {
            if (prop_name) {
                outPut << " // unknown property " << prop_name;
            }
        }
    }
    return outPut.str();
}

std::string dump_field(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter)) {
        //TODO attribute
        outPut << "\t";
        auto attrs = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
            case FIELD_ATTRIBUTE_PRIVATE:
                outPut << "private ";
                break;
            case FIELD_ATTRIBUTE_PUBLIC:
                outPut << "public ";
                break;
            case FIELD_ATTRIBUTE_FAMILY:
                outPut << "protected ";
                break;
            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                outPut << "internal ";
                break;
            case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                outPut << "protected internal ";
                break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL) {
            outPut << "const ";
        } else {
            if (attrs & FIELD_ATTRIBUTE_STATIC) {
                outPut << "static ";
            }
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY) {
                outPut << "readonly ";
            }
        }
        auto field_type = il2cpp_field_get_type(field);
        auto field_class = il2cpp_class_from_type(field_type);
        outPut << il2cpp_class_get_name(field_class) << " " << il2cpp_field_get_name(field);
        //TODO 获取构造函数初始化后的字段值
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum) {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            outPut << " = " << std::dec << val;
        }
        outPut << "; // 0x" << std::hex << il2cpp_field_get_offset(field) << "\n";
    }
    return outPut.str();
}

std::string dump_type(const Il2CppType *type) {
    std::stringstream outPut;
    auto *klass = il2cpp_class_from_type(type);
    outPut << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) {
        outPut << "[Serializable]\n";
    }
    //TODO attribute
    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum = il2cpp_class_is_enum(klass);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:
            outPut << "public ";
            break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
            outPut << "internal ";
            break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:
            outPut << "private ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:
            outPut << "protected ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "static ";
    } else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
    } else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "sealed ";
    }
    if (flags & TYPE_ATTRIBUTE_INTERFACE) {
        outPut << "interface ";
    } else if (is_enum) {
        outPut << "enum ";
    } else if (is_valuetype) {
        outPut << "struct ";
    } else {
        outPut << "class ";
    }
    outPut << il2cpp_class_get_name(klass); //TODO genericContainerIndex
    std::vector<std::string> extends;
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent) {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT) {
            extends.emplace_back(il2cpp_class_get_name(parent));
        }
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter)) {
        extends.emplace_back(il2cpp_class_get_name(itf));
    }
    if (!extends.empty()) {
        outPut << " : " << extends[0];
        for (int i = 1; i < extends.size(); ++i) {
            outPut << ", " << extends[i];
        }
    }
    outPut << "\n{";
    outPut << dump_field(klass);
    outPut << dump_property(klass);
    outPut << dump_method(klass);
    //TODO EventInfo
    outPut << "}\n";
    return outPut.str();
}

void il2cpp_api_init(void *handle) {
    LOGI("il2cpp_handle: %p", handle);
    init_il2cpp_api(handle);

    // Get base address from handle directly via dlinfo
    Dl_info dlInfo;
    if (dladdr(handle, &dlInfo)) {
        il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
        LOGI("il2cpp_base (from handle): %" PRIx64, il2cpp_base);
    }

    if (il2cpp_domain_get_assemblies) {
        if (!il2cpp_base) {
            if (dladdr((void *) il2cpp_domain_get_assemblies, &dlInfo)) {
                il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
            }
        }
        LOGI("il2cpp_base: %" PRIx64, il2cpp_base);
    } else {
        LOGW("il2cpp_domain_get_assemblies not found (symbols may be obfuscated)");
        LOGI("Will attempt metadata-only dump");
        return;
    }
    int wait_count = 0;
    while (!il2cpp_is_vm_thread(nullptr)) {
        LOGI("Waiting for il2cpp_init...");
        sleep(1);
        if (++wait_count > 30) {
            LOGW("Timeout waiting for il2cpp_init");
            return;
        }
    }
    auto domain = il2cpp_domain_get();
    il2cpp_thread_attach(domain);
}

void il2cpp_dump(const char *outDir) {
    LOGI("dumping...");

    // Always attempt metadata dump first (works even with obfuscated symbols)
    // Wait for the game to fully initialize and decrypt metadata
    LOGI("Waiting for game initialization before metadata dump...");
    sleep(10);
    dump_metadata(outDir);

    // Try API-based dump (will fail if symbols are obfuscated)
    if (!il2cpp_domain_get_assemblies) {
        LOGW("IL2CPP API not available (obfuscated symbols), skipping class dump");
        return;
    }

    size_t size;
    auto domain = il2cpp_domain_get();
    if (!domain) {
        LOGW("il2cpp_domain_get returned null");
        return;
    }
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    if (!assemblies || size == 0) {
        LOGW("No assemblies found");
        return;
    }
    std::stringstream imageOutput;
    for (int i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
    }
    std::vector<std::string> outPuts;
    if (il2cpp_image_get_class) {
        LOGI("Version greater than 2018.3");
        //使用il2cpp_image_get_class
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            imageStr << "\n// Dll : " << il2cpp_image_get_name(image);
            auto classCount = il2cpp_image_get_class_count(image);
            for (int j = 0; j < classCount; ++j) {
                auto klass = il2cpp_image_get_class(image, j);
                auto type = il2cpp_class_get_type(const_cast<Il2CppClass *>(klass));
                //LOGD("type name : %s", il2cpp_type_get_name(type));
                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    } else {
        LOGI("Version less than 2018.3");
        //使用反射
        auto corlib = il2cpp_get_corlib();
        auto assemblyClass = il2cpp_class_from_name(corlib, "System.Reflection", "Assembly");
        auto assemblyLoad = il2cpp_class_get_method_from_name(assemblyClass, "Load", 1);
        auto assemblyGetTypes = il2cpp_class_get_method_from_name(assemblyClass, "GetTypes", 0);
        if (assemblyLoad && assemblyLoad->methodPointer) {
            LOGI("Assembly::Load: %p", assemblyLoad->methodPointer);
        } else {
            LOGI("miss Assembly::Load");
            return;
        }
        if (assemblyGetTypes && assemblyGetTypes->methodPointer) {
            LOGI("Assembly::GetTypes: %p", assemblyGetTypes->methodPointer);
        } else {
            LOGI("miss Assembly::GetTypes");
            return;
        }
        typedef void *(*Assembly_Load_ftn)(void *, Il2CppString *, void *);
        typedef Il2CppArray *(*Assembly_GetTypes_ftn)(void *, void *);
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            auto image_name = il2cpp_image_get_name(image);
            imageStr << "\n// Dll : " << image_name;
            //LOGD("image name : %s", image->name);
            auto imageName = std::string(image_name);
            auto pos = imageName.rfind('.');
            auto imageNameNoExt = imageName.substr(0, pos);
            auto assemblyFileName = il2cpp_string_new(imageNameNoExt.data());
            auto reflectionAssembly = ((Assembly_Load_ftn) assemblyLoad->methodPointer)(nullptr,
                                                                                        assemblyFileName,
                                                                                        nullptr);
            auto reflectionTypes = ((Assembly_GetTypes_ftn) assemblyGetTypes->methodPointer)(
                    reflectionAssembly, nullptr);
            auto items = reflectionTypes->vector;
            for (int j = 0; j < reflectionTypes->max_length; ++j) {
                auto klass = il2cpp_class_from_system_type((Il2CppReflectionType *) items[j]);
                auto type = il2cpp_class_get_type(klass);
                //LOGD("type name : %s", il2cpp_type_get_name(type));
                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    }
    LOGI("write dump file");
    auto outPath = std::string(outDir).append("/files/dump.cs");
    std::ofstream outStream(outPath);
    outStream << imageOutput.str();
    auto count = outPuts.size();
    for (int i = 0; i < count; ++i) {
        outStream << outPuts[i];
    }
    outStream.close();
    LOGI("dump done!");
}

// MHY custom metadata magic: 4D 48 59 00
#define MHY_MAGIC 0x0059484D

// Dump raw memory region to file
static bool dump_region_to_file(const char *path, void *addr, size_t size) {
    FILE *outFile = fopen(path, "wb");
    if (!outFile) {
        LOGE("Failed to create %s", path);
        return false;
    }
    // Write in chunks to avoid issues
    size_t written = 0;
    size_t chunk = 4 * 1024 * 1024;
    uint8_t *ptr = (uint8_t *)addr;
    while (written < size) {
        size_t to_write = (size - written < chunk) ? (size - written) : chunk;
        size_t w = fwrite(ptr + written, 1, to_write, outFile);
        if (w == 0) break;
        written += w;
    }
    fclose(outFile);
    LOGI("Dumped %zu bytes to %s", written, path);
    return written > 0;
}

// Search for metadata in memory and dump it
static void dump_metadata(const char *outDir) {
    LOGI("Attempting to dump metadata from memory...");

    // Get il2cpp base from /proc/self/maps if not set
    if (!il2cpp_base) {
        FILE *maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[512];
            while (fgets(line, sizeof(line), maps)) {
                if (strstr(line, GameLibName) && strstr(line, "r-xp")) {
                    unsigned long start;
                    sscanf(line, "%lx-", &start);
                    il2cpp_base = start;
                    LOGI("Found %s base from maps: 0x%" PRIx64, GameLibName, il2cpp_base);
                    break;
                }
            }
            fclose(maps);
        }
    }

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGE("Failed to open /proc/self/maps");
        return;
    }

    char line[512];
    bool found_standard = false;
    bool found_mhy = false;

    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5];
        char path[256] = {0};

        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", &start, &end, perms, path) < 3) {
            continue;
        }

        if (perms[0] != 'r') continue;
        if (strstr(path, "[vdso]") || strstr(path, "[vvar]")) continue;

        size_t size = end - start;
        if (size < 0x100000 || size > 0x20000000) continue;

        uint8_t *ptr = (uint8_t *)start;
        uint8_t *region_end = (uint8_t *)end - 8;

        while (ptr < region_end) {
            uint32_t magic = *(uint32_t *)ptr;

            // Check standard IL2CPP metadata magic
            if (!found_standard && magic == METADATA_MAGIC) {
                uint32_t version = *(uint32_t *)(ptr + 4);
                if (version >= 16 && version <= 31) {
                    LOGI("Found standard metadata at %p, version %d", ptr, version);

                    // Calculate size from header
                    size_t meta_size = 0;
                    uint32_t *header = (uint32_t *)ptr;
                    for (int i = 2; i < 60; i += 2) {
                        uint32_t off = header[i];
                        uint32_t sz = header[i + 1];
                        if (off > 0 && off < 200 * 1024 * 1024 && sz > 0 && sz < 200 * 1024 * 1024) {
                            size_t e = (size_t)off + sz;
                            if (e > meta_size) meta_size = e;
                        }
                    }
                    if (meta_size < 1024 * 1024) meta_size = (size_t)(region_end - ptr);
                    meta_size = (meta_size + 0xFFF) & ~0xFFF;

                    // Dump to app data dir and sdcard
                    auto appPath = std::string(outDir).append("/files/global-metadata-decrypted.dat");
                    dump_region_to_file(appPath.c_str(), ptr, meta_size);
                    dump_region_to_file("/sdcard/global-metadata-decrypted.dat", ptr, meta_size);

                    found_standard = true;
                }
            }

            // Check MHY custom metadata magic
            if (!found_mhy && magic == MHY_MAGIC) {
                // Found MHY header - this is the encrypted metadata mapped in memory
                // Dump the entire region containing it
                size_t remaining = (size_t)(region_end - ptr);
                if (remaining > 100 * 1024 * 1024) remaining = 100 * 1024 * 1024;

                LOGI("Found MHY metadata at %p, dumping %zu bytes", ptr, remaining);
                auto appPath = std::string(outDir).append("/files/global-metadata-mhy.dat");
                dump_region_to_file(appPath.c_str(), ptr, remaining);
                dump_region_to_file("/sdcard/global-metadata-mhy.dat", ptr, remaining);

                found_mhy = true;
            }

            if (found_standard) break;
            ptr += 4;
        }
        if (found_standard) break;
    }

    fclose(maps);

    if (!found_standard && !found_mhy) {
        LOGW("No metadata found in memory (standard or MHY format)");

        // Last resort: dump the entire il2cpp data segment
        if (il2cpp_base) {
            LOGI("Dumping il2cpp data segments as fallback...");
            FILE *maps2 = fopen("/proc/self/maps", "r");
            if (maps2) {
                int seg = 0;
                while (fgets(line, sizeof(line), maps2)) {
                    if (strstr(line, GameLibName) && line[strlen(line)-2] != 'x') {
                        unsigned long start, end;
                        char perms[5];
                        sscanf(line, "%lx-%lx %4s", &start, &end, perms);
                        if (perms[0] == 'r' && (end - start) > 1024 * 1024) {
                            char segPath[256];
                            snprintf(segPath, sizeof(segPath), "/sdcard/il2cpp_segment_%d_%s.bin", seg++, perms);
                            dump_region_to_file(segPath, (void *)start, end - start);
                        }
                    }
                }
                fclose(maps2);
            }
        }
    }

    if (found_standard) {
        LOGI("Decrypted metadata dumped successfully!");
    } else if (found_mhy) {
        LOGI("MHY encrypted metadata dumped (needs offline decryption)");
    }
}
