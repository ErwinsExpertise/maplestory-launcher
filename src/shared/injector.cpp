#include "injector.h"

#include "config.h"
#include "embedded_config.h"

#include <windows.h>

namespace maple {

namespace {

using NtQueryInformationProcessFn = LONG (NTAPI*)(HANDLE, unsigned long, void*, unsigned long, unsigned long*);
constexpr unsigned long kProcessBasicInformationClass = 0;
constexpr std::uintptr_t kDefaultImageBase = 0x400000;

struct ProcessBasicInformationLocal {
    ULONG exit_status;
    void* peb_base_address;
    ULONG_PTR affinity_mask;
    LONG base_priority;
    ULONG_PTR unique_process_id;
    ULONG_PTR inherited_from_unique_process_id;
};

NtQueryInformationProcessFn nt_query_information_process() {
    static auto fn = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    return fn;
}

std::uintptr_t query_process_image_base(HANDLE process) {
    auto fn = nt_query_information_process();
    if (fn == nullptr) {
        return kDefaultImageBase;
    }

    ProcessBasicInformationLocal pbi{};
    if (fn(process, kProcessBasicInformationClass, &pbi, sizeof(pbi), nullptr) != 0) {
        return kDefaultImageBase;
    }

    std::uintptr_t image_base = 0;
    SIZE_T read = 0;
    auto peb_bytes = static_cast<std::uint8_t*>(pbi.peb_base_address);
    if (!ReadProcessMemory(process, peb_bytes + 8, &image_base, sizeof(image_base), &read) || read != sizeof(image_base)) {
        return kDefaultImageBase;
    }
    return image_base;
}

bool write_remote_patch(HANDLE process, std::uintptr_t address, const void* data, std::size_t size, std::wstring* error_message) {
    DWORD old_protect = 0;
    if (!VirtualProtectEx(process, reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        if (error_message != nullptr) {
            *error_message = L"VirtualProtectEx failed: " + last_error_message(GetLastError());
        }
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, reinterpret_cast<void*>(address), data, size, &written) || written != size) {
        if (error_message != nullptr) {
            *error_message = L"WriteProcessMemory failed: " + last_error_message(GetLastError());
        }
        VirtualProtectEx(process, reinterpret_cast<void*>(address), size, old_protect, &old_protect);
        return false;
    }

    FlushInstructionCache(process, reinterpret_cast<void*>(address), size);
    VirtualProtectEx(process, reinterpret_cast<void*>(address), size, old_protect, &old_protect);

    std::vector<std::uint8_t> verify(size);
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<void*>(address), verify.data(), size, &read) || read != size || std::memcmp(verify.data(), data, size) != 0) {
        if (error_message != nullptr) {
            *error_message = L"Patch verification failed";
        }
        return false;
    }

    return true;
}

bool apply_config_patches(HANDLE process, std::wstring* error_message) {
    const auto& config = embedded_config();
    for (const auto& patch : config.patches) {
        std::string error;
        const auto bytes = build_patch_bytes(patch, error);
        if (bytes.empty()) {
            if (error_message != nullptr) {
                *error_message = widen(error);
            }
            return false;
        }
        if (!write_remote_patch(process, patch.address, bytes.data(), bytes.size(), error_message)) {
            return false;
        }
    }
    return true;
}

}

std::wstring last_error_message(DWORD error) {
    LPWSTR buffer = nullptr;
    const DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::wstring message = size ? std::wstring(buffer, size) : L"unknown error";
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    return message;
}

bool apply_process_patches(HANDLE process, std::wstring* error_message, std::uintptr_t image_base) {
    if (image_base == 0) {
        image_base = query_process_image_base(process);
    }

    return apply_config_patches(process, error_message);
}

}  // namespace maple
