#include "injector.h"

#include "config.h"
#include "embedded_config.h"

#include <windows.h>

namespace maple {

namespace {

using NtQueryInformationProcessFn = LONG (NTAPI*)(HANDLE, unsigned long, void*, unsigned long, unsigned long*);
constexpr unsigned long kProcessBasicInformationClass = 0;
constexpr std::uintptr_t kDefaultImageBase = 0x400000;
constexpr std::uintptr_t kDamageCapIntRva = 0x2497E1;
constexpr std::uintptr_t kDamageCapDoubleRva = 0x3A0010;
constexpr std::uintptr_t kStatAccessorReturnRva = 0x511D9;

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

bool apply_damage_cap_patches(HANDLE process, std::uintptr_t image_base, std::wstring* error_message) {
    const std::uint32_t int_cap = 999999999u;
    const double double_cap = 999999999.0;
    return write_remote_patch(process, image_base + kDamageCapIntRva, &int_cap, sizeof(int_cap), error_message) &&
           write_remote_patch(process, image_base + kDamageCapDoubleRva, &double_cap, sizeof(double_cap), error_message);
}

bool apply_stat_unsigned_fix(HANDLE process, std::uintptr_t image_base, std::wstring* error_message) {
    const std::uint8_t movzx_ax_patch[] = {0x0F, 0xB7, 0x45, 0x0A};
    const std::uint8_t movzx_eax_ax[] = {0x0F, 0xB7, 0xC0};
    const std::uint8_t movzx_ecx_ax[] = {0x0F, 0xB7, 0xC8};
    const std::uint8_t movzx_edx_ax[] = {0x0F, 0xB7, 0xD0};
    const std::uint8_t movzx_edx_local[] = {0x0F, 0xB7, 0x55, 0xD4};
    const std::uint8_t movzx_eax_local[] = {0x0F, 0xB7, 0x45, 0xDC};
    const std::uint8_t movzx_eax_varc[] = {0x0F, 0xB7, 0x45, 0xF4};
    const std::uint8_t movzx_eax_var10[] = {0x0F, 0xB7, 0x45, 0xF0};
    const std::uint8_t movzx_eax_var14[] = {0x0F, 0xB7, 0x45, 0xEC};
    const std::uint8_t movzx_eax_var18[] = {0x0F, 0xB7, 0x45, 0xE8};

    struct Patch { std::uintptr_t rva; const void* data; std::size_t size; };
    const Patch patches[] = {
        {kStatAccessorReturnRva, movzx_ax_patch, sizeof(movzx_ax_patch)},
        {0x24C0B4, movzx_eax_ax, sizeof(movzx_eax_ax)}, {0x24C117, movzx_edx_local, sizeof(movzx_edx_local)}, {0x24C121, movzx_eax_local, sizeof(movzx_eax_local)},
        {0x24C21C, movzx_eax_ax, sizeof(movzx_eax_ax)}, {0x24C27F, movzx_edx_local, sizeof(movzx_edx_local)}, {0x24C289, movzx_eax_local, sizeof(movzx_eax_local)},
        {0x24C3B2, movzx_eax_ax, sizeof(movzx_eax_ax)}, {0x24C415, movzx_edx_local, sizeof(movzx_edx_local)}, {0x24C41F, movzx_eax_local, sizeof(movzx_eax_local)},
        {0x24C54B, movzx_eax_ax, sizeof(movzx_eax_ax)}, {0x24C5AB, movzx_edx_local, sizeof(movzx_edx_local)}, {0x24C5B5, movzx_eax_local, sizeof(movzx_eax_local)},
        {0x24EFD7, movzx_ecx_ax, sizeof(movzx_ecx_ax)}, {0x24EFDA, movzx_eax_varc, sizeof(movzx_eax_varc)}, {0x24EFE0, movzx_eax_var10, sizeof(movzx_eax_var10)},
        {0x24EFE6, movzx_eax_var14, sizeof(movzx_eax_var14)}, {0x24EFEC, movzx_eax_var18, sizeof(movzx_eax_var18)},
        {0x250521, movzx_edx_ax, sizeof(movzx_edx_ax)}, {0x250531, movzx_eax_varc, sizeof(movzx_eax_varc)}, {0x250537, movzx_eax_var10, sizeof(movzx_eax_var10)},
        {0x25053D, movzx_eax_var14, sizeof(movzx_eax_var14)}, {0x250543, movzx_eax_var18, sizeof(movzx_eax_var18)},
        {0x2507FA, movzx_edx_ax, sizeof(movzx_edx_ax)}, {0x25080D, movzx_eax_varc, sizeof(movzx_eax_varc)}, {0x250813, movzx_eax_var10, sizeof(movzx_eax_var10)},
        {0x250819, movzx_eax_var14, sizeof(movzx_eax_var14)}, {0x25081F, movzx_eax_var18, sizeof(movzx_eax_var18)},
    };

    for (const auto& patch : patches) {
        if (!write_remote_patch(process, image_base + patch.rva, patch.data, patch.size, error_message)) {
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

    return apply_config_patches(process, error_message) &&
           apply_damage_cap_patches(process, image_base, error_message) &&
           apply_stat_unsigned_fix(process, image_base, error_message);
}

}  // namespace maple
