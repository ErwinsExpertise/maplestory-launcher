#pragma once

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <string>

namespace maple {

std::wstring last_error_message(DWORD error);
bool apply_process_patches(HANDLE process, std::wstring* error_message = nullptr, std::uintptr_t image_base = 0);

}  // namespace maple
