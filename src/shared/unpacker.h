#pragma once

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <string>

namespace maple {

struct UnpackResult {
    DWORD pid = 0;
    HANDLE process = nullptr;
    bool success = false;
};

UnpackResult launch_unpacked_client(const std::filesystem::path& client_path,
                                    const std::filesystem::path& working_dir,
                                    std::wstring& error);

}
