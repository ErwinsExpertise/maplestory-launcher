cmake_minimum_required(VERSION 3.20)
project(maple_launcher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_definitions(UNICODE _UNICODE)

include(maple_config.cmake)

set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GENERATED_DIR}")

set(GENERATED_HEADER "${GENERATED_DIR}/embedded_config.h")
set(GENERATED_SOURCE "${GENERATED_DIR}/embedded_config.cpp")

file(WRITE "${GENERATED_HEADER}" "#pragma once\n\n#include \"config.h\"\n\nnamespace maple {\nconst Config& embedded_config();\n}\n")

if(MAPLE_UNPACK_MODE)
    set(UNPACK_MODE_CPP "true")
else()
    set(UNPACK_MODE_CPP "false")
endif()

set(CONFIG_SOURCE "#include \"embedded_config.h\"\n\n#include <optional>\n#include <vector>\n\nnamespace maple {\n\nconst Config& embedded_config() {\n    static const Config config{\n        LauncherSettings{\n            std::filesystem::path{R\"(${MAPLE_CLIENT})\"},\n            std::filesystem::path{R\"(${MAPLE_WORKING_DIR})\"},\n            std::wstring{L\"${MAPLE_ARGUMENTS}\"},\n            ${UNPACK_MODE_CPP},\n        },\n        {\n")

foreach(PATCH_SPEC IN LISTS MAPLE_PATCHES)
    string(REPLACE "|" ";" PATCH_PARTS "${PATCH_SPEC}")
    list(LENGTH PATCH_PARTS PATCH_LEN)
    if(PATCH_LEN LESS 3)
        message(FATAL_ERROR "Invalid patch spec: ${PATCH_SPEC}")
    endif()

    list(GET PATCH_PARTS 0 PATCH_ADDRESS)
    list(GET PATCH_PARTS 1 PATCH_TYPE_RAW)
    list(GET PATCH_PARTS 2 PATCH_VALUE_RAW)

    set(PATCH_SIZE_CODE "std::nullopt")
    if(PATCH_LEN GREATER 3)
        list(GET PATCH_PARTS 3 PATCH_SIZE_RAW)
        set(PATCH_SIZE_CODE "std::optional<std::size_t>{${PATCH_SIZE_RAW}}")
    endif()

    string(TOUPPER "${PATCH_TYPE_RAW}" PATCH_TYPE_UPPER)
    if(PATCH_TYPE_UPPER STREQUAL "HEX")
        set(PATCH_TYPE_CPP "PatchType::Hex")
    elseif(PATCH_TYPE_UPPER STREQUAL "ASCII")
        set(PATCH_TYPE_CPP "PatchType::Ascii")
    elseif(PATCH_TYPE_UPPER STREQUAL "U32")
        set(PATCH_TYPE_CPP "PatchType::U32")
    else()
        message(FATAL_ERROR "Unsupported patch type: ${PATCH_TYPE_RAW}")
    endif()

    string(REPLACE "\\" "\\\\" PATCH_VALUE_ESCAPED "${PATCH_VALUE_RAW}")
    string(REPLACE "\"" "\\\"" PATCH_VALUE_ESCAPED "${PATCH_VALUE_ESCAPED}")
    string(APPEND CONFIG_SOURCE "            PatchEntry{${PATCH_ADDRESS}u, ${PATCH_TYPE_CPP}, \"${PATCH_VALUE_ESCAPED}\", ${PATCH_SIZE_CODE}},\n")
endforeach()

string(APPEND CONFIG_SOURCE "        },\n    };\n    return config;\n}\n\n}  // namespace maple\n")
file(WRITE "${GENERATED_SOURCE}" "${CONFIG_SOURCE}")

add_library(shared OBJECT
    src/shared/aspirin_port.cpp
    src/shared/config.cpp
    src/shared/injector.cpp
    src/shared/unpacker.cpp
    ${GENERATED_SOURCE}
)

target_include_directories(shared PUBLIC src/shared ${GENERATED_DIR})

add_executable(maple_launcher WIN32
    src/launcher/app.rc
    src/launcher/main.cpp
    $<TARGET_OBJECTS:shared>
)

target_include_directories(maple_launcher PRIVATE src/shared ${GENERATED_DIR})

target_link_libraries(maple_launcher PRIVATE user32 comdlg32 comctl32)

if(MINGW)
    target_link_options(maple_launcher PRIVATE -municode)
    target_link_options(maple_launcher PRIVATE -static -static-libgcc -static-libstdc++)
endif()
