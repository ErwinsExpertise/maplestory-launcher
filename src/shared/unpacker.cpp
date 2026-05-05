#include "unpacker.h"
#include "aspirin_port.h"
#include "injector.h"

#include <windows.h>

#include <string>
#include <thread>

namespace maple {

namespace {

constexpr DWORD kUnpackTimeoutMs = 180000;

struct NativeUnpackContext {
    std::unique_ptr<aspirin::ASProtectUnpacker> unpacker;
    std::thread worker;
    HANDLE ready_event = nullptr;
    HANDLE detach_event = nullptr;
    std::wstring error;
    bool finished = false;
};

bool launch_unpacked_client_native(const std::filesystem::path& client_path,
                                   const std::filesystem::path&,
                                   std::wstring& error,
                                   UnpackResult& result) {
    NativeUnpackContext ctx{};
    ctx.ready_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ctx.detach_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ctx.ready_event == nullptr || ctx.detach_event == nullptr) {
        error = L"Failed to create native unpack events: " + last_error_message(GetLastError());
        if (ctx.ready_event) CloseHandle(ctx.ready_event);
        if (ctx.detach_event) CloseHandle(ctx.detach_event);
        return false;
    }

    auto logger = [&ctx](aspirin::LogMsgType type, const std::wstring& msg) {
        if (type == aspirin::LogMsgType::Fatal && ctx.error.empty()) {
            ctx.error = msg;
        }
    };

    ctx.unpacker = std::make_unique<aspirin::ASProtectUnpacker>(client_path, L"", logger);
    ctx.unpacker->set_live_mode(true);
    ctx.unpacker->set_ready_event(ctx.ready_event);
    ctx.unpacker->set_detach_event(ctx.detach_event);

    ctx.worker = std::thread([&ctx]() {
        try {
            ctx.finished = ctx.unpacker->run();
        } catch (const std::exception& ex) {
            ctx.error = std::wstring(ex.what(), ex.what() + std::strlen(ex.what()));
            ctx.finished = false;
        } catch (...) {
            ctx.error = L"Unknown native worker exception";
            ctx.finished = false;
        }
    });

    const DWORD wait = WaitForSingleObject(ctx.ready_event, kUnpackTimeoutMs);
    if (wait != WAIT_OBJECT_0) {
        error = ctx.error.empty() ? L"Native unpack timed out before ready signal" : ctx.error;
        SetEvent(ctx.detach_event);
        if (ctx.worker.joinable()) ctx.worker.join();
        CloseHandle(ctx.ready_event);
        CloseHandle(ctx.detach_event);
        return false;
    }

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ctx.unpacker->process_id());
    if (process == nullptr) {
        error = L"OpenProcess failed for native unpack target: " + last_error_message(GetLastError());
        SetEvent(ctx.detach_event);
        if (ctx.worker.joinable()) ctx.worker.join();
        CloseHandle(ctx.ready_event);
        CloseHandle(ctx.detach_event);
        return false;
    }

    std::wstring patch_error;
    if (!apply_process_patches(process, &patch_error, ctx.unpacker->image_base())) {
        error = L"Native unpack patch phase failed: " + patch_error;
        TerminateProcess(process, 1);
        CloseHandle(process);
        SetEvent(ctx.detach_event);
        if (ctx.worker.joinable()) ctx.worker.join();
        CloseHandle(ctx.ready_event);
        CloseHandle(ctx.detach_event);
        return false;
    }

    SetEvent(ctx.detach_event);
    if (ctx.worker.joinable()) {
        ctx.worker.join();
    }
    CloseHandle(ctx.ready_event);
    CloseHandle(ctx.detach_event);

    if (!ctx.finished && ctx.error.empty()) {
        error = L"Native unpacker exited unsuccessfully";
        CloseHandle(process);
        return false;
    }
    if (!ctx.error.empty()) {
        error = ctx.error;
        CloseHandle(process);
        return false;
    }

    result.pid = ctx.unpacker->process_id();
    result.process = process;
    result.success = true;
    return true;
}

}

UnpackResult launch_unpacked_client(const std::filesystem::path& client_path,
                                    const std::filesystem::path& working_dir,
                                    std::wstring& error) {
    UnpackResult result{};

    std::wstring native_error;
    if (launch_unpacked_client_native(client_path, working_dir, native_error, result)) {
        return result;
    }

    error = native_error.empty() ? L"Native unpack path failed" : native_error;
    return result;
}

}
