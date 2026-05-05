#include "config.h"
#include "embedded_config.h"
#include "injector.h"
#include "unpacker.h"

#include <windows.h>
#include <commdlg.h>
#include <windowsx.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr int kBrowseButtonId = 1003;
constexpr int kLaunchButtonId = 1004;
constexpr UINT kMsgUnpackFinished = WM_APP + 1;
constexpr UINT_PTR kProgressTimerId = 1;

constexpr int kWindowWidth = 900;
constexpr int kWindowHeight = 560;
constexpr int kLeftPanelWidth = 360;

constexpr COLORREF kBgLeft = RGB(10, 12, 24);
constexpr COLORREF kBgRight = RGB(19, 22, 42);
constexpr COLORREF kBgRightBorder = RGB(30, 34, 64);
constexpr COLORREF kTopAccent = RGB(200, 134, 10);
constexpr COLORREF kTitleGold = RGB(240, 192, 96);
constexpr COLORREF kMuted = RGB(106, 114, 160);
constexpr COLORREF kBody = RGB(192, 196, 224);
constexpr COLORREF kSubtle = RGB(90, 96, 128);
constexpr COLORREF kPanelDark = RGB(13, 15, 28);
constexpr COLORREF kPanelBorder = RGB(30, 34, 64);
constexpr COLORREF kReadyFill = RGB(26, 58, 32);
constexpr COLORREF kReadyBorder = RGB(45, 107, 58);
constexpr COLORREF kReadyText = RGB(92, 219, 122);
constexpr COLORREF kBusyFill = RGB(63, 46, 18);
constexpr COLORREF kBusyBorder = RGB(130, 94, 34);
constexpr COLORREF kBusyText = RGB(240, 192, 96);
constexpr COLORREF kErrorFill = RGB(64, 26, 32);
constexpr COLORREF kErrorBorder = RGB(130, 46, 56);
constexpr COLORREF kErrorText = RGB(242, 124, 124);
constexpr COLORREF kPrimary = RGB(200, 134, 10);
constexpr COLORREF kPrimaryHot = RGB(232, 160, 32);
constexpr COLORREF kDisabledButton = RGB(90, 94, 112);
constexpr COLORREF kSecondaryBorder = RGB(42, 48, 96);
constexpr COLORREF kSecondaryBorderHot = RGB(74, 85, 160);
constexpr COLORREF kSecondaryText = RGB(106, 114, 160);
constexpr COLORREF kSecondaryTextHot = RGB(154, 162, 208);

enum class LaunchState {
    Ready,
    Busy,
    Error,
};

struct AppState {
    HWND window = nullptr;
    HWND browse_button = nullptr;
    HWND launch_button = nullptr;
    HFONT title_font = nullptr;
    HFONT launcher_font = nullptr;
    HFONT body_font = nullptr;
    HFONT small_font = nullptr;
    bool browse_hot = false;
    bool launch_hot = false;
    bool launch_in_progress = false;
    int progress_tick = 0;
    LaunchState launch_state = LaunchState::Ready;
    std::wstring status_title = L"Ready to play";
    std::wstring status_detail = L"Game files found. Press Play to launch the client.";
    std::wstring footer_message = L"Ready to play";
    std::wstring version_label = L"v48";
    std::wstring server_label = L"Live";
    std::filesystem::path selected_client_path;
};

struct LaunchAsyncResult {
    bool success = false;
    bool close_launcher = false;
    std::wstring status_title;
    std::wstring status_detail;
    std::wstring error_message;
};

struct WindowSearchState {
    DWORD pid = 0;
    HWND found = nullptr;
};

std::filesystem::path module_dir() {
    std::vector<wchar_t> buffer(MAX_PATH);
    while (true) {
        const auto copied = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (copied == 0) {
            return {};
        }
        if (copied < buffer.size() - 1) {
            return std::filesystem::path(buffer.data()).parent_path();
        }
        buffer.resize(buffer.size() * 2);
    }
}

std::wstring quote_if_needed(const std::wstring& raw) {
    if (raw.find(L' ') == std::wstring::npos) {
        return raw;
    }
    return L"\"" + raw + L"\"";
}

HFONT create_font(int height, int weight) {
    return CreateFontW(
        height,
        0,
        0,
        0,
        weight,
        FALSE,
        FALSE,
        FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Segoe UI");
}

void show_error(HWND owner, const std::wstring& message) {
    MessageBoxW(owner, message.c_str(), L"MapleStory Launcher", MB_ICONERROR | MB_OK);
}

void set_launch_state(AppState& state, LaunchState launch_state, const std::wstring& title, const std::wstring& detail) {
    state.launch_state = launch_state;
    state.status_title = title;
    state.status_detail = detail;
    state.footer_message = detail;
    InvalidateRect(state.window, nullptr, TRUE);
}

void refresh_ready_status(AppState& state) {
    const bool found = !state.selected_client_path.empty() && std::filesystem::exists(state.selected_client_path);
    if (found) {
        set_launch_state(state, LaunchState::Ready, L"Ready to play", L"Game files found. Press Play to launch the client.");
    } else {
        set_launch_state(state, LaunchState::Error, L"Game files not found", L"Use Find Game Files to locate your MapleStory installation.");
    }
}

void set_busy(AppState& state, bool busy) {
    state.launch_in_progress = busy;
    EnableWindow(state.launch_button, busy ? FALSE : TRUE);
    EnableWindow(state.browse_button, busy ? FALSE : TRUE);
    InvalidateRect(state.launch_button, nullptr, TRUE);
    InvalidateRect(state.browse_button, nullptr, TRUE);
}

void tick_busy_status(AppState& state) {
    if (!state.launch_in_progress) {
        return;
    }
    static constexpr const wchar_t* dots[] = {L".", L"..", L"...", L"...."};
    const auto suffix = dots[state.progress_tick % 4];
    ++state.progress_tick;
    set_launch_state(state, LaunchState::Busy, std::wstring(L"Preparing game") + suffix, L"Unpacking and preparing the client for launch.");
}

std::filesystem::path resolve_client_path_for_launch(const AppState& state) {
    const auto base_dir = module_dir();
    const auto bundled_client = std::filesystem::weakly_canonical(base_dir / L"MapleStory.exe");
    if (std::filesystem::exists(bundled_client)) {
        return bundled_client;
    }
    return state.selected_client_path;
}

BOOL CALLBACK enum_windows_for_pid(HWND hwnd, LPARAM lparam) {
    auto* search = reinterpret_cast<WindowSearchState*>(lparam);
    DWORD window_pid = 0;
    GetWindowThreadProcessId(hwnd, &window_pid);
    if (window_pid != search->pid) {
        return TRUE;
    }
    if (!IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr) {
        return TRUE;
    }
    search->found = hwnd;
    return FALSE;
}

HWND find_main_window(DWORD pid) {
    WindowSearchState search{};
    search.pid = pid;
    EnumWindows(enum_windows_for_pid, reinterpret_cast<LPARAM>(&search));
    return search.found;
}

bool should_skip_patching(const std::filesystem::path& client_path) {
    const auto name = client_path.filename().wstring();
    return _wcsicmp(name.c_str(), L"CleanLocalhostV48.exe") == 0;
}

bool is_packed_client(const std::filesystem::path& client_path) {
    const auto name = client_path.filename().wstring();
    return _wcsicmp(name.c_str(), L"MapleStory.exe") == 0;
}

void start_unpack_async(const AppState& state, const std::filesystem::path& client_path,
                        const std::filesystem::path& working_dir) {
    const HWND window = state.window;
    std::thread([window, client_path, working_dir]() {
        auto result = std::make_unique<LaunchAsyncResult>();
        std::wstring unpack_error;
        auto unpack_result = maple::launch_unpacked_client(client_path, working_dir, unpack_error);

        if (!unpack_result.success) {
            result->success = false;
            result->status_title = L"Launch failed";
            result->status_detail = L"The game could not be prepared for launch.";
            result->error_message = L"The game could not be prepared for launch. Please close MapleStory and try again.";
            PostMessageW(window, kMsgUnpackFinished, 0, reinterpret_cast<LPARAM>(result.release()));
            return;
        }

        bool saw_window = false;
        for (int attempt = 0; attempt < 30; ++attempt) {
            Sleep(500);
            DWORD exit_code = STILL_ACTIVE;
            if (GetExitCodeProcess(unpack_result.process, &exit_code) && exit_code != STILL_ACTIVE) {
                CloseHandle(unpack_result.process);
                result->success = false;
                result->status_title = L"Game closed early";
                result->status_detail = L"The client exited before the launcher could finish.";
                PostMessageW(window, kMsgUnpackFinished, 0, reinterpret_cast<LPARAM>(result.release()));
                return;
            }
            if (find_main_window(unpack_result.pid) != nullptr) {
                saw_window = true;
                break;
            }
        }

        CloseHandle(unpack_result.process);
        result->success = true;
        result->close_launcher = saw_window;
        result->status_title = L"Ready to play";
        result->status_detail = saw_window ? L"Game launched successfully." : L"Game launch complete.";
        PostMessageW(window, kMsgUnpackFinished, 0, reinterpret_cast<LPARAM>(result.release()));
    }).detach();
}

void fill_rounded_rect(HDC dc, const RECT& rect, COLORREF fill, COLORREF border, int radius) {
    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    auto old_brush = SelectObject(dc, brush);
    auto old_pen = SelectObject(dc, pen);
    RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);
    SelectObject(dc, old_brush);
    SelectObject(dc, old_pen);
    DeleteObject(brush);
    DeleteObject(pen);
}

void draw_status_badge(HDC dc, const AppState& state, int x, int y) {
    COLORREF fill = kReadyFill;
    COLORREF border = kReadyBorder;
    COLORREF text = kReadyText;
    if (state.launch_state == LaunchState::Busy) {
        fill = kBusyFill;
        border = kBusyBorder;
        text = kBusyText;
    } else if (state.launch_state == LaunchState::Error) {
        fill = kErrorFill;
        border = kErrorBorder;
        text = kErrorText;
    }

    const RECT badge{x, y, x + 182, y + 34};
    fill_rounded_rect(dc, badge, fill, border, 24);

    HBRUSH dot_brush = CreateSolidBrush(text);
    auto old_pen = SelectObject(dc, GetStockObject(NULL_PEN));
    auto old_brush = SelectObject(dc, dot_brush);
    Ellipse(dc, x + 14, y + 12, x + 22, y + 20);
    SelectObject(dc, old_brush);
    SelectObject(dc, old_pen);
    DeleteObject(dot_brush);

    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, text);
    RECT label{x + 30, y + 7, badge.right - 12, badge.bottom - 6};
    DrawTextW(dc, state.status_title.c_str(), -1, &label, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
}

void paint_window(HWND window, AppState& state) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(window, &ps);

    RECT client{};
    GetClientRect(window, &client);

    HBRUSH left_brush = CreateSolidBrush(kBgLeft);
    RECT left_panel{0, 0, kLeftPanelWidth, client.bottom};
    FillRect(dc, &left_panel, left_brush);
    DeleteObject(left_brush);

    HBRUSH right_brush = CreateSolidBrush(kBgRight);
    RECT right_panel{kLeftPanelWidth, 0, client.right, client.bottom};
    FillRect(dc, &right_panel, right_brush);
    DeleteObject(right_brush);

    HBRUSH accent_brush = CreateSolidBrush(kTopAccent);
    RECT accent{0, 0, client.right, 3};
    FillRect(dc, &accent, accent_brush);
    DeleteObject(accent_brush);

    HPEN split_pen = CreatePen(PS_SOLID, 1, kBgRightBorder);
    auto old_pen = SelectObject(dc, split_pen);
    MoveToEx(dc, kLeftPanelWidth, 0, nullptr);
    LineTo(dc, kLeftPanelWidth, client.bottom);
    SelectObject(dc, old_pen);
    DeleteObject(split_pen);

    HBRUSH motif_brush = CreateSolidBrush(RGB(15, 21, 48));
    auto old_pen_null = SelectObject(dc, GetStockObject(NULL_PEN));
    auto old_brush = SelectObject(dc, motif_brush);
    Ellipse(dc, -40, 322, 200, 438);
    Ellipse(dc, 120, 356, 392, 468);
    SelectObject(dc, old_brush);
    DeleteObject(motif_brush);

    HBRUSH building1 = CreateSolidBrush(RGB(26, 32, 80));
    old_brush = SelectObject(dc, building1);
    Rectangle(dc, 34, 220, 52, 300);
    Rectangle(dc, 26, 210, 60, 225);
    Rectangle(dc, 78, 240, 92, 300);
    Rectangle(dc, 72, 232, 98, 244);
    Rectangle(dc, 118, 232, 138, 300);
    Rectangle(dc, 112, 222, 144, 236);
    Rectangle(dc, 170, 212, 186, 300);
    Rectangle(dc, 163, 202, 193, 216);
    Rectangle(dc, 220, 242, 232, 300);
    Rectangle(dc, 214, 232, 238, 244);
    Rectangle(dc, 262, 220, 284, 300);
    Rectangle(dc, 254, 210, 292, 224);
    SelectObject(dc, old_brush);
    DeleteObject(building1);

    HBRUSH star_brush = CreateSolidBrush(RGB(240, 192, 96));
    old_brush = SelectObject(dc, star_brush);
    for (const POINT p : {POINT{48, 62}, POINT{120, 30}, POINT{180, 82}, POINT{242, 46}, POINT{274, 102}, POINT{88, 140}, POINT{212, 160}, POINT{28, 170}}) {
        Ellipse(dc, p.x, p.y, p.x + 4, p.y + 4);
    }
    SelectObject(dc, old_brush);
    DeleteObject(star_brush);

    auto icon = static_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1), IMAGE_ICON, 32, 32, 0));
    RECT icon_frame{kLeftPanelWidth + 30, 38, kLeftPanelWidth + 76, 84};
    fill_rounded_rect(dc, icon_frame, RGB(26, 30, 56), kTopAccent, 10);
    if (icon != nullptr) {
        DrawIconEx(dc, icon_frame.left + 7, icon_frame.top + 7, icon, 30, 30, 0, nullptr, DI_NORMAL);
        DestroyIcon(icon);
    }

    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, kTitleGold);
    auto old_font = SelectObject(dc, state.title_font);
    RECT title{kLeftPanelWidth + 92, 36, client.right - 40, 66};
    DrawTextW(dc, L"MapleStory", -1, &title, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    SetTextColor(dc, kMuted);
    SelectObject(dc, state.small_font);
    RECT launcher{kLeftPanelWidth + 94, 68, client.right - 40, 88};
    DrawTextW(dc, L"LAUNCHER", -1, &launcher, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    draw_status_badge(dc, state, kLeftPanelWidth + 32, 122);

    SetTextColor(dc, kSubtle);
    RECT detail{kLeftPanelWidth + 32, 164, client.right - 42, 198};
    DrawTextW(dc, state.status_detail.c_str(), -1, &detail, DT_LEFT | DT_WORDBREAK);

    HPEN hr_pen = CreatePen(PS_SOLID, 1, kBgRightBorder);
    old_pen = SelectObject(dc, hr_pen);
    MoveToEx(dc, kLeftPanelWidth + 32, 224, nullptr);
    LineTo(dc, client.right - 42, 224);
    SelectObject(dc, old_pen);
    DeleteObject(hr_pen);

    fill_rounded_rect(dc, RECT{kLeftPanelWidth + 32, 248, kLeftPanelWidth + 220, 308}, kPanelDark, kPanelBorder, 10);
    fill_rounded_rect(dc, RECT{kLeftPanelWidth + 236, 248, kLeftPanelWidth + 424, 308}, kPanelDark, kPanelBorder, 10);

    SetTextColor(dc, kSubtle);
    SelectObject(dc, state.small_font);
    RECT version_label{kLeftPanelWidth + 46, 260, kLeftPanelWidth + 206, 278};
    DrawTextW(dc, L"VERSION", -1, &version_label, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    RECT server_label{kLeftPanelWidth + 250, 260, kLeftPanelWidth + 410, 278};
    DrawTextW(dc, L"SERVER", -1, &server_label, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    SetTextColor(dc, kBody);
    SelectObject(dc, state.body_font);
    RECT version_value{kLeftPanelWidth + 46, 282, kLeftPanelWidth + 206, 298};
    DrawTextW(dc, state.version_label.c_str(), -1, &version_value, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    RECT server_value{kLeftPanelWidth + 250, 282, kLeftPanelWidth + 410, 298};
    DrawTextW(dc, state.server_label.c_str(), -1, &server_value, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    SelectObject(dc, state.body_font);
    SetTextColor(dc, RGB(154, 162, 208));
    RECT left_caption{40, client.bottom - 88, kLeftPanelWidth - 30, client.bottom - 38};
    DrawTextW(dc, L"A calm little launchpad for MapleStory.", -1, &left_caption, DT_LEFT | DT_WORDBREAK);

    SetTextColor(dc, kSubtle);
    SelectObject(dc, state.small_font);
    RECT footer{kLeftPanelWidth + 32, client.bottom - 70, client.right - 42, client.bottom - 30};
    DrawTextW(dc, state.footer_message.c_str(), -1, &footer, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    SelectObject(dc, old_font);
    SelectObject(dc, old_pen_null);
    EndPaint(window, &ps);
}

void draw_button(const DRAWITEMSTRUCT& draw, const wchar_t* text, bool primary, bool hot, HFONT font) {
    const bool pressed = (draw.itemState & ODS_SELECTED) != 0;
    const bool disabled = (draw.itemState & ODS_DISABLED) != 0;

    COLORREF fill = primary ? (hot ? kPrimaryHot : kPrimary) : RGB(0, 0, 0);
    COLORREF border = primary ? (hot ? kPrimaryHot : kPrimary) : (hot ? kSecondaryBorderHot : kSecondaryBorder);
    COLORREF text_color = primary ? RGB(255, 248, 232) : (hot ? kSecondaryTextHot : kSecondaryText);
    if (disabled) {
        fill = primary ? kDisabledButton : RGB(19, 22, 42);
        border = kSecondaryBorder;
        text_color = RGB(132, 138, 152);
    }

    RECT shadow = draw.rcItem;
    OffsetRect(&shadow, 0, 3);
    HBRUSH shadow_brush = CreateSolidBrush(RGB(8, 10, 20));
    FillRect(draw.hDC, &shadow, shadow_brush);
    DeleteObject(shadow_brush);

    RECT body = draw.rcItem;
    if (pressed) {
        OffsetRect(&body, 0, 1);
    }

    fill_rounded_rect(draw.hDC, body, fill, border, 16);

    SetBkMode(draw.hDC, TRANSPARENT);
    SetTextColor(draw.hDC, text_color);
    auto old_font = SelectObject(draw.hDC, font);
    RECT text_rect = body;
    DrawTextW(draw.hDC, text, -1, &text_rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(draw.hDC, old_font);
}

void browse_for_client(AppState& state) {
    wchar_t file_buffer[MAX_PATH]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = state.window;
    dialog.lpstrFile = file_buffer;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrFilter = L"Executable Files\0*.exe\0All Files\0*.*\0";
    dialog.lpstrTitle = L"Find MapleStory.exe";

    std::wstring initial_dir;
    if (!state.selected_client_path.empty()) {
        initial_dir = state.selected_client_path.parent_path().wstring();
        dialog.lpstrInitialDir = initial_dir.c_str();
    }

    dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileNameW(&dialog)) {
        state.selected_client_path = file_buffer;
        refresh_ready_status(state);
    } else if (CommDlgExtendedError() != 0) {
        show_error(state.window, L"The file browser could not be opened.");
    }
}

bool launch_client(AppState& state) {
    const auto base_dir = module_dir();
    const auto& config = maple::embedded_config();

    const auto resolve = [&](const std::filesystem::path& path_value) {
        if (path_value.is_absolute()) {
            return path_value;
        }
        return std::filesystem::weakly_canonical(base_dir / path_value);
    };

    if (state.launch_in_progress) {
        return false;
    }

    const auto client_path = resolve_client_path_for_launch(state);
    const auto working_dir = resolve(config.launcher.working_dir);

    if (client_path.empty() || !std::filesystem::exists(client_path)) {
        show_error(state.window, L"Game files were not found. Use Find Game Files to locate your MapleStory installation.");
        return false;
    }

    if (config.launcher.unpack_mode || is_packed_client(client_path)) {
        set_busy(state, true);
        state.progress_tick = 0;
        set_launch_state(state, LaunchState::Busy, L"Preparing game", L"Unpacking and patching the client for launch.");
        SetTimer(state.window, kProgressTimerId, 450, nullptr);
        start_unpack_async(state, client_path, working_dir);
        return true;
    }

    std::wstring command_line = quote_if_needed(client_path.wstring());
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process_info{};
    std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back(L'\0');

    const BOOL created = CreateProcessW(
        client_path.wstring().c_str(),
        mutable_command.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        working_dir.wstring().c_str(),
        &startup,
        &process_info);

    if (!created) {
        show_error(state.window, L"The game could not be started. Please run the launcher as administrator and try again.");
        set_launch_state(state, LaunchState::Error, L"Launch failed", L"The game could not be started.");
        return false;
    }

    if (!should_skip_patching(client_path)) {
        std::wstring patch_error;
        if (!maple::apply_process_patches(process_info.hProcess, &patch_error)) {
            TerminateProcess(process_info.hProcess, 1);
            CloseHandle(process_info.hThread);
            CloseHandle(process_info.hProcess);
            show_error(state.window, L"The game could not be prepared for launch. Please close MapleStory and try again.");
            set_launch_state(state, LaunchState::Error, L"Launch failed", L"The game could not be prepared for launch.");
            return false;
        }
    }

    ResumeThread(process_info.hThread);
    WaitForInputIdle(process_info.hProcess, 5000);

    DWORD exit_code = STILL_ACTIVE;
    if (GetExitCodeProcess(process_info.hProcess, &exit_code) && exit_code != STILL_ACTIVE) {
        CloseHandle(process_info.hThread);
        CloseHandle(process_info.hProcess);
        set_launch_state(state, LaunchState::Error, L"Game closed early", L"The client exited before launch finished.");
        return false;
    }

    for (int attempt = 0; attempt < 20; ++attempt) {
        Sleep(500);
        if (GetExitCodeProcess(process_info.hProcess, &exit_code) && exit_code != STILL_ACTIVE) {
            CloseHandle(process_info.hThread);
            CloseHandle(process_info.hProcess);
            set_launch_state(state, LaunchState::Error, L"Game closed early", L"The client exited before launch finished.");
            return false;
        }
        if (find_main_window(process_info.dwProcessId) != nullptr) {
            CloseHandle(process_info.hThread);
            CloseHandle(process_info.hProcess);
            DestroyWindow(state.window);
            return true;
        }
    }

    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    set_launch_state(state, LaunchState::Ready, L"Ready to play", L"Game launch complete.");
    return true;
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<AppState*>(GetWindowLongPtrW(window, GWLP_USERDATA));

    switch (message) {
    case WM_NCCREATE: {
        const auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
        return TRUE;
    }
    case WM_PAINT:
        if (state != nullptr) {
            paint_window(window, *state);
            return 0;
        }
        return DefWindowProcW(window, message, wparam, lparam);
    case WM_MOUSEMOVE:
        if (state != nullptr) {
            TRACKMOUSEEVENT track{};
            track.cbSize = sizeof(track);
            track.dwFlags = TME_LEAVE;
            track.hwndTrack = window;
            TrackMouseEvent(&track);

            POINT point{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
            RECT browse{};
            RECT launch{};
            GetWindowRect(state->browse_button, &browse);
            GetWindowRect(state->launch_button, &launch);
            MapWindowPoints(HWND_DESKTOP, window, reinterpret_cast<LPPOINT>(&browse), 2);
            MapWindowPoints(HWND_DESKTOP, window, reinterpret_cast<LPPOINT>(&launch), 2);

            const bool browse_hot = PtInRect(&browse, point);
            const bool launch_hot = PtInRect(&launch, point);
            if (browse_hot != state->browse_hot || launch_hot != state->launch_hot) {
                state->browse_hot = browse_hot;
                state->launch_hot = launch_hot;
                InvalidateRect(state->browse_button, nullptr, TRUE);
                InvalidateRect(state->launch_button, nullptr, TRUE);
            }
        }
        return 0;
    case WM_MOUSELEAVE:
        if (state != nullptr && (state->browse_hot || state->launch_hot)) {
            state->browse_hot = false;
            state->launch_hot = false;
            InvalidateRect(state->browse_button, nullptr, TRUE);
            InvalidateRect(state->launch_button, nullptr, TRUE);
        }
        return 0;
    case WM_DRAWITEM:
        if (state != nullptr) {
            const auto* draw = reinterpret_cast<DRAWITEMSTRUCT*>(lparam);
            if (draw->CtlID == kBrowseButtonId) {
                draw_button(*draw, L"Find Game Files", false, state->browse_hot, state->body_font);
                return TRUE;
            }
            if (draw->CtlID == kLaunchButtonId) {
                draw_button(*draw, L"PLAY", true, state->launch_hot, state->body_font);
                return TRUE;
            }
        }
        return FALSE;
    case WM_COMMAND:
        if (state == nullptr) {
            return 0;
        }
        switch (LOWORD(wparam)) {
        case kBrowseButtonId:
            browse_for_client(*state);
            return 0;
        case kLaunchButtonId:
            launch_client(*state);
            return 0;
        default:
            return 0;
        }
    case kMsgUnpackFinished:
        if (state != nullptr) {
            auto result = std::unique_ptr<LaunchAsyncResult>(reinterpret_cast<LaunchAsyncResult*>(lparam));
            KillTimer(state->window, kProgressTimerId);
            set_busy(*state, false);
            if (result->success) {
                set_launch_state(*state, LaunchState::Ready, result->status_title, result->status_detail);
            } else {
                set_launch_state(*state, LaunchState::Error, result->status_title, result->status_detail);
                if (!result->error_message.empty()) {
                    show_error(state->window, result->error_message);
                }
            }
            if (result->success && result->close_launcher) {
                DestroyWindow(state->window);
            }
            return 0;
        }
        return 0;
    case WM_TIMER:
        if (state != nullptr && wparam == kProgressTimerId) {
            tick_busy_status(*state);
            return 0;
        }
        return 0;
    case WM_DESTROY:
        if (state != nullptr) {
            if (state->title_font != nullptr) DeleteObject(state->title_font);
            if (state->launcher_font != nullptr) DeleteObject(state->launcher_font);
            if (state->body_font != nullptr) DeleteObject(state->body_font);
            if (state->small_font != nullptr) DeleteObject(state->small_font);
        }
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(window, message, wparam, lparam);
    }
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    const auto base_dir = module_dir();
    const auto client_path = base_dir / L"MapleStory.exe";

    const wchar_t class_name[] = L"MapleLauncherWindow";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = window_proc;
    wc.hInstance = instance;
    wc.lpszClassName = class_name;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, 32, 32, 0));
    wc.hIconSm = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, 0));

    if (!RegisterClassExW(&wc)) {
        return 1;
    }

    AppState state{};
    state.selected_client_path = client_path;
    state.title_font = create_font(22, FW_BOLD);
    state.launcher_font = create_font(12, FW_NORMAL);
    state.body_font = create_font(15, FW_BOLD);
    state.small_font = create_font(13, FW_NORMAL);
    refresh_ready_status(state);

    const HWND window = CreateWindowExW(
        0,
        class_name,
        L"MapleStory Launcher",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        kWindowWidth,
        kWindowHeight,
        nullptr,
        nullptr,
        instance,
        &state);

    if (window == nullptr) {
        return 1;
    }

    state.window = window;
    state.browse_button = CreateWindowExW(0, L"BUTTON", L"Find Game Files", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        404, 420, 440, 40, window, reinterpret_cast<HMENU>(kBrowseButtonId), instance, nullptr);
    state.launch_button = CreateWindowExW(0, L"BUTTON", L"PLAY", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        404, 370, 440, 48, window, reinterpret_cast<HMENU>(kLaunchButtonId), instance, nullptr);

    ShowWindow(window, show_command);
    UpdateWindow(window);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}
