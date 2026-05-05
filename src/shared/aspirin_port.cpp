#include "aspirin_port.h"

#include "injector.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>

namespace maple::aspirin {

namespace {

std::wstring hex32(std::uintptr_t value) {
    wchar_t buffer[32]{};
    swprintf(buffer, std::size(buffer), L"%08X", static_cast<unsigned int>(value));
    return buffer;
}

std::wstring ptr_text(const void* value) {
    wchar_t buffer[32]{};
    swprintf(buffer, std::size(buffer), sizeof(void*) == 8 ? L"0x%016llX" : L"0x%08X",
             static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(value)));
    return buffer;
}

std::wstring join_message(std::wstring_view a, std::wstring_view b) {
    std::wstring out;
    out.reserve(a.size() + b.size());
    out.append(a);
    out.append(b);
    return out;
}

using NtQueryInformationProcessFn = LONG (NTAPI*)(HANDLE, unsigned long, void*, unsigned long, unsigned long*);
using NtQueryInformationThreadFn = LONG (NTAPI*)(HANDLE, unsigned long, void*, unsigned long, unsigned long*);
constexpr unsigned long kProcessBasicInformationClass = 0;
constexpr unsigned long kThreadBasicInformationClass = 0;

struct ProcessBasicInformationLocal {
    ULONG exit_status;
    void* peb_base_address;
    ULONG_PTR affinity_mask;
    LONG base_priority;
    ULONG_PTR unique_process_id;
    ULONG_PTR inherited_from_unique_process_id;
};

struct ThreadBasicInformationLocal {
    LONG exit_status;
    void* teb_base_address;
    struct {
        void* unique_process;
        void* unique_thread;
    } client_id;
    ULONG_PTR affinity_mask;
    LONG priority;
    LONG base_priority;
};

NtQueryInformationProcessFn nt_query_information_process() {
    static auto fn = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    return fn;
}

NtQueryInformationThreadFn nt_query_information_thread() {
    static auto fn = reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    return fn;
}

std::optional<std::uint8_t> parse_hex_byte(std::string_view text) {
    if (text.size() != 2 || text[0] == '?') {
        return std::nullopt;
    }

    std::uint32_t value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value > 0xFF) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(value);
}

std::vector<std::string_view> split_pattern(std::string_view pattern) {
    std::vector<std::string_view> parts;
    for (std::size_t i = 0; i + 1 < pattern.size(); i += 2) {
        parts.push_back(pattern.substr(i, 2));
    }
    return parts;
}

Breakpoint* match_breakpoint(Breakpoint& a, Breakpoint& b, Breakpoint& c, Breakpoint& d, void* address) {
    if (reinterpret_cast<void*>(a.address) == address) return &a;
    if (reinterpret_cast<void*>(b.address) == address) return &b;
    if (reinterpret_cast<void*>(c.address) == address) return &c;
    if (reinterpret_cast<void*>(d.address) == address) return &d;
    return nullptr;
}

std::wstring exception_code_text(DWORD code, void* address) {
    wchar_t buffer[64]{};
    swprintf(buffer, std::size(buffer), L"Code 0x%08X at %p", code, address);
    return buffer;
}

void log_call(const LogFn& logger, LogMsgType type, const std::wstring& message) {
    if (logger) {
        logger(type, message);
    }
}

void decode_emul_entry(std::vector<std::uint8_t>& entry, std::uint32_t obfus_key) {
    std::array<std::uint8_t, 16> key{};
    std::memcpy(key.data(), &obfus_key, sizeof(obfus_key));
    for (std::size_t i = 4; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i + 1);
    }
    for (std::size_t i = 0; i < entry.size(); ++i) {
        entry[i] ^= key[i % key.size()];
    }
}

}  // namespace

std::uint8_t AipEntryOffsets::get_byte(const void* entry, AipHandler type) const {
    return *(reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(type)]);
}

std::uint32_t PolyEntryOffsets::get_entry_offset(const void* entry) const {
    std::uint32_t value = 0;
    std::memcpy(&value, reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(PolyHandler::Offset)], sizeof(value));
    return value + key;
}

std::uint8_t PolyEntryOffsets::get_flow_type(const void* entry) const {
    return *(reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(PolyHandler::FlowType)]);
}

std::uint32_t PolyEntryOffsets::get_target(const void* entry) const {
    std::uint32_t value = 0;
    std::memcpy(&value, reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(PolyHandler::Target)], sizeof(value));
    return value + key;
}

std::uint32_t PolyEntryOffsets::get_target2(const void* entry) const {
    std::uint32_t value = 0;
    std::memcpy(&value, reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(PolyHandler::Target2)], sizeof(value));
    return value + key;
}

std::uint8_t PolyEntryOffsets::get_branch_type(const void* entry) const {
    return *(reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(PolyHandler::BranchType)]);
}

std::uint8_t PolyEntryOffsets::get_cmp_reg1(const void* entry) const {
    return *(reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(PolyHandler::CmpReg1)]);
}

std::uint8_t PolyEntryOffsets::get_cmp_reg2(const void* entry) const {
    return *(reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(PolyHandler::CmpReg2)]);
}

std::int32_t PolyEntryOffsets::get_cmp_displ1(const void* entry) const {
    std::int32_t value = 0;
    std::memcpy(&value, reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(PolyHandler::CmpDispl1)], sizeof(value));
    return value;
}

std::int32_t PolyEntryOffsets::get_cmp_displ2(const void* entry) const {
    std::int32_t value = 0;
    std::memcpy(&value, reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(PolyHandler::CmpDispl2)], sizeof(value));
    return value;
}

std::uint8_t PolyEntryOffsets::get_cmp_modifier(const void* entry) const {
    return *(reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(PolyHandler::CmpModifier)]);
}

RolyPoly::RolyPoly(HANDLE process, HANDLE trace_thread, std::uintptr_t address, MemoryRegion as_region, LogFn log,
                   const std::function<bool(std::uintptr_t, void*, std::size_t)>& rpm,
                   const std::function<bool(std::uintptr_t, const void*, std::size_t)>& wpm)
    : process_(process), trace_thread_(trace_thread), address_(address), as_region_(as_region), logger_(log), rpm_(rpm), wpm_(wpm) {
    state_signal_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

DWORD RolyPoly::on_access_violation(HANDLE thread, const EXCEPTION_RECORD& record) {
    log_call(logger_, LogMsgType::Info, L"[Poly] AV at " + hex32(reinterpret_cast<std::uintptr_t>(record.ExceptionAddress)));
    SuspendThread(thread);

    constexpr std::uintptr_t bait_ret_offset = 0xF00;
    if (state_ == State::TraceObfusEnter) {
        if (!as_region_.contains(reinterpret_cast<std::uintptr_t>(record.ExceptionAddress))) {
            throw std::runtime_error("Poly AV at unexpected address");
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(thread, &context)) {
            throw std::runtime_error("GetThreadContext failed in poly trace enter");
        }
        std::uint32_t obj_ptr = 0;
        if (!rpm_(context.Esp + 4, &obj_ptr, sizeof(obj_ptr))) {
            throw std::runtime_error("Failed to read poly context pointer");
        }
        log_call(logger_, LogMsgType::Info, L"Ctx at " + hex32(obj_ptr));
        if (!rpm_(obj_ptr, &poly_context_, sizeof(poly_context_))) {
            throw std::runtime_error("Failed to read poly context");
        }
        if (poly_context_.entry_access_funcs[0] < 0x10000) {
            throw std::runtime_error("Poly struct layout sanity check failed");
        }
        for (std::size_t i = 1; i < 10; ++i) {
            if (std::llabs(static_cast<long long>(poly_context_.entry_access_funcs[i]) - static_cast<long long>(poly_context_.entry_access_funcs[0])) > 0x10000) {
                throw std::runtime_error("Poly struct sanity check failed");
            }
        }
        SetEvent(state_signal_);
    } else if (state_ == State::TraceAccessFunc) {
        if (reinterpret_cast<std::uintptr_t>(record.ExceptionAddress) == reinterpret_cast<std::uintptr_t>(bait_page_) + bait_ret_offset) {
            throw std::runtime_error("Poly accessor returned unexpectedly");
        }
        if ((record.ExceptionInformation[1] & 0xFFFFF000u) != reinterpret_cast<std::uintptr_t>(bait_page_)) {
            throw std::runtime_error("Poly access trace AV not due to bait");
        }
        bait_access_offset_ = static_cast<int>(record.ExceptionInformation[1] - reinterpret_cast<std::uintptr_t>(bait_page_));
        SetEvent(state_signal_);
    }
    return DBG_CONTINUE;
}

void RolyPoly::start_trace(std::uintptr_t address) {
    log_call(logger_, LogMsgType::Info, L"Trace: " + hex32(address));
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(trace_thread_, &context)) {
        throw std::runtime_error("GetThreadContext failed in poly start_trace");
    }
    context.Eip = address;
    if (!SetThreadContext(trace_thread_, &context)) {
        throw std::runtime_error("SetThreadContext failed in poly start_trace");
    }
    ResumeThread(trace_thread_);
}

void RolyPoly::trace_access_funcs() {
    if (bait_page_ == nullptr) {
        bait_page_ = VirtualAllocEx(process_, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    }
    state_ = State::TraceAccessFunc;
    constexpr std::uintptr_t bait_ret_offset = 0xF00;
    for (std::size_t i = 0; i < 10; ++i) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (!GetThreadContext(trace_thread_, &context)) {
            throw std::runtime_error("GetThreadContext failed in poly trace_access_funcs");
        }
        context.Eax = reinterpret_cast<std::uintptr_t>(bait_page_);
        context.Eip = poly_context_.entry_access_funcs[poly_context_.permut[i]];
        const auto ret = reinterpret_cast<std::uintptr_t>(bait_page_) + bait_ret_offset;
        if (!wpm_(context.Esp, &ret, sizeof(ret))) {
            throw std::runtime_error("Failed writing poly bait return");
        }
        if (!SetThreadContext(trace_thread_, &context)) {
            throw std::runtime_error("SetThreadContext failed in poly trace_access_funcs");
        }
        ResumeThread(trace_thread_);
        if (WaitForSingleObject(state_signal_, 10000) == WAIT_TIMEOUT) {
            throw std::runtime_error("Poly trace timed out");
        }
        entry_offsets_.offsets[i] = bait_access_offset_;
    }
}

void RolyPoly::fetch_entries() {
    entry_offsets_.key = poly_context_.obfus_key;
    std::vector<std::uint8_t> data(poly_context_.entry_count * poly_context_.entry_size);
    if (!rpm_(poly_context_.entries_pointer, data.data(), data.size())) {
        throw std::runtime_error("Reading poly entry data failed");
    }
    auto* cursor = data.data();
    for (std::uint32_t i = 0; i < poly_context_.entry_count; ++i) {
        std::vector<std::uint8_t> entry(poly_context_.entry_size);
        std::memcpy(entry.data(), cursor, poly_context_.entry_size);
        entries_[entry_offsets_.get_entry_offset(entry.data())] = entry;
        cursor += poly_context_.entry_size;
    }
}

std::uint32_t AipEntryOffsets::get_dword(const void* entry, AipHandler type) const {
    std::uint32_t value = 0;
    std::memcpy(&value, reinterpret_cast<const std::uint8_t*>(entry) + offsets[static_cast<std::size_t>(type)], sizeof(value));
    return value;
}

std::uint32_t AipEntryOffsets::get_dword_deobfus(const void* entry, AipHandler type) const {
    return get_dword(entry, type) + key;
}

Aip::Aip(HANDLE process, HANDLE trace_thread, std::uintptr_t context_addr, LogFn log,
         const std::function<bool(std::uintptr_t, void*, std::size_t)>& rpm,
         const std::function<bool(std::uintptr_t, const void*, std::size_t)>& wpm)
    : process_(process), trace_thread_(trace_thread), logger_(log), rpm_(rpm), wpm_(wpm) {
    if (!rpm_(context_addr, &context_, sizeof(context_))) {
        throw std::runtime_error("Reading AIP context failed");
    }
    bait_page_ = VirtualAllocEx(process_, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    if (bait_page_ == nullptr) {
        throw std::runtime_error("AIP bait page allocation failed");
    }
    trace_signal_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

DWORD Aip::on_access_violation(HANDLE thread, const EXCEPTION_RECORD& record) {
    log_call(logger_, LogMsgType::Info, L"[AIP] AV at " + hex32(reinterpret_cast<std::uintptr_t>(record.ExceptionAddress)));
    SuspendThread(thread);
    if (state_ == State::Tracing) {
        constexpr std::uintptr_t bait_ret_offset = 0xF00;
        if (reinterpret_cast<std::uintptr_t>(record.ExceptionAddress) == reinterpret_cast<std::uintptr_t>(bait_page_) + bait_ret_offset) {
            throw std::runtime_error("AIP accessor returned unexpectedly");
        }
        if ((record.ExceptionInformation[1] & 0xFFFFF000u) != reinterpret_cast<std::uintptr_t>(bait_page_)) {
            throw std::runtime_error("AIP trace AV not due to bait page");
        }
        bait_access_offset_ = static_cast<int>(record.ExceptionInformation[1] - reinterpret_cast<std::uintptr_t>(bait_page_));
        SetEvent(trace_signal_);
    }
    return DBG_CONTINUE;
}

void Aip::process_import(std::uintptr_t ref_addr, bool& ref_is_jmp, void*& proc_addr, bool proc_addr_is_obfus) {
    if (state_ == State::Init) {
        trace_access_funcs();
        fetch_entries();
        state_ = State::Ready;
    }

    const auto it = patches_.find(ref_addr);
    if (it == patches_.end()) {
        throw std::runtime_error("AIP entry not found");
    }

    ref_is_jmp = it->second.is_jmp;
    if (!it->second.emul_data.empty()) {
        restore_emulated_code(ref_addr + 6, it->second.emul_data);
    }
    if (proc_addr_is_obfus) {
        proc_addr = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(proc_addr) + context_.obfus_key);
    }
}

void Aip::trace_access_funcs() {
    state_ = State::Tracing;
    constexpr std::uintptr_t bait_ret_offset = 0xF00;
    for (std::size_t i = 0; i < 10; ++i) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (!GetThreadContext(trace_thread_, &context)) {
            throw std::runtime_error("GetThreadContext failed in AIP trace_access_funcs");
        }
        context.Eax = reinterpret_cast<std::uintptr_t>(bait_page_);
        context.Eip = context_.entry_access_funcs[context_.permut[i]].proc;
        const auto ret = reinterpret_cast<std::uintptr_t>(bait_page_) + bait_ret_offset;
        if (!wpm_(context.Esp, &ret, sizeof(ret))) {
            throw std::runtime_error("Failed writing AIP bait return address");
        }
        if (!SetThreadContext(trace_thread_, &context)) {
            throw std::runtime_error("SetThreadContext failed in AIP trace_access_funcs");
        }
        ResumeThread(trace_thread_);
        if (WaitForSingleObject(trace_signal_, 10000) == WAIT_TIMEOUT) {
            throw std::runtime_error("AIP trace timed out");
        }
        entry_offsets_.offsets[i] = bait_access_offset_;
    }
    entry_offsets_.key = context_.obfus_key;
}

void Aip::fetch_entries() {
    if (context_.patches_count == 0) {
        throw std::runtime_error("No AIP patches");
    }
    std::vector<std::uint8_t> data(context_.patches_count * context_.entry_size);
    if (!rpm_(context_.patches, data.data(), data.size())) {
        throw std::runtime_error("Error reading AIP patches");
    }

    auto* cursor = data.data();
    for (std::uint32_t i = 0; i < context_.patches_count; ++i) {
        AipPatch patch;
        patch.is_jmp = entry_offsets_.get_byte(cursor, AipHandler::RefType) == context_.opcode_permut[static_cast<int>(AipOpcode::Jmp)];
        const auto emul_id = entry_offsets_.get_dword_deobfus(cursor, AipHandler::EmulId);
        if (emul_id != 0xFFFFFFFFu) {
            patch.emul_data.resize(context_.entry_size);
            if (!rpm_(context_.emuls + emul_id * context_.entry_size, patch.emul_data.data(), patch.emul_data.size())) {
                throw std::runtime_error("Error reading AIP emul data");
            }
            decode_emul_entry(patch.emul_data, context_.obfus_key);
        }
        patches_[entry_offsets_.get_dword_deobfus(cursor, AipHandler::Offset) + context_.text_base] = patch;
        cursor += context_.entry_size;
    }
}

void Aip::restore_emulated_code(std::uintptr_t to_address, const std::vector<std::uint8_t>& emul_entry) {
    const auto coded_opc = entry_offsets_.get_byte(emul_entry.data(), AipHandler::EhOpcode);
    const auto avail_space = static_cast<int>(entry_offsets_.get_dword_deobfus(emul_entry.data(), AipHandler::EhPatchSize)) - 6;
    std::vector<std::uint8_t> code;
    for (int opc = 0; opc <= static_cast<int>(AipOpcode::MovRDR); ++opc) {
        if (coded_opc != context_.opcode_permut[opc]) {
            continue;
        }
        switch (static_cast<AipOpcode>(opc)) {
        case AipOpcode::CmpJcc: code = recover_cmp_jcc(emul_entry, to_address); break;
        case AipOpcode::Cmp: code = recover_cmp(emul_entry); break;
        case AipOpcode::Add: code = recover_add(emul_entry); break;
        case AipOpcode::MovRR: code = recover_mov_rr(emul_entry); break;
        case AipOpcode::MovMR: code = recover_mov_mr(emul_entry, avail_space); break;
        default: throw std::runtime_error("[AIP] Unimplemented opcode type");
        }
        break;
    }
    if (!code.empty()) {
        if (avail_space != static_cast<int>(code.size())) {
            throw std::runtime_error("Recovered AIP code size mismatch");
        }
        if (!wpm_(to_address, code.data(), code.size())) {
            throw std::runtime_error("Failed writing recovered AIP code");
        }
    }
}

std::vector<std::uint8_t> Aip::recover_cmp(const std::vector<std::uint8_t>& e) {
    const auto r1 = entry_offsets_.get_byte(e.data(), AipHandler::EhReg1);
    const auto r2 = entry_offsets_.get_byte(e.data(), AipHandler::EhReg2);
    auto d1 = entry_offsets_.get_dword(e.data(), AipHandler::EhImm1);
    auto d2 = entry_offsets_.get_dword(e.data(), AipHandler::EhImm2);
    const auto addr_mode = static_cast<std::uint8_t>(entry_offsets_.get_byte(e.data(), AipHandler::EhAddressingMode) - 2);
    if ((r1 == 4 || r1 == 5) || (r2 == 4 || r2 == 5)) throw std::runtime_error("Unsupported AIP reg encoding");
    if (r1 > 7) throw std::runtime_error("Invalid AIP reg byte");
    if (d1 != 0 && addr_mode == 0) d1 += context_.image_base;
    if (d2 != 0 && addr_mode == 1) d2 += context_.image_base;

    std::vector<std::uint8_t> result;
    if (r2 <= 7) {
        if (d1 != 0 || d2 != 0) throw std::runtime_error("AIP cmp displacement unsupported");
        switch (addr_mode) {
        case 0: result = {0x39, static_cast<std::uint8_t>((r2 << 3) | r1)}; break;
        case 1: result = {0x3B, static_cast<std::uint8_t>((r1 << 3) | r2)}; break;
        case 2: result = {0x38, static_cast<std::uint8_t>((r2 << 3) | r1)}; break;
        case 3: result = {0x3A, static_cast<std::uint8_t>((r1 << 3) | r2)}; break;
        case 4: result = {0x3B, static_cast<std::uint8_t>(0xC0 | (r1 << 3) | r2)}; break;
        default: throw std::runtime_error("Invalid AIP cmp modifier");
        }
    } else {
        if (d1 != 0) throw std::runtime_error("AIP cmp displacement1 unsupported");
        switch (entry_offsets_.get_byte(e.data(), AipHandler::EhAddressingMode)) {
        case 0: result = d2 < 0x80 ? std::vector<std::uint8_t>{0x83, static_cast<std::uint8_t>(0x38 + r1), static_cast<std::uint8_t>(d2)} : std::vector<std::uint8_t>{0x81, static_cast<std::uint8_t>(0x38 + r1)}; break;
        case 2: result = {0x80, static_cast<std::uint8_t>(0x38 + r1), static_cast<std::uint8_t>(d2)}; break;
        case 4: result = d2 < 0x80 ? std::vector<std::uint8_t>{0x83, static_cast<std::uint8_t>(0xF8 + r1), static_cast<std::uint8_t>(d2)} : std::vector<std::uint8_t>{0x81, static_cast<std::uint8_t>(0xF8 + r1)}; break;
        default: throw std::runtime_error("Unsupported AIP cmp modifier");
        }
        if (result.size() == 2) {
            result.resize(6);
            std::memcpy(result.data() + 2, &d2, sizeof(d2));
        }
    }
    return result;
}

std::vector<std::uint8_t> Aip::recover_cmp_jcc(const std::vector<std::uint8_t>& e, std::uintptr_t to_address) {
    auto result = recover_cmp(e);
    const auto target = entry_offsets_.get_dword_deobfus(e.data(), AipHandler::EhAddrRva) + context_.image_base;
    const auto delta = static_cast<int>(target - (to_address + result.size()));
    if (delta < -0x7E || delta > 0x81) {
        const auto branch = entry_offsets_.get_byte(e.data(), AipHandler::EhBranchType);
        const auto old = result.size();
        result.resize(old + 6);
        result[old] = 0x0F;
        result[old + 1] = static_cast<std::uint8_t>(0x80 + branch);
        const auto rel = delta - 6;
        std::memcpy(result.data() + old + 2, &rel, sizeof(rel));
    } else {
        const auto old = result.size();
        result.resize(old + 2);
        result[old] = static_cast<std::uint8_t>(0x70 + entry_offsets_.get_byte(e.data(), AipHandler::EhBranchType));
        result[old + 1] = static_cast<std::uint8_t>(delta - 2);
    }
    return result;
}

std::vector<std::uint8_t> Aip::recover_add(const std::vector<std::uint8_t>& e) {
    const auto reg = entry_offsets_.get_byte(e.data(), AipHandler::EhReg1);
    const auto imm = entry_offsets_.get_dword(e.data(), AipHandler::EhImm1);
    const auto byte_imm = (imm < 0x80) || (imm >= 0xFFFFFF80u);
    std::vector<std::uint8_t> result;
    if (reg == 0 && !byte_imm) result = {0x05, 0, 0, 0, 0};
    else if (byte_imm) return {0x83, static_cast<std::uint8_t>(0xC0 | reg), static_cast<std::uint8_t>(imm)};
    else result = {0x81, static_cast<std::uint8_t>(0xC0 | reg), 0, 0, 0, 0};
    std::memcpy(result.data() + result.size() - 4, &imm, sizeof(imm));
    return result;
}

std::vector<std::uint8_t> Aip::recover_mov_rr(const std::vector<std::uint8_t>& e) {
    const auto r1 = entry_offsets_.get_byte(e.data(), AipHandler::EhReg1);
    const auto r2 = entry_offsets_.get_byte(e.data(), AipHandler::EhReg2);
    return {0x8B, static_cast<std::uint8_t>(0xC0 | (r1 << 3) | r2)};
}

std::vector<std::uint8_t> Aip::recover_mov_mr(const std::vector<std::uint8_t>& e, int space) {
    const auto reg = entry_offsets_.get_byte(e.data(), AipHandler::EhReg1);
    const auto displ = entry_offsets_.get_dword(e.data(), AipHandler::EhImm1) + context_.image_base;
    std::vector<std::uint8_t> result = space >= 7 ? std::vector<std::uint8_t>{0x89, static_cast<std::uint8_t>(0x04 | (reg << 3)), 0x25, 0, 0, 0, 0}
                                               : std::vector<std::uint8_t>{0x89, static_cast<std::uint8_t>(0x05 | (reg << 3)), 0, 0, 0, 0};
    std::memcpy(result.data() + result.size() - 4, &displ, sizeof(displ));
    return result;
}

bool MemoryRegion::contains(std::uintptr_t candidate) const {
    return candidate >= address && candidate < (address + size);
}

void Breakpoint::change(std::uintptr_t new_address, HwBreakpointType new_type) {
    address = new_address;
    type = new_type;
    disabled = false;
}

bool Breakpoint::is_set() const {
    return !disabled && address > 0;
}

std::optional<std::uint32_t> find_dynamic_pattern(std::string_view pattern, const std::uint8_t* buffer, std::uint32_t size) {
    const auto parts = split_pattern(pattern);
    if (parts.empty() || size < parts.size()) {
        return std::nullopt;
    }

    std::vector<std::optional<std::uint8_t>> bytes;
    bytes.reserve(parts.size());
    for (const auto part : parts) {
        bytes.push_back(parse_hex_byte(part));
    }

    for (std::uint32_t i = 0; i <= size - static_cast<std::uint32_t>(bytes.size()); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < bytes.size(); ++j) {
            if (bytes[j] && buffer[i + j] != *bytes[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return i;
        }
    }

    return std::nullopt;
}

std::optional<std::uint32_t> find_static_pattern(std::string_view pattern, const std::uint8_t* buffer, std::uint32_t size) {
    const auto parts = split_pattern(pattern);
    if (parts.empty() || size < parts.size()) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> bytes;
    bytes.reserve(parts.size());
    for (const auto part : parts) {
        const auto parsed = parse_hex_byte(part);
        if (!parsed) {
            return std::nullopt;
        }
        bytes.push_back(*parsed);
    }

    for (std::uint32_t i = 0; i <= size - static_cast<std::uint32_t>(bytes.size()); ++i) {
        if (memcmp(buffer + i, bytes.data(), bytes.size()) == 0) {
            return i;
        }
    }
    return std::nullopt;
}

DebuggerCore::DebuggerCore(std::filesystem::path executable, std::wstring parameters, LogFn log)
    : executable_(std::move(executable)), parameters_(std::move(parameters)), logger_(std::move(log)) {}

DebuggerCore::DebuggerCore(DWORD attach_pid, LogFn log)
    : attach_pid_(attach_pid), logger_(std::move(log)) {}

DebuggerCore::~DebuggerCore() {
    clear_soft_breakpoints();
    for (const auto& [_, handle] : threads_) {
        if (handle != nullptr) {
            CloseHandle(handle);
        }
    }
    if (process_info_.hThread != nullptr) {
        CloseHandle(process_info_.hThread);
    }
    if (process_info_.hProcess != nullptr) {
        CloseHandle(process_info_.hProcess);
    }
}

bool DebuggerCore::run() {
    log(LogMsgType::Info, L"DebuggerCore::run starting");
    if (!pe_execute()) {
        log(LogMsgType::Fatal, join_message(L"Creating the process failed: ", last_error_message(GetLastError())));
        return false;
    }

    log(LogMsgType::Info, L"DebuggerCore::run created/attached process, entering debug loop");

    try {
        DWORD status = DBG_CONTINUE;
        while (true) {
            if (detach_pending_ && detach_event_ != nullptr && WaitForSingleObject(detach_event_, 0) == WAIT_OBJECT_0) {
                log(LogMsgType::Good, L"Detach requested, stopping debugger");
                hide_thread_end_ = true;
                DebugActiveProcessStop(process_info_.dwProcessId);
                log(LogMsgType::Good, L"Debugger detached. Process continues running.");
                return true;
            }

            DEBUG_EVENT event{};
            log(LogMsgType::Info, L"Waiting for next debug event...");
            const DWORD wait_timeout = detach_pending_ ? 50 : INFINITE;
            if (!WaitForDebugEvent(&event, wait_timeout)) {
                if (detach_pending_ && GetLastError() == ERROR_SEM_TIMEOUT) {
                    continue;
                }
                log(LogMsgType::Fatal, join_message(L"OS Error: ", last_error_message(GetLastError())));
                return false;
            }

            log(LogMsgType::Info, L"Debug event received: code=" + std::to_wstring(event.dwDebugEventCode) +
                                     L", pid=" + std::to_wstring(event.dwProcessId) + L", tid=" + std::to_wstring(event.dwThreadId));

            switch (event.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT: {
                status = DBG_EXCEPTION_NOT_HANDLED;
                const auto& record = event.u.Exception.ExceptionRecord;
                switch (record.ExceptionCode) {
                case EXCEPTION_ACCESS_VIOLATION:
                    status = on_access_violation(threads_[event.dwThreadId], record);
                    break;
                case EXCEPTION_BREAKPOINT:
                    if (soft_breakpoints_.contains(record.ExceptionAddress)) {
                        status = on_software_breakpoint_event(event);
                    } else {
                        on_unsolicited_software_breakpoint(threads_[event.dwThreadId], record.ExceptionAddress);
                    }
                    break;
                case EXCEPTION_SINGLE_STEP:
                    status = on_hardware_breakpoint_event(event);
                    break;
                default:
                    if (event.u.Exception.dwFirstChance == 0) {
                        log(LogMsgType::Fatal, L"dwFirstChance = 0");
                        return false;
                    }
                    log(LogMsgType::Info, exception_code_text(record.ExceptionCode, record.ExceptionAddress));
                    status = DBG_EXCEPTION_NOT_HANDLED;
                    break;
                }
                break;
            }
            case CREATE_THREAD_DEBUG_EVENT:
                status = on_create_thread_debug_event(event);
                break;
            case CREATE_PROCESS_DEBUG_EVENT:
                status = on_create_process_debug_event(event);
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                status = on_exit_thread_debug_event(event);
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                status = on_exit_process_debug_event(event);
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status);
                return true;
            case LOAD_DLL_DEBUG_EVENT:
                status = on_load_dll_debug_event(event);
                break;
            case UNLOAD_DLL_DEBUG_EVENT:
                status = on_unload_dll_debug_event(event);
                break;
            case OUTPUT_DEBUG_STRING_EVENT:
                status = on_output_debug_string_event(event);
                break;
            case RIP_EVENT:
                status = on_rip_event(event);
                break;
            default:
                status = DBG_CONTINUE;
                break;
            }

            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status);
        }
    } catch (const std::exception& ex) {
        log(LogMsgType::Fatal, join_message(L"Critical error in debug loop: ", std::wstring(ex.what(), ex.what() + strlen(ex.what()))));
        return false;
    }
}

DWORD DebuggerCore::process_id() const { return process_info_.dwProcessId; }
HANDLE DebuggerCore::process_handle() const { return process_info_.hProcess; }
std::uintptr_t DebuggerCore::image_base() const { return image_base_; }
void DebuggerCore::set_live_mode(bool enabled) { live_mode_ = enabled; }
void DebuggerCore::set_ready_event(HANDLE event_handle) { ready_event_ = event_handle; }
void DebuggerCore::set_detach_event(HANDLE event_handle) { detach_event_ = event_handle; }
void DebuggerCore::set_pid_file_path(std::filesystem::path path) { pid_file_path_ = std::move(path); }

DWORD DebuggerCore::on_access_violation(HANDLE, const EXCEPTION_RECORD& record) {
    log(LogMsgType::Info, join_message(L"Access violation at ", ptr_text(record.ExceptionAddress)));
    return DBG_EXCEPTION_NOT_HANDLED;
}

void DebuggerCore::on_unsolicited_software_breakpoint(HANDLE, void* breakpoint_address) {
    log(LogMsgType::Info, join_message(L"Unsolicited int3 (", join_message(ptr_text(breakpoint_address), L")")));
}

DWORD DebuggerCore::on_singlestep(std::uintptr_t) {
    enable_breakpoints();
    return DBG_CONTINUE;
}

void DebuggerCore::fetch_memory_regions() {
    memory_regions_.clear();
    std::uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    while (VirtualQueryEx(process_info_.hProcess, reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) != 0 && address + mbi.RegionSize > address) {
        memory_regions_.push_back(MemoryRegion{reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), static_cast<std::uint32_t>(mbi.RegionSize)});
        address += mbi.RegionSize;
    }
}

bool DebuggerCore::read_process_memory(std::uintptr_t address, void* buffer, std::size_t size) const {
    SIZE_T read = 0;
    return ReadProcessMemory(process_info_.hProcess, reinterpret_cast<void*>(address), buffer, size, &read) && read == size;
}

bool DebuggerCore::write_process_memory(std::uintptr_t address, const void* buffer, std::size_t size) const {
    SIZE_T written = 0;
    return WriteProcessMemory(process_info_.hProcess, reinterpret_cast<void*>(address), buffer, size, &written) && written == size;
}

void DebuggerCore::set_breakpoint(std::uintptr_t address, HwBreakpointType type) {
    Breakpoint* slot = nullptr;
    if (hw1_.address == 0) slot = &hw1_;
    else if (hw2_.address == 0) slot = &hw2_;
    else if (hw3_.address == 0) slot = &hw3_;
    else if (hw4_.address == 0) slot = &hw4_;
    else throw std::runtime_error("All breakpoints in use");

    slot->change(address, type);
    for (const auto& [_, thread] : threads_) {
        update_debug_registers(thread);
    }
}

bool DebuggerCore::disable_breakpoint(void* address) {
    if (auto* bp = match_breakpoint(hw1_, hw2_, hw3_, hw4_, address)) {
        bp->disabled = true;
        return true;
    }
    return false;
}

void DebuggerCore::enable_breakpoints() {
    if (!(hw1_.disabled || hw2_.disabled || hw3_.disabled || hw4_.disabled)) {
        return;
    }
    hw1_.disabled = hw2_.disabled = hw3_.disabled = hw4_.disabled = false;
    for (const auto& [_, thread] : threads_) {
        update_debug_registers(thread);
    }
}

void DebuggerCore::reset_breakpoint(void* address) {
    if (auto* bp = match_breakpoint(hw1_, hw2_, hw3_, hw4_, address)) {
        bp->address = 0;
        bp->disabled = false;
    }
    for (const auto& [_, thread] : threads_) {
        update_debug_registers(thread);
    }
}

void DebuggerCore::apply_debug_registers(CONTEXT& context) const {
    DWORD mask = 0;
    context.Dr0 = hw1_.address;
    if (hw1_.is_set()) mask = 1;
    context.Dr1 = hw2_.address;
    if (hw2_.is_set()) mask |= (1u << 2);
    context.Dr2 = hw3_.address;
    if (hw3_.is_set()) mask |= (1u << 4);
    context.Dr3 = hw4_.address;
    if (hw4_.is_set()) mask |= (1u << 6);
    context.Dr6 &= 0xFFFFBFFFu;
    context.Dr7 = mask |
                  (static_cast<DWORD>(hw1_.type) << 16) |
                  (static_cast<DWORD>(hw2_.type) << 20) |
                  (static_cast<DWORD>(hw3_.type) << 24) |
                  (static_cast<DWORD>(hw4_.type) << 28);
}

void DebuggerCore::update_debug_registers(HANDLE thread) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &context)) {
        log(LogMsgType::Fatal, L"GetThreadContext failed");
        return;
    }
    apply_debug_registers(context);
    SetThreadContext(thread, &context);
}

void DebuggerCore::set_soft_breakpoint(void* address) {
    std::uint8_t original = 0;
    SIZE_T transferred = 0;
    if (!ReadProcessMemory(process_info_.hProcess, address, &original, 1, &transferred) || transferred != 1) {
        throw std::runtime_error("Read for soft breakpoint failed");
    }
    if (soft_breakpoints_.contains(address)) {
        return;
    }
    soft_breakpoints_[address] = original;
    const std::uint8_t int3 = 0xCC;
    if (!WriteProcessMemory(process_info_.hProcess, address, &int3, 1, &transferred) || transferred != 1) {
        throw std::runtime_error("Write for soft breakpoint failed");
    }
    FlushInstructionCache(process_info_.hProcess, address, 1);
}

void DebuggerCore::clear_soft_breakpoints() {
    for (const auto& [address, original] : soft_breakpoints_) {
        SIZE_T transferred = 0;
        WriteProcessMemory(process_info_.hProcess, address, &original, 1, &transferred);
        FlushInstructionCache(process_info_.hProcess, address, 1);
    }
    soft_breakpoints_.clear();
}

void DebuggerCore::detach_and_exit() {
    if (!live_mode_) {
        return;
    }

    if (!pid_file_path_.empty()) {
        std::wofstream file(pid_file_path_);
        file << process_info_.dwProcessId;
    }

    if (!ready_signaled_) {
        log(LogMsgType::Good, L"Signaling ready event...");
        SetEvent(ready_event_);
        ready_signaled_ = true;
    }
    log(LogMsgType::Good, L"Waiting for detach event while still pumping debug events...");
    detach_pending_ = true;
}

bool DebuggerCore::live_mode_enabled() const {
    return live_mode_;
}

void DebuggerCore::log(LogMsgType type, const std::wstring& message) const {
    if (logger_) {
        logger_(type, message);
    }
}

bool DebuggerCore::pe_execute() {
    if (attach_pid_ != 0) {
        log(LogMsgType::Info, L"Attaching to existing PID " + std::to_wstring(attach_pid_));
        return DebugActiveProcess(attach_pid_) != FALSE;
    }

    auto current_dir = executable_.parent_path();
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_SHOW;

    std::wstring command_line = L"\"" + executable_.wstring() + L"\"";
    if (!parameters_.empty()) {
        command_line.push_back(L' ');
        command_line += parameters_;
    }
    std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back(L'\0');

    const DWORD flags = CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED;
    log(LogMsgType::Info, L"CreateProcessW(suspended): " + command_line);
    const BOOL created = CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, FALSE, flags, nullptr,
                                        current_dir.empty() ? nullptr : current_dir.wstring().c_str(), &startup, &process_info_);
    if (created) {
        log(LogMsgType::Info, L"CreateProcessW succeeded for PID " + std::to_wstring(process_info_.dwProcessId));
        log(LogMsgType::Info, L"Calling DebugActiveProcess for PID " + std::to_wstring(process_info_.dwProcessId));
        if (!DebugActiveProcess(process_info_.dwProcessId)) {
            log(LogMsgType::Fatal, join_message(L"DebugActiveProcess failed: ", last_error_message(GetLastError())));
            TerminateProcess(process_info_.hProcess, 1);
            return false;
        }
        log(LogMsgType::Info, L"DebugActiveProcess succeeded");
    }
    return created != FALSE;
}

DWORD DebuggerCore::on_create_thread_debug_event(const DEBUG_EVENT& event) {
    log(LogMsgType::Info, L"[" + std::to_wstring(event.dwThreadId) + L"] Thread started (" + ptr_text(reinterpret_cast<const void*>(event.u.CreateThread.lpStartAddress)) + L").");
    threads_[event.dwThreadId] = event.u.CreateThread.hThread;
    update_debug_registers(event.u.CreateThread.hThread);
    return DBG_CONTINUE;
}

DWORD DebuggerCore::on_create_process_debug_event(const DEBUG_EVENT& event) {
    log(LogMsgType::Info, L"Launch Debug Session (PID: " + std::to_wstring(event.dwProcessId) + L", TID: " + std::to_wstring(event.dwThreadId) + L")");

    process_info_.hProcess = event.u.CreateProcessInfo.hProcess;
    process_info_.hThread = event.u.CreateProcessInfo.hThread;
    process_info_.dwProcessId = event.dwProcessId;
    process_info_.dwThreadId = event.dwThreadId;

    auto ntqip = nt_query_information_process();
    if (ntqip != nullptr) {
        ProcessBasicInformationLocal pbi{};
        if (ntqip(process_info_.hProcess, kProcessBasicInformationClass, &pbi, sizeof(pbi), nullptr) == 0) {
            log(LogMsgType::Info, L"PEB: " + hex32(reinterpret_cast<std::uintptr_t>(pbi.peb_base_address)));

            std::uint8_t flag = 0;
            SIZE_T transferred = 0;
            auto peb_bytes = static_cast<std::uint8_t*>(pbi.peb_base_address);
            if (ReadProcessMemory(process_info_.hProcess, peb_bytes + 2, &flag, 1, &transferred) && transferred == 1) {
                if (flag == 1) {
                    log(LogMsgType::Good, L"Patching PEB.BeingDebugged");
                    flag = 0;
                    WriteProcessMemory(process_info_.hProcess, peb_bytes + 2, &flag, 1, &transferred);
                }
            } else {
                log(LogMsgType::Fatal, L"Reading PEB failed");
            }

            std::uint32_t image_base = 0;
            if (ReadProcessMemory(process_info_.hProcess, peb_bytes + 8, &image_base, sizeof(image_base), &transferred) && transferred == sizeof(image_base)) {
                image_base_ = image_base;
                log(LogMsgType::Info, L"Process Image Base: " + hex32(image_base_));
            }

            std::uint32_t shim_data = 0;
            if (ReadProcessMemory(process_info_.hProcess, peb_bytes + 0x1E8, &shim_data, sizeof(shim_data), &transferred) && transferred == sizeof(shim_data) && shim_data != 0) {
                shim_data = 0;
                if (WriteProcessMemory(process_info_.hProcess, peb_bytes + 0x1E8, &shim_data, sizeof(shim_data), &transferred)) {
                    log(LogMsgType::Info, L"Cleared PEB.pShimData to prevent apphelp hooks");
                }
            }
        }
    }

    threads_[event.dwThreadId] = event.u.CreateProcessInfo.hThread;
    log(LogMsgType::Info, L"Installing initial unpack breakpoints...");
    on_debug_start(event.u.CreateProcessInfo.hFile);
    log(LogMsgType::Info, L"Initial unpack setup complete");
    if (event.u.CreateProcessInfo.hFile != nullptr && event.u.CreateProcessInfo.hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(event.u.CreateProcessInfo.hFile);
    }

    if (attach_pid_ == 0 && process_info_.hThread != nullptr) {
        const auto resume_result = ResumeThread(process_info_.hThread);
        if (resume_result == static_cast<DWORD>(-1)) {
            log(LogMsgType::Fatal, join_message(L"ResumeThread failed: ", last_error_message(GetLastError())));
        } else {
            log(LogMsgType::Info, L"Primary thread resumed after unpack setup");
        }
    }
    return DBG_CONTINUE;
}

DWORD DebuggerCore::on_exit_thread_debug_event(const DEBUG_EVENT& event) {
    if (!hide_thread_end_) {
        log(LogMsgType::Info, L"[" + std::to_wstring(event.dwThreadId) + L"] Thread ended (code " + std::to_wstring(event.u.ExitThread.dwExitCode) + L").");
    }
    if (auto it = threads_.find(event.dwThreadId); it != threads_.end()) {
        CloseHandle(it->second);
        threads_.erase(it);
    }
    return DBG_CONTINUE;
}

DWORD DebuggerCore::on_hardware_breakpoint_event(const DEBUG_EVENT& event) {
    HANDLE thread = threads_[event.dwThreadId];
    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &context)) {
        log(LogMsgType::Fatal, L"GetThreadContext failed");
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    bool step = false;
    DWORD result = DBG_EXCEPTION_NOT_HANDLED;
    if (((context.Dr6 >> 14) & 1) == 0 && (hw1_.is_set() || hw2_.is_set() || hw3_.is_set() || hw4_.is_set())) {
        std::uintptr_t bp_address = 0;
        switch (context.Dr6 & 0xF) {
        case 1: bp_address = hw1_.address; break;
        case 2: bp_address = hw2_.address; break;
        case 4: bp_address = hw3_.address; break;
        case 8: bp_address = hw4_.address; break;
        default:
            log(LogMsgType::Fatal, L"Multisignal: " + std::to_wstring(context.Dr6 & 0xF));
            break;
        }
        on_hardware_breakpoint(thread, bp_address, context);
        step = true;
    } else if (soft_bp_reenable_ != 0) {
        const std::uint8_t int3 = 0xCC;
        SIZE_T transferred = 0;
        WriteProcessMemory(process_info_.hProcess, reinterpret_cast<void*>(soft_bp_reenable_), &int3, 1, &transferred);
        soft_bp_reenable_ = 0;
        return DBG_CONTINUE;
    } else {
        result = on_singlestep(reinterpret_cast<std::uintptr_t>(event.u.Exception.ExceptionRecord.ExceptionAddress));
    }

    if (step) {
        if (disable_breakpoint(event.u.Exception.ExceptionRecord.ExceptionAddress)) {
            update_debug_registers(thread);
            context.ContextFlags = CONTEXT_CONTROL;
            context.EFlags |= 0x100;
            if (!SetThreadContext(thread, &context)) {
                log(LogMsgType::Fatal, L"SetThreadContext failed");
            }
        }
        result = DBG_CONTINUE;
    }
    return result;
}

DWORD DebuggerCore::on_load_dll_debug_event(const DEBUG_EVENT& event) {
    std::wstring dll_name = L"?";
    void* image_name = nullptr;
    wchar_t buffer[MAX_PATH + 1]{};
    SIZE_T transferred = 0;
    if (ReadProcessMemory(process_info_.hProcess, event.u.LoadDll.lpImageName, &image_name, sizeof(image_name), &transferred) &&
        ReadProcessMemory(process_info_.hProcess, image_name, buffer, sizeof(buffer), &transferred)) {
        dll_name = buffer;
    }
    log(LogMsgType::Info, L"[" + hex32(reinterpret_cast<std::uintptr_t>(event.u.LoadDll.lpBaseOfDll)) + L"] Loaded " + dll_name);
    if (event.u.LoadDll.hFile != nullptr) {
        CloseHandle(event.u.LoadDll.hFile);
    }
    return DBG_CONTINUE;
}

DWORD DebuggerCore::on_exit_process_debug_event(const DEBUG_EVENT& event) {
    log(LogMsgType::Info, L"Process ended (code " + std::to_wstring(event.u.ExitProcess.dwExitCode) + L").");
    return DBG_CONTINUE;
}

DWORD DebuggerCore::on_unload_dll_debug_event(const DEBUG_EVENT&) { return DBG_CONTINUE; }

DWORD DebuggerCore::on_output_debug_string_event(const DEBUG_EVENT& event) {
    if (event.u.DebugString.nDebugStringLength == 0 || event.u.DebugString.nDebugStringLength >= 256) {
        return DBG_CONTINUE;
    }
    std::array<char, 256> buffer{};
    if (read_process_memory(reinterpret_cast<std::uintptr_t>(event.u.DebugString.lpDebugStringData), buffer.data(), event.u.DebugString.nDebugStringLength)) {
        buffer[event.u.DebugString.nDebugStringLength] = '\0';
        log(LogMsgType::Info, L"[Debug Str] " + std::wstring(buffer.begin(), buffer.begin() + strlen(buffer.data())));
    }
    return DBG_CONTINUE;
}

DWORD DebuggerCore::on_rip_event(const DEBUG_EVENT&) {
    log(LogMsgType::Fatal, L"SYSTEM ERROR");
    return DBG_CONTINUE;
}

DWORD DebuggerCore::on_software_breakpoint_event(const DEBUG_EVENT& event) {
    auto* address = event.u.Exception.ExceptionRecord.ExceptionAddress;
    HANDLE thread = threads_[event.dwThreadId];

    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(thread, &context);
    --context.Eip;
    SetThreadContext(thread, &context);

    const auto original = soft_breakpoints_[address];
    SIZE_T transferred = 0;
    WriteProcessMemory(process_info_.hProcess, address, &original, 1, &transferred);
    FlushInstructionCache(process_info_.hProcess, address, 1);

    const auto action = on_software_breakpoint(thread, address);
    if (action == SoftBreakpointAction::ClearContinue) {
        soft_breakpoints_.erase(address);
    } else {
        soft_bp_reenable_ = context.Eip;
        context.EFlags |= 0x100;
        SetThreadContext(thread, &context);
    }

    return DBG_CONTINUE;
}

SoftBreakpointAction ASProtectUnpacker::on_software_breakpoint(HANDLE thread, void* breakpoint_address) {
    log(LogMsgType::Info, L"Soft BP at " + ptr_text(breakpoint_address));

    if (breakpoint_address == anti_debug_eh_) {
        CONTEXT thread_context{};
        thread_context.ContextFlags = CONTEXT_INTEGER;
        GetThreadContext(thread, &thread_context);

        const auto context_addr = static_cast<std::uintptr_t>(thread_context.Eax);
        CONTEXT saved_context{};
        if (!read_process_memory(context_addr, &saved_context, sizeof(saved_context))) {
            throw std::runtime_error("Failed to read anti-debug saved CONTEXT");
        }
        apply_debug_registers(saved_context);
        if (!write_process_memory(context_addr, &saved_context, sizeof(saved_context))) {
            throw std::runtime_error("Failed to restore anti-debug saved CONTEXT");
        }
        return SoftBreakpointAction::ClearContinue;
    }

    if (breakpoint_address == hashing_done_) {
        DWORD old_protect = 0;
        VirtualProtectEx(process_handle(), reinterpret_cast<void*>(guard_start_), guard_end_ - guard_start_, PAGE_NOACCESS, &old_protect);
        return SoftBreakpointAction::ClearContinue;
    }

    const auto it = site_target_to_site_.find(breakpoint_address);
    if (it == site_target_to_site_.end()) {
        throw std::runtime_error("Address not found in stolen target dictionary");
    }

    const auto site = reinterpret_cast<std::uintptr_t>(it->second);
    log(LogMsgType::Good, L"OEP (stolen!): " + ptr_text(it->second));
    oep_ = site;

    DWORD old_protect = 0;
    VirtualProtectEx(process_handle(), reinterpret_cast<void*>(guard_start_), guard_end_ - guard_start_, PAGE_EXECUTE_READ, &old_protect);

    if (!guard_addrs_.empty()) {
        fixup_api_call_sites(thread);
    } else {
        finish_unpacking();
    }
    return SoftBreakpointAction::ClearContinue;
}

DWORD ASProtectUnpacker::on_access_violation(HANDLE thread, const EXCEPTION_RECORD& record) {
    if (roly_poly_) {
        return roly_poly_->on_access_violation(thread, record);
    }
    if (aip_) {
        return aip_->on_access_violation(thread, record);
    }
    if (!is_guarded_address(static_cast<std::uintptr_t>(record.ExceptionInformation[1]))) {
        return DebuggerCore::on_access_violation(thread, record);
    }

    return process_guarded_access(thread, record);
}

void ASProtectUnpacker::on_debug_start(HANDLE pe_file) {
    pe_sections_.clear();
    guard_addrs_.clear();
    as_region_ = {};

    HANDLE file = pe_file;
    if (file == nullptr || file == INVALID_HANDLE_VALUE) {
        file = CreateFileW(executable_.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("CreateFileW failed for PE header read");
        }
    }

    std::array<std::uint8_t, 0x1000> header{};
    DWORD read = 0;
    SetFilePointer(file, 0, nullptr, FILE_BEGIN);
    if (!ReadFile(file, header.data(), static_cast<DWORD>(header.size()), &read, nullptr) || read < sizeof(IMAGE_DOS_HEADER)) {
        if (pe_file == nullptr || pe_file == INVALID_HANDLE_VALUE) {
            CloseHandle(file);
        }
        throw std::runtime_error("ReadFile failed for PE header read");
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(header.data() + dos->e_lfanew);
    const auto* section = IMAGE_FIRST_SECTION(nt);
    pe_sections_.assign(section, section + nt->FileHeader.NumberOfSections);
    major_linker_ = nt->OptionalHeader.MajorLinkerVersion;
    minor_linker_ = nt->OptionalHeader.MinorLinkerVersion;
    base_of_data_ = nt->OptionalHeader.BaseOfData;
    size_of_image_ = nt->OptionalHeader.SizeOfImage;

    if (pe_file == nullptr || pe_file == INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }

    set_breakpoint(image_base_ + 0x1020, HwBreakpointType::Write);
}

void ASProtectUnpacker::get_as_region(std::uintptr_t address) {
    fetch_memory_regions();
    as_region_ = {};
    for (const auto& region : memory_regions_) {
        if (region.contains(address)) {
            as_region_ = region;
            break;
        }
    }

    if (as_region_.size < 0x10000) {
        as_region_ = {};
        return;
    }

    log(LogMsgType::Good, L"AS region: " + hex32(as_region_.address) + L"~" + hex32(as_region_.address + as_region_.size));
    find_iat_wrapper_call();
}

void ASProtectUnpacker::on_hardware_breakpoint(HANDLE thread, std::uintptr_t breakpoint_address, CONTEXT& context) {
    if (breakpoint_address == image_base_ + 0x1020) {
        log(LogMsgType::Good, L"Text accessed from " + hex32(context.Eip));

        std::uint16_t instruction = 0;
        if (!read_process_memory(context.Eip, &instruction, sizeof(instruction)) || instruction != 0xA5F3) {
            return;
        }

        if (as_region_.address == 0) {
            get_as_region(context.Eip);
        }

        std::uintptr_t return_address = 0;
        if (!read_process_memory(context.Esp + 8, &return_address, sizeof(return_address)) || !as_region_.contains(return_address)) {
            throw std::runtime_error("Unexpected stack layout");
        }
        if (!read_process_memory(context.Esp + 12, &return_address, sizeof(return_address)) || !as_region_.contains(return_address)) {
            throw std::runtime_error("Unexpected stack layout (2)");
        }

        std::array<std::uint8_t, 2> jump_above{};
        if (!read_process_memory(return_address + 18, jump_above.data(), jump_above.size())) {
            throw std::runtime_error("Failed to read post-copy jump bytes");
        }
        if (jump_above[0] == 0x77) {
            return_address += 20;
        } else if (jump_above[0] == 0x0F && jump_above[1] == 0x87) {
            return_address += 24;
        }

        reset_breakpoint(reinterpret_cast<void*>(breakpoint_address));
        set_breakpoint(return_address);
        sections_unpacked_addr_ = return_address;
        return;
    }

    if (breakpoint_address == sections_unpacked_addr_) {
        reset_breakpoint(reinterpret_cast<void*>(breakpoint_address));
        guard_start_ = image_base_ + pe_sections_.front().VirtualAddress;
        guard_end_ = image_base_ + base_of_data_;
        DWORD old_protect = 0;
        VirtualProtectEx(process_handle(), reinterpret_cast<void*>(guard_start_), guard_end_ - guard_start_, PAGE_NOACCESS, &old_protect);
        return;
    }

    if (breakpoint_address == get_proc_result_addr_ || breakpoint_address == get_proc_result_addr_aip_) {
        if (obfuscated_aip_ && breakpoint_address == get_proc_result_addr_aip_) {
            std::uint32_t value = 0;
            if (!read_process_memory(context.Ebp - 4, &value, sizeof(value))) {
                throw std::runtime_error("Failed reading obfuscated proc result");
            }
            proc_addr_ = reinterpret_cast<void*>(static_cast<std::uintptr_t>(value));
        } else {
            proc_addr_ = reinterpret_cast<void*>(static_cast<std::uintptr_t>(context.Eax));
        }
        return;
    }

    if (breakpoint_address == proc_type_addr_ || breakpoint_address == proc_type_addr_aip_) {
        SuspendThread(thread);
        if (breakpoint_address == proc_type_addr_) {
            std::array<std::uint8_t, 2> op_types{};
            if (!read_process_memory(context.Eax + 0x4A, op_types.data(), op_types.size())) {
                throw std::runtime_error("RPM for env failed");
            }
            if (static_cast<std::uint8_t>(context.Edx) != op_types[0] && static_cast<std::uint8_t>(context.Edx) != op_types[1]) {
                throw std::runtime_error("Op type fault");
            }
            proc_is_jmp_ = static_cast<std::uint8_t>(context.Edx) == op_types[1];
            aip_in_play_ = false;
            log(LogMsgType::Good, std::wstring(L"-> ") + ptr_text(proc_addr_) + (proc_is_jmp_ ? L", jmp" : L", call"));
        } else {
            aip_in_play_ = true;
            if (!aip_) {
                aip_ = std::make_unique<Aip>(process_handle(), trace_thread_, context.Eax,
                    [this](LogMsgType type, const std::wstring& msg) { log(type, msg); },
                    [this](std::uintptr_t address, void* buffer, std::size_t size) { return read_process_memory(address, buffer, size); },
                    [this](std::uintptr_t address, const void* buffer, std::size_t size) { return write_process_memory(address, buffer, size); });
            }
        }
        if (proc_reveal_event_ != nullptr) {
            SetEvent(proc_reveal_event_);
        }
        return;
    }

    if (breakpoint_address == iat_wrapper_call_) {
        context.Eip += 5;
        return;
    }

    throw std::runtime_error("ASProtectUnpacker hardware breakpoint branch not yet ported");
}

DWORD ASProtectUnpacker::on_singlestep(std::uintptr_t breakpoint_address) {
    if (guard_stepping_) {
        if (guard_addrs_.size() >= 2) {
            const auto last = guard_addrs_.back();
            const auto prev = guard_addrs_[guard_addrs_.size() - 2];
            if (last == prev + 1) {
                place_bp_on_stolen(last - 1);
            }
        }

        DWORD old_protect = 0;
        VirtualProtectEx(process_handle(), reinterpret_cast<void*>(guard_start_), guard_end_ - guard_start_, PAGE_NOACCESS, &old_protect);
        guard_stepping_ = false;
        return DBG_CONTINUE;
    }
    return DebuggerCore::on_singlestep(breakpoint_address);
}

bool ASProtectUnpacker::is_guarded_address(std::uintptr_t address) const {
    if (guard_start_ == 0) {
        return false;
    }
    return address >= guard_start_ && address < guard_end_;
}

DWORD ASProtectUnpacker::process_guarded_access(HANDLE thread, const EXCEPTION_RECORD& record) {
    log(LogMsgType::Info, L"[Guard] " + hex32(static_cast<std::uintptr_t>(record.ExceptionInformation[1])) + L" (from " + ptr_text(record.ExceptionAddress) + L")");

    DWORD old_protect = 0;
    VirtualProtectEx(process_handle(), reinterpret_cast<void*>(guard_start_), guard_end_ - guard_start_, PAGE_EXECUTE_READWRITE, &old_protect);

    if (reinterpret_cast<std::uintptr_t>(record.ExceptionAddress) > guard_end_) {
        if (record.ExceptionInformation[1] < guard_start_ + 0x10) {
            if (is_sha_func(reinterpret_cast<std::uintptr_t>(record.ExceptionAddress))) {
                log(LogMsgType::Info, L"Guard ran into hashing, skipping...");
                skip_sha_func(thread);
                return DBG_CONTINUE;
            }
        }

        guard_addrs_.push_back(static_cast<std::uintptr_t>(record.ExceptionInformation[1]));
        if (guard_addrs_.size() > 1000) {
            throw std::runtime_error("Fast-fail: Something is wrong with page guarding in this target.");
        }

        guard_stepping_ = true;
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(thread, &context)) {
            throw std::runtime_error("GetThreadContext failed in process_guarded_access");
        }
        context.EFlags |= 0x100;
        if (!SetThreadContext(thread, &context)) {
            throw std::runtime_error("SetThreadContext failed in process_guarded_access");
        }
    } else {
        log(LogMsgType::Good, L"OEP: " + ptr_text(record.ExceptionAddress));
        oep_ = reinterpret_cast<std::uintptr_t>(record.ExceptionAddress);
        oep_ = fixup_oep_if_stolen(oep_, thread);
        VirtualProtectEx(process_handle(), reinterpret_cast<void*>(guard_start_), guard_end_ - guard_start_, PAGE_EXECUTE_READ, &old_protect);
        if (!guard_addrs_.empty()) {
            fixup_api_call_sites(thread);
        } else {
            finish_unpacking();
        }
    }

    return DBG_CONTINUE;
}

bool ASProtectUnpacker::is_sha_func(std::uintptr_t address) {
    std::array<std::uint8_t, 7> code{};
    if (!read_process_memory(address, code.data(), code.size())) {
        return false;
    }
    return code[0] == 0x03 && code[6] == 0xC1;
}

void ASProtectUnpacker::skip_sha_func(HANDLE thread) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &context)) {
        throw std::runtime_error("GetThreadContext failed in skip_sha_func");
    }

    std::uintptr_t ret_round = 0;
    if (!read_process_memory(context.Esp + 0x14, &ret_round, sizeof(ret_round)) || !as_region_.contains(ret_round)) {
        log(LogMsgType::Fatal, L"Unknown SHA round return address " + hex32(ret_round));
        return;
    }

    std::uintptr_t ret_hashing = 0;
    if (!read_process_memory(context.Esp + 0x2C, &ret_hashing, sizeof(ret_hashing)) || !as_region_.contains(ret_hashing)) {
        log(LogMsgType::Fatal, L"Unknown SHA return address " + hex32(ret_hashing));
        return;
    }

    hashing_done_ = reinterpret_cast<void*>(ret_hashing);
    set_soft_breakpoint(hashing_done_);
}

void ASProtectUnpacker::place_bp_on_stolen(std::uintptr_t site_addr) {
    std::array<std::uint8_t, 5> site{};
    if (!read_process_memory(site_addr, site.data(), site.size())) {
        return;
    }

    std::uintptr_t site_target = 0;
    if (site[0] == 0xE9) {
        std::int32_t rel = 0;
        memcpy(&rel, &site[1], sizeof(rel));
        site_target = static_cast<std::uintptr_t>(static_cast<std::int64_t>(site_addr + 5) + rel);
    } else if (site[0] == 0x68) {
        std::uint32_t imm = 0;
        memcpy(&imm, &site[1], sizeof(imm));
        site_target = imm;
    } else {
        return;
    }

    if (site_target >= image_base_ && site_target < image_base_ + size_of_image_) {
        return;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(process_handle(), reinterpret_cast<void*>(site_target), &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT) {
        return;
    }

    log(LogMsgType::Info, L"Set soft bp on " + hex32(site_target));
    set_soft_breakpoint(reinterpret_cast<void*>(site_target));
    site_target_to_site_[reinterpret_cast<void*>(site_target)] = reinterpret_cast<void*>(site_addr);
}

void ASProtectUnpacker::on_unsolicited_software_breakpoint(HANDLE thread, void* breakpoint_address) {
    DebuggerCore::on_unsolicited_software_breakpoint(thread, breakpoint_address);

    if (as_region_.address == 0) {
        get_as_region(reinterpret_cast<std::uintptr_t>(breakpoint_address));
    }

    auto ntqit = nt_query_information_thread();
    if (ntqit == nullptr) {
        return;
    }

    ThreadBasicInformationLocal tbi{};
    if (ntqit(thread, kThreadBasicInformationClass, &tbi, sizeof(tbi), nullptr) != 0) {
        return;
    }

    std::uint32_t seh_head = 0;
    SIZE_T transferred = 0;
    if (!ReadProcessMemory(process_handle(), tbi.teb_base_address, &seh_head, sizeof(seh_head), &transferred) || transferred != sizeof(seh_head)) {
        return;
    }

    std::uint32_t exc_handler = 0;
    if (!ReadProcessMemory(process_handle(), reinterpret_cast<void*>(seh_head + 4), &exc_handler, sizeof(exc_handler), &transferred) || transferred != sizeof(exc_handler)) {
        return;
    }

    log(LogMsgType::Info, L"EH: " + ptr_text(reinterpret_cast<void*>(exc_handler)));

    std::array<std::uint8_t, 256> code{};
    if (!read_process_memory(exc_handler, code.data(), code.size())) {
        return;
    }

    for (std::size_t i = 0; i + 5 <= code.size(); ++i) {
        if (code[i] == 0x89 && code[i + 1] == 0x50 && code[i + 2] == 0x10 && code[i + 3] == 0x33 && code[i + 4] == 0xC0) {
            const auto detected = reinterpret_cast<void*>(exc_handler + i + 3);
            if (anti_debug_eh_ == detected) {
                return;
            }
            anti_debug_eh_ = detected;
            log(LogMsgType::Good, L"Detected anti-debug EH tail at " + ptr_text(anti_debug_eh_));
            set_soft_breakpoint(anti_debug_eh_);
            return;
        }
    }
}

void ASProtectUnpacker::init_tracing() {
    if (as_region_.size == 0) {
        throw std::runtime_error("ASRegion not set");
    }

    std::vector<std::uint8_t> as_data(as_region_.size);
    if (!read_process_memory(as_region_.address, as_data.data(), as_data.size())) {
        throw std::runtime_error("Unable to read ASRegion");
    }

    auto get_proc = find_dynamic_pattern("668B4DEC668B55E88B45F4E8????????8945FC", as_data.data(), static_cast<std::uint32_t>(as_data.size()));
    if (!get_proc) {
        get_proc = find_dynamic_pattern("8945FC576A008D4D??8B45F4", as_data.data(), static_cast<std::uint32_t>(as_data.size()));
        if (!get_proc) {
            throw std::runtime_error("Failed to find proc reveal point");
        }
    } else {
        *get_proc += 16;
    }

    auto proc_type = find_dynamic_pattern("8B4DFC8B45F4", as_data.data() + *get_proc, static_cast<std::uint32_t>(as_data.size() - *get_proc));
    if (!proc_type) {
        throw std::runtime_error("Failed to find ref type");
    }

    proc_type_addr_ = as_region_.address + *get_proc + *proc_type + 6;
    get_proc_result_addr_ = as_region_.address + *get_proc;

    auto get_proc_aip = find_dynamic_pattern("668B4DE08BD78B45F4E8????????8945FC", as_data.data(), static_cast<std::uint32_t>(as_data.size()));
    if (!get_proc_aip) {
        get_proc_aip = find_dynamic_pattern("8D45FC50668B4DE08BD78B45F4E8", as_data.data(), static_cast<std::uint32_t>(as_data.size()));
        if (!get_proc_aip) {
            throw std::runtime_error("Failed to find proc reveal point AIP");
        }
        *get_proc_aip += 0x12;
        obfuscated_aip_ = true;
    } else {
        *get_proc_aip += 14;
        obfuscated_aip_ = false;
    }

    auto proc_type_aip = find_dynamic_pattern("8A404A3A45EF0F85", as_data.data() + *get_proc_aip, static_cast<std::uint32_t>(as_data.size() - *get_proc_aip));
    if (!proc_type_aip) {
        throw std::runtime_error("Failed to find ref type AIP");
    }

    proc_type_addr_aip_ = as_region_.address + *get_proc_aip + *proc_type_aip;
    get_proc_result_addr_aip_ = as_region_.address + *get_proc_aip;

    log(LogMsgType::Good, L"GetProcResultAddr: " + hex32(get_proc_result_addr_));
    log(LogMsgType::Good, L"ProcTypeAddr: " + hex32(proc_type_addr_));
    log(LogMsgType::Good, L"GetProcResultAddrAIP: " + hex32(get_proc_result_addr_aip_));
    log(LogMsgType::Good, L"ProcTypeAddrAIP: " + hex32(proc_type_addr_aip_));
}

void ASProtectUnpacker::fix_redirected_imports(std::uintptr_t array_ptr) {
    static constexpr const char* real_methods[11] = {
        "GetCommandLineA", "GetVersion", "", "GetModuleHandleA", "GetCurrentProcess",
        "GetCurrentProcessId", "LockResource", "FreeResource", "", "DialogBoxParamA", ""
    };

    std::array<std::uint32_t, 11> methods{};
    if (!read_process_memory(array_ptr, methods.data(), sizeof(methods))) {
        throw std::runtime_error("FixRedirectedImports: failed to read method table");
    }
    for (std::size_t i = 0; i < methods.size(); ++i) {
        if (!as_region_.contains(methods[i])) {
            throw std::runtime_error("FixRedirectedImports: invalid method pointer");
        }
    }

    std::uint32_t canary = 0;
    if (!read_process_memory(array_ptr + sizeof(methods), &canary, sizeof(canary))) {
        throw std::runtime_error("FixRedirectedImports: failed to read canary");
    }
    if (as_region_.contains(canary)) {
        throw std::runtime_error("FixRedirectedImports: Canary check failed");
    }

    auto* kernel = GetModuleHandleW(L"kernel32.dll");
    auto* user = GetModuleHandleW(L"user32.dll");
    for (std::size_t i = 0; i < methods.size(); ++i) {
        if (real_methods[i][0] == '\0') {
            continue;
        }
        HMODULE module = std::strcmp(real_methods[i], "DialogBoxParamA") == 0 ? user : kernel;
        methods[i] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(GetProcAddress(module, real_methods[i])));
    }

    if (!write_process_memory(array_ptr, methods.data(), sizeof(methods))) {
        throw std::runtime_error("FixRedirectedImports: failed to patch method table");
    }
}

void ASProtectUnpacker::find_iat_wrapper_call() {
    std::vector<std::uint8_t> as_mem(as_region_.size);
    if (!read_process_memory(as_region_.address, as_mem.data(), as_mem.size())) {
        throw std::runtime_error("Failed to read AS region for IAT wrapper scan");
    }

    auto calls = find_dynamic_pattern("50E8????????E8????????8B178902", as_mem.data(), static_cast<std::uint32_t>(as_mem.size()));
    if (!calls) {
        return;
    }

    iat_wrapper_call_ = as_region_.address + *calls + 6;
    log(LogMsgType::Good, L"IAT wrapper call located at " + hex32(iat_wrapper_call_));
    set_breakpoint(iat_wrapper_call_);

    auto gpa_set = find_dynamic_pattern("B8????????8B17890283", as_mem.data() + *calls, 200);
    if (gpa_set) {
        const auto patch_addr = as_region_.address + *calls + *gpa_set + 1;
        log(LogMsgType::Good, L"Patching GPA at " + hex32(patch_addr));
        const auto gpa = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcAddress")));
        if (!write_process_memory(patch_addr, &gpa, sizeof(gpa))) {
            throw std::runtime_error("Failed to patch redirected GetProcAddress");
        }
    } else {
        log(LogMsgType::Fatal, L"GPA pattern not found");
    }

    auto push = find_dynamic_pattern("6068????????8D45??FF35", as_mem.data(), static_cast<std::uint32_t>(as_mem.size()));
    if (!push) {
        log(LogMsgType::Fatal, L"Pattern for api redirects not found");
        return;
    }

    std::uint32_t array_ptr = 0;
    std::memcpy(&array_ptr, as_mem.data() + *push + 2, sizeof(array_ptr));
    fix_redirected_imports(array_ptr);
}

void ASProtectUnpacker::fixup_api_call_sites(HANDLE thread) {
    clear_soft_breakpoints();
    init_tracing();
    SuspendThread(thread);
    trace_thread_ = thread;
    set_breakpoint(get_proc_result_addr_);
    set_breakpoint(proc_type_addr_);
    set_breakpoint(get_proc_result_addr_aip_);
    set_breakpoint(proc_type_addr_aip_);
    log(LogMsgType::Info, L"Begin tracing...");
    if (proc_reveal_event_ != nullptr) {
        CloseHandle(proc_reveal_event_);
    }
    proc_reveal_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    std::vector<std::uintptr_t> sorted = guard_addrs_;
    std::sort(sorted.begin(), sorted.end());
    if (sorted.empty()) {
        finish_unpacking();
        return;
    }

    std::vector<std::uintptr_t> site_set;
    site_set.push_back(sorted[0] - 1);
    for (std::size_t i = 1; i < sorted.size(); ++i) {
        if ((sorted[i] - 1) >= site_set.back() + 6) {
            site_set.push_back(sorted[i] - 1);
        }
    }

    log(LogMsgType::Info, L"Deduced " + std::to_wstring(site_set.size()) + L" call sites from " + std::to_wstring(sorted.size()) + L" accesses");

    std::uintptr_t iat = image_base_ + base_of_data_;
    std::array<std::uintptr_t, 512> iat_data{};
    if (!read_process_memory(iat, iat_data.data(), sizeof(iat_data))) {
        throw std::runtime_error("Failed to read IAT for fixup_api_call_sites");
    }
    std::unordered_map<std::uintptr_t, std::uintptr_t> iat_map;
    for (std::size_t i = 0; i < iat_data.size(); ++i) {
        iat_map[iat_data[i]] = iat + i * sizeof(std::uintptr_t);
    }

    std::uintptr_t last_extent = 0;
    for (const auto site_addr : site_set) {
        if (site_addr + 1 < last_extent) {
            continue;
        }

        std::array<std::uint8_t, 6> site{};
        if (!read_process_memory(site_addr, site.data(), site.size())) {
            throw std::runtime_error("Failed to read call site in fixup_api_call_sites");
        }

        bool is_jmp = false;
        std::uintptr_t target = 0;
        if (site[0] == 0xE8) {
            target = do_trace(site_addr);
            is_jmp = proc_is_jmp_;
        } else if (site[1] == 0xE9 || site[1] == 0x68) {
            throw std::runtime_error("Stolen / polymorphic call-site tracing not yet ported in native path");
        } else {
            throw std::runtime_error("Unknown call site form in fixup_api_call_sites");
        }

        const auto iat_it = iat_map.find(target);
        if (iat_it == iat_map.end()) {
            throw std::runtime_error("Resolved target not present in IAT map");
        }

        site[0] = 0xFF;
        site[1] = static_cast<std::uint8_t>(0x15 + (is_jmp ? 0x10 : 0));
        std::uint32_t iat_slot = static_cast<std::uint32_t>(iat_it->second);
        std::memcpy(site.data() + 2, &iat_slot, sizeof(iat_slot));
        if (!write_process_memory(site_addr, site.data(), site.size())) {
            throw std::runtime_error("Failed rewriting traced call site");
        }
        last_extent = site_addr + site.size();
    }

    finish_unpacking();
}

std::uintptr_t ASProtectUnpacker::do_trace(std::uintptr_t address) {
    static constexpr std::array<std::uint8_t, 32> null_bytes{};

    log(LogMsgType::Info, L"Trace: " + hex32(address));
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(trace_thread_, &context)) {
        throw std::runtime_error("GetThreadContext failed in do_trace");
    }

    context.Eip = address;
    const auto old_esp = context.Esp;
    if (!write_process_memory(old_esp, null_bytes.data(), null_bytes.size())) {
        throw std::runtime_error("Failed clearing stack scratch area in do_trace");
    }
    if (!SetThreadContext(trace_thread_, &context)) {
        throw std::runtime_error("SetThreadContext failed in do_trace");
    }

    ResumeThread(trace_thread_);
    WaitForSingleObject(proc_reveal_event_, INFINITE);

    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(trace_thread_, &context)) {
        throw std::runtime_error("GetThreadContext post trace failed");
    }

    const auto result = reinterpret_cast<std::uintptr_t>(proc_addr_);
    context.Esp = old_esp;
    if (!SetThreadContext(trace_thread_, &context)) {
        throw std::runtime_error("SetThreadContext restore failed in do_trace");
    }

    if (aip_in_play_) {
        aip_->process_import(address, proc_is_jmp_, proc_addr_, obfuscated_aip_);
    }
    return result;
}

std::uintptr_t ASProtectUnpacker::restore_oep_for_msvc6(std::uintptr_t oep, HANDLE thread) {
    static constexpr std::array<std::uint8_t, 38> restore_data = {
        0x55, 0x8B, 0xEC, 0x6A, 0xFF,
        0x68, 0, 0, 0, 0,
        0x68, 0, 0, 0, 0,
        0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x83, 0xEC, 0x58,
        0x53, 0x56, 0x57,
        0x89, 0x65, 0xE8
    };

    std::array<std::uint8_t, 3> check_buf{};
    if (!read_process_memory(oep - restore_data.size() - 3, check_buf.data(), check_buf.size())) {
        return oep;
    }
    if (check_buf[0] != 0xC2 && check_buf[2] != 0xC3) {
        log(LogMsgType::Fatal, L"Stolen OEP gap mismatch.");
        return oep;
    }

    auto restore_buf = restore_data;
    const auto result = oep - static_cast<std::uint32_t>(restore_buf.size());

    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &context)) {
        throw std::runtime_error("GetThreadContext failed in restore_oep_for_msvc6");
    }
    if (context.Esp != context.Ebp - 0x74) {
        log(LogMsgType::Fatal, L"Stack frame mismatch: esp=" + hex32(context.Esp) + L", ebp=" + hex32(context.Ebp));
        return oep;
    }

    std::array<std::uintptr_t, 2> stack_data{};
    if (!read_process_memory(context.Ebp - 3 * sizeof(std::uintptr_t), stack_data.data(), sizeof(stack_data))) {
        throw std::runtime_error("Failed reading stack data for restore_oep_for_msvc6");
    }

    std::memcpy(restore_buf.data() + 6, &stack_data[1], sizeof(std::uint32_t));
    std::memcpy(restore_buf.data() + 11, &stack_data[0], sizeof(std::uint32_t));
    if (!write_process_memory(result, restore_buf.data(), restore_buf.size())) {
        throw std::runtime_error("Failed writing restore_oep_for_msvc6 buffer");
    }

    log(LogMsgType::Good, L"Stolen MSVC6 OEP restored: 0x" + hex32(result));
    return result;
}

std::uintptr_t ASProtectUnpacker::restore_oep_for_msvc2003(HANDLE thread) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &context)) {
        throw std::runtime_error("GetThreadContext failed in restore_oep_for_msvc2003");
    }

    const auto first_push = context.Ebp - (context.Esp + 0x20);
    std::uint32_t second_push = 0;
    if (!read_process_memory(context.Ebp - 8, &second_push, sizeof(second_push))) {
        throw std::runtime_error("Failed reading second push for restore_oep_for_msvc2003");
    }

    std::uint32_t needed_space = 2 + 5;
    if (first_push >= 0x80) {
        needed_space += 3;
    }

    std::uintptr_t result = 0;
    if (!read_process_memory(context.Esp, &result, sizeof(result))) {
        throw std::runtime_error("Failed reading return address for restore_oep_for_msvc2003");
    }
    result -= (5 + needed_space);

    std::uint32_t check = 0;
    if (!read_process_memory(result, &check, sizeof(check))) {
        throw std::runtime_error("Failed reading restore_oep_for_msvc2003 check dword");
    }
    if (check != 0) {
        throw std::runtime_error("MSVC2003 OEP recovery failed");
    }

    std::vector<std::uint8_t> restoration(needed_space);
    if (first_push < 0x80) {
        restoration[0] = 0x6A;
        restoration[1] = static_cast<std::uint8_t>(first_push);
        restoration[2] = 0x68;
        std::memcpy(restoration.data() + 3, &second_push, sizeof(second_push));
    } else {
        restoration[0] = 0x68;
        std::uint32_t fp32 = first_push;
        std::memcpy(restoration.data() + 1, &fp32, sizeof(fp32));
        restoration[5] = 0x68;
        std::memcpy(restoration.data() + 6, &second_push, sizeof(second_push));
    }

    if (!write_process_memory(result, restoration.data(), restoration.size())) {
        throw std::runtime_error("Failed writing restore_oep_for_msvc2003 buffer");
    }

    log(LogMsgType::Good, L"Stolen MSVC2003 OEP restored: 0x" + hex32(result));
    return result;
}

std::uintptr_t ASProtectUnpacker::fixup_oep_if_stolen(std::uintptr_t oep, HANDLE thread) {
    std::uint8_t test_byte = 0;
    if (major_linker_ == 6 && minor_linker_ == 0) {
        if (!read_process_memory(oep, &test_byte, sizeof(test_byte)) || test_byte != 0xFF) {
            return oep;
        }
        return restore_oep_for_msvc6(oep, thread);
    }
    if (major_linker_ == 7 && minor_linker_ == 10) {
        if (!read_process_memory(oep, &test_byte, sizeof(test_byte)) || test_byte != 0xC3) {
            return oep;
        }
        return restore_oep_for_msvc2003(thread);
    }
    return oep;
}

void ASProtectUnpacker::finish_unpacking() {
    if (live_mode_enabled()) {
        log(LogMsgType::Good, L"In-memory unpacking complete (OEP: 0x" + hex32(oep_) + L"). Switching to live mode.");
        detach_and_exit();
        return;
    }
    throw std::runtime_error("Native dump-to-disk path not yet ported");
}

}  // namespace maple::aspirin
