#pragma once

#include <windows.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace maple::aspirin {

enum class LogMsgType {
    Info,
    Good,
    Fatal,
};

using LogFn = std::function<void(LogMsgType, const std::wstring&)>;

struct MemoryRegion {
    std::uintptr_t address = 0;
    std::uint32_t size = 0;

    bool contains(std::uintptr_t candidate) const;
};

enum class HwBreakpointType : std::uint32_t {
    Execute = 0,
    Write = 1,
    Reserved = 2,
    Access = 3,
};

struct Breakpoint {
    std::uintptr_t address = 0;
    HwBreakpointType type = HwBreakpointType::Execute;
    bool disabled = false;

    void change(std::uintptr_t new_address, HwBreakpointType new_type);
    bool is_set() const;
};

enum class SoftBreakpointAction {
    KeepContinue,
    ClearContinue,
};

enum class AipHandler : std::uint8_t {
    Offset,
    RefType,
    EmulId,
    Unknown3,
    Unknown4,
    ImpSpec1,
    ImpSpec1b,
    LibId,
    ProcId,
    IsSipPatch,
    Eh0 = 0,
    EhOpcode = 1,
    EhPatchSize,
    EhAddrRva,
    EhBranchType,
    EhReg1,
    EhReg2,
    EhImm1,
    EhImm2,
    EhAddressingMode,
};

enum class AipOpcode : std::uint8_t {
    Call,
    Jmp,
    CmpJcc,
    Cmp,
    Invalid,
    Add,
    MovRR,
    MovMR,
    MovRDR,
};

struct AipHandlerRec {
    std::uint32_t proc = 0;
    std::uint32_t unk4 = 0;
    std::uint32_t unk8 = 0;
};

#pragma pack(push, 1)
struct AipContext {
    std::uint32_t class_info;
    std::uint32_t unk4;
    std::uint32_t unk8;
    std::uint32_t unkC;
    std::uint32_t mem_indxs;
    std::uint32_t image_base;
    std::uint32_t patches_count;
    std::uint32_t emuls_count;
    std::uint8_t prot_type;
    std::uint8_t padding0[3];
    std::uint32_t text_base;
    std::uint32_t text_end_rva;
    std::uint32_t aip_enter_handler;
    std::uint32_t aip_exit_handler;
    std::uint32_t unk34_handler;
    std::uint32_t unk38_handler;
    std::uint32_t imports;
    std::uint8_t permut[10];
    std::uint8_t opcode_permut[9];
    std::uint8_t padding1[1];
    std::uint32_t patches;
    std::uint32_t emuls;
    std::uint8_t permut2[10];
    AipHandlerRec entry_access_funcs[10];
    std::uint32_t obfus_key;
    std::uint32_t entry_size;
};
#pragma pack(pop)

struct AipPatch {
    bool is_jmp = false;
    std::vector<std::uint8_t> emul_data;
};

struct AipEntryOffsets {
    std::array<int, 10> offsets{};
    std::uint32_t key = 0;

    std::uint8_t get_byte(const void* entry, AipHandler type) const;
    std::uint32_t get_dword(const void* entry, AipHandler type) const;
    std::uint32_t get_dword_deobfus(const void* entry, AipHandler type) const;
};

class Aip {
public:
    Aip(HANDLE process, HANDLE trace_thread, std::uintptr_t context_addr, LogFn log,
        const std::function<bool(std::uintptr_t, void*, std::size_t)>& rpm,
        const std::function<bool(std::uintptr_t, const void*, std::size_t)>& wpm);

    DWORD on_access_violation(HANDLE thread, const EXCEPTION_RECORD& record);
    void process_import(std::uintptr_t ref_addr, bool& ref_is_jmp, void*& proc_addr, bool proc_addr_is_obfus);

private:
    void trace_access_funcs();
    void fetch_entries();
    void restore_emulated_code(std::uintptr_t to_address, const std::vector<std::uint8_t>& emul_entry);
    std::vector<std::uint8_t> recover_cmp(const std::vector<std::uint8_t>& entry);
    std::vector<std::uint8_t> recover_cmp_jcc(const std::vector<std::uint8_t>& entry, std::uintptr_t to_address);
    std::vector<std::uint8_t> recover_add(const std::vector<std::uint8_t>& entry);
    std::vector<std::uint8_t> recover_mov_rr(const std::vector<std::uint8_t>& entry);
    std::vector<std::uint8_t> recover_mov_mr(const std::vector<std::uint8_t>& entry, int space);

    enum class State {
        Init,
        Tracing,
        Ready,
    };

    HANDLE process_ = nullptr;
    HANDLE trace_thread_ = nullptr;
    AipContext context_{};
    AipEntryOffsets entry_offsets_{};
    std::unordered_map<std::uintptr_t, AipPatch> patches_;
    State state_ = State::Init;
    void* bait_page_ = nullptr;
    int bait_access_offset_ = 0;
    HANDLE trace_signal_ = nullptr;
    LogFn logger_;
    std::function<bool(std::uintptr_t, void*, std::size_t)> rpm_;
    std::function<bool(std::uintptr_t, const void*, std::size_t)> wpm_;
};

enum class PolyHandler : std::uint8_t {
    Offset,
    FlowType,
    Target2,
    Target,
    BranchType,
    CmpReg1,
    CmpReg2,
    CmpDispl1,
    CmpDispl2,
    CmpModifier,
};

#pragma pack(push, 1)
struct PolyContext {
    std::uint32_t class_info;
    std::uint32_t unk4;
    std::uint32_t unk8;
    std::uint32_t unkC;
    std::uint32_t image_base;
    std::uint32_t entry_count;
    std::uint32_t poly_code_ptr;
    std::uint32_t flow_obfus_enter_handler;
    std::uint32_t flow_obfus_exit_handler;
    std::uint8_t permut[10];
    std::uint8_t padding0[2];
    std::uint32_t entries_pointer;
    std::uint8_t permut2[10];
    std::uint8_t padding1[2];
    std::uint32_t entry_access_funcs[10];
    std::uint32_t obfus_key;
    std::uint32_t entry_size;
};
#pragma pack(pop)

struct PolyEntryOffsets {
    std::array<int, 10> offsets{};
    std::uint32_t key = 0;

    std::uint32_t get_entry_offset(const void* entry) const;
    std::uint8_t get_flow_type(const void* entry) const;
    std::uint32_t get_target(const void* entry) const;
    std::uint32_t get_target2(const void* entry) const;
    std::uint8_t get_branch_type(const void* entry) const;
    std::uint8_t get_cmp_reg1(const void* entry) const;
    std::uint8_t get_cmp_reg2(const void* entry) const;
    std::int32_t get_cmp_displ1(const void* entry) const;
    std::int32_t get_cmp_displ2(const void* entry) const;
    std::uint8_t get_cmp_modifier(const void* entry) const;
};

class RolyPoly {
public:
    RolyPoly(HANDLE process, HANDLE trace_thread, std::uintptr_t address, MemoryRegion as_region, LogFn log,
             const std::function<bool(std::uintptr_t, void*, std::size_t)>& rpm,
             const std::function<bool(std::uintptr_t, const void*, std::size_t)>& wpm);

    DWORD on_access_violation(HANDLE thread, const EXCEPTION_RECORD& record);

private:
    void start_trace(std::uintptr_t address);
    void trace_access_funcs();
    void fetch_entries();

    enum class State {
        Init,
        TraceObfusEnter,
        TraceAccessFunc,
        EvalEntries,
    };

    HANDLE process_ = nullptr;
    HANDLE trace_thread_ = nullptr;
    std::uintptr_t address_ = 0;
    MemoryRegion as_region_{};
    LogFn logger_;
    std::function<bool(std::uintptr_t, void*, std::size_t)> rpm_;
    std::function<bool(std::uintptr_t, const void*, std::size_t)> wpm_;
    State state_ = State::Init;
    HANDLE state_signal_ = nullptr;
    std::uintptr_t flow_obfus_site_ = 0;
    std::uintptr_t flow_obfus_enter_ = 0;
    PolyContext poly_context_{};
    PolyEntryOffsets entry_offsets_{};
    std::unordered_map<std::uint32_t, std::vector<std::uint8_t>> entries_;
    void* bait_page_ = nullptr;
    int bait_access_offset_ = 0;
};

std::optional<std::uint32_t> find_dynamic_pattern(std::string_view pattern, const std::uint8_t* buffer, std::uint32_t size);
std::optional<std::uint32_t> find_static_pattern(std::string_view pattern, const std::uint8_t* buffer, std::uint32_t size);

class DebuggerCore {
public:
    DebuggerCore(std::filesystem::path executable, std::wstring parameters, LogFn log);
    DebuggerCore(DWORD attach_pid, LogFn log);
    virtual ~DebuggerCore();

    DebuggerCore(const DebuggerCore&) = delete;
    DebuggerCore& operator=(const DebuggerCore&) = delete;

    bool run();

    DWORD process_id() const;
    HANDLE process_handle() const;
    std::uintptr_t image_base() const;

    void set_live_mode(bool enabled);
    void set_ready_event(HANDLE event_handle);
    void set_detach_event(HANDLE event_handle);
    void set_pid_file_path(std::filesystem::path path);

protected:
    virtual void on_debug_start(HANDLE pe_file) = 0;
    virtual DWORD on_access_violation(HANDLE thread, const EXCEPTION_RECORD& record);
    virtual void on_hardware_breakpoint(HANDLE thread, std::uintptr_t breakpoint_address, CONTEXT& context) = 0;
    virtual SoftBreakpointAction on_software_breakpoint(HANDLE thread, void* breakpoint_address) = 0;
    virtual void on_unsolicited_software_breakpoint(HANDLE thread, void* breakpoint_address);
    virtual DWORD on_singlestep(std::uintptr_t breakpoint_address);

    void fetch_memory_regions();
    bool read_process_memory(std::uintptr_t address, void* buffer, std::size_t size) const;
    bool write_process_memory(std::uintptr_t address, const void* buffer, std::size_t size) const;

    void set_breakpoint(std::uintptr_t address, HwBreakpointType type = HwBreakpointType::Execute);
    bool disable_breakpoint(void* address);
    void enable_breakpoints();
    void reset_breakpoint(void* address);
    void apply_debug_registers(CONTEXT& context) const;
    void update_debug_registers(HANDLE thread);

    void set_soft_breakpoint(void* address);
    void clear_soft_breakpoints();
    void detach_and_exit();
    bool live_mode_enabled() const;

    void log(LogMsgType type, const std::wstring& message) const;

    std::filesystem::path executable_;
    std::wstring parameters_;
    PROCESS_INFORMATION process_info_{};
    std::uintptr_t image_base_ = 0;
    std::vector<MemoryRegion> memory_regions_;
    bool hide_thread_end_ = false;

private:
    bool pe_execute();
    DWORD on_create_thread_debug_event(const DEBUG_EVENT& event);
    DWORD on_create_process_debug_event(const DEBUG_EVENT& event);
    DWORD on_exit_thread_debug_event(const DEBUG_EVENT& event);
    DWORD on_load_dll_debug_event(const DEBUG_EVENT& event);
    DWORD on_exit_process_debug_event(const DEBUG_EVENT& event);
    DWORD on_unload_dll_debug_event(const DEBUG_EVENT& event);
    DWORD on_output_debug_string_event(const DEBUG_EVENT& event);
    DWORD on_rip_event(const DEBUG_EVENT& event);
    DWORD on_hardware_breakpoint_event(const DEBUG_EVENT& event);
    DWORD on_software_breakpoint_event(const DEBUG_EVENT& event);

    DWORD attach_pid_ = 0;
    Breakpoint hw1_{};
    Breakpoint hw2_{};
    Breakpoint hw3_{};
    Breakpoint hw4_{};
    std::unordered_map<DWORD, HANDLE> threads_;
    std::unordered_map<void*, std::uint8_t> soft_breakpoints_;
    std::uintptr_t soft_bp_reenable_ = 0;
    bool live_mode_ = false;
    bool ready_signaled_ = false;
    bool detach_pending_ = false;
    HANDLE ready_event_ = nullptr;
    HANDLE detach_event_ = nullptr;
    std::filesystem::path pid_file_path_;
    LogFn logger_;
};

class ASProtectUnpacker final : public DebuggerCore {
public:
    using DebuggerCore::DebuggerCore;

protected:
    void on_debug_start(HANDLE pe_file) override;
    void on_hardware_breakpoint(HANDLE thread, std::uintptr_t breakpoint_address, CONTEXT& context) override;
    SoftBreakpointAction on_software_breakpoint(HANDLE thread, void* breakpoint_address) override;
    DWORD on_access_violation(HANDLE thread, const EXCEPTION_RECORD& record) override;
    void on_unsolicited_software_breakpoint(HANDLE thread, void* breakpoint_address) override;
    DWORD on_singlestep(std::uintptr_t breakpoint_address) override;

private:
    void get_as_region(std::uintptr_t address);
    bool is_guarded_address(std::uintptr_t address) const;
    DWORD process_guarded_access(HANDLE thread, const EXCEPTION_RECORD& record);
    bool is_sha_func(std::uintptr_t address);
    void skip_sha_func(HANDLE thread);
    void place_bp_on_stolen(std::uintptr_t site_addr);
    void init_tracing();
    void find_iat_wrapper_call();
    void fix_redirected_imports(std::uintptr_t array_ptr);
    void fixup_api_call_sites(HANDLE thread);
    std::uintptr_t do_trace(std::uintptr_t address);
    std::uintptr_t restore_oep_for_msvc6(std::uintptr_t oep, HANDLE thread);
    std::uintptr_t restore_oep_for_msvc2003(HANDLE thread);
    std::uintptr_t fixup_oep_if_stolen(std::uintptr_t oep, HANDLE thread);
    void finish_unpacking();

    std::uint32_t base_of_data_ = 0;
    std::uint32_t size_of_image_ = 0;
    std::uint8_t major_linker_ = 0;
    std::uint8_t minor_linker_ = 0;
    std::vector<IMAGE_SECTION_HEADER> pe_sections_;

    std::uintptr_t sections_unpacked_addr_ = 0;
    std::uintptr_t guard_start_ = 0;
    std::uintptr_t guard_end_ = 0;
    bool guard_stepping_ = false;
    std::vector<std::uintptr_t> guard_addrs_;
    MemoryRegion as_region_{};
    void* anti_debug_eh_ = nullptr;
    void* hashing_done_ = nullptr;
    std::uintptr_t oep_ = 0;
    std::unordered_map<void*, void*> site_target_to_site_;
    std::uintptr_t get_proc_result_addr_ = 0;
    std::uintptr_t proc_type_addr_ = 0;
    std::uintptr_t get_proc_result_addr_aip_ = 0;
    std::uintptr_t proc_type_addr_aip_ = 0;
    std::uintptr_t iat_wrapper_call_ = 0;
    bool obfuscated_aip_ = false;
    HANDLE proc_reveal_event_ = nullptr;
    void* proc_addr_ = nullptr;
    bool proc_is_jmp_ = false;
    bool aip_in_play_ = false;
    HANDLE trace_thread_ = nullptr;
    std::unique_ptr<Aip> aip_;
    std::unique_ptr<RolyPoly> roly_poly_;
};

}  // namespace maple::aspirin
