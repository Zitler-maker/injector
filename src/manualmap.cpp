#include "manualmap.h"

#include "log.h"
#include "remote.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr SIZE_T kMaxImageSize = 1ull << 30;
constexpr WORD kMaxSections = 96;
constexpr DWORD kMaxImportDescriptors = 4096;
constexpr DWORD kMaxImportThunks = 65536;
constexpr DWORD kMaxTlsCallbacks = 128;
constexpr size_t kMaxImportName = 512;

bool span_ok(uint64_t offset, uint64_t length, size_t size) {
    return offset <= size && length <= size - offset;
}

std::wstring ascii_to_wide(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    const int length = MultiByteToWideChar(CP_ACP, 0, text.c_str(), static_cast<int>(text.size()),
                                           nullptr, 0);
    if (length <= 0) {
        return std::wstring();
    }
    std::wstring wide(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_ACP, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), length);
    return wide;
}

bool read_ascii_cstring(const std::vector<uint8_t>& image, uint64_t offset, std::string& out) {
    out.clear();
    if (offset >= image.size()) {
        return false;
    }
    const size_t limit = std::min<size_t>(kMaxImportName, image.size() - static_cast<size_t>(offset));
    for (size_t i = 0; i < limit; ++i) {
        const char character = static_cast<char>(image[static_cast<size_t>(offset) + i]);
        if (character == '\0') {
            return true;
        }
        out.push_back(character);
    }
    return false;
}

bool read_file(const std::wstring& path, std::vector<uint8_t>& out, DWORD& error) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        log_last_error(LogLevel::error, L"CreateFileW(dll)", error);
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size)) {
        error = GetLastError();
        log_last_error(LogLevel::error, L"GetFileSizeEx", error);
        CloseHandle(file);
        return false;
    }
    if (size.QuadPart <= 0 || size.QuadPart > static_cast<LONGLONG>(kMaxImageSize)) {
        error = ERROR_FILE_INVALID;
        log_line(LogLevel::error, L"dll size %lld is outside allowed range", size.QuadPart);
        CloseHandle(file);
        return false;
    }

    out.resize(static_cast<size_t>(size.QuadPart));
    size_t total = 0;
    while (total < out.size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(out.size() - total, 1u << 20));
        DWORD read = 0;
        if (!ReadFile(file, out.data() + total, chunk, &read, nullptr)) {
            error = GetLastError();
            log_last_error(LogLevel::error, L"ReadFile(dll)", error);
            CloseHandle(file);
            return false;
        }
        if (read == 0) {
            error = ERROR_HANDLE_EOF;
            log_last_error(LogLevel::error, L"ReadFile(dll)", error);
            CloseHandle(file);
            return false;
        }
        total += read;
    }
    CloseHandle(file);
    error = ERROR_SUCCESS;
    return true;
}

DWORD section_protection(DWORD characteristics) {
    const bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    if (executable) {
        if (writable) {
            return PAGE_EXECUTE_READWRITE;
        }
        return readable ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    }
    if (writable) {
        return PAGE_READWRITE;
    }
    return readable ? PAGE_READONLY : PAGE_NOACCESS;
}

IMAGE_DATA_DIRECTORY image_directory(const IMAGE_NT_HEADERS64& nt, size_t index) {
    const DWORD count = std::min<DWORD>(nt.OptionalHeader.NumberOfRvaAndSizes,
                                        IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    if (index >= count) {
        return IMAGE_DATA_DIRECTORY{};
    }
    return nt.OptionalHeader.DataDirectory[index];
}

struct remote_image {
    HANDLE process = nullptr;
    void* base = nullptr;

    ~remote_image() {
        if (base != nullptr) {
            VirtualFreeEx(process, base, 0, MEM_RELEASE);
        }
    }

    void release() { base = nullptr; }
};

bool apply_relocations(std::vector<uint8_t>& image, const IMAGE_NT_HEADERS64& nt, uint64_t delta,
                       DWORD& error) {
    const IMAGE_DATA_DIRECTORY directory = image_directory(nt, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (directory.Size == 0) {
        return true;
    }
    if (!span_ok(directory.VirtualAddress, directory.Size, image.size())) {
        error = ERROR_INVALID_DATA;
        log_line(LogLevel::error, L"relocation directory lies outside image");
        return false;
    }

    uint64_t cursor = directory.VirtualAddress;
    uint64_t remaining = directory.Size;
    while (remaining >= sizeof(IMAGE_BASE_RELOCATION)) {
        IMAGE_BASE_RELOCATION block{};
        std::memcpy(&block, image.data() + cursor, sizeof(block));
        if (block.SizeOfBlock < sizeof(block) || block.SizeOfBlock > remaining) {
            error = ERROR_INVALID_DATA;
            log_line(LogLevel::error, L"malformed relocation block at rva 0x%llx",
                     static_cast<unsigned long long>(cursor));
            return false;
        }

        const size_t entry_count =
            (block.SizeOfBlock - sizeof(block)) / sizeof(WORD);
        const size_t entries_offset = static_cast<size_t>(cursor) + sizeof(block);
        if (!span_ok(entries_offset, entry_count * sizeof(WORD), image.size())) {
            error = ERROR_INVALID_DATA;
            log_line(LogLevel::error, L"relocation entries outside image");
            return false;
        }

        for (size_t i = 0; i < entry_count; ++i) {
            WORD entry = 0;
            std::memcpy(&entry, image.data() + entries_offset + i * sizeof(WORD), sizeof(entry));
            const WORD type = static_cast<WORD>(entry >> 12);
            const WORD offset = static_cast<WORD>(entry & 0x0FFF);
            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;
            }
            const uint64_t target = static_cast<uint64_t>(block.VirtualAddress) + offset;
            if (type == IMAGE_REL_BASED_DIR64) {
                if (!span_ok(target, sizeof(uint64_t), image.size())) {
                    error = ERROR_INVALID_DATA;
                    log_line(LogLevel::error, L"relocation target outside image");
                    return false;
                }
                uint64_t value = 0;
                std::memcpy(&value, image.data() + target, sizeof(value));
                value += delta;
                std::memcpy(image.data() + target, &value, sizeof(value));
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                if (!span_ok(target, sizeof(uint32_t), image.size())) {
                    error = ERROR_INVALID_DATA;
                    log_line(LogLevel::error, L"relocation target outside image");
                    return false;
                }
                uint32_t value = 0;
                std::memcpy(&value, image.data() + target, sizeof(value));
                value += static_cast<uint32_t>(delta);
                std::memcpy(image.data() + target, &value, sizeof(value));
            } else {
                error = ERROR_INVALID_DATA;
                log_line(LogLevel::error, L"unsupported relocation type %u", type);
                return false;
            }
        }

        cursor += block.SizeOfBlock;
        remaining -= block.SizeOfBlock;
    }

    if (remaining != 0) {
        error = ERROR_INVALID_DATA;
        log_line(LogLevel::error, L"relocation directory size mismatch");
        return false;
    }
    return true;
}

std::wstring basename_of(const std::wstring& path) {
    const size_t separator = path.find_last_of(L"\\/");
    return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

bool ensure_import_module(DWORD pid, HANDLE process, const std::string& module_name,
                         DWORD timeout_ms, DWORD& error) {
    const std::wstring wide = ascii_to_wide(module_name);
    if (wide.empty()) {
        error = ERROR_INVALID_NAME;
        log_line(LogLevel::error, L"empty import module name");
        return false;
    }

    // API set contract names (api-ms-win-*) resolve to a host module via the loader schema,
    // so the name must be resolved locally before deciding what to load in the target.
    HMODULE local = GetModuleHandleW(wide.c_str());
    if (local == nullptr) {
        local = LoadLibraryW(wide.c_str());
    }
    if (local == nullptr) {
        error = GetLastError();
        log_last_error(LogLevel::error, L"load import module locally", error);
        return false;
    }

    std::wstring load_target = wide;
    std::wstring probe_name = wide;
    wchar_t local_path[MAX_PATH]{};
    const DWORD path_length = GetModuleFileNameW(local, local_path, MAX_PATH);
    if (path_length > 0 && path_length < MAX_PATH) {
        load_target = local_path;
        probe_name = basename_of(local_path);
    }

    DWORD probe_error = ERROR_SUCCESS;
    if (remote_module_base(pid, probe_name.c_str(), probe_error) != nullptr) {
        return true;
    }

    log_line(LogLevel::info, L"import module %ls (%ls) is not loaded in target, loading",
             wide.c_str(), probe_name.c_str());
    if (!remote_load_library(pid, process, load_target, timeout_ms, error)) {
        return false;
    }
    if (remote_module_base(pid, probe_name.c_str(), probe_error) == nullptr) {
        error = probe_error;
        log_last_error(LogLevel::error, L"locate import module after load", error);
        return false;
    }
    return true;
}

bool resolve_imports(std::vector<uint8_t>& image, const IMAGE_NT_HEADERS64& nt, HANDLE process,
                     DWORD pid, DWORD timeout_ms, DWORD& error) {
    const IMAGE_DATA_DIRECTORY directory = image_directory(nt, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (directory.Size == 0) {
        return true;
    }
    if (!span_ok(directory.VirtualAddress, directory.Size, image.size())) {
        error = ERROR_INVALID_DATA;
        log_line(LogLevel::error, L"import directory lies outside image");
        return false;
    }

    uint64_t descriptor_cursor = directory.VirtualAddress;
    bool list_terminated = false;
    for (DWORD index = 0; index < kMaxImportDescriptors; ++index) {
        if (!span_ok(descriptor_cursor, sizeof(IMAGE_IMPORT_DESCRIPTOR), image.size())) {
            error = ERROR_INVALID_DATA;
            log_line(LogLevel::error, L"import descriptor outside image");
            return false;
        }
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        std::memcpy(&descriptor, image.data() + descriptor_cursor, sizeof(descriptor));
        if (descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0 && descriptor.Name == 0) {
            list_terminated = true;
            break;
        }
        if (descriptor.Name == 0 || descriptor.FirstThunk == 0) {
            error = ERROR_INVALID_DATA;
            log_line(LogLevel::error, L"malformed import descriptor");
            return false;
        }

        std::string module_name;
        if (!read_ascii_cstring(image, descriptor.Name, module_name) || module_name.empty()) {
            error = ERROR_INVALID_DATA;
            log_line(LogLevel::error, L"unreadable import module name");
            return false;
        }
        if (!ensure_import_module(pid, process, module_name, timeout_ms, error)) {
            return false;
        }
        const std::wstring wide_module = ascii_to_wide(module_name);

        const uint64_t thunk_source =
            descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
        bool thunks_terminated = false;
        for (DWORD thunk_index = 0; thunk_index < kMaxImportThunks; ++thunk_index) {
            const uint64_t name_entry_offset =
                thunk_source + static_cast<uint64_t>(thunk_index) * sizeof(uint64_t);
            const uint64_t iat_offset =
                descriptor.FirstThunk + static_cast<uint64_t>(thunk_index) * sizeof(uint64_t);
            if (!span_ok(name_entry_offset, sizeof(uint64_t), image.size()) ||
                !span_ok(iat_offset, sizeof(uint64_t), image.size())) {
                error = ERROR_INVALID_DATA;
                log_line(LogLevel::error, L"import thunk outside image");
                return false;
            }

            uint64_t thunk = 0;
            std::memcpy(&thunk, image.data() + name_entry_offset, sizeof(thunk));
            if (thunk == 0) {
                thunks_terminated = true;
                break;
            }

            void* resolved = nullptr;
            DWORD resolve_error = ERROR_SUCCESS;
            if ((thunk & IMAGE_ORDINAL_FLAG64) != 0) {
                const WORD ordinal = static_cast<WORD>(thunk & 0xFFFF);
                resolved = remote_export_ordinal(pid, wide_module.c_str(), ordinal, resolve_error);
                if (resolved == nullptr) {
                    error = resolve_error;
                    log_line(LogLevel::error, L"import %ls!#%u not resolved", wide_module.c_str(),
                             static_cast<unsigned>(ordinal));
                    return false;
                }
            } else {
                if (!span_ok(thunk, sizeof(WORD), image.size())) {
                    error = ERROR_INVALID_DATA;
                    log_line(LogLevel::error, L"import name outside image");
                    return false;
                }
                std::string proc_name;
                if (!read_ascii_cstring(image, thunk + sizeof(WORD), proc_name) || proc_name.empty()) {
                    error = ERROR_INVALID_DATA;
                    log_line(LogLevel::error, L"unreadable import name");
                    return false;
                }
                resolved = remote_export(pid, wide_module.c_str(), proc_name.c_str(), resolve_error);
                if (resolved == nullptr) {
                    error = resolve_error;
                    log_line(LogLevel::error, L"import %ls!%hs not resolved", wide_module.c_str(),
                             proc_name.c_str());
                    return false;
                }
            }

            const uint64_t address = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(resolved));
            std::memcpy(image.data() + iat_offset, &address, sizeof(address));
        }
        if (!thunks_terminated) {
            error = ERROR_INVALID_DATA;
            log_line(LogLevel::error, L"import thunk list is too long");
            return false;
        }
        descriptor_cursor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    if (!list_terminated) {
        error = ERROR_INVALID_DATA;
        log_line(LogLevel::error, L"import descriptor list is too long");
        return false;
    }
    return true;
}

bool run_tls_callbacks(HANDLE process, uintptr_t remote_base, const std::vector<uint8_t>& mapped,
                       const IMAGE_NT_HEADERS64& nt, DWORD timeout_ms, DWORD& error) {
    const IMAGE_DATA_DIRECTORY directory = image_directory(nt, IMAGE_DIRECTORY_ENTRY_TLS);
    if (directory.Size == 0 || directory.VirtualAddress == 0) {
        return true;
    }
    if (!span_ok(directory.VirtualAddress, sizeof(IMAGE_TLS_DIRECTORY64), mapped.size())) {
        error = ERROR_INVALID_DATA;
        log_line(LogLevel::error, L"TLS directory lies outside image");
        return false;
    }

    IMAGE_TLS_DIRECTORY64 tls{};
    std::memcpy(&tls, mapped.data() + directory.VirtualAddress, sizeof(tls));
    if (tls.AddressOfCallBacks == 0) {
        return true;
    }
    if (tls.AddressOfCallBacks < remote_base) {
        error = ERROR_INVALID_DATA;
        log_line(LogLevel::error, L"TLS callback array points outside mapped image");
        return false;
    }
    const uint64_t callbacks_offset = tls.AddressOfCallBacks - remote_base;
    if (!span_ok(callbacks_offset, sizeof(uint64_t), mapped.size())) {
        error = ERROR_INVALID_DATA;
        log_line(LogLevel::error, L"TLS callback array lies outside mapped image");
        return false;
    }

    for (DWORD index = 0; index < kMaxTlsCallbacks; ++index) {
        const uint64_t entry_offset = callbacks_offset + static_cast<uint64_t>(index) * sizeof(uint64_t);
        if (!span_ok(entry_offset, sizeof(uint64_t), mapped.size())) {
            error = ERROR_INVALID_DATA;
            log_line(LogLevel::error, L"TLS callback array is too long");
            return false;
        }
        uint64_t callback = 0;
        std::memcpy(&callback, mapped.data() + entry_offset, sizeof(callback));
        if (callback == 0) {
            return true;
        }

        DWORD exit_code = 0;
        const bool called = remote_call(
            process, reinterpret_cast<void*>(static_cast<uintptr_t>(callback)),
            reinterpret_cast<void*>(remote_base),
            reinterpret_cast<void*>(static_cast<uintptr_t>(DLL_PROCESS_ATTACH)), nullptr,
            timeout_ms, exit_code, error);
        if (!called) {
            log_line(LogLevel::error, L"TLS callback 0x%llx failed",
                     static_cast<unsigned long long>(callback));
            return false;
        }
        log_line(LogLevel::info, L"TLS callback 0x%llx executed",
                 static_cast<unsigned long long>(callback));
    }

    error = ERROR_INVALID_DATA;
    log_line(LogLevel::error, L"TLS callback array is not null terminated");
    return false;
}

bool register_cfg_targets(HANDLE process, uintptr_t remote_base,
                          const std::vector<IMAGE_SECTION_HEADER>& sections) {
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy{};
    if (!GetProcessMitigationPolicy(process, ProcessControlFlowGuardPolicy, &policy, sizeof(policy)) ||
        policy.EnableControlFlowGuard == 0) {
        return true;
    }

    using set_valid_targets_fn = BOOL(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);
    set_valid_targets_fn set_targets = nullptr;
    for (const wchar_t* host : {L"kernelbase.dll", L"kernel32.dll"}) {
        HMODULE module = GetModuleHandleW(host);
        if (module != nullptr) {
            set_targets = reinterpret_cast<set_valid_targets_fn>(
                GetProcAddress(module, "SetProcessValidCallTargets"));
            if (set_targets != nullptr) {
                break;
            }
        }
    }
    if (set_targets == nullptr) {
        log_line(LogLevel::warn, L"CFG is enabled but SetProcessValidCallTargets is unavailable");
        return true;
    }

    constexpr SIZE_T kPageSize = 0x1000;
    for (const IMAGE_SECTION_HEADER& section : sections) {
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }
        const SIZE_T length =
            static_cast<SIZE_T>(std::max<uint64_t>(section.Misc.VirtualSize, section.SizeOfRawData));
        for (SIZE_T offset = 0; offset < length; offset += kPageSize) {
            CFG_CALL_TARGET_INFO target{};
            target.Offset = 0;
            target.Flags = CFG_CALL_TARGET_VALID;
            const uintptr_t page = remote_base + section.VirtualAddress + offset;
            if (!set_targets(process, reinterpret_cast<PVOID>(page), kPageSize, 1, &target)) {
                log_last_error(LogLevel::warn, L"SetProcessValidCallTargets", GetLastError());
            }
        }
    }
    log_line(LogLevel::info, L"CFG call targets registered for mapped image");
    return true;
}

} // namespace

bool inject_manual_map(HANDLE process, DWORD pid, const std::wstring& dll_path, DWORD timeout_ms,
                       DWORD& error) {
    std::vector<uint8_t> file;
    if (!read_file(dll_path, file, error)) {
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    if (file.size() < sizeof(dos)) {
        error = ERROR_BAD_EXE_FORMAT;
        log_line(LogLevel::error, L"file is too small for a DOS header");
        return false;
    }
    std::memcpy(&dos, file.data(), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        error = ERROR_BAD_EXE_FORMAT;
        log_line(LogLevel::error, L"missing MZ signature");
        return false;
    }
    if (dos.e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
        !span_ok(static_cast<uint64_t>(dos.e_lfanew), sizeof(IMAGE_NT_HEADERS64), file.size())) {
        error = ERROR_BAD_EXE_FORMAT;
        log_line(LogLevel::error, L"NT headers lie outside file");
        return false;
    }

    IMAGE_NT_HEADERS64 nt{};
    std::memcpy(&nt, file.data() + dos.e_lfanew, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        error = ERROR_BAD_EXE_FORMAT;
        log_line(LogLevel::error, L"missing PE signature");
        return false;
    }
    if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        error = ERROR_BAD_EXE_FORMAT;
        log_line(LogLevel::error, L"image is not x64 (machine 0x%x)", nt.FileHeader.Machine);
        return false;
    }
    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        error = ERROR_BAD_EXE_FORMAT;
        log_line(LogLevel::error, L"PE32+ optional header expected");
        return false;
    }
    if (nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
        error = ERROR_BAD_EXE_FORMAT;
        log_line(LogLevel::error, L"optional header is truncated");
        return false;
    }
    if (nt.FileHeader.NumberOfSections == 0 || nt.FileHeader.NumberOfSections > kMaxSections) {
        error = ERROR_BAD_EXE_FORMAT;
        log_line(LogLevel::error, L"section count %u is invalid", nt.FileHeader.NumberOfSections);
        return false;
    }

    const IMAGE_OPTIONAL_HEADER64& optional = nt.OptionalHeader;
    if (optional.SizeOfImage == 0 || optional.SizeOfImage > kMaxImageSize ||
        optional.SizeOfHeaders == 0 || optional.SizeOfHeaders > optional.SizeOfImage ||
        optional.SizeOfHeaders > file.size()) {
        error = ERROR_BAD_EXE_FORMAT;
        log_line(LogLevel::error, L"image or header size is invalid");
        return false;
    }

    const size_t section_offset = static_cast<size_t>(dos.e_lfanew) + sizeof(DWORD) +
                                  sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    if (!span_ok(section_offset, static_cast<uint64_t>(nt.FileHeader.NumberOfSections) *
                                     sizeof(IMAGE_SECTION_HEADER),
                 file.size())) {
        error = ERROR_BAD_EXE_FORMAT;
        log_line(LogLevel::error, L"section table lies outside file");
        return false;
    }

    std::vector<IMAGE_SECTION_HEADER> sections(nt.FileHeader.NumberOfSections);
    std::memcpy(sections.data(), file.data() + section_offset,
                sections.size() * sizeof(IMAGE_SECTION_HEADER));

    for (const IMAGE_SECTION_HEADER& section : sections) {
        const uint64_t virtual_span = std::max<uint64_t>(section.Misc.VirtualSize, section.SizeOfRawData);
        if (!span_ok(section.VirtualAddress, virtual_span, optional.SizeOfImage)) {
            error = ERROR_BAD_EXE_FORMAT;
            log_line(LogLevel::error, L"section spans outside image");
            return false;
        }
        if (section.SizeOfRawData != 0 &&
            !span_ok(section.PointerToRawData, section.SizeOfRawData, file.size())) {
            error = ERROR_BAD_EXE_FORMAT;
            log_line(LogLevel::error, L"section raw data lies outside file");
            return false;
        }
    }

    remote_image image{process, nullptr};
    image.base = remote_alloc(process, optional.SizeOfImage, PAGE_EXECUTE_READWRITE, error);
    if (image.base == nullptr) {
        log_last_error(LogLevel::error, L"VirtualAllocEx(image)", error);
        return false;
    }
    const uintptr_t remote_base = reinterpret_cast<uintptr_t>(image.base);
    const uintptr_t preferred_base = static_cast<uintptr_t>(optional.ImageBase);
    const uint64_t delta = remote_base - preferred_base;

    std::vector<uint8_t> mapped(optional.SizeOfImage, 0);
    std::memcpy(mapped.data(), file.data(), optional.SizeOfHeaders);
    for (const IMAGE_SECTION_HEADER& section : sections) {
        if (section.SizeOfRawData == 0) {
            continue;
        }
        size_t copy_length = section.SizeOfRawData;
        if (section.Misc.VirtualSize != 0 && section.Misc.VirtualSize < copy_length) {
            copy_length = section.Misc.VirtualSize;
        }
        std::memcpy(mapped.data() + section.VirtualAddress, file.data() + section.PointerToRawData,
                    copy_length);
    }

    if (delta != 0 && !apply_relocations(mapped, nt, delta, error)) {
        return false;
    }
    if (!resolve_imports(mapped, nt, process, pid, timeout_ms, error)) {
        return false;
    }

    if (!remote_write(process, image.base, mapped.data(), mapped.size(), error)) {
        log_last_error(LogLevel::error, L"WriteProcessMemory(image)", error);
        return false;
    }
    if (!FlushInstructionCache(process, image.base, mapped.size())) {
        error = GetLastError();
        log_last_error(LogLevel::error, L"FlushInstructionCache(image)", error);
        return false;
    }

    DWORD previous = 0;
    if (!VirtualProtectEx(process, image.base, optional.SizeOfHeaders, PAGE_READONLY, &previous)) {
        error = GetLastError();
        log_last_error(LogLevel::error, L"VirtualProtectEx(headers)", error);
        return false;
    }
    for (const IMAGE_SECTION_HEADER& section : sections) {
        const SIZE_T length =
            static_cast<SIZE_T>(std::max<uint64_t>(section.Misc.VirtualSize, section.SizeOfRawData));
        if (length == 0) {
            continue;
        }
        void* const target = reinterpret_cast<void*>(remote_base + section.VirtualAddress);
        if (!VirtualProtectEx(process, target, length, section_protection(section.Characteristics),
                              &previous)) {
            error = GetLastError();
            log_line(LogLevel::error, L"VirtualProtectEx(section %hs) failed", section.Name);
            log_last_error(LogLevel::error, L"VirtualProtectEx", error);
            return false;
        }
    }

    log_line(LogLevel::info, L"image mapped at 0x%llx (preferred 0x%llx)",
             static_cast<unsigned long long>(remote_base),
             static_cast<unsigned long long>(optional.ImageBase));

    register_cfg_targets(process, remote_base, sections);

    if (!run_tls_callbacks(process, remote_base, mapped, nt, timeout_ms, error)) {
        return false;
    }

    if (optional.AddressOfEntryPoint != 0) {
        if (optional.AddressOfEntryPoint >= optional.SizeOfImage) {
            error = ERROR_BAD_EXE_FORMAT;
            log_line(LogLevel::error, L"entry point lies outside image");
            return false;
        }
        void* const entry = reinterpret_cast<void*>(remote_base + optional.AddressOfEntryPoint);
        DWORD exit_code = 0;
        if (!remote_call(process, entry, image.base,
                         reinterpret_cast<void*>(static_cast<uintptr_t>(DLL_PROCESS_ATTACH)), nullptr,
                         timeout_ms, exit_code, error)) {
            log_line(LogLevel::error, L"DllMain(DLL_PROCESS_ATTACH) call failed");
            return false;
        }
        if (exit_code == 0) {
            error = ERROR_DLL_INIT_FAILED;
            log_line(LogLevel::error, L"DllMain returned FALSE");
            return false;
        }
    } else {
        log_line(LogLevel::info, L"image has no entry point, DllMain skipped");
    }

    image.release();
    log_line(LogLevel::info, L"manual map completed");
    return true;
}
