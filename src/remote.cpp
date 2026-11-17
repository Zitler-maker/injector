#include "remote.h"

#include "log.h"

#include <tlhelp32.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr SIZE_T kStubRegionSize = 0x100;
constexpr size_t kStubBufferSize = 64;

std::wstring basename_of(const std::wstring& path) {
    const size_t separator = path.find_last_of(L"\\/");
    return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

void* translate_local_export(DWORD pid, HMODULE local_module, FARPROC local_function, DWORD& error) {
    wchar_t module_path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(local_module, module_path, static_cast<DWORD>(MAX_PATH));
    if (length == 0 || length >= MAX_PATH) {
        error = length == 0 ? GetLastError() : ERROR_BUFFER_OVERFLOW;
        return nullptr;
    }

    DWORD base_error = ERROR_SUCCESS;
    void* const remote_base = remote_module_base(pid, module_path, base_error);
    if (remote_base == nullptr) {
        error = base_error;
        return nullptr;
    }
    const uintptr_t delta = reinterpret_cast<uintptr_t>(remote_base) -
                            reinterpret_cast<uintptr_t>(local_module);
    error = ERROR_SUCCESS;
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(local_function) + delta);
}

} // namespace

void* remote_alloc(HANDLE process, SIZE_T size, DWORD protect, DWORD& error) {
    void* memory = VirtualAllocEx(process, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect);
    error = memory ? ERROR_SUCCESS : GetLastError();
    return memory;
}

bool remote_free(HANDLE process, void* remote_memory, DWORD& error) {
    if (remote_memory == nullptr) {
        error = ERROR_SUCCESS;
        return true;
    }
    const BOOL result = VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
    error = result ? ERROR_SUCCESS : GetLastError();
    return result != FALSE;
}

bool remote_write(HANDLE process, void* remote_destination, const void* source, SIZE_T size, DWORD& error) {
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_destination, source, size, &written)) {
        error = GetLastError();
        return false;
    }
    if (written != size) {
        error = ERROR_WRITE_FAULT;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

bool remote_read(HANDLE process, void* destination, const void* remote_source, SIZE_T size, DWORD& error) {
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, remote_source, destination, size, &read)) {
        error = GetLastError();
        return false;
    }
    if (read != size) {
        error = ERROR_READ_FAULT;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

void* remote_module_base(DWORD pid, const wchar_t* module_name, DWORD& error) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return nullptr;
    }

    const std::wstring wanted = basename_of(module_name);
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    void* base = nullptr;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, wanted.c_str()) == 0 ||
                _wcsicmp(entry.szExePath, module_name) == 0) {
                base = entry.modBaseAddr;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    error = base ? ERROR_SUCCESS : ERROR_MOD_NOT_FOUND;
    return base;
}

void* remote_export(DWORD pid, const wchar_t* module_name, const char* proc_name, DWORD& error) {
    const std::wstring module(module_name);
    HMODULE local = GetModuleHandleW(module.c_str());
    if (local == nullptr) {
        local = LoadLibraryW(module.c_str());
    }
    if (local == nullptr) {
        error = GetLastError();
        return nullptr;
    }

    const FARPROC function = GetProcAddress(local, proc_name);
    if (function == nullptr) {
        error = GetLastError();
        return nullptr;
    }
    return translate_local_export(pid, local, function, error);
}

void* remote_export_ordinal(DWORD pid, const wchar_t* module_name, WORD ordinal, DWORD& error) {
    const std::wstring module(module_name);
    HMODULE local = GetModuleHandleW(module.c_str());
    if (local == nullptr) {
        local = LoadLibraryW(module.c_str());
    }
    if (local == nullptr) {
        error = GetLastError();
        return nullptr;
    }

    const FARPROC function = GetProcAddress(local, MAKEINTRESOURCEA(ordinal));
    if (function == nullptr) {
        error = GetLastError();
        return nullptr;
    }
    return translate_local_export(pid, local, function, error);
}

HANDLE remote_thread(HANDLE process, void* start, void* parameter, bool use_nt_create_thread_ex,
                     DWORD& error) {
    if (!use_nt_create_thread_ex) {
        HANDLE thread = CreateRemoteThread(process, nullptr, 0,
                                           reinterpret_cast<LPTHREAD_START_ROUTINE>(start),
                                           parameter, 0, nullptr);
        error = thread ? ERROR_SUCCESS : GetLastError();
        return thread;
    }

    using nt_create_thread_ex_fn = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
                                                ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        error = GetLastError();
        return nullptr;
    }
    auto create_thread = reinterpret_cast<nt_create_thread_ex_fn>(GetProcAddress(ntdll, "NtCreateThreadEx"));
    if (create_thread == nullptr) {
        error = GetLastError();
        return nullptr;
    }

    HANDLE thread = nullptr;
    const LONG status = create_thread(&thread, THREAD_ALL_ACCESS, nullptr, process, start, parameter,
                                      0, 0, 0, 0, nullptr);
    if (status < 0) {
        error = static_cast<DWORD>(status);
        return nullptr;
    }
    error = ERROR_SUCCESS;
    return thread;
}

bool remote_call(HANDLE process, void* function, void* arg1, void* arg2, void* arg3,
                 DWORD timeout_ms, DWORD& exit_code, DWORD& error) {
    unsigned char stub[kStubBufferSize];
    size_t length = 0;

    auto emit = [&](unsigned char value) { stub[length++] = value; };
    auto emit_move = [&](unsigned char rex, unsigned char modrm, void* value) {
        emit(rex);
        emit(modrm);
        const uint64_t raw = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(value));
        std::memcpy(stub + length, &raw, sizeof(raw));
        length += sizeof(raw);
    };

    emit(0x48); emit(0x83); emit(0xEC); emit(0x28);          // sub rsp, 0x28
    emit_move(0x48, 0xB9, arg1);                              // mov rcx, arg1
    emit_move(0x48, 0xBA, arg2);                              // mov rdx, arg2
    emit_move(0x49, 0xB8, arg3);                              // mov r8, arg3
    emit_move(0x48, 0xB8, function);                          // mov rax, function
    emit(0xFF); emit(0xD0);                                   // call rax
    emit(0x48); emit(0x83); emit(0xC4); emit(0x28);           // add rsp, 0x28
    emit(0xC3);                                               // ret

    void* const stub_memory = remote_alloc(process, kStubRegionSize, PAGE_READWRITE, error);
    if (stub_memory == nullptr) {
        log_last_error(LogLevel::error, L"VirtualAllocEx(remote stub)", error);
        return false;
    }

    bool success = false;
    if (!remote_write(process, stub_memory, stub, length, error)) {
        log_last_error(LogLevel::error, L"WriteProcessMemory(remote stub)", error);
    } else if (!FlushInstructionCache(process, stub_memory, length)) {
        error = GetLastError();
        log_last_error(LogLevel::error, L"FlushInstructionCache(remote stub)", error);
    } else {
        // Targets that enforce W^X (Firefox) silently refuse threads started on writable+executable
        // pages, so the stub becomes read+execute before the thread starts.
        DWORD previous = 0;
        if (!VirtualProtectEx(process, stub_memory, kStubRegionSize, PAGE_EXECUTE_READ, &previous)) {
            error = GetLastError();
            log_last_error(LogLevel::error, L"VirtualProtectEx(remote stub)", error);
        } else {
            HANDLE thread = remote_thread(process, stub_memory, nullptr, false, error);
            if (thread == nullptr) {
                log_last_error(LogLevel::error, L"CreateRemoteThread(remote call)", error);
            } else {
                const DWORD wait = WaitForSingleObject(thread, timeout_ms);
                if (wait == WAIT_OBJECT_0) {
                    DWORD thread_exit = 0;
                    if (GetExitCodeThread(thread, &thread_exit)) {
                        exit_code = thread_exit;
                        error = ERROR_SUCCESS;
                        success = true;
                    } else {
                        error = GetLastError();
                        log_last_error(LogLevel::error, L"GetExitCodeThread(remote call)", error);
                    }
                } else if (wait == WAIT_TIMEOUT) {
                    error = ERROR_TIMEOUT;
                    log_line(LogLevel::error, L"remote call timed out after %lu ms", timeout_ms);
                } else {
                    error = GetLastError();
                    log_last_error(LogLevel::error, L"WaitForSingleObject(remote call)", error);
                }
                CloseHandle(thread);
            }
        }
    }

    DWORD free_error = ERROR_SUCCESS;
    if (!remote_free(process, stub_memory, free_error)) {
        log_last_error(LogLevel::warn, L"VirtualFreeEx(remote stub)", free_error);
    }
    return success;
}

bool remote_load_library(DWORD pid, HANDLE process, const std::wstring& module_path,
                         DWORD timeout_ms, DWORD& error) {
    const SIZE_T path_bytes = (module_path.size() + 1) * sizeof(wchar_t);
    void* const remote_path = remote_alloc(process, path_bytes, PAGE_READWRITE, error);
    if (remote_path == nullptr) {
        log_last_error(LogLevel::error, L"VirtualAllocEx(import path)", error);
        return false;
    }

    bool success = false;
    DWORD call_error = ERROR_SUCCESS;
    if (!remote_write(process, remote_path, module_path.c_str(), path_bytes, call_error)) {
        log_last_error(LogLevel::error, L"WriteProcessMemory(import path)", call_error);
    } else {
        void* const load_library = remote_export(pid, L"kernel32.dll", "LoadLibraryW", call_error);
        if (load_library == nullptr) {
            log_last_error(LogLevel::error, L"Resolve LoadLibraryW", call_error);
        } else {
            HANDLE thread = remote_thread(process, load_library, remote_path, false, call_error);
            if (thread == nullptr) {
                log_last_error(LogLevel::error, L"CreateRemoteThread(LoadLibraryW)", call_error);
            } else {
                const DWORD wait = WaitForSingleObject(thread, timeout_ms);
                if (wait == WAIT_OBJECT_0) {
                    DWORD exit_code = 0;
                    if (GetExitCodeThread(thread, &exit_code)) {
                        if (exit_code != 0) {
                            success = true;
                        } else {
                            call_error = ERROR_MOD_NOT_FOUND;
                            log_line(LogLevel::error, L"target LoadLibraryW(\"%ls\") returned NULL",
                                     module_path.c_str());
                        }
                    } else {
                        call_error = GetLastError();
                        log_last_error(LogLevel::error, L"GetExitCodeThread(LoadLibraryW)", call_error);
                    }
                } else if (wait == WAIT_TIMEOUT) {
                    call_error = ERROR_TIMEOUT;
                    log_line(LogLevel::error, L"LoadLibraryW timed out after %lu ms", timeout_ms);
                } else {
                    call_error = GetLastError();
                    log_last_error(LogLevel::error, L"WaitForSingleObject(LoadLibraryW)", call_error);
                }
                CloseHandle(thread);
            }
        }
    }

    DWORD free_error = ERROR_SUCCESS;
    if (!remote_free(process, remote_path, free_error)) {
        log_last_error(LogLevel::warn, L"VirtualFreeEx(import path)", free_error);
    }
    error = call_error;
    return success;
}
