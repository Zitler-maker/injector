#include "inject_crt.h"

#include "log.h"
#include "remote.h"

bool inject_load_library(HANDLE process, DWORD pid, const std::wstring& dll_path,
                         bool use_nt_create_thread_ex, DWORD timeout_ms, DWORD& error) {
    const SIZE_T path_bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    void* const remote_path = remote_alloc(process, path_bytes, PAGE_READWRITE, error);
    if (remote_path == nullptr) {
        log_last_error(LogLevel::error, L"VirtualAllocEx(dll path)", error);
        return false;
    }

    bool success = false;
    if (!remote_write(process, remote_path, dll_path.c_str(), path_bytes, error)) {
        log_last_error(LogLevel::error, L"WriteProcessMemory(dll path)", error);
    } else {
        void* const load_library = remote_export(pid, L"kernel32.dll", "LoadLibraryW", error);
        if (load_library == nullptr) {
            log_last_error(LogLevel::error, L"Resolve LoadLibraryW", error);
        } else {
            HANDLE thread = remote_thread(process, load_library, remote_path, use_nt_create_thread_ex, error);
            if (thread == nullptr) {
                log_last_error(LogLevel::error,
                               use_nt_create_thread_ex ? L"NtCreateThreadEx" : L"CreateRemoteThread",
                               error);
            } else {
                const DWORD wait = WaitForSingleObject(thread, timeout_ms);
                if (wait == WAIT_OBJECT_0) {
                    DWORD exit_code = 0;
                    if (!GetExitCodeThread(thread, &exit_code)) {
                        error = GetLastError();
                        log_last_error(LogLevel::error, L"GetExitCodeThread", error);
                    } else if (exit_code == 0) {
                        error = ERROR_DLL_INIT_FAILED;
                        log_line(LogLevel::error,
                                 L"LoadLibraryW returned NULL in target (exit code 0); "
                                 L"path or dependencies are invalid");
                    } else {
                        error = ERROR_SUCCESS;
                        success = true;
                    }
                } else if (wait == WAIT_TIMEOUT) {
                    error = ERROR_TIMEOUT;
                    log_line(LogLevel::error, L"thread wait timed out after %lu ms", timeout_ms);
                } else {
                    error = GetLastError();
                    log_last_error(LogLevel::error, L"WaitForSingleObject", error);
                }
                CloseHandle(thread);
            }
        }
    }

    DWORD free_error = ERROR_SUCCESS;
    if (!remote_free(process, remote_path, free_error)) {
        log_last_error(LogLevel::warn, L"VirtualFreeEx(dll path)", free_error);
    }
    return success;
}
