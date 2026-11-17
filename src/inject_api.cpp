#include "inject_api.h"

#include "inject_crt.h"
#include "manualmap.h"
#include "process.h"

bool inject_into_process(InjectMethod method, DWORD pid, const std::wstring& dll_path,
                         DWORD timeout_ms, DWORD& error) {
    HANDLE process = open_process_for_injection(pid, error);
    if (process == nullptr) {
        return false;
    }

    bool success = false;
    switch (method) {
    case InjectMethod::crt:
        success = inject_load_library(process, pid, dll_path, false, timeout_ms, error);
        break;
    case InjectMethod::nt_crt:
        success = inject_load_library(process, pid, dll_path, true, timeout_ms, error);
        break;
    case InjectMethod::manual_map:
        success = inject_manual_map(process, pid, dll_path, timeout_ms, error);
        break;
    }

    CloseHandle(process);
    return success;
}

const wchar_t* inject_method_name(InjectMethod method) {
    switch (method) {
    case InjectMethod::crt:
        return L"crt";
    case InjectMethod::nt_crt:
        return L"ntcrt";
    case InjectMethod::manual_map:
        return L"manualmap";
    }
    return L"crt";
}
