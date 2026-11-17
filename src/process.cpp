#include "process.h"

#include <tlhelp32.h>

#include <cwchar>

namespace {

std::wstring stem_of(const std::wstring& name) {
    const size_t dot = name.find_last_of(L'.');
    return dot == std::wstring::npos ? name : name.substr(0, dot);
}

} // namespace

bool list_processes(std::vector<process_entry>& out, DWORD& error) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        error = GetLastError();
        CloseHandle(snapshot);
        return false;
    }

    do {
        out.push_back(process_entry{entry.th32ProcessID, std::wstring(entry.szExeFile)});
    } while (Process32NextW(snapshot, &entry));

    const DWORD last = GetLastError();
    CloseHandle(snapshot);
    if (last != ERROR_NO_MORE_FILES) {
        error = last;
        return false;
    }
    error = ERROR_SUCCESS;
    return true;
}

std::vector<DWORD> find_processes_by_name(const std::wstring& name, DWORD& error) {
    std::vector<process_entry> all;
    std::vector<DWORD> result;
    if (!list_processes(all, error)) {
        return result;
    }

    const bool has_extension = name.find(L'.') != std::wstring::npos;
    for (const process_entry& entry : all) {
        const bool matches = _wcsicmp(entry.name.c_str(), name.c_str()) == 0 ||
                             (!has_extension && _wcsicmp(stem_of(entry.name).c_str(), name.c_str()) == 0);
        if (matches) {
            result.push_back(entry.pid);
        }
    }
    error = ERROR_SUCCESS;
    return result;
}

bool enable_debug_privilege(DWORD& error) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        error = GetLastError();
        return false;
    }

    LUID luid{};
    bool enabled = false;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        error = GetLastError();
    } else {
        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        SetLastError(ERROR_SUCCESS);
        if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
            error = GetLastError();
        } else if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
            error = ERROR_NOT_ALL_ASSIGNED;
        } else {
            error = ERROR_SUCCESS;
            enabled = true;
        }
    }

    CloseHandle(token);
    return enabled;
}

HANDLE open_process_for_injection(DWORD pid, DWORD& error) {
    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                     PROCESS_VM_READ | PROCESS_QUERY_INFORMATION |
                                     PROCESS_SET_INFORMATION,
                                 FALSE, pid);
    error = process ? ERROR_SUCCESS : GetLastError();
    return process;
}
