#pragma once

#include <windows.h>

#include <string>
#include <vector>

struct process_entry {
    DWORD pid = 0;
    std::wstring name;
};

bool list_processes(std::vector<process_entry>& out, DWORD& error);
std::vector<DWORD> find_processes_by_name(const std::wstring& name, DWORD& error);
bool enable_debug_privilege(DWORD& error);
HANDLE open_process_for_injection(DWORD pid, DWORD& error);
