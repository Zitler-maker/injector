#pragma once

#include <windows.h>

#include <string>

enum class InjectMethod {
    crt,
    nt_crt,
    manual_map
};

const wchar_t* inject_method_name(InjectMethod method);

bool inject_into_process(InjectMethod method, DWORD pid, const std::wstring& dll_path,
                         DWORD timeout_ms, DWORD& error);
