#pragma once

#include <windows.h>

#include <string>

bool inject_manual_map(HANDLE process, DWORD pid, const std::wstring& dll_path, DWORD timeout_ms,
                       DWORD& error);
