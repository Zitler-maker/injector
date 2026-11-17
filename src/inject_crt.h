#pragma once

#include <windows.h>

#include <string>

bool inject_load_library(HANDLE process, DWORD pid, const std::wstring& dll_path,
                         bool use_nt_create_thread_ex, DWORD timeout_ms, DWORD& error);
