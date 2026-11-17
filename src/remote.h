#pragma once

#include <windows.h>

#include <string>

void* remote_alloc(HANDLE process, SIZE_T size, DWORD protect, DWORD& error);
bool remote_free(HANDLE process, void* remote_memory, DWORD& error);
bool remote_write(HANDLE process, void* remote_destination, const void* source, SIZE_T size, DWORD& error);
bool remote_read(HANDLE process, void* destination, const void* remote_source, SIZE_T size, DWORD& error);

void* remote_module_base(DWORD pid, const wchar_t* module_name, DWORD& error);
void* remote_export(DWORD pid, const wchar_t* module_name, const char* proc_name, DWORD& error);
void* remote_export_ordinal(DWORD pid, const wchar_t* module_name, WORD ordinal, DWORD& error);

bool remote_load_library(DWORD pid, HANDLE process, const std::wstring& module_path,
                         DWORD timeout_ms, DWORD& error);

HANDLE remote_thread(HANDLE process, void* start, void* parameter, bool use_nt_create_thread_ex,
                     DWORD& error);
bool remote_call(HANDLE process, void* function, void* arg1, void* arg2, void* arg3,
                 DWORD timeout_ms, DWORD& exit_code, DWORD& error);
