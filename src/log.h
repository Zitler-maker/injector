#pragma once

#include <windows.h>

enum class LogLevel {
    info,
    warn,
    error
};

void log_line(LogLevel level, const wchar_t* format, ...);
void log_last_error(LogLevel level, const wchar_t* call, DWORD code);
const wchar_t* win32_message(DWORD code);

// Receives the fully formatted line (including the level tag). May be called from any thread.
using log_sink_fn = void (*)(LogLevel level, const wchar_t* line);
void log_set_sink(log_sink_fn sink);
