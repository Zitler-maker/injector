#include "log.h"

#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>

namespace {

constexpr size_t kMessageBufferChars = 1024;

log_sink_fn g_sink = nullptr;

const wchar_t* level_tag(LogLevel level) {
    switch (level) {
    case LogLevel::info:
        return L"[INFO] ";
    case LogLevel::warn:
        return L"[WARN] ";
    case LogLevel::error:
        return L"[ERROR] ";
    }
    return L"[INFO] ";
}

void write_stderr_line(const std::wstring& text) {
    if (text.empty()) {
        return;
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return;
    }
    std::vector<char> utf8(static_cast<size_t>(needed));
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        utf8.data(), needed, nullptr, nullptr);
    fwrite(utf8.data(), 1, utf8.size(), stderr);
    fputc('\n', stderr);
    fflush(stderr);
}

std::wstring format_wide(const wchar_t* format, va_list args) {
    va_list counter;
    va_copy(counter, args);
    const int length = _vscwprintf(format, counter);
    va_end(counter);
    if (length < 0) {
        return std::wstring();
    }
    std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1);
    vswprintf(buffer.data(), buffer.size(), format, args);
    return std::wstring(buffer.data(), static_cast<size_t>(length));
}

} // namespace

void log_line(LogLevel level, const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    std::wstring body = format_wide(format, args);
    va_end(args);
    const std::wstring line = std::wstring(level_tag(level)) + body;
    write_stderr_line(line);
    if (g_sink != nullptr) {
        g_sink(level, line.c_str());
    }
}

void log_set_sink(log_sink_fn sink) {
    g_sink = sink;
}

const wchar_t* win32_message(DWORD code) {
    static thread_local wchar_t buffer[kMessageBufferChars];
    buffer[0] = L'\0';
    DWORD length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                  nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                  buffer, static_cast<DWORD>(kMessageBufferChars), nullptr);
    if (length == 0) {
        swprintf_s(buffer, L"unknown error");
        return buffer;
    }
    while (length > 0 && (buffer[length - 1] == L'\r' || buffer[length - 1] == L'\n' ||
                          buffer[length - 1] == L' ' || buffer[length - 1] == L'.')) {
        buffer[--length] = L'\0';
    }
    return buffer;
}

void log_last_error(LogLevel level, const wchar_t* call, DWORD code) {
    log_line(level, L"%ls failed: error %lu (%ls)", call, code, win32_message(code));
}
