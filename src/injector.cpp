#include "inject_api.h"
#include "log.h"
#include "process.h"

#include <windows.h>

#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

constexpr DWORD kDefaultTimeoutMs = 10000;
constexpr DWORD kMinTimeoutMs = 1000;
constexpr DWORD kMaxTimeoutMs = 600000;
constexpr DWORD kMaxPathChars = 32767;
constexpr int kExitOk = 0;
constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;

enum class method {
    crt,
    nt_crt,
    manual_map
};

struct options {
    bool show_help = false;
    bool list = false;
    bool valid = true;
    bool has_pid = false;
    std::wstring parse_error;
    DWORD pid = 0;
    std::wstring name;
    std::wstring dll;
    InjectMethod injection_method = InjectMethod::crt;
    DWORD timeout_ms = kDefaultTimeoutMs;
};

void print_stdout(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    va_list counter;
    va_copy(counter, args);
    const int length = _vscwprintf(format, counter);
    va_end(counter);
    if (length < 0) {
        va_end(args);
        return;
    }
    std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1);
    vswprintf(buffer.data(), buffer.size(), format, args);
    va_end(args);

    const int needed = WideCharToMultiByte(CP_UTF8, 0, buffer.data(), length, nullptr, 0, nullptr,
                                           nullptr);
    if (needed <= 0) {
        return;
    }
    std::vector<char> utf8(static_cast<size_t>(needed));
    WideCharToMultiByte(CP_UTF8, 0, buffer.data(), length, utf8.data(), needed, nullptr, nullptr);
    fwrite(utf8.data(), 1, utf8.size(), stdout);
    fflush(stdout);
}

void print_usage() {
    print_stdout(L"injector - x64 DLL injector\n"
                 L"\n"
                 L"usage: injector --dll=<path> (--pid=<pid> | --name=<image>) [--method=crt|ntcrt|manualmap]\n"
                 L"                [--timeout=<ms>]\n"
                 L"       injector --list\n"
                 L"       injector --help\n"
                 L"\n"
                 L"options:\n"
                 L"  --dll=<path>     absolute or relative path to the x64 DLL (required)\n"
                 L"  --pid=<pid>      target process id\n"
                 L"  --name=<image>   target image name, e.g. game.exe; all matches are injected\n"
                 L"  --method=<m>     crt (CreateRemoteThread+LoadLibraryW), ntcrt (NtCreateThreadEx+\n"
                 L"                   LoadLibraryW) or manualmap (manual PE mapping)\n"
                 L"  --timeout=<ms>   timeout for remote thread wait, default 10000\n"
                 L"  --list           list running processes sorted by image name\n"
                 L"  --help           show this help\n"
                 L"\n"
                 L"Read as: --timeout is milliseconds; --method defaults to crt.\n");
}

bool parse_dword(const std::wstring& text, DWORD& out) {
    if (text.empty()) {
        return false;
    }
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long value = wcstoul(text.c_str(), &end, 10);
    if (errno != 0 || end == nullptr || *end != L'\0' || value == 0) {
        return false;
    }
    out = static_cast<DWORD>(value);
    return true;
}

bool parse_method(const std::wstring& text, InjectMethod& out) {
    if (text == L"crt") {
        out = InjectMethod::crt;
        return true;
    }
    if (text == L"ntcrt") {
        out = InjectMethod::nt_crt;
        return true;
    }
    if (text == L"manualmap") {
        out = InjectMethod::manual_map;
        return true;
    }
    return false;
}

options parse_options(int argc, wchar_t** argv) {
    options result;
    for (int index = 1; index < argc; ++index) {
        const std::wstring argument = argv[index];
        if (argument == L"--help" || argument == L"-h") {
            result.show_help = true;
        } else if (argument == L"--list") {
            result.list = true;
        } else if (argument.rfind(L"--pid=", 0) == 0) {
            if (!parse_dword(argument.substr(6), result.pid)) {
                result.valid = false;
                result.parse_error = L"invalid --pid value: " + argument.substr(6);
            } else {
                result.has_pid = true;
            }
        } else if (argument.rfind(L"--name=", 0) == 0) {
            result.name = argument.substr(7);
            if (result.name.empty()) {
                result.valid = false;
                result.parse_error = L"--name requires a value";
            }
        } else if (argument.rfind(L"--dll=", 0) == 0) {
            result.dll = argument.substr(6);
            if (result.dll.empty()) {
                result.valid = false;
                result.parse_error = L"--dll requires a value";
            }
        } else if (argument.rfind(L"--method=", 0) == 0) {
            if (!parse_method(argument.substr(9), result.injection_method)) {
                result.valid = false;
                result.parse_error = L"invalid --method value: " + argument.substr(9);
            }
        } else if (argument.rfind(L"--timeout=", 0) == 0) {
            DWORD timeout = 0;
            if (!parse_dword(argument.substr(10), timeout) || timeout < kMinTimeoutMs ||
                timeout > kMaxTimeoutMs) {
                result.valid = false;
                result.parse_error = L"--timeout must be in range 1000..600000 ms";
            } else {
                result.timeout_ms = timeout;
            }
        } else {
            result.valid = false;
            result.parse_error = L"unknown argument: " + argument;
        }
    }
    return result;
}

bool to_full_path(const std::wstring& input, std::wstring& out, DWORD& error) {
    std::vector<wchar_t> buffer(kMaxPathChars + 1);
    const DWORD written = GetFullPathNameW(input.c_str(), static_cast<DWORD>(buffer.size()),
                                           buffer.data(), nullptr);
    if (written == 0) {
        error = GetLastError();
        return false;
    }
    if (written >= buffer.size()) {
        error = ERROR_BUFFER_OVERFLOW;
        return false;
    }
    out.assign(buffer.data(), written);
    error = ERROR_SUCCESS;
    return true;
}

bool run_injection(const options& opts, DWORD pid, const std::wstring& dll, DWORD& error) {
    return inject_into_process(opts.injection_method, pid, dll, opts.timeout_ms, error);
}

int run_list() {
    std::vector<process_entry> entries;
    DWORD error = ERROR_SUCCESS;
    if (!list_processes(entries, error)) {
        log_last_error(LogLevel::error, L"process enumeration", error);
        return kExitFailure;
    }

    std::sort(entries.begin(), entries.end(), [](const process_entry& left, const process_entry& right) {
        const int order = _wcsicmp(left.name.c_str(), right.name.c_str());
        return order != 0 ? order < 0 : left.pid < right.pid;
    });

    for (const process_entry& entry : entries) {
        print_stdout(L"%6lu  %ls\n", entry.pid, entry.name.c_str());
    }
    return kExitOk;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        print_usage();
        return kExitUsage;
    }

    const options opts = parse_options(argc, argv);
    if (opts.show_help) {
        print_usage();
        return kExitOk;
    }
    if (!opts.valid) {
        log_line(LogLevel::error, L"%ls", opts.parse_error.c_str());
        print_usage();
        return kExitUsage;
    }
    if (opts.list) {
        return run_list();
    }

    if (opts.dll.empty()) {
        log_line(LogLevel::error, L"--dll is required");
        print_usage();
        return kExitUsage;
    }
    if (opts.has_pid == !opts.name.empty()) {
        log_line(LogLevel::error, L"specify exactly one of --pid or --name");
        print_usage();
        return kExitUsage;
    }

    std::wstring dll_full_path;
    DWORD path_error = ERROR_SUCCESS;
    if (!to_full_path(opts.dll, dll_full_path, path_error)) {
        log_last_error(LogLevel::error, L"GetFullPathNameW", path_error);
        return kExitFailure;
    }
    const DWORD attributes = GetFileAttributesW(dll_full_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        path_error = GetLastError();
        log_last_error(LogLevel::error, L"GetFileAttributesW(dll)", path_error);
        return kExitFailure;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        log_line(LogLevel::error, L"%ls is a directory", dll_full_path.c_str());
        return kExitFailure;
    }

    DWORD privilege_error = ERROR_SUCCESS;
    if (!enable_debug_privilege(privilege_error)) {
        log_last_error(LogLevel::warn, L"SeDebugPrivilege", privilege_error);
        log_line(LogLevel::warn, L"continuing without SeDebugPrivilege; protected targets may fail");
    }

    std::vector<DWORD> targets;
    if (opts.has_pid) {
        targets.push_back(opts.pid);
    } else {
        DWORD search_error = ERROR_SUCCESS;
        targets = find_processes_by_name(opts.name, search_error);
        if (targets.empty()) {
            log_line(LogLevel::error, L"no running process matches image name %ls",
                     opts.name.c_str());
            return kExitFailure;
        }
        log_line(LogLevel::info, L"%zu process(es) match %ls", targets.size(), opts.name.c_str());
    }

    log_line(LogLevel::info, L"dll: %ls", dll_full_path.c_str());
    log_line(LogLevel::info, L"method: %ls, timeout: %lu ms", inject_method_name(opts.injection_method),
             opts.timeout_ms);

    size_t succeeded = 0;
    for (const DWORD pid : targets) {
        DWORD error = ERROR_SUCCESS;
        const bool ok = run_injection(opts, pid, dll_full_path, error);
        if (ok) {
            ++succeeded;
            log_line(LogLevel::info, L"[OK] pid=%lu method=%ls dll=%ls", pid,
                     inject_method_name(opts.injection_method), dll_full_path.c_str());
        } else {
            log_line(LogLevel::error, L"[FAIL] pid=%lu method=%ls error=%lu (%ls)", pid,
                     inject_method_name(opts.injection_method), error, win32_message(error));
        }
    }

    const size_t failed = targets.size() - succeeded;
    log_line(failed == 0 ? LogLevel::info : LogLevel::error,
             L"summary: %zu target(s), %zu succeeded, %zu failed", targets.size(), succeeded, failed);
    return failed == 0 ? kExitOk : kExitFailure;
}
