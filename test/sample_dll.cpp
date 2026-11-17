#include <windows.h>

#include <cstdio>
#include <string>

namespace {

constexpr int kPingValue = 0x5A17;

std::wstring describe_target(HMODULE module) {
    wchar_t exe_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    wchar_t message[1024]{};
    swprintf_s(message,
               L"sample_dll injected\n\n"
               L"process: %ls\n"
               L"pid: %lu\n"
               L"module base: %p",
               exe_path, GetCurrentProcessId(), module);
    return std::wstring(message);
}

void write_marker(HMODULE module) {
    wchar_t temp_path[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temp_path);
    if (length == 0 || length >= MAX_PATH) {
        return;
    }

    wchar_t marker_path[MAX_PATH]{};
    swprintf_s(marker_path, L"%lsinjected_%lu.txt", temp_path, GetCurrentProcessId());

    wchar_t exe_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    FILE* file = nullptr;
    if (_wfopen_s(&file, marker_path, L"wb") != 0 || file == nullptr) {
        return;
    }
    fwprintf(file, L"path: %ls\npid: %lu\nbase: %p\n", exe_path, GetCurrentProcessId(), module);
    fclose(file);
}

DWORD WINAPI notify_thread(LPVOID context) {
    const auto* text = static_cast<std::wstring*>(context);
    MessageBoxW(nullptr, text->c_str(), L"sample_dll", MB_OK | MB_ICONINFORMATION | MB_TOPMOST |
                                                       MB_SETFOREGROUND);
    delete text;
    return 0;
}

} // namespace

extern "C" __declspec(dllexport) int sample_ping(void) {
    return kPingValue;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        write_marker(instance);
        auto* text = new std::wstring(describe_target(instance));
        HANDLE thread = CreateThread(nullptr, 0, notify_thread, text, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        } else {
            delete text;
        }
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
