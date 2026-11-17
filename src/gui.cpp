#include "inject_api.h"
#include "log.h"
#include "process.h"

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace {

extern "C" const unsigned char kEmbeddedSampleDll[];
extern "C" const std::size_t kEmbeddedSampleDll_size;

constexpr wchar_t kWindowClass[] = L"injector_gui_window";
constexpr int kIconResourceId = 101;

constexpr int kIdFilter = 1001;
constexpr int kIdRefresh = 1002;
constexpr int kIdList = 1003;
constexpr int kIdDll = 1004;
constexpr int kIdBrowse = 1005;
constexpr int kIdMethod = 1006;
constexpr int kIdTimeout = 1007;
constexpr int kIdInject = 1008;
constexpr int kIdLog = 1009;
constexpr int kIdLanguage = 1010;
constexpr int kIdLabelFilter = 1101;
constexpr int kIdLabelDll = 1102;
constexpr int kIdLabelMethod = 1103;
constexpr int kIdLabelTimeout = 1104;

constexpr UINT kMsgLog = WM_APP + 1;
constexpr UINT kMsgDone = WM_APP + 2;

constexpr DWORD kDefaultTimeoutMs = 10000;
constexpr DWORD kMinTimeoutMs = 1000;
constexpr DWORD kMaxTimeoutMs = 600000;
constexpr int kMaxLogChars = 200000;
constexpr const wchar_t* kLanguageRegistryKey = L"Software\\DLLInjector";
constexpr const wchar_t* kLanguageRegistryValue = L"Language";

enum class Lang {
    ru,
    en
};

enum class Str {
    app_title,
    label_filter,
    button_refresh,
    label_dll,
    button_browse,
    label_method,
    label_timeout,
    button_inject,
    column_pid,
    column_process,
    method_crt,
    method_ntcrt,
    method_manualmap,
    hint_start,
    warn_select_process,
    warn_choose_dll,
    err_timeout_range,
    err_directory,
    done_ok,
    done_fail,
    log_embedded,
    log_extract_failed,
    count
};

struct translation {
    const wchar_t* ru;
    const wchar_t* en;
};

constexpr translation kTranslations[] = {
    {L"DLL-инжектор x64", L"DLL Injector x64"},
    {L"Фильтр:", L"Filter:"},
    {L"Обновить", L"Refresh"},
    {L"DLL:", L"DLL:"},
    {L"Обзор...", L"Browse..."},
    {L"Метод:", L"Method:"},
    {L"Таймаут (мс):", L"Timeout (ms):"},
    {L"Внедрить", L"Inject"},
    {L"PID", L"PID"},
    {L"Процесс", L"Process"},
    {L"crt — CreateRemoteThread + LoadLibraryW", L"crt — CreateRemoteThread + LoadLibraryW"},
    {L"ntcrt — NtCreateThreadEx + LoadLibraryW", L"ntcrt — NtCreateThreadEx + LoadLibraryW"},
    {L"manualmap — ручной PE-маппинг", L"manualmap — manual PE mapping"},
    {L"выберите процесс, укажите DLL и нажмите «Внедрить»",
     L"select a process, choose the DLL and press Inject"},
    {L"сначала выберите процесс в списке", L"select a process in the list first"},
    {L"укажите путь к DLL", L"specify the DLL path"},
    {L"таймаут должен быть числом в диапазоне %lu..%lu мс",
     L"timeout must be a number in the range %lu..%lu ms"},
    {L"%ls — это каталог, а не DLL", L"%ls is a directory, not a DLL"},
    {L"внедрение завершено успешно", L"injection completed successfully"},
    {L"внедрение завершилось с ошибкой", L"injection failed"},
    {L"встроенная тестовая DLL распакована в %ls", L"bundled sample DLL extracted to %ls"},
    {L"не удалось распаковать встроенную DLL", L"failed to extract the bundled DLL"},
};

constexpr size_t kTranslationCount = static_cast<size_t>(Str::count);

static_assert(std::size(kTranslations) == kTranslationCount,
              "translation table size must match the Str enum");

Lang g_language = Lang::ru;

const wchar_t* tr(Str id) {
    const translation& entry = kTranslations[static_cast<size_t>(id)];
    return g_language == Lang::ru ? entry.ru : entry.en;
}

void load_language() {
    DWORD value = 0;
    DWORD size = sizeof(value);
    if (RegGetValueW(HKEY_CURRENT_USER, kLanguageRegistryKey, kLanguageRegistryValue,
                     RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS) {
        if (value == static_cast<DWORD>(Lang::en)) {
            g_language = Lang::en;
        } else if (value == static_cast<DWORD>(Lang::ru)) {
            g_language = Lang::ru;
        }
    }
}

void save_language() {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kLanguageRegistryKey, 0, nullptr, 0, KEY_SET_VALUE,
                        nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return;
    }
    const DWORD value = static_cast<DWORD>(g_language);
    RegSetValueExW(key, kLanguageRegistryValue, 0, REG_DWORD,
                   reinterpret_cast<const BYTE*>(&value), sizeof(value));
    RegCloseKey(key);
}

HWND g_window = nullptr;
HWND g_label_filter = nullptr;
HWND g_filter = nullptr;
HWND g_refresh = nullptr;
HWND g_list = nullptr;
HWND g_label_dll = nullptr;
HWND g_dll = nullptr;
HWND g_browse = nullptr;
HWND g_label_method = nullptr;
HWND g_method = nullptr;
HWND g_label_timeout = nullptr;
HWND g_timeout = nullptr;
HWND g_inject = nullptr;
HWND g_log = nullptr;
HWND g_language_combo = nullptr;
HFONT g_font = nullptr;
bool g_busy = false;
int g_dpi = 96;
std::vector<process_entry> g_processes;

int scaled(int value) {
    return MulDiv(value, g_dpi, 96);
}

struct injection_job {
    InjectMethod method = InjectMethod::crt;
    DWORD pid = 0;
    std::wstring dll;
    DWORD timeout_ms = kDefaultTimeoutMs;
};

struct injection_result {
    bool success = false;
    InjectMethod method = InjectMethod::crt;
    DWORD pid = 0;
    std::wstring dll;
    DWORD error = ERROR_SUCCESS;
};

void log_sink(LogLevel, const wchar_t* line) {
    HWND window = g_window;
    if (window == nullptr || !IsWindow(window)) {
        return;
    }
    auto* copy = new std::wstring(line);
    if (!PostMessageW(window, kMsgLog, 0, reinterpret_cast<LPARAM>(copy))) {
        delete copy;
    }
}

std::wstring window_text(HWND control) {
    const int length = GetWindowTextLengthW(control);
    if (length <= 0) {
        return std::wstring();
    }
    std::wstring text(static_cast<size_t>(length), L'\0');
    GetWindowTextW(control, text.data(), length + 1);
    return text;
}

std::wstring trim(const std::wstring& text) {
    const size_t first = text.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) {
        return std::wstring();
    }
    const size_t last = text.find_last_not_of(L" \t\r\n");
    return text.substr(first, last - first + 1);
}

HMENU control_id(int id) {
    return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id));
}

void append_log_line(const std::wstring& text) {
    if (GetWindowTextLengthW(g_log) > kMaxLogChars) {
        SetWindowTextW(g_log, L"");
    }
    SendMessageW(g_log, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
    SendMessageW(g_log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L"\r\n"));
}

DWORD selected_pid() {
    const int index = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (index < 0) {
        return 0;
    }
    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = index;
    if (!ListView_GetItem(g_list, &item)) {
        return 0;
    }
    return static_cast<DWORD>(item.lParam);
}

void set_column_text(int column, const wchar_t* text) {
    LVCOLUMNW info{};
    info.mask = LVCF_TEXT;
    info.pszText = const_cast<wchar_t*>(text);
    ListView_SetColumn(g_list, column, &info);
}

void populate_process_list() {
    ListView_DeleteAllItems(g_list);

    std::wstring filter = window_text(g_filter);
    CharLowerBuffW(filter.data(), static_cast<DWORD>(filter.size()));

    int row = 0;
    for (const process_entry& entry : g_processes) {
        if (!filter.empty()) {
            std::wstring name = entry.name;
            CharLowerBuffW(name.data(), static_cast<DWORD>(name.size()));
            if (name.find(filter) == std::wstring::npos) {
                continue;
            }
        }

        const std::wstring pid_text = std::to_wstring(entry.pid);
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = row;
        item.pszText = const_cast<wchar_t*>(pid_text.c_str());
        item.lParam = static_cast<LPARAM>(entry.pid);
        const int inserted = ListView_InsertItem(g_list, &item);
        if (inserted < 0) {
            break;
        }
        ListView_SetItemText(g_list, inserted, 1, const_cast<wchar_t*>(entry.name.c_str()));
        ++row;
    }

    if (!filter.empty() && row > 0) {
        ListView_SetItemState(g_list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(g_list, 0, FALSE);
    }
}

void load_processes() {
    std::vector<process_entry> entries;
    DWORD error = ERROR_SUCCESS;
    if (!list_processes(entries, error)) {
        log_last_error(LogLevel::error, L"process enumeration", error);
        return;
    }

    std::sort(entries.begin(), entries.end(), [](const process_entry& left, const process_entry& right) {
        const int order = _wcsicmp(left.name.c_str(), right.name.c_str());
        return order != 0 ? order < 0 : left.pid < right.pid;
    });

    g_processes = std::move(entries);
    populate_process_list();
}

void browse_for_dll(HWND owner) {
    std::vector<wchar_t> file(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner;
    dialog.lpstrFilter = L"DLL (*.dll)\0*.dll\0All files (*.*)\0*.*\0";
    dialog.lpstrFile = file.data();
    dialog.nMaxFile = static_cast<DWORD>(file.size());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&dialog)) {
        SetWindowTextW(g_dll, file.data());
    }
}

bool parse_timeout(const std::wstring& text, DWORD& out) {
    if (text.empty()) {
        return false;
    }
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long value = wcstoul(text.c_str(), &end, 10);
    if (errno != 0 || end == nullptr || *end != L'\0' || value < kMinTimeoutMs ||
        value > kMaxTimeoutMs) {
        return false;
    }
    out = static_cast<DWORD>(value);
    return true;
}

bool extract_embedded_sample_dll(std::wstring& out, DWORD& error) {
    wchar_t temp_path[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temp_path);
    if (length == 0 || length >= MAX_PATH) {
        error = length == 0 ? GetLastError() : ERROR_BUFFER_OVERFLOW;
        return false;
    }

    wchar_t file_name[MAX_PATH]{};
    swprintf_s(file_name, L"%lsinjector_sample_%lu.dll", temp_path, GetCurrentProcessId());
    out = file_name;

    HANDLE file = CreateFileW(out.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }

    DWORD written = 0;
    const DWORD size = static_cast<DWORD>(kEmbeddedSampleDll_size);
    if (!WriteFile(file, kEmbeddedSampleDll, size, &written, nullptr) || written != size) {
        error = GetLastError();
        CloseHandle(file);
        DeleteFileW(out.c_str());
        return false;
    }
    CloseHandle(file);
    error = ERROR_SUCCESS;
    return true;
}

DWORD WINAPI injection_thread(LPVOID parameter) {
    auto* job = static_cast<injection_job*>(parameter);
    DWORD error = ERROR_SUCCESS;
    const bool success = inject_into_process(job->method, job->pid, job->dll, job->timeout_ms, error);

    if (success) {
        log_line(LogLevel::info, L"[OK] pid=%lu method=%ls dll=%ls", job->pid,
                 inject_method_name(job->method), job->dll.c_str());
    } else {
        log_line(LogLevel::error, L"[FAIL] pid=%lu method=%ls error=%lu (%ls)", job->pid,
                 inject_method_name(job->method), error, win32_message(error));
    }

    auto* result = new injection_result{success, job->method, job->pid, job->dll, error};
    HWND window = g_window;
    if (window == nullptr || !PostMessageW(window, kMsgDone, 0, reinterpret_cast<LPARAM>(result))) {
        delete result;
    }
    delete job;
    return 0;
}

void start_injection() {
    if (g_busy) {
        return;
    }

    const DWORD pid = selected_pid();
    if (pid == 0) {
        log_line(LogLevel::warn, L"%ls", tr(Str::warn_select_process));
        SetFocus(g_list);
        return;
    }

    const std::wstring dll_input = trim(window_text(g_dll));
    if (dll_input.empty()) {
        log_line(LogLevel::warn, L"%ls", tr(Str::warn_choose_dll));
        SetFocus(g_dll);
        return;
    }

    DWORD timeout_ms = kDefaultTimeoutMs;
    if (!parse_timeout(trim(window_text(g_timeout)), timeout_ms)) {
        log_line(LogLevel::error, tr(Str::err_timeout_range), kMinTimeoutMs, kMaxTimeoutMs);
        SetFocus(g_timeout);
        return;
    }

    std::vector<wchar_t> full_path(32768, L'\0');
    if (GetFullPathNameW(dll_input.c_str(), static_cast<DWORD>(full_path.size()), full_path.data(),
                         nullptr) == 0) {
        log_last_error(LogLevel::error, L"GetFullPathNameW", GetLastError());
        return;
    }
    const std::wstring dll_path = full_path.data();

    const DWORD attributes = GetFileAttributesW(dll_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        log_last_error(LogLevel::error, L"GetFileAttributesW(dll)", GetLastError());
        return;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        log_line(LogLevel::error, tr(Str::err_directory), dll_path.c_str());
        return;
    }

    const int method_index = static_cast<int>(SendMessageW(g_method, CB_GETCURSEL, 0, 0));
    const InjectMethod method = method_index == 1   ? InjectMethod::nt_crt
                                : method_index == 2 ? InjectMethod::manual_map
                                                    : InjectMethod::crt;

    DWORD privilege_error = ERROR_SUCCESS;
    if (!enable_debug_privilege(privilege_error)) {
        log_last_error(LogLevel::warn, L"SeDebugPrivilege", privilege_error);
    }

    log_line(LogLevel::info, L"---");
    log_line(LogLevel::info, L"target pid: %lu, method: %ls, timeout: %lu ms", pid,
             inject_method_name(method), timeout_ms);
    log_line(LogLevel::info, L"dll: %ls", dll_path.c_str());

    auto* job = new injection_job{method, pid, dll_path, timeout_ms};
    g_busy = true;
    EnableWindow(g_inject, FALSE);

    HANDLE thread = CreateThread(nullptr, 0, injection_thread, job, 0, nullptr);
    if (thread == nullptr) {
        const DWORD error = GetLastError();
        delete job;
        g_busy = false;
        EnableWindow(g_inject, TRUE);
        log_last_error(LogLevel::error, L"CreateThread", error);
        return;
    }
    CloseHandle(thread);
}

void apply_language() {
    SetWindowTextW(g_window, tr(Str::app_title));
    SetWindowTextW(g_label_filter, tr(Str::label_filter));
    SetWindowTextW(g_refresh, tr(Str::button_refresh));
    SetWindowTextW(g_label_dll, tr(Str::label_dll));
    SetWindowTextW(g_browse, tr(Str::button_browse));
    SetWindowTextW(g_label_method, tr(Str::label_method));
    SetWindowTextW(g_label_timeout, tr(Str::label_timeout));
    SetWindowTextW(g_inject, tr(Str::button_inject));

    if (g_list != nullptr) {
        set_column_text(0, tr(Str::column_pid));
        set_column_text(1, tr(Str::column_process));
    }

    if (g_method != nullptr) {
        const int selected = static_cast<int>(SendMessageW(g_method, CB_GETCURSEL, 0, 0));
        SendMessageW(g_method, CB_RESETCONTENT, 0, 0);
        SendMessageW(g_method, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(tr(Str::method_crt)));
        SendMessageW(g_method, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(tr(Str::method_ntcrt)));
        SendMessageW(g_method, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(tr(Str::method_manualmap)));
        SendMessageW(g_method, CB_SETCURSEL, selected < 0 ? 0 : selected, 0);
    }

    if (g_language_combo != nullptr) {
        SendMessageW(g_language_combo, CB_SETCURSEL, static_cast<WPARAM>(g_language), 0);
    }
}

void create_controls(HWND window) {
    g_label_filter = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                    0, 0, 0, 0, window, control_id(kIdLabelFilter),
                                    nullptr, nullptr);
    g_filter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0,
                               window, control_id(kIdFilter), nullptr, nullptr);
    g_refresh = CreateWindowExW(0, L"BUTTON", L"",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0,
                                window, control_id(kIdRefresh), nullptr, nullptr);
    g_language_combo = CreateWindowExW(0, L"COMBOBOX", L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST |
                                           WS_VSCROLL,
                                       0, 0, 0, 0, window, control_id(kIdLanguage), nullptr,
                                       nullptr);
    SendMessageW(g_language_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Русский"));
    SendMessageW(g_language_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"English"));

    g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
                                 LVS_SHOWSELALWAYS,
                             0, 0, 0, 0, window, control_id(kIdList), nullptr, nullptr);
    ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<wchar_t*>(L"");
    column.cx = scaled(90);
    column.iSubItem = 0;
    ListView_InsertColumn(g_list, 0, &column);
    column.pszText = const_cast<wchar_t*>(L"");
    column.cx = scaled(400);
    column.iSubItem = 1;
    ListView_InsertColumn(g_list, 1, &column);

    g_label_dll = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0,
                                  0, window, control_id(kIdLabelDll), nullptr,
                                  nullptr);
    g_dll = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0,
                            window, control_id(kIdDll), nullptr, nullptr);
    g_browse = CreateWindowExW(0, L"BUTTON", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0,
                               window, control_id(kIdBrowse), nullptr, nullptr);

    g_label_method = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT, 0,
                                     0, 0, 0, window, control_id(kIdLabelMethod),
                                     nullptr, nullptr);
    g_method = CreateWindowExW(0, L"COMBOBOX", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST |
                                   WS_VSCROLL,
                               0, 0, 0, 0, window, control_id(kIdMethod), nullptr,
                               nullptr);
    SendMessageW(g_method, CB_SETDROPPEDWIDTH, 360, 0);

    g_label_timeout = CreateWindowExW(0, L"STATIC", L"",
                                      WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, window,
                                      control_id(kIdLabelTimeout), nullptr, nullptr);
    g_timeout = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"10000",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL,
                                0, 0, 0, 0, window, control_id(kIdTimeout), nullptr,
                                nullptr);

    g_inject = CreateWindowExW(0, L"BUTTON", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 0, 0, 0, 0,
                               window, control_id(kIdInject), nullptr, nullptr);

    g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY |
                                ES_AUTOVSCROLL,
                            0, 0, 0, 0, window, control_id(kIdLog), nullptr, nullptr);

    NONCLIENTMETRICSW metrics{};
    metrics.cbSize = sizeof(metrics);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0)) {
        g_font = CreateFontIndirectW(&metrics.lfMessageFont);
    }
    if (g_font == nullptr) {
        g_font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    }

    const HWND controls[] = {g_label_filter, g_filter, g_refresh, g_list,        g_label_dll,
                             g_dll,          g_browse, g_label_method, g_method,  g_label_timeout,
                             g_timeout,      g_inject, g_log,          g_language_combo};
    for (const HWND control : controls) {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
    }

    apply_language();
}

void layout_controls(HWND window) {
    RECT client{};
    GetClientRect(window, &client);
    const int width = client.right;
    const int height = client.bottom;

    const int margin = scaled(12);
    const int row = scaled(26);
    const int gap = scaled(8);
    const int button_width = scaled(100);
    const int language_width = scaled(110);

    MoveWindow(g_label_filter, margin, margin + scaled(5), scaled(60), scaled(20), TRUE);
    MoveWindow(g_language_combo, width - margin - language_width, margin, language_width,
               scaled(240), TRUE);

    const int filter_x = margin + scaled(64);
    const int refresh_x = width - margin - language_width - gap - button_width;
    MoveWindow(g_filter, filter_x, margin, refresh_x - filter_x - gap, row, TRUE);
    MoveWindow(g_refresh, refresh_x, margin, button_width, row, TRUE);

    const int list_y = margin + row + gap;
    const int list_h = std::max(scaled(140), (height * 42) / 100);
    MoveWindow(g_list, margin, list_y, width - 2 * margin, list_h, TRUE);
    ListView_SetColumnWidth(g_list, 1, std::max(scaled(120), width - 2 * margin - scaled(100)));

    const int dll_y = list_y + list_h + scaled(10);
    MoveWindow(g_label_dll, margin, dll_y + scaled(5), scaled(40), scaled(20), TRUE);
    const int dll_x = margin + scaled(42);
    MoveWindow(g_dll, dll_x, dll_y, width - dll_x - button_width - margin - gap, row, TRUE);
    MoveWindow(g_browse, width - margin - button_width, dll_y, button_width, row, TRUE);

    const int method_y = dll_y + row + gap;
    MoveWindow(g_label_method, margin, method_y + scaled(5), scaled(60), scaled(20), TRUE);
    const int method_x = margin + scaled(64);
    MoveWindow(g_method, method_x, method_y, scaled(230), scaled(240), TRUE);
    const int timeout_label_x = method_x + scaled(230) + scaled(16);
    MoveWindow(g_label_timeout, timeout_label_x, method_y + scaled(5), scaled(110), scaled(20),
               TRUE);
    MoveWindow(g_timeout, timeout_label_x + scaled(112), method_y, scaled(100), row, TRUE);

    const int inject_y = method_y + row + scaled(10);
    MoveWindow(g_inject, margin, inject_y, width - 2 * margin, scaled(32), TRUE);

    const int log_y = inject_y + scaled(32) + gap;
    MoveWindow(g_log, margin, log_y, width - 2 * margin,
               std::max(scaled(80), height - log_y - margin), TRUE);
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE:
        g_window = window;
        create_controls(window);
        layout_controls(window);
        return 0;

    case WM_SIZE:
        if (g_log != nullptr) {
            layout_controls(window);
        }
        return 0;

    case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
        info->ptMinTrackSize.x = scaled(660);
        info->ptMinTrackSize.y = scaled(560);
        return 0;
    }

    case WM_COMMAND: {
        const int id = LOWORD(wparam);
        const int code = HIWORD(wparam);
        if (id == kIdRefresh && code == BN_CLICKED) {
            load_processes();
        } else if (id == kIdBrowse && code == BN_CLICKED) {
            browse_for_dll(window);
        } else if (id == kIdInject && code == BN_CLICKED) {
            start_injection();
        } else if (id == kIdFilter && code == EN_CHANGE) {
            populate_process_list();
        } else if (id == kIdLanguage && code == CBN_SELCHANGE) {
            const int selected = static_cast<int>(SendMessageW(g_language_combo, CB_GETCURSEL, 0, 0));
            g_language = selected == static_cast<int>(Lang::en) ? Lang::en : Lang::ru;
            save_language();
            apply_language();
        }
        return 0;
    }

    case kMsgLog: {
        auto* text = reinterpret_cast<std::wstring*>(lparam);
        append_log_line(*text);
        delete text;
        return 0;
    }

    case kMsgDone: {
        auto* result = reinterpret_cast<injection_result*>(lparam);
        g_busy = false;
        EnableWindow(g_inject, TRUE);
        append_log_line(tr(result->success ? Str::done_ok : Str::done_fail));
        delete result;
        return 0;
    }

    case WM_DESTROY:
        g_window = nullptr;
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(window, message, wparam, lparam);
    }
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    INITCOMMONCONTROLSEX common_controls{};
    common_controls.dwSize = sizeof(common_controls);
    common_controls.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&common_controls);

    HDC screen = GetDC(nullptr);
    if (screen != nullptr) {
        g_dpi = GetDeviceCaps(screen, LOGPIXELSY);
        ReleaseDC(nullptr, screen);
    }
    if (g_dpi <= 0) {
        g_dpi = 96;
    }

    load_language();

    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(kIconResourceId));
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    window_class.lpszClassName = kWindowClass;
    window_class.hIconSm = window_class.hIcon;
    if (!RegisterClassExW(&window_class)) {
        return 1;
    }

    RECT work_area{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0);
    const int work_width = work_area.right - work_area.left;
    const int work_height = work_area.bottom - work_area.top;
    const int window_width = std::min(scaled(820), std::max(scaled(660), work_width - scaled(40)));
    const int window_height = std::min(scaled(640), std::max(scaled(560), work_height - scaled(60)));
    const int window_x = work_area.left + (work_width - window_width) / 2;
    const int window_y = work_area.top + (work_height - window_height) / 2;

    HWND window = CreateWindowExW(0, kWindowClass, tr(Str::app_title),
                                  WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, window_x, window_y,
                                  window_width, window_height, nullptr, nullptr, instance,
                                  nullptr);
    if (window == nullptr) {
        return 1;
    }

    log_set_sink(log_sink);
    ShowWindow(window, show_command);
    UpdateWindow(window);

    log_line(LogLevel::info, L"%ls", tr(Str::hint_start));
    DWORD extract_error = ERROR_SUCCESS;
    std::wstring extracted;
    if (extract_embedded_sample_dll(extracted, extract_error)) {
        SetWindowTextW(g_dll, extracted.c_str());
        log_line(LogLevel::info, tr(Str::log_embedded), extracted.c_str());
    } else if (extract_error != ERROR_SUCCESS) {
        log_last_error(LogLevel::error, L"extract bundled DLL", extract_error);
    }
    load_processes();

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return 0;
}
