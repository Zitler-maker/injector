# x64 DLL Injector

Windows 10/11 x64 DLL injector with three injection methods: `CreateRemoteThread + LoadLibraryW`, `NtCreateThreadEx + LoadLibraryW`, and a full manual PE mapper. Ships with a GUI panel and a CLI, plus a sample DLL for verification.

[Русская версия](README.ru.md)

## Layout

```
src/
  gui.cpp          Win32 panel: process list, DLL picker, method, timeout, log
  injector.cpp     CLI: wmain, argument parsing, dispatch, final report
  inject_api.cpp/h shared inject entry used by GUI and CLI
  process.cpp/h    process enumeration, name lookup, SeDebugPrivilege, OpenProcess
  inject_crt.cpp/h CreateRemoteThread / NtCreateThreadEx + LoadLibraryW
  manualmap.cpp/h  manual PE mapping (headers, sections, relocations, imports, TLS, DllMain)
  remote.cpp/h     remote memory, module base lookup, export translation, remote call stub
  log.cpp/h        [INFO]/[WARN]/[ERROR] logging to stderr and an optional sink
test/
  sample_dll.cpp   demo DLL: drops %TEMP%\injected_<pid>.txt and shows a MessageBox
resources/
  injector.rc      icon and manifest resources
  app.ico          application icon
  app.manifest     comctl32 v6 + DPI awareness
tools/
  embed_binary.ps1 build-time step: turns sample_dll.dll into a C++ byte array
  make_icon.ps1    regenerates app.ico from a source image
CMakeLists.txt
build.bat
```

## Build

```
build.bat
```

Resolves CMake from PATH or from the Visual Studio installation, configures with the default Visual Studio generator for x64, builds Release.

Artifacts:

```
dist\DLLInjector.exe            standalone GUI: one file, nothing else needed
build\Release\injector.exe      GUI panel
build\Release\injector-cli.exe  console version
build\Release\sample_dll.dll
```

`dist\DLLInjector.exe` is self-contained: the sample DLL is embedded as a resource and extracted to `%TEMP%\injector_sample_<pid>.dll` at startup (the DLL path field is pre-filled with it), the icon is compiled in, and the CRT is linked statically (`/MT`). It runs from an empty folder with no DLLs, no VC++ runtime and no config files next to it. The only runtime dependency is Windows itself (kernel32, user32, gdi32, advapi32, comctl32, comdlg32).

Manual equivalent:

```
cmake -S . -B build -A x64
cmake --build build --config Release
```

Requirements: MSVC (VS 2019+), Windows SDK. Compiler flags: `/W4 /permissive- /EHsc /utf-8`, C++20.

## GUI

Run `dist\DLLInjector.exe` (double-click works, no console window). The panel has:

- process list with a filter field and **Refresh**;
- **DLL** path with a **Browse...** picker (pre-filled with the embedded sample DLL extracted to `%TEMP%`);
- method combo (`crt`, `ntcrt`, `manualmap`) and timeout in milliseconds;
- **Inject** button; the injection runs on a worker thread so the window stays responsive;
- log pane mirroring the same `[INFO]/[WARN]/[ERROR]` output as the CLI.

Typing into the filter selects the first match automatically. Pick the row you want and press **Inject**.

### Languages

The combo in the top-right switches the whole panel between **English** and **Русский** live. The choice is saved to `HKCU\Software\DLLInjector\Language` and restored on the next launch. Russian is the default.

## CLI

```
injector-cli.exe --dll=<path> (--pid=<pid> | --name=<image>) [--method=crt|ntcrt|manualmap] [--timeout=<ms>]
injector-cli.exe --list
injector-cli.exe --help
```

| Option | Meaning |
|---|---|
| `--dll=<path>` | Path to the x64 DLL. Relative paths are resolved via `GetFullPathNameW`. Required. |
| `--pid=<pid>` | Target process id. |
| `--name=<image>` | Target image name, e.g. `firefox.exe`. Without an extension (`firefox`) matches the image stem. Every match is injected, each result logged. |
| `--method=<m>` | `crt` (default), `ntcrt`, `manualmap`. |
| `--timeout=<ms>` | Remote thread wait timeout, default `10000`, range `1000..600000`. |
| `--list` | Print running processes sorted by image name. |
| `--help` | Usage. |

Exactly one of `--pid` / `--name` is required. Exit codes: `0` all targets injected, `1` at least one failure, `2` usage error.

## Methods

- **crt** — `OpenProcess` → `VirtualAllocEx` + `WriteProcessMemory` for the DLL path → `CreateRemoteThread(LoadLibraryW)` → wait → `GetExitCodeThread`. Exit code `0` means `LoadLibraryW` failed.
- **ntcrt** — same, but the thread is created via `NtCreateThreadEx` resolved from `ntdll.dll` with `GetProcAddress`.
- **manualmap** — the DLL is parsed and mapped without registration in the PEB loader lists:
  - `MZ` / `PE\0\0` / `IMAGE_FILE_MACHINE_AMD64` / `PE32+` validation, `SizeOfImage` and section bounds checked before every allocation and copy;
  - headers and sections copied at their RVAs, base relocations applied (`DIR64`, `HIGHLOW`, `ABSOLUTE` skipped);
  - imports resolved through `LoadLibraryA`/`GetProcAddress` in the injector, translated to the target via the ASLR delta of the corresponding module; import modules not loaded in the target are loaded there first via a remote `LoadLibraryW` call; ordinal imports supported;
  - TLS callbacks (`IMAGE_DIRECTORY_ENTRY_TLS`) executed with `DLL_PROCESS_ATTACH` before `DllMain`;
  - section protections applied per `Characteristics`, headers set to `PAGE_READONLY`, instruction cache flushed;
  - `DllMain(DLL_PROCESS_ATTACH)` invoked through a generated x64 stub; `FALSE` return fails the injection;
  - any parse or mapping error fails closed: remote memory is released and an error code is reported.

Threads are created with `CreateRemoteThread`; the step-by-step state is logged. Targets that enforce W^X (Firefox) silently refuse threads started on writable+executable pages, so the generated call stub is written as `PAGE_READWRITE` and flipped to `PAGE_EXECUTE_READ` before the thread starts, and import modules are loaded by starting a thread directly at `LoadLibraryW` with the remote path as argument.

## Sample DLL

`sample_dll.dll` (`test/sample_dll.cpp`) verifies injection visually and on disk:

1. writes `%TEMP%\injected_<pid>.txt` with the target path, pid and module base;
2. spawns a thread with a MessageBox showing the same data.

```bat
build\Release\injector-cli.exe --name=firefox.exe --dll=build\Release\sample_dll.dll --method=crt
```

The standalone GUI does not need this file: it extracts its embedded copy automatically.

For `manualmap` use the full path to the DLL and note that the MessageBox appears only after mapping completes. Content processes of sandboxed browsers usually deny `OpenProcess` with same-user rights; target the main browser process (the parent of the other `firefox.exe` entries).

## Logging

All diagnostics go to stderr with `[INFO]`, `[WARN]`, `[ERROR]` prefixes. Operation failures include the call name and `GetLastError` code with system text, e.g.:

```
[ERROR] VirtualAllocEx(dll path) failed: error 5 (Access is denied)
[ERROR] [FAIL] pid=1234 method=crt error=5 (Access is denied)
[INFO] summary: 1 target(s), 0 succeeded, 1 failed
```

`--list` output goes to stdout.

## Notes and limitations

- x64 injector and x64 DLLs only; a 32-bit injection path is out of scope.
- No unloading/ejection support.
- Manual map covers relocations, imports, TLS callbacks, section protections and `DllMain`; it does not allocate a TLS index slot for `__declspec(thread)` variables, does not register exception tables in `ntdll`, and does not link the module into the PEB module list. DLLs that depend on those facilities may misbehave under `manualmap`; use `crt`/`ntcrt` for them.
- `SeDebugPrivilege` is attempted first. If the process token does not hold it, a warning is logged and injection continues; protected targets then fail at `OpenProcess` with the real error.
- Some security products flag injector binaries by signature. Add the build directory to your AV exclusions if your build disappears.

## Legal

Use only on processes you own or are authorized to test.
