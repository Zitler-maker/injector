# x64 DLL-инжектор

Инжектор DLL для Windows 10/11 x64 с тремя методами: `CreateRemoteThread + LoadLibraryW`, `NtCreateThreadEx + LoadLibraryW` и полноценный ручной маппер PE. В комплекте GUI-панель, консольная версия и тестовая DLL для проверки.

[English version](README.md)

## Структура

```
src/
  gui.cpp          Win32-панель: список процессов, выбор DLL, метод, таймаут, лог
  injector.cpp     CLI: wmain, разбор аргументов, диспетчер, итоговый отчёт
  inject_api.cpp/h общий вход инжекта для GUI и CLI
  process.cpp/h    перечисление процессов, поиск по имени, SeDebugPrivilege, OpenProcess
  inject_crt.cpp/h CreateRemoteThread / NtCreateThreadEx + LoadLibraryW
  manualmap.cpp/h  ручной маппинг PE (заголовки, секции, релокации, импорты, TLS, DllMain)
  remote.cpp/h     удалённая память, поиск базы модуля, трансляция экспорта, стаб для удалённого вызова
  log.cpp/h        логи [INFO]/[WARN]/[ERROR] в stderr и в подключаемый приёмник
test/
  sample_dll.cpp   демо-DLL: пишет %TEMP%\injected_<pid>.txt и показывает MessageBox
resources/
  injector.rc      ресурсы: иконка и манифест
  app.ico          иконка приложения
  app.manifest     comctl32 v6 + DPI awareness
tools/
  embed_binary.ps1 шаг сборки: превращает sample_dll.dll в C++ байтовый массив
  make_icon.ps1    пересобирает app.ico из исходной картинки
CMakeLists.txt
build.bat
```

## Сборка

```
build.bat
```

Скрипт находит CMake в PATH или в установке Visual Studio, конфигурирует под x64 генератором VS по умолчанию и собирает Release.

Результат:

```
dist\DLLInjector.exe            автономный GUI: один файл, больше ничего не нужно
build\Release\injector.exe      GUI-панель
build\Release\injector-cli.exe  консольная версия
build\Release\sample_dll.dll    тестовая DLL
```

`dist\DLLInjector.exe` самодостаточен: тестовая DLL вшита ресурсом и извлекается при старте в `%TEMP%\injector_sample_<pid>.dll` (путь сразу подставлен в поле DLL), иконка скомпилирована внутрь, CRT слинкован статически (`/MT`). Запускается из пустой папки — рядом не нужны ни DLL, ни VC++ Runtime, ни конфиги. Зависимость только от самой Windows (kernel32, user32, gdi32, advapi32, comctl32, comdlg32).

Вручную:

```
cmake -S . -B build -A x64
cmake --build build --config Release
```

Требования: MSVC (VS 2019+), Windows SDK. Флаги: `/W4 /permissive- /EHsc /utf-8`, C++20.

## GUI

Запусти `dist\DLLInjector.exe` (двойной клик, консольного окна нет). В панели:

- список процессов с фильтром и кнопкой **Обновить**;
- путь к **DLL** с кнопкой **Обзор...** (по умолчанию подставлена вшитая тестовая DLL, извлечённая в `%TEMP%`);
- выбор метода (`crt`, `ntcrt`, `manualmap`) и таймаут в миллисекундах;
- кнопка **Внедрить**; инжект идёт в рабочем потоке, окно не подвисает;
- панель лога с теми же `[INFO]/[WARN]/[ERROR]`, что и в CLI.

При вводе фильтра первый совпавший процесс выделяется автоматически. Выбери нужную строку и нажми **Внедрить**.

### Языки

Комбо в правом верхнем углу переключает всю панель между **Русский** и **English** на лету. Выбор сохраняется в `HKCU\Software\DLLInjector\Language` и восстанавливается при следующем запуске. По умолчанию — русский.

## CLI

```
injector-cli.exe --dll=<path> (--pid=<pid> | --name=<image>) [--method=crt|ntcrt|manualmap] [--timeout=<ms>]
injector-cli.exe --list
injector-cli.exe --help
```

| Опция | Значение |
|---|---|
| `--dll=<path>` | Путь к x64 DLL. Относительный путь приводится к полному через `GetFullPathNameW`. Обязателен. |
| `--pid=<pid>` | PID целевого процесса. |
| `--name=<image>` | Имя образа, например `firefox.exe`. Без расширения (`firefox`) матчится по имени без `.exe`. Инжект во все совпадения, результат логируется по каждому. |
| `--method=<m>` | `crt` (по умолчанию), `ntcrt`, `manualmap`. |
| `--timeout=<ms>` | Таймаут ожидания удалённого потока, по умолчанию `10000`, диапазон `1000..600000`. |
| `--list` | Список процессов, отсортированный по имени. |
| `--help` | Подсказка. |

Нужно ровно одно из `--pid` / `--name`. Коды выхода: `0` — все цели проинжекчены, `1` — хотя бы одна ошибка, `2` — ошибка аргументов.

## Методы

- **crt** — `OpenProcess` → `VirtualAllocEx` + `WriteProcessMemory` под путь DLL → `CreateRemoteThread(LoadLibraryW)` → ожидание → `GetExitCodeThread`. Код выхода `0` означает, что `LoadLibraryW` упал.
- **ntcrt** — то же, но поток создаётся через `NtCreateThreadEx`, который резолвится из `ntdll.dll` через `GetProcAddress`.
- **manualmap** — DLL парсится и маппится без регистрации в списках загрузчика PEB:
  - проверки `MZ` / `PE\0\0` / `IMAGE_FILE_MACHINE_AMD64` / `PE32+`, границы `SizeOfImage` и секций валидируются до каждой аллокации и копирования;
  - заголовки и секции копируются по своим RVA, применяются релокации (`DIR64`, `HIGHLOW`, `ABSOLUTE` пропускается);
  - импорты резолвятся через `LoadLibraryA`/`GetProcAddress` в инжекторе и транслируются в цель по ASLR-дельте соответствующего модуля; отсутствующие в цели модули импорта сначала загружаются там удалённым вызовом `LoadLibraryW`; импорт по ординалу поддержан;
  - TLS-колбэки (`IMAGE_DIRECTORY_ENTRY_TLS`) вызываются с `DLL_PROCESS_ATTACH` до `DllMain`;
  - защита секций выставляется по `Characteristics`, заголовки — `PAGE_READONLY`, кэш инструкций сбрасывается;
  - `DllMain(DLL_PROCESS_ATTACH)` вызывается через сгенерированный x64-стаб; возврат `FALSE` = провал инжекта;
  - любая ошибка парсинга или маппинга — fail closed: удалённая память освобождается, возвращается код ошибки.

Все потоки создаются через `CreateRemoteThread`, каждый шаг пишется в лог. Цели с политикой W^X (Firefox) молча отказываются исполнять потоки на записываемых+исполняемых страницах, поэтому стаб вызова пишется как `PAGE_READWRITE` и перед стартом потока переводится в `PAGE_EXECUTE_READ`, а модули импорта грузятся запуском потока прямо на `LoadLibraryW` с удалённым путём в аргументе.

## Тестовая DLL

`sample_dll.dll` (`test/sample_dll.cpp`) проверяет инжект визуально и на диске:

1. пишет `%TEMP%\injected_<pid>.txt` с путём цели, pid и базой модуля;
2. поднимает поток с MessageBox с теми же данными.

```bat
build\Release\injector-cli.exe --name=firefox.exe --dll=build\Release\sample_dll.dll --method=crt
```

Автономному GUI этот файл не нужен: он извлекает вшитую копию сам.

Для `manualmap` указывай полный путь к DLL; MessageBox появится после завершения маппинга. Контент-процессы песочницы браузеров обычно дают `OpenProcess` отказ даже под тем же пользователем — целься в главный процесс браузера (родитель остальных `firefox.exe`).

## Логирование

Вся диагностика идёт в stderr с префиксами `[INFO]`, `[WARN]`, `[ERROR]`. При ошибке операции печатается имя вызова, код `GetLastError` и системный текст, например:

```
[ERROR] VirtualAllocEx(dll path) failed: error 5 (Отказано в доступе)
[ERROR] [FAIL] pid=1234 method=crt error=5 (Отказано в доступе)
[INFO] summary: 1 target(s), 0 succeeded, 1 failed
```

Вывод `--list` идёт в stdout.

## Ограничения

- Только x64-инжектор и x64-DLL; 32-битного пути нет.
- Выгрузки/эжекта нет.
- Manual map покрывает релокации, импорты, TLS-колбэки, защиту секций и `DllMain`; он не выделяет TLS-индекс для `__declspec(thread)`-переменных, не регистрирует таблицы исключений в `ntdll` и не линкует модуль в список модулей PEB. DLL, зависящие от этого, под `manualmap` могут работать неправильно — для них `crt`/`ntcrt`.
- `SeDebugPrivilege` включается первым делом. Если в токене процесса его нет — WARN и продолжение; защищённые цели упадут на `OpenProcess` с реальной ошибкой.
- Часть антивирусов ловит инжекторы по сигнатуре. Если сборка исчезает — добавь каталог сборки в исключения.

## Правовое

Только для процессов, которыми владеешь ты или которые тебе разрешено тестировать.
