cmake_minimum_required(VERSION 3.20)

project(injector LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(INJECTOR_CORE
    src/log.cpp
    src/process.cpp
    src/remote.cpp
    src/inject_crt.cpp
    src/manualmap.cpp
    src/inject_api.cpp
)

add_library(sample_dll SHARED test/sample_dll.cpp)

target_compile_definitions(sample_dll PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    target_compile_options(sample_dll PRIVATE /W4 /permissive- /EHsc /utf-8)
endif()

target_link_libraries(sample_dll PRIVATE kernel32 user32)

set(EMBEDDED_SAMPLE_DLL ${CMAKE_BINARY_DIR}/generated/sample_dll_data.cpp)

add_custom_command(
    OUTPUT ${EMBEDDED_SAMPLE_DLL}
    COMMAND powershell -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_SOURCE_DIR}/tools/embed_binary.ps1"
            -InputFile "$<TARGET_FILE:sample_dll>"
            -OutputFile "${EMBEDDED_SAMPLE_DLL}"
            -SymbolName kEmbeddedSampleDll
    DEPENDS sample_dll "${CMAKE_SOURCE_DIR}/tools/embed_binary.ps1"
    COMMENT "Embedding sample DLL"
    VERBATIM
)
set_source_files_properties(${EMBEDDED_SAMPLE_DLL} PROPERTIES GENERATED TRUE)

add_executable(injector WIN32
    src/gui.cpp
    ${INJECTOR_CORE}
    ${EMBEDDED_SAMPLE_DLL}
    resources/injector.rc
)
add_dependencies(injector sample_dll)

add_executable(injector_cli
    src/injector.cpp
    ${INJECTOR_CORE}
    resources/injector.rc
)
set_target_properties(injector_cli PROPERTIES OUTPUT_NAME injector-cli)

foreach(target injector injector_cli)
    target_include_directories(${target} PRIVATE src)

    target_compile_definitions(${target} PRIVATE
        UNICODE
        _UNICODE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
    )

    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /EHsc /utf-8)
    endif()

    target_link_libraries(${target} PRIVATE kernel32 user32 gdi32 advapi32 ntdll comctl32 comdlg32)
endforeach()

if(MSVC)
    target_link_options(injector_cli PRIVATE /SUBSYSTEM:CONSOLE)
    target_link_options(injector PRIVATE /MANIFEST:NO)
    target_link_options(injector_cli PRIVATE /MANIFEST:NO)
endif()

add_custom_command(TARGET injector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/dist"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:injector>"
            "${CMAKE_SOURCE_DIR}/dist/DLLInjector.exe"
    COMMENT "Copied standalone injector to dist"
)
