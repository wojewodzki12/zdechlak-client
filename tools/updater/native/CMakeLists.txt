cmake_minimum_required(VERSION 3.15)
project(zdechlak_launcher C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
get_filename_component(ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(S "${ROOT}/build/cross/sources")
add_library(monocypher STATIC "${S}/monocypher/src/monocypher.c"
    "${S}/monocypher/src/optional/monocypher-ed25519.c")
target_include_directories(monocypher PUBLIC "${S}/monocypher/src" "${S}/monocypher/src/optional")
add_executable(launcher launcher.cpp)
target_include_directories(launcher PRIVATE "${S}/json/single_include" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(launcher PRIVATE monocypher)
if(NOT DEFINED ZDECHLAK_LAUNCHER_VERSION)
    set(ZDECHLAK_LAUNCHER_VERSION "1.0.3")
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
execute_process(COMMAND "${Python3_EXECUTABLE}" -c
    "import runpy; k=runpy.run_path(r'${ROOT}/updater/trust.py')['PUBLIC_KEY']; print(','.join(str(x) for x in k))"
    OUTPUT_VARIABLE KEY_BYTES OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/trust.h" "static const unsigned char public_key[32] = {${KEY_BYTES}};\n")
if(WIN32)
    enable_language(RC)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/launcher.rc" "1 ICON \"${ROOT}/branding/ZDECHLAK.ico\"\n")
    target_sources(launcher PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/launcher.rc")
    target_compile_definitions(launcher PRIVATE UNICODE _UNICODE _WIN32_WINNT=0x0601 NOMINMAX
        "ZDECHLAK_LAUNCHER_VERSION=\"${ZDECHLAK_LAUNCHER_VERSION}\"")
    target_link_libraries(launcher PRIVATE winhttp bcrypt shell32 user32 gdi32)
    # Prefer fully static MinGW/POSIX runtimes so clean Windows installs do not
    # require libwinpthread-1.dll / libgcc / libstdc++ next to the launcher.
    # WinHTTP and other OS import libs remain dynamic.
    target_link_options(launcher PRIVATE -municode -mwindows -static -Wl,--dynamicbase,--nxcompat)
    set_target_properties(launcher PROPERTIES OUTPUT_NAME ZDECHLAK)
else()
    # The same verification and transaction code can be tested without Wine.
    target_compile_definitions(launcher PRIVATE ZDECHLAK_NATIVE_TEST
        "ZDECHLAK_LAUNCHER_VERSION=\"${ZDECHLAK_LAUNCHER_VERSION}\"")
    target_link_libraries(launcher PRIVATE crypto)
endif()
