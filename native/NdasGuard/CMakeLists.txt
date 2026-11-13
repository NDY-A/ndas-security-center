cmake_minimum_required(VERSION 3.20)
project(NdasGuard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)

add_executable(NdasGuard src/main.cpp)
target_compile_definitions(NdasGuard PRIVATE UNICODE _UNICODE)
target_compile_options(NdasGuard PRIVATE /W4 /utf-8)
target_link_libraries(NdasGuard PRIVATE advapi32 shlwapi shell32)
