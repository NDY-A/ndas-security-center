cmake_minimum_required(VERSION 3.20)
project(AegisMl LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)

set(ORT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../vendor/onnxruntime-win-x64-1.22.0" CACHE PATH "ONNX Runtime root")

add_executable(AegisMlDump src/dump_features.cpp src/pe_features.cpp)
target_include_directories(AegisMlDump PRIVATE include src)
target_compile_definitions(AegisMlDump PRIVATE UNICODE _UNICODE)
target_compile_options(AegisMlDump PRIVATE /W4 /utf-8)

if(EXISTS "${ORT_DIR}/include/onnxruntime_c_api.h")
    add_library(AegisMl SHARED src/exports.cpp src/pe_features.cpp src/model.cpp)
    target_include_directories(AegisMl PRIVATE include src "${ORT_DIR}/include")
    target_compile_definitions(AegisMl PRIVATE UNICODE _UNICODE)
    target_compile_options(AegisMl PRIVATE /W4 /utf-8)
    add_custom_command(TARGET AegisMl POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${ORT_DIR}/lib/onnxruntime.dll"
                "$<TARGET_FILE_DIR:AegisMl>/ndas-ort.dll")
else()
    message(WARNING "ONNX Runtime not found at ${ORT_DIR}; AegisMl.dll target disabled")
endif()
