#include "model.h"

#include <windows.h>
#include <onnxruntime_c_api.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "features.h"

namespace aegis_ml {
namespace {

using OrtGetApiBaseFn = const OrtApiBase*(ORT_API_CALL*)(void);

const OrtApi* g_api = nullptr;
OrtEnv* g_env = nullptr;
OrtSessionOptions* g_options = nullptr;
OrtSession* g_session = nullptr;
OrtMemoryInfo* g_memory = nullptr;
HMODULE g_ortModule = nullptr;
std::string g_inputName;
std::string g_outputName;
std::string g_version;
std::mutex g_mutex;

void ResetLocked() {
    if (g_session) {
        g_api->ReleaseSession(g_session);
        g_session = nullptr;
    }
    if (g_options) {
        g_api->ReleaseSessionOptions(g_options);
        g_options = nullptr;
    }
    if (g_memory) {
        g_api->ReleaseMemoryInfo(g_memory);
        g_memory = nullptr;
    }
    g_inputName.clear();
    g_outputName.clear();
    g_version.clear();
}

bool EnsureOrtRuntime(std::string* err) {
    if (g_api) return true;
    const wchar_t* candidates[] = {L"ndas-ort.dll", L"onnxruntime.dll"};
    for (const wchar_t* name : candidates) {
        HMODULE module = LoadLibraryW(name);
        if (!module) continue;
        auto getApiBase = reinterpret_cast<OrtGetApiBaseFn>(GetProcAddress(module, "OrtGetApiBase"));
        if (!getApiBase) {
            FreeLibrary(module);
            continue;
        }
        const OrtApiBase* apiBase = getApiBase();
        if (!apiBase) {
            FreeLibrary(module);
            continue;
        }
        g_api = apiBase->GetApi(ORT_API_VERSION);
        if (!g_api) {
            FreeLibrary(module);
            continue;
        }
        g_ortModule = module;
        return true;
    }
    *err = "cannot load ndas-ort.dll";
    return false;
}

bool EnsureEnv(std::string* err) {
    if (g_api) return true;
    if (!EnsureOrtRuntime(err)) return false;
    OrtStatus* status = g_api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "AegisMl", &g_env);
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        return false;
    }
    return true;
}

}  // namespace

int LoadModel(const wchar_t* path, std::string* err) {
    std::lock_guard<std::mutex> lock(g_mutex);
    ResetLocked();
    if (!path || !err) return -1;
    *err = "";
    if (!EnsureEnv(err)) return -1;

    OrtStatus* status = g_api->CreateSessionOptions(&g_options);
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        return -1;
    }
    g_api->SetSessionGraphOptimizationLevel(g_options, ORT_ENABLE_ALL);
    g_api->SetIntraOpNumThreads(g_options, 1);
    g_api->SetSessionExecutionMode(g_options, ORT_SEQUENTIAL);

    status = g_api->CreateSession(g_env, path, g_options, &g_session);
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        ResetLocked();
        return -1;
    }

    status = g_api->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &g_memory);
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        ResetLocked();
        return -1;
    }

    OrtAllocator* allocator = nullptr;
    status = g_api->GetAllocatorWithDefaultOptions(&allocator);
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        ResetLocked();
        return -1;
    }

    char* inputName = nullptr;
    status = g_api->SessionGetInputName(g_session, 0, allocator, &inputName);
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        ResetLocked();
        return -1;
    }
    g_inputName = inputName;
    g_api->AllocatorFree(allocator, inputName);

    size_t outputCount = 0;
    status = g_api->SessionGetOutputCount(g_session, &outputCount);
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        ResetLocked();
        return -1;
    }

    std::string probabilityOutput;
    std::string firstOutput;
    for (size_t i = 0; i < outputCount; ++i) {
        char* name = nullptr;
        if (g_api->SessionGetOutputName(g_session, i, allocator, &name) != nullptr) continue;
        std::string candidate = name ? name : "";
        if (name) g_api->AllocatorFree(allocator, name);
        if (firstOutput.empty()) firstOutput = candidate;

        OrtTypeInfo* typeInfo = nullptr;
        if (g_api->SessionGetOutputTypeInfo(g_session, i, &typeInfo) == nullptr && typeInfo) {
            const OrtTensorTypeAndShapeInfo* tensorInfo = nullptr;
            if (g_api->CastTypeInfoToTensorInfo(typeInfo, &tensorInfo) == nullptr && tensorInfo) {
                ONNXTensorElementDataType elementType = ONNX_TENSOR_ELEMENT_DATA_TYPE_UNDEFINED;
                g_api->GetTensorElementType(tensorInfo, &elementType);
                size_t dimensions = 0;
                g_api->GetDimensionsCount(tensorInfo, &dimensions);
                if (elementType == ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT && dimensions >= 2) {
                    std::vector<int64_t> dims(dimensions);
                    g_api->GetDimensions(tensorInfo, dims.data(), dimensions);
                    if (dims.back() == 2 && probabilityOutput.empty()) {
                        probabilityOutput = candidate;
                    }
                }
            }
            g_api->ReleaseTypeInfo(typeInfo);
        }
    }

    if (probabilityOutput.empty()) probabilityOutput = firstOutput;
    if (probabilityOutput.empty()) {
        *err = "model has no outputs";
        ResetLocked();
        return -1;
    }
    g_outputName = probabilityOutput;

    const wchar_t* fileName = wcsrchr(path, L'\\');
    fileName = fileName ? fileName + 1 : path;
    int len = WideCharToMultiByte(CP_UTF8, 0, fileName, -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) {
        g_version.resize((size_t)len - 1);
        WideCharToMultiByte(CP_UTF8, 0, fileName, -1, g_version.data(), len, nullptr, nullptr);
    }

    return 0;
}

void UnloadModel() {
    std::lock_guard<std::mutex> lock(g_mutex);
    ResetLocked();
}

bool ModelLoaded() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_session != nullptr;
}

const char* ModelVersion() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_version.c_str();
}

int ScoreBuffer(const float* features, int count, float* maliciousProbability, std::string* err) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!features || !maliciousProbability || !err) return -1;
    *err = "";
    if (!g_session) {
        *err = "model not loaded";
        return -2;
    }
    if (count != F_COUNT) {
        *err = "feature count mismatch";
        return -3;
    }

    const int64_t shape[2] = {1, count};
    OrtValue* input = nullptr;
    OrtStatus* status = g_api->CreateTensorWithDataAsOrtValue(
        g_memory, const_cast<float*>(features), (size_t)count * sizeof(float), shape, 2,
        ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &input);
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        return -4;
    }

    const char* inputNames[1] = {g_inputName.c_str()};
    const char* outputNames[1] = {g_outputName.c_str()};
    OrtValue* output = nullptr;
    status = g_api->Run(g_session, nullptr, inputNames, &input, 1, outputNames, 1, &output);
    g_api->ReleaseValue(input);
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        return -5;
    }

    OrtTensorTypeAndShapeInfo* info = nullptr;
    status = g_api->GetTensorTypeAndShape(output, &info);
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        g_api->ReleaseValue(output);
        return -6;
    }

    ONNXTensorElementDataType elementType = ONNX_TENSOR_ELEMENT_DATA_TYPE_UNDEFINED;
    g_api->GetTensorElementType(info, &elementType);
    size_t dimCount = 0;
    g_api->GetDimensionsCount(info, &dimCount);
    int64_t dims[4] = {};
    if (dimCount > 4) dimCount = 4;
    g_api->GetDimensions(info, dims, dimCount);
    size_t elementCount = 1;
    for (size_t i = 0; i < dimCount; ++i) elementCount *= (size_t)std::max<int64_t>(1, dims[i]);
    g_api->ReleaseTensorTypeAndShapeInfo(info);
    if (elementType != ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) {
        g_api->ReleaseValue(output);
        *err = "model output is not a float tensor";
        return -8;
    }

    float* data = nullptr;
    status = g_api->GetTensorMutableData(output, reinterpret_cast<void**>(&data));
    if (status) {
        *err = g_api->GetErrorMessage(status);
        g_api->ReleaseStatus(status);
        g_api->ReleaseValue(output);
        return -7;
    }

    float probability = 0.0f;
    if (elementCount >= 2) {
        probability = data[1];
    } else if (elementCount == 1) {
        probability = data[0];
    } else {
        g_api->ReleaseValue(output);
        *err = "unexpected model output shape";
        return -8;
    }
    g_api->ReleaseValue(output);

    if (!std::isfinite(probability)) probability = 0.0f;
    *maliciousProbability = std::clamp(probability, 0.0f, 1.0f);
    return 0;
}

}  // namespace aegis_ml
