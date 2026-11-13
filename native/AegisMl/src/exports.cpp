#include "aegis_ml.h"

#include <string>

#include "features.h"
#include "model.h"
#include "pe_features.h"

namespace {
thread_local std::string g_lastError;
}

extern "C" {

int __stdcall AegisMlGetFeatureCount(void) { return aegis_ml::F_COUNT; }

const char* __stdcall AegisMlGetFeatureNames(void) { return aegis_ml::FeatureNamesCsv(); }

int __stdcall AegisMlExtractFile(const wchar_t* path, float* buffer, int capacity) {
    if (!buffer || capacity < aegis_ml::F_COUNT) {
        g_lastError = "buffer too small";
        return AEGIS_ML_ERR_BUFFER;
    }
    std::string err;
    int count = aegis_ml::ExtractFeatures(path, buffer, &err);
    if (count < 0) g_lastError = err;
    return count;
}

int __stdcall AegisMlLoadModel(const wchar_t* modelPath) {
    std::string err;
    int result = aegis_ml::LoadModel(modelPath, &err);
    if (result != 0) g_lastError = err;
    return result;
}

void __stdcall AegisMlUnloadModel(void) { aegis_ml::UnloadModel(); }

int __stdcall AegisMlScoreBuffer(const float* features, int count, float* maliciousProbability) {
    std::string err;
    int result = aegis_ml::ScoreBuffer(features, count, maliciousProbability, &err);
    if (result != 0) g_lastError = err;
    return result;
}

int __stdcall AegisMlScoreFile(const wchar_t* path, float* maliciousProbability) {
    float features[aegis_ml::F_COUNT];
    std::string err;
    int count = aegis_ml::ExtractFeatures(path, features, &err);
    if (count < 0) {
        g_lastError = err;
        return count;
    }
    int result = aegis_ml::ScoreBuffer(features, count, maliciousProbability, &err);
    if (result != 0) g_lastError = err;
    return result;
}

const char* __stdcall AegisMlLastError(void) { return g_lastError.c_str(); }

const char* __stdcall AegisMlModelVersion(void) { return aegis_ml::ModelVersion(); }

}  // extern "C"
