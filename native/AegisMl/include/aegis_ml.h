#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// All functions return 0 on success and a negative value on failure.
// AegisMlLastError returns a thread-local UTF-8 message (may be empty).

#define AEGIS_ML_OK 0
#define AEGIS_ML_ERR_INVALID_ARGUMENT -1
#define AEGIS_ML_ERR_IO -2
#define AEGIS_ML_ERR_NOT_PE -3
#define AEGIS_ML_ERR_TOO_LARGE -4
#define AEGIS_ML_ERR_NO_MODEL -5
#define AEGIS_ML_ERR_INFERENCE -6
#define AEGIS_ML_ERR_BUFFER -7

// Number of float features produced per file. Fixed at build time.
__declspec(dllexport) int __stdcall AegisMlGetFeatureCount(void);

// Comma-separated feature names in the exact order used by feature buffers.
__declspec(dllexport) const char* __stdcall AegisMlGetFeatureNames(void);

// Extract features for one file. buffer must hold at least AegisMlGetFeatureCount() floats.
// Returns the feature count on success, or a negative error code.
__declspec(dllexport) int __stdcall AegisMlExtractFile(
    const wchar_t* path,
    float* buffer,
    int capacity);

// Load an ONNX model (LightGBM classifier, input float[N, featureCount],
// output probabilities tensor float[N, 2]). Returns 0 on success.
__declspec(dllexport) int __stdcall AegisMlLoadModel(const wchar_t* modelPath);
__declspec(dllexport) void __stdcall AegisMlUnloadModel(void);

// Score a feature buffer. Writes probability of the malicious class (0..1).
__declspec(dllexport) int __stdcall AegisMlScoreBuffer(
    const float* features,
    int count,
    float* maliciousProbability);

// Extract + score one file in a single call.
__declspec(dllexport) int __stdcall AegisMlScoreFile(
    const wchar_t* path,
    float* maliciousProbability);

__declspec(dllexport) const char* __stdcall AegisMlLastError(void);
__declspec(dllexport) const char* __stdcall AegisMlModelVersion(void);

#ifdef __cplusplus
}
#endif
