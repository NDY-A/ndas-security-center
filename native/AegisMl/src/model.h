#pragma once

#include <string>

namespace aegis_ml {

int LoadModel(const wchar_t* path, std::string* err);
void UnloadModel();
bool ModelLoaded();
int ScoreBuffer(const float* features, int count, float* maliciousProbability, std::string* err);
const char* ModelVersion();

}  // namespace aegis_ml
