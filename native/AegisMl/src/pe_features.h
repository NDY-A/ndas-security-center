#pragma once

#include <cstdint>
#include <string>

namespace aegis_ml {

// Extracts features into features[0..F_COUNT). Returns the feature count on
// success or a negative AEGIS_ML_ERR_* code; writes a message into err.
int ExtractFeatures(const wchar_t* path, float* features, std::string* err);

const char* FeatureNamesCsv();

}  // namespace aegis_ml
