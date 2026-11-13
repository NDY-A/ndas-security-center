#pragma once

// Fixed-order feature schema shared by training (AegisMlDump CSV) and
// inference (AegisMlScoreFile). Never reorder or remove entries; append only,
// then retrain the model.
#define AEGIS_ML_FEATURE_LIST(X) \
    X(file_size_log) \
    X(file_entropy) \
    X(is_dotnet) \
    X(is_dll) \
    X(machine_amd64) \
    X(machine_i386) \
    X(machine_other) \
    X(subsystem_gui) \
    X(subsystem_cui) \
    X(subsystem_other) \
    X(timestamp_zero) \
    X(timestamp_anomalous) \
    X(has_authenticode) \
    X(has_checksum) \
    X(overlay_size_log) \
    X(overlay_ratio) \
    X(el_fanew_sane) \
    X(rich_header_present) \
    X(pdb_path_present) \
    X(debug_directory_present) \
    X(tls_directory_present) \
    X(reloc_directory_present) \
    X(resource_directory_present) \
    X(export_directory_present) \
    X(export_count_log) \
    X(section_count) \
    X(zero_rawsize_section_count) \
    X(high_entropy_sections) \
    X(very_high_entropy_sections) \
    X(max_section_entropy) \
    X(mean_section_entropy) \
    X(min_section_entropy) \
    X(exec_section_count) \
    X(writable_section_count) \
    X(wx_section_count) \
    X(entry_in_section) \
    X(entry_section_entropy) \
    X(entry_section_high_entropy) \
    X(nonstandard_section_name_count) \
    X(section_name_upx) \
    X(section_name_vmp) \
    X(section_name_aspack) \
    X(section_name_other_packer) \
    X(has_text_section) \
    X(has_data_section) \
    X(has_rdata_section) \
    X(has_rsrc_section) \
    X(has_reloc_section) \
    X(max_virtual_raw_ratio_log) \
    X(mean_virtual_raw_ratio) \
    X(size_mismatch_section_count) \
    X(has_import_directory) \
    X(import_dll_count) \
    X(import_func_count_log) \
    X(import_ordinal_count) \
    X(api_injection_count) \
    X(api_credential_count) \
    X(api_persistence_count) \
    X(api_anti_debug_count) \
    X(api_network_count) \
    X(api_process_count) \
    X(api_service_count) \
    X(api_registry_count) \
    X(api_file_count) \
    X(api_crypto_count) \
    X(api_antivm_count) \
    X(dll_kernel32) \
    X(dll_ntdll) \
    X(dll_advapi32) \
    X(dll_user32) \
    X(dll_ws2_32) \
    X(dll_wininet) \
    X(dll_shell32) \
    X(dll_ole32) \
    X(dll_vcruntime) \
    X(dll_nonstandard) \
    X(avg_imports_per_dll) \
    X(ascii_string_count_log) \
    X(wide_string_count_log) \
    X(url_count) \
    X(ip_count) \
    X(registry_path_count) \
    X(suspicious_keyword_count) \
    X(kw_powershell) \
    X(kw_cmd) \
    X(kw_appdata) \
    X(kw_temp) \
    X(kw_base64) \
    X(kw_http) \
    X(embedded_pe_headers) \
    X(printable_ratio) \
    X(zero_byte_ratio) \
    X(hist_00_0f) \
    X(hist_10_1f) \
    X(hist_20_2f) \
    X(hist_30_3f) \
    X(hist_40_4f) \
    X(hist_50_5f) \
    X(hist_60_6f) \
    X(hist_70_7f) \
    X(hist_80_8f) \
    X(hist_90_9f) \
    X(hist_a0_af) \
    X(hist_b0_bf) \
    X(hist_c0_cf) \
    X(hist_d0_df) \
    X(hist_e0_ef) \
    X(hist_f0_ff)

namespace aegis_ml {

enum FeatureIndex : int {
#define AEGIS_ML_ENUM_ENTRY(name) F_##name,
    AEGIS_ML_FEATURE_LIST(AEGIS_ML_ENUM_ENTRY)
#undef AEGIS_ML_ENUM_ENTRY
    F_COUNT
};

}  // namespace aegis_ml
