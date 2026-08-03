/**
 * @file lgbm/feat_vector.cpp
 * @brief 特征向量序列化实现
 * @author ternaryop8479
 * @date 2026-08-03
 */

#include "lgbm/feat_vector.h"

// 特征字段宏列表(与feat_pack.h中的结构体字段顺序一致, 禁止随意调整顺序)
#define EFG_FEAT_FIELDS(X) \
	X(node_count) X(edge_count) X(density) X(avg_degree) X(max_degree) \
	X(degree_var) X(degree_ske) X(edge_node_ratio) X(isolated_node_count) \
	X(largest_component_ratio) X(entropy) \
	X(avg_jmp_count) X(jmp_count_var) X(jmp_count_ske) X(max_jmp_count) \
	X(avg_indirect_jmp_count) X(indirect_jmp_count_var) X(indirect_jmp_count_ske) \
	X(max_indirect_jmp_count) X(indirect_jmp_edge_ratio) X(total_indirect_jmp_count) \
	X(max_span) X(avg_span) X(span_var) X(span_ske) X(jmp_count_entropy) \
	X(data_flow_edge_ratio) X(avg_span_with_data) X(max_span_with_data) \
	X(span_with_data_var) X(span_with_data_ske) \
	X(avg_jmp_count_with_data) X(max_jmp_count_with_data) \
	X(jmp_count_with_data_var) X(jmp_count_with_data_ske) \
	X(avg_indirect_jmp_with_data) X(max_indirect_jmp_with_data) \
	X(indirect_jmp_with_data_var) X(indirect_jmp_with_data_ske)

#define TSPM_FEAT_FIELDS(X) \
	X(max_malchain_length) X(avg_malchain_length) X(max_benchain_length) \
	X(avg_benchain_length) X(malchain_count) X(benchain_count) \
	X(mal_ben_avglength_ratio) X(mal_ben_maxlength_ratio) X(chain_count_diff) \
	X(is_mal_dominant) X(malchain_density) X(benchain_density) \
	X(avg_malchain_similarity) X(avg_benchain_similarity) X(avg_malmatch_depth) \
	X(avg_benmatch_depth) X(max_malmatch_depth) X(max_benmatch_depth) \
	X(malapi_count) X(benapi_count) \
	X(avg_malchain_weight) X(malchain_weight_var) X(malchain_weight_ske) \
	X(avg_benchain_weight) X(benchain_weight_var) X(benchain_weight_ske) \
	X(max_malchain_weight) X(max_benchain_weight) \
	X(avg_malweight_density) X(avg_benweight_density) \
	X(max_malweight_density) X(max_benweight_density) \
	X(tspm_mal_weight) X(tspm_ben_weight) X(weight_diff) X(weight_ratio) \
	X(avg_malskip_count) X(avg_benskip_count) \
	X(avg_malchain_branching) X(avg_benchain_branching) \
	X(max_malchain_branching) X(max_benchain_branching) \
	X(tspm_score)

#define PE_FEAT_FIELDS(X) \
	X(machine_type) X(is_64bit) X(num_sections) X(time_date_stamp) \
	X(has_symbol_table) X(size_of_optional_header) X(file_characteristics) \
	X(is_dll) X(linker_version) X(size_of_code) X(size_of_initialized_data) \
	X(size_of_uninitialized_data) X(address_of_entry_point) X(base_of_code) \
	X(image_base) X(section_alignment) X(file_alignment) X(os_version) \
	X(subsystem_version) X(size_of_image) X(size_of_headers) \
	X(checksum_is_zero) X(subsystem) X(dll_characteristics) \
	X(size_of_stack_reserve) X(size_of_stack_commit) X(size_of_heap_reserve) \
	X(size_of_heap_commit) X(number_of_rva_and_sizes) \
	X(file_entropy) X(section_entropy_mean) X(section_entropy_max) \
	X(section_entropy_min) X(section_entropy_std) X(text_section_entropy) \
	X(high_entropy_section_count) \
	X(entry_section_index) X(entry_section_entropy) X(raw_size_mean) \
	X(raw_size_max) X(virtual_size_mean) X(virtual_size_max) \
	X(vsize_raw_ratio_mean) X(vsize_raw_ratio_max) X(high_gap_section_count) \
	X(nonstandard_name_count) X(writable_executable_count) X(executable_count) \
	X(import_count) X(distinct_dll_count) X(imports_per_dll_mean) \
	X(imports_per_dll_max) X(ordinal_import_count) X(ordinal_import_ratio) \
	X(unique_api_count) X(api_name_len_mean) X(api_name_len_max) \
	X(api_name_char_entropy) X(dll_name_entropy) X(has_dynamic_import) \
	X(suspicious_api_count) X(suspicious_api_ratio) X(suspicious_dll_count) \
	X(suspicious_dll_ratio) X(process_api_count) X(network_api_count) \
	X(crypto_api_count) X(persistence_api_count) X(import_dir_size) \
	X(string_count) X(string_avg_len) X(string_max_len) X(long_string_count) \
	X(printable_ratio) X(url_count) X(file_path_count) X(registry_count) \
	X(ip_count) X(suspicious_keyword_count) \
	X(file_size) X(overlay_size) X(overlay_ratio) X(headers_image_ratio) \
	X(image_gap_ratio) X(nonzero_data_directory_count) X(export_present) \
	X(debug_present) X(resource_present) X(rich_header_entry_count)

// 用于编译期统计维度数的宏
#define FEAT_COUNT_ONE(name) +1
static_assert(0 EFG_FEAT_FIELDS(FEAT_COUNT_ONE) == starlight_v3::lgbm::kEfgFeatDims, "EFGFeatPack维度与宏列表不一致");
static_assert(0 TSPM_FEAT_FIELDS(FEAT_COUNT_ONE) == starlight_v3::lgbm::kTspmFeatDims, "TSPMFeatPack维度与宏列表不一致");
static_assert(0 PE_FEAT_FIELDS(FEAT_COUNT_ONE) == starlight_v3::lgbm::kPeFeatDims, "PEFeatPack维度与宏列表不一致");
// 结构体字段数与宏维度数对齐(防止向结构体新增字段但遗漏同步宏时静默丢维度)
static_assert(starlight_v3::EFGFeatPack::kFieldCount == starlight_v3::lgbm::kEfgFeatDims, "EFGFeatPack新增字段但未同步EFG_FEAT_FIELDS宏");
static_assert(starlight_v3::TSPMFeatPack::kFieldCount == starlight_v3::lgbm::kTspmFeatDims, "TSPMFeatPack新增字段但未同步TSPM_FEAT_FIELDS宏");
static_assert(starlight_v3::PEFeatPack::kFieldCount == starlight_v3::lgbm::kPeFeatDims, "PEFeatPack新增字段但未同步PE_FEAT_FIELDS宏");
#undef FEAT_COUNT_ONE

namespace starlight_v3::lgbm {

SIZE_T serialize_feat_pack(const FeatPack &feats, double *out) {
	// 先序列化EFG特征(39维)
#define EMIT_EFG_FIELD(name) *out++ = static_cast<double>(feats.efg_feats.name);
	EFG_FEAT_FIELDS(EMIT_EFG_FIELD)
#undef EMIT_EFG_FIELD

	// 再序列化TSPM特征(43维)
#define EMIT_TSPM_FIELD(name) *out++ = static_cast<double>(feats.tspm_feats.name);
	TSPM_FEAT_FIELDS(EMIT_TSPM_FIELD)
#undef EMIT_TSPM_FIELD

	// 最后序列化PE特征(89维)
#define EMIT_PE_FIELD(name) *out++ = static_cast<double>(feats.pe_feats.name);
	PE_FEAT_FIELDS(EMIT_PE_FIELD)
#undef EMIT_PE_FIELD

	return kTotalFeatDims;
}

} // namespace starlight_v3::lgbm

// 清理宏列表, 防止污染其他编译单元
#undef EFG_FEAT_FIELDS
#undef TSPM_FEAT_FIELDS
#undef PE_FEAT_FIELDS
