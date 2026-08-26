/**
 * @file pe/iat.cpp
 * @brief IAT/导入目录结构特征提取实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <array>
#include <cctype>
#include <cmath>
#include <string>

#include "pe/iat.h"
#include "pe/imports.h"

namespace starlight_v3::pe {

namespace {

double name_entropy(const std::string &value) {
	if (value.empty()) return 0.0;
	std::array<size_t, 256> counts = {};
	for (unsigned char c : value) ++counts[c];
	double result = 0.0;
	for (size_t count : counts) {
		if (count == 0) continue;
		const double p = static_cast<double>(count) / value.size();
		result -= p * std::log2(p);
	}
	return result;
}

bool system_dll(const std::string &name) {
	std::string lower = name;
	for (char &c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return lower == "kernel32.dll" || lower == "kernelbase.dll" || lower == "ntdll.dll"
		|| lower == "user32.dll" || lower == "advapi32.dll" || lower == "msvcrt.dll";
}

} // namespace

IatFeatPack extract_iat_feats(const PeView &view) {
	IatFeatPack feats = {};
	const auto imports = enumerate_imports(view);
	const double count = static_cast<double>(imports.size());
	feats.import_count = count;
	if (count != 0.0) {
		double ordinal = 0.0;
		double entropy_sum = 0.0;
		for (const auto &entry : imports) {
			ordinal += entry.ordinal ? 1.0 : 0.0;
			entropy_sum += name_entropy(entry.dll_name);
		}
		feats.ordinal_ratio = ordinal / count;
		feats.import_dll_entropy = entropy_sum / count;
		feats.first_dll_is_system = system_dll(imports.front().dll_name) ? 1.0 : 0.0;
	}
	const PeView::Dir import_dir = view.data_dir(1);
	const PeView::Dir delay_dir = view.data_dir(13);
	const PeView::Dir bound_dir = view.data_dir(11);
	feats.import_directory_size = import_dir.size;
	feats.delay_import_present = delay_dir.rva != 0 && delay_dir.size != 0 ? 1.0 : 0.0;
	feats.delay_import_size = delay_dir.size;
	feats.bound_import_present = bound_dir.rva != 0 && bound_dir.size != 0 ? 1.0 : 0.0;
	return feats;
}

} // namespace starlight_v3::pe
