/**
 * @file pe/imports.cpp
 * @brief PE导入表轻量解析实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

#include "pe/imports.h"

namespace starlight_v3::pe {

namespace {

	template <typename T>
	T read(const uint8_t *data, size_t offset, size_t size) {
		if (offset > size || sizeof(T) > size - offset)
			return 0;
		T value = 0;
		std::memcpy(&value, data + offset, sizeof(T));
		return value;
	}

	constexpr uint32_t kImportDirectory = 1;
	constexpr uint32_t kDelayImportDirectory = 13;

} // namespace

std::vector<ImportEntry> enumerate_imports(const PeView &view) {
	std::vector<ImportEntry> result;
	const PeView::Dir dir = view.data_dir(kImportDirectory);
	if (dir.rva == 0 || dir.size < 20)
		return result;
	size_t descriptor_offset = 0;
	if (!view.rva_to_offset(dir.rva, descriptor_offset))
		return result;
	const uint8_t *data = view.data();
	const size_t total = view.size();
	const size_t dir_end = std::min(total, descriptor_offset + static_cast<size_t>(dir.size));
	const uint64_t ordinal_flag = view.is64() ? 0x8000000000000000ULL : 0x80000000ULL;
	const size_t thunk_size = view.is64() ? 8 : 4;
	for (size_t d = descriptor_offset; d + 20 <= dir_end; d += 20) {
		const uint32_t original_thunk = read<uint32_t>(data, d, total);
		const uint32_t name_rva = read<uint32_t>(data, d + 12, total);
		const uint32_t first_thunk = read<uint32_t>(data, d + 16, total);
		if (original_thunk == 0 && name_rva == 0 && first_thunk == 0)
			break;
		size_t name_offset = 0;
		if (!view.rva_to_offset(name_rva, name_offset) || name_offset >= total)
			continue;
		const char *name = reinterpret_cast<const char *>(data + name_offset);
		const size_t name_len = strnlen(name, total - name_offset);
		const std::string dll(name, name_len);
		const uint32_t thunk_rva = original_thunk != 0 ? original_thunk : first_thunk;
		size_t thunk_offset = 0;
		if (!view.rva_to_offset(thunk_rva, thunk_offset))
			continue;
		for (size_t t = 0; thunk_offset + thunk_size <= total && t < 1u << 20; ++t) {
			const uint64_t value = view.is64() ? read<uint64_t>(data, thunk_offset, total) : read<uint32_t>(data, thunk_offset, total);
			if (value == 0)
				break;
			ImportEntry entry;
			entry.dll_name = dll;
			entry.ordinal = (value & ordinal_flag) != 0;
			if (!entry.ordinal) {
				const uint32_t hint_name_rva = static_cast<uint32_t>(value);
				size_t hint_name_offset = 0;
				if (view.rva_to_offset(hint_name_rva, hint_name_offset) && hint_name_offset + 2 < total) {
					const char *function = reinterpret_cast<const char *>(data + hint_name_offset + 2);
					const size_t max_len = total - hint_name_offset - 2;
					entry.function_name.assign(function, strnlen(function, max_len));
				}
			}
			result.push_back(std::move(entry));
			thunk_offset += thunk_size;
		}
	}
	(void)kDelayImportDirectory; // 延迟导入特征由IAT模块根据数据目录单独统计
	return result;
}

} // namespace starlight_v3::pe
