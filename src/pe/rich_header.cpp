/**
 * @file pe/rich_header.cpp
 * @brief PE Rich Header解码与编译器指纹特征提取实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>

#include "pe/rich_header.h"

namespace starlight_v3::pe {

namespace {

uint32_t read_u32(const uint8_t *data) {
	uint32_t value = 0;
	std::memcpy(&value, data, sizeof(value));
	return value;
}

constexpr uint32_t kRich = 0x68636952; // "Rich"小端序
constexpr uint32_t kDanS = 0x536e6144; // "DanS"小端序

} // namespace

RichHeaderFeatPack extract_rich_header_feats(const PeView &view) {
	RichHeaderFeatPack feats = {};
	if (view.size() < 0x40) {
		return feats;
	}

	const uint8_t *data = view.data();
	uint32_t lfanew = 0;
	std::memcpy(&lfanew, data + 0x3c, sizeof(lfanew));
	const size_t limit = std::min<size_t>(lfanew, view.size());
	if (limit <= 0x40) {
		return feats;
	}

	// Rich标记位于PE头之前的DOS Stub中, 其后的DWORD是解密异或密钥。
	size_t rich_offset = std::numeric_limits<size_t>::max();
	for (size_t i = 0x40; i + 8 <= limit; ++i) {
		if (read_u32(data + i) == kRich) {
			rich_offset = i;
			break;
		}
	}
	if (rich_offset == std::numeric_limits<size_t>::max()) {
		return feats;
	}
	feats.present = 1.0;
	const uint32_t key = read_u32(data + rich_offset + 4);
	size_t dans_offset = std::numeric_limits<size_t>::max();
	for (size_t i = 0x40; i + 4 <= rich_offset; i += 4) {
		if ((read_u32(data + i) ^ key) == kDanS) {
			dans_offset = i;
			break;
		}
	}
	if (dans_offset == std::numeric_limits<size_t>::max() || dans_offset + 16 > rich_offset) {
		return feats;
	}

	const size_t entry_bytes = rich_offset - (dans_offset + 16);
	if (entry_bytes == 0 || entry_bytes % 8 != 0) {
		return feats;
	}
	feats.valid = 1.0;
	feats.entry_count = static_cast<double>(entry_bytes / 8);
	uint32_t min_build = std::numeric_limits<uint32_t>::max();
	uint32_t max_build = 0;
	std::array<bool, 65536> products = {};
	for (size_t offset = dans_offset + 16; offset < rich_offset; offset += 8) {
		const uint32_t product_build = read_u32(data + offset) ^ key;
		const uint32_t count = read_u32(data + offset + 4) ^ key;
		const uint16_t product = static_cast<uint16_t>(product_build >> 16);
		const uint16_t build = static_cast<uint16_t>(product_build & 0xffffu);
		if (!products[product]) {
			products[product] = true;
			feats.distinct_product_count += 1.0;
		}
		feats.total_count += static_cast<double>(count);
		feats.max_entry_count = std::max(feats.max_entry_count, static_cast<double>(count));
		min_build = std::min<uint32_t>(min_build, build);
		max_build = std::max<uint32_t>(max_build, build);
	}
	if (min_build != std::numeric_limits<uint32_t>::max()) {
		feats.min_build = min_build;
		feats.max_build = max_build;
		feats.build_span = max_build - min_build;
	}
	feats.present_without_debug = view.data_dir(6).size == 0 ? 1.0 : 0.0;
	return feats;
}

} // namespace starlight_v3::pe
