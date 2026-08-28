/**
 * @file pe/rich_header.cpp
 * @brief PE Rich Header解码与编译器指纹特征提取实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

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

	// 循环左移(校验和计算用)
	uint32_t rotate_left(uint32_t value, uint32_t bits) {
		bits &= 31;
		return bits == 0 ? value : (value << bits) | (value >> (32 - bits));
	}

	// 复算Rich Header校验和: DanS起始偏移 + DOS头各字节按下标循环左移 + 各条目按其计数循环左移
	// 链接器把该值同时用作异或密钥, 故校验和与密钥相等即结构完整
	// 注意: e_lfanew(0x3c~0x40)在计算时视为0, 因为写入Rich块时该字段尚未确定
	uint32_t rich_checksum(const uint8_t *data, size_t dans_offset, size_t rich_offset, uint32_t key) {
		uint32_t checksum = static_cast<uint32_t>(dans_offset);
		for (size_t i = 0; i < dans_offset; ++i) {
			if (i >= 0x3c && i < 0x40) {
				continue;
			}
			checksum += rotate_left(static_cast<uint32_t>(data[i]), static_cast<uint32_t>(i & 0x1f));
		}
		for (size_t offset = dans_offset + 16; offset + 8 <= rich_offset; offset += 8) {
			const uint32_t product_build = read_u32(data + offset) ^ key;
			const uint32_t count = read_u32(data + offset + 4) ^ key;
			checksum += rotate_left(product_build, count & 0x1f);
		}
		return checksum;
	}

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
	// 校验和吻合才认定结构完整(仅检查条目字节对齐会漏掉被改写过的Rich块)
	feats.valid = rich_checksum(data, dans_offset, rich_offset, key) == key ? 1.0 : 0.0;
	feats.entry_count = static_cast<double>(entry_bytes / 8);
	uint32_t min_build = std::numeric_limits<uint32_t>::max();
	uint32_t max_build = 0;
	uint32_t min_product = std::numeric_limits<uint32_t>::max();
	uint32_t max_product = 0;
	std::array<bool, 65536> products = {};
	std::array<bool, 65536> builds = {};
	double build_sum = 0.0;
	double build_sq_sum = 0.0;
	double zero_build_count = 0.0;
	double distinct_build_count = 0.0;
	uint32_t known_products = 0;
	for (size_t offset = dans_offset + 16; offset < rich_offset; offset += 8) {
		const uint32_t product_build = read_u32(data + offset) ^ key;
		const uint32_t count = read_u32(data + offset + 4) ^ key;
		const uint16_t product = static_cast<uint16_t>(product_build >> 16);
		const uint16_t build = static_cast<uint16_t>(product_build & 0xffffu);
		if (!products[product]) {
			products[product] = true;
			feats.distinct_product_count += 1.0;
		}
		if (!builds[build]) {
			builds[build] = true;
			distinct_build_count += 1.0;
		}
		if (product != 0 && product < 0x1000)
			++known_products;
		feats.total_count += static_cast<double>(count);
		build_sum += build;
		build_sq_sum += static_cast<double>(build) * build;
		// BuildId为0的条目是链接器记录的导入函数计数, 不代表编译器产物
		if (build == 0)
			zero_build_count += 1.0;
		feats.max_entry_count = std::max(feats.max_entry_count, static_cast<double>(count));
		min_build = std::min<uint32_t>(min_build, build);
		max_build = std::max<uint32_t>(max_build, build);
		min_product = std::min<uint32_t>(min_product, product);
		max_product = std::max<uint32_t>(max_product, product);
	}
	if (min_build != std::numeric_limits<uint32_t>::max()) {
		feats.min_build = min_build;
		feats.max_build = max_build;
		feats.build_span = max_build - min_build;
		feats.prodid_min = min_product;
		feats.prodid_max = max_product;
		feats.prodid_span = max_product - min_product;
	}
	const double entry_count = feats.entry_count;
	feats.known_product_count = known_products;
	feats.unknown_product_count = entry_count - known_products;
	feats.product_diversity = entry_count > 0.0 ? feats.distinct_product_count / entry_count : 0.0;
	feats.distinct_build_count = distinct_build_count;
	// BuildId不单调且同一取值可对应多个VS版本(如50727既是VS2005也是VS2012),
	// 故不按版本区间分桶, 仅统计不同BuildId数量, 具体阈值交由模型学习
	feats.mixed_toolchain = distinct_build_count > 1.0 ? 1.0 : 0.0;
	if (entry_count > 0.0) {
		feats.build_mean = build_sum / entry_count;
		const double variance = build_sq_sum / entry_count - feats.build_mean * feats.build_mean;
		feats.build_std = variance > 0.0 ? std::sqrt(variance) : 0.0;
		feats.build_zero_ratio = zero_build_count / entry_count;
	}
	// 产物计数的集中程度，避免只看总条目数丢失编译器组合信息。
	if (entry_count > 0.0 && feats.total_count > 0.0) {
		for (size_t offset = dans_offset + 16; offset < rich_offset; offset += 8) {
			const double p = static_cast<double>(read_u32(data + offset + 4) ^ key) / feats.total_count;
			if (p > 0.0)
				feats.count_entropy -= p * std::log2(p);
		}
	}
	feats.present_without_debug = view.data_dir(6).size == 0 ? 1.0 : 0.0;
	return feats;
}

} // namespace starlight_v3::pe
