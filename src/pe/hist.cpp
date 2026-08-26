/**
 * @file pe/hist.cpp
 * @brief 文件分块熵特征提取器实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <array>
#include <cmath>

#include "pe/hist.h"

namespace {

using starlight_v3::SIZE_T; // 匿名命名空间内使用引擎基础类型

// 计算字节序列的Shannon熵(以2为底): 统计256种字节值频率得到概率分布，
// 熵 = -sum(p * log2(p))，空序列返回0.0。
double block_shannon_entropy(const uint8_t *data, SIZE_T len) {
	if (len == 0) {
		return 0.0;
	}
	std::array<uint64_t, 256> freq = {};
	for (SIZE_T i = 0; i < len; ++i) {
		++freq[data[i]];
	}
	double entropy = 0.0;
	for (int i = 0; i < 256; ++i) {
		if (freq[i] == 0) {
			continue;
		}
		double p = (double)freq[i] / (double)len;
		entropy -= p * std::log2(p);
	}
	return entropy;
}

} // namespace

namespace starlight_v3::pe {

BlockEntropyFeatPack extract_block_entropy_feats(const uint8_t *data, SIZE_T len) {
	BlockEntropyFeatPack feats = {}; // 值初始化，空输入保持全零
	if (data == nullptr || len == 0) {
		return feats;
	}

	// 分块熵: 均分16块，最后一块并入尾部余数
	static constexpr SIZE_T kBlockCount = 16;
	const SIZE_T block_size = len / kBlockCount;
	SIZE_T offset = 0;
	for (SIZE_T b = 0; b < kBlockCount; ++b) {
		SIZE_T block_len = (b == kBlockCount - 1) ? (len - offset) : block_size;
		feats.block_entropy[b] = block_shannon_entropy(data + offset, block_len);
		offset += block_len;
	}

	return feats;
}

} // namespace starlight_v3::pe
