/**
 * @file lgbm/feat_extractor/byte_hist.h
 * @brief 文件分块熵特征提取器
 * @author ternaryop8479
 * @date 2026-08-18
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_BYTE_HIST_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_BYTE_HIST_H

#include <cstdint>

#include "basic/feat_pack.h"

namespace starlight_v3::lgbm {

/**
 * @brief 从原始文件字节提取分块熵特征(16维)
 * @note 全文件按字节数均分16块统计每块Shannon熵(0~8), 最后一块并入尾部余数.
 * @param data 文件完整字节，只读，可为nullptr
 * @param len 字节长度，为0时返回全零特征
 * @return 提取出的16维特征
 */
BlockEntropyFeatPack extract_block_entropy_feats(const uint8_t *data, SIZE_T len);

} // namespace starlight_v3::lgbm

#endif
