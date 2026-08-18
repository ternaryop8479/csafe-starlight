/**
 * @file lgbm/feat_extractor/byte_hist.h
 * @brief 文件原始字节分布特征提取器
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
 * @brief 从原始文件字节提取字节分布特征(272维)
 * @note byte_hist[i] = log1p(256 * count_i / total)，与文件大小解耦，均匀分布时各维约0.69；
 * 文件均分16块统计每块Shannon熵(0~8), 最后一块并入尾部余数.
 * @param data 文件完整字节，只读，可为nullptr
 * @param len 字节长度，为0时返回全零特征
 * @return 提取出的272维特征
 */
ByteHistFeatPack extract_byte_hist_feats(const uint8_t *data, SIZE_T len);

} // namespace starlight_v3::lgbm

#endif
