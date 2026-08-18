/**
 * @file lgbm/feat_extractor/pe.h
 * @brief PE静态特征提取器
 * @author ternaryop8479
 * @date 2026-08-02
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_PE_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_PE_H

#include <string>

#include "basic/feat_pack.h"
#include "lgbm/feat_extractor/byte_hist.h"

namespace starlight_v3::lgbm {

/**
 * @brief 从PE文件中提取静态特征(91维)
 * @param file_path 目标PE文件路径
 * @param byte_hist_out 可选输出参数: 非空时同步填充字节直方图特征(复用同一次PE解析的文件字节, 零额外磁盘I/O)
 * @return 提取出的91维特征
 */
PEFeatPack extract_pe_feats(const std::string &file_path, ByteHistFeatPack *byte_hist_out = nullptr);

} // namespace starlight_v3::lgbm

#endif
