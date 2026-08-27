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
#include "pe/view.h"

namespace starlight_v3::lgbm {

/**
 * @brief 从已读入内存的PE文件视图中提取静态特征(91维)
 * @param view 目标PE文件视图(见pe/view.h)，其生命周期必须覆盖本次调用
 * @param block_entropy_out 可选输出参数: 非空时填充分块熵特征(复用同一次PE解析的文件字节, 零额外磁盘I/O; 提取失败时填全零)
 * @note 供已持有PeView的调用方复用同一份文件字节，避免重复读盘
 * @return 提取出的91维特征
 */
PEFeatPack extract_pe_feats(const pe::PeView &view, BlockEntropyFeatPack *block_entropy_out = nullptr);

/**
 * @brief 从PE文件中提取静态特征(91维)
 * @param file_path 目标PE文件路径
 * @param block_entropy_out 可选输出参数: 非空时填充分块熵特征(复用同一次PE解析的文件字节, 零额外磁盘I/O; 提取失败时填全零)
 * @note 内部读入文件后转调视图版本，仅需PE特征的调用方可直接使用本重载
 * @return 提取出的91维特征
 */
PEFeatPack extract_pe_feats(const std::string &file_path, BlockEntropyFeatPack *block_entropy_out = nullptr);

} // namespace starlight_v3::lgbm

#endif
