/**
 * @file lgbm/feat_extractor/tspm.h
 * @brief tosSPM推理结果的特征提取器
 * @author ternaryop8479
 * @date 2026-08-02
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_TSPM_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_TSPM_H

#include "basic/efg.h"
#include "basic/feat_pack.h"
#include "tspm/reasoner.h"

namespace starlight_v3::lgbm {

/**
 * @brief 从tosSPM推理结果中提取特征(43维)
 * @param result tosSPM引擎推理结果
 * @param efg 推理时使用的EFG(用于计算入口距离与节点总数), 只读, 不修改
 * @return 提取出的43维特征
 */
TSPMFeatPack extract_tspm_feats(const tspm::AnalysisResult &result, const EFG &efg);

} // namespace starlight_v3::lgbm

#endif
