/**
 * @file lgbm/feat_extractor/efg.h
 * @brief EFG的特征提取器
 * @author ternaryop8479
 * @date 2026-08-02
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_EFG_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_EFG_H

#include "basic/efg.h"
#include "basic/feat_pack.h"

namespace starlight_v3::lgbm {

/**
 * @brief 从EFG中提取结构及边信息特征(39维)
 * @param efg 目标EFG, 只读, 不修改
 * @return 提取出的39维特征
 */
EFGFeatPack extract_efg_feats(const EFG &efg);

} // namespace starlight_v3::lgbm

#endif
