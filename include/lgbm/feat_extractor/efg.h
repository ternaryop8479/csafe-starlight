/**
 * @file lgbm/feat_extractor/efg.h
 * @brief EFG的特征提取器
 * @author ternaryop8479
 * @date 2026-08-02
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_EFG_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_EFG_H

#include "basic/efg.h"
#include "basic/feat_pack.h"

namespace starlight_v3::lgbm {

/**
 * @brief 从EFG中提取结构及边信息特征(39维)
 *
 * 特征完全依据EFGFeatPack的字段定义计算:
 * 结构统计11维(节点/边/密度/出度/孤立节点/最大连通分量/结构熵)
 * 边信息统计28维(跳转次数/间接跳转/跨度/携带数据的边的子集统计)
 *
 * 注意事项:
 * 1. EFG的边只保存avg_span与span_variance, 无原始跨度列表,
 *    因此所有跨度族特征以单边avg_span作为跨边统计的样本值(近似).
 * 2. 结构熵为出度分布的Shannon熵; 孤立节点数为出度为0的节点数.
 * 3. 空集合统计一律置0.0, 不产生NaN/INVALID_NUM.
 * @param efg 目标EFG, 只读, 不修改
 * @return 提取出的39维特征
 */
EFGFeatPack extract_efg_feats(const EFG &efg);

} // namespace starlight_v3::lgbm

#endif
