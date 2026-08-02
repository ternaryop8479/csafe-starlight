/**
 * @file lgbm/feat_extractor/tspm.h
 * @brief tosSPM推理结果的特征提取器
 * @author ternaryop8479
 * @date 2026-08-02
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_TSPM_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_TSPM_H

#include "basic/efg.h"
#include "basic/feat_pack.h"
#include "tspm/reasoner.h"

namespace starlight_v3::lgbm {

/**
 * @brief 从tosSPM推理结果中提取特征(43维)
 *
 * 特征完全依据TSPMFeatPack的字段定义计算:
 * 链条统计20维 + 链条权重12维 + 引擎输出4维 + 执行统计6维 + 最终输出1维
 *
 * 语义约定(与tosSPM引擎2026-08-02对EvidenceTree的扩展一致):
 * 1. 一条"链" = 证据森林中根→weight≠0节点的路径, 共享子树按路径实例重复计数;
 *    链的类别由终止节点权重符号决定(正=恶意, 负=良性).
 * 2. 链长度 = 路径节点总数(含被跳过的节点).
 * 3. 链的跳过次数 = 路径上is_skipped==true的节点数.
 * 4. 匹配深度 = 链根节点到EFG入口(节点0)的边数, 由EFG计算;
 *    入口不可达(孤立节点)的链深度记0且不参与深度统计.
 * 5. 链条密度 = 链路径全部节点(含跳过)在EFG中下标的去重并集 / EFG节点总数.
 * 6. 相似度 = 平均链长 * 链数 / 覆盖节点数.
 * 7. 空集合的统计量一律置0.0, 不产生NaN/INF.
 * @param result tosSPM引擎推理结果
 * @param efg 推理时使用的EFG(用于计算入口距离与节点总数), 只读, 不修改
 * @return 提取出的43维特征
 */
TSPMFeatPack extract_tspm_feats(const tspm::AnalysisResult &result, const EFG &efg);

} // namespace starlight_v3::lgbm

#endif
