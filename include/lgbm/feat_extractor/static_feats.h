/**
 * @file lgbm/feat_extractor/static_feats.h
 * @brief 文件字节派生的静态特征组聚合提取器
 * @author ternaryop8479
 * @date 2026-08-27
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_STATIC_FEATS_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_STATIC_FEATS_H

#include "basic/feat_pack.h"
#include "pe/authenticode.h"
#include "pe/view.h"

namespace starlight_v3::lgbm {

/**
 * @brief 从PE文件视图一次性提取全部文件字节派生的静态特征组
 * @param view 目标PE文件视图(见pe/view.h)，其生命周期必须覆盖本次调用
 * @param feats 输出: 填充PE头节段/分块熵/Rich Header/.NET/IAT/能力六组特征, 其余组保持原值
 * @note 全程复用同一份文件字节, 无额外磁盘I/O。签名者身份以返回值给出而不直接落特征,
 * 因其折叠为置信度需查白签名表, 本函数不依赖模型侧数据。
 * @return 签名者身份, 供上层查白签名表后填充SigFeatPack
 */
pe::CertIdentity extract_static_feats(const pe::PeView &view, FeatPack &feats);

} // namespace starlight_v3::lgbm

#endif
