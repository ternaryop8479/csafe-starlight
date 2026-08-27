/**
 * @file pe/capability.h
 * @brief 导入API能力类别特征提取
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_PE_CAPABILITY_H
#define CSAFE_STARLIGHT_V3_INCLUDE_PE_CAPABILITY_H

#include "basic/feat_pack.h"
#include "pe/imports.h"

namespace starlight_v3::pe {

/**
 * @brief 提取导入API能力类别特征(12维)
 * @param imports 已枚举好的导入项列表(见enumerate_imports), 由调用方解析一次后与IAT特征共用
 * @return 提取出的12维特征
 */
CapabilityFeatPack extract_capability_feats(const std::vector<ImportEntry> &imports);

} // namespace starlight_v3::pe

#endif
