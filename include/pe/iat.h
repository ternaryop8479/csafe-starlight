/**
 * @file pe/iat.h
 * @brief IAT/导入目录结构特征提取
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_PE_IAT_H
#define CSAFE_STARLIGHT_V3_INCLUDE_PE_IAT_H

#include "basic/feat_pack.h"
#include "pe/imports.h"
#include "pe/view.h"

namespace starlight_v3::pe {

/**
 * @brief 提取IAT/导入目录结构特征(8维)
 * @param view 目标PE文件视图(用于读取导入/延迟导入/绑定导入数据目录)
 * @param imports 已枚举好的导入项列表(见enumerate_imports), 由调用方解析一次后与能力特征共用
 * @return 提取出的8维特征
 */
IatFeatPack extract_iat_feats(const PeView &view, const std::vector<ImportEntry> &imports);

} // namespace starlight_v3::pe

#endif
