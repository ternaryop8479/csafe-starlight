/**
 * @file pe/dotnet.h
 * @brief CLR头与.NET元数据轻量解析及特征提取
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_PE_DOTNET_H
#define CSAFE_STARLIGHT_V3_INCLUDE_PE_DOTNET_H

#include "basic/feat_pack.h"
#include "pe/view.h"

namespace starlight_v3::pe {

/**
 * @brief 提取CLR头与.NET元数据特征
 * @param view 已加载的PE文件视图
 * @return .NET元数据特征(维度见lgbm::kDotnetFeatDims), 非.NET文件返回全零
 */
DotnetFeatPack extract_dotnet_feats(const PeView &view);

} // namespace starlight_v3::pe

#endif
