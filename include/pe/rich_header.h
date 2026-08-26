/**
 * @file pe/rich_header.h
 * @brief PE Rich Header解码与编译器指纹特征提取
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_PE_RICH_HEADER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_PE_RICH_HEADER_H

#include "basic/feat_pack.h"
#include "pe/view.h"

namespace starlight_v3::pe {

/**
 * @brief 提取Rich Header编译器指纹特征
 * @param view 已加载的PE文件视图
 * @return 10维Rich Header特征
 */
RichHeaderFeatPack extract_rich_header_feats(const PeView &view);

} // namespace starlight_v3::pe

#endif
