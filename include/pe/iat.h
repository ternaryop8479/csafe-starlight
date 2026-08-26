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
#include "pe/view.h"

namespace starlight_v3::pe {

IatFeatPack extract_iat_feats(const PeView &view);

} // namespace starlight_v3::pe

#endif
