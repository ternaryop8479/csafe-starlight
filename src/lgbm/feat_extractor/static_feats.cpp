/**
 * @file lgbm/feat_extractor/static_feats.cpp
 * @brief 文件字节派生的静态特征组聚合提取器实现
 * @author ternaryop8479
 * @date 2026-08-27
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <vector>

#include "lgbm/feat_extractor/pe.h"
#include "lgbm/feat_extractor/static_feats.h"
#include "pe/authenticode.h"
#include "pe/capability.h"
#include "pe/dotnet.h"
#include "pe/iat.h"
#include "pe/imports.h"
#include "pe/rich_header.h"

namespace starlight_v3::lgbm {

pe::CertIdentity extract_static_feats(const pe::PeView &view, FeatPack &feats) {
	// PE头/节段特征与分块熵特征(后者复用同一次解析的文件字节)
	feats.pe_feats = extract_pe_feats(view, &feats.block_entropy_feats);

	// 直接由文件视图解析的特征组
	feats.rich_header_feats = pe::extract_rich_header_feats(view);
	feats.dotnet_feats = pe::extract_dotnet_feats(view);

	// 导入表解析一次后由IAT与能力两组特征共用
	const std::vector<pe::ImportEntry> imports = pe::enumerate_imports(view);
	feats.iat_feats = pe::extract_iat_feats(view, imports);
	feats.capability_feats = pe::extract_capability_feats(imports);

	// 签名者身份交由上层查表折叠为置信度
	return pe::inspect_signature(view);
}

} // namespace starlight_v3::lgbm
