/**
 * @file lgbm/feat_vector.h
 * @brief 特征向量的维度约定与FeatPack序列化接口
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_VECTOR_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_VECTOR_H

#include "basic/feat_pack.h"
#include "basic/types.h"

namespace starlight_v3::lgbm {

// 各特征组的维度(与feat_pack.h中的结构体字段一一对应)
constexpr SIZE_T kEfgFeatDims = 36; ///< EFG结构及边信息特征维度(EFGFeatPack)
constexpr SIZE_T kTspmFeatDims = 35; ///< tosSPM推理结果特征维度(TSPMFeatPack)
constexpr SIZE_T kPeFeatDims = 91; ///< PE静态特征维度(PEFeatPack，含CLR与壳指纹)
constexpr SIZE_T kBlockEntropyFeatDims = 16; ///< 文件分块熵特征维度(BlockEntropyFeatPack)
constexpr SIZE_T kSigFeatDims = 2; ///< 白签名置信度特征维度(SigFeatPack)
constexpr SIZE_T kRichHeaderFeatDims = 22; ///< Rich Header编译器指纹特征维度(RichHeaderFeatPack)
constexpr SIZE_T kDotnetFeatDims = 24; ///< CLR与.NET元数据特征维度(DotnetFeatPack)
constexpr SIZE_T kIatFeatDims = 8; ///< IAT/导入目录结构特征维度(IatFeatPack)
constexpr SIZE_T kCapabilityFeatDims = 12; ///< 导入API能力类别特征维度(CapabilityFeatPack)
constexpr SIZE_T kTotalFeatDims = 246; ///< 总特征维度(36 + 35 + 91 + 16 + 2 + 22 + 24 + 8 + 12)

/**
 * @brief 将FeatPack按固定顺序序列化为double特征向量
 * @note 特征顺序约定: 先EFG特征(36维), 再TSPM特征(35维), 然后PE特征(91维), 再分块熵特征(16维), 签名置信度特征(2维), Rich Header特征(22维), .NET特征(24维), IAT特征(8维), 最后能力类别特征(12维).
 * 该顺序与feat_vector.cpp中宏列表的顺序保持一致, 训练与推理共用本函数, 保证特征顺序永不漂移.
 * bool字段序列化为0/1, SIZE_T与GREAT_SIZE_T字段序列化为static_cast<double>(无精度损失).
 * @param feats 待序列化的特征集合, 只读, 不修改
 * @param out 输出缓冲区, 调用方必须保证容量至少为kTotalFeatDims个double
 * @return 实际写入的维度数, 恒等于kTotalFeatDims
 */
SIZE_T serialize_feat_pack(const FeatPack &feats, double *out);

} // namespace starlight_v3::lgbm

#endif
