/**
 * @file lgbm/feat_extractor/pe.h
 * @brief PE静态特征提取器
 * @author ternaryop8479
 * @date 2026-08-02
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_PE_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_FEAT_EXTRACTOR_PE_H

#include <string>

#include "basic/feat_pack.h"

namespace starlight_v3::lgbm {

/**
 * @brief 从PE文件中提取静态特征(89维)
 *
 * 特征完全依据PEFeatPack的字段定义计算, 分为六组:
 * PE头数据29维 + 节段熵7维 + 节段统计12维 + 导入表统计21维 + 字符串10维 + 结构统计10维
 *
 * 注意事项:
 * 1. 使用pe-parse重新解析目标文件, 仅在文件不是PE格式或损坏到无意义时返回全零特征;
 *    其余情况尽可能提取, 仅提取失败的部分填充零.
 * 2. 字符串特征仅扫描不可执行节段(提升速度且不丢失关键信息),
 *    printable_ratio为可打印字节占被扫描字节的比例.
 * 3. pe-parse的迭代可能抛出STL异常(参考efg_generator的错误处理方式),
 *    异常时保留已提取的中间结果继续填充.
 * 4. 序号导入(symbol为空)不参与API名相关统计.
 * 5. 高危API/DLL/字符串关键词判定表与标准节段前缀表见实现文件.
 * @param file_path 目标PE文件路径
 * @return 提取出的89维特征
 */
PEFeatPack extract_pe_feats(const std::string &file_path);

} // namespace starlight_v3::lgbm

#endif
