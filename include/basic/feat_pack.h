/**
 * @file feat_pack.h
 * @brief 程序的特征数据集合数据结构封装
 * @author ternaryop8479
 * @date 2026-07-31
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_BASIC_FEAT_PACK_H
#define CSAFE_STARLIGHT_V3_INCLUDE_BASIC_FEAT_PACK_H

#include "types.h"

namespace starlight_v3 {

/**
 * @brief 来自tosSPM推理结果的特征数据(43维)
 */
struct TSPMFeatPack { // 累死我了呜呜呜呜
	// 链条统计特征
	SIZE_T max_malchain_length; ///< 匹配到的最长病毒链长度
	double avg_malchain_length; ///< 匹配到的平均病毒链长度
	SIZE_T max_benchain_length; ///< 匹配到的最长良性链长度
	double avg_benchain_length; ///< 匹配到的平均良性链长度
	SIZE_T malchain_count; ///< 匹配到的病毒链数
	SIZE_T benchain_count; ///< 匹配到的良性链数
	double mal_ben_avglength_ratio; ///< 平均病毒链长度/平均良性链长度
	double mal_ben_maxlength_ratio; ///< 最长病毒链长度/最长良性链长度
	SIZE_T chain_count_diff; ///< 恶意链数量与良性链数量之差
	bool is_mal_dominant; ///< 最长链是否是恶意调用链
	double malchain_density; ///< 恶意链条密度，即匹配的恶意链条覆盖的节点与总节点数之比
	double benchain_density; ///< 良性链条密度，即匹配的良性链条覆盖的节点与总节点数之比
	double avg_malchain_similarity; ///< 恶意链条平均相似度(由匹配的平均链长度、匹配到的链数量以及链条密度可以直接计算得出)
	double avg_benchain_similarity; ///< 良性链条平均相似度(由匹配的平均链长度、匹配到的链数量以及链条密度可以直接计算得出)
	double avg_malmatch_depth; ///< 恶意链条匹配发生的平均深度
	double avg_benmatch_depth; ///< 良性链条匹配发生的平均深度
	SIZE_T max_malmatch_depth; ///< 恶意链条匹配发生的最大深度
	SIZE_T max_benmatch_depth; ///< 良性链条匹配发生的最大深度
	SIZE_T malapi_count; ///< 恶意链条的API总数
	SIZE_T benapi_count; ///< 良性链条的API总数

	// 链条权重特征
	double avg_malchain_weight; ///< 恶意链条平均权重
	double malchain_weight_var; ///< 恶意链条权重方差
	double malchain_weight_ske; ///< 恶意链条权重偏度
	double avg_benchain_weight; ///< 良性链条平均权重
	double benchain_weight_var; ///< 良性链条权重方差
	double benchain_weight_ske; ///< 良性链条权重偏度
	double max_malchain_weight; ///< 恶意链条最高权重
	double max_benchain_weight; ///< 良性链条最高权重
	double avg_malweight_density; ///< 所有病毒链条长度与链条权重之比的均值
	double avg_benweight_density; ///< 所有良性链条长度与链条权重之比的均值
	double max_malweight_density; ///< 病毒链条长度与链条权重之比的最大值
	double max_benweight_density; ///< 良性链条长度与链条权重之比的最大值

	// 引擎输出权重特征
	double tspm_mal_weight; ///< 引擎输出的程序恶意权重
	double tspm_ben_weight; ///< 引擎输出的程序良性权重
	double weight_diff; ///< 引擎输出的恶意权重与良性权重之差
	double weight_ratio; ///< 引擎输出的恶意权重与良性权重之比

	// 引擎执行过程中的统计特征
	double avg_malskip_count; ///< 匹配单条恶意链条时的平均跳过次数
	double avg_benskip_count; ///< 匹配单条良性链条时的平均跳过次数
	double avg_malchain_branching; ///< 匹配到的恶意链条所根据EFG合并成的树的平均出度
	double avg_benchain_branching; ///< 匹配到的良性链条所根据EFG合并成的树的平均出度
	double max_malchain_branching; ///< 匹配到的恶意链条所根据EFG合并成的树的最大出度
	double max_benchain_branching; ///< 匹配到的良性链条所根据EFG合并成的树的最大出度

	// 引擎最终输出
	double tspm_score; ///< tosSPM引擎输出的最终权重
};

/**
 * @brief 来自程序EFG控制流程图的推理数据(39维)
 */
struct EFGFeatPack {
	// EFG的结构统计数据(11维)
	SIZE_T node_count; ///< EFG节点总数
	SIZE_T edge_count; ///< EFG边总数
	double density; ///< 图密度，边数/(节点数 * (节点数 - 1))
	double avg_degree; ///< 图平均出度
	SIZE_T max_degree; ///< 图最大出度
	double degree_var; ///< 图出度方差
	double degree_ske; ///< 图出度偏度
	double edge_node_ratio; ///< 边数/节点比
	SIZE_T isolated_node_count; ///< 孤立节点数(即连通分量数-1)
	double largest_component_ratio; ///< 最大连通分量占比(包含ENTRY节点的连通分量节点数占全图总节点数之比)
	double entropy; ///< 图的结构熵

	// EFG的边信息数据(28维)
	double avg_jmp_count; ///< 单边平均跳转次数
	double jmp_count_var; ///< 边跳转次数方差
	double jmp_count_ske; ///< 边跳转次数偏度
	double max_jmp_count; ///< 最大跳转次数
	double avg_indirect_jmp_count; ///< 单边平均间接跳转次数
	double indirect_jmp_count_var; ///< 边间接跳转次数方差
	double indirect_jmp_count_ske; ///< 边间接跳转次数偏度
	double max_indirect_jmp_count; ///< 最大间接跳转次数
	double indirect_jmp_edge_ratio; ///< 带有间接跳转的边与总边数之比
	double total_indirect_jmp_count; ///< 总间接跳转次数
	double max_span; ///< 最大跨度
	double avg_span; ///< 边平均跨度
	double span_var; ///< 边跨度的方差
	double span_ske; ///< 边跨度的偏度
	double jmp_count_entropy; ///< 跳转次数分布的熵
	double data_flow_edge_ratio; ///< 携带数据的边占总边数之比
	double avg_span_with_data; ///< 携带数据的边的平均跨度
	double max_span_with_data; ///< 携带数据的边的最大跨度
	double span_with_data_var; ///< 携带数据的边的跨度方差
	double span_with_data_ske; ///< 携带数据的边的跨度偏度
	double avg_jmp_count_with_data; ///< 携带数据的边的平均跳转次数
	double max_jmp_count_with_data; ///< 携带数据的边的最大跳转次数
	double jmp_count_with_data_var; ///< 携带数据的边的跳转次数方差
	double jmp_count_with_data_ske; ///< 携带数据的边的跳转次数偏度
	double avg_indirect_jmp_with_data; ///< 携带数据的边的平均间接跳转次数
	double max_indirect_jmp_with_data; ///< 携带数据的边的最大间接跳转次数
	double indirect_jmp_with_data_var; ///< 携带数据的边的间接跳转次数方差
	double indirect_jmp_with_data_ske; ///< 携带数据的边的间接跳转次数偏度
};

struct FeatPack {
	// 来自tosSPM引擎推理过程及结果的特征数据
	TSPMFeatPack tspm_feats;

	// 从EFG中能够提取出的特征数据
	EFGFeatPack efg_feats;

	// 程序PE结构统计数据
	// 程序PE头数据
	// 来自程序不同节段的熵数据
	// 程序的节段统计数据
	// 程序的导入表统计数据
	// 程序字符串相关数据
};

}

#endif
