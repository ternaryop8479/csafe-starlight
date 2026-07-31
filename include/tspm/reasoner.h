/**
 * @file tspm/reasoner.h
 * @brief tosSPM模型推理引擎接口声明
 * @author ternaryop8479
 * @date 2026-07-31
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_TSPM_REASONER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_TSPM_REASONER_H

#include "basic/efg.h"
#include "basic/types.h"
#include "tspm/model.h"
#include <memory>

namespace starlight_v3::tspm {

/**
 * @brief 模型推理过程中的证据树(即dfs树)
 */
struct EvidenceTree {
	std::string api_name;
	double weight;
	std::vector<std::shared_ptr<EvidenceTree>> sub_nodes;
};

/**
 * @brief 模型输出的推理结果，包含推理链和各维度评估分数等
 */
struct AnalysisResult {
	std::vector<std::shared_ptr<EvidenceTree>> evidence_trees;
	double final_score = 0.0;
	double malware_score = 0.0;
	double benign_score = 0.0;
};

class Reasoner {

public:
	Reasoner() = delete; // 不允许使用默认构造函数初始化，必须传入一个const Model引用
	~Reasoner() = default;

	/**
	 * @brief 唯一构造函数
	 * @param model 已加载(或将要在Reasoner开始推理前加载)的const Model引用，即Reasoner所使用的模型对象
	 */
	Reasoner(const Model &model);

	/**
	 * @brief 通过程序的EFG(外部调用流程图)对一个程序进行分析
	 * @param efg 从已知程序中提取的外部调用流程图(详细接口见efg_generator.h)
	 * @param enable_record_evidence 是否启用推理证据记录，如果启用的话将会记录证据树
	 * @return 分析结果，包含各维度评估分数及推理链
	 */
	AnalysisResult analyze_efg(const EFG &efg, bool enable_record_evidence = true);

private:
	const Model &model_; ///< 用于推理的模型

	/**
	 * @brief 用于在推理过程中表示当前匹配链条的总黑白权重
	 */
	struct DFSData {
		std::shared_ptr<EvidenceTree> current_tree = nullptr; ///< 当前节点的dfs树指针
		double black_weight = 0.0; ///< 黑权重
		double white_weight = 0.0; ///< 白权重

#pragma omp declare simd // 该SIMD优化应用于+=运算符重载函数
		/**
		 * @brief 权重+=运算符重载
		 * @return 返回经过加法后的当前对象
		 */
		DFSData& operator+=(const DFSData &wp) noexcept {
			black_weight += wp.black_weight;
			white_weight += wp.white_weight;
			return *this;
		}
	};

	/**
	 * @brief 利用model_进行dfs，匹配指定EFG中的链条
	 * @param efg 用于匹配的目标EFG
	 * @param current_trie_node 当前节点的Trie树父节点
	 * @param current_efg_node 当前节点在EFG中的位置
	 * @param current_skip_count 当前链条匹配跳过次数
	 * @details 若当前节点有匹配链条的话，current_trie_node的所有子节点中有且仅有一个子节点和current_efg_node的API相同
	 * @return 当前DFS所匹配到的总权重
	 */
	DFSData dfs_risk_score(const EFG &efg, bool enable_record_evidence, SIZE_T current_trie_node, SIZE_T current_efg_node, SIZE_T current_skip_count, std::unordered_map<GREAT_SIZE_T, DFSData> &memory);
};

} // namespace starlight_v3::tspm

#endif
