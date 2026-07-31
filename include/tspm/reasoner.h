/**
 * @file tspm/reasoner.h
 * @brief tosSPM模型推理引擎接口声明
 * @author ternaryop8479
 * @date 2026-07-29
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_TSPM_REASONER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_TSPM_REASONER_H

#include "basic/efg.h"
#include "basic/types.h"
#include "tspm/model.h"

namespace starlight_v3::tspm {

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
	 * @brief 通过程序的EFG(外部调用流程图)计算一个已知程序的风险度
	 * @param efg 从已知程序中提取的外部调用流程图(详细接口见efg_generator.h)
	 * @return 目标程序风险度，返回值值域[0.0, 1.0]
	 */
	double calculate_risk_score(const EFG &efg);

private:
	const Model &model_; ///< 用于推理的模型

	/**
	 * @brief 用于在推理过程中表示当前匹配链条的总黑白权重
	 */
	struct WeightPair {
		double black_weight = 0.0; ///< 黑权重
		double white_weight = 0.0; ///< 白权重

#pragma omp declare simd // 该SIMD优化应用于加法运算符重载函数
		/**
		 * @brief 权重加法运算符重载
		 * @details 该加法运算逻辑与二维向量的加法逻辑相同
		 * @return 返回wp与当前对象相加后得到的权重
		 */
		WeightPair operator+(const WeightPair &wp) const noexcept {
			return { .black_weight = black_weight + wp.black_weight,
				.white_weight = white_weight + wp.white_weight };
		}

#pragma omp declare simd // 该SIMD优化应用于+=运算符重载函数
		/**
		 * @brief 权重+=运算符重载
		 * @return 返回经过加法后的当前对象
		 */
		WeightPair& operator+=(const WeightPair &wp) noexcept {
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
	WeightPair dfs_risk_score(const EFG &efg, SIZE_T current_trie_node, SIZE_T current_efg_node, SIZE_T current_skip_count);

	std::unordered_map<GREAT_SIZE_T, WeightPair> memory_; ///< 记忆化缓存，用于记忆化搜索(dfs)
};

} // namespace starlight_v3::tspm

#endif
