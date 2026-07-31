/**
 * @file tspm/model.h
 * @brief tosSPM模型数据结构声明
 * @author ternaryop8479
 * @date 2026-07-26
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_TSPM_MODEL_H
#define CSAFE_STARLIGHT_V3_INCLUDE_TSPM_MODEL_H

#include <string>
#include <unordered_map>
#include <vector>

#include "basic/api_table.h"
#include "basic/types.h"

namespace starlight_v3::tspm {

/**
 * @brief Trie树节点结构体
 */
struct TrieNode {
	APIID_T api_id; ///< 当前节点所代表的API ID
	SIZE_T trans_start, trans_count; ///< 边数组中当前节点的所有子节点的索引区间
	double weight; ///< 当前节点权重
};

/**
 * @brief TSPM模型数据结构体
 */
struct Model {
	APITable api_table; ///< 模型API表

	// Trie树存储
	std::vector<TrieNode> nodes; ///< Trie树节点列表
	std::vector<SIZE_T> edges; ///< Trie树边列表(存储一个节点的所有子节点在Trie树nodes数组中的索引)

	// 模型参数
	double max_skip; ///< 推理中最多可以跳过的API数
};

} // namespace starlight_v3::tspm

#endif
