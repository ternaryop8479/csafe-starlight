/**
 * @file tspm/reasoner.cpp
 * @brief tosSPM模型推理接口实现
 * @author ternaryop8479
 * @date 2026-07-29
 */

#include "tspm/reasoner.h"
#include "basic/types.h"

// 内部工具函数
namespace {

/**
 * @brief 通过dfs_risk_score的参数生成其对应的GREAT_SIZE_T键
 */
inline starlight_v3::GREAT_SIZE_T make_64_key(starlight_v3::SIZE_T trie, starlight_v3::SIZE_T efg, starlight_v3::SIZE_T skip) {
    return ((uint64_t)skip << 60) | ((uint64_t)efg << 20) | (uint64_t)trie;
}

}

namespace starlight_v3::tspm {

// 构造函数
Reasoner::Reasoner(const Model &model) : model_(model) {
}

// 推理函数封装
double Reasoner::calculate_risk_score(const EFG &efg) {
	WeightPair total_weight; // EFG总权重

	// 清除memory_记忆化数组
	memory_.clear();

	// 分别将每个节点作为根节点执行匹配任务
	for (SIZE_T i = 0; i < efg.nodes_.size(); ++i) {
		// 匹配链条并叠加至总权重
		total_weight += dfs_risk_score(efg, 0, i, 0);
	}

	// 检查黑白权重是否为0
	bool black_zero = near_zero(total_weight.black_weight);
	bool white_zero = near_zero(total_weight.white_weight);

	if (black_zero && white_zero) { // 黑白权重均为0
		return 0.0;
	}
	if (black_zero) { // 仅黑权重为0
		return -1.0;
	}
	if (white_zero) { // 仅白权重为0
		return 1.0;
	}

	// 因为白权重为负，黑权重为正，所以原本(|Wm| - |Wb|) / (|Wm| + |Wb|)的式子需要改成(Wm + Wb) / (Wm - Wb)
	return (total_weight.black_weight + total_weight.white_weight) / (total_weight.black_weight - total_weight.white_weight);
}

// to迷惑行为之写复杂函数之前碎碎念(qwq)
// 1. 定义WeightPair matched_weight, dfs_weight，分别用于存储当前dfs匹配到的权重和对当前节点子节点进行dfs时匹配到的总权重
// 2. 定义SIZE_T matched_trie_node，用于标记current_trie_node的子节点中与current_efg_node匹配的节点(如果没有匹配的节点就是INVALID_NUM)
// 3. 遍历current_trie_node所有子节点
//     对于每个子节点：
//     3.1. 检查current_trie_subnode和current_efg_node的API字符串是否相同，
//          若相同，则将current_trie_subnode的权重写入matched_weight(如果匹配的话)，然后设置matched_trie_node为current_trie_subnode并break
// 4. 若matched_trie_node == INVALID_NUM且current_skip_count>=max_skip，则直接返回空WeightPair(即最开始初始化的WeightPair)
// 5. 遍历current_efg_node的所有子节点
//     对于每个子节点：
//     5.1. 分别将efg, matched_trie_node/current_trie_node(取决于是否匹配到matched_trie_node，匹配到了就是第一个，反之是第二个)，
//          current_efg_subnode, current_skip_count(如果matched_trie_node为INVALID_NUM则该参数为current_skip_count+1，否则为0)作为参数执行DFS
//     5.2. 将当前DFS的返回值叠加到dfs_weight上
// 6. 如果dfs_weight中black_weight或white_weight不等于0，则返回dfs_weight，否则返回matched_weight
Reasoner::WeightPair Reasoner::dfs_risk_score(const EFG &efg, SIZE_T current_trie_node, SIZE_T current_efg_node, SIZE_T current_skip_count) {
	// 生成当前参数下的记忆化哈希表键
	GREAT_SIZE_T key = make_64_key(current_trie_node, current_efg_node, current_skip_count);

	// 查询记忆化缓存
	auto it = memory_.find(key);
	if(it != memory_.end()) {
		return it->second;
	}

	WeightPair matched_weight, dfs_weight; // 分别用于存储匹配到的权重值以及所有dfs权重之和
	SIZE_T matched_trie_node = INVALID_NUM; // 用于标记current_trie_node的子节点中与current_efg_node匹配的节点

	// 遍历current_trie_node所有子节点
	for (int i = model_.nodes[current_trie_node].trans_start; i - model_.nodes[current_trie_node].trans_start < model_.nodes[current_trie_node].trans_count; ++i) {
		const TrieNode &current_trie_subnode = model_.nodes[model_.edges[i]]; // Alias for 当前子节点

		// 检查current_trie_subnode和current_efg_node的API是否相同
		if (model_.api_table.query_api(current_trie_subnode.api_id).second == efg.api_table_.query_api(efg.nodes_[current_efg_node]).second) {
			// 判断当前节点是否有权重，要有权重才能写入进matched_weight
			if (!near_zero(current_trie_subnode.weight)) {
				// 将权重写入matched_weight
				matched_weight.black_weight = (current_trie_subnode.weight > 0.0) ? current_trie_subnode.weight : 0.0;
				matched_weight.white_weight = (current_trie_subnode.weight < 0.0) ? current_trie_subnode.weight : 0.0;
			}
			// 设置matched_trie_node
			matched_trie_node = model_.edges[i];

			// 因为Trie树单个节点的子节点不会重复，因此直接break
			break;
		}
	}

	// 判断是否有匹配节点或未超过max_skip
	if (matched_trie_node == INVALID_NUM && current_skip_count > model_.max_skip) {
		return matched_weight; // 因为如果没有挖掘到节点的话matched_weight就没有经过修改，因此直接返回空的matched_weight即可
	}

	// 要用来传入dfs参数的current_trie_node，不匹配就用current_trie_node，反之用匹配到的trie_node
	SIZE_T dfs_trie_node = (matched_trie_node == INVALID_NUM) ? current_trie_node : matched_trie_node;

	// 要用来传入dfs参数的current_skip_count，不匹配的话就是current_skip_count+1，匹配了的话需要重置跳跃次数，就是0
	SIZE_T dfs_skip_count = (matched_trie_node == INVALID_NUM) ? current_skip_count + 1 : 0;

	// 遍历current_efg_node的所有子节点
	for (SIZE_T i = efg.offeset_[current_efg_node]; i < efg.offeset_[current_efg_node + 1]; ++i) {
		// 直接把结果加到dfs_weight上，因为如果没挖掘到数据的话，dfs_risk_score返回的WeightPair为空
		dfs_weight += dfs_risk_score(efg, dfs_trie_node, efg.edges_[i].to_node_index, dfs_skip_count);
	}

	// 生成最后返回的WeightPair对象
	WeightPair result;
	result.black_weight = !near_zero(dfs_weight.black_weight) ? dfs_weight.black_weight : matched_weight.black_weight;
	result.white_weight = !near_zero(dfs_weight.white_weight) ? dfs_weight.white_weight : matched_weight.white_weight;

	// 将当前结果加入记忆化缓存
	memory_.emplace(key, result);

	return result;
}

}
