/**
 * @file tspm/reasoner.cpp
 * @brief tosSPM模型推理接口实现
 * @author ternaryop8479
 * @date 2026-07-29
 */

#include "tspm/reasoner.h"
#include "basic/types.h"
#include <memory>

// 内部工具函数
namespace {

/**
 * @brief 通过dfs_risk_score的参数生成其对应的GREAT_SIZE_T键
 */
inline starlight_v3::GREAT_SIZE_T make_64_key(starlight_v3::SIZE_T trie, starlight_v3::SIZE_T efg, starlight_v3::SIZE_T skip) {
	return ((uint64_t)skip << 60) | ((uint64_t)efg << 20) | (uint64_t)trie;
}

} // namespace

namespace starlight_v3::tspm {

// 构造函数
Reasoner::Reasoner(const Model &model) : model_(model) {
}

// 推理函数封装
AnalysisResult Reasoner::analyze_efg(const EFG &efg, bool enable_record_evidence) {
	AnalysisResult result; // 最终推理输出
	DFSData total_weight; // EFG总权重

	// 记忆化哈希表
	std::unordered_map<GREAT_SIZE_T, DFSData> memory;

	// 分别将每个节点作为根节点执行匹配任务
	for (SIZE_T i = 0; i < efg.nodes_.size(); ++i) {
		// 匹配链条并叠加至总权重
		DFSData current_dfs_data = dfs_risk_score(efg, enable_record_evidence, 0, i, 0, memory);

		// 判断证据树是否为空并加入推理结果
		if (current_dfs_data.current_tree != nullptr) {
			result.evidence_trees.push_back(current_dfs_data.current_tree);
		}

		// 正常叠加权重
		total_weight += current_dfs_data;
	}

	// 记录病毒及良性维度评分
	result.malware_score = total_weight.black_weight;
	result.benign_score = total_weight.white_weight;

	// 检查黑白权重是否为0
	bool black_zero = near_zero(total_weight.black_weight);
	bool white_zero = near_zero(total_weight.white_weight);

	if (black_zero && white_zero) { // 黑白权重均为0
		return result;
	} else if (black_zero) { // 仅黑权重为0
		result.final_score = -1.0;
		return result;
	} else if (white_zero) { // 仅白权重为0
		result.final_score = 1.0;
		return result;
	}

	// 因为白权重为负，黑权重为正，所以原本(|Wm| - |Wb|) / (|Wm| + |Wb|)的式子需要改成(Wm + Wb) / (Wm - Wb)
	result.final_score = (total_weight.black_weight + total_weight.white_weight) / (total_weight.black_weight - total_weight.white_weight);

	return result;
}

// to迷惑行为之写复杂函数之前碎碎念(qwq)
// 1. 定义DFSData matched_weight, dfs_weight，分别用于存储当前dfs匹配到的权重和对当前节点子节点进行dfs时匹配到的总权重
// 2. 定义SIZE_T matched_trie_node，用于标记current_trie_node的子节点中与current_efg_node匹配的节点(如果没有匹配的节点就是INVALID_NUM)
// 3. 遍历current_trie_node所有子节点
//     对于每个子节点：
//     3.1. 检查current_trie_subnode和current_efg_node的API字符串是否相同，
//          若相同，则将current_trie_subnode的权重写入matched_weight(如果匹配的话)，然后设置matched_trie_node为current_trie_subnode并break
// 4. 若matched_trie_node == INVALID_NUM且current_skip_count>=max_skip，则直接返回空DFSData(即最开始初始化的DFSData)
// 5. 遍历current_efg_node的所有子节点
//     对于每个子节点：
//     5.1. 分别将efg, matched_trie_node/current_trie_node(取决于是否匹配到matched_trie_node，匹配到了就是第一个，反之是第二个)，
//          current_efg_subnode, current_skip_count(如果matched_trie_node为INVALID_NUM则该参数为current_skip_count+1，否则为0)作为参数执行DFS
//     5.2. 将当前DFS的返回值叠加到dfs_weight上
// 6. 如果dfs_weight中black_weight或white_weight不等于0，则返回dfs_weight，否则返回matched_weight
Reasoner::DFSData Reasoner::dfs_risk_score(const EFG &efg, bool enable_record_evidence, SIZE_T current_trie_node, SIZE_T current_efg_node, SIZE_T current_skip_count, std::unordered_map<GREAT_SIZE_T, DFSData> &memory) {
	// 生成当前参数下的记忆化哈希表键
	GREAT_SIZE_T key = make_64_key(current_trie_node, current_efg_node, current_skip_count);

	// 查询记忆化缓存
	auto it = memory.find(key);
	if (it != memory.end()) {
		return it->second;
	}

	// 初始化当前树节点
	std::shared_ptr<EvidenceTree> current_evtree_node = nullptr;

	DFSData matched_weight, dfs_weight; // 分别用于存储匹配到的权重值以及所有dfs权重之和
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

	// 标记当前节点是否在Trie树中找到了匹配节点
	bool matched = matched_trie_node != INVALID_NUM;

	if (!matched && current_skip_count > model_.max_skip) { // 没有匹配节点且当前跳过次数超过max_skip
		return matched_weight; // 因为如果没有挖掘到节点的话matched_weight就没有经过修改，因此直接返回空的matched_weight即可
	} else if (enable_record_evidence && matched) { // 匹配到了Trie树节点并且允许记录dfs树
		current_evtree_node = std::make_shared<EvidenceTree>();
		current_evtree_node->api_name = efg.api_table_.query_api(efg.nodes_[current_efg_node]).second; // 记录API名
		current_evtree_node->weight = model_.nodes[matched_trie_node].weight; // 记录该Trie树节点的权重
	}

	// 要用来传入dfs参数的current_trie_node，不匹配就用current_trie_node，反之用匹配到的trie_node
	SIZE_T dfs_trie_node = (!matched) ? current_trie_node : matched_trie_node;

	// 要用来传入dfs参数的current_skip_count，不匹配的话就是current_skip_count+1，匹配了的话需要重置跳跃次数，就是0
	SIZE_T dfs_skip_count = (!matched) ? current_skip_count + 1 : 0;

	// 遍历current_efg_node的所有子节点
	for (SIZE_T i = efg.offeset_[current_efg_node]; i < efg.offeset_[current_efg_node + 1]; ++i) {
		// 直接把结果加到dfs_weight上，因为如果没挖掘到数据的话，dfs_risk_score返回的DFSData为空
		DFSData current_dfs_data = dfs_risk_score(efg, enable_record_evidence, dfs_trie_node, efg.edges_[i].to_node_index, dfs_skip_count, memory);

		// 检查当前dfs是否挖掘到结果(只要当前dfs出来的节点不是nullptr就一定挖到了节点)且允许记录dfs树
		if (enable_record_evidence && current_dfs_data.current_tree != nullptr) {
			// 首先确保分配了内存
			if (current_evtree_node == nullptr) {
				current_evtree_node = std::make_shared<EvidenceTree>();
			}

			// 将该dfs返回的节点接入为当前节点的子节点
			current_evtree_node->sub_nodes.push_back(current_dfs_data.current_tree);
		}

		// 最后不要忘了叠加权重
		dfs_weight += current_dfs_data;
	}

	// 生成最后返回的DFSData对象
	DFSData result;
	result.black_weight = !near_zero(dfs_weight.black_weight) ? dfs_weight.black_weight : matched_weight.black_weight;
	result.white_weight = !near_zero(dfs_weight.white_weight) ? dfs_weight.white_weight : matched_weight.white_weight;

	// 当前节点和子节点有任意一者存在匹配节点就将当前节点视为有效节点加入记录(前提是开启了dfs树记录)
	if (enable_record_evidence && (matched || (current_evtree_node != nullptr && !current_evtree_node->sub_nodes.empty()))) {
		result.current_tree = current_evtree_node;
	}

	// 将当前结果加入记忆化缓存
	memory.emplace(key, result);

	return result;
}

} // namespace starlight_v3
