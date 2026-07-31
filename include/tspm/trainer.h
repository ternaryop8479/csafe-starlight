/**
 * @file tspm/trainer.h
 * @brief tosSPM训练器接口声明
 * @author ternaryop8479
 * @date 2026-07-26
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_TSPM_TRAINER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_TSPM_TRAINER_H

#include "basic/api_table.h"
#include "basic/efg.h"
#include "basic/types.h"
#include "tspm/model.h"
#include <functional>
#include <unordered_set>

namespace starlight_v3::tspm {

/**
 * @brief API链数据结构，即一个普通数组(因为需要支持随机访问所以不能使用queue)
 */
using APIChain = std::vector<APIID_T>;

/**
 * @brief 调用链数据结构封装
 */
struct CallChain {
	APIChain api_chain; ///< API链数据
	double weight; ///< 该条调用链的风险权重(取值[-1.0, 1.0])
};

/**
 * @brief 用于存储一个节点在EFG表中的位置(索引)
 */
struct EFGListNode {
	SIZE_T graph_index; ///< 节点所属EFG在EFG表中的索引
	SIZE_T api_index; ///< 节点在所属EFG中的索引
};

/**
 * @brief 用于存储一个API在调用链库中的位置(索引)
 */
struct CallChainAPI {
	SIZE_T call_chain_index; ///< API所属调用链在调用链库中的索引
	SIZE_T api_index; ///< API在其所属调用链中的索引
};

/**
 * @brief 训练配置结构体
 */
struct TrainingConfig {
	bool fast_mode; ///< 快速训练模式(在max_skip>0的时候会出现一定数据损失，可以大幅提升训练速度)
	SIZE_T max_skip; ///< 挖掘时为了跨过混淆API允许的最大忽略次数，过大可能导致模型文件过大或OOM，过小可能导致模型掺杂被混淆过的病毒样本数据
	SIZE_T max_length; ///< 一条有效链的最大长度
	SIZE_T max_depth; ///< DFS递归树最大深度
	double min_support; ///< 最小支持度，取值[0.0, 1.0]
	double max_root_support; ///< 根节点最大支持度，可用于提前剪枝出现频次较高的根节点
	double max_expan_ratio; ///< 最大膨胀率，可用于剪枝分裂出的组合数较多(远高于其本身支持度)的API
	double min_distinction; ///< 剪枝时的黑白样本最小区分度，取值[0.0, 1.0]，越大剪枝越激进
	double preprune_factor; ///< 提前剪枝因数，用于限制BFS过程中由于max_skip过大导致的组合爆炸(越小剪枝越严格，模型精度越低，建议不小于1.0)
	std::unordered_set<std::string> banned_apis; ///< 用于标记被禁止的噪声API，即不允许出现在数据库中的API黑名单

	/**
	 * @brief 最大支持度，取值[0.0, 1.0]
	 * @warn 该参数已弃用，极其不建议在非必要(数据集质量过低)的情况下修改该参数
	 */
	double max_support = 1.0;
};

// 用于存储投影表和投影(单个投影实质上是一个图节点)的类型别名，只有代码实现需要用到
using Projection = EFGListNode;
using ProjectionList = std::vector<Projection>;

class Trainer {

public:
	Trainer() = delete;
	~Trainer() = default;

	/**
	 * @brief 唯一构造函数
	 * @param log_callback 用于输出日志信息的回调接口
	 */
	Trainer(const TrainingConfig &config, std::function<void(const std::string &)> log_callback);

	/**
	 * @brief 训练接口
	 * @param malware_dataset 将要用于训练的病毒数据集，即不同病毒的EFG图集
	 * @param benign_dataset 将要用于训练的白样本数据集，即不同白样本的EFG图集
	 * @warning 由于引入了原地修改机制以加速训练，训练后的两个dataset的api_table将均无法使用
	 * @return 训练完成的模型
	 */
	Model train(std::vector<EFG> &malware_dataset, std::vector<EFG> &benign_dataset);

private:
	// 训练配置
	TrainingConfig config_;
	std::function<void(const std::string &)> log_callback_;

	/**
	 * @brief 内部封装的用于搜索频繁条目的接口
	 * @param current_proj_list 当前处理的API链的投影表
	 */
	void dfs_call_chains(const ProjectionList &current_proj_list, SIZE_T current_depth = 0);

	// 训练时用到的临时变量(用于作为dfs间参数使用)
	SIZE_T max_count_; ///< 允许一条链在数据集中出现的最高次数，设置为0则无上限
	SIZE_T min_count_; ///< 允许一条链在数据集中出现的最小次数
	std::unordered_set<APIID_T> banned_apis_; ///< 被ban掉的API
	const std::vector<EFG> *dataset_ = nullptr; ///< 当前使用的数据集
	std::unordered_set<GREAT_SIZE_T> edge_set_; ///< 防环路用去重边集
	std::vector<CallChain> current_call_chain_list_; ///< 当前调用链数据库
	APIChain current_prefix_; ///< 当前前缀，用于拼接调用链
	std::vector<std::vector<SIZE_T>> visited_map_; // 全局visited数组
	GREAT_SIZE_T timeset_ = 1; // 时间戳，用来给visited做标记(用uint64_t防止大数据集下时间戳溢出)
	std::vector<CallChain> call_chain_list_; ///< 最终输出与Trie树之间的CallChain缓存

	/**
	 * @brief DFS构建Trie树时调用链的API节点封装
	 */
	struct ChainListAPI {
		double weight; ///< 以当前结尾的链条权重(如果当前节点不是任何一条链的结束节点则权重为0)
		int64_t depth; ///< 当前节点所处的深度(即api_index)
		SIZE_T node_begin; ///< 当前节点的起始链条索引
		SIZE_T node_end; ///< 当前节点的结束链条索引
		SIZE_T node_index; ///< 当前API节点在model.nodes_(即CSR Trie树的nodes数组)中的索引
	};

	/**
	 * @brief 内部封装的用于根据调用链生成Trie树模型的接口(由于参数较少，因此参数不通过成员变量传递)
	 * @param model 输出模型
	 * @param node_in_chain_list 当前处理的节点在API调用链集合中的覆盖范围(位置)
	 * @param node_index_in_trie 当前处理的节点在生成的CSR Trie树中的节点索引
	 */
	void dfs_trie_tree(Model &model, const ChainListAPI &node_in_chain_list);
};

} // namespace starlight_v3::tspm

#endif
