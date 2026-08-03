/**
 * @file tspm/trainer.cpp
 * @brief tosSPM模型训练引擎实现
 * @author ternaryop8479
 * @date 2026-07-29
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "external/BS_thread_pool.hpp"
#include "external/xxhash/xxhash.h"

#include "basic/api_table.h"
#include "basic/types.h"
#include "tspm/trainer.h"

namespace starlight_v3::tspm {

// 构造函数
Trainer::Trainer(const TrainingConfig &config, std::function<void(const std::string &)> log_callback) : config_(config), log_callback_(log_callback) {
}

// 训练接口
Model Trainer::train(std::vector<EFG> &malware_dataset, std::vector<EFG> &benign_dataset) {
	// 先清空call_chain_list_确保上一轮训练的数据被正确清除
	call_chain_list_.clear();

	// 总耗时计时
	auto total_begin = std::chrono::steady_clock::now();

	// 用来计算APIChain的哈希
	struct APIChainHasher {
		SIZE_T operator()(const APIChain &chain) const {
			return XXH3_64bits(chain.data(), chain.size() * sizeof(APIID_T));
		}
	};

	Model model; // 输出

	log_by_callback("[Trainer::train()] Initializing dataset.\n");

	// 计时
	auto begin = std::chrono::steady_clock::now();

	// 先合并两个数据集的api_table，生成一个大table(这里注意还要修改两个数据集里nodes的api_id)，同时生成两个数据集的1-gram投影表
	std::vector<std::pair<APIID_T, ProjectionList>> malware_proj_list, benign_proj_list; // 本地病毒/白文件投影表
	std::vector<SIZE_T> malware_api_weight, benign_api_weight; // 病毒/良性样本的权重
	for (SIZE_T i = 0; i < malware_dataset.size(); ++i) { // 先遍历病毒数据集
		EFG &efg = malware_dataset[i]; // Alias for malware_dataset[i]
		std::vector<bool> visited; // 用于标记当前api是否访问
		for (SIZE_T j = 0; j < efg.nodes_.size(); ++j) { // 遍历EFG中所有节点
			APIID_T &node = efg.nodes_[j];
			// 查询API字符串并将字符串插入api_table_
			const auto &[found, api_str] = efg.api_table_.query_api(node);
			if (!found) {
				continue;
			}
			model.api_table.insert(api_str);

			// 插入病毒投影表
			Projection proj;
			proj.graph_index = i;
			proj.api_index = j;
			APIID_T api_id = model.api_table.query_id(api_str).second;
			if (malware_proj_list.size() <= api_id) { // 检查当前投影集大小
				malware_proj_list.resize(api_id + 1);
			}
			malware_proj_list[api_id].first = api_id; // 在投影生成阶段，malware_proj_list的索引对应为API_ID，直到排序阶段无实际意义
			malware_proj_list[api_id].second.emplace_back(proj);
			if (visited.size() <= api_id) { // 检查当前visited大小
				visited.resize(api_id + 1, false);
			}
			if (!visited[api_id]) { // 如果未记录过当前API则进行记录
				visited[api_id] = true; // 访问标记
				if (malware_api_weight.size() <= api_id) { // 扩容malware_api_weight
					malware_api_weight.resize(api_id + 1, 0);
				}
				++malware_api_weight[api_id];
			}

			// 修改数据集节点的api_id
			node = api_id;
		}
	}
	for (SIZE_T i = 0; i < benign_dataset.size(); ++i) { // 遍历白数据集
		EFG &efg = benign_dataset[i]; // Alias for malware_dataset[i]
		std::vector<bool> visited; // 用于标记当前api是否访问
		for (SIZE_T j = 0; j < efg.nodes_.size(); ++j) { // 遍历EFG中所有节点
			APIID_T &node = efg.nodes_[j];
			// 查询API字符串并将字符串插入api_table_
			const auto &[found, api_str] = efg.api_table_.query_api(node);
			if (!found) {
				continue;
			}
			model.api_table.insert(api_str);

			// 插入白文件投影表
			Projection proj;
			proj.graph_index = i;
			proj.api_index = j;
			APIID_T api_id = model.api_table.query_id(api_str).second;
			if (benign_proj_list.size() <= api_id) { // 检查当前投影集大小
				benign_proj_list.resize(api_id + 1);
			}
			benign_proj_list[api_id].first = api_id; // 在投影生成阶段，benign_proj_list的索引对应为API_ID，直到排序阶段无实际意义
			benign_proj_list[api_id].second.emplace_back(proj);
			if (visited.size() <= api_id) { // 检查当前visited大小
				visited.resize(api_id + 1, false);
			}
			if (!visited[api_id]) { // 如果未记录过当前API则进行记录
				visited[api_id] = true; // 访问标记
				if (benign_api_weight.size() <= api_id) { // 扩容benign_api_weight
					benign_api_weight.resize(api_id + 1, 0);
				}
				++benign_api_weight[api_id];
			}

			// 修改数据集节点的api_id
			node = api_id;
		}
	}

	// 根据用户输入配置里用字符串存储的banned_apis生成banned_apis_成员变量(存储API ID)
	for (const std::string &api : config_.banned_apis) {
		banned_apis_.insert(model.api_table.query_id(api).second);
	}

	// 忽略掉不存在于解析列表中的API
	if (banned_apis_.count(INVALID_NUM)) {
		banned_apis_.erase(INVALID_NUM);
	}

	// 计时
	auto end = std::chrono::steady_clock::now();

	// 数据转移与预处理
	log_by_callback("[Trainer::train()] Done. Time: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()) + "ms. Begin to train the malware dataset(totally " + std::to_string(malware_proj_list.size()) + " projections).\n");

	// 计时
	begin = std::chrono::steady_clock::now();

	// 线程池
	BS::thread_pool thread_pool(config_.thread_count ? config_.thread_count : std::thread::hardware_concurrency());

	// 全局timeset_(一个看起来没什么用但是可以很好地反馈训练情况的数据)
	std::atomic<GREAT_SIZE_T> global_timeset_;

	// 投影表LPT派发排序函数，通过先算消耗时间长的投影集提升训练速度
	auto lpt_sorter = [](const std::pair<APIID_T, ProjectionList> &pl1, const std::pair<APIID_T, ProjectionList> &pl2) {
		return pl1.second.size() > pl2.second.size(); // 按投影集大小倒序排序
	};

	// 先挖掘黑数据集调用链
	std::vector<CallChain> malware_api_chain_list; // 返回的病毒调用链
	dataset_ = &malware_dataset; // 设置数据集
	global_timeset_ = 0; // 重置时间戳
	min_count_ = static_cast<SIZE_T>(std::ceil(malware_dataset.size() * config_.min_support)); // 最小支持度
	if (min_count_ == 0) { // 最低次数为0的时候输出警告信息
		log_by_callback("[Trainer::train()] WARN: min_count=0\n");
	}
	max_count_ = static_cast<SIZE_T>(std::ceil(malware_dataset.size() * config_.max_support)); // 最大支持度

	// 排序投影集
	std::sort(malware_proj_list.begin(), malware_proj_list.end(), lpt_sorter);

	// DFS参数列表
	for (const auto &[api_id, proj_list] : malware_proj_list) {
		// 查询当前API是否被ban
		if (banned_apis_.count(api_id)) {
			continue;
		}

		// 检查根节点支持度
		if (malware_api_weight[api_id] > malware_dataset.size() * config_.max_root_support || malware_api_weight[api_id] < min_count_) {
			continue;
		}

		// 递归搜索
		thread_pool.detach_task([&]() {
			DFSData current_data; // 当前递归用的DFSData对象

			// 初始化current_data
			current_data.timeset_ = 1;
			current_data.visited_map_ = std::vector<std::vector<GREAT_SIZE_T>>(malware_dataset.size(), std::vector<GREAT_SIZE_T>());

			// 加入当前投影前缀
			current_data.current_prefix_.emplace_back(api_id);

			// 将1-gram API数据写入数据集
			if (malware_api_weight[api_id] <= max_count_) { // 因为max_root_support和max_support不是一个参数，所以这里需要单独特判
				CallChain root_node;
				root_node.api_chain = current_data.current_prefix_;
				root_node.weight = malware_api_weight[api_id];
				current_call_chain_list_mutex_.lock();
				current_call_chain_list_.push_back(root_node);
				current_call_chain_list_mutex_.unlock();
			}

			dfs_call_chains(proj_list, current_data); // 挖掘调用链
			log_by_callback("\r[Trainer::train()] Digged a malware projection(global_timeset_=" + std::to_string(global_timeset_ += current_data.timeset_) + "): " + model.api_table.query_api(api_id).second);

			current_data.current_prefix_.pop_back();
		});
	}

	// 等待任务结束
	thread_pool.wait();

	// 计时
	end = std::chrono::steady_clock::now();

	log_by_callback("\r[Trainer::train()] Malware dataset training done. Time: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()) + "ms. Call chain count: " + std::to_string(current_call_chain_list_.size()) + ", Begin to train the benign dataset(totally " + std::to_string(benign_proj_list.size()) + " projections).\n");
	malware_api_chain_list = std::move(current_call_chain_list_); // 移动当前调用链数据

	// 清除这一轮训练数据
	current_call_chain_list_.clear();

	// 计时
	begin = std::chrono::steady_clock::now();

	// 挖掘白数据集
	std::vector<CallChain> benign_api_chain_list; // 返回的白样本调用链
	dataset_ = &benign_dataset; // 设置数据集
	global_timeset_ = 0; // 重置时间戳
	min_count_ = static_cast<SIZE_T>(std::ceil(benign_dataset.size() * config_.min_support)); // 最小支持度
	if (min_count_ == 0) { // 最低次数为0的时候输出警告信息
		log_by_callback("[Trainer::train()] WARN: min_count=0\n");
	}
	max_count_ = static_cast<SIZE_T>(std::ceil(benign_dataset.size() * config_.max_support)); // 最大支持度

	// 排序投影集
	std::sort(benign_proj_list.begin(), benign_proj_list.end(), lpt_sorter);

	// DFS参数列表
	for (const auto &[api_id, proj_list] : benign_proj_list) {
		// 查询当前API是否被ban
		if (banned_apis_.count(api_id)) {
			continue;
		}
		// 检查根节点支持度
		if (benign_api_weight[api_id] > benign_dataset.size() * config_.max_root_support || benign_api_weight[api_id] < min_count_) {
			continue;
		}

		// 递归搜索
		thread_pool.detach_task([&]() {
			DFSData current_data; // 当前递归用的DFSData对象

			// 初始化current_data
			current_data.timeset_ = 1;
			current_data.visited_map_ = std::vector<std::vector<GREAT_SIZE_T>>(benign_dataset.size(), std::vector<GREAT_SIZE_T>());

			// 加入当前投影前缀
			current_data.current_prefix_.emplace_back(api_id);

			// 将1-gram API数据写入数据集
			if (benign_api_weight[api_id] <= max_count_) { // 因为max_root_support和max_support不是一个参数，所以这里需要单独特判
				CallChain root_node;
				root_node.api_chain = current_data.current_prefix_;
				root_node.weight = benign_api_weight[api_id];
				current_call_chain_list_mutex_.lock();
				current_call_chain_list_.push_back(root_node);
				current_call_chain_list_mutex_.unlock();
			}

			dfs_call_chains(proj_list, current_data); // 挖掘调用链
			log_by_callback("\r[Trainer::train()] Digged a benign projection(global_timeset_=" + std::to_string(global_timeset_ += current_data.timeset_) + "): " + model.api_table.query_api(api_id).second);

			current_data.current_prefix_.pop_back();
		});
	}

	// 等待任务结束
	thread_pool.wait();

	// 计时
	end = std::chrono::steady_clock::now();

	log_by_callback("\r[Trainer::train()] Benign dataset training done. Time: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()) + "ms. Call chain count: " + std::to_string(current_call_chain_list_.size()) + ". Merging call chains.\n");
	benign_api_chain_list = std::move(current_call_chain_list_); // 移动当前调用链数据

	// 清除这一轮训练数据
	current_call_chain_list_.clear();

	// 计时
	begin = std::chrono::steady_clock::now();

	// 合并黑白调用链集
	std::unordered_map<APIChain, double, APIChainHasher> call_chain_set; // 最后用于计算的调用链集
	for (const CallChain &call_chain : malware_api_chain_list) {
		// 黑样本这里可以先把数据插入到call_chain_set里，但是白样本不行，因为需要处理重复(算区分度)
		call_chain_set.emplace(call_chain.api_chain, call_chain.weight);
	}

	// 计时
	end = std::chrono::steady_clock::now();

	// 计算调用链权重
	log_by_callback("[Trainer::train()] Done. Time: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()) + "ms. Calculating the weights of the call chains.\n");

	// 计时
	begin = std::chrono::steady_clock::now();

	// 再遍历一遍白数据集，统计区分度
	for (const CallChain &call_chain : benign_api_chain_list) {
		const auto &it = call_chain_set.find(call_chain.api_chain);
		if (it == call_chain_set.end()) { // 没有找到这条链，说明这条白链唯一，直接insert成weight=-1
			call_chain_set.emplace(call_chain.api_chain, -1.0);
		} else {
			double &weight = it->second;
			// 计算黑白调用链频率
			double malware_percent = weight / malware_dataset.size();
			double benign_percent = call_chain.weight / benign_dataset.size();

			// 计算权重(区分度)并写入
			weight = (malware_percent - benign_percent) / (malware_percent + benign_percent);
		}
	}

	// 最后遍历一边call_chain_set，clamp规范一下区分度(只需要规范到1.0即可，因为所有白样本有黑样本没有的调用链都在刚才被设置成-1.0了)
	// 同时把current_call_chain_list_数据写入到model
	for (auto &[api_chain, weight] : call_chain_set) {
		// 绝对值小于最小区分度就剪掉
		if (std::fabs(weight) < config_.min_distinction) {
			continue;
		}
		weight = std::clamp(weight, -1.0, 1.0);
		CallChain call_chain;
		call_chain.weight = weight;
		call_chain.api_chain = api_chain;
		call_chain_list_.push_back(call_chain);
	}

	// 好孩子记得释放不用的内存
	current_call_chain_list_.clear();

	// 计时
	end = std::chrono::steady_clock::now();

	log_by_callback("[Trainer::train()] Done. Time: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()) + "ms. Sorting call chains.\n");

	// 计时
	begin = std::chrono::steady_clock::now();

	// 排序调用链
	std::sort(call_chain_list_.begin(), call_chain_list_.end(), [](const CallChain &chain1, const CallChain &chain2) -> bool {
		for (SIZE_T i = 0; i < std::min(chain1.api_chain.size(), chain2.api_chain.size()); ++i) {
			if (chain1.api_chain[i] != chain2.api_chain[i]) {
				return chain1.api_chain[i] < chain2.api_chain[i];
			}
		}
		return chain1.api_chain.size() < chain2.api_chain.size();
	});

	// 计时
	end = std::chrono::steady_clock::now();

	// 构建Trie树
	log_by_callback("[Trainer::train()] Done. Time: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()) + "ms. Generating trie tree to model.\n");

	// 计时
	begin = std::chrono::steady_clock::now();

	// 处理虚拟根节点
	model.nodes.push_back({ .api_id = INVALID_NUM,
		.trans_start = 0,
		.trans_count = 0,
		.weight = 0.0 });

	// 直接dfs！
	dfs_trie_tree(model,
		{ .weight = 0.0,
			.depth = -1, // 设置成-1就不需要做各种头疼的depth->index转换了
			.node_begin = 0,
			.node_end = static_cast<SIZE_T>(call_chain_list_.size() - 1), // 注意！这里call_chain_list_大小为0的时候会崩溃，此处的崩溃设计不是bug，而是代码设计，用于提醒用户数据集出现问题
			.node_index = 0 });

	// 计时
	end = std::chrono::steady_clock::now();

	// 其他参数写入
	log_by_callback("[Trainer::train()] Done. Time: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()) + "ms. Writing model parameters.\n");
	model.max_skip = config_.max_skip;

	// 总耗时计时
	auto total_end = std::chrono::steady_clock::now();

	log_by_callback("[Trainer::train()] All done. Total time: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(total_end - total_begin).count()) + "ms.\n");

	return model;
}

// 这里是toの碎碎念喵
// 大概步骤：
// 1. 初始化一个本地投影集
// 2. bfs当前投影集里的所有节点
//     对于bfs到的所有节点:
//     2.1. visited数组查重+depth检查深度(要限制最大搜索深度)
//     2.2. 计算传入的节点和当前节点之间的边的hashcode
//     2.3. 用edge_set_查重这个hashcode，重复则continue(查环)
//     2.4. 将当前节点收录进本地投影集里
//     2.5. 将当前节点所属图收录进本地EFG集里
//     2.6. 遍历当前节点的子节点并将子节点push进bfs队列
// 3. 遍历bfs过程中生成的投影集
//     对于投影集里的所有节点:
//     3.1 计算该节点的支持度，小于最小支持度则直接continue
//     3.2 将当前api_id push_back到current_prefix_
//     3.3 将current_prefix_插入到current_call_chain_list_数据库
//     3.4 将当前节点和传入的节点的边的hashcode插入edge_set_中
//     3.5 创建一个new_proj并将其设置为当前遍历到的API的投影
//     3.6 下一步dfs()
//     3.7 从edge_set_删掉当前边，然后从current_prefix_ pop当前API
// 4. 没有了喵
void Trainer::dfs_call_chains(const ProjectionList &current_proj_list, DFSData &current_data, SIZE_T current_depth) {
	const std::vector<EFG> &dataset = *dataset_; // 加个别名，方便后面用

	std::unordered_map<APIID_T, ProjectionList> local_proj_list; // 本地投影集
	std::unordered_map<APIID_T, std::unordered_set<SIZE_T>> local_efg_map; // 本地EFG集，用来标记候选的API在哪些图中出现过(也就是unordered_set存储的是图id)
	SIZE_T valid_branches = 0; // 用于记录合法分支

	// 遍历投影里的所有节点
	for (const Projection &proj : current_proj_list) {
		// 取个别名方便用
		const EFG &current_efg = dataset[proj.graph_index];

		// BFS
		std::vector<GREAT_SIZE_T> &visited = current_data.visited_map_[proj.graph_index];
		if (visited.size() < current_efg.nodes_.size()) { // 按需扩容或初始化当前visited数组
			visited.resize(current_efg.nodes_.size(), 0);
		}
		const GREAT_SIZE_T &timeset_ = ++current_data.timeset_; // Alias for timeset_ in current_data

		std::queue<std::pair<EFGListNode, SIZE_T>> queue; // 这里不用Projection作为类型名的原因是这里本质上还是对图进行bfs，但是只有通过了不成环筛选的节点才能被当作投影push(这里的Projection和EFGListNode是一个类型)，pair的第二个参数代表深度
		queue.push(std::make_pair(proj, 0));
		visited[proj.api_index] = timeset_; // 标记根节点
		while (!queue.empty()) {
			auto [node, depth] = queue.front();
			queue.pop();

			// 检查搜索深度
			if (depth > config_.max_skip + 1) {
				continue;
			}

			// 当前节点的API_ID
			APIID_T current_api_id = current_efg.nodes_[node.api_index];

			// 当前API的EFG图集(由于代码中使用比较频繁故alias)
			std::unordered_set<SIZE_T> &current_api_efg_set = local_efg_map[current_api_id];

			// 只收录非根节点(不然会死循环)和出现次数小于max_count_的API
			if (depth > 0 && current_api_efg_set.size() <= max_count_) {
				// 计算hashcode(这里的SIZE_T=uint32_t, GREAT_SIZE_T=uint64_t)
				GREAT_SIZE_T hashcode = ((static_cast<GREAT_SIZE_T>(current_data.current_prefix_.back())) << 32ull) | static_cast<GREAT_SIZE_T>(current_api_id);
				if (current_data.edge_set_.count(hashcode)) { // 检查是否全局成环
					continue;
				}

				// 只有当前API不在banned_apis_列表里的时候加入到投影集，这样可以确保生成的链不含被ban的api
				if (!banned_apis_.count(current_api_id)) {
					// 把当前节点insert进local_proj_list中
					ProjectionList &proj_list = local_proj_list.try_emplace(current_api_id).first->second;
					if (proj_list.empty()) { // 说明这个API是新插入的
						proj_list.reserve(current_efg.nodes_.size() / 2); // 一般一张EFG的节点数很少，最坏情况下所有节点push进来也只需要重分配一次，省空间且无需多次重分配
					}
					proj_list.push_back(node); // push_back当前节点

					// 把当前节点所属图insert进local_efg_map中(std::unordered_set不需要预分配，所以说直接insert即可)
					current_api_efg_set.insert(proj.graph_index);

					// 根据当前的支持度更新valid_branches
					if (current_api_efg_set.size() == min_count_) { // 判断是否达到最小支持度
						++valid_branches;
					}
					if (current_api_efg_set.size() == max_count_ + 1) { // 判断是否超过最大支持度
						--valid_branches;
					}
				}
			}

			// 判断是否提前剪枝结束当前循环
			if (static_cast<double>(valid_branches) > static_cast<double>(current_proj_list.size()) * config_.max_expan_ratio * config_.preprune_factor) {
				return;
			}

			// 遍历当前节点的子节点
			for (SIZE_T e = current_efg.offeset_[node.api_index]; e < current_efg.offeset_[node.api_index + 1]; ++e) {
				EFGListNode sub_node;
				sub_node.graph_index = node.graph_index;
				sub_node.api_index = current_efg.edges_[e].to_node_index;

				// 检查将要push的节点是否已访问并进行标记
				if (visited[sub_node.api_index] == timeset_) {
					continue;
				}
				visited[sub_node.api_index] = timeset_;

				// 把子节点push进queue
				queue.emplace(sub_node, depth + 1);
			}
		}
	}

	// 根据valid_branches计算膨胀度并尝试剪枝
	if (static_cast<double>(valid_branches) > static_cast<double>(current_proj_list.size()) * config_.max_expan_ratio) {
		return;
	}

	// 遍历生成的投影集
	for (const auto &[api_id, proj_list] : local_proj_list) {
		// 当前API的EFG图集(同样alias)
		std::unordered_set<SIZE_T> &current_api_efg_set = local_efg_map[api_id];

		// 跳过不符合条件的API
		if (current_api_efg_set.size() < min_count_ || current_api_efg_set.size() > max_count_) {
			continue;
		}

		// 计算hashcode(这个要先算，因为后面current_prefix_就变了，和碎碎念里说的处理顺序不一样)
		GREAT_SIZE_T hashcode = ((static_cast<GREAT_SIZE_T>(current_data.current_prefix_.back())) << 32ull) | static_cast<GREAT_SIZE_T>(api_id);

		// 将当前api_id插入current_prefix末尾
		current_data.current_prefix_.push_back(api_id);

		// 将当前调用链(前缀)加入调用链数据库
		CallChain call_chain;
		call_chain.api_chain = current_data.current_prefix_;
		call_chain.weight = local_efg_map[api_id].size(); // 这里的weight实际上是API链出现次数
		current_call_chain_list_mutex_.lock();
		current_call_chain_list_.push_back(call_chain);
		current_call_chain_list_mutex_.unlock();

		// 只有不超过最大递归深度且不超过最大调用链长度时向下继续递归
		if (current_depth + 1 < config_.max_depth && current_data.current_prefix_.size() < config_.max_length) {
			// 将当前边的hashcode插入edge_set_中
			current_data.edge_set_.insert(hashcode);

			// 这里其实new_proj_list = proj_list，因此无需单独计算new_proj_list
			dfs_call_chains(proj_list, current_data, current_depth + 1);

			// 后处理
			current_data.edge_set_.erase(hashcode); // 删除当前边
		}

		// 后处理
		current_data.current_prefix_.pop_back(); // pop_back当前API
	}
}

// 碎碎念x2
// to可爱喵(自恋的屑)
// (我讨厌dfs！！！QAQ)
// 1. 定义一个std::vector<ChainListAPI> local_chain_node_list数组供下一步dfs
// 2. 将node_in_chain_list的起始链条的当前深度api的子api push_back进local_chain_node_list作为第一个子节点
// 3. 遍历node_in_chain_list.node_begin到node_in_chain_list.node_end的所有调用链
//     对于每条链：
//     3.1. 检查当前api的子api是否和local_chain_node_list.back()的API相同，
//          若不相同，则对当前api的子api创建新的ChainListAPI对象，并push_back进local_chain_node_list
//     3.2. 检查当前api的子api是否是当前链的结束节点，
//          若是结束节点，则将当前链条的权重写入local_chain_node_list.back()
//     3.3. 将local_chain_node_list.back().node_end自增1
// 4. 设置当前节点在CSR Trie树中的trans_start
// 5. 遍历生成的local_chain_node_list
//     对于每个子节点(注意下文的"(当前)子节点"和"(当前)节点"间的语义区别)：
//     5.1. 将当前子节点的数据push_back进model.nodes
//     5.2. 将当前子节点在model.nodes中的索引写入到local_chain_node_list的当前子节点的node_index中
//     5.3. 将当前子节点在model.nodes的索引push_back进edges_
//     5.4. 将当前节点的trans_count++
// 6. 再次遍历local_chain_node_list
//     对于每个子节点：
//     6.1. 判断其在CallChain中是否还有子节点并dfs_trie_tree继续递归
// 5. 摸了qwq
void Trainer::dfs_trie_tree(Model &model, const ChainListAPI &node_in_chain_list) {
	std::vector<ChainListAPI> local_chain_node_list; // 我也说不清是用来做什么的，你知道它意思就行

	// 当前层深度
	const int64_t current_depth = node_in_chain_list.depth + 1;

	// 遍历当前node_in_chain_list.node_begin到node_in_chain_list.end的所有调用链
	for (SIZE_T i = node_in_chain_list.node_begin; i <= node_in_chain_list.node_end; ++i) {
		const CallChain &current_chain = call_chain_list_[i]; // Alias for 当前节点的CallChain
		const CallChain &last_chain = call_chain_list_[std::max(static_cast<int64_t>(i) - 1ll, 0ll)]; // Alias for 上一个节点的CallChain

		// 判断当前链条长度是否达到当前遍历深度，防止越界
		if (current_depth >= current_chain.api_chain.size()) {
			continue;
		}

		// 检查当前是否是首个节点且当前子api是否和上一个子api相同，若当前为首个节点或不同则执行操作
		if (local_chain_node_list.empty() || current_depth >= last_chain.api_chain.size() || current_chain.api_chain[local_chain_node_list.back().depth] != last_chain.api_chain[local_chain_node_list.back().depth]) {
			local_chain_node_list.push_back({ .weight = 0.0,
				.depth = current_depth,
				.node_begin = i,
				.node_end = i - 1 });
		}

		// 检查当前子api是不是整条CallChain的最后一个api
		if (local_chain_node_list.back().depth == current_chain.api_chain.size() - 1) {
			local_chain_node_list.back().weight = current_chain.weight;
		}

		// 自增当前子api的node_end
		++(local_chain_node_list.back().node_end);
	}
	// 这里其实不需要再给最后一个节点做处理了，因为所有节点的数据都在循环内完成了

	// 设置当前节点在CSR Trie树中的trans_start
	model.nodes[node_in_chain_list.node_index].trans_start = model.edges.size();

	// 第一次遍历local_chain_node_list(为了处理CSR数据并完善ChainListAPI的node_index参数)
	for (ChainListAPI &node : local_chain_node_list) {
		// 将当前子节点的数据push_back进model.nodes
		model.nodes.push_back({ .api_id = call_chain_list_[node.node_begin].api_chain[node.depth],
			.trans_count = 0,
			.weight = node.weight });

		// 将当前子节点在model.nodes中的索引写入到local_chain_node_list的当前子节点的node_index中
		node.node_index = model.nodes.size() - 1;

		// 将当前子节点在model.nodes的索引push_back进edges_
		model.edges.push_back(node.node_index);

		// 更新当前节点的trans_count
		++model.nodes[node_in_chain_list.node_index].trans_count;
	}

	// 第二次遍历local_chain_node_list并递归(to这个zaco第一次跑程序的时候忘了递归了)
	for (const ChainListAPI &node : local_chain_node_list) {
		if (node.node_begin > node.node_end) {
			continue;
		}
		dfs_trie_tree(model, node);
	}
}

} // namespace starlight_v3::tspm
