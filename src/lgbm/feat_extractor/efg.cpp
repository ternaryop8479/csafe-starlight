/**
 * @file lgbm/feat_extractor/efg.cpp
 * @brief EFG的特征提取器实现
 * @author ternaryop8479
 * @date 2026-08-02
 */

#include "lgbm/feat_extractor/efg.h"
#include "basic/types.h"
#include <cmath>
#include <unordered_map>
#include <vector>

// 内部工具函数
namespace {

/**
 * @brief 单维数值序列的统计结果
 */
struct FeatStats {
	double mean = 0.0; ///< 均值
	double var = 0.0; ///< 总体方差
	double ske = 0.0; ///< 偏度
	double max = 0.0; ///< 最大值
};

/**
 * @brief 计算数值序列的均值/总体方差/偏度/最大值
 *
 * 偏度使用g1 = m3 / sigma^3, 序列长度不足3或标准差趋近于0时置0.0.
 * @param data 数值序列
 * @param n 序列长度
 * @return 统计结果, 序列为空时全部为0.0
 */
FeatStats calc_feat_stats(const double *data, starlight_v3::SIZE_T n) {
	FeatStats stats;
	if (n == 0) {
		return stats;
	}

	double sum = 0.0;
	stats.max = data[0];
	for (starlight_v3::SIZE_T i = 0; i < n; ++i) {
		sum += data[i];
		if (data[i] > stats.max) {
			stats.max = data[i];
		}
	}
	stats.mean = sum / (double)n;

	double m2 = 0.0;
	for (starlight_v3::SIZE_T i = 0; i < n; ++i) {
		double d = data[i] - stats.mean;
		m2 += d * d;
	}
	stats.var = m2 / (double)n;

	double sigma = std::sqrt(stats.var);
	if (n >= 3 && !starlight_v3::near_zero(sigma)) {
		double m3 = 0.0;
		for (starlight_v3::SIZE_T i = 0; i < n; ++i) {
			double d = data[i] - stats.mean;
			m3 += d * d * d;
		}
		stats.ske = m3 / (double)n / (sigma * sigma * sigma);
	}
	return stats;
}

/**
 * @brief 计算数值序列分布的Shannon熵
 * @param data 数值序列
 * @param n 序列长度
 * @return 熵值, 序列为空时为0.0
 */
double calc_entropy(const double *data, starlight_v3::SIZE_T n) {
	if (n == 0) {
		return 0.0;
	}
	std::unordered_map<double, starlight_v3::SIZE_T> freq;
	for (starlight_v3::SIZE_T i = 0; i < n; ++i) {
		++freq[data[i]];
	}
	double entropy = 0.0;
	for (auto &entry : freq) {
		double p = (double)entry.second / (double)n;
		entropy -= p * std::log(p);
	}
	return entropy;
}

/**
 * @brief 通过迭代BFS统计包含指定节点的连通分量大小
 * @param efg 目标EFG
 * @param start 起始节点下标
 * @param visited 访问标记表(传入时为全0)
 * @param mark 本次BFS使用的访问标记值
 * @return 连通分量中的节点数
 */
starlight_v3::SIZE_T bfs_component_size(const starlight_v3::EFG &efg, starlight_v3::SIZE_T start, std::vector<starlight_v3::SIZE_T> &visited, starlight_v3::SIZE_T mark) {
	starlight_v3::SIZE_T count = 0;
	std::vector<starlight_v3::SIZE_T> stack;
	stack.push_back(start);
	visited[start] = mark;
	while (!stack.empty()) {
		starlight_v3::SIZE_T current = stack.back();
		stack.pop_back();
		++count;
		for (starlight_v3::SIZE_T e = efg.offeset_[current]; e < efg.offeset_[current + 1]; ++e) {
			starlight_v3::SIZE_T next = (starlight_v3::SIZE_T)efg.edges_[e].to_node_index;
			// 防御: to_node_index越界时跳过, 防止外部构造的畸形EFG触发越界写
			if (next >= visited.size()) {
				continue;
			}
			if (visited[next] != mark) {
				visited[next] = mark;
				stack.push_back(next);
			}
		}
	}
	return count;
}

} // namespace

namespace starlight_v3::lgbm {

// EFG特征提取主函数
EFGFeatPack extract_efg_feats(const EFG &efg) {
	EFGFeatPack feats = {}; // 值初始化, 保证空图/空边集返回全零特征
	SIZE_T node_count = (SIZE_T)efg.nodes_.size();
	SIZE_T edge_count = (SIZE_T)efg.edges_.size();
	feats.node_count = node_count;
	feats.edge_count = edge_count;

	// 无边EFG(有节点但无调用边, 如.NET程序)的语义: 全部节点出度为0(孤立), 入口分量仅含节点0
	if (node_count == 0) {
		return feats;
	}
	if (edge_count == 0) {
		feats.isolated_node_count = node_count;
		feats.largest_component_ratio = 1.0 / (double)node_count;
		return feats;
	}

	// ---- 结构统计特征(11维) ----
	// 节点出度序列
	std::vector<double> out_degrees;
	out_degrees.reserve(node_count);
	SIZE_T isolated_count = 0;
	for (SIZE_T i = 0; i < node_count; ++i) {
		double degree = (double)(efg.offeset_[i + 1] - efg.offeset_[i]);
		out_degrees.push_back(degree);
		if (degree == 0.0) {
			++isolated_count;
		}
	}

	FeatStats degree_stats = calc_feat_stats(out_degrees.data(), node_count);
	feats.density = node_count > 1 ? (double)edge_count / ((double)node_count * (node_count - 1)) : 0.0;
	feats.avg_degree = (double)edge_count / (double)node_count;
	feats.max_degree = (SIZE_T)degree_stats.max;
	feats.degree_var = degree_stats.var;
	feats.degree_ske = degree_stats.ske;
	feats.edge_node_ratio = (double)edge_count / (double)node_count;
	feats.isolated_node_count = isolated_count;
	feats.entropy = calc_entropy(out_degrees.data(), node_count);

	// 最大连通分量(包含ENTRY节点即节点0的分量)
	std::vector<SIZE_T> visited(node_count, 0);
	feats.largest_component_ratio = (double)bfs_component_size(efg, 0, visited, 1) / (double)node_count;

	// ---- 边信息特征(28维) ----
	// 全量边的样本序列
	std::vector<double> jmp_counts;
	std::vector<double> indirect_jmp_counts;
	std::vector<double> spans;
	jmp_counts.reserve(edge_count);
	indirect_jmp_counts.reserve(edge_count);
	spans.reserve(edge_count);

	// 携带数据的边(spans_with_data > 0)的子集样本序列
	std::vector<double> data_spans;
	std::vector<double> data_jmp_counts;
	std::vector<double> data_indirect_jmp_counts;

	SIZE_T indirect_jmp_edge_count = 0;
	SIZE_T data_flow_edge_count = 0;
	double total_indirect_jmp = 0.0;
	for (SIZE_T e = 0; e < edge_count; ++e) {
		const EFGEdge &edge = efg.edges_[e];
		jmp_counts.push_back((double)edge.jump_count);
		indirect_jmp_counts.push_back((double)edge.indirect_jump_count);
		spans.push_back(edge.avg_span);
		total_indirect_jmp += (double)edge.indirect_jump_count;

		if (edge.indirect_jump_count > 0) {
			++indirect_jmp_edge_count;
		}
		if (edge.spans_with_data > 0) {
			++data_flow_edge_count;
			data_spans.push_back(edge.avg_span);
			data_jmp_counts.push_back((double)edge.jump_count);
			data_indirect_jmp_counts.push_back((double)edge.indirect_jump_count);
		}
	}

	FeatStats jmp_stats = calc_feat_stats(jmp_counts.data(), edge_count);
	FeatStats indirect_stats = calc_feat_stats(indirect_jmp_counts.data(), edge_count);
	FeatStats span_stats = calc_feat_stats(spans.data(), edge_count);

	feats.avg_jmp_count = jmp_stats.mean;
	feats.jmp_count_var = jmp_stats.var;
	feats.jmp_count_ske = jmp_stats.ske;
	feats.max_jmp_count = jmp_stats.max;
	feats.avg_indirect_jmp_count = indirect_stats.mean;
	feats.indirect_jmp_count_var = indirect_stats.var;
	feats.indirect_jmp_count_ske = indirect_stats.ske;
	feats.max_indirect_jmp_count = indirect_stats.max;
	feats.indirect_jmp_edge_ratio = (double)indirect_jmp_edge_count / (double)edge_count;
	feats.total_indirect_jmp_count = total_indirect_jmp;
	feats.max_span = span_stats.max;
	feats.avg_span = span_stats.mean;
	feats.span_var = span_stats.var;
	feats.span_ske = span_stats.ske;
	feats.jmp_count_entropy = calc_entropy(jmp_counts.data(), edge_count);

	// 携带数据的边的子集统计(空子集时为0.0)
	feats.data_flow_edge_ratio = (double)data_flow_edge_count / (double)edge_count;
	SIZE_T data_edge_count = (SIZE_T)data_spans.size();
	FeatStats data_span_stats = calc_feat_stats(data_spans.data(), data_edge_count);
	FeatStats data_jmp_stats = calc_feat_stats(data_jmp_counts.data(), data_edge_count);
	FeatStats data_indirect_stats = calc_feat_stats(data_indirect_jmp_counts.data(), data_edge_count);

	feats.avg_span_with_data = data_span_stats.mean;
	feats.max_span_with_data = data_span_stats.max;
	feats.span_with_data_var = data_span_stats.var;
	feats.span_with_data_ske = data_span_stats.ske;
	feats.avg_jmp_count_with_data = data_jmp_stats.mean;
	feats.max_jmp_count_with_data = data_jmp_stats.max;
	feats.jmp_count_with_data_var = data_jmp_stats.var;
	feats.jmp_count_with_data_ske = data_jmp_stats.ske;
	feats.avg_indirect_jmp_with_data = data_indirect_stats.mean;
	feats.max_indirect_jmp_with_data = data_indirect_stats.max;
	feats.indirect_jmp_with_data_var = data_indirect_stats.var;
	feats.indirect_jmp_with_data_ske = data_indirect_stats.ske;

	return feats;
}

} // namespace starlight_v3::lgbm
