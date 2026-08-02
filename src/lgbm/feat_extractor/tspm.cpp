/**
 * @file lgbm/feat_extractor/tspm.cpp
 * @brief tosSPM推理结果的特征提取器实现
 * @author ternaryop8479
 * @date 2026-08-02
 */

#include "lgbm/feat_extractor/tspm.h"
#include "basic/types.h"
#include <cmath>
#include <unordered_set>
#include <vector>

// 内部工具函数
namespace {

/**
 * @brief 单维数值序列的统计结果
 */
struct SampleStats {
	double mean = 0.0; ///< 均值
	double var = 0.0; ///< 总体方差
	double ske = 0.0; ///< 偏度
	double max = 0.0; ///< 最大值
};

/**
 * @brief 计算数值序列的均值/总体方差/偏度/最大值
 *
 * 偏度使用g1 = m3 / sigma^3, 序列长度不足3或标准差趋近于0时置0.0.
 * @param samples 数值序列
 * @return 统计结果, 序列为空时全部为0.0
 */
SampleStats calc_sample_stats(const std::vector<double> &samples) {
	SampleStats stats;
	starlight_v3::SIZE_T n = (starlight_v3::SIZE_T)samples.size();
	if (n == 0) {
		return stats;
	}

	double sum = 0.0;
	stats.max = samples[0];
	for (double v : samples) {
		sum += v;
		if (v > stats.max) {
			stats.max = v;
		}
	}
	stats.mean = sum / (double)n;

	double m2 = 0.0;
	for (double v : samples) {
		double d = v - stats.mean;
		m2 += d * d;
	}
	stats.var = m2 / (double)n;

	double sigma = std::sqrt(stats.var);
	if (n >= 3 && !starlight_v3::near_zero(sigma)) {
		double m3 = 0.0;
		for (double v : samples) {
			double d = v - stats.mean;
			m3 += d * d * d;
		}
		stats.ske = m3 / (double)n / (sigma * sigma * sigma);
	}
	return stats;
}

/**
 * @brief 计算EFG中每个节点到入口节点(节点0)的有向边数
 *
 * 沿出边方向BFS, 不可达节点的距离为INVALID_NUM.
 * @param efg 目标EFG
 * @return 距离数组, 下标对应EFG节点下标
 */
std::vector<starlight_v3::SIZE_T> calc_entry_distances(const starlight_v3::EFG &efg) {
	starlight_v3::SIZE_T node_count = (starlight_v3::SIZE_T)efg.nodes_.size();
	std::vector<starlight_v3::SIZE_T> dist(node_count, starlight_v3::INVALID_NUM);
	if (node_count == 0) {
		return dist;
	}

	dist[0] = 0;
	std::vector<starlight_v3::SIZE_T> queue;
	queue.reserve(node_count);
	queue.push_back(0);
	for (starlight_v3::SIZE_T head = 0; head < queue.size(); ++head) {
		starlight_v3::SIZE_T current = queue[head];
		for (starlight_v3::SIZE_T e = efg.offeset_[current]; e < efg.offeset_[current + 1]; ++e) {
			starlight_v3::SIZE_T next = (starlight_v3::SIZE_T)efg.edges_[e].to_node_index;
			if (dist[next] == starlight_v3::INVALID_NUM) {
				dist[next] = dist[current] + 1;
				queue.push_back(next);
			}
		}
	}
	return dist;
}

/**
 * @brief 单个类(恶意/良性)的链条统计累加器
 */
struct ClassAccum {
	starlight_v3::SIZE_T chain_count = 0; ///< 链数
	double length_sum = 0.0; ///< 各链长度之和(含跳过)
	std::vector<double> lengths; ///< 各链长度(含跳过)
	std::vector<double> weights; ///< 各链权重(终止节点权重)
	std::vector<double> weight_densities; ///< 各链的长度/权重比
	std::vector<double> depths; ///< 各链深度(仅入口可达的链)
	std::vector<double> skips; ///< 各链跳过次数
	double branch_sum = 0.0; ///< 链上节点出度之和(池化)
	starlight_v3::SIZE_T branch_node_count = 0; ///< 链上节点总数(池化)
	double branch_max = 0.0; ///< 链上节点最大出度(池化)
	double max_length = 0.0; ///< 最长链长度
	std::unordered_set<starlight_v3::SIZE_T> covered; ///< 链路径覆盖的EFG节点下标去重集合
};

/**
 * @brief 统计证据森林中所有链条的累加器
 */
class ChainAccumulator {
public:
	/**
	 * @brief 遍历证据森林并累加全部链条的统计量
	 * @param roots 证据森林根节点列表
	 * @param dist EFG入口距离数组
	 * @param efg 目标EFG
	 */
	void walk_forest(const std::vector<std::shared_ptr<starlight_v3::tspm::EvidenceTree>> &roots, const std::vector<starlight_v3::SIZE_T> &dist, const starlight_v3::EFG &efg) {
		for (const auto &root : roots) {
			std::vector<const starlight_v3::tspm::EvidenceTree *> path;
			walk_node(root.get(), path, dist, efg);
		}
	}

	ClassAccum mal_; ///< 恶意链统计
	ClassAccum ben_; ///< 良性链统计

private:
	/**
	 * @brief 递归遍历单个证据树节点, 每到达一个带权重节点即完成一条链
	 */
	void walk_node(const starlight_v3::tspm::EvidenceTree *node, std::vector<const starlight_v3::tspm::EvidenceTree *> &path, const std::vector<starlight_v3::SIZE_T> &dist, const starlight_v3::EFG &efg) {
		path.push_back(node);
		if (!starlight_v3::near_zero(node->weight)) { // 带权重节点 = 链终止节点
			collect_chain(path, dist, efg);
		} else { // 中间节点(含跳过节点), 继续向下遍历
			for (const auto &child : node->sub_nodes) {
				walk_node(child.get(), path, dist, efg);
			}
		}
		path.pop_back();
	}

	/**
	 * @brief 根据一条链的路径累加统计量
	 */
	void collect_chain(const std::vector<const starlight_v3::tspm::EvidenceTree *> &path, const std::vector<starlight_v3::SIZE_T> &dist, const starlight_v3::EFG &efg) {
		const starlight_v3::tspm::EvidenceTree *terminal = path.back();
		ClassAccum &acc = (terminal->weight > 0.0) ? mal_ : ben_;
		double length = (double)path.size();
		acc.chain_count++;
		acc.lengths.push_back(length);
		acc.length_sum += length;
		acc.weights.push_back(terminal->weight);
		acc.weight_densities.push_back(length / terminal->weight);
		if (length > acc.max_length) {
			acc.max_length = length;
		}

		// 跳过次数 = 路径上被跳过节点的数量
		double skip_count = 0.0;
		for (const auto *pnode : path) {
			if (pnode->is_skipped) {
				++skip_count;
			}
		}
		acc.skips.push_back(skip_count);

		// 深度 = 链根节点到EFG入口的边数, 入口不可达的链不参与深度统计
		starlight_v3::SIZE_T root_index = path.front()->node_index_in_efg;
		if (root_index < dist.size() && dist[root_index] != starlight_v3::INVALID_NUM) {
			acc.depths.push_back((double)dist[root_index]);
		}

		// 出度池化(含跳过节点的子节点)与覆盖集合(含跳过节点)
		for (const auto *pnode : path) {
			double out_degree = (double)pnode->sub_nodes.size();
			acc.branch_sum += out_degree;
			++acc.branch_node_count;
			if (out_degree > acc.branch_max) {
				acc.branch_max = out_degree;
			}
			if (pnode->node_index_in_efg < efg.nodes_.size()) {
				acc.covered.insert(pnode->node_index_in_efg);
			}
		}
	}
};

} // namespace

namespace starlight_v3::lgbm {

// TSPM特征提取主函数
TSPMFeatPack extract_tspm_feats(const tspm::AnalysisResult &result, const EFG &efg) {
	TSPMFeatPack feats = {}; // 值初始化, 空集合统计量全部置0.0

	// 遍历证据森林, 统计全部链条
	ChainAccumulator accumulator;
	std::vector<SIZE_T> dist = calc_entry_distances(efg);
	accumulator.walk_forest(result.evidence_trees, dist, efg);

	SIZE_T efg_node_count = (SIZE_T)efg.nodes_.size();

	// ---- 恶意链统计 ----
	SampleStats mal_len_stats = calc_sample_stats(accumulator.mal_.lengths);
	SampleStats mal_weight_stats = calc_sample_stats(accumulator.mal_.weights);
	SampleStats mal_density_stats = calc_sample_stats(accumulator.mal_.weight_densities);
	SampleStats mal_depth_stats = calc_sample_stats(accumulator.mal_.depths);
	SampleStats mal_skip_stats = calc_sample_stats(accumulator.mal_.skips);
	SIZE_T mal_covered_count = (SIZE_T)accumulator.mal_.covered.size();
	double mal_branch_avg = accumulator.mal_.branch_node_count > 0 ? accumulator.mal_.branch_sum / (double)accumulator.mal_.branch_node_count : 0.0;

	feats.max_malchain_length = (SIZE_T)mal_len_stats.max;
	feats.avg_malchain_length = mal_len_stats.mean;
	feats.malchain_count = accumulator.mal_.chain_count;
	feats.malchain_density = efg_node_count > 0 ? (double)mal_covered_count / (double)efg_node_count : 0.0;
	feats.avg_malchain_similarity = (accumulator.mal_.chain_count > 0 && mal_covered_count > 0) ? mal_len_stats.mean * (double)accumulator.mal_.chain_count / (double)mal_covered_count : 0.0;
	feats.avg_malmatch_depth = mal_depth_stats.mean;
	feats.max_malmatch_depth = (SIZE_T)mal_depth_stats.max;
	feats.malapi_count = (SIZE_T)accumulator.mal_.length_sum;

	feats.avg_malchain_weight = mal_weight_stats.mean;
	feats.malchain_weight_var = mal_weight_stats.var;
	feats.malchain_weight_ske = mal_weight_stats.ske;
	feats.max_malchain_weight = mal_weight_stats.max;
	feats.avg_malweight_density = mal_density_stats.mean;
	feats.max_malweight_density = mal_density_stats.max;

	feats.avg_malskip_count = mal_skip_stats.mean;
	feats.avg_malchain_branching = mal_branch_avg;
	feats.max_malchain_branching = accumulator.mal_.branch_max;

	// ---- 良性链统计 ----
	SampleStats ben_len_stats = calc_sample_stats(accumulator.ben_.lengths);
	SampleStats ben_weight_stats = calc_sample_stats(accumulator.ben_.weights);
	SampleStats ben_density_stats = calc_sample_stats(accumulator.ben_.weight_densities);
	SampleStats ben_depth_stats = calc_sample_stats(accumulator.ben_.depths);
	SampleStats ben_skip_stats = calc_sample_stats(accumulator.ben_.skips);
	SIZE_T ben_covered_count = (SIZE_T)accumulator.ben_.covered.size();
	double ben_branch_avg = accumulator.ben_.branch_node_count > 0 ? accumulator.ben_.branch_sum / (double)accumulator.ben_.branch_node_count : 0.0;

	feats.max_benchain_length = (SIZE_T)ben_len_stats.max;
	feats.avg_benchain_length = ben_len_stats.mean;
	feats.benchain_count = accumulator.ben_.chain_count;
	feats.benchain_density = efg_node_count > 0 ? (double)ben_covered_count / (double)efg_node_count : 0.0;
	feats.avg_benchain_similarity = (accumulator.ben_.chain_count > 0 && ben_covered_count > 0) ? ben_len_stats.mean * (double)accumulator.ben_.chain_count / (double)ben_covered_count : 0.0;
	feats.avg_benmatch_depth = ben_depth_stats.mean;
	feats.max_benmatch_depth = (SIZE_T)ben_depth_stats.max;
	feats.benapi_count = (SIZE_T)accumulator.ben_.length_sum;

	feats.avg_benchain_weight = ben_weight_stats.mean;
	feats.benchain_weight_var = ben_weight_stats.var;
	feats.benchain_weight_ske = ben_weight_stats.ske;
	feats.max_benchain_weight = ben_weight_stats.max;
	feats.avg_benweight_density = ben_density_stats.mean;
	feats.max_benweight_density = ben_density_stats.max;

	feats.avg_benskip_count = ben_skip_stats.mean;
	feats.avg_benchain_branching = ben_branch_avg;
	feats.max_benchain_branching = accumulator.ben_.branch_max;

	// ---- 跨类比较特征 ----
	bool mal_has_chain = accumulator.mal_.chain_count > 0;
	bool ben_has_chain = accumulator.ben_.chain_count > 0;
	feats.mal_ben_avglength_ratio = (mal_has_chain && ben_has_chain) ? mal_len_stats.mean / ben_len_stats.mean : 0.0;
	feats.mal_ben_maxlength_ratio = (mal_has_chain && ben_has_chain) ? mal_len_stats.max / ben_len_stats.max : 0.0;
	feats.chain_count_diff = (accumulator.mal_.chain_count >= accumulator.ben_.chain_count) ? accumulator.mal_.chain_count - accumulator.ben_.chain_count : accumulator.ben_.chain_count - accumulator.mal_.chain_count;
	feats.is_mal_dominant = mal_has_chain && (!ben_has_chain || accumulator.mal_.max_length >= accumulator.ben_.max_length);

	// ---- 引擎输出特征 ----
	feats.tspm_mal_weight = result.malware_score;
	feats.tspm_ben_weight = result.benign_score;
	feats.weight_diff = result.malware_score - result.benign_score;
	feats.weight_ratio = !near_zero(result.benign_score) ? std::fabs(result.malware_score / result.benign_score) : 0.0;
	feats.tspm_score = result.final_score;

	return feats;
}

} // namespace starlight_v3::lgbm
