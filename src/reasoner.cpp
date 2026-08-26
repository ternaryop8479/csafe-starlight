/**
 * @file reasoner.cpp
 * @brief 最终推理器实现(整合推理)
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <unordered_set>

#include "efg_generator.h"
#include "lgbm/feat_extractor/efg.h"
#include "lgbm/feat_extractor/pe.h"
#include "lgbm/feat_extractor/tspm.h"
#include "lgbm/feat_vector.h"
#include "reasoner.h"

namespace starlight_v3 {

// 将推理结果的证据树导出为Graphviz DOT文件
void extract_evidence_dot(const AnalysisResult &result, const std::string &filename) {
	std::ofstream ofs(filename);
	if (!ofs.is_open()) {
		std::cerr << "Error: Cannot open file " << filename << " for writing." << std::endl;
		return;
	}

	// DOT 文件头
	ofs << "digraph EvidenceTree {" << std::endl;
	ofs << "  rankdir=TB;" << std::endl; // 布局方向: TB=自上而下, LR=自左至右
	ofs << "  node [shape=box, style=\"rounded,filled\", fontname=\"Arial\", fontsize=10];" << std::endl;
	ofs << "  edge [fontname=\"Arial\", fontsize=9];" << std::endl;

	// 添加总分展示 (作为一个不可见的标题节点或 Label)
	// 这里使用 Label 属性显示在图表最上方
	ofs << "  labelloc=\"t\";" << std::endl;
	ofs << "  label=\"<<TABLE BORDER=\"0\" CELLBORDER=\"0\" CELLSPACING=\"0\">" << std::endl;
	ofs << "    <TR><TD><B>Analysis Summary</B></TD></TR>" << std::endl;
	ofs << "    <TR><TD>Final Score: " << std::fixed << std::setprecision(4) << result.final_score << "</TD></TR>" << std::endl;
	ofs << "    <TR><TD>Malware Score: " << std::fixed << std::setprecision(4) << result.tspm_result.malware_score << "</TD></TR>" << std::endl;
	ofs << "    <TR><TD>Benign Score: " << std::fixed << std::setprecision(4) << result.tspm_result.benign_score << "</TD></TR>" << std::endl;
	ofs << "  </TABLE>>\";" << std::endl;
	ofs << "  fontsize=14;" << std::endl;
	ofs << "  fontname=\"Arial Bold\";" << std::endl;
	ofs << std::endl;

	// 用于记录已经处理过的节点指针，避免在 DAG 中重复定义节点
	std::unordered_set<const tspm::EvidenceTree *> visited_nodes;

	// 递归辅助函数：处理节点及其子树
	std::function<void(const std::shared_ptr<tspm::EvidenceTree> &)> process_node =
		[&](const std::shared_ptr<tspm::EvidenceTree> &node) {
			if (!node) {
				return;
			}

			const tspm::EvidenceTree *raw_ptr = node.get();

			// 如果节点已经被处理过，则直接返回（避免重复定义和无限递归）
			if (visited_nodes.count(raw_ptr)) {
				return;
			}
			visited_nodes.insert(raw_ptr);

			// 生成唯一的节点 ID (使用指针地址)
			std::string node_id = "node_" + std::to_string(reinterpret_cast<uintptr_t>(raw_ptr));

			// 定义节点样式 (颜色高亮)
			ofs << "  " << node_id << " [";

			if (node->weight > 1e-6) {
				// 恶意/风险权重 -> 红色
				ofs << "fillcolor=\"#ffcccc\", color=\"#cc0000\", penwidth=1.5";
			} else if (node->weight < -1e-6) {
				// 良性权重 -> 绿色
				ofs << "fillcolor=\"#ccffcc\", color=\"#006600\", penwidth=1.5";
			} else {
				// 权重为0或接近0 -> 灰色 (通常是路径节点)
				ofs << "fillcolor=\"#eeeeee\", color=\"#999999\", style=\"rounded,dashed,filled\"";
			}

			// 标签内容：API名 和 权重
			ofs << ", label=\"" << node->api_name << "\\n";
			ofs << "Weight: " << std::fixed << std::setprecision(3) << node->weight << "\"];" << std::endl;

			// 递归处理子节点并绘制边
			for (const auto &child : node->sub_nodes) {
				if (!child) {
					continue;
				}

				std::string child_id = "node_" + std::to_string(reinterpret_cast<uintptr_t>(child.get()));

				// 绘制边
				ofs << "  " << node_id << " -> " << child_id << " [";

				// 边的颜色也可以跟随子节点的颜色，稍微淡一点
				if (child->weight > 1e-6) {
					ofs << "color=\"#ff9999\"";
				} else if (child->weight < -1e-6) {
					ofs << "color=\"#99cc99\"";
				} else {
					ofs << "color=\"#cccccc\"";
				}
				ofs << "];" << std::endl;

				// 递归处理子节点
				process_node(child);
			}
		};

	// 遍历所有的根节点
	for (const auto &root_tree : result.tspm_result.evidence_trees) {
		process_node(root_tree);
	}

	ofs << "}" << std::endl;
	ofs.close();

	std::cout << "DOT file exported to: " << filename << std::endl;
	std::cout << "You can generate image using: dot -Tpng " << filename << " -o output.png" << std::endl;
}

// 构造函数, 同时初始化tosSPM推理器与LightGBM推理器
Reasoner::Reasoner(const Model &model) : model_(model), tspm_reasoner_(model.tspm_model()), lgbm_reasoner_(model.lgbm_model()) {
}

Reasoner::~Reasoner() = default;

// 对已知EFG进行分析(不提取PE特征, PE特征全零)
AnalysisResult Reasoner::analyze_efg(const EFG &efg) {
	AnalysisResult result = {}; // 值初始化, 未提取的PE特征保持全零

	// tosSPM推理(记录证据树, 供特征提取与DOT导出使用)
	result.tspm_result = tspm_reasoner_.analyze_efg(efg, true);

	// 提取特征: EFG特征 + TSPM特征, PE特征保持全零
	result.feats.efg_feats = lgbm::extract_efg_feats(efg);
	result.feats.tspm_feats = lgbm::extract_tspm_feats(result.tspm_result, efg);

	// LightGBM打分
	double features[lgbm::kTotalFeatDims];
	lgbm::serialize_feat_pack(result.feats, features);
	result.final_score = lgbm_reasoner_.predict(features, static_cast<int32_t>(lgbm::kTotalFeatDims));
	return result;
}

// 对已知EFG进行分析(提取完整434维特征)
AnalysisResult Reasoner::analyze_efg(const EFG &efg, const std::string &file_path) {
	AnalysisResult result = {}; // 值初始化, 四个特征组全部清零

	// tosSPM推理(记录证据树, 供特征提取与DOT导出使用)
	result.tspm_result = tspm_reasoner_.analyze_efg(efg, true);

	// 提取特征: EFG特征 + TSPM特征 + PE特征 + 字节分布特征
	result.feats.efg_feats = lgbm::extract_efg_feats(efg);
	result.feats.tspm_feats = lgbm::extract_tspm_feats(result.tspm_result, efg);
	result.feats.pe_feats = lgbm::extract_pe_feats(file_path, &result.feats.block_entropy_feats);

	// LightGBM打分
	double features[lgbm::kTotalFeatDims];
	lgbm::serialize_feat_pack(result.feats, features);
	result.final_score = lgbm_reasoner_.predict(features, static_cast<int32_t>(lgbm::kTotalFeatDims));
	return result;
}

// 对指定PE文件进行分析(内部自动生成EFG)
AnalysisResult Reasoner::analyze_file(const std::string &file_path) {
	auto [success, efg] = generate_efg(file_path);
	if (!success) {
		throw std::runtime_error("Reasoner::analyze_file(): EFG generation failed, file is not a valid PE: " + file_path);
	}
	return analyze_efg(efg, file_path);
}

} // namespace starlight_v3
