#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "basic/types.h"
#include "efg_generator.h"
#include "tspm/reasoner.h"
#include "tspm/trainer.h"

namespace fs = std::filesystem;

/**
 * @brief 将 AnalysisResult 导出为 Graphviz DOT 格式文件
 * @param result 推理结果
 * @param filename 输出的文件名 (例如 "result.dot")
 */
void export_analysis_to_dot(const starlight_v3::tspm::AnalysisResult& result, const std::string& filename) {
    std::ofstream ofs(filename);
    if (!ofs.is_open()) {
        std::cerr << "Error: Cannot open file " << filename << " for writing." << std::endl;
        return;
    }

    // 1. DOT 文件头
    ofs << "digraph EvidenceTree {" << std::endl;
    ofs << "  rankdir=TB;" << std::endl; // TB: Top to Bottom, LR: Left to Right
    ofs << "  node [shape=box, style=\"rounded,filled\", fontname=\"Arial\", fontsize=10];" << std::endl;
    ofs << "  edge [fontname=\"Arial\", fontsize=9];" << std::endl;

    // 2. 添加总分展示 (作为一个不可见的标题节点或 Label)
    // 这里使用 Label 属性显示在图表最上方
    ofs << "  labelloc=\"t\";" << std::endl;
    ofs << "  label=\"<<TABLE BORDER=\"0\" CELLBORDER=\"0\" CELLSPACING=\"0\">" << std::endl;
    ofs << "    <TR><TD><B>Analysis Summary</B></TD></TR>" << std::endl;
    ofs << "    <TR><TD>Final Score: " << std::fixed << std::setprecision(4) << result.final_score << "</TD></TR>" << std::endl;
    ofs << "    <TR><TD>Malware Score: " << std::fixed << std::setprecision(4) << result.malware_score << "</TD></TR>" << std::endl;
    ofs << "    <TR><TD>Benign Score: " << std::fixed << std::setprecision(4) << result.benign_score << "</TD></TR>" << std::endl;
    ofs << "  </TABLE>>\";" << std::endl;
    ofs << "  fontsize=14;" << std::endl;
    ofs << "  fontname=\"Arial Bold\";" << std::endl;
    ofs << std::endl;

    // 用于记录已经处理过的节点指针，避免在 DAG 中重复定义节点
    std::unordered_set<const starlight_v3::tspm::EvidenceTree*> visited_nodes;

    // 递归辅助函数：处理节点及其子树
    std::function<void(const std::shared_ptr<starlight_v3::tspm::EvidenceTree>&)> process_node = 
        [&](const std::shared_ptr<starlight_v3::tspm::EvidenceTree>& node) {
            if (!node) return;

            const starlight_v3::tspm::EvidenceTree* raw_ptr = node.get();
            
            // 如果节点已经被处理过，则直接返回（避免重复定义和无限递归）
            if (visited_nodes.count(raw_ptr)) {
                return;
            }
            visited_nodes.insert(raw_ptr);

            // 生成唯一的节点 ID (使用指针地址)
            std::string node_id = "node_" + std::to_string(reinterpret_cast<uintptr_t>(raw_ptr));

            // --- 1. 定义节点样式 (颜色高亮) ---
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

            // --- 2. 递归处理子节点并绘制边 ---
            for (const auto& child : node->sub_nodes) {
                if (!child) continue;

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

    // 3. 遍历所有的根节点
    for (const auto& root_tree : result.evidence_trees) {
        process_node(root_tree);
    }

    ofs << "}" << std::endl;
    ofs.close();

    std::cout << "DOT file exported to: " << filename << std::endl;
    std::cout << "You can generate image using: dot -Tpng " << filename << " -o output.png" << std::endl;
}

std::vector<starlight_v3::EFG> load_dataset(const fs::path &folder_path, size_t max_dataset_size, size_t thread_count = 0, const std::unordered_set<std::string> &allowed_extensions = {}) {
	if (!fs::is_directory(folder_path)) {
		return {};
	}

	// 1. 收集所有文件路径（带数量上限和扩展名过滤）
	std::vector<fs::path> file_paths;
	file_paths.reserve(max_dataset_size); // 预分配

	try {
		for (auto &entry : fs::recursive_directory_iterator(folder_path, fs::directory_options::skip_permission_denied)) {
			if (file_paths.size() >= max_dataset_size)
				break;

			if (!entry.is_regular_file())
				continue;

			// 扩展名过滤
			if (!allowed_extensions.empty()) {
				std::string ext = entry.path().extension().string();
				// 转小写比较（这里简化，未做大小写处理，您可自行添加）
				if (!allowed_extensions.count(ext))
					continue;
			}

			file_paths.push_back(entry.path());
		}
	} catch (const fs::filesystem_error &e) {
		std::cerr << "Warning: traversal error: " << e.what() << '\n';
	}

	const size_t total = file_paths.size();
	if (total == 0)
		return {};

	// 2. 线程数计算
	unsigned int hw = std::thread::hardware_concurrency();
	hw = hw ? hw : 4;
	unsigned int real_threads = thread_count ? static_cast<unsigned int>(thread_count) : hw;
	real_threads = std::min(real_threads, static_cast<unsigned int>(total));

	// 3. 并行生成 EFG，按索引写入
	std::vector<std::optional<starlight_v3::EFG>> results(total);
	std::atomic<size_t> current_idx { 0 };
	std::atomic<size_t> loaded_count { 0 };
	std::mutex cout_mutex;

	auto worker = [&]() {
		while (true) {
			size_t idx = current_idx.fetch_add(1);
			if (idx >= total)
				break;

			try {
				auto [success, efg] = starlight_v3::generate_efg(file_paths[idx].string());
				if (success) {
					results[idx].emplace(std::move(efg));
					size_t count = loaded_count.fetch_add(1) + 1;
					if (count % 10 == 0 || count == total) {
						std::lock_guard lock(cout_mutex);
						std::cout << "\rLoaded " << count << "/" << total
								  << " (" << file_paths[idx].filename() << ")"
								  << std::flush;
					}
				}
			} catch (const std::exception &e) {
				std::lock_guard lock(cout_mutex);
				std::cerr << "\nException in " << file_paths[idx] << ": " << e.what() << '\n';
			} catch (...) {
				std::lock_guard lock(cout_mutex);
				std::cerr << "\nUnknown exception in " << file_paths[idx] << '\n';
			}
		}
	};

	std::vector<std::thread> threads;
	threads.reserve(real_threads);
	for (unsigned i = 0; i < real_threads; ++i)
		threads.emplace_back(worker);
	for (auto &t : threads)
		t.join();

	// 4. 压缩结果
	std::vector<starlight_v3::EFG> dataset;
	dataset.reserve(loaded_count);
	for (auto &opt : results) {
		if (opt.has_value())
			dataset.push_back(std::move(*opt));
	}

	std::cout << "\nFinished. Valid EFGs: " << dataset.size() << std::endl;
	return dataset;
}

int main() {
	// 1. 指定黑白数据集文件夹路径（请根据你的实际路径修改）
	std::string malware_folder = "/toDataDrive/CSafe/CSafe-Starlight/dataset/malware/";
	std::string benign_folder = "/toDataDrive/CSafe/CSafe-Starlight/dataset/benign/";

	std::vector<starlight_v3::EFG> malware_dataset;
	std::vector<starlight_v3::EFG> benign_dataset;

	// 2. 提取 EFG
	std::cout << "=== Loading Malware Dataset ===" << std::endl;
	malware_dataset = load_dataset(malware_folder, 1000);

	std::cout << "\n=== Loading Benign Dataset ===" << std::endl;
	benign_dataset = load_dataset(benign_folder, 1000);

	// 检查数据集是否为空
	if (malware_dataset.empty() || benign_dataset.empty()) {
		std::cerr << "\n[Error] Dataset is empty. Please check the folder paths. Exiting..." << std::endl;
		std::cin.get(); // 按任意键退出
		return -1;
	}

	// 3. 配置训练参数
	starlight_v3::tspm::TrainingConfig config;
	config.preprune_factor = /*1.5*/ 10000000000.0;
	config.max_root_support = 1.0;
	config.max_expan_ratio = 1.8;
	config.thread_count = 0;
	config.min_support = 0.002; // 病毒最小支持度
	config.max_skip = 2; // 允许跳过1个混淆API
	config.max_length = 5; // 调用链最大长度
	config.max_depth = 5; // 最大递归深度
	config.min_distinction = 0.64; // 最小区分度

	// 4. 日志回调函数
	auto logger = [](const std::string &msg) {
		std::cout << "\r\033[2K" << msg << std::flush;
	};

	// 5. 初始化训练器并开始训练
	starlight_v3::tspm::Trainer trainer(config, logger);

	std::cout << "\n=== Starting Training ===" << std::endl;
	starlight_v3::tspm::Model model = trainer.train(malware_dataset, benign_dataset);

	std::cout << "\n=== Training Complete ===" << std::endl;

	std::cout << "Starting test." << std::endl;

	std::cout << "=== Loading Malware Dataset ===" << std::endl;
	malware_dataset = load_dataset(malware_folder, 150);

	std::cout << "\n=== Loading Benign Dataset ===" << std::endl;
	benign_dataset = load_dataset(benign_folder, 150);

	starlight_v3::tspm::Reasoner reasoner(model);
	std::cout << "malware: " << std::endl;
	for(int i = 0; i < malware_dataset.size(); ++i) {
		starlight_v3::tspm::AnalysisResult result = reasoner.analyze_efg(malware_dataset[i]);
		// if(i % 3) {
		// 	export_analysis_to_dot(result, "dot_files/malware_" + std::to_string(result.evidence_trees.size()) + ".dot");
		// }
		std::cout << "(size=" << malware_dataset[i].nodes_.size() << ", score=" << result.final_score << ", malscore=" << result.malware_score << ", benscore=" << result.benign_score << ", evidence count=" << result.evidence_trees.size() << ")" << std::endl;
	}
	std::cout << std::endl;
	std::cout << "benign: " << std::endl;
	for(int i = 0; i < benign_dataset.size(); ++i) {
		starlight_v3::tspm::AnalysisResult result = reasoner.analyze_efg(benign_dataset[i]);
		// if(i % 3) {
		// 	export_analysis_to_dot(result, "dot_files/benign_" + std::to_string(result.evidence_trees.size()) + ".dot");
		// }
		std::cout << "(size=" << malware_dataset[i].nodes_.size() << ", score=" << result.final_score << ", malscore=" << result.malware_score << ", benscore=" << result.benign_score << ", evidence count=" << result.evidence_trees.size() << ")" << std::endl;
	}
	return 0;
}
