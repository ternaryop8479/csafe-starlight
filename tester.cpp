#include <atomic>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "basic/types.h"
#include "efg_generator.h"
#include "lgbm/feat_extractor/efg.h"
#include "lgbm/feat_extractor/pe.h"
#include "lgbm/feat_extractor/tspm.h"
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

std::vector<starlight_v3::EFG> load_dataset(const fs::path &folder_path, size_t max_dataset_size, size_t thread_count = 0, const std::unordered_set<std::string> &allowed_extensions = {}, std::vector<fs::path> *paths_out = nullptr) {
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
	if (paths_out != nullptr) {
		paths_out->clear();
		paths_out->reserve(loaded_count);
	}
	for (size_t i = 0; i < results.size(); ++i) {
		if (results[i].has_value()) {
			dataset.push_back(std::move(*results[i]));
			if (paths_out != nullptr) {
				paths_out->push_back(file_paths[i]);
			}
		}
	}

	std::cout << "\nFinished. Valid EFGs: " << dataset.size() << std::endl;
	return dataset;
}

// ---- 临时验证: 全量171维特征输出(核对后移除) ----

#define EFG_FEAT_FIELDS(X) \
	X(node_count) X(edge_count) X(density) X(avg_degree) X(max_degree) \
	X(degree_var) X(degree_ske) X(edge_node_ratio) X(isolated_node_count) \
	X(largest_component_ratio) X(entropy) \
	X(avg_jmp_count) X(jmp_count_var) X(jmp_count_ske) X(max_jmp_count) \
	X(avg_indirect_jmp_count) X(indirect_jmp_count_var) X(indirect_jmp_count_ske) \
	X(max_indirect_jmp_count) X(indirect_jmp_edge_ratio) X(total_indirect_jmp_count) \
	X(max_span) X(avg_span) X(span_var) X(span_ske) X(jmp_count_entropy) \
	X(data_flow_edge_ratio) X(avg_span_with_data) X(max_span_with_data) \
	X(span_with_data_var) X(span_with_data_ske) \
	X(avg_jmp_count_with_data) X(max_jmp_count_with_data) \
	X(jmp_count_with_data_var) X(jmp_count_with_data_ske) \
	X(avg_indirect_jmp_with_data) X(max_indirect_jmp_with_data) \
	X(indirect_jmp_with_data_var) X(indirect_jmp_with_data_ske)

#define TSPM_FEAT_FIELDS(X) \
	X(max_malchain_length) X(avg_malchain_length) X(max_benchain_length) \
	X(avg_benchain_length) X(malchain_count) X(benchain_count) \
	X(mal_ben_avglength_ratio) X(mal_ben_maxlength_ratio) X(chain_count_diff) \
	X(is_mal_dominant) X(malchain_density) X(benchain_density) \
	X(avg_malchain_similarity) X(avg_benchain_similarity) X(avg_malmatch_depth) \
	X(avg_benmatch_depth) X(max_malmatch_depth) X(max_benmatch_depth) \
	X(malapi_count) X(benapi_count) \
	X(avg_malchain_weight) X(malchain_weight_var) X(malchain_weight_ske) \
	X(avg_benchain_weight) X(benchain_weight_var) X(benchain_weight_ske) \
	X(max_malchain_weight) X(max_benchain_weight) \
	X(avg_malweight_density) X(avg_benweight_density) \
	X(max_malweight_density) X(max_benweight_density) \
	X(tspm_mal_weight) X(tspm_ben_weight) X(weight_diff) X(weight_ratio) \
	X(avg_malskip_count) X(avg_benskip_count) \
	X(avg_malchain_branching) X(avg_benchain_branching) \
	X(max_malchain_branching) X(max_benchain_branching) \
	X(tspm_score)

#define PE_FEAT_FIELDS(X) \
	X(machine_type) X(is_64bit) X(num_sections) X(time_date_stamp) \
	X(has_symbol_table) X(size_of_optional_header) X(file_characteristics) \
	X(is_dll) X(linker_version) X(size_of_code) X(size_of_initialized_data) \
	X(size_of_uninitialized_data) X(address_of_entry_point) X(base_of_code) \
	X(image_base) X(section_alignment) X(file_alignment) X(os_version) \
	X(subsystem_version) X(size_of_image) X(size_of_headers) \
	X(checksum_is_zero) X(subsystem) X(dll_characteristics) \
	X(size_of_stack_reserve) X(size_of_stack_commit) X(size_of_heap_reserve) \
	X(size_of_heap_commit) X(number_of_rva_and_sizes) \
	X(file_entropy) X(section_entropy_mean) X(section_entropy_max) \
	X(section_entropy_min) X(section_entropy_std) X(text_section_entropy) \
	X(high_entropy_section_count) \
	X(entry_section_index) X(entry_section_entropy) X(raw_size_mean) \
	X(raw_size_max) X(virtual_size_mean) X(virtual_size_max) \
	X(vsize_raw_ratio_mean) X(vsize_raw_ratio_max) X(high_gap_section_count) \
	X(nonstandard_name_count) X(writable_executable_count) X(executable_count) \
	X(import_count) X(distinct_dll_count) X(imports_per_dll_mean) \
	X(imports_per_dll_max) X(ordinal_import_count) X(ordinal_import_ratio) \
	X(unique_api_count) X(api_name_len_mean) X(api_name_len_max) \
	X(api_name_char_entropy) X(dll_name_entropy) X(has_dynamic_import) \
	X(suspicious_api_count) X(suspicious_api_ratio) X(suspicious_dll_count) \
	X(suspicious_dll_ratio) X(process_api_count) X(network_api_count) \
	X(crypto_api_count) X(persistence_api_count) X(import_dir_size) \
	X(string_count) X(string_avg_len) X(string_max_len) X(long_string_count) \
	X(printable_ratio) X(url_count) X(file_path_count) X(registry_count) \
	X(ip_count) X(suspicious_keyword_count) \
	X(file_size) X(overlay_size) X(overlay_ratio) X(headers_image_ratio) \
	X(image_gap_ratio) X(nonzero_data_directory_count) X(export_present) \
	X(debug_present) X(resource_present) X(rich_header_entry_count)

#define FEAT_COUNT_ONE(name) +1
constexpr size_t kEfgFeatDims = 0 EFG_FEAT_FIELDS(FEAT_COUNT_ONE);
constexpr size_t kTspmFeatDims = 0 TSPM_FEAT_FIELDS(FEAT_COUNT_ONE);
constexpr size_t kPeFeatDims = 0 PE_FEAT_FIELDS(FEAT_COUNT_ONE);
#undef FEAT_COUNT_ONE

static_assert(kEfgFeatDims == 39, "EFGFeatPack 维度与宏列表不一致");
static_assert(kTspmFeatDims == 43, "TSPMFeatPack 维度与宏列表不一致");
static_assert(kPeFeatDims == 89, "PEFeatPack 维度与宏列表不一致");

/**
 * @brief 输出特征CSV表头
 */
void write_feats_csv_header(std::ofstream &ofs) {
	if (!ofs.is_open()) {
		return;
	}
	ofs << "label,file";
#define CSV_HEADER_FIELD(name) ofs << ",efg_" #name;
	EFG_FEAT_FIELDS(CSV_HEADER_FIELD)
#undef CSV_HEADER_FIELD
#define CSV_HEADER_FIELD(name) ofs << ",tspm_" #name;
	TSPM_FEAT_FIELDS(CSV_HEADER_FIELD)
#undef CSV_HEADER_FIELD
#define CSV_HEADER_FIELD(name) ofs << ",pe_" #name;
	PE_FEAT_FIELDS(CSV_HEADER_FIELD)
#undef CSV_HEADER_FIELD
	ofs << '\n';
}

/**
 * @brief 输出单个文件的171维特征CSV行
 */
void write_feats_csv_row(std::ofstream &ofs, const std::string &label, const fs::path &path,
	const starlight_v3::EFG &efg, const starlight_v3::tspm::AnalysisResult &result) {
	if (!ofs.is_open()) {
		return;
	}
	starlight_v3::EFGFeatPack efg_f = starlight_v3::lgbm::extract_efg_feats(efg);
	starlight_v3::TSPMFeatPack tspm_f = starlight_v3::lgbm::extract_tspm_feats(result, efg);
	starlight_v3::PEFeatPack pe_f = starlight_v3::lgbm::extract_pe_feats(path.string());
	ofs << label << ',' << path.filename().string();
#define CSV_VAL(name) ofs << ',' << std::setprecision(10) << efg_f.name;
	EFG_FEAT_FIELDS(CSV_VAL)
#undef CSV_VAL
#define CSV_VAL(name) ofs << ',' << std::setprecision(10) << tspm_f.name;
	TSPM_FEAT_FIELDS(CSV_VAL)
#undef CSV_VAL
#define CSV_VAL(name) ofs << ',' << std::setprecision(10) << pe_f.name;
	PE_FEAT_FIELDS(CSV_VAL)
#undef CSV_VAL
	ofs << '\n';
}

/**
 * @brief 控制台输出单个文件的全部171维特征(带名称)
 */
void print_full_feats(const std::string &label, const fs::path &path,
	const starlight_v3::EFG &efg, const starlight_v3::tspm::AnalysisResult &result) {
	starlight_v3::EFGFeatPack efg_f = starlight_v3::lgbm::extract_efg_feats(efg);
	starlight_v3::TSPMFeatPack tspm_f = starlight_v3::lgbm::extract_tspm_feats(result, efg);
	starlight_v3::PEFeatPack pe_f = starlight_v3::lgbm::extract_pe_feats(path.string());
	std::cout << "--- " << label << " (" << path.filename().string() << ") full "
			  << (kEfgFeatDims + kTspmFeatDims + kPeFeatDims) << " dims ---" << std::endl;
#define PRINT_FIELD(name) std::cout << "  efg_" #name " = " << std::setprecision(10) << efg_f.name << std::endl;
	EFG_FEAT_FIELDS(PRINT_FIELD)
#undef PRINT_FIELD
#define PRINT_FIELD(name) std::cout << "  tspm_" #name " = " << std::setprecision(10) << tspm_f.name << std::endl;
	TSPM_FEAT_FIELDS(PRINT_FIELD)
#undef PRINT_FIELD
#define PRINT_FIELD(name) std::cout << "  pe_" #name " = " << std::setprecision(10) << pe_f.name << std::endl;
	PE_FEAT_FIELDS(PRINT_FIELD)
#undef PRINT_FIELD
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
	std::vector<fs::path> malware_paths, benign_paths;
	malware_dataset = load_dataset(malware_folder, 150, 0, {}, &malware_paths);

	std::cout << "\n=== Loading Benign Dataset ===" << std::endl;
	benign_dataset = load_dataset(benign_folder, 150, 0, {}, &benign_paths);

	// 临时验证: 打印单个样本的TSPM特征(核对后移除)
	auto print_tspm_feats = [&](const std::string &label, const starlight_v3::tspm::AnalysisResult &r, const starlight_v3::EFG &efg) {
		starlight_v3::TSPMFeatPack f = starlight_v3::lgbm::extract_tspm_feats(r, efg);
		std::cout << "--- " << label << " ---" << std::endl;
		std::cout << "chains: mal_count=" << f.malchain_count << " ben_count=" << f.benchain_count
				  << " mal_maxlen=" << f.max_malchain_length << " mal_avglen=" << f.avg_malchain_length
				  << " ben_maxlen=" << f.max_benchain_length << " ben_avglen=" << f.avg_benchain_length
				  << " mal_density=" << f.malchain_density << " ben_density=" << f.benchain_density
				  << " mal_sim=" << f.avg_malchain_similarity << " ben_sim=" << f.avg_benchain_similarity
				  << " mal_depth=" << f.avg_malmatch_depth << "/" << f.max_malmatch_depth
				  << " ben_depth=" << f.avg_benmatch_depth << "/" << f.max_benmatch_depth
				  << " mal_api=" << f.malapi_count << " ben_api=" << f.benapi_count << std::endl;
		std::cout << "weights: mal_avg=" << f.avg_malchain_weight << " mal_var=" << f.malchain_weight_var
				  << " mal_ske=" << f.malchain_weight_ske << " mal_max=" << f.max_malchain_weight
				  << " ben_avg=" << f.avg_benchain_weight << " ben_var=" << f.benchain_weight_var
				  << " ben_ske=" << f.benchain_weight_ske << " ben_max=" << f.max_benchain_weight
				  << " mal_wd=" << f.avg_malweight_density << "/" << f.max_malweight_density
				  << " ben_wd=" << f.avg_benweight_density << "/" << f.max_benweight_density << std::endl;
		std::cout << "exec: mal_skip=" << f.avg_malskip_count << " ben_skip=" << f.avg_benskip_count
				  << " mal_br=" << f.avg_malchain_branching << "/" << f.max_malchain_branching
				  << " ben_br=" << f.avg_benchain_branching << "/" << f.max_benchain_branching
				  << " | engine: mal=" << f.tspm_mal_weight << " ben=" << f.tspm_ben_weight
				  << " wdiff=" << f.weight_diff << " wratio=" << f.weight_ratio << " score=" << f.tspm_score
				  << " dominant=" << f.is_mal_dominant << std::endl;
	};

	starlight_v3::tspm::Reasoner reasoner(model);
	std::cout << "Feature dims: EFG=" << kEfgFeatDims << " TSPM=" << kTspmFeatDims
			  << " PE=" << kPeFeatDims << " total=" << (kEfgFeatDims + kTspmFeatDims + kPeFeatDims) << std::endl;
	std::ofstream feats_csv("feats_dump.csv");
	write_feats_csv_header(feats_csv);

	std::cout << "malware: " << std::endl;
	for(size_t i = 0; i < malware_dataset.size(); ++i) {
		starlight_v3::tspm::AnalysisResult result = reasoner.analyze_efg(malware_dataset[i]);
		if(i == 0) {
			print_tspm_feats("malware[0]", result, malware_dataset[i]);
			print_full_feats("malware[0]", malware_paths[i], malware_dataset[i], result);
		}
		write_feats_csv_row(feats_csv, "malware", malware_paths[i], malware_dataset[i], result);
		// if(i % 3) {
		// 	export_analysis_to_dot(result, "dot_files/malware_" + std::to_string(result.evidence_trees.size()) + ".dot");
		// }
		std::cout << "(size=" << malware_dataset[i].nodes_.size() << ", score=" << result.final_score << ", malscore=" << result.malware_score << ", benscore=" << result.benign_score << ", evidence count=" << result.evidence_trees.size() << ")" << std::endl;
	}
	std::cout << std::endl;
	std::cout << "benign: " << std::endl;
	for(size_t i = 0; i < benign_dataset.size(); ++i) {
		starlight_v3::tspm::AnalysisResult result = reasoner.analyze_efg(benign_dataset[i]);
		if(i == 0) {
			print_tspm_feats("benign[0]", result, benign_dataset[i]);
			print_full_feats("benign[0]", benign_paths[i], benign_dataset[i], result);
		}
		write_feats_csv_row(feats_csv, "benign", benign_paths[i], benign_dataset[i], result);
		if(i % 3) {
			export_analysis_to_dot(result, "dot_files/benign_" + std::to_string(result.evidence_trees.size()) + ".dot");
		}
		std::cout << "(size=" << benign_dataset[i].nodes_.size() << ", score=" << result.final_score << ", malscore=" << result.malware_score << ", benscore=" << result.benign_score << ", evidence count=" << result.evidence_trees.size() << ")" << std::endl;
	}
	return 0;
}
