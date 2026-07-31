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
	std::string malware_folder = "/run/media/Ternary_Operator/ShihyDataHouse/CSafe-NebulaEngine/dataset/malware/";
	std::string benign_folder = "/run/media/Ternary_Operator/ShihyDataHouse/CSafe-NebulaEngine/dataset/benign/";

	std::vector<starlight_v3::EFG> malware_dataset;
	std::vector<starlight_v3::EFG> benign_dataset;

	// 2. 提取 EFG
	std::cout << "=== Loading Malware Dataset ===" << std::endl;
	malware_dataset = load_dataset(malware_folder, 5000);

	std::cout << "\n=== Loading Benign Dataset ===" << std::endl;
	benign_dataset = load_dataset(benign_folder, 5000);

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
	config.max_expan_ratio = 1.9;
	config.fast_mode = false; // 全训练
	config.min_support = 0.002; // 病毒最小支持度
	config.max_skip = 1; // 允许跳过1个混淆API
	config.max_length = 5; // 调用链最大长度
	config.max_depth = 5; // 最大递归深度
	config.min_distinction = 0.0; // 最小区分度

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
	malware_dataset = load_dataset(malware_folder, 200);

	std::cout << "\n=== Loading Benign Dataset ===" << std::endl;
	benign_dataset = load_dataset(benign_folder, 200);

	starlight_v3::tspm::Reasoner reasoner(model);
	std::cout << "malware: " << std::endl;
	for(int i = 0; i < malware_dataset.size(); ++i) {
		std::cout << "(size=" << malware_dataset[i].nodes_.size() << ", score=" << reasoner.calculate_risk_score(malware_dataset[i]) << ")" << std::endl;
	}
	std::cout << std::endl;
	std::cout << "benign: " << std::endl;
	for(int i = 0; i < benign_dataset.size(); ++i) {
		std::cout << "(size=" << benign_dataset[i].nodes_.size() << ", score=" << reasoner.calculate_risk_score(benign_dataset[i]) << ")" << std::endl;
	}
	return 0;
}
