/**
 * @file starlight_v3.cpp
 * @brief CSafe Starlight V3 官方训练/跑分/推理命令行工具
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 *
 * 子命令:
 *   train <malware_dir> <benign_dir> <model_path> [max_train_samples]  训练模型
 *   score <model_path> <malware_dir> <benign_dir> [max_score_samples]  对黑白数据集跑分并统计
 *   infer <model_path> <target> [max_samples]                          推理判定(按单文件或文件夹)
 *   --version                                                          输出版本信息
 */

#include <atomic>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "efg_generator.h"
#include "model.h"
#include "reasoner.h"
#include "trainer.h"

namespace fs = std::filesystem;
namespace {

constexpr const char *kVersion = "3.0.0";

// 恶意判定阈值, final_score大于该值判为恶意
constexpr double kMalwareThreshold = 0.5;

/**
 * @brief 将扩展名转小写
 */
std::string lowercase_ext(const std::string &ext) {
	std::string result = ext;
	for (char &c : result) {
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	return result;
}

/**
 * @brief 解析无符号整数参数, 非法输入返回默认值并打印警告
 */
size_t parse_size_arg(const char *str, size_t default_value, const char *arg_name) {
	if (str == nullptr) {
		return default_value;
	}
	try {
		return static_cast<size_t>(std::stoull(str));
	} catch (const std::exception &) {
		std::cerr << "[Warning] 参数 " << arg_name << " 不是合法的非负整数, 使用默认值 "
				  << default_value << std::endl;
		return default_value;
	}
}

/**
 * @brief 从指定文件夹加载EFG数据集, 可选输出每个EFG对应的源文件路径
 * @param folder_path 数据集文件夹路径
 * @param max_dataset_size 最大加载样本数
 * @param thread_count 并行加载线程数, 0表示系统最大并发数
 * @param allowed_extensions 允许的文件扩展名集合(自动转小写比较), 为空表示不过滤
 * @param paths_out 非空时输出每个成功加载的EFG对应的源文件路径
 * @return 加载成功的EFG数据集
 */
std::vector<starlight_v3::EFG> load_dataset(const fs::path &folder_path, size_t max_dataset_size, size_t thread_count = 0, const std::unordered_set<std::string> &allowed_extensions = {}, std::vector<fs::path> *paths_out = nullptr) {
	std::vector<starlight_v3::EFG> empty_result;
	if (!fs::exists(folder_path)) {
		std::cerr << "[Error] 路径不存在: " << folder_path << std::endl;
		return empty_result;
	}
	if (!fs::is_directory(folder_path)) {
		std::cerr << "[Error] 路径不是文件夹: " << folder_path << std::endl;
		return empty_result;
	}

	// 1. 收集所有文件路径(带数量上限和扩展名过滤)
	std::vector<fs::path> file_paths;
	file_paths.reserve(max_dataset_size);

	try {
		for (auto &entry : fs::recursive_directory_iterator(folder_path, fs::directory_options::skip_permission_denied)) {
			if (file_paths.size() >= max_dataset_size)
				break;

			if (!entry.is_regular_file())
				continue;

			// 扩展名过滤(大小写不敏感)
			if (!allowed_extensions.empty()) {
				std::string ext = lowercase_ext(entry.path().extension().string());
				if (!allowed_extensions.count(ext))
					continue;
			}

			file_paths.push_back(entry.path());
		}
	} catch (const fs::filesystem_error &e) {
		std::cerr << "[Warning] 目录遍历错误: " << e.what() << std::endl;
	}

	const size_t total = file_paths.size();
	if (total == 0)
		return empty_result;

	// 2. 线程数计算
	unsigned int hw = std::thread::hardware_concurrency();
	hw = hw ? hw : 4;
	unsigned int real_threads = thread_count ? static_cast<unsigned int>(thread_count) : hw;
	real_threads = std::min(real_threads, static_cast<unsigned int>(total));

	// 3. 并行生成 EFG, 按索引写入
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
						std::cout << "\r[Info] 已加载 " << count << "/" << total
								  << " (" << file_paths[idx].filename() << ")"
								  << std::flush;
					}
				}
			} catch (const std::exception &e) {
				std::lock_guard lock(cout_mutex);
				std::cerr << "\n[Warning] 生成EFG异常 " << file_paths[idx] << ": " << e.what() << std::endl;
			} catch (...) {
				std::lock_guard lock(cout_mutex);
				std::cerr << "\n[Warning] 生成EFG未知异常 " << file_paths[idx] << std::endl;
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

	std::cout << "\n[Info] 有效EFG数量: " << dataset.size() << std::endl;
	return dataset;
}

/**
 * @brief 将EFG数据集与文件路径绑定为TrainSample列表
 * @note 调用方必须保证 dataset 与 paths 长度一致
 */
std::vector<starlight_v3::TrainSample> make_samples(const std::vector<starlight_v3::EFG> &dataset, const std::vector<fs::path> &paths) {
	std::vector<starlight_v3::TrainSample> samples;
	samples.reserve(dataset.size());
	for (size_t i = 0; i < dataset.size(); ++i) {
		starlight_v3::TrainSample sample;
		sample.efg = dataset[i];
		sample.file_path = paths[i].string();
		samples.push_back(std::move(sample));
	}
	return samples;
}

/**
 * @brief 加载模型并返回, 失败返回false
 */
bool load_model(const std::string &model_path, starlight_v3::Model &model) {
	try {
		model = starlight_v3::Model::load_from_file(model_path);
	} catch (const std::exception &e) {
		std::cerr << "[Error] 模型加载失败: " << e.what() << std::endl;
		return false;
	}
	std::cout << "[Info] 模型加载完成: tspm节点=" << model.tspm_model().nodes.size()
			  << ", lgbm模型=" << model.lgbm_model().model_string.size() << "字节" << std::endl;
	return true;
}

/**
 * @brief 训练模式: 交叉训练生成特征 -> LightGBM训练 -> 最终tosSPM全量训练 -> 保存模型
 * @return 0成功, 非0失败
 */
int run_train(const std::string &malware_folder, const std::string &benign_folder, const std::string &model_path, size_t max_train_samples) {
	// 1. 加载训练数据集(同时收集源文件路径, 用于PE特征提取)
	std::cout << "[Info] 正在加载恶意样本数据集..." << std::endl;
	std::vector<fs::path> malware_paths, benign_paths;
	std::vector<starlight_v3::EFG> malware_dataset = load_dataset(malware_folder, max_train_samples, 0, {}, &malware_paths);

	std::cout << "\n[Info] 正在加载良性样本数据集..." << std::endl;
	std::vector<starlight_v3::EFG> benign_dataset = load_dataset(benign_folder, max_train_samples, 0, {}, &benign_paths);

	// 检查数据集是否为空
	if (malware_dataset.empty() || benign_dataset.empty()) {
		std::cerr << "\n[Error] 数据集为空, 请检查文件夹路径后重试。" << std::endl;
		return -1;
	}

	// 2. 绑定样本(EFG + 文件路径)
	std::vector<starlight_v3::TrainSample> malware_samples = make_samples(malware_dataset, malware_paths);
	std::vector<starlight_v3::TrainSample> benign_samples = make_samples(benign_dataset, benign_paths);

	// 3. 配置训练参数
	starlight_v3::TrainConfig config;

	// tosSPM训练参数(字段说明见include/tspm/trainer.h的TrainingConfig)
	config.tspm_config.preprune_factor = 10000000000.0;
	config.tspm_config.max_root_support = 1.0;
	config.tspm_config.max_expan_ratio = 1.8;
	config.tspm_config.thread_count = 0;
	config.tspm_config.min_support = 0.002; // 病毒最小支持度
	config.tspm_config.max_skip = 2; // 允许跳过1个混淆API
	config.tspm_config.max_length = 5; // 调用链最大长度
	config.tspm_config.max_depth = 5; // 最大递归深度
	config.tspm_config.min_distinction = 0.64; // 最小区分度

	// LightGBM训练参数(字段说明见include/lgbm/trainer.h的LGBMConfig)
	config.lgbm_config.num_iterations = 200; // 最大训练轮数
	config.lgbm_config.learning_rate = 0.05; // 学习率
	config.lgbm_config.num_leaves = 63; // 叶子节点数
	config.lgbm_config.min_data_in_leaf = 20; // 叶子最小样本数
	config.lgbm_config.feature_fraction = 0.9; // 特征采样比例
	config.lgbm_config.bagging_fraction = 0.9; // 样本采样比例
	config.lgbm_config.bagging_freq = 1; // bagging频率
	config.lgbm_config.lambda_l2 = 1.0; // L2正则
	config.lgbm_config.validation_ratio = 0.2; // 验证集比例
	config.lgbm_config.early_stopping_rounds = 20; // 早停轮数
	config.lgbm_config.random_seed = 42; // 随机种子
	config.lgbm_config.thread_count = 0; // LightGBM线程数

	// 交叉训练配置
	config.cross_validation_k = 2; // 交叉训练折数
	config.random_seed = 42; // 折划分随机种子
	config.thread_count = 0; // 特征生成并行线程数

	// 4. 日志回调函数
	auto logger = [](const std::string &msg) {
		std::cout << "\r\033[2K" << msg << std::flush;
	};
	config.log_callback = logger;

	// 5. 执行完整训练流程
	std::cout << "\n[Info] 开始训练..." << std::endl;
	starlight_v3::Trainer trainer;
	starlight_v3::Model model = trainer.train(config, malware_samples, benign_samples);

	std::cout << "\n[Info] 训练完成, 正在保存模型..." << std::endl;
	try {
		model.save_to_file(model_path);
	} catch (const std::exception &e) {
		std::cerr << "[Error] 模型保存失败: " << e.what() << std::endl;
		return -1;
	}
	std::cout << "[Info] 模型已保存至: " << model_path << std::endl;

	// 6. 重新加载模型验证(模型文件已保存, 独立于训练过程)
	std::cout << "[Info] 正在重新加载模型以验证..." << std::endl;
	starlight_v3::Model loaded_model;
	if (!load_model(model_path, loaded_model)) {
		return -1;
	}
	return 0;
}

/**
 * @brief 打印推理结果单行
 */
void print_infer_result(const fs::path &path, const starlight_v3::AnalysisResult &result) {
	std::cout << (result.final_score > kMalwareThreshold ? "[MALWARE] " : "[BENIGN ] ")
			  << path.string()
			  << " score=" << result.final_score
			  << " (malscore=" << result.tspm_result.malware_score
			  << ", benscore=" << result.tspm_result.benign_score
			  << ")" << std::endl;
}

/**
 * @brief 跑分模式: 从指定路径加载模型, 对黑白数据集分别打分并输出统计
 * @return 0成功, 非0失败
 */
int run_score(const std::string &model_path, const std::string &malware_folder, const std::string &benign_folder, size_t max_score_samples) {
	// 1. 加载模型
	std::cout << "[Info] 正在加载模型..." << std::endl;
	starlight_v3::Model model;
	if (!load_model(model_path, model)) {
		return -1;
	}

	// 2. 加载打分数据集(注意: 训练会清空数据集api_table, 打分必须重新加载)
	std::cout << "\n[Info] 正在加载恶意样本数据集..." << std::endl;
	std::vector<fs::path> malware_paths;
	std::vector<starlight_v3::EFG> malware_dataset = load_dataset(malware_folder, max_score_samples, 0, {}, &malware_paths);

	std::cout << "\n[Info] 正在加载良性样本数据集..." << std::endl;
	std::vector<fs::path> benign_paths;
	std::vector<starlight_v3::EFG> benign_dataset = load_dataset(benign_folder, max_score_samples, 0, {}, &benign_paths);

	if (malware_dataset.empty() && benign_dataset.empty()) {
		std::cerr << "\n[Error] 两个数据集均为空, 请检查文件夹路径后重试。" << std::endl;
		return -1;
	}

	// 3. 打分并统计
	starlight_v3::Reasoner reasoner(model);

	// 对单个数据集打分并输出每样本一行, 返回[平均分, 判恶意数, 总样本数]
	auto score_dataset = [&](const std::vector<starlight_v3::EFG> &dataset, const std::vector<fs::path> &paths, const std::string &label) {
		if (dataset.empty()) {
			std::cout << "(" << label << " 数据集为空)" << std::endl;
			return std::make_tuple(0.0, (size_t)0, (size_t)0);
		}
		double score_sum = 0.0;
		size_t predicted_malware = 0;
		size_t failed_count = 0;
		for (size_t i = 0; i < dataset.size(); ++i) {
			try {
				starlight_v3::AnalysisResult result = reasoner.analyze_efg(dataset[i], paths[i].string());
				if (result.final_score > kMalwareThreshold) {
					++predicted_malware;
				}
				score_sum += result.final_score;
				std::cout << label << " " << paths[i].filename().string()
						  << " score=" << result.final_score
						  << " (malscore=" << result.tspm_result.malware_score
						  << ", benscore=" << result.tspm_result.benign_score
						  << ", efg_nodes=" << dataset[i].nodes_.size() << ")" << std::endl;
			} catch (const std::exception &e) {
				++failed_count;
				std::cerr << "[Warning] 样本推理异常 " << paths[i] << ": " << e.what() << std::endl;
			}
		}
		if (failed_count > 0) {
			std::cout << "[Info] " << label << " 有 " << failed_count << " 个样本推理失败" << std::endl;
		}
		return std::make_tuple(score_sum, predicted_malware, dataset.size() - failed_count);
	};

	std::cout << "\n[Info] 正在对恶意样本数据集打分..." << std::endl;
	auto [mal_sum, mal_predicted, mal_total] = score_dataset(malware_dataset, malware_paths, "malware");
	std::cout << "\n[Info] 正在对良性样本数据集打分..." << std::endl;
	auto [ben_sum, ben_predicted, ben_total] = score_dataset(benign_dataset, benign_paths, "benign");

	// 4. 汇总统计
	std::cout << "\n[Info] 跑分汇总:" << std::endl;
	if (mal_total > 0) {
		double mal_avg = mal_sum / static_cast<double>(mal_total);
		double mal_acc = static_cast<double>(mal_predicted) / static_cast<double>(mal_total);
		std::cout << "恶意样本: 平均分=" << mal_avg << ", 判为恶意=" << mal_predicted
				  << "/" << mal_total << " (准确率=" << mal_acc << ")" << std::endl;
	}
	if (ben_total > 0) {
		double ben_avg = ben_sum / static_cast<double>(ben_total);
		double ben_acc = 1.0 - static_cast<double>(ben_predicted) / static_cast<double>(ben_total);
		std::cout << "良性样本: 平均分=" << ben_avg << ", 判为良性=" << (ben_total - ben_predicted)
				  << "/" << ben_total << " (准确率=" << ben_acc << ")" << std::endl;
	}
	return 0;
}

/**
 * @brief 推理模式: 对单个PE文件进行推理判定
 * @return 0成功(含判定为良性), 1推理失败, 非0错误
 */
int infer_single_file(starlight_v3::Reasoner &reasoner, const fs::path &file_path) {
	if (!fs::exists(file_path)) {
		std::cerr << "[Error] 文件不存在: " << file_path << std::endl;
		return 1;
	}
	if (!fs::is_regular_file(file_path)) {
		std::cerr << "[Error] 不是普通文件: " << file_path << std::endl;
		return 1;
	}

	try {
		starlight_v3::AnalysisResult result = reasoner.analyze_file(file_path.string());
		print_infer_result(file_path, result);
		return 0;
	} catch (const std::exception &e) {
		std::cerr << "[Error] 推理失败 " << file_path << ": " << e.what() << std::endl;
		return 1;
	}
}

/**
 * @brief 推理模式: 对文件夹内所有PE文件递归推理判定
 * @return 0成功, 非0失败
 */
int infer_folder(starlight_v3::Reasoner &reasoner, const fs::path &folder_path, size_t max_samples) {
	std::vector<fs::path> file_paths;
	try {
		for (auto &entry : fs::recursive_directory_iterator(folder_path, fs::directory_options::skip_permission_denied)) {
			if (file_paths.size() >= max_samples)
				break;
			if (!entry.is_regular_file())
				continue;
			// 不预设扩展名过滤: 交予generate_efg自行判断是否为PE, 非PE文件推理失败计入failed
			file_paths.push_back(entry.path());
		}
	} catch (const fs::filesystem_error &e) {
		std::cerr << "[Warning] 目录遍历错误: " << e.what() << std::endl;
	}

	if (file_paths.empty()) {
		std::cerr << "[Error] 文件夹内未找到可执行文件: " << folder_path << std::endl;
		return -1;
	}

	size_t malware_count = 0;
	size_t benign_count = 0;
	size_t failed_count = 0;
	std::cout << "[Info] 正在推理 " << file_paths.size() << " 个文件..." << std::endl;
	for (const fs::path &p : file_paths) {
		try {
			starlight_v3::AnalysisResult result = reasoner.analyze_file(p.string());
			print_infer_result(p, result);
			if (result.final_score > kMalwareThreshold) {
				++malware_count;
			} else {
				++benign_count;
			}
		} catch (const std::exception &e) {
			++failed_count;
			std::cerr << "[Error] 推理失败 " << p << ": " << e.what() << std::endl;
		}
	}

	// 汇总
	std::cout << "\n[Info] 推理汇总:" << std::endl;
	std::cout << "总数: " << file_paths.size()
			  << ", 恶意: " << malware_count
			  << ", 良性: " << benign_count
			  << ", 失败: " << failed_count << std::endl;
	return 0;
}

// 打印命令行用法
void print_usage(const char *program_name) {
	std::cout << "CSafe Starlight V3 " << kVersion << " - 杀毒引擎官方训练/跑分/推理工具" << std::endl;
	std::cout << std::endl;
	std::cout << "Usage:" << std::endl;
	std::cout << "  " << program_name << " train <malware_dir> <benign_dir> <model_path> [max_train_samples]" << std::endl;
	std::cout << "  " << program_name << " score <model_path> <malware_dir> <benign_dir> [max_score_samples]" << std::endl;
	std::cout << "  " << program_name << " infer <model_path> <target> [max_samples]" << std::endl;
	std::cout << std::endl;
	std::cout << "Subcommands:" << std::endl;
	std::cout << "  train   训练模型: 交叉训练生成特征 -> LightGBM -> 最终tosSPM全量训练, 保存到model_path" << std::endl;
	std::cout << "  score   跑分: 对黑白样本文件夹分别打分, 输出平均分与判定准确率(用于模型评估)" << std::endl;
	std::cout << "  infer   推理判定: 对单个PE文件或文件夹(递归)执行恶意/良性判定" << std::endl;
	std::cout << std::endl;
	std::cout << "  --version  输出版本信息" << std::endl;
	std::cout << "  -h, --help 显示本帮助" << std::endl;
}

} // namespace

int main(int argc, char *argv[]) {
	if (argc < 2) {
		print_usage(argv[0]);
		return -1;
	}

	std::string mode = argv[1];
	if (mode == "--version") {
		std::cout << "CSafe Starlight V3 " << kVersion << std::endl;
		return 0;
	}
	if (mode == "-h" || mode == "--help") {
		print_usage(argv[0]);
		return 0;
	}

	if (mode == "train") {
		if (argc < 5) {
			std::cerr << "[Error] train 需要参数: <malware_dir> <benign_dir> <model_path>" << std::endl;
			print_usage(argv[0]);
			return -1;
		}
		size_t max_train_samples = parse_size_arg(argc >= 6 ? argv[5] : nullptr, 1000, "max_train_samples");
		return run_train(argv[2], argv[3], argv[4], max_train_samples);
	}

	if (mode == "score") {
		if (argc < 5) {
			std::cerr << "[Error] score 需要参数: <model_path> <malware_dir> <benign_dir>" << std::endl;
			print_usage(argv[0]);
			return -1;
		}
		size_t max_score_samples = parse_size_arg(argc >= 6 ? argv[5] : nullptr, 200, "max_score_samples");
		return run_score(argv[2], argv[3], argv[4], max_score_samples);
	}

	if (mode == "infer") {
		if (argc < 4) {
			std::cerr << "[Error] infer 需要参数: <model_path> <target>" << std::endl;
			print_usage(argv[0]);
			return -1;
		}
		size_t max_samples = parse_size_arg(argc >= 5 ? argv[4] : nullptr, 200, "max_samples");

		// 加载模型
		std::cout << "[Info] 正在加载模型..." << std::endl;
		starlight_v3::Model model;
		if (!load_model(argv[2], model)) {
			return -1;
		}
		starlight_v3::Reasoner reasoner(model);

		// 判断目标是文件还是文件夹
		fs::path target(argv[3]);
		if (!fs::exists(target)) {
			std::cerr << "[Error] 目标不存在: " << target << std::endl;
			return -1;
		}
		if (fs::is_directory(target)) {
			return infer_folder(reasoner, target, max_samples);
		}
		return infer_single_file(reasoner, target);
	}

	std::cerr << "[Error] 未知子命令: " << mode << std::endl;
	print_usage(argv[0]);
	return -1;
}
