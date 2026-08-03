/**
 * @file trainer.cpp
 * @brief 最终训练器实现(交叉训练编排)
 * @author ternaryop8479
 * @date 2026-08-03
 */

#include "trainer.h"
#include "external/BS_thread_pool.hpp"
#include "lgbm/feat_extractor/efg.h"
#include "lgbm/feat_extractor/pe.h"
#include "lgbm/feat_extractor/tspm.h"
#include "lgbm/feat_vector.h"
#include "tspm/reasoner.h"
#include <algorithm>
#include <atomic>
#include <numeric>
#include <random>
#include <thread>

namespace {

// 剔除数据集中的无边EFG, 返回被剔除的数量
// 无边EFG的特征是edges_为空(典型如.NET程序, 其EFG没有调用边, 会干扰tosSPM训练)
size_t drop_edgeless(std::vector<starlight_v3::EFG> &dataset) {
	size_t before = dataset.size();
	dataset.erase(std::remove_if(dataset.begin(), dataset.end(),
		[](const starlight_v3::EFG &efg) { return efg.edges_.empty(); }), dataset.end());
	return before - dataset.size();
}

/**
 * @brief 拷贝数据集后剔除无边EFG再执行tosSPM训练
 * @details 以值传递拷贝数据集, 因为train()训练完成后会清空数据集的api_table,
 * 拷贝可以保证调用方的原数据集不受影响. 无边EFG在每次训练前都被剔除, 防止干扰训练.
 * @param trainer tosSPM训练器
 * @param log_callback 日志回调, 用于输出剔除统计
 * @param malware 恶意样本的EFG拷贝
 * @param benign 良性样本的EFG拷贝
 * @return 训练完成的tosSPM模型
 */
starlight_v3::tspm::Model train_tspm_filtered(starlight_v3::tspm::Trainer &trainer, const std::function<void(const std::string &)> &log_callback, std::vector<starlight_v3::EFG> malware, std::vector<starlight_v3::EFG> benign) {
	// 剔除无边EFG
	size_t dropped_mal = drop_edgeless(malware);
	size_t dropped_ben = drop_edgeless(benign);
	if (log_callback) {
		log_callback("[train_tspm_filtered] 剔除无边EFG: 恶意" + std::to_string(dropped_mal) + "个, 良性" + std::to_string(dropped_ben) + "个\n");
	}

	// 剔除后数据集不能为空
	if (malware.empty() || benign.empty()) {
		throw std::runtime_error("train_tspm_filtered(): 剔除无边EFG后训练集为空(恶意" + std::to_string(malware.size()) + "个, 良性" + std::to_string(benign.size()) + "个)");
	}

	return trainer.train(malware, benign);
}

/**
 * @brief 将[0, total)的下标洗牌后均分为k折
 * @param total 样本总数
 * @param k 折数
 * @param rng 随机数生成器
 * @return k个下标集合, 余数分配到前几折
 */
std::vector<std::vector<size_t>> split_folds(size_t total, starlight_v3::SIZE_T k, std::mt19937 &rng) {
	std::vector<size_t> indices(total);
	std::iota(indices.begin(), indices.end(), 0);
	std::shuffle(indices.begin(), indices.end(), rng);

	std::vector<std::vector<size_t>> folds(static_cast<size_t>(k));
	for (size_t i = 0; i < total; ++i) {
		folds[i % static_cast<size_t>(k)].push_back(indices[i]);
	}
	return folds;
}

} // namespace

namespace starlight_v3 {

// 执行完整训练流程
Model Trainer::train(const TrainConfig &config, const std::vector<TrainSample> &malware_samples, const std::vector<TrainSample> &benign_samples) {
	// 参数校验
	if (config.cross_validation_k < 2) {
		throw std::invalid_argument("Trainer::train(): cross_validation_k必须不小于2");
	}
	if (malware_samples.empty() || benign_samples.empty()) {
		throw std::invalid_argument("Trainer::train(): 黑白数据集均不能为空");
	}

	// 日志回调缺省为空回调, 避免匿名命名空间函数中判空
	std::function<void(const std::string &)> log_callback = config.log_callback ? config.log_callback : [](const std::string &) {};

	// 1. 黑白数据集各自独立划分k折
	std::mt19937 rng(config.random_seed);
	std::vector<std::vector<size_t>> mal_folds = split_folds(malware_samples.size(), config.cross_validation_k, rng);
	std::vector<std::vector<size_t>> ben_folds = split_folds(benign_samples.size(), config.cross_validation_k, rng);

	// 2. 分配特征矩阵与标签(行序: 先恶意样本再良性样本, 标签恶意=1良性=0)
	const size_t mal_count = malware_samples.size();
	const size_t total_samples = mal_count + benign_samples.size();
	std::vector<double> feature_matrix(total_samples * lgbm::kTotalFeatDims);
	std::vector<float> labels(total_samples);
	for (size_t i = 0; i < mal_count; ++i) {
		labels[i] = 1.0f;
	}
	for (size_t i = 0; i < benign_samples.size(); ++i) {
		labels[mal_count + i] = 0.0f;
	}

	// 3. 交叉训练: 每折用其余折训练tosSPM模型并对当前折推理生成特征
	BS::thread_pool thread_pool(config.thread_count ? config.thread_count : std::thread::hardware_concurrency());
	std::atomic<size_t> feature_fail_count { 0 }; // 特征生成失败的样本数(线程池任务异常被吞时上报, 防止静默丢失)
	for (SIZE_T fold = 0; fold < config.cross_validation_k; ++fold) {
		// 3a. 合并训练折的EFG(深拷贝, train()会清空api_table, 不能影响原样本)
		std::vector<EFG> train_mal, train_ben;
		for (SIZE_T other_fold = 0; other_fold < config.cross_validation_k; ++other_fold) {
			if (other_fold == fold) {
				continue;
			}
			for (size_t idx : mal_folds[static_cast<size_t>(other_fold)]) {
				train_mal.push_back(malware_samples[idx].efg);
			}
			for (size_t idx : ben_folds[static_cast<size_t>(other_fold)]) {
				train_ben.push_back(benign_samples[idx].efg);
			}
		}

		// 3b. 训练本折的tosSPM模型(拷贝+剔除无边EFG)
		log_callback("[Trainer::train()] 交叉训练第" + std::to_string(fold + 1) + "/" + std::to_string(config.cross_validation_k) + "折\n");
		tspm::Trainer tspm_trainer(config.tspm_config, log_callback);
		tspm::Model tspm_model = train_tspm_filtered(tspm_trainer, log_callback, std::move(train_mal), std::move(train_ben));

		// 3c. 用本折模型对测试折样本并行推理, 生成特征向量写入特征矩阵
		// 注意: 测试折不剔除无边EFG, 对无边EFG正常推理, 供LightGBM学习无边样本的形态
		log_callback("[Trainer::train()] 推理第" + std::to_string(fold + 1) + "折特征(恶意" + std::to_string(mal_folds[static_cast<size_t>(fold)].size()) + "个, 良性" + std::to_string(ben_folds[static_cast<size_t>(fold)].size()) + "个)\n");
		for (size_t idx : mal_folds[static_cast<size_t>(fold)]) {
			thread_pool.detach_task([&, idx] {
				const TrainSample &sample = malware_samples[idx];
				// 每个任务独立构造Reasoner(无共享状态, 线程安全)
				try {
					tspm::Reasoner reasoner(tspm_model);
					tspm::AnalysisResult result = reasoner.analyze_efg(sample.efg, true);

					// 提取三组特征并序列化
					FeatPack feats;
					feats.efg_feats = lgbm::extract_efg_feats(sample.efg);
					feats.tspm_feats = lgbm::extract_tspm_feats(result, sample.efg);
					feats.pe_feats = lgbm::extract_pe_feats(sample.file_path);
					lgbm::serialize_feat_pack(feats, feature_matrix.data() + idx * lgbm::kTotalFeatDims);
				} catch (const std::exception &e) {
					// 线程池会吞掉任务异常, 这里显式上报防止该样本特征静默全零进入训练
					++feature_fail_count;
					log_callback("[Trainer::train()] 恶意样本特征生成失败(行" + std::to_string(idx) + ", 特征将保持全零): " + sample.file_path + " -> " + e.what() + "\n");
				} catch (...) {
					++feature_fail_count;
					log_callback("[Trainer::train()] 恶意样本特征生成失败(行" + std::to_string(idx) + ", 特征将保持全零): " + sample.file_path + " -> 未知异常\n");
				}
			});
		}
		for (size_t idx : ben_folds[static_cast<size_t>(fold)]) {
			thread_pool.detach_task([&, idx] {
				const TrainSample &sample = benign_samples[idx];
				try {
					tspm::Reasoner reasoner(tspm_model);
					tspm::AnalysisResult result = reasoner.analyze_efg(sample.efg, true);

					FeatPack feats;
					feats.efg_feats = lgbm::extract_efg_feats(sample.efg);
					feats.tspm_feats = lgbm::extract_tspm_feats(result, sample.efg);
					feats.pe_feats = lgbm::extract_pe_feats(sample.file_path);
					lgbm::serialize_feat_pack(feats, feature_matrix.data() + (mal_count + idx) * lgbm::kTotalFeatDims);
				} catch (const std::exception &e) {
					++feature_fail_count;
					log_callback("[Trainer::train()] 良性样本特征生成失败(行" + std::to_string(mal_count + idx) + ", 特征将保持全零): " + sample.file_path + " -> " + e.what() + "\n");
				} catch (...) {
					++feature_fail_count;
					log_callback("[Trainer::train()] 良性样本特征生成失败(行" + std::to_string(mal_count + idx) + ", 特征将保持全零): " + sample.file_path + " -> 未知异常\n");
				}
			});
		}
		thread_pool.wait();

		// 本折的tspm_model与reasoner在作用域结束时析构, 释放Trie树与证据树内存
	}

	// 4. 使用全部特征向量训练LightGBM模型
	if (feature_fail_count.load() > 0) {
		log_callback("[Trainer::train()] 警告: " + std::to_string(feature_fail_count.load()) + "个样本特征生成失败, 其特征保持全零\n");
	}
	log_callback("[Trainer::train()] 开始训练LightGBM模型(共" + std::to_string(total_samples) + "个样本, " + std::to_string(lgbm::kTotalFeatDims) + "维特征)\n");
	lgbm::Trainer lgbm_trainer;
	lgbm::Model lgbm_model = lgbm_trainer.train(feature_matrix.data(), static_cast<int32_t>(total_samples), static_cast<int32_t>(lgbm::kTotalFeatDims), labels.data(), config.lgbm_config);

	// 5. 使用全量数据训练最终tosSPM模型(同样剔除无边EFG)
	log_callback("[Trainer::train()] 开始全量训练最终tosSPM模型\n");
	std::vector<EFG> all_mal, all_ben;
	all_mal.reserve(mal_count);
	all_ben.reserve(benign_samples.size());
	for (const TrainSample &sample : malware_samples) {
		all_mal.push_back(sample.efg);
	}
	for (const TrainSample &sample : benign_samples) {
		all_ben.push_back(sample.efg);
	}
	tspm::Trainer final_tspm_trainer(config.tspm_config, log_callback);
	tspm::Model final_tspm_model = train_tspm_filtered(final_tspm_trainer, log_callback, std::move(all_mal), std::move(all_ben));

	// 6. 打包返回
	log_callback("[Trainer::train()] 训练完成\n");
	return Model(final_tspm_model, lgbm_model);
}

} // namespace starlight_v3
