/**
 * @file trainer.cpp
 * @brief 最终训练器实现(交叉训练编排)
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <algorithm>
#include <atomic>
#include <random>
#include <thread>

#ifdef __linux__ // glibc环境下使用malloc_trim(0)优化内存占用
#include <malloc.h>
#endif

#include "external/BS_thread_pool.hpp"

#include "lgbm/feat_extractor/efg.h"
#include "lgbm/feat_extractor/pe.h"
#include "lgbm/feat_extractor/tspm.h"
#include "lgbm/feat_vector.h"
#include "trainer.h"
#include "tspm/reasoner.h"

namespace {

// 剔除数据集中的无边EFG, 返回被剔除的数量
// 无边EFG的特征是edges_为空(典型如.NET程序, 其EFG没有调用边, 会干扰tosSPM训练)
size_t drop_edgeless(std::vector<starlight_v3::EFG> &dataset) {
	size_t before = dataset.size();
	dataset.erase(std::remove_if(dataset.begin(), dataset.end(),
					  [](const starlight_v3::EFG &efg) {
						  return efg.edges_.empty();
					  }),
		dataset.end());
	return before - dataset.size();
}

// 以值传递拷贝数据集后剔除无边EFG并执行tosSPM训练(train()训练完成后会清空数据集，因此需要拷贝数据集而不是引用)
starlight_v3::tspm::Model train_tspm_filtered(starlight_v3::tspm::Trainer &trainer, const std::function<void(const std::string &)> &log_callback, std::vector<starlight_v3::EFG> malware, std::vector<starlight_v3::EFG> benign) {
	// 剔除无边EFG
	size_t dropped_mal = drop_edgeless(malware);
	size_t dropped_ben = drop_edgeless(benign);
	if (log_callback) {
		log_callback("[train_tspm_filtered] Dropped edgeless EFGs: " + std::to_string(dropped_mal) + " malware, " + std::to_string(dropped_ben) + " benign\n");
	}

	// 剔除后数据集不能为空
	if (malware.empty() || benign.empty()) {
		throw std::runtime_error("train_tspm_filtered(): training set empty after dropping edgeless EFGs (" + std::to_string(malware.size()) + " malware, " + std::to_string(benign.size()) + " benign)");
	}

	return trainer.train(malware, benign);
}

// 将[0, total)的下标按"edgeless/普通"分层洗牌后均分为k折，确保每折交叉训练的时候样本分布均匀
std::vector<std::vector<size_t>> split_folds(size_t total, starlight_v3::SIZE_T k, std::mt19937 &rng, const std::vector<starlight_v3::TrainSample> &samples) {
	std::vector<size_t> edgeless_idx, normal_idx;
	edgeless_idx.reserve(total);
	normal_idx.reserve(total);
	for (size_t i = 0; i < total; ++i) {
		if (samples[i].efg.edges_.empty()) {
			edgeless_idx.push_back(i);
		} else {
			normal_idx.push_back(i);
		}
	}
	std::shuffle(edgeless_idx.begin(), edgeless_idx.end(), rng);
	std::shuffle(normal_idx.begin(), normal_idx.end(), rng);

	// 按比例交替合并: 以较小组为节奏, 均匀穿插两组下标, 使整体序列两类交错分布
	std::vector<size_t> indices;
	indices.reserve(total);
	const size_t edgeless_n = edgeless_idx.size();
	const size_t normal_n = normal_idx.size();
	const size_t max_n = std::max(edgeless_n, normal_n);
	for (size_t i = 0; i < max_n; ++i) {
		if (i < edgeless_n)
			indices.push_back(edgeless_idx[i]);
		if (i < normal_n)
			indices.push_back(normal_idx[i]);
	}

	std::vector<std::vector<size_t>> folds(static_cast<size_t>(k));
	// 按连续分块分配折: 穿插序列本身已按edgeless/普通交错, 每折拿到一段连续区间即可保证两类比例均衡;
	// 若按i%k隔位分配, 当k=2时偶数位全是edgeless、奇数位全是普通, 训练折会被整折剔除导致崩溃
	const size_t kk = static_cast<size_t>(k);
	for (size_t i = 0; i < total; ++i) {
		folds[std::min(i * kk / total, kk - 1)].push_back(indices[i]);
	}
	return folds;
}

} // namespace

namespace starlight_v3 {

// 执行完整训练流程
Model Trainer::train(const TrainConfig &config, const std::vector<TrainSample> &malware_samples, const std::vector<TrainSample> &benign_samples) {
	// 参数校验
	if (config.cross_validation_k < 2) {
		throw std::invalid_argument("Trainer::train(): cross_validation_k must be at least 2");
	}
	if (malware_samples.empty() || benign_samples.empty()) {
		throw std::invalid_argument("Trainer::train(): both malware and benign datasets must be non-empty");
	}

	// 日志回调缺省为空回调, 避免匿名命名空间函数中判空
	std::function<void(const std::string &)> log_callback = config.log_callback ? config.log_callback : [](const std::string &) {
	};

	// 黑白数据集各自独立划分k折(按edgeless/普通分层打乱, 保证每折两类比例均匀)
	std::mt19937 rng(config.random_seed);
	std::vector<std::vector<size_t>> mal_folds = split_folds(malware_samples.size(), config.cross_validation_k, rng, malware_samples);
	std::vector<std::vector<size_t>> ben_folds = split_folds(benign_samples.size(), config.cross_validation_k, rng, benign_samples);

	// 分配特征矩阵与标签(行序: 先恶意样本再良性样本, 标签恶意=1良性=0)
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

	// 交叉训练: 每折用其余折训练tosSPM模型并对当前折推理生成特征
	BS::thread_pool thread_pool(config.thread_count ? config.thread_count : std::thread::hardware_concurrency());
	std::atomic<size_t> feature_fail_count { 0 }; // 特征生成失败的样本数(线程池任务异常被吞时上报, 防止静默丢失)
	for (SIZE_T fold = 0; fold < config.cross_validation_k; ++fold) {
		// 合并训练折的EFG(深拷贝, train()会清空api_table, 不能影响原样本)
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

		// 训练本折的tosSPM模型(拷贝+剔除无边EFG)
		log_callback("[Trainer::train()] Cross-validation fold " + std::to_string(fold + 1) + "/" + std::to_string(config.cross_validation_k) + "\n");
		tspm::Trainer tspm_trainer(config.tspm_config, log_callback);
		tspm::Model tspm_model = train_tspm_filtered(tspm_trainer, log_callback, std::move(train_mal), std::move(train_ben));

		// 用本折模型对测试折样本并行推理, 生成特征向量写入特征矩阵
		// 注意: 测试折不剔除无边EFG, 对无边EFG正常推理, 供LightGBM学习无边样本的形态
		log_callback("[Trainer::train()] Inferring fold " + std::to_string(fold + 1) + " features (" + std::to_string(mal_folds[static_cast<size_t>(fold)].size()) + " malware, " + std::to_string(ben_folds[static_cast<size_t>(fold)].size()) + " benign)\n");
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
					// 依旧好孩子要注意释放内存
					result.evidence_trees.clear();
					result.evidence_trees.shrink_to_fit();
					feats.pe_feats = lgbm::extract_pe_feats(sample.file_path);
					lgbm::serialize_feat_pack(feats, feature_matrix.data() + idx * lgbm::kTotalFeatDims);
				} catch (const std::exception &e) {
					// 线程池会吞掉任务异常, 这里显式上报防止该样本特征静默全零进入训练
					++feature_fail_count;
					log_callback("[Trainer::train()] Malware feature generation failed (row " + std::to_string(idx) + ", features will stay zero): " + sample.file_path + " -> " + e.what() + "\n");
				} catch (...) {
					++feature_fail_count;
					log_callback("[Trainer::train()] Malware feature generation failed (row " + std::to_string(idx) + ", features will stay zero): " + sample.file_path + " -> unknown exception\n");
				}
#ifdef __linux__
				malloc_trim(0); // 归还碎片堆内存
#endif
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
					// 释放内存
					result.evidence_trees.clear();
					result.evidence_trees.shrink_to_fit();
					feats.pe_feats = lgbm::extract_pe_feats(sample.file_path);
					lgbm::serialize_feat_pack(feats, feature_matrix.data() + (mal_count + idx) * lgbm::kTotalFeatDims);
				} catch (const std::exception &e) {
					++feature_fail_count;
					log_callback("[Trainer::train()] Benign feature generation failed (row " + std::to_string(mal_count + idx) + ", features will stay zero): " + sample.file_path + " -> " + e.what() + "\n");
				} catch (...) {
					++feature_fail_count;
					log_callback("[Trainer::train()] Benign feature generation failed (row " + std::to_string(mal_count + idx) + ", features will stay zero): " + sample.file_path + " -> unknown exception\n");
				}
#ifdef __linux__
				malloc_trim(0); // 归还碎片堆内存
#endif
			});
		}
		thread_pool.wait();

#ifdef __linux__
		malloc_trim(0); // 归还碎片堆内存
#endif
	}

	// 使用全部特征向量训练LightGBM模型
	if (feature_fail_count.load() > 0) {
		log_callback("[Trainer::train()] WARNING: " + std::to_string(feature_fail_count.load()) + " samples failed feature generation, their features stay zero\n");
	}

#ifdef __linux__
	malloc_trim(0); // 归还碎片堆内存
#endif

	log_callback("[Trainer::train()] Starting LightGBM training (" + std::to_string(total_samples) + " samples, " + std::to_string(lgbm::kTotalFeatDims) + " features)\n");
	lgbm::Trainer lgbm_trainer;
	lgbm::Model lgbm_model = lgbm_trainer.train(feature_matrix.data(), static_cast<int32_t>(total_samples), static_cast<int32_t>(lgbm::kTotalFeatDims), labels.data(), config.lgbm_config);

	// 使用全量数据训练最终tosSPM模型(同样剔除无边EFG)
	log_callback("[Trainer::train()] Starting full-data final tosSPM training\n");
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

	// 归还碎片堆内存
#ifdef __linux__
	malloc_trim(0);
#endif

	// 打包返回
	log_callback("[Trainer::train()] Training complete\n");
	return Model(final_tspm_model, lgbm_model);
}

} // namespace starlight_v3
