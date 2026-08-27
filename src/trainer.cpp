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
#include "lgbm/feat_extractor/static_feats.h"
#include "authenticode/reasoner.h"
#include "authenticode/trainer.h"
#include "lgbm/feat_extractor/tspm.h"
#include "lgbm/feat_vector.h"
#include "efg_generator.h"
#include "pe/authenticode.h"
#include "pe/view.h"
#include "trainer.h"
#include "tspm/reasoner.h"

namespace {

// 提取单个PE文件的签名者身份(供签名扫描阶段并行调用)
starlight_v3::pe::CertIdentity scan_one_signature(const starlight_v3::TrainSample &sample) {
	// 命中预取则零I/O
	if (sample.cert_identity.has_value()) {
		return *sample.cert_identity;
	}
	starlight_v3::pe::PeView view;
	if (!starlight_v3::pe::PeView::load(sample.file_path, view)) {
		return starlight_v3::pe::CertIdentity {}; // 非法PE: 返回present=false的空身份
	}
	return starlight_v3::pe::inspect_signature(view);
}

// 取一个样本的静态特征组: 命中预取则零I/O, 否则现场读盘提取
// 只覆盖静态特征组, 其余特征组(tspm/efg/sig)保持调用方已填的值
void load_static_feats(const starlight_v3::TrainSample &sample, starlight_v3::FeatPack &feats) {
	if (sample.static_feats.has_value()) {
		const starlight_v3::FeatPack &cache = *sample.static_feats;
		feats.pe_feats = cache.pe_feats;
		feats.block_entropy_feats = cache.block_entropy_feats;
		feats.rich_header_feats = cache.rich_header_feats;
		feats.dotnet_feats = cache.dotnet_feats;
		feats.iat_feats = cache.iat_feats;
		feats.capability_feats = cache.capability_feats;
		return;
	}

	// 未预取: 现场读入文件视图后提取(非法PE则静态特征保持全零)
	starlight_v3::pe::PeView view;
	if (starlight_v3::pe::PeView::load(sample.file_path, view)) {
		starlight_v3::lgbm::extract_static_feats(view, feats);
	}
}

// 剔除数据集中的无边EFG, 返回被剔除的数量
// 无边EFG的特征是edges_为空(典型如.NET程序, 其EFG没有调用边, 会干扰tosSPM训练)
size_t drop_edgeless(std::vector<starlight_v3::EFG> &dataset) {
	size_t before = dataset.size();
	dataset.erase(std::remove_if(dataset.begin(), dataset.end(), [](const starlight_v3::EFG &efg) {
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

	std::vector<std::vector<size_t>> folds(static_cast<size_t>(k));
	// 按类各自隔位轮转分配折: 每折拿到与整体等比例的edgeless/普通样本, 保证折间两类比例均衡;
	// 连续分块在edgeless占比高时会让前几折几乎全是edgeless、后几折几乎全是普通, 折间特征分布严重偏斜
	for (size_t i = 0; i < edgeless_idx.size(); ++i) {
		folds[i % static_cast<size_t>(k)].push_back(edgeless_idx[i]);
	}
	for (size_t i = 0; i < normal_idx.size(); ++i) {
		folds[i % static_cast<size_t>(k)].push_back(normal_idx[i]);
	}
	return folds;
}

} // namespace

namespace starlight_v3 {

// 从PE文件准备一个训练样本(单次读盘完成EFG、签名者身份与可选的静态特征预取)
bool prepare_train_sample(const std::string &file_path, bool prefetch_static_feats, TrainSample &out) {
	// 载入文件视图: 后续所有解析共用这一份字节
	pe::PeView view;
	if (!pe::PeView::load(file_path, view)) {
		return false;
	}

	// EFG生成失败(非PE/严重损坏)时整个样本作废
	auto [success, efg] = generate_efg(view);
	if (!success) {
		return false;
	}

	TrainSample sample;
	sample.efg = std::move(efg);
	sample.file_path = file_path;
	if (prefetch_static_feats) {
		// 静态特征提取顺带产出签名者身份, 无需额外解析
		FeatPack feats = {};
		sample.cert_identity = lgbm::extract_static_feats(view, feats);
		sample.static_feats = std::move(feats);
	} else {
		sample.cert_identity = pe::inspect_signature(view);
	}

	out = std::move(sample);
	return true;
}

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

	// 签名扫描: 收集全部样本的签名者身份, 聚合构建白签名表,
	// 同时缓存每样本的签名置信度(表构建后查表得到, 特征生成阶段直接取用)
	// 注: 白签名表为聚合身份声誉统计而非样本级预测目标, 故基于全量语料一次构建, 不融入交叉训练
	authenticode::Trainer sig_trainer(config.authenticode_config, log_callback);
	std::vector<starlight_v3::pe::CertIdentity> mal_identities(malware_samples.size());
	std::vector<starlight_v3::pe::CertIdentity> ben_identities(benign_samples.size());
	log_callback("[Trainer::train()] Scanning authenticode signatures (" + std::to_string(malware_samples.size() + benign_samples.size()) + " samples)\n");
	{
		std::atomic<size_t> scan_idx { 0 };
		auto scan_worker = [&]() {
			while (true) {
				const size_t i = scan_idx.fetch_add(1);
				if (i >= malware_samples.size() + benign_samples.size()) {
					break;
				}
				if (i < malware_samples.size()) {
					mal_identities[i] = scan_one_signature(malware_samples[i]);
					sig_trainer.ingest(mal_identities[i], true);
				} else {
					const size_t bi = i - malware_samples.size();
					ben_identities[bi] = scan_one_signature(benign_samples[bi]);
					sig_trainer.ingest(ben_identities[bi], false);
				}
			}
		};
		unsigned int hw = std::thread::hardware_concurrency();
		hw = hw ? hw : 4;
		hw = hw < static_cast<unsigned int>(malware_samples.size() + benign_samples.size())
			     ? hw
			     : static_cast<unsigned int>(malware_samples.size() + benign_samples.size());
		std::vector<std::thread> scan_threads;
		scan_threads.reserve(hw);
		for (unsigned int t = 0; t < hw; ++t) {
			scan_threads.emplace_back(scan_worker);
		}
		for (auto &t : scan_threads) {
			t.join();
		}
	}
	const authenticode::Model sig_model = sig_trainer.build();

	// 查表得到每样本的签名置信度(特征生成阶段直接取用)
	authenticode::Reasoner sig_reasoner(sig_model);
	std::vector<double> mal_sig_conf(malware_samples.size());
	std::vector<double> ben_sig_conf(benign_samples.size());
	for (size_t i = 0; i < mal_sig_conf.size(); ++i) {
		mal_sig_conf[i] = sig_reasoner.confidence(mal_identities[i]);
	}
	for (size_t i = 0; i < ben_sig_conf.size(); ++i) {
		ben_sig_conf[i] = sig_reasoner.confidence(ben_identities[i]);
	}

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
					FeatPack feats = {};
					feats.efg_feats = lgbm::extract_efg_feats(sample.efg);
					feats.tspm_feats = lgbm::extract_tspm_feats(result, sample.efg);
					// 依旧好孩子要注意释放内存
					result.evidence_trees.clear();
					result.evidence_trees.shrink_to_fit();
					load_static_feats(sample, feats);
					feats.sig_feats.sig_confidence = mal_sig_conf[idx];
					feats.sig_feats.signed_present = mal_identities[idx].present ? 1.0 : 0.0;
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

					FeatPack feats = {};
					feats.efg_feats = lgbm::extract_efg_feats(sample.efg);
					feats.tspm_feats = lgbm::extract_tspm_feats(result, sample.efg);
					// 释放内存
					result.evidence_trees.clear();
					result.evidence_trees.shrink_to_fit();
					load_static_feats(sample, feats);
					feats.sig_feats.sig_confidence = ben_sig_conf[idx];
					feats.sig_feats.signed_present = ben_identities[idx].present ? 1.0 : 0.0;
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
	Model result_model(final_tspm_model, lgbm_model);
	result_model.set_sig_table(sig_model);
	return result_model;
}

} // namespace starlight_v3
