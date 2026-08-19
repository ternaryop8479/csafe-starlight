/**
 * @file lgbm/trainer.cpp
 * @brief LightGBM模型训练器实现
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <algorithm>
#include <limits>
#include <random>
#include <string>
#include <vector>

#include "lgbm/detail/lgbm_handle.h"
#include "lgbm/trainer.h"

namespace {

// 根据配置拼接LightGBM参数串, 格式为"key1=value1 key2=value2 ..."
std::string build_lgbm_params(const starlight_v3::lgbm::LGBMConfig &config) {
	std::string params;
	params += "objective=binary ";
	params += "metric=binary_logloss ";
	params += "num_leaves=" + std::to_string(config.num_leaves) + " ";
	params += "learning_rate=" + std::to_string(config.learning_rate) + " ";
	params += "min_data_in_leaf=" + std::to_string(config.min_data_in_leaf) + " ";
	params += "feature_fraction=" + std::to_string(config.feature_fraction) + " ";
	params += "bagging_fraction=" + std::to_string(config.bagging_fraction) + " ";
	params += "bagging_freq=" + std::to_string(config.bagging_freq) + " ";
	params += "lambda_l2=" + std::to_string(config.lambda_l2) + " ";
	// 类别不平衡时自动按反类样本比例加权, 避免多数类主导损失函数
	if (config.is_unbalance) {
		params += "is_unbalance=true ";
	}
	// 特征矩阵为稠密行主序数据, 强制按行构建直方图以提升训练速度
	params += "force_row_wise=true ";
	if (config.thread_count > 0) {
		params += "num_threads=" + std::to_string(config.thread_count) + " ";
	}
	return params;
}

} // namespace

namespace starlight_v3::lgbm {

Model Trainer::train(const double *feature_matrix, int32_t nrows, int32_t ncols, const float *labels, const LGBMConfig &config) {
	if (feature_matrix == nullptr || labels == nullptr || nrows <= 0 || ncols <= 0) {
		throw std::invalid_argument("Trainer::train(): invalid argument (null feature_matrix/labels or non-positive rows/cols)");
	}

	// 按标签分层划分训练集与验证集(正类与负类各自独立洗牌后再按validation_ratio切分)
	std::vector<size_t> positive_indices, negative_indices; // 正类(标签=1)与负类(标签=0)的样本下标
	for (int32_t i = 0; i < nrows; ++i) {
		if (labels[i] > 0.5f) {
			positive_indices.push_back(static_cast<size_t>(i));
		} else {
			negative_indices.push_back(static_cast<size_t>(i));
		}
	}

	// 划分验证集
	std::vector<size_t> train_indices, valid_indices; // 训练集与验证集的样本下标
	const bool has_valid = config.validation_ratio > 0.0;
	if (has_valid) {
		std::mt19937 rng(config.random_seed);
		std::shuffle(positive_indices.begin(), positive_indices.end(), rng);
		std::shuffle(negative_indices.begin(), negative_indices.end(), rng);

		// 正负类各取validation_ratio比例作为验证集
		size_t positive_valid_count = static_cast<size_t>(positive_indices.size() * config.validation_ratio);
		size_t negative_valid_count = static_cast<size_t>(negative_indices.size() * config.validation_ratio);

		valid_indices.insert(valid_indices.end(), positive_indices.begin(), positive_indices.begin() + static_cast<long>(positive_valid_count));
		valid_indices.insert(valid_indices.end(), negative_indices.begin(), negative_indices.begin() + static_cast<long>(negative_valid_count));
		train_indices.insert(train_indices.end(), positive_indices.begin() + static_cast<long>(positive_valid_count), positive_indices.end());
		train_indices.insert(train_indices.end(), negative_indices.begin() + static_cast<long>(negative_valid_count), negative_indices.end());
	} else {
		// 不划分验证集则全部作为训练集
		train_indices = std::move(positive_indices);
		train_indices.insert(train_indices.end(), negative_indices.begin(), negative_indices.end());
	}

	// 拷贝出训练集与验证集的连续矩阵(便于一次性传给C API)
	const int32_t train_nrows = static_cast<int32_t>(train_indices.size());
	std::vector<double> train_matrix(static_cast<size_t>(train_nrows) * static_cast<size_t>(ncols));
	std::vector<float> train_labels(static_cast<size_t>(train_nrows));
	for (int32_t i = 0; i < train_nrows; ++i) {
		const double *src_row = feature_matrix + static_cast<size_t>(train_indices[static_cast<size_t>(i)]) * static_cast<size_t>(ncols);
		std::copy(src_row, src_row + ncols, train_matrix.data() + static_cast<size_t>(i) * static_cast<size_t>(ncols));
		train_labels[static_cast<size_t>(i)] = labels[train_indices[static_cast<size_t>(i)]];
	}

	// 创建训练集与验证集的LightGBM Dataset
	// 注意: 本版本LGBM_DatasetCreateFromMat的签名没有label参数, 标签必须通过LGBM_DatasetSetField单独设置
	// (且label仅支持C_API_DTYPE_FLOAT32, 见c_api.h中LGBM_DatasetSetField的说明)
	detail::DatasetHandleGuard train_dataset, valid_dataset;
	detail::check_lgbm_status(LGBM_DatasetCreateFromMat(train_matrix.data(), C_API_DTYPE_FLOAT64, train_nrows, ncols, 1, "max_bin=255 force_row_wise=true", nullptr, &train_dataset.handle));
	detail::check_lgbm_status(LGBM_DatasetSetField(train_dataset.handle, "label", train_labels.data(), train_nrows, C_API_DTYPE_FLOAT32));
	if (has_valid) {
		const int32_t valid_nrows = static_cast<int32_t>(valid_indices.size());
		std::vector<double> valid_matrix(static_cast<size_t>(valid_nrows) * static_cast<size_t>(ncols));
		std::vector<float> valid_labels(static_cast<size_t>(valid_nrows));
		for (int32_t i = 0; i < valid_nrows; ++i) {
			const double *src_row = feature_matrix + static_cast<size_t>(valid_indices[static_cast<size_t>(i)]) * static_cast<size_t>(ncols);
			std::copy(src_row, src_row + ncols, valid_matrix.data() + static_cast<size_t>(i) * static_cast<size_t>(ncols));
			valid_labels[static_cast<size_t>(i)] = labels[valid_indices[static_cast<size_t>(i)]];
		}
		// 验证集必须引用训练集构造(reference参数), 使两者共享同一套bin mapper,
		// 否则LGBM_BoosterAddValidData会因bin mapper不一致而失败
		detail::check_lgbm_status(LGBM_DatasetCreateFromMat(valid_matrix.data(), C_API_DTYPE_FLOAT64, valid_nrows, ncols, 1, "max_bin=255 force_row_wise=true", train_dataset.handle, &valid_dataset.handle));
		detail::check_lgbm_status(LGBM_DatasetSetField(valid_dataset.handle, "label", valid_labels.data(), valid_nrows, C_API_DTYPE_FLOAT32));
	}

	// 创建Booster并挂载验证集
	std::string params = build_lgbm_params(config);
	detail::BoosterHandleGuard booster;
	detail::check_lgbm_status(LGBM_BoosterCreate(train_dataset.handle, params.c_str(), &booster.handle));
	if (has_valid) {
		detail::check_lgbm_status(LGBM_BoosterAddValidData(booster.handle, valid_dataset.handle));
	}

	// 训练循环: 逐轮训练并监控验证集binary_logloss, 跟踪最佳迭代轮数实现早停
	const int max_iterations = static_cast<int>(config.num_iterations);
	const bool enable_early_stop = has_valid && config.early_stopping_rounds > 0;
	int best_iteration = max_iterations; // 保存模型时使用的迭代轮数
	double best_score = std::numeric_limits<double>::infinity();
	for (int iteration = 1; iteration <= max_iterations; ++iteration) {
		int is_finished = 0;
		detail::check_lgbm_status(LGBM_BoosterUpdateOneIter(booster.handle, &is_finished));

		if (enable_early_stop) {
			// 取data_idx=1(验证集)的binary_logloss指标, out_len传入期望数量1, 传出实际数量
			int eval_count = 1;
			double current_score = 0.0;
			detail::check_lgbm_status(LGBM_BoosterGetEval(booster.handle, 1, &eval_count, &current_score));
			if (current_score < best_score) {
				best_score = current_score;
				best_iteration = iteration;
			}
			// 连续early_stopping_rounds轮无改善则提前终止
			if (iteration - best_iteration >= static_cast<int>(config.early_stopping_rounds)) {
				break;
			}
		}
	}

	// 以最佳迭代轮数导出模型文本(两段式调用: 先问长度再取内容)
	int64_t model_len = 0;
	detail::check_lgbm_status(LGBM_BoosterSaveModelToString(booster.handle, 0, best_iteration, C_API_FEATURE_IMPORTANCE_GAIN, 0, &model_len, nullptr));
	std::string model_string(static_cast<size_t>(model_len), '\0');
	detail::check_lgbm_status(LGBM_BoosterSaveModelToString(booster.handle, 0, best_iteration, C_API_FEATURE_IMPORTANCE_GAIN, model_len, &model_len, model_string.data()));

	Model model;
	model.model_string = std::move(model_string);
	return model;
}

} // namespace starlight_v3::lgbm
