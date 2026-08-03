/**
 * @file lgbm/trainer.h
 * @brief LightGBM模型训练器接口声明
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_TRAINER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_TRAINER_H

#include "basic/types.h"
#include "lgbm/model.h"
#include <cstdint>

namespace starlight_v3::lgbm {

/**
 * @brief LightGBM训练配置结构体
 * @details 所有字段均无默认值, 使用前必须显式填满所有字段
 */
struct LGBMConfig {
	SIZE_T num_iterations; ///< 最大训练轮数, 值域[1, +∞)。每轮训练一棵树, 轮数越大拟合能力越强, 过大容易过拟合
	double learning_rate; ///< 学习率, 值域(0, 1]。学习率越小每棵树贡献越少、模型越平滑, 但需要更多训练轮数才能收敛
	SIZE_T num_leaves; ///< 单棵树的叶子节点数上限, 值域[2, +∞)。越大单棵树越复杂、分裂越细, 过大容易过拟合
	SIZE_T min_data_in_leaf; ///< 叶子节点最小样本数, 值域[1, +∞)。越小叶子划分越细, 越大越能抑制过拟合
	double feature_fraction; ///< 每次分裂时随机采样的特征比例, 值域(0, 1]。越小随机性越强、越能抑制过拟合, 1.0表示不采样
	double bagging_fraction; ///< 每轮训练随机采样的样本比例, 值域(0, 1]。需与bagging_freq配合使用, 1.0表示不采样
	SIZE_T bagging_freq; ///< bagging采样的执行频率(每多少轮执行一次采样), 值域[0, +∞)。0表示禁用bagging
	double lambda_l2; ///< L2正则化系数, 值域[0, +∞)。越大叶子权重收缩越强、越能抑制过拟合
	double validation_ratio; ///< 从训练集中划出的验证集比例, 值域[0, 1)。按标签分层划分, 用于早停与选取最佳迭代轮数, 0表示不划分验证集(此时不早停、模型保存全部训练轮数)
	SIZE_T early_stopping_rounds; ///< 早停轮数, 值域[0, +∞)。验证集分数连续多少轮无改善即停止训练, 0表示不早停。仅在validation_ratio > 0时生效
	unsigned int random_seed; ///< 验证集划分的随机种子, 固定后可复现训练结果
	SIZE_T thread_count; ///< LightGBM训练线程数, 值域[0, +∞)。0表示使用系统最大并发数
};

/**
 * @brief LightGBM训练器
 * @details 职责范围仅限LightGBM模型本身: 输入特征矩阵与标签, 输出训练完成的LightGBM模型.
 * 不感知特征来源, 也不感知tosSPM等其他模块的存在.
 */
class Trainer {

public:
	Trainer() = default;
	~Trainer() = default;

	/**
	 * @brief 使用特征矩阵训练LightGBM二分类模型
	 * @details 内部按validation_ratio分层划分验证集(使用random_seed洗牌), 训练过程中
	 * 监控验证集binary_logloss, 早停触发或训练满num_iterations轮后, 以最佳迭代轮数
	 * 保存模型返回. objective固定为binary(二分类), metric固定为binary_logloss.
	 * @param feature_matrix 特征矩阵, 行主序(每行一个样本, ncols个特征), 调用方保证有效
	 * @param nrows 样本行数, 值域[1, +∞)
	 * @param ncols 特征维度数, 值域[1, +∞), 训练与推理时必须保持一致
	 * @param labels 标签数组, 长度nrows, 1.0代表正类(恶意), 0.0代表负类(良性)
	 * @param config 训练配置, 所有字段必须显式填满
	 * @return 训练完成的LightGBM模型
	 */
	Model train(const double *feature_matrix, int32_t nrows, int32_t ncols, const float *labels, const LGBMConfig &config);
};

} // namespace starlight_v3::lgbm

#endif
