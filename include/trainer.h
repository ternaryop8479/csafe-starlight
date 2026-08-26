/**
 * @file trainer.h
 * @brief 最终训练器接口声明(交叉训练编排层)
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_TRAINER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_TRAINER_H

#include <functional>
#include <string>
#include <vector>

#include "authenticode/trainer.h"
#include "basic/efg.h"
#include "basic/types.h"
#include "lgbm/trainer.h"
#include "model.h"
#include "tspm/trainer.h"

namespace starlight_v3 {

/**
 * @brief 训练样本数据结构封装，包含提取完成的EFG及文件路径
 */
struct TrainSample {
	EFG efg; ///< 样本的EFG(外部调用流程图)
	std::string file_path; ///< 样本PE文件的路径
};

/**
 * @brief 最终训练配置结构体
 */
struct TrainConfig {
	tspm::TrainingConfig tspm_config; ///< tosSPM训练参数(见tspm/trainer.h中TrainingConfig的字段说明)
	authenticode::TrainerConfig authenticode_config; ///< 白签名表训练参数(见authenticode/trainer.h中TrainerConfig的字段说明)
	lgbm::LGBMConfig lgbm_config; ///< LightGBM训练参数(见lgbm/trainer.h中LGBMConfig的字段说明)
	SIZE_T cross_validation_k; ///< 交叉训练折数, 值域[2, +∞)。数据集按此折数划分后轮流作为测试集生成特征, 折数越大每折训练集越完整、特征越稳定, 但tosSPM训练与推理次数随之增加
	unsigned int random_seed; ///< 折划分的随机种子, 固定后可复现交叉训练的划分结果
	SIZE_T thread_count; ///< 特征生成阶段的并行线程数, 值域[0, +∞)。0表示使用系统最大并发数
	std::function<void(const std::string &)> log_callback; ///< 日志回调, 训练过程的所有日志都会通过该回调输出
};

/**
 * @brief 训练器封装
 */
class Trainer {

public:
	Trainer() = default;
	~Trainer() = default;

	/**
	 * @brief 执行完整训练流程
	 * @param config 训练配置, 所有字段必须显式填满
	 * @param malware_samples 恶意样本集(标签为1), 允许与良性样本集大小不同
	 * @param benign_samples 良性样本集(标签为0), 允许与恶意样本集大小不同
	 * @return 训练完成的最终模型(含tosSPM模型与LightGBM模型)
	 */
	Model train(const TrainConfig &config, const std::vector<TrainSample> &malware_samples, const std::vector<TrainSample> &benign_samples);
};

} // namespace starlight_v3

#endif
