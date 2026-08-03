/**
 * @file lgbm/reasoner.h
 * @brief LightGBM模型推理器接口声明
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_REASONER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_REASONER_H

#include <cstdint>

#include "lgbm/detail/lgbm_handle.h"
#include "lgbm/model.h"

namespace starlight_v3::lgbm {

/**
 * @brief LightGBM推理器
 * @details 职责范围仅限LightGBM模型本身: 输入特征向量, 输出恶意概率.
 * 不感知特征来源, 也不感知tosSPM等其他模块的存在.
 * 该对象持有Booster句柄, 禁止拷贝; 多线程推理时请每个线程独立构造实例.
 */
class Reasoner {

public:
	/**
	 * @brief 唯一构造函数
	 * @param model 已加载的LightGBM模型, 构造时通过LGBM_BoosterLoadModelFromString恢复Booster
	 */
	explicit Reasoner(const Model &model);
	~Reasoner();

	Reasoner(const Reasoner &) = delete;
	Reasoner &operator=(const Reasoner &) = delete;

	/**
	 * @brief 对单个样本的特征向量进行预测
	 * @param features 特征向量, 列数必须与训练时的ncols一致, 调用方保证有效
	 * @param ncols 特征维度数, 必须等于训练时的特征维度数
	 * @return 恶意概率, 值域[0, 1], 越接近1越可能为恶意
	 */
	double predict(const double *features, int32_t ncols);

private:
	detail::BoosterHandleGuard booster_; ///< 推理用的Booster句柄
};

} // namespace starlight_v3::lgbm

#endif
