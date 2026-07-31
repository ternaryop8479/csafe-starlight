/**
 * @file reasoner.h
 * @brief 模型推理引擎接口声明
 * @author ternaryop8479
 * @date 2026-07-13
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_REASONER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_REASONER_H

#include "basic/efg.h"
#include "model.h"

namespace starlight_v3 {

class Reasoner {

public:
	Reasoner() = delete; // 不允许使用默认构造函数初始化，必须传入一个const Model引用
	~Reasoner() = default;

	/**
	 * @brief 唯一构造函数
	 * @param model 已加载(或将要在Reasoner开始推理前加载)的const Model引用，即Reasoner所使用的模型对象
	 */
	Reasoner(const Model &model);

	/**
	 * @brief 通过程序的EFG(外部调用流程图)计算一个已知程序的风险度
	 * @param efg 从已知程序中提取的外部调用流程图(详细接口见efg_generator.h)
	 * @return 目标程序风险度，返回值值域[0.0, 1.0]
	 */
	double calculate_risk_score(const EFG &efg);

private:
	const Model &model_; ///< 用于推理的模型
};

} // namespace starlight_v3

#endif
