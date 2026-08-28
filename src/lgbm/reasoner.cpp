/**
 * @file lgbm/reasoner.cpp
 * @brief LightGBM模型推理器实现
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include "lgbm/reasoner.h"
#include "lgbm/feat_vector.h"

namespace starlight_v3::lgbm {

// 构造函数, 加载模型字符串恢复Booster
Reasoner::Reasoner(const Model &model) {
	int num_iterations = 0;
	detail::check_lgbm_status(LGBM_BoosterLoadModelFromString(model.model_string.c_str(), &num_iterations, &booster_.handle));

	// 校验模型特征维度与当前引擎一致: LightGBM的PredictForMat对列数不匹配不报错,
	// 若混用不同版本模型会静默读越界产生未定义行为, 因此必须在加载期拦下
	int num_feature = 0;
	detail::check_lgbm_status(LGBM_BoosterGetNumFeature(booster_.handle, &num_feature));
	if (num_feature != static_cast<int>(kTotalFeatDims)) {
		throw std::runtime_error("Reasoner::Reasoner(): 模型特征维度(" + std::to_string(num_feature)
			+ ")与当前引擎特征维度(" + std::to_string(kTotalFeatDims)
			+ ")不一致, 请使用与本引擎配套训练的模型文件");
	}
}

Reasoner::~Reasoner() = default;

// 单样本预测, binary二分类的NORMAL预测输出1个值, 即恶意概率
// 注意: 本版本LGBM_BoosterPredictForMat不支持parameter为nullptr(内部会无条件构造std::string),
// 且binary单行NORMAL预测固定输出1个值, 直接传入out_len=1与接收缓冲即可
double Reasoner::predict(const double *features, int32_t ncols) {
	double out_result = 0.0;
	int64_t out_len = 1;
	detail::check_lgbm_status(LGBM_BoosterPredictForMat(booster_.handle, features, C_API_DTYPE_FLOAT64, 1, ncols, 1, C_API_PREDICT_NORMAL, 0, -1, "", &out_len, &out_result));
	if (out_len != 1) {
		throw std::runtime_error("Reasoner::predict(): unexpected output length, expected 1, got " + std::to_string(out_len));
	}
	return out_result;
}

} // namespace starlight_v3::lgbm
