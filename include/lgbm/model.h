/**
 * @file lgbm/model.h
 * @brief LightGBM模型数据结构声明
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_MODEL_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_MODEL_H

#include <string>

namespace starlight_v3::lgbm {

/**
 * @brief LightGBM模型数据结构
 * @details 该结构体只存储LightGBM原生模型文本, 不持有任何句柄, 可自由拷贝.
 * 模型文本由LGBM_BoosterSaveModelToString生成(以best_iteration轮保存),
 * 加载时直接交给LGBM_BoosterLoadModelFromString即可恢复模型.
 */
struct Model {
	std::string model_string; ///< LightGBM原生模型文本
};

} // namespace starlight_v3::lgbm

#endif
