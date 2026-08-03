/**
 * @file model.h
 * @brief 最终模型数据结构声明(单文件存储tosSPM模型与LightGBM模型)
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_MODEL_H
#define CSAFE_STARLIGHT_V3_INCLUDE_MODEL_H

#include <string>

#include "lgbm/model.h"
#include "tspm/model.h"

namespace starlight_v3 {

/**
 * @brief 模型数据结构封装
 */
class Model {

public:
	Model() = default;
	~Model() = default;

	/**
	 * @brief 构造函数
	 * @param tspm_model tosSPM模型(需要非空)
	 * @param lgbm_model LightGBM模型(需要非空)
	 */
	Model(const tspm::Model &tspm_model, const lgbm::Model &lgbm_model);

	/**
	 * @brief 将两个模型一起保存到指定路径
	 * @param path 输出文件路径
	 */
	void save_to_file(const std::string &path) const;

	/**
	 * @brief 从指定路径加载模型文件
	 * @param path 输入文件路径
	 * @return 加载完成的模型
	 */
	static Model load_from_file(const std::string &path);

	/**
	 * @brief 获取内部tosSPM模型
	 * @return tosSPM模型的const引用
	 */
	const tspm::Model &tspm_model() const;

	/**
	 * @brief 获取内部LightGBM模型
	 * @return LightGBM模型的const引用
	 */
	const lgbm::Model &lgbm_model() const;

private:
	tspm::Model tspm_model_; ///< tosSPM模型(Trie树)
	lgbm::Model lgbm_model_; ///< LightGBM模型
};

} // namespace starlight_v3

#endif
