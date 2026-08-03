/**
 * @file model.h
 * @brief 最终模型数据结构声明(单文件存储tosSPM模型与LightGBM模型)
 * @author ternaryop8479
 * @date 2026-08-03
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_MODEL_H
#define CSAFE_STARLIGHT_V3_INCLUDE_MODEL_H

#include "lgbm/model.h"
#include "tspm/model.h"
#include <string>

namespace starlight_v3 {

/**
 * @brief 最终模型数据结构
 * @details 同时包含tosSPM模型(Trie树)与LightGBM模型, 两个模型一起序列化到同一个模型文件中.
 * 推理时Reasoner从该结构中同时取两个模型完成整合分析.
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
	 * @details 文件格式: 8字节魔数"CSLGBMV1" + 4字节版本号 + 8字节tosSPM段长度 +
	 * tosSPM段(API表/Trie树/模型参数) + 8字节LightGBM段长度 + LightGBM段(原生模型文本)
	 * @param path 输出文件路径
	 * @throw std::runtime_error 文件无法打开或写入失败时抛出
	 */
	void save_to_file(const std::string &path) const;

	/**
	 * @brief 从指定路径加载模型文件
	 * @param path 输入文件路径
	 * @return 加载完成的模型
	 * @throw std::runtime_error 文件无法打开、魔数/版本不符或数据损坏时抛出
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
