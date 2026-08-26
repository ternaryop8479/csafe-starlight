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

#include "authenticode/model.h"
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
	 * @return 保存是否成功
	 * @retval true 保存成功
	 * @retval false 保存失败
	 */
	bool save_to_file(const std::string &path) const;

	/**
	 * @brief 从指定路径加载模型文件
	 * @param path 输入文件路径
	 * @return 加载是否成功
	 * @retval true 加载成功
	 * @retval false 加载失败
	 */
	bool load_from_file(const std::string &path);

	/**
	 * @brief 设置当前模型版本
	 * @param year 完整或简写的阿拉伯数字年份(即YYYY或YY)
	 * @param month 两位阿拉伯数字月份(即MM)
	 * @param day 两位阿拉伯数字日(即DD)
	 */
	void change_version(int year, int month, int day);

	/**
	 * @brief 获取当前模型版本
	 * @return 当前模型版本字符串，获取失败则为空
	 */
	std::string get_version() const;

	/**
	 * @brief 获取内部tosSPM模型
	 * @return tosSPM模型的const引用
	 */
	const tspm::Model &tspm_model() const;

	/**
	 * @brief 获取内部白签名表模型
	 * @return 白签名表模型的const引用
	 */
	const authenticode::Model &sig_table() const;

	/**
	 * @brief 设置白签名表模型(训练流程在LightGBM训练前构建, 保存时随模型一并序列化)
	 * @param sig_table 白签名表模型
	 */
	void set_sig_table(const authenticode::Model &sig_table);

	/**
	 * @brief 获取内部LightGBM模型
	 * @return LightGBM模型的const引用
	 */
	const lgbm::Model &lgbm_model() const;

private:
	tspm::Model tspm_model_; ///< tosSPM模型(Trie树)
	lgbm::Model lgbm_model_; ///< LightGBM模型
	authenticode::Model sig_table_; ///< 白签名表模型(推理时供签名置信度特征查表)
	SIZE_T version_ = 0; ///< 用于标记当前模型训练日期
};

} // namespace starlight_v3

#endif
