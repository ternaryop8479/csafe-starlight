/**
 * @file model.h
 * @brief 模型数据结构声明
 * @author ternaryop8479
 * @date 2026-07-12
 */
// 吃货殿下生日快乐 \>v<\

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_MODEL_H
#define CSAFE_STARLIGHT_V3_INCLUDE_MODEL_H

#include <string>
#include <unordered_map>
#include <vector>

#include "basic/api_table.h"
#include "basic/types.h"

#include "tspm/model.h"

namespace starlight_v3 {

class Model {

	// 允许Trainer和Reasoner直接读写Model的私有数据(不应该在类内开放有关封装实现细节的接口)
	friend class Trainer;
	friend class Reasoner;

public:
	Model() = default;
	~Model() = default;

	/**
	 * @brief 从文件中加载模型
	 * @param model_path 目标模型路径(支持相对路径)
	 * @return 模型是否加载成功
	 * @retval true 加载成功
	 * @retval false 加载失败
	 */
	bool load_from(const std::string &model_path);

	/**
	 * @brief 保存当前模型到文件
	 * @param model_path 模型要写入到的位置(支持相对路径)
	 * @return 模型是否保存成功
	 * @retval true 保存成功
	 * @retval false 保存失败
	 */
	bool save_to(const std::string &target_path);

protected:
	tspm::Model model_; // tosSPM模型
};

} // namespace starlight_v3

#endif
