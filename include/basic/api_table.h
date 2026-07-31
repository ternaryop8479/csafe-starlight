/**
 * @file api_table.h
 * @brief API映射表数据结构声明
 * @author ternaryop8479
 * @date 2026-07-09
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_BASIC_API_TABLE_H
#define CSAFE_STARLIGHT_V3_INCLUDE_BASIC_API_TABLE_H

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "basic/types.h"

namespace starlight_v3 {

// 用来存储APIID的类型
using APIID_T = SIZE_T;

/**
 * @brief API映射表，负责去重并生成API名和ID间的映射处理
 */
class APITable {

public:
	APITable() = default;
	~APITable() = default;
	/**
	 * @brief 构造函数
	 * @details 可以根据已有的API表生成APITable对象
	 * @param api_table 一个已有的API数组(重复不敏感，unordered_map自带去重)
	 */
	APITable(const std::vector<std::string> &api_table);

	/**
	 * @brief 插入一条新的API
	 * @param api 一条API字符串
	 * @return 代表插入是否成功
	 * @retval true 插入成功
	 * @retval false 插入失败
	 */
	bool insert(const std::string &api);
	/**
	 * @brief 根据ID查询API名
	 * @param id 目标API的ID
	 * @return 查询结果及所得数据，pair的bool变量代表是否有匹配API，std::string对象代表匹配的API数据
	 */
	std::pair<bool, std::string> query_api(SIZE_T id) const;
	/**
	 * @brief 根据API名查询ID
	 * @param id 目标API名
	 * @return 查询结果及所得数据，pair的bool变量代表是否有匹配API，SIZE_T变量代表匹配到的ID
	 */
	std::pair<bool, SIZE_T> query_id(const std::string &api) const;
	/**
	 * @brief 获取API表的vector数据
	 * @return 一个const引用，指向对象内部的API表，API在该表中的索引即为API的ID
	 * @warning 该函数返回的表不保证线程安全，多线程并行请谨慎使用并加锁
	 */
	const std::vector<std::string> &get_table() const;

private:
	std::vector<std::string> api_table_; // API映射表，api_table_[i]代表id为i的API字符串
	std::unordered_map<std::string, APIID_T> api_map_; // 存储API映射数据，可以根据API字符串查询得到其在api_table_数组中的索引
};

}

#endif
