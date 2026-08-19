/**
 * @file basic/api_table.cpp
 * @brief API映射表数据结构实现
 * @author ternaryop8479
 * @date 2026-07-09
 */

#include <utility>

#include "basic/api_table.h"
#include "basic/types.h"

namespace starlight_v3 {

APITable::APITable(const std::vector<std::string> &api_table) {
	for (const std::string &item : api_table) {
		insert(item); // 调用内部插入函数，自带去重
	}
}

bool APITable::insert(const std::string &api) {
	// 首先尝试给item分配新的id(就是api_table_.size())，如果插入失败就直接插下一个实现去重
	if (!api_map_.emplace(api, api_table_.size()).second) {
		return false;
	}
	api_table_.emplace_back(api); // 将API插入数组末尾
	return true;
}

std::pair<bool, std::string> APITable::query_api(SIZE_T id) const {
	if (id >= api_table_.size()) { // 当且仅当id越界时查找不到对应API数据
		return { false, "" };
	}
	return { true, api_table_[id] };
}

std::pair<bool, SIZE_T> APITable::query_id(const std::string &api) const {
	auto it = api_map_.find(api);
	if (it == api_map_.end()) { // 找不到元素
		return { false, INVALID_NUM };
	}
	return { true, it->second };
}

const std::vector<std::string> &APITable::get_table() const {
	return api_table_;
}

}
