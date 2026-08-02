/**
 * @file efg.h
 * @brief 外部调用流程图数据结构的声明
 * @author ternaryop8479
 * @date 2026-07-09
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_BASIC_EFG_H
#define CSAFE_STARLIGHT_V3_INCLUDE_BASIC_EFG_H

#include <string>
#include <unordered_map>
#include <vector>

#include "basic/api_table.h"
#include "basic/types.h"

namespace starlight_v3 {

/**
 * @brief 程序的边数据结构体
 */
struct EFGEdge {
	SIZE_T to_node_index = 0;
	SIZE_T jump_count = 0;
	SIZE_T indirect_jump_count = 0;
	double avg_span = 0.0;
	double span_variance = 0.0;
	SIZE_T spans_with_data = 0;
};

/**
 * @brief 程序的外部调用流程图数据结构声明
 */
struct EFG {
	// API映射表
	APITable api_table_;

	// 采取CSR格式存储图数据
	std::vector<SIZE_T> nodes_;
	std::vector<EFGEdge> edges_;
	std::vector<SIZE_T> offeset_;
};

}

#endif
