/**
 * @file types.h
 * @brief 引擎所用到的基础类型定义
 * @author ternaryop8479
 * @date 2026-07-09
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_BASIC_TYPES_H
#define CSAFE_STARLIGHT_V3_INCLUDE_BASIC_TYPES_H

#include <cstdint>
#include <limits>

namespace starlight_v3 {

// 引擎逻辑需要，这里固定SIZE_T = uint32_t，不再修改
using SIZE_T = uint32_t;
using GREAT_SIZE_T = uint64_t;
const SIZE_T INVALID_NUM = std::numeric_limits<SIZE_T>::max(); // 以该类型最大值作为无效值

// 浮点数计算部分
const double EPSILON = 1e-8;

/**
 * @brief 判断一个浮点数是否趋近于0
 * @param k 目标浮点数
 * @return 是否趋近于0
 * @retval true 该浮点数趋近于0
 * @retval false 该浮点数不趋近于0
 */
inline bool near_zero(double k) {
	return k > -EPSILON && k < EPSILON;
}

}

#endif
