/**
 * @file efg_generator.h
 * @brief 外部调用流程图生成模块声明
 * @author ternaryop8479
 * @date 2026-07-09
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_EFG_GENERATOR_H
#define CSAFE_STARLIGHT_V3_INCLUDE_EFG_GENERATOR_H

#include <string>

#include "basic/efg.h"
#include "basic/types.h"

namespace starlight_v3 {

/**
 * @brief 根据制定程序路径生成目标程序的外部调用流程图
 * @param file_path 目标程序路径(支持相对路径)
 * @return 函数执行状态及目标程序EFG
 * @retvalue {false, EFG()} 解析失败
 * @retvalue {true, EFG(...)} 解析成功
 */
std::pair<bool, EFG> generate_efg(const std::string &file_path);

} // namespace starlight_v3

#endif
