/**
 * @file pe/imports.h
 * @brief PE导入表轻量解析接口
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_PE_IMPORTS_H
#define CSAFE_STARLIGHT_V3_INCLUDE_PE_IMPORTS_H

#include <cstdint>
#include <string>
#include <vector>

#include "pe/view.h"

namespace starlight_v3::pe {

struct ImportEntry {
	std::string dll_name; ///< 所属DLL名称
	std::string function_name; ///< 函数名, 序号导入时为空
	bool ordinal = false; ///< 是否为序号导入
};

std::vector<ImportEntry> enumerate_imports(const PeView &view);

} // namespace starlight_v3::pe

#endif
