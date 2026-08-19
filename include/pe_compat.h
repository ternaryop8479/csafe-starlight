/**
 * @file pe_compat.h
 * @brief pe-parse兼容解析工具(修补已知缺陷后重试解析)
 * @author ternaryop8479
 * @date 2026-08-18
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_BASIC_PE_COMPAT_H
#define CSAFE_STARLIGHT_V3_INCLUDE_BASIC_PE_COMPAT_H

#include <cstdint>
#include <string>
#include <vector>

#include <pe-parse/parse.h>

namespace starlight_v3 {

/**
 * @brief pe-parse兼容解析结果，pe非空即解析成功
 * @note 仅当文件被pe-parse的已知缺陷误拒时才走修补路径，此时patched_data持有修补后的文件字节，
 * 必须存活至DestructParsedPE之后(否则解析产物内悬垂指针)；正常路径下patched_data为空。
 */
struct ParsedPECompat {
	peparse::parsed_pe *pe = nullptr; ///< 解析产物(失败为nullptr)
	std::vector<std::uint8_t> patched_data; ///< 修补路径下的文件字节持有者(正常路径为空)
};

/**
 * @brief 解析PE文件，首次失败时自动执行兼容修补后重试
 * @note 修补项:
 *  1. 数据目录指向无原始数据的节段(SizeOfRawData为0，典型如UPX壳的UPX0段)时，将该目录Size清零:
 *     UPX等壳的导出/重定位目录RVA指向运行时才解压的段，pe-parse对Size非0的目录尝试读取段数据
 *     必然失败导致整个文件被拒；清零Size(保留VA)使pe-parse跳过读取，特征层仍可按VA判断目录存在性。
 *  2. debug目录空条目(SizeOfData为0且AddressOfRawData为0但PointerToRawData非0)的PointerToRawData清零:
 *     此类条目常见于.NET程序集的可复现构建标记，pe-parse会把AddressOfRawData为0换算成RVA 0再查段，
 *     必然失败导致整个文件被拒；清零后满足其全零break条件正常跳过。
 * @param file_path 目标PE文件路径
 * @return 兼容解析结果，调用方负责DestructParsedPE(pe)释放
 */
ParsedPECompat parse_pe_with_compat(const std::string &file_path);

} // namespace starlight_v3

#endif
