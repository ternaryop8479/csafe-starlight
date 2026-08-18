/**
 * @file pe_compat.cpp
 * @brief pe-parse兼容解析工具实现(修补已知缺陷后重试解析)
 * @author ternaryop8479
 * @date 2026-08-18
 */

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include <pe-parse/parse.h>

#include "basic/pe_compat.h"

namespace starlight_v3 {

namespace {

// 将文件读取到自有缓冲区，失败时返回false
// 注意: 不能使用peparse::readFileToFileBuffer，它会对文件做PROT_READ+MAP_SHARED映射，
// 对映射区写入会触发SIGSEGV(且MAP_SHARED会回写源文件)，因此这里用ifstream读到自有缓冲区再修补
bool read_file_bytes(const std::string &file_path, std::vector<std::uint8_t> &out) {
	std::ifstream ifs(file_path, std::ios::binary);
	if (!ifs) {
		return false;
	}
	ifs.seekg(0, std::ios::end);
	const std::streamoff file_size = ifs.tellg();
	if (file_size <= 0) {
		return false;
	}
	ifs.seekg(0, std::ios::beg);
	out.resize(file_size);
	ifs.read(reinterpret_cast<char *>(out.data()), static_cast<std::streamsize>(file_size));
	return ifs.gcount() == file_size;
}

} // namespace

ParsedPECompat parse_pe_with_compat(const std::string &file_path) {
	// 先走标准解析路径，大多数文件无需任何修补即可直接解析
	ParsedPECompat result;
	result.pe = peparse::ParsePEFromFile(file_path.c_str());
	if (result.pe != nullptr) {
		return result;
	}

	// 标准解析失败，读取文件字节到自有缓冲区后执行修补
	if (!read_file_bytes(file_path, result.patched_data)) {
		return result;
	}
	std::uint8_t *raw = result.patched_data.data();
	const std::uint32_t raw_len = static_cast<std::uint32_t>(result.patched_data.size());

	// MZ校验
	if (raw_len < 0x40 || raw[0] != 'M' || raw[1] != 'Z') {
		result.patched_data.clear();
		return result;
	}

	// e_lfanew -> PE头偏移
	const std::uint32_t lfanew = *reinterpret_cast<const std::uint32_t *>(raw + 0x3c);
	if (lfanew + 4 + 20 + 2 > raw_len) {
		result.patched_data.clear();
		return result;
	}
	std::uint8_t *pe_base = raw + lfanew;
	if (std::memcmp(pe_base, "PE\0\0", 4) != 0) {
		result.patched_data.clear();
		return result;
	}

	// COFF头: Machine(2) NumberOfSections(2) 后接OptionalHeader
	const std::uint32_t opt_off = 4 + 20;
	const std::uint16_t num_sections = *reinterpret_cast<const std::uint16_t *>(pe_base + 4 + 2);
	const std::uint16_t opt_magic = *reinterpret_cast<const std::uint16_t *>(pe_base + opt_off);
	const bool is_64 = (opt_magic == 0x20b);
	if (opt_magic != 0x10b && opt_magic != 0x20b) {
		result.patched_data.clear();
		return result;
	}
	// DataDirectory起始偏移: PE32=96，PE32+=112；NumberOfRvaAndSizes: PE32偏移92，PE32+偏移108
	const std::uint32_t dd_base = opt_off + (is_64 ? 112 : 96);
	const std::uint32_t num_dirs_off = opt_off + (is_64 ? 108 : 92);
	// 节表起始偏移: 可选头总长 PE32=224，PE32+=240
	const std::uint32_t sec_off = opt_off + (is_64 ? 240 : 224);
	if (lfanew + sec_off + num_sections * 40 > raw_len) {
		result.patched_data.clear();
		return result;
	}
	const std::uint8_t *sec_table = pe_base + sec_off;

	// 修补1: 当数据目录指向无原始数据的节段(SizeOfRawData为0，典型如UPX壳的UPX0段)时，
	// 清零该目录的Size字段(保留VA)，使pe-parse跳过对这段数据的读取
	const std::uint16_t num_dirs = std::min<std::uint16_t>(
		*reinterpret_cast<const std::uint16_t *>(pe_base + num_dirs_off), 16);
	for (std::uint16_t d = 0; d < num_dirs; ++d) {
		std::uint8_t *dir = pe_base + dd_base + d * 8;
		const std::uint32_t dir_rva = *reinterpret_cast<const std::uint32_t *>(dir);
		const std::uint32_t dir_size = *reinterpret_cast<const std::uint32_t *>(dir + 4);
		if (dir_rva == 0 || dir_size == 0) {
			continue;
		}
		for (std::uint16_t i = 0; i < num_sections; ++i) {
			const std::uint8_t *sh = sec_table + i * 40;
			const std::uint32_t va = *reinterpret_cast<const std::uint32_t *>(sh + 12);
			const std::uint32_t vsz = *reinterpret_cast<const std::uint32_t *>(sh + 8);
			const std::uint32_t raw_size = *reinterpret_cast<const std::uint32_t *>(sh + 16);
			// 用64位算术判断段内归属，防止va+vsz回绕导致恶意文件绕过检查
			if (dir_rva >= va && (std::uint64_t)dir_rva < (std::uint64_t)va + vsz) {
				if (raw_size == 0) {
					*reinterpret_cast<std::uint32_t *>(dir + 4) = 0;
				}
				break;
			}
		}
	}

	// 修补2: 清理debug目录中的空条目(详见头文件说明)，仅在修补1未清零该目录Size时执行
	const std::uint32_t dbg_rva = *reinterpret_cast<const std::uint32_t *>(pe_base + dd_base + 6 * 8);
	const std::uint32_t dbg_size = *reinterpret_cast<const std::uint32_t *>(pe_base + dd_base + 6 * 8 + 4);
	if (dbg_size != 0) {
		int dbg_sec_idx = -1;
		for (std::uint16_t i = 0; i < num_sections; ++i) {
			const std::uint8_t *sh = sec_table + i * 40;
			const std::uint32_t va = *reinterpret_cast<const std::uint32_t *>(sh + 12);
			const std::uint32_t vsz = *reinterpret_cast<const std::uint32_t *>(sh + 8);
			// 用64位算术判断段内归属，防止va+vsz回绕导致恶意文件绕过检查
			if (dbg_rva >= va && (std::uint64_t)dbg_rva < (std::uint64_t)va + vsz) {
				dbg_sec_idx = i;
				break;
			}
		}
		if (dbg_sec_idx >= 0) {
			const std::uint8_t *sh = sec_table + dbg_sec_idx * 40;
			const std::uint32_t raw_off = *reinterpret_cast<const std::uint32_t *>(sh + 20);
			// 文件偏移换算与边界检查都用64位算术，防止偏移回绕导致越界访问
			const std::uint64_t dbg_file_off = (std::uint64_t)raw_off
				+ (std::uint64_t)(dbg_rva - *reinterpret_cast<const std::uint32_t *>(sh + 12));
			if (dbg_file_off + dbg_size <= raw_len) {
				// 条目布局: Characteristics(4) TimeStamp(4) Major(2) Minor(2) Type(4)
				// SizeOfData(4) AddressOfRawData(4) PointerToRawData(4) = 28字节
				const std::uint32_t entry_size = 28;
				for (std::uint32_t i = 0; i + entry_size <= dbg_size; i += entry_size) {
					std::uint8_t *ent = raw + dbg_file_off + i;
					const std::uint32_t size_of_data = *reinterpret_cast<const std::uint32_t *>(ent + 16);
					const std::uint32_t addr_of_raw = *reinterpret_cast<const std::uint32_t *>(ent + 20);
					const std::uint32_t ptr_to_raw = *reinterpret_cast<const std::uint32_t *>(ent + 24);
					if (size_of_data == 0 && addr_of_raw == 0 && ptr_to_raw != 0) {
						*reinterpret_cast<std::uint32_t *>(ent + 24) = 0;
					}
				}
			}
		}
	}

	// 用修补后的缓冲区重试解析: makeBufferFromPointer的buffer归调用方持有(copy=true)，
	// 数据由patched_data持有，生命周期必须覆盖ParsePEFromBuffer返回产物的整个使用期
	result.pe = peparse::ParsePEFromBuffer(peparse::makeBufferFromPointer(raw, raw_len));
	if (result.pe == nullptr) {
		result.patched_data.clear();
	}
	return result;
}

} // namespace starlight_v3
