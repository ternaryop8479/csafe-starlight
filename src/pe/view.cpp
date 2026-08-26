/**
 * @file pe/view.cpp
 * @brief PE文件字节视图实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <cstdint>
#include <cstring>
#include <fstream>

#include "pe/view.h"

namespace starlight_v3::pe {

namespace {

// 从缓冲区指定偏移安全读取小端整数, 越界返回0(调用方需先行完成边界校验)
template<typename T>
T read_le(const uint8_t *base, size_t offset, size_t total) {
	// 用减法比较而非offset+sizeof(T), 避免offset接近上界时加法回绕使检查失效
	if (offset > total || sizeof(T) > total - offset) {
		return 0;
	}
	T value = 0;
	std::memcpy(&value, base + offset, sizeof(T));
	return value;
}

} // namespace

bool PeView::load(const std::string &path, PeView &out) {
	// 一次性整读文件到自有缓冲区
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs) {
		return false;
	}
	ifs.seekg(0, std::ios::end);
	const std::streamoff file_size = ifs.tellg();
	if (file_size <= 0) {
		return false;
	}
	ifs.seekg(0, std::ios::beg);

	PeView view;
	view.bytes_.resize(static_cast<size_t>(file_size));
	ifs.read(reinterpret_cast<char *>(view.bytes_.data()), file_size);
	if (ifs.gcount() != file_size) {
		return false;
	}

	const uint8_t *raw = view.bytes_.data();
	const size_t total = view.bytes_.size();

	// DOS头: MZ魔数与e_lfanew
	if (total < 0x40 || raw[0] != 'M' || raw[1] != 'Z') {
		return false;
	}
	const uint32_t lfanew = read_le<uint32_t>(raw, 0x3c, total);
	// 边界比较提升到64位: lfanew是文件内的uint32, 若在32位域内做加法, 接近上界时会回绕导致检查失效
	if (lfanew == 0 || static_cast<uint64_t>(lfanew) + 4 + 20 > total || std::memcmp(raw + lfanew, "PE\0\0", 4) != 0) {
		return false;
	}

	// COFF头: NumberOfSections位于PE签名后+2
	const size_t coff_off = lfanew + 4;
	const uint16_t num_sections = read_le<uint16_t>(raw, coff_off + 2, total);
	const uint16_t opt_size = read_le<uint16_t>(raw, coff_off + 16, total);

	// OptionalHeader: Magic区分PE32/PE32+
	const size_t opt_off = coff_off + 20;
	if (opt_off + 2 > total) {
		return false;
	}
	const uint16_t opt_magic = read_le<uint16_t>(raw, opt_off, total);
	if (opt_magic != 0x10b && opt_magic != 0x20b) {
		return false;
	}
	view.is64_ = (opt_magic == 0x20b);

	// 入口点RVA(AddressOfEntryPoint): PE32/PE32+均在OptionalHeader偏移16处
	view.entry_rva_ = read_le<uint32_t>(raw, opt_off + 16, total);

	// 数据目录: NumberOfRvaAndSizes与目录数组基址在PE32/PE32+下偏移不同
	const size_t num_dirs_off = opt_off + (view.is64_ ? 108 : 92);
	const size_t dd_base = opt_off + (view.is64_ ? 112 : 96);
	const uint32_t num_dirs = read_le<uint32_t>(raw, num_dirs_off, total);
	const uint32_t dir_count = num_dirs < 16 ? num_dirs : 16;
	for (uint32_t d = 0; d < dir_count; ++d) {
		const size_t entry_off = dd_base + d * 8;
		if (entry_off + 8 > total) {
			break; // 截断的目录区按已读到的部分处理
		}
		view.dirs_[d].rva = read_le<uint32_t>(raw, entry_off, total);
		view.dirs_[d].size = read_le<uint32_t>(raw, entry_off + 4, total);
	}

	// 节表: 紧随OptionalHeader之后, 每项40字节
	const size_t sec_off = opt_off + opt_size;
	if (sec_off + static_cast<size_t>(num_sections) * 40 > total) {
		return false;
	}
	view.sections_.reserve(num_sections);
	for (uint16_t s = 0; s < num_sections; ++s) {
		const uint8_t *sh = raw + sec_off + s * 40;
		Section sec {};
		const char *name_ptr = reinterpret_cast<const char *>(sh);
		size_t name_len = 0;
		while (name_len < 8 && name_ptr[name_len] != '\0') {
			++name_len;
		}
		sec.name = std::string_view(name_ptr, name_len);
		sec.vsize = read_le<uint32_t>(sh, 8, total);
		sec.va = read_le<uint32_t>(sh, 12, total);
		sec.raw_size = read_le<uint32_t>(sh, 16, total);
		sec.raw_ptr = read_le<uint32_t>(sh, 20, total);
		sec.chars = read_le<uint32_t>(sh, 36, total);
		view.sections_.push_back(sec);
	}

	// overlay起始: 所有节段原始数据的末尾与头部长度取较大者(签名字符串即附加在此处之后)
	size_t overlay = sec_off + static_cast<size_t>(num_sections) * 40;
	for (const Section &sec : view.sections_) {
		const uint64_t end = static_cast<uint64_t>(sec.raw_ptr) + sec.raw_size;
		if (end > overlay && end <= total) { // 越过文件末尾的伪造raw_ptr不参与计算
			overlay = static_cast<size_t>(end);
		}
	}
	view.overlay_offset_ = overlay;

	out = std::move(view);
	return true;
}

const uint8_t *PeView::data() const {
	return bytes_.data();
}

size_t PeView::size() const {
	return bytes_.size();
}

bool PeView::is64() const {
	return is64_;
}

uint32_t PeView::entry_rva() const {
	return entry_rva_;
}

uint16_t PeView::section_count() const {
	return static_cast<uint16_t>(sections_.size());
}

const std::vector<PeView::Section> &PeView::sections() const {
	return sections_;
}

bool PeView::rva_to_offset(uint32_t rva, size_t &offset) const {
	for (const Section &section : sections_) {
		const uint64_t begin = section.va;
		const uint64_t span = std::max(section.vsize, section.raw_size);
		if (rva < begin || static_cast<uint64_t>(rva) - begin >= span) {
			continue;
		}
		const uint64_t result = static_cast<uint64_t>(section.raw_ptr) + rva - begin;
		// 用>=拒绝等于文件长度的末尾后一位: 该偏移无任何可读字节, 放行会迫使每个调用方自行再判一次
		if (result >= bytes_.size()) {
			return false;
		}
		offset = static_cast<size_t>(result);
		return true;
	}
	return false;
}

PeView::Dir PeView::data_dir(int index) const {
	if (index < 0 || index >= 16) {
		return { 0, 0 };
	}
	return dirs_[static_cast<size_t>(index)];
}

size_t PeView::overlay_offset() const {
	return overlay_offset_;
}

} // namespace starlight_v3::pe
