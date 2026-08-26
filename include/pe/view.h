/**
 * @file pe/view.h
 * @brief PE文件字节视图: 一次性读入并提供头/节表/数据目录/overlay的只读访问
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_PE_VIEW_H
#define CSAFE_STARLIGHT_V3_INCLUDE_PE_VIEW_H

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace starlight_v3::pe {

/**
 * @brief PE文件的只读解析视图
 *
 * 将整个文件一次性读入自有缓冲区，随后以零拷贝视图暴露DOS/NT头、节表、数据目录
 * 与overlay位置，供各静态特征提取模块共用，避免同一文件被反复读盘。
 * 所有偏移解析均带边界防御，畸形PE在load阶段即返回失败或得到安全的空视图。
 */
class PeView {

public:
	/**
	 * @brief 节段只读视图
	 */
	struct Section {
		std::string_view name; ///< 节名(去除尾部NUL, 直接指向文件缓冲区)
		uint32_t va; ///< VirtualAddress
		uint32_t vsize; ///< VirtualSize
		uint32_t raw_ptr; ///< PointerToRawData
		uint32_t raw_size; ///< SizeOfRawData
		uint32_t chars; ///< Characteristics
	};

	/**
	 * @brief 数据目录项视图
	 */
	struct Dir {
		uint32_t rva; ///< VirtualAddress
		uint32_t size; ///< Size
	};

	/**
	 * @brief 从指定路径加载并解析PE
	 * @param path 目标PE文件路径
	 * @param out 输出的视图对象, 成功时其内容被完全填充
	 * @return 是否为可解析的合法PE(非PE/截断/魔数非法均返回false)
	 */
	static bool load(const std::string &path, PeView &out);

	const uint8_t *data() const; ///< 文件完整字节(只读)
	size_t size() const; ///< 文件字节长度
	bool is64() const; ///< 是否为PE32+(OptionalHeaderMagic==0x20b)
	uint32_t entry_rva() const; ///< 入口点RVA(AddressOfEntryPoint)
	uint16_t section_count() const; ///< 节段数量(NumberOfSections)
	const std::vector<Section> &sections() const; ///< 节段视图列表
	Dir data_dir(int index) const; ///< 数据目录项(index∈[0,16), 越界返回{0,0})
	size_t overlay_offset() const; ///< overlay起始偏移(所有节段原始数据之后, 签名blob即位于此处)

private:
	std::vector<uint8_t> bytes_; ///< 文件完整字节缓冲区
	bool is64_ = false; ///< 是否为PE32+
	uint32_t entry_rva_ = 0; ///< 入口点RVA
	std::vector<Section> sections_; ///< 解析出的节段视图列表
	std::array<Dir, 16> dirs_ = {}; ///< 数据目录(最多16项, 未提供的项保持{0,0})
	size_t overlay_offset_ = 0; ///< overlay起始偏移
};

} // namespace starlight_v3::pe

#endif
