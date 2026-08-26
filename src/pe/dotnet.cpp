/**
 * @file pe/dotnet.cpp
 * @brief CLR头与.NET元数据轻量解析及特征提取实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>

#include "pe/dotnet.h"

namespace starlight_v3::pe {

namespace {

constexpr uint32_t kClrDirectory = 14;
constexpr uint32_t kIlOnly = 0x1;
constexpr uint32_t kRequires32Bit = 0x2;
constexpr uint32_t kStrongNameSigned = 0x8;
constexpr uint32_t kNativeEntryPoint = 0x10;

template<typename T>
T read(const uint8_t *data, size_t offset, size_t size) {
	if (offset > size || sizeof(T) > size - offset) return 0;
	T value = 0;
	std::memcpy(&value, data + offset, sizeof(T));
	return value;
}

double entropy(const uint8_t *data, size_t size) {
	if (data == nullptr || size == 0) return 0.0;
	std::array<size_t, 256> counts = {};
	for (size_t i = 0; i < size; ++i) ++counts[data[i]];
	double result = 0.0;
	for (size_t count : counts) {
		if (count == 0) continue;
		const double p = static_cast<double>(count) / static_cast<double>(size);
		result -= p * std::log2(p);
	}
	return result;
}

// 读取#US堆的压缩长度前缀(1/2/4字节变长), 成功返回消耗的字节数, 失败返回0
size_t read_compressed_uint(const uint8_t *data, size_t remain, uint32_t &value) {
	if (remain < 1) return 0;
	const uint8_t b0 = data[0];
	if ((b0 & 0x80) == 0) { value = b0; return 1; }
	if ((b0 & 0xC0) == 0x80) {
		if (remain < 2) return 0;
		value = (static_cast<uint32_t>(b0 & 0x3F) << 8) | data[1];
		return 2;
	}
	if (remain < 4) return 0;
	value = (static_cast<uint32_t>(b0 & 0x1F) << 24) | (static_cast<uint32_t>(data[1]) << 16) | (static_cast<uint32_t>(data[2]) << 8) | data[3];
	return 4;
}

// 已知.NET保护器特征串(仅在元数据/字符串堆中做静态存在性检测, 不作硬性恶意判定)
constexpr const char *kProtectorMarkers[] = {
	"ConfuserEx", "Confuser", ".NET Reactor", "Eziriz", "Dotfuscator",
	"SmartAssembly", "Obfuscar", "Eazfuscator", "Agile.NET", "SecureTeam",
	"CryptoObfuscator", "Babel"
};

bool contains_marker(const uint8_t *data, size_t size, const char *marker) {
	if (data == nullptr || size == 0) return false;
	const size_t marker_len = std::strlen(marker);
	if (marker_len == 0 || marker_len > size) return false;
	for (size_t i = 0; i + marker_len <= size; ++i) {
		if (std::memcmp(data + i, marker, marker_len) == 0) return true;
	}
	return false;
}

// MethodDef表在#~流中的布局(用于解析RVA列以定位IL方法体)
struct MethodDefLayout {
	size_t offset; ///< MethodDef表首行相对tables起始的偏移
	size_t row; ///< MethodDef单行字节宽
};

// tables_base为#~流中各表数据的起始偏移(即24字节头与Rows数组之后), 由调用方按Valid位图算出
bool compute_methoddef_layout(const std::array<uint32_t, 45> &rows, uint8_t heap_sizes, size_t tables_base, MethodDefLayout &out) {
	const size_t sidx = (heap_sizes & 0x01) ? 4 : 2; // #Strings索引宽
	const size_t gidx = (heap_sizes & 0x02) ? 4 : 2; // #GUID索引宽
	const size_t bidx = (heap_sizes & 0x04) ? 4 : 2; // #Blob索引宽
	auto ssize = [&](uint32_t table) { return rows[table] < 65536 ? size_t(2) : size_t(4); };
	auto csize = [](uint32_t max_rows) { return max_rows < 16384 ? size_t(2) : size_t(4); };
	size_t off = tables_base; // 表数据起点: #~头(24字节)与Rows数组之后, 漏算Rows会使所有列偏移整体前移
	off += static_cast<size_t>(rows[0]) * (2 + sidx + 3 * gidx); // Module
	{
		const uint32_t m = std::max({ rows[0], rows[26], rows[35], rows[1] }); // ResolutionScope
		off += static_cast<size_t>(rows[1]) * (csize(m) + 2 * sidx); // TypeRef
	}
	{
		const uint32_t m = std::max({ rows[2], rows[1], rows[27] }); // TypeDefOrRef
		off += static_cast<size_t>(rows[2]) * (4 + 2 * sidx + csize(m) + ssize(4) + ssize(6)); // TypeDef
	}
	off += static_cast<size_t>(rows[3]) * ssize(4); // FieldPtr
	off += static_cast<size_t>(rows[4]) * (2 + sidx + bidx); // Field
	off += static_cast<size_t>(rows[5]) * ssize(6); // MethodPtr
	out.offset = off;
	out.row = 4 + 2 + 2 + sidx + bidx + ssize(8); // MethodDef: RVA+ImplFlags+Flags+Name+Signature+ParamList
	return true;
}

} // namespace

DotnetFeatPack extract_dotnet_feats(const PeView &view) {
	DotnetFeatPack feats = {};
	const PeView::Dir clr_dir = view.data_dir(kClrDirectory);
	if (clr_dir.rva == 0 || clr_dir.size < 16) return feats;

	size_t clr_offset = 0;
	if (!view.rva_to_offset(clr_dir.rva, clr_offset) || clr_offset + 16 > view.size()) return feats;
	const uint8_t *data = view.data();
	const uint32_t clr_size = read<uint32_t>(data, clr_offset, view.size());
	const uint32_t flags = read<uint32_t>(data, clr_offset + 16, view.size());
	feats.present = 1.0;
	feats.il_only = (flags & kIlOnly) != 0;
	feats.requires_32bit = (flags & kRequires32Bit) != 0;
	feats.strong_name = (flags & kStrongNameSigned) != 0;
	feats.native_entrypoint = (flags & kNativeEntryPoint) != 0;

	// COR20字段: Metadata RVA/Size在头部偏移8/12, Resources RVA/Size在24/28。
	const uint32_t metadata_rva = read<uint32_t>(data, clr_offset + 8, view.size());
	const uint32_t metadata_size = read<uint32_t>(data, clr_offset + 12, view.size());
	const uint32_t resource_rva = read<uint32_t>(data, clr_offset + 24, view.size());
	const uint32_t resource_size = read<uint32_t>(data, clr_offset + 28, view.size());
	feats.managed_resource_size = resource_size;
	(void)clr_size;

	size_t metadata_offset = 0;
	if (!view.rva_to_offset(metadata_rva, metadata_offset) || metadata_offset + 20 > view.size()) return feats;
	if (read<uint32_t>(data, metadata_offset, view.size()) != 0x424A5342) return feats; // BSJB
	// metadata_size取自CLR头, 畸形样本可声明超出文件的长度; 后续各流边界均以它为准,
	// 故先夹到文件实际剩余字节, 否则流指针会指向文件外并在熵计算时越界读
	const uint32_t metadata_size_max = static_cast<uint32_t>(
		std::min<uint64_t>(view.size() - metadata_offset, 0xFFFFFFFFu));
	const uint32_t metadata_size_clamped = std::min(metadata_size, metadata_size_max);
	const uint32_t version_length = read<uint32_t>(data, metadata_offset + 12, view.size());
	const size_t version_end = metadata_offset + 16 + version_length;
	if (version_end + 4 > view.size() || version_end > metadata_offset + metadata_size_clamped) return feats;
	feats.metadata_version_length = version_length;
	feats.metadata_major = read<uint16_t>(data, metadata_offset + 4, view.size());
	feats.metadata_minor = read<uint16_t>(data, metadata_offset + 6, view.size());
	const uint16_t stream_count = read<uint16_t>(data, version_end + 2, view.size());
	feats.stream_count = stream_count;

	struct Stream { uint32_t offset = 0; uint32_t size = 0; std::string name; };
	std::vector<Stream> streams;
	size_t stream_header = version_end + 4;
	for (uint16_t i = 0; i < stream_count && stream_header + 8 <= view.size(); ++i) {
		Stream stream;
		stream.offset = read<uint32_t>(data, stream_header, view.size());
		stream.size = read<uint32_t>(data, stream_header + 4, view.size());
		stream_header += 8;
		while (stream_header < view.size() && data[stream_header] != 0) stream.name.push_back(static_cast<char>(data[stream_header++]));
		if (stream_header >= view.size()) return feats;
		++stream_header;
		while ((stream_header - (version_end + 4)) % 4 != 0) ++stream_header;
		if (stream.offset > metadata_size_clamped || stream.size > metadata_size_clamped - stream.offset) continue;
		streams.push_back(std::move(stream));
	}

	const uint8_t *strings = nullptr;
	const uint8_t *user_strings = nullptr;
	const uint8_t *blob = nullptr;
	uint32_t strings_size = 0, user_strings_size = 0, blob_size = 0, guid_size = 0;
	const uint8_t *tables = nullptr;
	uint32_t tables_size = 0;
	for (const Stream &stream : streams) {
		const uint8_t *ptr = data + metadata_offset + stream.offset;
		if (stream.name == "#Strings") { strings = ptr; strings_size = stream.size; }
		else if (stream.name == "#US") { user_strings = ptr; user_strings_size = stream.size; }
		else if (stream.name == "#Blob") { blob = ptr; blob_size = stream.size; }
		else if (stream.name == "#GUID") { guid_size = stream.size; }
		else if (stream.name == "#~" || stream.name == "#-") { tables = ptr; tables_size = stream.size; }
	}
	feats.strings_size = strings_size;
	feats.user_strings_size = user_strings_size;
	feats.blob_size = blob_size;
	feats.guid_size = guid_size;
	if (strings != nullptr) feats.strings_entropy = entropy(strings, strings_size);
	if (user_strings != nullptr) feats.user_strings_entropy = entropy(user_strings, user_strings_size);
	(void)resource_rva;
	(void)resource_size;

	// #Strings堆逐字符串统计(名称/符号来源), 用于区分正常命名与混淆命名
	if (strings != nullptr) {
		size_t off = 0;
		size_t len_sum = 0, len_max = 0, long_cnt = 0, short_cnt = 0, high_entropy_cnt = 0;
		double digit_sum = 0.0, non_ascii_sum = 0.0;
		while (off < strings_size) {
			const size_t remaining = strings_size - off;
			size_t len = 0;
			while (len < remaining && strings[off + len] != 0) ++len;
			if (len == 0) { ++off; continue; }
			++feats.strings_count;
			len_sum += len;
			len_max = std::max(len_max, len);
			if (len >= 30) ++long_cnt;
			if (len <= 3) ++short_cnt;
			size_t digits = 0, non_ascii = 0;
			for (size_t i = 0; i < len; ++i) {
				const uint8_t c = strings[off + i];
				if (c >= '0' && c <= '9') ++digits;
				if (c >= 0x80) ++non_ascii;
			}
			digit_sum += static_cast<double>(digits) / static_cast<double>(len);
			non_ascii_sum += static_cast<double>(non_ascii) / static_cast<double>(len);
			if (entropy(strings + off, len) > 4.5) ++high_entropy_cnt;
			off += len + 1;
		}
		if (feats.strings_count > 0) {
			feats.strings_length_mean = static_cast<double>(len_sum) / feats.strings_count;
			feats.strings_length_max = static_cast<double>(len_max);
			feats.strings_long_ratio = static_cast<double>(long_cnt) / feats.strings_count;
			feats.strings_short_ratio = static_cast<double>(short_cnt) / feats.strings_count;
			feats.strings_digit_ratio = digit_sum / feats.strings_count;
			feats.strings_non_ascii_ratio = non_ascii_sum / feats.strings_count;
			feats.strings_high_entropy_ratio = static_cast<double>(high_entropy_cnt) / feats.strings_count;
		}
	}

	// #US堆(用户字符串, UTF-16)逐条目统计
	if (user_strings != nullptr) {
		size_t off = 0;
		size_t len_sum = 0, long_cnt = 0;
		while (off < user_strings_size) {
			uint32_t byte_len = 0;
			const size_t used = read_compressed_uint(user_strings + off, user_strings_size - off, byte_len);
			if (used == 0 || byte_len > user_strings_size - off - used) break;
			const size_t chars = byte_len / 2; // UTF-16码元数(含尾标志字节的粗略口径)
			if (chars > 0) {
				++feats.user_strings_count;
				len_sum += chars;
				if (chars >= 30) ++long_cnt;
			}
			off += used + byte_len;
		}
		if (feats.user_strings_count > 0) {
			feats.user_strings_length_mean = static_cast<double>(len_sum) / feats.user_strings_count;
			feats.user_strings_long_ratio = static_cast<double>(long_cnt) / feats.user_strings_count;
		}
	}

	// 保护器标记检测: 在字符串堆与用户字符串堆中扫描已知特征串
	{
		double marker_count = 0.0;
		for (const char *marker : kProtectorMarkers) {
			if (contains_marker(strings, strings_size, marker) || contains_marker(user_strings, user_strings_size, marker)) {
				marker_count += 1.0;
			}
		}
		feats.protector_marker_count = marker_count;
	}

	// #~头部的Valid位图和Rows数组直接给出各元数据表行数, 无需知道列布局。
	if (tables == nullptr || tables_size < 24) return feats;
	const uint8_t heap_sizes = tables[6];
	const uint64_t valid = read<uint64_t>(tables, 8, tables_size);
	size_t rows_offset = 24;
	std::array<uint32_t, 45> rows = {};
	// Rows数组按Valid位图逐位排布, 必须遍历全部64位: 高于44的位虽无对应表, 但混淆器会置位,
	// 只统计低45位会低估Rows数组长度, 使后续表数据起点前移
	for (size_t table = 0; table < 64; ++table) {
		if ((valid & (uint64_t(1) << table)) == 0) continue;
		if (rows_offset + 4 > tables_size) return feats;
		const uint32_t row_count = read<uint32_t>(tables, rows_offset, tables_size);
		if (table < rows.size()) rows[table] = row_count;
		rows_offset += 4;
	}
	// HeapSizes位0x40标记Rows数组后存在4字节ExtraData(部分混淆器会写入)
	if ((heap_sizes & 0x40) != 0) {
		if (rows_offset + 4 > tables_size) return feats;
		rows_offset += 4;
	}
	feats.type_ref_rows = rows[1];
	feats.type_def_rows = rows[2];
	feats.field_rows = rows[4];
	feats.method_def_rows = rows[6];
	feats.member_ref_rows = rows[10];
	feats.custom_attribute_rows = rows[12];
	feats.assembly_ref_rows = rows[35];
	feats.resource_rows = rows[40];
	feats.module_rows = rows[0];
	feats.param_rows = rows[8];
	feats.interface_impl_rows = rows[9];
	feats.constant_rows = rows[11];
	feats.decl_security_rows = rows[14];
	feats.class_layout_rows = rows[15];
	feats.standalone_sig_rows = rows[17];
	feats.event_rows = rows[20];
	feats.property_rows = rows[23];
	feats.method_impl_rows = rows[25];
	feats.type_spec_rows = rows[27];
	feats.impl_map_rows = rows[28];
	feats.field_rva_rows = rows[29];
	feats.nested_class_rows = rows[41];
	feats.generic_param_rows = rows[42];
	feats.method_spec_rows = rows[43];
	feats.metadata_other_rows = static_cast<double>(rows[24] + rows[26] + rows[38] + rows[39] + rows[44]);

	// MethodDef IL体统计: 定位MethodDef表, 逐行读取RVA并解析tiny/fat方法体
	if (rows[6] > 0) {
		MethodDefLayout layout;
		if (compute_methoddef_layout(rows, heap_sizes, rows_offset, layout) && layout.row >= 8 && layout.offset < tables_size
			&& static_cast<size_t>(rows[6]) <= (tables_size - layout.offset) / layout.row) {
			size_t missing = 0, tiny = 0, fat = 0, zero_il = 0;
			double il_sum = 0.0;
			uint32_t il_max = 0, il_min = 0xFFFFFFFFu;
			size_t body_count = 0;
			for (uint32_t i = 0; i < rows[6]; ++i) {
				const uint32_t rva = read<uint32_t>(tables, layout.offset + static_cast<size_t>(i) * layout.row, tables_size);
				if (rva == 0) { ++missing; continue; }
				size_t body_off = 0;
				if (!view.rva_to_offset(rva, body_off) || body_off + 1 > view.size()) { ++missing; continue; }
				const uint8_t hdr = data[body_off];
				uint32_t il_size = 0;
				size_t header_size = 0;
				bool is_fat = false;
				if ((hdr & 0x3) == 0x2) { // tiny格式: 1字节头, 大小=首字节>>2
					il_size = hdr >> 2;
					header_size = 1;
				} else if ((hdr & 0x3) == 0x3) { // fat格式: 头长由flags高4位给出(以4字节为单位), 大小在偏移4
					// 越界时read返回0会被误记为"IL长度为0的合法方法体", 故先显式校验12字节头可读
					if (view.size() - body_off < 12) { ++missing; continue; }
					is_fat = true;
					il_size = read<uint32_t>(data, body_off + 4, view.size());
					header_size = static_cast<size_t>(read<uint16_t>(data, body_off, view.size()) >> 12) * 4;
					if (header_size < 12) { ++missing; continue; } // 头长小于fat头固定长度即为畸形
				} else {
					++missing; // 非tiny非fat, 视为不可解析
					continue;
				}
				// IL体必须完整落在文件内, 否则声明的长度不可信(畸形样本会写入近4GiB的假长度,
				// 直接计入会把均值/最大值污染成天文数字)
				if (view.size() - body_off < header_size || view.size() - body_off - header_size < il_size) {
					++missing;
					continue;
				}
				++body_count;
				if (is_fat) ++fat; else ++tiny;
				if (il_size == 0) ++zero_il;
				il_sum += il_size;
				il_max = std::max(il_max, il_size);
				il_min = std::min(il_min, il_size);
			}
			feats.method_body_count = static_cast<double>(body_count);
			feats.method_body_missing_ratio = static_cast<double>(missing) / static_cast<double>(rows[6]);
			feats.method_il_total_size = il_sum;
			if (body_count > 0) {
				feats.method_il_mean_size = il_sum / static_cast<double>(body_count);
				feats.method_il_max_size = il_max;
				feats.method_il_min_size = il_min;
				feats.method_tiny_body_ratio = static_cast<double>(tiny) / static_cast<double>(body_count);
				feats.method_fat_body_ratio = static_cast<double>(fat) / static_cast<double>(body_count);
				feats.method_il_zero_ratio = static_cast<double>(zero_il) / static_cast<double>(body_count);
			}
		}
	}
	return feats;
}

} // namespace starlight_v3::pe
