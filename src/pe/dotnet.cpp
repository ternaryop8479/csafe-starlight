/**
 * @file pe/dotnet.cpp
 * @brief CLR头与.NET元数据轻量解析及特征提取实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <array>
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

bool rva_to_file(const PeView &view, uint32_t rva, size_t &offset) {
	for (const auto &section : view.sections()) {
		const uint64_t begin = section.va;
		const uint64_t span = std::max(section.vsize, section.raw_size);
		if (rva >= begin && static_cast<uint64_t>(rva) - begin < span) {
			const uint64_t result = static_cast<uint64_t>(section.raw_ptr) + rva - begin;
			if (result <= view.size()) {
				offset = static_cast<size_t>(result);
				return offset <= view.size();
			}
		}
	}
	return false;
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

} // namespace

DotnetFeatPack extract_dotnet_feats(const PeView &view) {
	DotnetFeatPack feats = {};
	const PeView::Dir clr_dir = view.data_dir(kClrDirectory);
	if (clr_dir.rva == 0 || clr_dir.size < 16) return feats;

	size_t clr_offset = 0;
	if (!rva_to_file(view, clr_dir.rva, clr_offset) || clr_offset + 16 > view.size()) return feats;
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
	if (!rva_to_file(view, metadata_rva, metadata_offset) || metadata_offset + 20 > view.size()) return feats;
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

	// #~头部的Valid位图和Rows数组直接给出各元数据表行数, 无需知道列布局。
	if (tables == nullptr || tables_size < 24) return feats;
	const uint8_t heap_sizes = tables[6];
	(void)heap_sizes;
	const uint64_t valid = read<uint64_t>(tables, 8, tables_size);
	size_t rows_offset = 24;
	std::array<uint32_t, 45> rows = {};
	for (size_t table = 0; table < rows.size(); ++table) {
		if ((valid & (uint64_t(1) << table)) == 0) continue;
		if (rows_offset + 4 > tables_size) return feats;
		rows[table] = read<uint32_t>(tables, rows_offset, tables_size);
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
	return feats;
}

} // namespace starlight_v3::pe
