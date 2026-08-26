/**
 * @file model.cpp
 * @brief 最终模型序列化实现
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>

#include "model.h"

namespace {

// 模型文件的魔数(自适应长度: 以'\0'结尾, 读取时按strlen取实际长度, 后续魔数变长无需改读取逻辑)
constexpr char MODEL_MAGIC[] = { 'C', 'S', 'T', 'A', 'R', 'L', '3', 'A', '\0' };

// 二进制写缓冲, 所有写入均使用固定宽度类型(uint32_t/uint64_t/double)
class BufferWriter {
public:
	std::string data; ///< 序列化产物

	template <typename T>
	void put(T value) {
		data.append(reinterpret_cast<const char *>(&value), sizeof(T));
	}

	// 写入字符串: 4字节长度 + 原始字节
	void put_string(const std::string &str) {
		put(static_cast<uint32_t>(str.size()));
		data.append(str);
	}
};

// 二进制读缓冲, 读取时带越界检查
class BufferReader {
public:
	const char *ptr; ///< 当前读取位置
	const char *end; ///< 缓冲末尾

	explicit BufferReader(const std::string &data) : ptr(data.data()), end(data.data() + data.size()) {
	}

	// 读取一个固定宽度类型, 越界返回false
	template <typename T>
	bool get(T &value) {
		if (ptr + sizeof(T) > end) {
			return false;
		}
		std::memcpy(&value, ptr, sizeof(T));
		ptr += sizeof(T);
		return true;
	}

	// 读取字符串, 越界返回false
	bool get_string(std::string &str) {
		uint32_t length = 0;
		if (!get(length)) {
			return false;
		}
		if (ptr + length > end) {
			return false;
		}
		str.assign(ptr, length);
		ptr += length;
		return true;
	}
};

// 序列化tosSPM模型到二进制缓冲
std::string serialize_tspm_model(const starlight_v3::tspm::Model &model) {
	BufferWriter writer;

	// API映射表: 数量 + 每个API名字(4字节长度 + 字节)
	const std::vector<std::string> &table = model.api_table.get_table();
	writer.put(static_cast<uint64_t>(table.size()));
	for (const std::string &name : table) {
		writer.put_string(name);
	}

	// Trie树节点: 数量 + 每个节点(api_id + trans_start + trans_count + weight)
	writer.put(static_cast<uint64_t>(model.nodes.size()));
	for (const starlight_v3::tspm::TrieNode &node : model.nodes) {
		writer.put(static_cast<uint32_t>(node.api_id));
		writer.put(static_cast<uint32_t>(node.trans_start));
		writer.put(static_cast<uint32_t>(node.trans_count));
		writer.put(node.weight);
	}

	// Trie树边列表: 数量 + 每条边(目标节点在nodes数组中的索引)
	writer.put(static_cast<uint64_t>(model.edges.size()));
	for (starlight_v3::SIZE_T edge : model.edges) {
		writer.put(static_cast<uint32_t>(edge));
	}

	// 模型参数
	writer.put(model.max_skip);

	return writer.data;
}

// 从二进制缓冲反序列化tosSPM模型, 失败抛异常
starlight_v3::tspm::Model deserialize_tspm_model(BufferReader &reader) {
	starlight_v3::tspm::Model model;

	// API映射表
	uint64_t table_size = 0;
	if (!reader.get(table_size)) {
		throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (api table count)");
	}
	// 防御: 每个API名至少4字节长度前缀+1字节内容, 数量超界说明文件被篡改, 避免触发超大分配(bad_alloc/length_error)
	if (table_size > static_cast<uint64_t>(reader.end - reader.ptr) / 5u) {
		throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (api table count exceeds remaining data)");
	}
	std::vector<std::string> names(static_cast<size_t>(table_size));
	for (uint64_t i = 0; i < table_size; ++i) {
		if (!reader.get_string(names[static_cast<size_t>(i)])) {
			throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (api table content)");
		}
	}
	model.api_table = starlight_v3::APITable(names);

	// Trie树节点
	uint64_t node_count = 0;
	if (!reader.get(node_count)) {
		throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (node count)");
	}
	// 防御: 每个节点固定20字节(api_id+trans_start+trans_count各4字节+weight 8字节), 数量超界说明文件被篡改
	if (node_count > static_cast<uint64_t>(reader.end - reader.ptr) / 20u) {
		throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (node count exceeds remaining data)");
	}
	model.nodes.resize(static_cast<size_t>(node_count));
	for (uint64_t i = 0; i < node_count; ++i) {
		starlight_v3::tspm::TrieNode &node = model.nodes[static_cast<size_t>(i)];
		uint32_t api_id = 0, trans_start = 0, trans_count = 0;
		if (!reader.get(api_id) || !reader.get(trans_start) || !reader.get(trans_count) || !reader.get(node.weight)) {
			throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (node content)");
		}
		node.api_id = api_id;
		node.trans_start = trans_start;
		node.trans_count = trans_count;
	}

	// Trie树边列表
	uint64_t edge_count = 0;
	if (!reader.get(edge_count)) {
		throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (edge count)");
	}
	// 防御: 每条边固定4字节, 数量超界说明文件被篡改
	if (edge_count > static_cast<uint64_t>(reader.end - reader.ptr) / 4u) {
		throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (edge count exceeds remaining data)");
	}
	model.edges.resize(static_cast<size_t>(edge_count));
	for (uint64_t i = 0; i < edge_count; ++i) {
		uint32_t edge = 0;
		if (!reader.get(edge)) {
			throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (edge content)");
		}
		model.edges[static_cast<size_t>(i)] = edge;
	}

	// 模型参数
	if (!reader.get(model.max_skip)) {
		throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (model parameter)");
	}

	// 语义校验: 防止损坏/篡改的模型文件导致推理时越界读
	// 注意: Trie根节点的api_id为INVALID_NUM(哨兵值, 见src/tspm/trainer.cpp的模型生成), 需放行
	for (const starlight_v3::tspm::TrieNode &node : model.nodes) {
		if (node.api_id != starlight_v3::INVALID_NUM && node.api_id >= names.size()) {
			throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (node api_id out of api table range)");
		}
		if (static_cast<uint64_t>(node.trans_start) + static_cast<uint64_t>(node.trans_count) > model.edges.size()) {
			throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (node edge range out of edge list)");
		}
	}
	for (starlight_v3::SIZE_T edge : model.edges) {
		if (edge >= node_count) {
			throw std::runtime_error("Model::load_from_file(): tosSPM section corrupted (edge points to nonexistent node)");
		}
	}

	return model;
}

} // namespace

namespace starlight_v3 {

// 构造函数
Model::Model(const tspm::Model &tspm_model, const lgbm::Model &lgbm_model) : tspm_model_(tspm_model), lgbm_model_(lgbm_model) {
}

// 将两个模型一起保存到指定路径
bool Model::save_to_file(const std::string &path) const {
	// 先序列化tosSPM段
	std::string tspm_section = serialize_tspm_model(tspm_model_);

	// 组装最终文件内容
	std::string content;
	content.append(MODEL_MAGIC, sizeof(MODEL_MAGIC)); // 含结尾'\0', 构成自适应长度魔数
	content.append(reinterpret_cast<const char *>(&version_), sizeof(version_));
	const uint64_t tspm_len = static_cast<uint64_t>(tspm_section.size());
	content.append(reinterpret_cast<const char *>(&tspm_len), sizeof(tspm_len));
	content.append(tspm_section);
	const uint64_t lgbm_len = static_cast<uint64_t>(lgbm_model_.model_string.size());
	content.append(reinterpret_cast<const char *>(&lgbm_len), sizeof(lgbm_len));
	content.append(lgbm_model_.model_string);

	// 追加白签名表节(V3B格式): 长度前缀 + 表序列化字节
	const std::string sigtab_data = sig_table_.serialize();
	const uint64_t sigtab_len = static_cast<uint64_t>(sigtab_data.size());
	content.append(reinterpret_cast<const char *>(&sigtab_len), sizeof(sigtab_len));
	content.append(sigtab_data);

	// 一次性写入文件
	std::ofstream ofs(path, std::ios::binary);
	if (!ofs.is_open()) {
		return false;
	}
	ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
	if (!ofs.good()) {
		return false;
	}

	return true;
}

// 从指定路径加载模型文件
bool Model::load_from_file(const std::string &path) {
	// 读取整个文件内容
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs.is_open()) {
		return false;
	}
	std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

	BufferReader reader(content);

	// 校验魔数: 按'\0'结尾自适应读取长度, 兼容未来魔数变长
	constexpr size_t kMaxMagicLen = 32; // 魔数长度上限(防御: 超长魔数视为无效文件)
	const char *magic_start = reader.ptr;
	size_t magic_len = 0;
	while (magic_len < kMaxMagicLen && magic_len < static_cast<size_t>(reader.end - magic_start)
		&& magic_start[magic_len] != '\0') {
		++magic_len;
	}
	if (magic_len >= kMaxMagicLen || magic_len >= static_cast<size_t>(reader.end - magic_start)
		|| magic_start[magic_len] != '\0') {
		return false; // 未找到魔数终止符或超长, 无效
	}
	if (magic_len != std::strlen(MODEL_MAGIC) || std::memcmp(magic_start, MODEL_MAGIC, magic_len) != 0) {
		return false;
	}
	reader.ptr = magic_start + magic_len + 1; // 跳过魔数及其'\0'

	// 读取版本号(病毒库日期标记), 不校验匹配, 兼容任意日期训练的模型
	if (!reader.get(version_)) {
		return false;
	}

	// 读取tosSPM段
	uint64_t tspm_len = 0;
	if (!reader.get(tspm_len)) {
		return false;
	}
	if (reader.ptr + tspm_len > reader.end) {
		return false;
	}
	const char *tspm_end = reader.ptr + tspm_len;
	try {
		tspm_model_ = deserialize_tspm_model(reader);
	} catch (const std::exception &) {
		return false;
	}
	if (reader.ptr != tspm_end) {
		return false;
	}

	// 读取LightGBM段
	uint64_t lgbm_len = 0;
	if (!reader.get(lgbm_len)) {
		return false;
	}
	if (reader.ptr + lgbm_len > reader.end) {
		return false;
	}
	lgbm_model_.model_string.assign(reader.ptr, lgbm_len);
	reader.ptr += lgbm_len;

	// 白签名表节(V3B新增): 旧版模型可能没有该节, 剩余不足8字节时视为空表以兼容加载
	if (reader.end - reader.ptr >= static_cast<std::ptrdiff_t>(sizeof(uint64_t))) {
		uint64_t sigtab_len = 0;
		if (!reader.get(sigtab_len)) {
			return false;
		}
		if (reader.ptr + sigtab_len != reader.end) {
			return false;
		}
		sig_table_ = authenticode::Model::deserialize(std::string(reader.ptr, sigtab_len));
		reader.ptr += sigtab_len;
	} else {
		sig_table_ = authenticode::Model();
	}

	return true;
}

// 设置当前模型版本
void Model::change_version(int year, int month, int day) {
	year = year % 100; // 保留年份后两位
	version_ = year * 10000 + month * 100 + day; // 合成版本时间戳
}

// 获取当前模型版本
std::string Model::get_version() const {
	int year = version_ / 10000, month = version_ % 10000 / 100, day = version_ % 100;
	// 补零并返回
	std::string result;
	result += (year < 10) ? "0" : "";
	result += std::to_string(year);
	result += ".";
	result += (month < 10) ? "0" : "";
	result += std::to_string(month);
	result += ".";
	result += (day < 10) ? "0" : "";
	result += std::to_string(day);
	return result;
}

// 获取内部白签名表模型
const authenticode::Model &Model::sig_table() const {
	return sig_table_;
}

// 设置白签名表模型
void Model::set_sig_table(const authenticode::Model &sig_table) {
	sig_table_ = sig_table;
}

// 获取内部tosSPM模型
const tspm::Model &Model::tspm_model() const {
	return tspm_model_;
}

// 获取内部LightGBM模型
const lgbm::Model &Model::lgbm_model() const {
	return lgbm_model_;
}

} // namespace starlight_v3
