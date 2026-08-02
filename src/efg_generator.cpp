#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <queue>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <Zydis/Zydis.h>
#include <pe-parse/nt-headers.h>
#include <pe-parse/parse.h>

#include "basic/efg.h"
#include "efg_generator.h"

#ifndef ZYDIS_MAX_OPERAND_COUNT
#define ZYDIS_MAX_OPERAND_COUNT 10
#endif

#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#endif

namespace starlight_v3 {

// PE导入函数信息，包含DLL名、函数名及IAT地址
struct ImportInfo {
	std::string dll_name_;
	std::string func_name_;
	uint64_t iat_address_;
	uint64_t iat_rva_;
};

// 可执行代码段信息，包含段基址、大小、名称和原始字节
struct CodeSection {
	uint64_t base_rva_;
	uint32_t size_;
	std::string name_;
	std::vector<uint8_t> bytes_;
};

// PE文件解析器，解析PE文件并提取导入表与可执行段数据
class PEParser {
public:
	explicit PEParser(const std::string &file_path);
	~PEParser();
	PEParser(const PEParser &) = delete;
	PEParser &operator=(const PEParser &) = delete;

	bool parse();
	const std::vector<ImportInfo> &get_imports() const;
	const std::vector<CodeSection> &get_exec_sections() const;
	uint64_t get_entry_point() const;
	uint64_t get_image_base() const;
	bool is_64bit() const;

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

// PEParser内部实现，封装pe-parse相关数据和回调
struct PEParser::Impl {
	std::string file_path_;
	std::string file_name_;
	peparse::parsed_pe *pe_ = nullptr;
	std::vector<ImportInfo> imports_;
	std::vector<CodeSection> exec_sections_;
	uint64_t entry_point_rva_ = 0;
	uint64_t image_base_ = 0;
	bool is_64bit_ = false;

	static int import_callback(void *ctx, const peparse::VA &va,
		const std::string &module,
		const std::string &symbol);
	static int section_callback(void *ctx, const peparse::VA &,
		const std::string &sec_name,
		const peparse::image_section_header &sec,
		const peparse::bounded_buffer *sec_data);
};

// 导入表回调，将导入信息存入Impl对象
int PEParser::Impl::import_callback(void *ctx, const peparse::VA &va,
	const std::string &module,
	const std::string &symbol) {
	auto *impl = static_cast<Impl *>(ctx);
	ImportInfo info;
	info.dll_name_ = module;
	info.func_name_ = symbol;
	info.iat_address_ = va;
	info.iat_rva_ = va - impl->image_base_;
	impl->imports_.push_back(std::move(info));
	return 0;
}

// 段回调，提取可执行段数据
int PEParser::Impl::section_callback(void *ctx, const peparse::VA &,
	const std::string &sec_name,
	const peparse::image_section_header &sec,
	const peparse::bounded_buffer *sec_data) {
	auto *impl = static_cast<Impl *>(ctx);
	CodeSection cs;
	cs.base_rva_ = sec.VirtualAddress;
	cs.size_ = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
	cs.name_ = sec_name;
	if (sec_data && sec_data->buf && sec_data->bufLen > 0) {
		cs.bytes_.assign(sec_data->buf, sec_data->buf + sec_data->bufLen);
	}
	if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) && !cs.bytes_.empty()) {
		impl->exec_sections_.push_back(std::move(cs));
	}
	return 0;
}

PEParser::PEParser(const std::string &file_path)
	: impl_(std::make_unique<Impl>()) {
	impl_->file_path_ = file_path;
	size_t pos = file_path.find_last_of("/\\");
	impl_->file_name_ = (pos != std::string::npos)
		? file_path.substr(pos + 1)
		: file_path;
}

PEParser::~PEParser() {
	if (impl_ && impl_->pe_) {
		peparse::DestructParsedPE(impl_->pe_);
	}
}

bool PEParser::parse() {
	impl_->pe_ = peparse::ParsePEFromFile(impl_->file_path_.c_str());
	if (!impl_->pe_)
		return false;

	peparse::VA entry_va = 0;
	if (!peparse::GetEntryPoint(impl_->pe_, entry_va))
		return false;

	// 先判定PE格式再取image_base: PE32+的ImageBase在OptionalHeader64中是64位字段,
	// 若按PE32结构读取会把高32位截断, 导致入口/导入RVA全部算错
	impl_->is_64bit_ = (impl_->pe_->peHeader.nt.OptionalMagic == 0x20b);
	impl_->image_base_ = impl_->is_64bit_
		? impl_->pe_->peHeader.nt.OptionalHeader64.ImageBase
		: impl_->pe_->peHeader.nt.OptionalHeader.ImageBase;
	impl_->entry_point_rva_ = entry_va - impl_->image_base_;

	try {
		peparse::IterImpVAString(impl_->pe_, &Impl::import_callback, impl_.get());
	} catch (const std::range_error &e) {
		// 如果解析到一半出错了，就保留已经解析出来的导入表
	}
	try {
		peparse::IterSec(impl_->pe_, &Impl::section_callback, impl_.get());
	} catch (const std::range_error &e) {
		// 如果解析到一半出错了，就保留已经解析出来的节段
	}
	return true;
}

const std::vector<ImportInfo> &PEParser::get_imports() const {
	return impl_->imports_;
}

const std::vector<CodeSection> &PEParser::get_exec_sections() const {
	return impl_->exec_sections_;
}

uint64_t PEParser::get_entry_point() const {
	return impl_->entry_point_rva_;
}

uint64_t PEParser::get_image_base() const {
	return impl_->image_base_;
}

bool PEParser::is_64bit() const {
	return impl_->is_64bit_;
}

// 跳跃记录，记录控制流跳跃的RVA、跨度及是否为间接跳转
struct JumpRecord {
	uint64_t jump_rva_;
	int64_t span_;
	bool has_span_;
	bool is_indirect_;
};

// EFG内部节点数据，存储调用点RVA、API名和是否为入口节点
struct EFGNodeData {
	uint64_t call_rva_;
	std::string import_name_;
	bool is_entry_;
};

// EFG内部边数据，包含跳跃详情及统计信息
struct EFGEdgeData {
	uint64_t from_call_index_;
	uint64_t to_node_index_;
	std::vector<JumpRecord> jumps_;
	int jump_count_ = 0;
	int indirect_jump_count_ = 0;
	double avg_span_ = 0.0;
	double span_variance_ = 0.0;
	int spans_with_data_ = 0;
};

// EFG构建器，从已解析的PE数据构建外部调用流程图
class EFGBuilder {
public:
	explicit EFGBuilder(const PEParser &parser);
	~EFGBuilder();
	EFGBuilder(const EFGBuilder &) = delete;
	EFGBuilder &operator=(const EFGBuilder &) = delete;

	EFG build();

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

// EFGBuilder内部实现，封装Zydis解码器和构建过程中的所有状态
struct EFGBuilder::Impl {
	static constexpr uint64_t ENTRY_NODE_RVA = 0xFFFFFFFF;

	explicit Impl(const PEParser &parser);

	void build_global_efg();
	void add_or_update_edge(uint64_t from, uint64_t to,
		const std::vector<JumpRecord> &jumps);
	bool get_call_target(uint64_t rva,
		const ZydisDecodedInstruction &instr,
		const ZydisDecodedOperand *op_buf,
		uint64_t &target_rva, bool &is_import,
		std::string &imp_name);
	bool decode_at(uint64_t rva, ZydisDecodedInstruction &instr,
		ZydisDecodedOperand *operands);
	bool is_executable_rva(uint64_t rva);
	void preprocess_thunks(const std::vector<uint8_t> &code,
		uint64_t code_base);
	EFG to_efg();

	const PEParser &parser_;
	uint64_t image_base_;
	ZydisDecoder decoder_;
	std::unordered_map<uint64_t, std::string> iat_by_rva_;
	std::unordered_map<uint64_t, std::string> iat_by_va_;
	std::unordered_map<uint64_t, std::string> thunk_by_rva_;
	std::unordered_map<uint64_t, EFGNodeData> api_nodes_;
	std::map<std::pair<uint64_t, uint64_t>, EFGEdgeData> api_edges_;
};

EFGBuilder::Impl::Impl(const PEParser &parser)
	: parser_(parser), image_base_(parser.get_image_base()) {
	const ZydisMachineMode machine = parser_.is_64bit()
		? ZYDIS_MACHINE_MODE_LONG_64
		: ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
	const ZydisStackWidth stack_width = parser_.is_64bit()
		? ZYDIS_STACK_WIDTH_64
		: ZYDIS_STACK_WIDTH_32;
	ZydisDecoderInit(&decoder_, machine, stack_width);

	for (const auto &imp : parser_.get_imports()) {
		const std::string name = imp.dll_name_ + "!" + imp.func_name_;
		iat_by_rva_[imp.iat_rva_] = name;
		iat_by_va_[imp.iat_address_] = name;
	}

	for (const auto &sec : parser_.get_exec_sections()) {
		preprocess_thunks(sec.bytes_, sec.base_rva_);
	}
}

void EFGBuilder::Impl::build_global_efg() {
	api_nodes_[ENTRY_NODE_RVA] = { ENTRY_NODE_RVA, "ENTRY", true };

	struct State {
		uint64_t rva;
		uint64_t prev_api;
		std::vector<JumpRecord> jumps;
	};

	std::queue<State> worklist;
	worklist.push({ parser_.get_entry_point(), ENTRY_NODE_RVA, {} });

	std::unordered_map<uint64_t, std::unordered_set<uint64_t>> visited_states;
	int state_limit = 5000000;

	while (!worklist.empty() && state_limit-- > 0) {
		State state = std::move(worklist.front());
		worklist.pop();

		uint64_t rva = state.rva;
		uint64_t prev_api = state.prev_api;

		if (visited_states[rva].count(prev_api))
			continue;
		visited_states[rva].insert(prev_api);

		if (!is_executable_rva(rva))
			continue;

		ZydisDecodedInstruction instr {};
		ZydisDecodedOperand op_buf[ZYDIS_MAX_OPERAND_COUNT];
		if (!decode_at(rva, instr, op_buf))
			continue;

		uint64_t next_rva = rva + instr.length;
		uint64_t target_rva = 0;
		bool is_import = false;
		std::string imp_name;
		bool has_target = get_call_target(rva, instr, op_buf,
			target_rva, is_import, imp_name);

		if (instr.meta.category == ZYDIS_CATEGORY_CALL && is_import) {
			api_nodes_[rva] = { rva, imp_name, false };
			add_or_update_edge(prev_api, rva, state.jumps);
			worklist.push({ next_rva, rva, {} });
			continue;
		}

		if (instr.meta.category == ZYDIS_CATEGORY_CALL && has_target && is_executable_rva(target_rva)) {
			worklist.push({ target_rva, prev_api, state.jumps });
			worklist.push({ next_rva, prev_api, std::move(state.jumps) });
			continue;
		}

		if (instr.meta.category == ZYDIS_CATEGORY_RET) {
			continue;
		}

		if (instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
			if (has_target && is_executable_rva(target_rva)) {
				bool is_direct = false;
				for (uint8_t i = 0; i < instr.operand_count_visible; ++i) {
					if (op_buf[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
						is_direct = true;
						break;
					}
				}
				state.jumps.push_back({ rva,
					is_direct ? std::abs(static_cast<int64_t>(target_rva) - static_cast<int64_t>(rva))
							  : 0,
					is_direct,
					!is_direct });
				worklist.push({ target_rva, prev_api, std::move(state.jumps) });
			}
			continue;
		}

		if (instr.meta.category == ZYDIS_CATEGORY_COND_BR) {
			if (has_target && is_executable_rva(target_rva)) {
				bool is_direct = false;
				for (uint8_t i = 0; i < instr.operand_count_visible; ++i) {
					if (op_buf[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
						is_direct = true;
						break;
					}
				}
				auto jumps_copy = state.jumps;
				jumps_copy.push_back({ rva,
					is_direct ? std::abs(static_cast<int64_t>(target_rva) - static_cast<int64_t>(rva))
							  : 0,
					is_direct,
					!is_direct });
				worklist.push({ target_rva, prev_api, jumps_copy });
			}
			worklist.push({ next_rva, prev_api, std::move(state.jumps) });
			continue;
		}

		worklist.push({ next_rva, prev_api, std::move(state.jumps) });
	}
}

void EFGBuilder::Impl::add_or_update_edge(
	uint64_t from, uint64_t to,
	const std::vector<JumpRecord> &jumps) {
	if (from == 0 || to == 0)
		return;
	auto &edge = api_edges_[{ from, to }];
	edge.from_call_index_ = from;
	edge.to_node_index_ = to;

	for (const auto &j : jumps) {
		edge.jumps_.push_back(j);
	}

	edge.jump_count_ = static_cast<int>(edge.jumps_.size());
	edge.indirect_jump_count_ = static_cast<int>(
		std::count_if(edge.jumps_.begin(), edge.jumps_.end(),
			[](const JumpRecord &j) {
				return j.is_indirect_;
			}));
	edge.spans_with_data_ = static_cast<int>(
		std::count_if(edge.jumps_.begin(), edge.jumps_.end(),
			[](const JumpRecord &j) {
				return j.has_span_;
			}));

	if (edge.spans_with_data_ > 0) {
		double sum = 0;
		for (const auto &j : edge.jumps_) {
			if (j.has_span_)
				sum += j.span_;
		}
		edge.avg_span_ = sum / edge.spans_with_data_;
		double sq_sum = 0;
		for (const auto &j : edge.jumps_) {
			if (j.has_span_) {
				sq_sum += (j.span_ - edge.avg_span_) * (j.span_ - edge.avg_span_);
			}
		}
		edge.span_variance_ = sq_sum / edge.spans_with_data_;
	}
}

bool EFGBuilder::Impl::get_call_target(
	uint64_t rva,
	const ZydisDecodedInstruction &instr,
	const ZydisDecodedOperand *op_buf,
	uint64_t &target_rva, bool &is_import,
	std::string &imp_name) {
	for (uint8_t i = 0; i < instr.operand_count_visible; ++i) {
		const auto &op = op_buf[i];
		if (!(op.actions & ZYDIS_OPERAND_ACTION_READ))
			continue;

		if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			if (op.imm.is_relative) {
				target_rva = rva + instr.length + (op.imm.is_signed ? op.imm.value.s : op.imm.value.u);
			} else {
				target_rva = op.imm.value.u - image_base_;
			}
			if (thunk_by_rva_.count(target_rva)) {
				is_import = true;
				imp_name = thunk_by_rva_.at(target_rva);
			}
			return true;
		}

		if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
			if (op.mem.base == ZYDIS_REGISTER_RIP) {
				target_rva = rva + instr.length + op.mem.disp.value;
				if (iat_by_rva_.count(target_rva)) {
					is_import = true;
					imp_name = iat_by_rva_.at(target_rva);
					return true;
				}
			} else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.disp.has_displacement) {
				uint64_t eff_va = op.mem.disp.value;
				target_rva = (eff_va >= image_base_)
					? (eff_va - image_base_)
					: eff_va;
				if (iat_by_va_.count(eff_va)) {
					is_import = true;
					imp_name = iat_by_va_.at(eff_va);
					return true;
				}
			}
			return false;
		}
	}
	return false;
}

bool EFGBuilder::Impl::decode_at(
	uint64_t rva,
	ZydisDecodedInstruction &instr,
	ZydisDecodedOperand *operands) {
	for (const auto &sec : parser_.get_exec_sections()) {
		if (rva >= sec.base_rva_ && rva < sec.base_rva_ + sec.size_) {
			size_t offset = rva - sec.base_rva_;
			// VirtualSize > SizeOfRawData 的节段(虚拟填充/.bss/截断文件)可能没有原始字节,
			// 此时 data()+offset 越过缓冲区、size()-offset 下溢, 必须拒绝
			if (offset >= sec.bytes_.size()) {
				return false;
			}
			return ZYAN_SUCCESS(ZydisDecoderDecodeFull(
				&decoder_,
				sec.bytes_.data() + offset,
				sec.bytes_.size() - offset,
				&instr, operands));
		}
	}
	return false;
}

bool EFGBuilder::Impl::is_executable_rva(uint64_t rva) {
	for (const auto &sec : parser_.get_exec_sections()) {
		if (rva >= sec.base_rva_ && rva < sec.base_rva_ + sec.size_)
			return true;
	}
	return false;
}

void EFGBuilder::Impl::preprocess_thunks(
	const std::vector<uint8_t> &code,
	uint64_t code_base) {
	size_t offset = 0;
	while (offset < code.size()) {
		ZydisDecodedInstruction instr {};
		ZydisDecodedOperand op_buf[ZYDIS_MAX_OPERAND_COUNT];
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
				&decoder_, code.data() + offset,
				code.size() - offset, &instr, op_buf))) {
			offset++;
			continue;
		}
		if (instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
			for (uint8_t i = 0; i < instr.operand_count_visible; ++i) {
				const auto &op = op_buf[i];
				if (!(op.actions & ZYDIS_OPERAND_ACTION_READ))
					continue;
				uint64_t target_rva = 0;
				bool is_import = false;
				std::string imp_name;
				if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
					if (op.mem.base == ZYDIS_REGISTER_RIP) {
						target_rva = code_base + offset + instr.length + op.mem.disp.value;
						if (iat_by_rva_.count(target_rva)) {
							is_import = true;
							imp_name = iat_by_rva_.at(target_rva);
						}
					} else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.disp.has_displacement) {
						uint64_t target_va = op.mem.disp.value;
						if (iat_by_va_.count(target_va)) {
							is_import = true;
							imp_name = iat_by_va_.at(target_va);
							target_rva = target_va - image_base_;
						}
					}
				}
				if (is_import) {
					thunk_by_rva_[code_base + offset] = imp_name;
				}
				break;
			}
		}
		offset += instr.length;
	}
}

EFG EFGBuilder::Impl::to_efg() {
	EFG efg;

	// 收集所有已经被EFG引用的导入函数名（即被调用过的导入函数）
	std::unordered_set<std::string> used_import_names;
	for (const auto &[rva, node] : api_nodes_) {
		if (!node.is_entry_) {
			used_import_names.insert(node.import_name_);
		}
	}

	// 为每个存在导入表中但未被调用的函数创建孤立节点，作为单独的连通分量
	constexpr uint64_t IMPORT_NODE_BASE = 0x100000000ULL;
	std::unordered_set<std::string> added_unused_imports;
	for (const auto &imp : parser_.get_imports()) {
		const std::string name = imp.dll_name_ + "!" + imp.func_name_;
		if (used_import_names.count(name) > 0) {
			continue;
		}
		if (added_unused_imports.count(name) > 0) {
			continue; // 去重，避免多次添加同名导入
		}
		uint64_t node_rva = IMPORT_NODE_BASE + imp.iat_rva_;
		api_nodes_[node_rva] = { node_rva, name, false };
		added_unused_imports.insert(name);
	}

	// 收集所有节点RVA
	std::vector<uint64_t> node_rvas;
	node_rvas.reserve(api_nodes_.size());
	for (const auto &[rva, node] : api_nodes_) {
		node_rvas.push_back(rva);
	}

	// ROOT节点（0xFFFFFFFF）排在第0位，其余按RVA排序保证确定性
	auto root_it = std::find(node_rvas.begin(), node_rvas.end(), ENTRY_NODE_RVA);
	if (root_it != node_rvas.end() && root_it != node_rvas.begin()) {
		std::iter_swap(root_it, node_rvas.begin());
	}
	std::sort(node_rvas.begin() + 1, node_rvas.end());

	// 构建RVA到节点索引的映射
	std::unordered_map<uint64_t, SIZE_T> rva_to_index;
	rva_to_index.reserve(node_rvas.size());
	for (SIZE_T i = 0; i < static_cast<SIZE_T>(node_rvas.size()); ++i) {
		rva_to_index[node_rvas[i]] = i;
	}

	// 插入API名，获取ID，直接存入 nodes_ 数组
	efg.nodes_.reserve(node_rvas.size());
	for (uint64_t rva : node_rvas) {
		const auto &node = api_nodes_.at(rva);
		efg.api_table_.insert(node.import_name_);
		auto result = efg.api_table_.query_id(node.import_name_);
		if (result.first) {
			efg.nodes_.push_back(result.second);
		} else {
			efg.nodes_.push_back(INVALID_NUM);
		}
	}

	// 构建边，将源节点和目标节点的索引存入边结构
	struct EdgeEntry {
		SIZE_T from_index;
		SIZE_T to_index;
		const EFGEdgeData *edge_ptr;
	};
	std::vector<EdgeEntry> edge_entries;
	edge_entries.reserve(api_edges_.size());
	for (const auto &[pair, edge] : api_edges_) {
		auto from_it = rva_to_index.find(edge.from_call_index_);
		auto to_it = rva_to_index.find(edge.to_node_index_);
		if (from_it == rva_to_index.end() || to_it == rva_to_index.end()) {
			continue;
		}
		edge_entries.push_back({ from_it->second, to_it->second, &edge });
	}

	// 按源节点索引排序，符合CSR格式规范
	std::sort(edge_entries.begin(), edge_entries.end(),
		[](const EdgeEntry &a, const EdgeEntry &b) {
			if (a.from_index != b.from_index)
				return a.from_index < b.from_index;
			return a.to_index < b.to_index;
		});

	// 构建 CSR 的 offset 数组
	SIZE_T num_nodes = static_cast<SIZE_T>(node_rvas.size());
	efg.offeset_.resize(num_nodes + 1, 0);
	for (const auto &entry : edge_entries) {
		efg.offeset_[entry.from_index + 1]++;
	}
	for (SIZE_T i = 1; i <= num_nodes; ++i) {
		efg.offeset_[i] += efg.offeset_[i - 1];
	}

	// 填充 edges 数组
	efg.edges_.resize(edge_entries.size());
	std::vector<SIZE_T> cursor(num_nodes, 0);
	for (const auto &entry : edge_entries) {
		SIZE_T pos = efg.offeset_[entry.from_index] + cursor[entry.from_index];
		++cursor[entry.from_index];
		const auto *edge = entry.edge_ptr;

		// 直接存节点的索引，外部遍历时就用这个索引去 nodes_ 里取 API ID
		efg.edges_[pos].to_node_index = entry.to_index;
		efg.edges_[pos].jump_count = static_cast<SIZE_T>(edge->jump_count_);
		efg.edges_[pos].indirect_jump_count = static_cast<SIZE_T>(edge->indirect_jump_count_);
		efg.edges_[pos].avg_span = edge->avg_span_;
		efg.edges_[pos].span_variance = edge->span_variance_;
		efg.edges_[pos].spans_with_data = static_cast<SIZE_T>(edge->spans_with_data_);
	}

	return efg;
}

EFGBuilder::EFGBuilder(const PEParser &parser)
	: impl_(std::make_unique<Impl>(parser)) {
}

EFGBuilder::~EFGBuilder() = default;

EFG EFGBuilder::build() {
	impl_->build_global_efg();
	return impl_->to_efg();
}

std::pair<bool, EFG> generate_efg(const std::string &file_path) {
	PEParser parser(file_path);
	if (!parser.parse()) {
		return { false, EFG {} };
	}

	if (parser.get_exec_sections().empty() || parser.get_entry_point() == 0) {
		return { false, EFG {} };
	}

	EFGBuilder builder(parser);
	EFG efg = builder.build();

	return { true, std::move(efg) };
}

} // namespace starlight_v3
