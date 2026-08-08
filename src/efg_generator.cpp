/**
 * @file efg_generator.cpp
 * @brief 程序的EFG提取器实现
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <queue>
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

// 最大允许500万状态，超过则会被截断
constexpr SIZE_T STATE_LIMIT = 5000000;

// PE导入函数信息，包含DLL名、函数名及IAT地址
struct ImportInfo {
	std::string func_name_; ///< 导入函数名(为空表示序号导入)
	uint64_t iat_address_; ///< 导入函数在IAT(导入地址表)中的虚拟地址
	uint64_t iat_rva_; ///< 导入函数在IAT中的相对虚拟地址(RVA)
};

// 可执行代码段信息，包含段基址、大小、名称和原始字节
struct CodeSection {
	uint64_t base_rva_; ///< 代码段的起始RVA
	uint32_t size_; ///< 代码段虚拟大小(用于RVA归属判断)
	std::string name_; ///< 代码段名称(如".text")
	std::vector<uint8_t> bytes_; ///< 代码段的原始字节(用于反汇编解码)
};

// PE文件解析器，解析PE文件并提取导入表与可执行段数据
class PEParser {
public:
	explicit PEParser(const std::string &file_path); ///< 构造函数: 记录文件路径
	~PEParser(); ///< 析构函数: 释放pe-parse解析产物
	PEParser(const PEParser &) = delete; ///< 禁止拷贝
	PEParser &operator=(const PEParser &) = delete; ///< 禁止赋值

	bool parse(); ///< 解析PE文件(提取导入表/可执行段/入口点), 失败返回false
	const std::vector<ImportInfo> &get_imports() const; ///< 获取解析出的导入函数列表
	const std::vector<CodeSection> &get_exec_sections() const; ///< 获取可执行代码段列表
	uint64_t get_entry_point() const; ///< 获取入口点RVA
	uint64_t get_image_base() const; ///< 获取镜像基址
	bool is_64bit() const; ///< 是否为PE32+格式

private:
	struct Impl;
	std::unique_ptr<Impl> impl_; ///< pimpl: 隐藏pe-parse相关内部状态
};

// PEParser内部实现，封装pe-parse相关数据和回调
struct PEParser::Impl {
	std::string file_path_; ///< 待解析的PE文件路径
	std::string file_name_; ///< 文件路径中的纯文件名(用于日志/调试)
	peparse::parsed_pe *pe_ = nullptr; ///< pe-parse解析产物(析构时释放)
	std::vector<ImportInfo> imports_; ///< 解析出的导入函数列表
	std::vector<CodeSection> exec_sections_; ///< 解析出的可执行代码段列表
	uint64_t entry_point_rva_ = 0; ///< 程序入口点RVA(由入口VA减去镜像基址得到)
	uint64_t image_base_ = 0; ///< 镜像基址(PE32+为64位, 详见parse())
	bool is_64bit_ = false; ///< 是否为PE32+(64位)格式

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
	info.func_name_ = symbol; ///< 记录函数名
	info.iat_address_ = va; ///< 记录IAT中的虚拟地址
	info.iat_rva_ = va - impl->image_base_; ///< 换算为RVA(供后续节段内查找)
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
	cs.base_rva_ = sec.VirtualAddress; ///< 记录段基址RVA
	cs.size_ = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData; ///< 虚拟大小优先, 缺失时退回原始数据大小
	cs.name_ = sec_name; ///< 记录段名
	if (sec_data && sec_data->buf && sec_data->bufLen > 0) {
		cs.bytes_.assign(sec_data->buf, sec_data->buf + sec_data->bufLen); ///< 拷贝段原始字节
	}
	// 仅收录可执行且带原始字节的段(供反汇编解码)
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
		peparse::DestructParsedPE(impl_->pe_); ///< 释放pe-parse分配的内存
	}
}

bool PEParser::parse() {
	// 解析PE文件, 失败(非PE或严重损坏)直接返回false
	impl_->pe_ = peparse::ParsePEFromFile(impl_->file_path_.c_str());
	if (!impl_->pe_)
		return false;

	// 获取入口点虚拟地址
	peparse::VA entry_va = 0;
	if (!peparse::GetEntryPoint(impl_->pe_, entry_va))
		return false;

	// 先判定PE格式再取image_base: PE32+的ImageBase在OptionalHeader64中是64位字段,
	//    若按PE32结构读取会把高32位截断, 导致入口/导入RVA全部算错
	impl_->is_64bit_ = (impl_->pe_->peHeader.nt.OptionalMagic == 0x20b);
	impl_->image_base_ = impl_->is_64bit_
		? impl_->pe_->peHeader.nt.OptionalHeader64.ImageBase
		: impl_->pe_->peHeader.nt.OptionalHeader.ImageBase;
	impl_->entry_point_rva_ = entry_va - impl_->image_base_;

	// 迭代提取导入表与节段, 异常统一在最小作用域内消化
	try {
		peparse::IterImpVAString(impl_->pe_, &Impl::import_callback, impl_.get());
	} catch (const std::exception &e) {
		// 如果解析到一半出错了，就保留已经解析出来的导入表
		// 注意: pe-parse可能抛出range_error/length_error/logic_error等, 统一在最小作用域内消化,
		// 防止恶意构造的PE文件异常逃逸导致整个推理/训练流程中断
	}
	try {
		peparse::IterSec(impl_->pe_, &Impl::section_callback, impl_.get());
	} catch (const std::exception &e) {
		// 如果解析到一半出错了，就保留已经解析出来的节段
		// 同上: 统一消化pe-parse的各类STL异常
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
	uint64_t jump_rva_; ///< 产生跳跃的指令所在RVA
	int64_t span_; ///< 跳跃跨度(目标RVA与当前RVA之差, 仅直接跳转有效)
	bool has_span_; ///< 是否为直接跳转(可直接计算跨度)
	bool is_indirect_; ///< 是否为间接跳转(寄存器/内存间接目标)
};

// EFG内部节点数据，存储调用点RVA、API名和是否为入口节点
struct EFGNodeData {
	uint64_t call_rva_; ///< 节点对应的调用点RVA(或ENTRY哨兵值)
	std::string import_name_; ///< 该节点命中的导入函数名(ENTRY节点为"ENTRY")
	bool is_entry_; ///< 是否为入口节点
};

// EFG内部边数据，包含跳跃详情及统计信息
struct EFGEdgeData {
	uint64_t from_call_index_; ///< 源节点RVA(调用点或ENTRY)
	uint64_t to_node_index_; ///< 目标节点RVA(被调用的导入函数)
	std::vector<JumpRecord> jumps_; ///< 该边累积的全部跳跃记录
	int jump_count_ = 0; ///< 跳跃总次数
	int indirect_jump_count_ = 0; ///< 其中间接跳跃的次数
	double avg_span_ = 0.0; ///< 直接跳跃的平均跨度
	double span_variance_ = 0.0; ///< 直接跳跃跨度的方差
	int spans_with_data_ = 0; ///< 携带跨度数据(直接跳转)的跳跃数
};

// EFG构建器，从已解析的PE数据构建外部调用流程图
class EFGBuilder {
public:
	explicit EFGBuilder(const PEParser &parser); ///< 构造函数: 初始化解码器与IAT映射并预处理thunk
	~EFGBuilder(); ///< 析构函数
	EFGBuilder(const EFGBuilder &) = delete; ///< 禁止拷贝
	EFGBuilder &operator=(const EFGBuilder &) = delete; ///< 禁止赋值

	EFG build(); ///< 执行构建: 遍历控制流生成节点与边, 输出CSR格式的EFG

private:
	struct Impl;
	std::unique_ptr<Impl> impl_; ///< pimpl: 隐藏构建内部状态
};

// EFGBuilder内部实现，封装Zydis解码器和构建过程中的所有状态
struct EFGBuilder::Impl {
	static constexpr uint64_t ENTRY_NODE_RVA = 0xFFFFFFFF; ///< 入口节点哨兵RVA(人为定义, 排第0位)

	explicit Impl(const PEParser &parser);

	void build_global_efg(); ///< 从入口点开始遍历控制流, 收集节点与边
	void add_or_update_edge(uint64_t from, uint64_t to,
		const std::vector<JumpRecord> &jumps); ///< 聚合(源,目标)边的跳跃记录并重算统计量
	bool get_call_target(uint64_t rva,
		const ZydisDecodedInstruction &instr,
		const ZydisDecodedOperand *op_buf,
		uint64_t &target_rva, bool &is_import,
		std::string &imp_name); ///< 解析调用/跳转目标(含IAT导入识别)
	bool decode_at(uint64_t rva, ZydisDecodedInstruction &instr,
		ZydisDecodedOperand *operands); ///< 在可执行段内解码rva处指令
	bool is_executable_rva(uint64_t rva); ///< 判断rva是否落在可执行段内
	void preprocess_thunks(const std::vector<uint8_t> &code,
		uint64_t code_base); ///< 预扫描识别"jmp [IAT]"thunk跳板
	EFG to_efg(); ///< 将内部节点/边数据转换为CSR格式的EFG

	const PEParser &parser_; ///< 解析器引用(只读, 生命周期由外部保证)
	uint64_t image_base_; ///< 镜像基址(用于绝对地址->RVA换算)
	ZydisDecoder decoder_; ///< Zydis反汇编解码器
	std::unordered_map<uint64_t, std::string> iat_by_rva_; ///< IAT的RVA->导入名映射
	std::unordered_map<uint64_t, std::string> iat_by_va_; ///< IAT的VA->导入名映射
	std::unordered_map<uint64_t, std::string> thunk_by_rva_; ///< thunk跳板RVA->导入名映射(预处理阶段收集)
	std::unordered_map<uint64_t, EFGNodeData> api_nodes_; ///< 节点RVA->节点数据
	std::map<std::pair<uint64_t, uint64_t>, EFGEdgeData> api_edges_; ///< (源,目标)RVA对->边数据
};

EFGBuilder::Impl::Impl(const PEParser &parser)
	: parser_(parser), image_base_(parser.get_image_base()) {
	// 根据PE位宽选择Zydis机器模式与栈宽度
	const ZydisMachineMode machine = parser_.is_64bit()
		? ZYDIS_MACHINE_MODE_LONG_64
		: ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
	const ZydisStackWidth stack_width = parser_.is_64bit()
		? ZYDIS_STACK_WIDTH_64
		: ZYDIS_STACK_WIDTH_32;
	ZydisDecoderInit(&decoder_, machine, stack_width);

	// 建立IAT地址到导入名的双向映射(RVA与VA两种查法)
	for (const auto &imp : parser_.get_imports()) {
		const std::string name = imp.func_name_;
		iat_by_rva_[imp.iat_rva_] = name;
		iat_by_va_[imp.iat_address_] = name;
	}

	// 预处理各可执行段, 识别"jmp [IAT]"形式的thunk跳板
	for (const auto &sec : parser_.get_exec_sections()) {
		preprocess_thunks(sec.bytes_, sec.base_rva_);
	}
}

void EFGBuilder::Impl::build_global_efg() {
	// 预置入口节点(哨兵RVA)
	api_nodes_[ENTRY_NODE_RVA] = { ENTRY_NODE_RVA, "ENTRY", true };

	// 工作队列状态: 当前待解码的RVA + 最近一个已建节点RVA + 途中累积的跳跃记录
	struct State {
		uint64_t rva;
		uint64_t prev_api;
		std::vector<JumpRecord> jumps;
	};

	std::queue<State> worklist;
	// 从入口点开始, prev_api初始为ENTRY节点
	worklist.push({ parser_.get_entry_point(), ENTRY_NODE_RVA, {} });

	// 去重表: 记录(rva, prev_api)组合是否已处理, 防止无限循环
	std::unordered_map<uint64_t, std::unordered_set<uint64_t>> visited_states;

	SIZE_T i = 0;
	while (!worklist.empty() && i++ < STATE_LIMIT) { // 状态上限防御(见STATE_LIMIT说明)
		State state = std::move(worklist.front());
		worklist.pop();

		uint64_t rva = state.rva;
		uint64_t prev_api = state.prev_api;

		// 该(rva, prev_api)组合已处理过则跳过
		if (visited_states[rva].count(prev_api))
			continue;
		visited_states[rva].insert(prev_api);

		// RVA不在任何可执行段内则跳过
		if (!is_executable_rva(rva))
			continue;

		// 反汇编当前指令
		ZydisDecodedInstruction instr {};
		ZydisDecodedOperand op_buf[ZYDIS_MAX_OPERAND_COUNT];
		if (!decode_at(rva, instr, op_buf))
			continue;

		uint64_t next_rva = rva + instr.length; // 顺序下一条指令
		uint64_t target_rva = 0;
		bool is_import = false;
		std::string imp_name;
		// 解析指令的调用/跳转目标(含是否命中IAT导入)
		bool has_target = get_call_target(rva, instr, op_buf,
			target_rva, is_import, imp_name);

		// 情形1: 直接调用导入函数 -> 建立"prev_api -> 该导入"节点与边, 并沿顺序流继续
		if (instr.meta.category == ZYDIS_CATEGORY_CALL && is_import) {
			api_nodes_[rva] = { rva, imp_name, false };
			add_or_update_edge(prev_api, rva, state.jumps);
			worklist.push({ next_rva, rva, {} });
			continue;
		}

		// 情形2: 调用代码内部目标(非导入) -> 同时追踪调用目标与顺序流, 共享prev_api与跳跃记录
		if (instr.meta.category == ZYDIS_CATEGORY_CALL && has_target && is_executable_rva(target_rva)) {
			worklist.push({ target_rva, prev_api, state.jumps });
			worklist.push({ next_rva, prev_api, std::move(state.jumps) });
			continue;
		}

		// 情形3: 函数返回 -> 结束当前追踪分支
		if (instr.meta.category == ZYDIS_CATEGORY_RET) {
			continue;
		}

		// 情形4: 无条件跳转 -> 记录跳跃(若目标可执行则追踪目标), 不再追踪顺序流
		if (instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
			if (has_target && is_executable_rva(target_rva)) {
				// 判断是否为直接跳转(存在立即数操作数)
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

		// 情形5: 条件跳转 -> 跳跃记录需保留副本(两分支共用), 同时追踪目标与顺序流
		if (instr.meta.category == ZYDIS_CATEGORY_COND_BR) {
			if (has_target && is_executable_rva(target_rva)) {
				bool is_direct = false;
				for (uint8_t i = 0; i < instr.operand_count_visible; ++i) {
					if (op_buf[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
						is_direct = true;
						break;
					}
				}
				auto jumps_copy = state.jumps; // 拷贝一份给跳转分支
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

		// 其他普通指令 -> 沿顺序流继续
		worklist.push({ next_rva, prev_api, std::move(state.jumps) });
	}
}

void EFGBuilder::Impl::add_or_update_edge(
	uint64_t from, uint64_t to,
	const std::vector<JumpRecord> &jumps) {
	// 忽略非法节点RVA(0既非ENTRY也非有效调用点)
	if (from == 0 || to == 0)
		return;
	// 以(源,目标)为键聚合边: 同一对节点多次出现时累积跳跃记录
	auto &edge = api_edges_[{ from, to }];
	edge.from_call_index_ = from;
	edge.to_node_index_ = to;

	// 追加本次收集的跳跃记录
	for (const auto &j : jumps) {
		edge.jumps_.push_back(j);
	}

	// 重新统计跳跃次数与间接跳转次数
	edge.jump_count_ = static_cast<int>(edge.jumps_.size());
	edge.indirect_jump_count_ = static_cast<int>(
		std::count_if(edge.jumps_.begin(), edge.jumps_.end(),
			[](const JumpRecord &j) {
				return j.is_indirect_;
			}));
	// 统计携带跨度数据(直接跳转)的跳跃数
	edge.spans_with_data_ = static_cast<int>(
		std::count_if(edge.jumps_.begin(), edge.jumps_.end(),
			[](const JumpRecord &j) {
				return j.has_span_;
			}));

	// 有直接跳转数据时计算平均跨度与跨度方差(总体方差)
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
	// 遍历指令的所有可见操作数, 寻找读取类操作数以解析调用/跳转目标
	for (uint8_t i = 0; i < instr.operand_count_visible; ++i) {
		const auto &op = op_buf[i];
		// 非读取操作数(如仅写入)不构成调用目标
		if (!(op.actions & ZYDIS_OPERAND_ACTION_READ))
			continue;

		// 立即数操作数: 相对目标按RIP相对计算, 绝对目标减去镜像基址换算为RVA
		if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			if (op.imm.is_relative) {
				target_rva = rva + instr.length + (op.imm.is_signed ? op.imm.value.s : op.imm.value.u);
			} else {
				target_rva = op.imm.value.u - image_base_;
			}
			// 若目标命中预处理收集的thunk跳板, 则判定为导入调用
			if (thunk_by_rva_.count(target_rva)) {
				is_import = true;
				imp_name = thunk_by_rva_.at(target_rva);
			}
			return true;
		}

		// 内存操作数: 解析有效地址并尝试命中IAT导入
		if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
			// RIP相对寻址: 有效地址 = 下一条指令RVA + 位移
			if (op.mem.base == ZYDIS_REGISTER_RIP) {
				target_rva = rva + instr.length + op.mem.disp.value;
				if (iat_by_rva_.count(target_rva)) {
					is_import = true;
					imp_name = iat_by_rva_.at(target_rva);
					return true;
				}
			}
			// 绝对寻址(无基址寄存器): 位移即有效VA, 换算为RVA后查IAT
			else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.disp.has_displacement) {
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
	// 在可执行段中定位rva, 找到所在段后偏移解码
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
	// 判断rva是否落在任一可执行段范围内
	for (const auto &sec : parser_.get_exec_sections()) {
		if (rva >= sec.base_rva_ && rva < sec.base_rva_ + sec.size_)
			return true;
	}
	return false;
}

void EFGBuilder::Impl::preprocess_thunks(
	const std::vector<uint8_t> &code,
	uint64_t code_base) {
	// 逐指令解码整个代码段, 识别"jmp [IAT]"形式的导入thunk跳板
	// 这类跳板是编译器为导入函数生成的间接跳转占位, 调用点call到跳板即等价于调用导入函数
	size_t offset = 0;
	while (offset < code.size()) {
		ZydisDecodedInstruction instr {};
		ZydisDecodedOperand op_buf[ZYDIS_MAX_OPERAND_COUNT];
		// 解码失败则单字节前进(容忍非代码数据), 成功则按指令长度前进
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
				&decoder_, code.data() + offset,
				code.size() - offset, &instr, op_buf))) {
			offset++;
			continue;
		}
		if (instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
			// 遍历操作数, 解析jmp的目标是否命中IAT
			for (uint8_t i = 0; i < instr.operand_count_visible; ++i) {
				const auto &op = op_buf[i];
				if (!(op.actions & ZYDIS_OPERAND_ACTION_READ))
					continue;
				uint64_t target_rva = 0;
				bool is_import = false;
				std::string imp_name;
				if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
					// RIP相对寻址: 目标RVA = 当前指令RVA + 长度 + 位移
					if (op.mem.base == ZYDIS_REGISTER_RIP) {
						target_rva = code_base + offset + instr.length + op.mem.disp.value;
						if (iat_by_rva_.count(target_rva)) {
							is_import = true;
							imp_name = iat_by_rva_.at(target_rva);
						}
					}
					// 绝对寻址: 位移即有效VA
					else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.disp.has_displacement) {
						uint64_t target_va = op.mem.disp.value;
						if (iat_by_va_.count(target_va)) {
							is_import = true;
							imp_name = iat_by_va_.at(target_va);
							target_rva = target_va - image_base_;
						}
					}
				}
				// 命中IAT则登记该thunk跳板RVA -> 导入名
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
		const std::string name = imp.func_name_;
		// 已被调用过则无需添加
		if (used_import_names.count(name) > 0) {
			continue;
		}
		if (added_unused_imports.count(name) > 0) {
			continue; // 去重，避免多次添加同名导入
		}
		// 孤立节点RVA使用高位基址+偏移, 与真实代码RVA区分
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
			continue; // 目标不是EFG节点(如未收录的RVA)则跳过
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

	// 构建 CSR 的 offset 数组(前缀和)
	SIZE_T num_nodes = static_cast<SIZE_T>(node_rvas.size());
	efg.offeset_.resize(num_nodes + 1, 0);
	for (const auto &entry : edge_entries) {
		efg.offeset_[entry.from_index + 1]++;
	}
	for (SIZE_T i = 1; i <= num_nodes; ++i) {
		efg.offeset_[i] += efg.offeset_[i - 1];
	}

	// 填充 edges 数组(按CSR的cursor定位写入位置)
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
	// 解析PE文件, 失败(非PE/严重损坏)返回空EFG
	PEParser parser(file_path);
	if (!parser.parse()) {
		return { false, EFG {} };
	}

	// 无可执行段或入口无效则无法构建调用图, 返回空EFG
	if (parser.get_exec_sections().empty() || parser.get_entry_point() == 0) {
		return { false, EFG {} };
	}

	// 构建EFG: 反汇编遍历控制流, 提取节点与边
	EFGBuilder builder(parser);
	EFG efg = builder.build();

	return { true, std::move(efg) };
}

} // namespace starlight_v3
