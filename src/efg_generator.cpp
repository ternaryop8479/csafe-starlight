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
#include <cstring>
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
#include "pe_compat.h"

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
	ParsedPECompat pe_compat_; ///< 兼容解析结果(仅修补路径持有文件字节，存活至本对象析构)
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
	// 解析PE文件，失败(非PE或严重损坏)或命中pe-parse已知缺陷时走兼容修补路径
	impl_->pe_compat_ = parse_pe_with_compat(impl_->file_path_);
	impl_->pe_ = impl_->pe_compat_.pe;
	if (!impl_->pe_) {
		return false;
	}

	// 获取入口点虚拟地址
	peparse::VA entry_va = 0;
	if (!peparse::GetEntryPoint(impl_->pe_, entry_va)) {
		return false;
	}

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

// 跳跃统计的在线聚合数据，O(1)拷贝/合并，避免为每条跳跃记录做堆分配
// 平均跨度与方差在构建结束时由各统计量一次换算(E[x]与E[x^2]式)
struct JumpStats {
	int jump_count = 0; ///< 跳跃总次数
	int indirect_jump_count = 0; ///< 其中间接跳跃的次数
	int spans_with_data = 0; ///< 携带跨度数据(直接跳转)的跳跃数
	double sum_span = 0.0; ///< 直接跳跃跨度之和
	double sum_sq_span = 0.0; ///< 直接跳跃跨度平方之和(用于方差换算)
};

// EFG内部节点数据，存储调用点RVA、API名和是否为入口节点
struct EFGNodeData {
	uint64_t call_rva_; ///< 节点对应的调用点RVA(或ENTRY哨兵值)
	std::string import_name_; ///< 该节点命中的导入函数名(ENTRY节点为"ENTRY")
	bool is_entry_; ///< 是否为入口节点
};

// EFG内部边数据，汇总跳跃统计信息
struct EFGEdgeData {
	int jump_count_ = 0; ///< 跳跃总次数
	int indirect_jump_count_ = 0; ///< 其中间接跳跃的次数
	int spans_with_data_ = 0; ///< 携带跨度数据(直接跳转)的跳跃数
	double sum_span_ = 0.0; ///< 直接跳跃跨度之和
	double sum_sq_span_ = 0.0; ///< 直接跳跃跨度平方之和
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
		const JumpStats &stats); ///< 聚合(源,目标)边的跳跃统计量
	static uint64_t edge_key(uint64_t from, uint64_t to); ///< 打包(源,目标)RVA为64位键
	static void record_jump(JumpStats &stats, uint64_t rva,
		uint64_t target_rva, const ZydisDecodedInstruction &instr,
		const ZydisDecodedOperand *op_buf); ///< 将一次跳跃计入在线统计
	bool get_call_target(uint64_t rva,
		const ZydisDecodedInstruction &instr,
		const ZydisDecodedOperand *op_buf,
		uint64_t &target_rva, bool &is_import,
		std::string &imp_name); ///< 解析调用/跳转目标(含IAT导入识别)
	const CodeSection *find_section(uint64_t rva,
		size_t &out_offset) const; ///< 定位rva所在可执行段(未命中返回nullptr)
	bool decode_at(uint64_t rva, ZydisDecodedInstruction &instr,
		ZydisDecoderContext &context,
		const CodeSection *&sec_cache); ///< 在可执行段内解码rva处指令头(不含操作数), sec_cache为段定位缓存(沿顺序流复用)
	bool decode_operands(const ZydisDecodedInstruction &instr,
		const ZydisDecoderContext &context,
		ZydisDecodedOperand *operands); ///< 解码指令操作数(需与指令头共用context)
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
	std::unordered_map<uint64_t, EFGEdgeData> api_edges_; ///< 边键(打包源/目标RVA)->边数据
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

	// 工作队列状态: 当前待解码的RVA + 最近一个已建节点RVA + 途中累积的跳跃统计
	struct State {
		uint64_t rva;
		uint64_t prev_api;
		JumpStats jumps;
	};

	std::queue<State> worklist; // 要处理的解析入口

	// 如果有入口点的话，先push入口点到待处理的解析入口中
	if (parser_.get_entry_point() != 0) {
		worklist.push({ parser_.get_entry_point(), ENTRY_NODE_RVA, {} });
	}

	// push所有可执行段头部到待处理的解析入口中
	for (const auto &sec : parser_.get_exec_sections()) {
		worklist.push({ sec.base_rva_, ENTRY_NODE_RVA, {} });
	}

	// 去重表: 以打包键(rva, prev_api)记录组合是否已处理, 防止无限循环
	std::unordered_set<GREAT_SIZE_T> visited_states;
	visited_states.reserve(1 << 20);

	// 段定位缓存: 顺序流rva连续递增, 沿流程复用当前段免去逐指令段扫描
	const CodeSection *sec_cache = nullptr;

	SIZE_T i = 0;
	while (!worklist.empty() && i++ < STATE_LIMIT) { // 状态上限防御(见STATE_LIMIT说明)
		State state = worklist.front();
		worklist.pop();

		const uint64_t rva = state.rva;
		const uint64_t prev_api = state.prev_api;

		// 该(rva, prev_api)组合已处理过则跳过
		if (!visited_states.insert((static_cast<GREAT_SIZE_T>(rva) << 32) | prev_api).second) {
			continue;
		}

		// 仅解码指令头(不含操作数), context为后续按需解操作数保留
		ZydisDecodedInstruction instr {};
		ZydisDecoderContext context {};
		if (!decode_at(rva, instr, context, sec_cache)) {
			continue;
		}

		uint64_t next_rva = rva + instr.length; // 顺序下一条指令
		const ZydisInstructionCategory category = instr.meta.category;

		// 仅分支/调用类指令才需要解码操作数(普通指令占绝大多数, 可省去操作数解码开销)
		const bool is_branch_or_call = (category == ZYDIS_CATEGORY_CALL) || (category == ZYDIS_CATEGORY_UNCOND_BR) || (category == ZYDIS_CATEGORY_COND_BR);
		ZydisDecodedOperand op_buf[ZYDIS_MAX_OPERAND_COUNT];
		uint64_t target_rva = 0;
		bool is_import = false;
		std::string imp_name;
		bool has_target = false;
		if (is_branch_or_call && decode_operands(instr, context, op_buf)) {
			// 解析指令的调用/跳转目标(含是否命中IAT导入)
			has_target = get_call_target(rva, instr, op_buf,
				target_rva, is_import, imp_name);
		}

		// 情形1: 直接调用导入函数 -> 建立"prev_api -> 该导入"节点与边, 并沿顺序流继续
		if (category == ZYDIS_CATEGORY_CALL && is_import) {
			api_nodes_[rva] = { rva, imp_name, false };
			add_or_update_edge(prev_api, rva, state.jumps);
			worklist.push({ next_rva, rva, {} });
			continue;
		}

		// 情形2: 调用代码内部目标(非导入) -> 同时追踪调用目标与顺序流, 共享prev_api与跳跃统计
		if (category == ZYDIS_CATEGORY_CALL) {
			if (has_target && is_executable_rva(target_rva)) {
				worklist.push({ target_rva, prev_api, state.jumps });
				worklist.push({ next_rva, prev_api, std::move(state.jumps) });
			} else {
				worklist.push({ next_rva, prev_api, std::move(state.jumps) });
			}
			continue;
		}

		// 情形3: 函数返回 -> 结束当前追踪分支
		if (category == ZYDIS_CATEGORY_RET) {
			continue;
		}

		// 情形4: 无条件跳转 -> 记录跳跃(若目标可执行则追踪目标), 不再追踪顺序流
		if (category == ZYDIS_CATEGORY_UNCOND_BR) {
			if (has_target && is_executable_rva(target_rva)) {
				record_jump(state.jumps, rva, target_rva, instr, op_buf);
				worklist.push({ target_rva, prev_api, std::move(state.jumps) });
			}
			continue;
		}

		// 情形5: 条件跳转 -> 跳跃统计需保留副本(两分支共用), 同时追踪目标与顺序流
		if (category == ZYDIS_CATEGORY_COND_BR) {
			if (has_target && is_executable_rva(target_rva)) {
				JumpStats jumps_copy = state.jumps; // 拷贝一份给跳转分支
				record_jump(jumps_copy, rva, target_rva, instr, op_buf);
				worklist.push({ target_rva, prev_api, jumps_copy });
			}
			worklist.push({ next_rva, prev_api, std::move(state.jumps) });
			continue;
		}

		// 其他普通指令 -> 沿顺序流继续
		worklist.push({ next_rva, prev_api, std::move(state.jumps) });
	}
}

uint64_t EFGBuilder::Impl::edge_key(uint64_t from, uint64_t to) {
	// 源与目标RVA均小于2^32(ENTRY哨兵0xFFFFFFFF亦合法)，可直接打包
	return (from << 32) | to;
}

void EFGBuilder::Impl::record_jump(JumpStats &stats, uint64_t rva,
	uint64_t target_rva, const ZydisDecodedInstruction &instr,
	const ZydisDecodedOperand *op_buf) {
	++stats.jump_count;

	// 判断是否为直接跳转(存在立即数操作数)
	bool is_direct = false;
	for (uint8_t i = 0; i < instr.operand_count_visible; ++i) {
		if (op_buf[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			is_direct = true;
			break;
		}
	}

	// 间接跳转无跨度数据
	if (!is_direct) {
		++stats.indirect_jump_count;
		return;
	}

	// 直接跳转: 累计跨度与平方, 供结束时换算均值/方差
	++stats.spans_with_data;
	const double span = std::abs(static_cast<int64_t>(target_rva) - static_cast<int64_t>(rva));
	stats.sum_span += span;
	stats.sum_sq_span += span * span;
}

void EFGBuilder::Impl::add_or_update_edge(
	uint64_t from, uint64_t to,
	const JumpStats &stats) {
	// 忽略非法节点RVA(0既非ENTRY也非有效调用点)
	if (from == 0 || to == 0) {
		return;
	}
	// 以打包键聚合边: 同一对节点多次出现时累加跳跃统计量(O(1))
	auto &edge = api_edges_[edge_key(from, to)];
	edge.jump_count_ += stats.jump_count;
	edge.indirect_jump_count_ += stats.indirect_jump_count;
	edge.spans_with_data_ += stats.spans_with_data;
	edge.sum_span_ += stats.sum_span;
	edge.sum_sq_span_ += stats.sum_sq_span;
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
		if (!(op.actions & ZYDIS_OPERAND_ACTION_READ)) {
			continue;
		}

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

const CodeSection *EFGBuilder::Impl::find_section(
	uint64_t rva, size_t &out_offset) const {
	// 在可执行段中定位rva, 命中返回段指针与段内偏移
	for (const auto &sec : parser_.get_exec_sections()) {
		if (rva >= sec.base_rva_ && rva < sec.base_rva_ + sec.size_) {
			out_offset = static_cast<size_t>(rva - sec.base_rva_);
			return &sec;
		}
	}
	return nullptr;
}

bool EFGBuilder::Impl::decode_at(
	uint64_t rva,
	ZydisDecodedInstruction &instr,
	ZydisDecoderContext &context,
	const CodeSection *&sec_cache) {
	// 顺序流上rva通常连续递增, 借助缓存段摊还段定位(仅越出段范围时才重新定位)
	if (sec_cache == nullptr || rva < sec_cache->base_rva_ || rva >= sec_cache->base_rva_ + sec_cache->size_) {
		size_t offset = 0;
		sec_cache = find_section(rva, offset);
		if (sec_cache == nullptr) {
			return false;
		}
	}
	const size_t offset = static_cast<size_t>(rva - sec_cache->base_rva_);
	// VirtualSize > SizeOfRawData 的节段(虚拟填充/.bss/截断文件)可能没有原始字节,
	// 此时 data()+offset 越过缓冲区、size()-offset 下溢, 必须拒绝
	if (offset >= sec_cache->bytes_.size()) {
		return false;
	}
	// 仅解码指令头, 操作数留待分支/调用类指令按需再解(降低多数指令的解码开销)
	return ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
		&decoder_, &context,
		sec_cache->bytes_.data() + offset,
		sec_cache->bytes_.size() - offset,
		&instr));
}

bool EFGBuilder::Impl::decode_operands(
	const ZydisDecodedInstruction &instr,
	const ZydisDecoderContext &context,
	ZydisDecodedOperand *operands) {
	// 需与指令头解码共用同一个context(保存Zydis内部解码状态)
	return ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
		&decoder_, &context, &instr,
		operands, instr.operand_count_visible));
}

bool EFGBuilder::Impl::is_executable_rva(uint64_t rva) {
	// 判断rva是否落在任一可执行段范围内(与decode_at共用单次段定位)
	size_t offset = 0;
	return find_section(rva, offset) != nullptr;
}

void EFGBuilder::Impl::preprocess_thunks(
	const std::vector<uint8_t> &code,
	uint64_t code_base) {
	// 逐指令解码整个代码段, 识别"jmp [IAT]"形式的导入thunk跳板
	// 这类跳板是编译器为导入函数生成的间接跳转占位, 调用点call到跳板即等价于调用导入函数
	// 仅对JMP指令按需解码操作数(其余指令仅解指令头)
	size_t offset = 0;
	while (offset < code.size()) {
		ZydisDecodedInstruction instr {};
		ZydisDecoderContext context {};
		// 解码失败则单字节前进(容忍非代码数据), 成功则按指令长度前进
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
				&decoder_, &context, code.data() + offset,
				code.size() - offset, &instr))) {
			offset++;
			continue;
		}
		if (instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
			ZydisDecodedOperand op_buf[ZYDIS_MAX_OPERAND_COUNT];
			if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
					&decoder_, &context, &instr,
					op_buf, instr.operand_count_visible))) {
				offset += instr.length;
				continue;
			}
			// 遍历操作数, 解析jmp的目标是否命中IAT
			for (uint8_t i = 0; i < instr.operand_count_visible; ++i) {
				const auto &op = op_buf[i];
				if (!(op.actions & ZYDIS_OPERAND_ACTION_READ)) {
					continue;
				}
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
	for (const auto &[key, edge] : api_edges_) {
		// 从打包键还原源/目标RVA
		const uint64_t from = key >> 32;
		const uint64_t to = key & 0xFFFFFFFFull;
		auto from_it = rva_to_index.find(from);
		auto to_it = rva_to_index.find(to);
		if (from_it == rva_to_index.end() || to_it == rva_to_index.end()) {
			continue; // 目标不是EFG节点(如未收录的RVA)则跳过
		}
		edge_entries.push_back({ from_it->second, to_it->second, &edge });
	}

	// 按源节点索引排序，符合CSR格式规范
	std::sort(edge_entries.begin(), edge_entries.end(),
		[](const EdgeEntry &a, const EdgeEntry &b) {
			if (a.from_index != b.from_index) {
				return a.from_index < b.from_index;
			}
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
		efg.edges_[pos].spans_with_data = static_cast<SIZE_T>(edge->spans_with_data_);

		// 由在线统计量换算平均跨度与总体方差(E[x^2]-E[x]^2式, 与原逐条求和等价)
		if (edge->spans_with_data_ > 0) {
			const double avg_span = edge->sum_span_ / edge->spans_with_data_;
			efg.edges_[pos].avg_span = avg_span;
			double variance = edge->sum_sq_span_ / edge->spans_with_data_ - avg_span * avg_span;
			efg.edges_[pos].span_variance = (variance > 0.0) ? variance : 0.0; // 数值误差防护
		} else {
			efg.edges_[pos].avg_span = 0.0;
			efg.edges_[pos].span_variance = 0.0;
		}
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
	// 解析PE文件，失败(非PE/严重损坏)返回空EFG
	PEParser parser(file_path);
	if (!parser.parse()) {
		return { false, EFG {} };
	}

	// 无可执行段则不构建调用图, 但文件本身是合法PE(如纯资源DLL), 返回仅含ENTRY节点的空EFG
	// 让上游能正常提取静态PE特征兜底, 而非整体拒绝(避免纯资源DLL频繁扫描失败)
	EFGBuilder builder(parser);
	EFG efg = builder.build();

	return { true, std::move(efg) };
}

} // namespace starlight_v3
