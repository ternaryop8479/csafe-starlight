/**
 * @file feat_pack.h
 * @brief 程序的特征数据集合数据结构封装
 * @author ternaryop8479
 * @date 2026-07-31
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_BASIC_FEAT_PACK_H
#define CSAFE_STARLIGHT_V3_INCLUDE_BASIC_FEAT_PACK_H

#include "types.h"

namespace starlight_v3 {

/**
 * @brief 来自tosSPM推理结果的特征数据(43维)
 */
struct TSPMFeatPack { // 累死我了呜呜呜呜
	// 链条统计特征
	SIZE_T max_malchain_length; ///< 匹配到的最长病毒链长度
	double avg_malchain_length; ///< 匹配到的平均病毒链长度
	SIZE_T max_benchain_length; ///< 匹配到的最长良性链长度
	double avg_benchain_length; ///< 匹配到的平均良性链长度
	SIZE_T malchain_count; ///< 匹配到的病毒链数
	SIZE_T benchain_count; ///< 匹配到的良性链数
	double mal_ben_avglength_ratio; ///< 平均病毒链长度/平均良性链长度
	double mal_ben_maxlength_ratio; ///< 最长病毒链长度/最长良性链长度
	SIZE_T chain_count_diff; ///< 恶意链数量与良性链数量之差
	bool is_mal_dominant; ///< 最长链是否是恶意调用链
	double malchain_density; ///< 恶意链条密度，即匹配的恶意链条覆盖的节点与总节点数之比
	double benchain_density; ///< 良性链条密度，即匹配的良性链条覆盖的节点与总节点数之比
	double avg_malchain_similarity; ///< 恶意链条平均相似度(由匹配的平均链长度、匹配到的链数量以及链条密度可以直接计算得出)
	double avg_benchain_similarity; ///< 良性链条平均相似度(由匹配的平均链长度、匹配到的链数量以及链条密度可以直接计算得出)
	double avg_malmatch_depth; ///< 恶意链条匹配发生的平均深度
	double avg_benmatch_depth; ///< 良性链条匹配发生的平均深度
	SIZE_T max_malmatch_depth; ///< 恶意链条匹配发生的最大深度
	SIZE_T max_benmatch_depth; ///< 良性链条匹配发生的最大深度
	SIZE_T malapi_count; ///< 恶意链条的API总数
	SIZE_T benapi_count; ///< 良性链条的API总数

	// 链条权重特征
	double avg_malchain_weight; ///< 恶意链条平均权重
	double malchain_weight_var; ///< 恶意链条权重方差
	double malchain_weight_ske; ///< 恶意链条权重偏度
	double avg_benchain_weight; ///< 良性链条平均权重
	double benchain_weight_var; ///< 良性链条权重方差
	double benchain_weight_ske; ///< 良性链条权重偏度
	double max_malchain_weight; ///< 恶意链条最高权重
	double max_benchain_weight; ///< 良性链条最高权重
	double avg_malweight_density; ///< 所有病毒链条长度与链条权重之比的均值
	double avg_benweight_density; ///< 所有良性链条长度与链条权重之比的均值
	double max_malweight_density; ///< 病毒链条长度与链条权重之比的最大值
	double max_benweight_density; ///< 良性链条长度与链条权重之比的最大值

	// 引擎输出权重特征
	double tspm_mal_weight; ///< 引擎输出的程序恶意权重
	double tspm_ben_weight; ///< 引擎输出的程序良性权重
	double weight_diff; ///< 引擎输出的恶意权重与良性权重之差
	double weight_ratio; ///< 引擎输出的恶意权重与良性权重之比

	// 引擎执行过程中的统计特征
	double avg_malskip_count; ///< 匹配单条恶意链条时的平均跳过次数
	double avg_benskip_count; ///< 匹配单条良性链条时的平均跳过次数
	double avg_malchain_branching; ///< 匹配到的恶意链条所根据EFG合并成的树的平均出度
	double avg_benchain_branching; ///< 匹配到的良性链条所根据EFG合并成的树的平均出度
	double max_malchain_branching; ///< 匹配到的恶意链条所根据EFG合并成的树的最大出度
	double max_benchain_branching; ///< 匹配到的良性链条所根据EFG合并成的树的最大出度

	// 引擎最终输出
	double tspm_score; ///< tosSPM引擎输出的最终权重
};

/**
 * @brief 来自程序EFG控制流程图的推理数据(39维)
 */
struct EFGFeatPack {
	// EFG的结构统计数据(11维)
	SIZE_T node_count; ///< EFG节点总数
	SIZE_T edge_count; ///< EFG边总数
	double density; ///< 图密度，边数/(节点数 * (节点数 - 1))
	double avg_degree; ///< 图平均出度
	SIZE_T max_degree; ///< 图最大出度
	double degree_var; ///< 图出度方差
	double degree_ske; ///< 图出度偏度
	double edge_node_ratio; ///< 边数/节点比
	SIZE_T isolated_node_count; ///< 孤立节点数(即连通分量数-1)
	double largest_component_ratio; ///< 最大连通分量占比(包含ENTRY节点的连通分量节点数占全图总节点数之比)
	double entropy; ///< 图的结构熵

	// EFG的边信息数据(28维)
	double avg_jmp_count; ///< 单边平均跳转次数
	double jmp_count_var; ///< 边跳转次数方差
	double jmp_count_ske; ///< 边跳转次数偏度
	double max_jmp_count; ///< 最大跳转次数
	double avg_indirect_jmp_count; ///< 单边平均间接跳转次数
	double indirect_jmp_count_var; ///< 边间接跳转次数方差
	double indirect_jmp_count_ske; ///< 边间接跳转次数偏度
	double max_indirect_jmp_count; ///< 最大间接跳转次数
	double indirect_jmp_edge_ratio; ///< 带有间接跳转的边与总边数之比
	double total_indirect_jmp_count; ///< 总间接跳转次数
	double max_span; ///< 最大跨度
	double avg_span; ///< 边平均跨度
	double span_var; ///< 边跨度的方差
	double span_ske; ///< 边跨度的偏度
	double jmp_count_entropy; ///< 跳转次数分布的熵
	double data_flow_edge_ratio; ///< 携带数据的边占总边数之比
	double avg_span_with_data; ///< 携带数据的边的平均跨度
	double max_span_with_data; ///< 携带数据的边的最大跨度
	double span_with_data_var; ///< 携带数据的边的跨度方差
	double span_with_data_ske; ///< 携带数据的边的跨度偏度
	double avg_jmp_count_with_data; ///< 携带数据的边的平均跳转次数
	double max_jmp_count_with_data; ///< 携带数据的边的最大跳转次数
	double jmp_count_with_data_var; ///< 携带数据的边的跳转次数方差
	double jmp_count_with_data_ske; ///< 携带数据的边的跳转次数偏度
	double avg_indirect_jmp_with_data; ///< 携带数据的边的平均间接跳转次数
	double max_indirect_jmp_with_data; ///< 携带数据的边的最大间接跳转次数
	double indirect_jmp_with_data_var; ///< 携带数据的边的间接跳转次数方差
	double indirect_jmp_with_data_ske; ///< 携带数据的边的间接跳转次数偏度
};

/**
 * @brief 来自程序PE文件的结构化统计特征
 */
struct PEFeatPack {
	// PE头数据特征
	SIZE_T machine_type; ///< 机器类型(IMAGE_FILE_HEADER.Machine)
	bool is_64bit; ///< 是否为PE32+格式
	SIZE_T num_sections; ///< 节段数量(NumberOfSections)
	SIZE_T time_date_stamp; ///< 编译时间戳(TimeDateStamp)
	bool has_symbol_table; ///< 是否带COFF符号表
	SIZE_T size_of_optional_header; ///< 可选头大小
	SIZE_T file_characteristics; ///< 文件特征值(Characteristics)
	bool is_dll; ///< 是否为DLL文件
	double linker_version; ///< 链接器版本号(major * 100 + minor)
	SIZE_T size_of_code; ///< 代码段大小
	SIZE_T size_of_initialized_data; ///< 已初始化数据大小
	SIZE_T size_of_uninitialized_data; ///< 未初始化数据大小
	SIZE_T address_of_entry_point; ///< 入口点RVA
	SIZE_T base_of_code; ///< 代码段基址RVA
	GREAT_SIZE_T image_base; ///< 映像基址
	SIZE_T section_alignment; ///< 节段对齐
	SIZE_T file_alignment; ///< 文件对齐
	double os_version; ///< 操作系统版本号(major * 100 + minor)
	double subsystem_version; ///< 子系统版本号(major * 100 + minor)
	SIZE_T size_of_image; ///< 映像总大小
	SIZE_T size_of_headers; ///< 头部总大小
	bool checksum_is_zero; ///< 校验和是否为0(加壳样本常见)
	SIZE_T subsystem; ///< 子系统类型
	SIZE_T dll_characteristics; ///< DLL特征值
	GREAT_SIZE_T size_of_stack_reserve; ///< 栈保留大小
	GREAT_SIZE_T size_of_stack_commit; ///< 栈提交大小
	GREAT_SIZE_T size_of_heap_reserve; ///< 堆保留大小
	GREAT_SIZE_T size_of_heap_commit; ///< 堆提交大小
	SIZE_T number_of_rva_and_sizes; ///< 数据目录条目数

	// 节段熵特征
	double file_entropy; ///< 整个文件的Shannon熵
	double section_entropy_mean; ///< 各节段熵的均值
	double section_entropy_max; ///< 各节段熵的最大值
	double section_entropy_min; ///< 各节段熵的最小值
	double section_entropy_std; ///< 各节段熵的标准差
	double text_section_entropy; ///< .text节段的熵
	SIZE_T high_entropy_section_count; ///< 熵大于7.2的节段数(加壳信号)

	// 节段统计特征
	SIZE_T entry_section_index; ///< 入口点所在节段的下标
	double entry_section_entropy; ///< 入口点所在节段的熵
	double raw_size_mean; ///< 各节段SizeOfRawData均值
	double raw_size_max; ///< 各节段SizeOfRawData最大值
	double virtual_size_mean; ///< 各节段VirtualSize均值
	double virtual_size_max; ///< 各节段VirtualSize最大值
	double vsize_raw_ratio_mean; ///< 各节段VirtualSize/SizeOfRawData均值(压缩比信号)
	double vsize_raw_ratio_max; ///< 各节段VirtualSize/SizeOfRawData最大值
	SIZE_T high_gap_section_count; ///< VirtualSize大于SizeOfRawData的节段数
	SIZE_T nonstandard_name_count; ///< 非标准名称节段数
	SIZE_T writable_executable_count; ///< 可写可执行(W+X)节段数(经典可疑特征)
	SIZE_T executable_count; ///< 可执行节段数

	// 导入表统计特征
	SIZE_T import_count; ///< 导入函数总数
	SIZE_T distinct_dll_count; ///< 导入的不同DLL数
	double imports_per_dll_mean; ///< 每个DLL平均导入函数数
	double imports_per_dll_max; ///< 每个DLL最大导入函数数
	SIZE_T ordinal_import_count; ///< 序号导入函数数
	double ordinal_import_ratio; ///< 序号导入占比
	SIZE_T unique_api_count; ///< 去重后的API名数量
	double api_name_len_mean; ///< API名平均长度
	SIZE_T api_name_len_max; ///< API名最大长度
	double api_name_char_entropy; ///< API名整体字符分布熵
	double dll_name_entropy; ///< DLL名分布熵
	bool has_dynamic_import; ///< 是否存在LoadLibrary/GetProcAddress(动态解析信号)
	SIZE_T suspicious_api_count; ///< 高危API调用数(注入/隐藏/持久化等)
	double suspicious_api_ratio; ///< 高危API占比
	SIZE_T suspicious_dll_count; ///< 高危DLL数(网络/系统/加密相关)
	double suspicious_dll_ratio; ///< 高危DLL占比
	SIZE_T process_api_count; ///< 进程操作类API数(打开/注入/远程线程等)
	SIZE_T network_api_count; ///< 网络类API数(socket/连接/下载等)
	SIZE_T crypto_api_count; ///< 加密类API数(加解密/哈希等)
	SIZE_T persistence_api_count; ///< 持久化类API数(注册表/服务/自启动等)
	SIZE_T import_dir_size; ///< 导入表数据目录大小

	// 字符串特征
	SIZE_T string_count; ///< 可打印字符串总数
	double string_avg_len; ///< 字符串平均长度
	SIZE_T string_max_len; ///< 字符串最大长度
	SIZE_T long_string_count; ///< 长度大于等于30的字符串数
	double printable_ratio; ///< 可打印字节占文件总字节比例
	SIZE_T url_count; ///< 包含URL的字符串数
	SIZE_T file_path_count; ///< 包含文件路径的字符串数
	SIZE_T registry_count; ///< 包含注册表键的字符串数
	SIZE_T ip_count; ///< 包含IP地址的字符串数
	SIZE_T suspicious_keyword_count; ///< 包含可疑关键词的字符串数

	// 结构统计特征
	SIZE_T file_size; ///< 文件总大小
	SIZE_T overlay_size; ///< 文件尾部附加数据大小(最后一个节段之后的数据)
	double overlay_ratio; ///< 附加数据占文件大小比例
	double headers_image_ratio; ///< SizeOfHeaders/SizeOfImage
	double image_gap_ratio; ///< 映像空隙比例((SizeOfImage - 各节VirtualSize之和)/SizeOfImage)
	SIZE_T nonzero_data_directory_count; ///< 非空数据目录数
	bool export_present; ///< 是否存在导出表
	bool debug_present; ///< 是否存在调试目录
	bool resource_present; ///< 是否存在资源目录
	SIZE_T rich_header_entry_count; ///< Rich Header条目数(编译器指纹)
};

struct FeatPack {
	// 来自tosSPM引擎推理过程及结果的特征数据
	TSPMFeatPack tspm_feats;

	// 从EFG中能够提取出的特征数据
	EFGFeatPack efg_feats;

	// 从PE文件中提取出的静态特征数据
	PEFeatPack pe_feats;
};

}

#endif
