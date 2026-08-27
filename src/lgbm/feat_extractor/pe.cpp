/**
 * @file lgbm/feat_extractor/pe.cpp
 * @brief PE静态特征提取器实现
 * @author ternaryop8479
 * @date 2026-08-02
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <pe-parse/nt-headers.h>
#include <pe-parse/parse.h>

#include "basic/types.h"
#include "lgbm/feat_extractor/pe.h"
#include "pe/hist.h"
#include "pe_compat.h"

#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#endif

#ifndef IMAGE_SCN_MEM_WRITE
#define IMAGE_SCN_MEM_WRITE 0x80000000
#endif

// 内部工具函数与常量表
namespace {

using starlight_v3::SIZE_T; // 匿名命名空间内使用引擎基础类型

// 关键词判定表
// 标准节段名前缀(前缀匹配, 不匹配即视为非标准名称)
const std::vector<std::string_view> STANDARD_SECTION_PREFIXES = {
	".text",
	".rdata",
	".data",
	".bss",
	".rsrc",
	".reloc",
	".idata",
	".edata",
	".tls",
	".pdata",
	".xdata",
	".CRT",
	".debug",
	".didat",
	".gfids",
	".sdata",
	".srdata",
	".sbss",
	".buildid",
	".stub",
	".textbss",
};

// 进程操作类API
const std::vector<std::string_view> PROCESS_APIS = {
	"CreateRemoteThread",
	"WriteProcessMemory",
	"ReadProcessMemory",
	"OpenProcess",
	"VirtualAllocEx",
	"VirtualProtectEx",
	"NtWriteVirtualMemory",
	"NtReadVirtualMemory",
	"NtCreateThreadEx",
	"QueueUserAPC",
	"SetThreadContext",
	"ResumeThread",
	"CreateProcessInternalW",
	"CreateProcessA",
	"CreateProcessW",
	"WinExec",
	"ShellExecuteA",
	"ShellExecuteW",
	"NtUnmapViewOfSection",
	"TerminateProcess",
	"SetWindowsHookExA",
	"SetWindowsHookExW",
};

// 网络类API
const std::vector<std::string_view> NETWORK_APIS = {
	"WSAStartup",
	"socket",
	"connect",
	"send",
	"recv",
	"sendto",
	"recvfrom",
	"bind",
	"listen",
	"accept",
	"WSASocketA",
	"WSASocketW",
	"getaddrinfo",
	"gethostbyname",
	"InternetOpenA",
	"InternetOpenW",
	"InternetConnectA",
	"InternetConnectW",
	"InternetOpenUrlA",
	"InternetOpenUrlW",
	"InternetReadFile",
	"HttpSendRequestA",
	"HttpSendRequestW",
	"URLDownloadToFileA",
	"URLDownloadToFileW",
	"WinHttpOpen",
	"WinHttpConnect",
	"WinHttpOpenRequest",
	"WinHttpSendRequest",
	"WinHttpReceiveResponse",
	"FtpPutFileA",
	"FtpPutFileW",
};

// 加密类API
const std::vector<std::string_view> CRYPTO_APIS = {
	"CryptEncrypt",
	"CryptDecrypt",
	"CryptGenKey",
	"CryptAcquireContextA",
	"CryptAcquireContextW",
	"CryptCreateHash",
	"CryptHashData",
	"CryptDeriveKey",
	"CryptExportKey",
	"CryptImportKey",
	"CryptDestroyKey",
	"BCryptEncrypt",
	"BCryptDecrypt",
	"BCryptGenerateSymmetricKey",
	"BCryptHashData",
};

// 持久化类API
const std::vector<std::string_view> PERSISTENCE_APIS = {
	"RegSetValueA",
	"RegSetValueW",
	"RegSetValueExA",
	"RegSetValueExW",
	"RegCreateKeyA",
	"RegCreateKeyW",
	"RegCreateKeyExA",
	"RegCreateKeyExW",
	"RegOpenKeyA",
	"RegOpenKeyW",
	"RegOpenKeyExA",
	"RegOpenKeyExW",
	"RegDeleteKeyA",
	"RegDeleteKeyW",
	"CreateServiceA",
	"CreateServiceW",
	"OpenSCManagerA",
	"OpenSCManagerW",
	"StartServiceA",
	"StartServiceW",
	"DeleteService",
	"CopyFileA",
	"CopyFileW",
	"MoveFileA",
	"MoveFileW",
	"SetFileAttributesA",
	"SetFileAttributesW",
	"RegisterServiceProcess",
};

// 高危总表中除上述分类外的动态解析/反调试/令牌类API
const std::vector<std::string_view> EXTRA_SUSPICIOUS_APIS = {
	"LoadLibraryA",
	"LoadLibraryW",
	"GetProcAddress",
	"LdrLoadDll",
	"LdrGetProcedureAddress",
	"IsDebuggerPresent",
	"CheckRemoteDebuggerPresent",
	"NtQueryInformationProcess",
	"NtQuerySystemInformation",
	"OutputDebugStringA",
	"OutputDebugStringW",
	"AdjustTokenPrivileges",
	"OpenProcessToken",
	"LookupPrivilegeValueA",
	"LookupPrivilegeValueW",
	"SetTokenInformation",
	"DuplicateTokenEx",
	"NtSetInformationProcess",
};

// 动态解析信号API(has_dynamic_import)
const std::vector<std::string_view> DYNAMIC_APIS = {
	"LoadLibraryA",
	"LoadLibraryW",
	"GetProcAddress",
};

// 高危DLL表(比较时忽略大小写与.dll后缀)
const std::vector<std::string_view> SUSPICIOUS_DLLS = {
	"ws2_32.dll",
	"wininet.dll",
	"urlmon.dll",
	"winhttp.dll",
	"dnsapi.dll",
	"wsock32.dll",
	"iphlpapi.dll",
	"netapi32.dll",
	"mpr.dll",
	"crypt32.dll",
	"bcrypt.dll",
	"wintrust.dll",
	"advapi32.dll",
	"ntdll.dll",
	"secur32.dll",
	"wtsapi32.dll",
	"userenv.dll",
	"sspicli.dll",
	"rpcrt4.dll",
	"ole32.dll",
	"oleaut32.dll",
	"shell32.dll",
	"winspool.drv",
	"wlanapi.dll",
};

// 字符串扫描关键词表
const std::vector<std::string_view> STRING_KEYWORDS = {
	"CreateRemoteThread",
	"WriteProcessMemory",
	"VirtualAllocEx",
	"WinExec",
	"LoadLibrary",
	"GetProcAddress",
	"IsDebuggerPresent",
	"RegSetValue",
	"CreateService",
	"ShellExecute",
	"URLDownloadToFile",
	"InternetOpen",
	"CryptEncrypt",
	"AdjustTokenPrivileges",
	"NtUnmapViewOfSection",
	"SetWindowsHookEx",
};

// 已知加壳工具的特征节名前缀，命中即视为加壳信号
const std::vector<std::string_view> PACKER_SECTION_PREFIXES = {
	"UPX0",
	"UPX1",
	"UPX2",
	".vmp0",
	".vmp1",
	".themida",
	".aspack",
	".mpress1",
};

// 已知加壳工具在文件字节中的魔数签名(大小写不敏感子串匹配)
const std::vector<std::string_view> PACKER_MAGIC_SIGNATURES = {
	"UPX!",
	"VMProtect",
	"Themida",
	"WinLicense",
	"ASPack",
	"MPRESS",
	"MPRESS~1",
};

// 字符串工具
// ASCII大小写不敏感字符比较
inline bool ieq_char(char a, char b) {
	return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
}

// 判断haystack是否包含needle(ASCII大小写不敏感): 按窗口逐字符匹配
bool icontains(std::string_view haystack, std::string_view needle) {
	if (needle.empty()) {
		return true;
	}
	if (needle.size() > haystack.size()) {
		return false;
	}
	for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
		bool matched = true;
		for (size_t j = 0; j < needle.size(); ++j) {
			if (!ieq_char(haystack[i + j], needle[j])) {
				matched = false;
				break;
			}
		}
		if (matched) {
			return true;
		}
	}
	return false;
}

// 判断字符是否为词字符(字母/数字/下划线)
bool is_word_char(char c) {
	const unsigned char u = (unsigned char)c;
	return (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') || (u >= '0' && u <= '9') || u == '_';
}

// 判断haystack是否包含needle且匹配位置前后都不是词字符(ASCII大小写不敏感):
// 避免子串误命中常见词, 如"CoMPRESSion"含"MPRESS"、"fileupX00"含"UPX0"等
bool contains_word(std::string_view haystack, std::string_view needle) {
	if (needle.empty()) {
		return true;
	}
	if (needle.size() > haystack.size()) {
		return false;
	}
	for (SIZE_T i = 0; i + needle.size() <= haystack.size(); ++i) {
		bool matched = true;
		for (SIZE_T j = 0; j < needle.size(); ++j) {
			if (!ieq_char(haystack[i + j], needle[j])) {
				matched = false;
				break;
			}
		}
		if (!matched) {
			continue;
		}
		const bool before_ok = (i == 0) || !is_word_char(haystack[i - 1]);
		const bool after_ok = (i + needle.size() >= haystack.size()) || !is_word_char(haystack[i + needle.size()]);
		if (before_ok && after_ok) {
			return true;
		}
	}
	return false;
}

// 判断s是否以prefix开头(ASCII大小写不敏感): 逐前缀字符比较
bool has_prefix_ci(std::string_view s, std::string_view prefix) {
	if (prefix.size() > s.size()) {
		return false;
	}
	for (size_t i = 0; i < prefix.size(); ++i) {
		if (!ieq_char(s[i], prefix[i])) {
			return false;
		}
	}
	return true;
}

// 判断两个字符串是否相等(ASCII大小写不敏感): 长度相等且逐字符一致
bool iequals(std::string_view a, std::string_view b) {
	if (a.size() != b.size()) {
		return false;
	}
	for (size_t i = 0; i < a.size(); ++i) {
		if (!ieq_char(a[i], b[i])) {
			return false;
		}
	}
	return true;
}

// 将DLL名归一化(转小写并去掉.dll后缀), 用于高危DLL表的模糊匹配
std::string normalize_dll_name(std::string_view name) {
	std::string s;
	s.reserve(name.size());
	for (char c : name) {
		s.push_back((char)std::tolower((unsigned char)c));
	}
	if (s.size() >= 4 && s.compare(s.size() - 4, 4, ".dll") == 0) {
		s.resize(s.size() - 4);
	}
	return s;
}

// 判断s是否命中关键字表(ASCII大小写不敏感精确匹配)
bool in_table(std::string_view s, const std::vector<std::string_view> &table) {
	for (auto &entry : table) {
		if (iequals(s, entry)) {
			return true;
		}
	}
	return false;
}

// 判断DLL名是否命中高危DLL表: 双方先归一化(转小写去.dll)再比较
bool in_dll_table(std::string_view dll, const std::vector<std::string_view> &table) {
	std::string normalized = normalize_dll_name(dll);
	for (auto &entry : table) {
		if (normalized == normalize_dll_name(entry)) {
			return true;
		}
	}
	return false;
}

// 熵计算
// 计算字节序列的Shannon熵(以2为底): 统计256种字节值频率得到概率分布,
// 熵 = -sum(p * log2(p)), 空序列返回0.0.
double shannon_entropy(const uint8_t *data, size_t len) {
	if (len == 0) {
		return 0.0;
	}
	std::array<uint64_t, 256> freq = {};
	for (size_t i = 0; i < len; ++i) {
		++freq[data[i]];
	}
	double entropy = 0.0;
	for (int i = 0; i < 256; ++i) {
		if (freq[i] == 0) {
			continue;
		}
		double p = (double)freq[i] / (double)len;
		entropy -= p * std::log2(p);
	}
	return entropy;
}

// 根据256频次表计算Shannon熵: 各字节频率占比p, 熵 = -sum(p * log2(p)), 总数为0时返回0.0
double entropy_from_freq(const std::array<uint64_t, 256> &freq, uint64_t total) {
	if (total == 0) {
		return 0.0;
	}
	double entropy = 0.0;
	for (int i = 0; i < 256; ++i) {
		if (freq[i] == 0) {
			continue;
		}
		double p = (double)freq[i] / (double)total;
		entropy -= p * std::log2(p);
	}
	return entropy;
}

// 根据字符串分布(DLL名->出现次数)计算Shannon熵: 同entropy_from_freq但输入为名->次数映射
double entropy_from_distribution(const std::unordered_map<std::string, SIZE_T> &freq_map, SIZE_T total) {
	if (total == 0) {
		return 0.0;
	}
	double entropy = 0.0;
	for (auto &entry : freq_map) {
		double p = (double)entry.second / (double)total;
		entropy -= p * std::log2(p);
	}
	return entropy;
}

// 字符串扫描
// 字符串扫描累加器
struct StringScanAccum {
	SIZE_T count = 0; ///< 字符串总数
	double len_sum = 0.0; ///< 字符串长度之和
	SIZE_T max_len = 0; ///< 字符串最大长度
	SIZE_T long_count = 0; ///< 长度>=30的字符串数
	SIZE_T printable_bytes = 0; ///< 可打印字节数
	SIZE_T url_count = 0; ///< URL串数
	SIZE_T path_count = 0; ///< 文件路径串数
	SIZE_T reg_count = 0; ///< 注册表串数
	SIZE_T ip_count = 0; ///< IP地址串数
	SIZE_T kw_count = 0; ///< 可疑关键词串数
	SIZE_T scanned_bytes = 0; ///< 被扫描的字节总数
};

// 判断s从pos位置起是否为点分四段IP: 每段1~3位数字, 段间以'.'分隔
bool match_ip_at(std::string_view s, size_t pos) {
	size_t i = pos;
	size_t digits = 0;
	while (i < s.size() && std::isdigit((unsigned char)s[i]) && digits < 3) {
		++i;
		++digits;
	}
	if (digits == 0 || (i < s.size() && std::isdigit((unsigned char)s[i]))) {
		return false;
	}
	for (int segment = 0; segment < 3; ++segment) {
		if (i >= s.size() || s[i] != '.') {
			return false;
		}
		++i;
		digits = 0;
		while (i < s.size() && std::isdigit((unsigned char)s[i]) && digits < 3) {
			++i;
			++digits;
		}
		if (digits == 0 || (i < s.size() && std::isdigit((unsigned char)s[i]))) {
			return false;
		}
	}
	return true;
}

// 判断字符串是否包含点分四段IP: 逐位置尝试匹配
bool contains_ip(std::string_view s) {
	for (size_t i = 0; i < s.size(); ++i) {
		if (match_ip_at(s, i)) {
			return true;
		}
	}
	return false;
}

// 扫描一段字节并累加字符串统计:
// 跳过不可打印字节(0x20~0x7E之外), 连续可打印run长度>=4才计为一条字符串;
// 对每条字符串按run长度与内容匹配URL/路径/注册表/IP/可疑关键词, 累加各分类计数.
void scan_bytes_strings(StringScanAccum &acc, const uint8_t *data, size_t len) {
	acc.scanned_bytes += (SIZE_T)len;
	size_t i = 0;
	while (i < len) {
		// 跳过不可打印字节
		while (i < len && !(data[i] >= 0x20 && data[i] <= 0x7E)) {
			++i;
		}
		// 一个可打印串
		size_t start = i;
		while (i < len && data[i] >= 0x20 && data[i] <= 0x7E) {
			++i;
		}
		size_t run_len = i - start;
		acc.printable_bytes += (SIZE_T)run_len;
		if (run_len < 4) {
			continue;
		}
		std::string_view run((const char *)data + start, run_len);
		++acc.count;
		acc.len_sum += (double)run_len;
		if (run_len > acc.max_len) {
			acc.max_len = (SIZE_T)run_len;
		}
		if (run_len >= 30) {
			++acc.long_count;
		}
		if (icontains(run, "://") || icontains(run, "www.") || has_prefix_ci(run, "http")) {
			++acc.url_count;
		}
		if (icontains(run, "\\")) {
			++acc.path_count;
		}
		if (icontains(run, "HKEY_") || icontains(run, "\\Registry\\") || icontains(run, "Software\\")) {
			++acc.reg_count;
		}
		if (contains_ip(run)) {
			++acc.ip_count;
		}
		for (auto &keyword : STRING_KEYWORDS) {
			if (icontains(run, keyword)) {
				++acc.kw_count;
				break;
			}
		}
	}
}

// PE数据结构
// 节段信息
struct SectionInfo {
	std::string name;
	uint32_t virtual_address = 0;
	uint32_t virtual_size = 0;
	uint32_t raw_size = 0;
	uint32_t pointer_to_raw = 0;
	uint32_t characteristics = 0;
	double entropy = 0.0;
};

// PE32/PE32+可选头的统一视图: 屏蔽两种可选头结构差异, 供特征提取统一读取
struct OptView {
	uint16_t major_linker = 0;
	uint16_t minor_linker = 0;
	uint32_t size_of_code = 0;
	uint32_t size_of_initialized_data = 0;
	uint32_t size_of_uninitialized_data = 0;
	uint32_t address_of_entry_point = 0;
	uint32_t base_of_code = 0;
	uint64_t image_base = 0;
	uint32_t section_alignment = 0;
	uint32_t file_alignment = 0;
	uint16_t major_os = 0;
	uint16_t minor_os = 0;
	uint16_t major_subsystem = 0;
	uint16_t minor_subsystem = 0;
	uint32_t size_of_image = 0;
	uint32_t size_of_headers = 0;
	uint32_t checksum = 0;
	uint16_t subsystem = 0;
	uint16_t dll_characteristics = 0;
	uint64_t stack_reserve = 0;
	uint64_t stack_commit = 0;
	uint64_t heap_reserve = 0;
	uint64_t heap_commit = 0;
	uint32_t number_of_rva_and_sizes = 0;
	std::array<peparse::data_directory, 16> dirs = {};
	bool valid = false; ///< 可选头是否可识别(PE32/PE32+)
};

// 根据Magic构建可选头统一视图: 先校验Magic(0x10b=PE32, 0x20b=PE32+),
// 再按对应结构体逐字段拷贝到统一视图, 无法识别的Magic返回valid=false的默认视图.
OptView make_opt_view(const peparse::pe_header &header) {
	OptView view;
	uint16_t magic = header.nt.OptionalMagic;
	if (magic != 0x10b && magic != 0x20b) {
		return view;
	}
	view.valid = true;

	if (magic == 0x20b) {
		const auto &o = header.nt.OptionalHeader64;
		view.major_linker = o.MajorLinkerVersion;
		view.minor_linker = o.MinorLinkerVersion;
		view.size_of_code = o.SizeOfCode;
		view.size_of_initialized_data = o.SizeOfInitializedData;
		view.size_of_uninitialized_data = o.SizeOfUninitializedData;
		view.address_of_entry_point = o.AddressOfEntryPoint;
		view.base_of_code = o.BaseOfCode;
		view.image_base = o.ImageBase;
		view.section_alignment = o.SectionAlignment;
		view.file_alignment = o.FileAlignment;
		view.major_os = o.MajorOperatingSystemVersion;
		view.minor_os = o.MinorOperatingSystemVersion;
		view.major_subsystem = o.MajorSubsystemVersion;
		view.minor_subsystem = o.MinorSubsystemVersion;
		view.size_of_image = o.SizeOfImage;
		view.size_of_headers = o.SizeOfHeaders;
		view.checksum = o.CheckSum;
		view.subsystem = o.Subsystem;
		view.dll_characteristics = o.DllCharacteristics;
		view.stack_reserve = o.SizeOfStackReserve;
		view.stack_commit = o.SizeOfStackCommit;
		view.heap_reserve = o.SizeOfHeapReserve;
		view.heap_commit = o.SizeOfHeapCommit;
		view.number_of_rva_and_sizes = o.NumberOfRvaAndSizes;
		for (int i = 0; i < 16; ++i) {
			view.dirs[i] = o.DataDirectory[i];
		}
	} else {
		const auto &o = header.nt.OptionalHeader;
		view.major_linker = o.MajorLinkerVersion;
		view.minor_linker = o.MinorLinkerVersion;
		view.size_of_code = o.SizeOfCode;
		view.size_of_initialized_data = o.SizeOfInitializedData;
		view.size_of_uninitialized_data = o.SizeOfUninitializedData;
		view.address_of_entry_point = o.AddressOfEntryPoint;
		view.base_of_code = o.BaseOfCode;
		view.image_base = o.ImageBase;
		view.section_alignment = o.SectionAlignment;
		view.file_alignment = o.FileAlignment;
		view.major_os = o.MajorOperatingSystemVersion;
		view.minor_os = o.MinorOperatingSystemVersion;
		view.major_subsystem = o.MajorSubsystemVersion;
		view.minor_subsystem = o.MinorSubsystemVersion;
		view.size_of_image = o.SizeOfImage;
		view.size_of_headers = o.SizeOfHeaders;
		view.checksum = o.CheckSum;
		view.subsystem = o.Subsystem;
		view.dll_characteristics = o.DllCharacteristics;
		view.stack_reserve = o.SizeOfStackReserve;
		view.stack_commit = o.SizeOfStackCommit;
		view.heap_reserve = o.SizeOfHeapReserve;
		view.heap_commit = o.SizeOfHeapCommit;
		view.number_of_rva_and_sizes = o.NumberOfRvaAndSizes;
		for (int i = 0; i < 16; ++i) {
			view.dirs[i] = o.DataDirectory[i];
		}
	}
	return view;
}

// 节段迭代上下文(收集节段信息与所有节段的字符串统计)
struct SectionScanCtx {
	std::vector<SectionInfo> sections;
	StringScanAccum strings;
};

// 节段迭代回调: 记录节段信息(名称/地址/大小/特征/熵)，并对所有节段执行字符串扫描
int section_callback(void *ctx, const peparse::VA &, const std::string &sec_name,
	const peparse::image_section_header &sec, const peparse::bounded_buffer *sec_data) {
	auto *scan = static_cast<SectionScanCtx *>(ctx);
	SectionInfo info;
	info.name = sec_name;
	info.virtual_address = sec.VirtualAddress;
	info.virtual_size = sec.Misc.VirtualSize;
	info.raw_size = sec.SizeOfRawData;
	info.pointer_to_raw = sec.PointerToRawData;
	info.characteristics = sec.Characteristics;
	if (sec_data != nullptr && sec_data->buf != nullptr && sec_data->bufLen > 0) {
		info.entropy = shannon_entropy(sec_data->buf, sec_data->bufLen);
	}
	scan->sections.push_back(std::move(info));

	// 字符串扫描: 所有节段(含可执行段，捕获代码段硬编码的命令串/URL/IP等)
	if (sec_data != nullptr && sec_data->buf != nullptr && sec_data->bufLen > 0) {
		scan_bytes_strings(scan->strings, sec_data->buf, sec_data->bufLen);
	}
	return 0;
}

// 将RVA转换为文件偏移: 遍历节段定位包含该RVA的节段，未命中或非法时返回0
uint64_t rva_to_file_offset(uint64_t rva, const std::vector<SectionInfo> &sections) {
	for (const SectionInfo &sec : sections) {
		if (rva >= sec.virtual_address && rva < (uint64_t)sec.virtual_address + sec.virtual_size) {
			return (uint64_t)sec.pointer_to_raw + (rva - sec.virtual_address);
		}
	}
	return 0;
}

// 导入信息
struct ImportInfo {
	std::string dll;
	std::string func;
	bool ordinal = false; ///< 是否为序号导入(此时func为pe-parse合成的占位名, 非真实API名)
};

// 判断pe-parse给出的symbol是否为序号导入的合成占位名
// pe-parse对序号导入不返回空串, 而是合成"ORDINAL_<DLL名>_<序号>"(如ORDINAL_MFC42.DLL_4698),
// 若按真实API名参与统计会污染API名长度/字符熵/去重计数等维度
bool is_ordinal_symbol(const std::string &symbol) {
	static constexpr char kOrdinalPrefix[] = "ORDINAL_";
	return symbol.rfind(kOrdinalPrefix, 0) == 0;
}

// 导入表迭代回调: 记录每个导入函数所属DLL与函数名
int import_callback(void *ctx, const peparse::VA &, const std::string &module, const std::string &symbol) {
	auto *imports = static_cast<std::vector<ImportInfo> *>(ctx);
	ImportInfo info;
	info.dll = module;
	info.func = symbol;
	info.ordinal = symbol.empty() || is_ordinal_symbol(symbol);
	imports->push_back(std::move(info));
	return 0;
}

// parsed_pe的RAII守卫, 任何退出路径(含异常)都会释放pe-parse分配的内存
class ParsedPEGuard {
public:
	// pe_compat参数: 走兼容修补路径时持有文件字节，必须存活至DestructParsedPE之后
	explicit ParsedPEGuard(peparse::parsed_pe *pe, const starlight_v3::ParsedPECompat &pe_compat)
		: pe_(pe), pe_compat_(pe_compat) {
	}
	~ParsedPEGuard() {
		if (pe_ != nullptr) {
			peparse::DestructParsedPE(pe_);
		}
	}
	ParsedPEGuard(const ParsedPEGuard &) = delete;
	ParsedPEGuard &operator=(const ParsedPEGuard &) = delete;

private:
	peparse::parsed_pe *pe_;
	starlight_v3::ParsedPECompat pe_compat_; // 注意: 需要拷贝以延长文件字节生命周期，数据量最多一个文件大小
};

} // namespace

namespace starlight_v3::lgbm {

// PE特征提取主函数
PEFeatPack extract_pe_feats(const pe::PeView &view, BlockEntropyFeatPack *block_entropy_out) {
	PEFeatPack feats = {}; // 值初始化, 提取失败的部分保持全零
	// 提前清零输出参数: 任何提前返回路径都不再触碰该指针, 避免调用方读到未初始化值
	if (block_entropy_out != nullptr) {
		*block_entropy_out = BlockEntropyFeatPack {};
	}

	// 兼容解析: 首次解析失败时自动修补pe-parse已知缺陷(无数据段目录/空debug条目)后重试
	// 直接复用视图内的文件字节, 不再重复读盘
	ParsedPECompat pe_compat = parse_pe_with_compat(view.data(), view.size());
	if (pe_compat.pe == nullptr) {
		return feats; // 非PE格式或损坏到无意义, 返回全零
	}
	ParsedPEGuard pe_guard(pe_compat.pe, pe_compat); // RAII: 任何退出路径(含异常)都释放pe-parse分配的内存
	peparse::parsed_pe *pe = pe_compat.pe;

	// PE头特征(28维)
	const peparse::file_header &file_header = pe->peHeader.nt.FileHeader;
	feats.machine_type = file_header.Machine;
	feats.num_sections = file_header.NumberOfSections;
	feats.time_date_stamp = file_header.TimeDateStamp;
	feats.has_symbol_table = file_header.PointerToSymbolTable != 0;
	feats.size_of_optional_header = file_header.SizeOfOptionalHeader;
	feats.file_characteristics = file_header.Characteristics;
	feats.is_dll = (file_header.Characteristics & 0x2000) != 0;

	OptView opt = make_opt_view(pe->peHeader);
	if (opt.valid) {
		feats.linker_version = (double)opt.major_linker * 100.0 + (double)opt.minor_linker;
		feats.size_of_code = opt.size_of_code;
		feats.size_of_initialized_data = opt.size_of_initialized_data;
		feats.size_of_uninitialized_data = opt.size_of_uninitialized_data;
		feats.address_of_entry_point = opt.address_of_entry_point;
		feats.base_of_code = opt.base_of_code;
		feats.image_base = opt.image_base;
		feats.section_alignment = opt.section_alignment;
		feats.file_alignment = opt.file_alignment;
		feats.os_version = (double)opt.major_os * 100.0 + (double)opt.minor_os;
		feats.subsystem_version = (double)opt.major_subsystem * 100.0 + (double)opt.minor_subsystem;
		feats.size_of_image = opt.size_of_image;
		feats.size_of_headers = opt.size_of_headers;
		feats.checksum_is_zero = opt.checksum == 0;
		feats.subsystem = opt.subsystem;
		feats.dll_characteristics = opt.dll_characteristics;
		feats.size_of_stack_reserve = opt.stack_reserve;
		feats.size_of_stack_commit = opt.stack_commit;
		feats.size_of_heap_reserve = opt.heap_reserve;
		feats.size_of_heap_commit = opt.heap_commit;
		feats.number_of_rva_and_sizes = opt.number_of_rva_and_sizes;
	}

	// 节段统计(12维) + 节段熵(7维) + 字符串(10维)
	SectionScanCtx scan;
	try {
		peparse::IterSec(pe, &section_callback, &scan);
	} catch (const std::exception &) {
		// pe-parse可能抛出STL异常, 保留已提取的部分节段
	}
	const std::vector<SectionInfo> &sections = scan.sections;
	SIZE_T section_count = (SIZE_T)sections.size();

	double entropy_sum = 0.0;
	double entropy_max = 0.0;
	double entropy_min = 0.0;
	double entropy_sq_sum = 0.0;
	SIZE_T raw_size_sum = 0;
	SIZE_T raw_size_max = 0;
	SIZE_T virtual_size_sum = 0;
	SIZE_T virtual_size_max = 0;
	double ratio_sum = 0.0;
	double ratio_max = 0.0;
	SIZE_T high_gap_count = 0;
	SIZE_T nonstandard_count = 0;
	SIZE_T writable_exec_count = 0;
	SIZE_T exec_count = 0;
	SIZE_T text_entropy_set = 0;
	double text_entropy = 0.0;
	SIZE_T entry_section_index = INVALID_NUM;
	uint64_t raw_end_max = 0;

	for (SIZE_T i = 0; i < section_count; ++i) {
		const SectionInfo &sec = sections[i];
		// 熵统计
		entropy_sum += sec.entropy;
		entropy_sq_sum += sec.entropy * sec.entropy;
		if (i == 0) {
			entropy_min = sec.entropy;
		}
		if (sec.entropy > entropy_max) {
			entropy_max = sec.entropy;
		}
		if (sec.entropy < entropy_min) {
			entropy_min = sec.entropy;
		}
		// 尺寸统计
		raw_size_sum += sec.raw_size;
		if (sec.raw_size > raw_size_max) {
			raw_size_max = sec.raw_size;
		}
		virtual_size_sum += sec.virtual_size;
		if (sec.virtual_size > virtual_size_max) {
			virtual_size_max = sec.virtual_size;
		}
		// 压缩比统计
		double vsize_ratio = sec.raw_size > 0 ? (double)sec.virtual_size / (double)sec.raw_size : 0.0;
		ratio_sum += vsize_ratio;
		if (vsize_ratio > ratio_max) {
			ratio_max = vsize_ratio;
		}
		if (sec.virtual_size > sec.raw_size) {
			++high_gap_count;
		}
		// 名称统计
		bool is_standard = false;
		for (auto &prefix : STANDARD_SECTION_PREFIXES) {
			if (sec.name.compare(0, prefix.size(), prefix) == 0) {
				is_standard = true;
				break;
			}
		}
		if (!is_standard) {
			++nonstandard_count;
		}
		// 统计命中已知壳节名前缀的节段数
		for (auto &prefix : PACKER_SECTION_PREFIXES) {
			if (sec.name.compare(0, prefix.size(), prefix) == 0) {
				++feats.packer_section_count;
				break;
			}
		}
		// 特征位统计
		if ((sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
			++exec_count;
			if ((sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
				++writable_exec_count;
			}
		}
		// .text节段熵
		if (sec.name == ".text" && text_entropy_set == 0) {
			text_entropy = sec.entropy;
			text_entropy_set = 1;
		}
		// 入口点所在节段
		if (opt.valid && entry_section_index == INVALID_NUM
			&& opt.address_of_entry_point >= sec.virtual_address
			&& opt.address_of_entry_point < (uint64_t)sec.virtual_address + sec.virtual_size) {
			entry_section_index = i;
		}
		// overlay计算用的原始数据末端
		uint64_t raw_end = (uint64_t)sec.pointer_to_raw + sec.raw_size;
		if (raw_end > raw_end_max) {
			raw_end_max = raw_end;
		}
	}

	// 入口点所在节段下标, 特征值按1起编号(0表示入口点不落在任何节段内, 加壳/畸形样本常见),
	// 不能把INVALID_NUM直接当特征值输出: 4294967295会与合法下标混在同一条数轴上被模型当极大数切分
	feats.entry_section_index = entry_section_index != INVALID_NUM ? entry_section_index + 1 : 0;
	feats.entry_section_entropy = entry_section_index != INVALID_NUM ? sections[entry_section_index].entropy : 0.0;
	feats.raw_size_mean = section_count > 0 ? (double)raw_size_sum / (double)section_count : 0.0;
	feats.raw_size_max = raw_size_max;
	feats.virtual_size_mean = section_count > 0 ? (double)virtual_size_sum / (double)section_count : 0.0;
	feats.virtual_size_max = virtual_size_max;
	feats.vsize_raw_ratio_mean = section_count > 0 ? ratio_sum / (double)section_count : 0.0;
	feats.vsize_raw_ratio_max = ratio_max;
	feats.high_gap_section_count = high_gap_count;
	feats.nonstandard_name_count = nonstandard_count;
	feats.writable_executable_count = writable_exec_count;
	feats.executable_count = exec_count;

	feats.section_entropy_mean = section_count > 0 ? entropy_sum / (double)section_count : 0.0;
	feats.section_entropy_max = entropy_max;
	feats.section_entropy_min = entropy_min;
	double entropy_avg = feats.section_entropy_mean;
	// 注意: mean(x^2)-mean(x)^2在浮点舍入下可能为极小负值, clamp到0防止sqrt产生NaN
	double entropy_variance = section_count > 0 ? std::max(0.0, entropy_sq_sum / (double)section_count - entropy_avg * entropy_avg) : 0.0;
	feats.section_entropy_std = std::sqrt(entropy_variance);
	feats.text_section_entropy = text_entropy;
	feats.high_entropy_section_count = 0;
	for (SIZE_T i = 0; i < section_count; ++i) {
		if (sections[i].entropy > 7.2) {
			++feats.high_entropy_section_count;
		}
	}

	// 字符串特征(扫描所有节段的字节)
	SIZE_T scanned_bytes = scan.strings.scanned_bytes;
	feats.string_count = scan.strings.count;
	feats.string_avg_len = scan.strings.count > 0 ? scan.strings.len_sum / (double)scan.strings.count : 0.0;
	feats.string_max_len = scan.strings.max_len;
	feats.long_string_count = scan.strings.long_count;
	feats.printable_ratio = scanned_bytes > 0 ? (double)scan.strings.printable_bytes / (double)scanned_bytes : 0.0;
	feats.url_count = scan.strings.url_count;
	feats.file_path_count = scan.strings.path_count;
	feats.registry_count = scan.strings.reg_count;
	feats.ip_count = scan.strings.ip_count;
	feats.suspicious_keyword_count = scan.strings.kw_count;

	// 导入表特征(21维)
	std::vector<ImportInfo> imports;
	try {
		peparse::IterImpVAString(pe, &import_callback, &imports);
	} catch (const std::exception &) {
		// pe-parse可能抛出STL异常, 保留已提取的部分导入
	}
	SIZE_T import_count = (SIZE_T)imports.size();
	if (import_count > 0) {
		std::unordered_map<std::string, SIZE_T> dll_freq;
		std::unordered_set<std::string> unique_apis;
		std::array<uint64_t, 256> name_char_freq = {};
		SIZE_T named_import_count = 0;
		SIZE_T name_len_sum = 0;
		SIZE_T name_len_max = 0;
		SIZE_T ordinal_count = 0;
		SIZE_T suspicious_count = 0;
		SIZE_T process_count = 0;
		SIZE_T network_count = 0;
		SIZE_T crypto_count = 0;
		SIZE_T persistence_count = 0;
		SIZE_T suspicious_dll_count = 0;
		bool has_dynamic = false;

		for (const auto &imp : imports) {
			++dll_freq[imp.dll];
			// 序号导入无真实API名, 不参与任何按名统计(去重计数/名长/字符熵/能力分类)
			if (imp.ordinal) {
				++ordinal_count;
				continue;
			}
			unique_apis.insert(imp.func);
			++named_import_count;
			name_len_sum += (SIZE_T)imp.func.size();
			if (imp.func.size() > name_len_max) {
				name_len_max = (SIZE_T)imp.func.size();
			}
			for (char c : imp.func) {
				++name_char_freq[(uint8_t)c];
			}
			if (in_table(imp.func, DYNAMIC_APIS)) {
				has_dynamic = true;
			}
			bool is_suspicious = false;
			if (in_table(imp.func, PROCESS_APIS)) {
				++process_count;
				is_suspicious = true;
			}
			if (in_table(imp.func, NETWORK_APIS)) {
				++network_count;
				is_suspicious = true;
			}
			if (in_table(imp.func, CRYPTO_APIS)) {
				++crypto_count;
				is_suspicious = true;
			}
			if (in_table(imp.func, PERSISTENCE_APIS)) {
				++persistence_count;
				is_suspicious = true;
			}
			if (!is_suspicious && in_table(imp.func, EXTRA_SUSPICIOUS_APIS)) {
				is_suspicious = true;
			}
			if (is_suspicious) {
				++suspicious_count;
			}
		}

		SIZE_T dll_count = (SIZE_T)dll_freq.size();
		SIZE_T dll_import_max = 0;
		for (auto &entry : dll_freq) {
			if (entry.second > dll_import_max) {
				dll_import_max = entry.second;
			}
			if (in_dll_table(entry.first, SUSPICIOUS_DLLS)) {
				++suspicious_dll_count;
			}
		}

		feats.import_count = import_count;
		feats.distinct_dll_count = dll_count;
		feats.imports_per_dll_max = dll_import_max;
		feats.ordinal_import_count = ordinal_count;
		feats.unique_api_count = (SIZE_T)unique_apis.size();
		feats.api_name_len_mean = named_import_count > 0 ? (double)name_len_sum / (double)named_import_count : 0.0;
		feats.api_name_len_max = name_len_max;
		feats.api_name_char_entropy = entropy_from_freq(name_char_freq, name_len_sum);
		feats.dll_name_entropy = entropy_from_distribution(dll_freq, import_count);
		feats.has_dynamic_import = has_dynamic;
		feats.suspicious_api_count = suspicious_count;
		feats.suspicious_dll_count = suspicious_dll_count;
		feats.process_api_count = process_count;
		feats.network_api_count = network_count;
		feats.crypto_api_count = crypto_count;
		feats.persistence_api_count = persistence_count;
	}
	feats.import_dir_size = opt.valid ? opt.dirs[peparse::DIR_IMPORT].Size : 0;

	// 结构统计特征(7维) + 整文件熵
	uint64_t file_size = 0;
	if (pe->fileBuffer != nullptr) {
		file_size = pe->fileBuffer->bufLen;
	}
	feats.file_size = file_size;
	feats.file_entropy = (pe->fileBuffer != nullptr && pe->fileBuffer->buf != nullptr && file_size > 0)
		? shannon_entropy(pe->fileBuffer->buf, (size_t)file_size)
		: 0.0;
	feats.overlay_size = file_size > raw_end_max ? (GREAT_SIZE_T)(file_size - raw_end_max) : 0;
	if (opt.valid) {
		SIZE_T nonzero_dir_count = 0;
		SIZE_T dir_count = std::min(opt.number_of_rva_and_sizes, (uint32_t)16);
		for (SIZE_T i = 0; i < dir_count; ++i) {
			if (opt.dirs[i].VirtualAddress != 0) {
				++nonzero_dir_count;
			}
		}
		feats.nonzero_data_directory_count = nonzero_dir_count;
		feats.export_present = opt.dirs[peparse::DIR_EXPORT].VirtualAddress != 0;
		feats.debug_present = opt.dirs[peparse::DIR_DEBUG].VirtualAddress != 0;
		feats.resource_present = opt.dirs[peparse::DIR_RESOURCE].VirtualAddress != 0;
	}
	const peparse::rich_header &rich = pe->peHeader.rich;
	feats.rich_header_entry_count = (rich.isPresent && rich.isValid) ? (SIZE_T)rich.Entries.size() : 0;

	// CLR/.NET特征(4维): COM描述符目录(数据目录索引14)非零即为.NET程序
	if (opt.valid) {
		const peparse::data_directory &clr_dir = opt.dirs[peparse::DIR_COM_DESCRIPTOR];
		feats.is_dotnet = clr_dir.VirtualAddress != 0;
		feats.clr_header_size = clr_dir.Size;
		// 解析IMAGE_COR20_HEADER: 偏移+8处为MetaData数据目录(RVA+Size)，需RVA转文件偏移并做越界检查
		if (feats.is_dotnet && pe->fileBuffer != nullptr && pe->fileBuffer->buf != nullptr) {
			uint64_t clr_off = rva_to_file_offset(clr_dir.VirtualAddress, sections);
			uint64_t file_len = pe->fileBuffer->bufLen;
			if (clr_off != 0 && clr_off + 16 <= file_len) {
				const uint8_t *clr = pe->fileBuffer->buf + clr_off;
				feats.clr_metadata_rva = (SIZE_T)(clr[8] | ((uint32_t)clr[9] << 8) | ((uint32_t)clr[10] << 16) | ((uint32_t)clr[11] << 24));
				feats.clr_metadata_size = (SIZE_T)(clr[12] | ((uint32_t)clr[13] << 8) | ((uint32_t)clr[14] << 16) | ((uint32_t)clr[15] << 24));
			}
		}
	}

	// 壳指纹特征(6维): 在文件字节中搜索壳魔数签名(节名统计已在节段循环中完成)
	if (pe->fileBuffer != nullptr && pe->fileBuffer->buf != nullptr && pe->fileBuffer->bufLen > 0) {
		std::string_view file_bytes((const char *)pe->fileBuffer->buf, pe->fileBuffer->bufLen);
		for (auto &sig : PACKER_MAGIC_SIGNATURES) {
			bool found = contains_word(file_bytes, sig);
			if (!found) {
				continue;
			}
			if (sig == "UPX!") {
				feats.is_upx = true;
			} else if (sig == "VMProtect") {
				feats.is_vmprotect = true;
			} else if (sig == "Themida" || sig == "WinLicense") {
				feats.is_themida = true;
			} else if (sig == "ASPack") {
				feats.is_aspack = true;
			} else {
				feats.is_mpress = true;
			}
		}
	}

	// 同步提取分块熵特征，复用本次PE解析的文件字节，避免重复读盘
	if (block_entropy_out != nullptr && pe->fileBuffer != nullptr && pe->fileBuffer->buf != nullptr) {
		*block_entropy_out = starlight_v3::pe::extract_block_entropy_feats(pe->fileBuffer->buf, pe->fileBuffer->bufLen);
	}

	return feats;
}

PEFeatPack extract_pe_feats(const std::string &file_path, BlockEntropyFeatPack *block_entropy_out) {
	// 读入文件视图后转调视图版本, 非PE(视图加载失败)返回全零特征
	pe::PeView view;
	if (!pe::PeView::load(file_path, view)) {
		if (block_entropy_out != nullptr) {
			*block_entropy_out = BlockEntropyFeatPack {};
		}
		return PEFeatPack {};
	}
	return extract_pe_feats(view, block_entropy_out);
}

} // namespace starlight_v3::lgbm
