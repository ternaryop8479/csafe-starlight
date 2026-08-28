/**
 * @file pe/capability.cpp
 * @brief 导入API能力类别特征提取实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <initializer_list>
#include <string>

#include "pe/capability.h"
#include "pe/imports.h"

namespace starlight_v3::pe {

namespace {

	bool has(const std::string &name, std::initializer_list<const char *> needles) {
		for (const char *needle : needles) {
			if (name.find(needle) != std::string::npos)
				return true;
		}
		return false;
	}

} // namespace

CapabilityFeatPack extract_capability_feats(const std::vector<ImportEntry> &imports) {
	CapabilityFeatPack feats = {};
	for (const auto &entry : imports) {
		const std::string &name = entry.function_name;
		if (has(name, { "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread", "SetWindowsHookEx" }))
			++feats.injection_count;
		if (has(name, { "Debugger", "DebugActiveProcess", "NtQueryInformationProcess", "OutputDebugString" }))
			++feats.anti_debug_count;
		if (has(name, { "socket", "connect", "WSA", "Internet", "WinHttp", "HttpSend" }))
			++feats.network_count;
		if (has(name, { "URLDownload", "InternetReadFile", "WinHttpReadData", "BITS" }))
			++feats.download_count;
		if (has(name, { "CreateProcess", "OpenProcess", "TerminateProcess", "Process32" }))
			++feats.process_count;
		if (has(name, { "CreateService", "OpenSCManager", "StartService" }))
			++feats.service_count;
		if (has(name, { "RegOpen", "RegCreate", "RegSet", "RegQuery", "RegDelete" }))
			++feats.registry_count;
		if (has(name, { "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "FindFirstFile" }))
			++feats.file_count;
		if (has(name, { "Crypt", "BCrypt", "NCrypt" }))
			++feats.crypto_count;
		if (has(name, { "ShellExecute", "WinExec", "CreateProcess" }))
			++feats.shell_count;
		if (has(name, { "VirtualAlloc", "VirtualProtect", "MapViewOfFile", "HeapAlloc" }))
			++feats.memory_count;
		if (has(name, { "CreateMutex", "CreateEvent", "CreatePipe", "MapViewOfFile" }))
			++feats.ipc_count;
	}
	return feats;
}

} // namespace starlight_v3::pe
