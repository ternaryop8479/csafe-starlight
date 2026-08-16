/**
 * @file dataset_filter.cpp
 * @brief 数据集筛选与拷贝工具
 * @author ternaryop8479
 * @date 2026-08-05
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 *
 * 用途: 从任意文件夹递归收集样本, 初筛PE, 生成EFG并标注是否edgeless,
 * 按目标比例裁切(edgeless占总样本的比例), 随机抽取后拷贝到目标目录, 命名[MD5].[原后缀].
 *
 * 用法:
 *   dataset_filter <src_dir> <dst_dir> <edgeless_ratio> [thread_count] [max_samples]
 *     src_dir        源文件夹(递归)
 *     dst_dir        目标文件夹(不存在则创建)
 *     edgeless_ratio 目标edgeless占总样本比例, 取值[0,1], 如0.4表示40%样本为edgeless
 *     thread_count   并行线程数, 默认系统并发
 *     max_samples    最大拷贝样本总数, 超出时按比例缩裁, 0或省略为不限制
 */

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <openssl/md5.h>

#include "efg_generator.h"
#include "external/BS_thread_pool.hpp"

namespace fs = std::filesystem;

namespace {

// 计算文件MD5 by OpenSSL
std::string file_md5(const fs::path &path) {
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs) {
		return "";
	}
	MD5_CTX ctx;
	MD5_Init(&ctx);
	char buf[8192];
	while (ifs) {
		ifs.read(buf, sizeof(buf));
		std::streamsize got = ifs.gcount();
		if (got > 0) {
			MD5_Update(&ctx, buf, static_cast<size_t>(got));
		}
	}
	unsigned char digest[MD5_DIGEST_LENGTH];
	MD5_Final(digest, &ctx);
	// 转hex
	static const char hex_chars[] = "0123456789abcdef";
	std::string result;
	result.reserve(MD5_DIGEST_LENGTH * 2);
	for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
		result.push_back(hex_chars[digest[i] >> 4]);
		result.push_back(hex_chars[digest[i] & 0xf]);
	}
	return result;
}

// 判断是否为PE文件(检查DOS魔数MZ)
bool is_pe_header(const fs::path &path) {
	std::ifstream ifs(path, std::ios::binary);
	if (!ifs) {
		return false;
	}
	uint8_t buf[2] = { 0, 0 };
	ifs.read(reinterpret_cast<char *>(buf), 2);
	return ifs.gcount() == 2 && buf[0] == 'M' && buf[1] == 'Z';
}

// 样本条目: 源路径 + 是否edgeless
struct SampleEntry {
	fs::path src_path; ///< 源文件路径
	bool edgeless; ///< 是否为无边EFG
};

} // namespace

int main(int argc, char *argv[]) {
	if (argc < 4) {
		std::cerr << "用法: " << argv[0] << " <src_dir> <dst_dir> <edgeless_ratio> [thread_count]" << std::endl;
		std::cerr << "  edgeless_ratio: edgeless样本占总样本比例, 取值[0,1], 如0.4表示40%样本为edgeless" << std::endl;
		return -1;
	}
	fs::path src_dir = argv[1];
	fs::path dst_dir = argv[2];
	double target_ratio = 0.0;
	try {
		target_ratio = std::stod(argv[3]);
	} catch (const std::exception &) {
		std::cerr << "[Error] edgeless_ratio参数非法: " << argv[3] << std::endl;
		return -1;
	}
	if (target_ratio < 0.0 || target_ratio > 1.0) {
		std::cerr << "[Error] edgeless_ratio必须取值[0,1], 实际: " << target_ratio << std::endl;
		return -1;
	}
	unsigned int thread_count = 0;
	if (argc >= 5) {
		try {
			thread_count = static_cast<unsigned int>(std::stoul(argv[4]));
		} catch (const std::exception &) {
			std::cerr << "[Error] thread_count参数非法: " << argv[4] << std::endl;
			return -1;
		}
	}
	unsigned int hw = std::thread::hardware_concurrency();
	thread_count = thread_count ? thread_count : (hw ? hw : 4);

	// 最大拷贝样本总数, 0=不限制
	size_t max_samples = 0;
	if (argc >= 6) {
		try {
			max_samples = std::stoull(argv[5]);
		} catch (const std::exception &) {
			std::cerr << "[Error] max_samples参数非法: " << argv[5] << std::endl;
			return -1;
		}
	}

	if (!fs::is_directory(src_dir)) {
		std::cerr << "[Error] 源文件夹不存在: " << src_dir << std::endl;
		return -1;
	}
	fs::create_directories(dst_dir);

	// 1. 单遍递归收集所有文件路径
	std::vector<fs::path> file_paths;
	std::cout << "[Info] 正在遍历 " << src_dir << " ..." << std::endl;
	try {
		for (auto &entry : fs::recursive_directory_iterator(src_dir, fs::directory_options::skip_permission_denied)) {
			if (entry.is_regular_file()) {
				file_paths.push_back(entry.path());
			}
		}
	} catch (const fs::filesystem_error &e) {
		std::cerr << "[Warning] 目录遍历错误: " << e.what() << std::endl;
	}
	std::cout << "[Info] 共发现 " << file_paths.size() << " 个文件" << std::endl;
	if (file_paths.empty()) {
		return -1;
	}

	// 2. 并行: 初筛PE头 + 生成EFG标注edgeless
	//    结果按索引写入, 原子计数进度
	const size_t total_files = file_paths.size();
	std::vector<std::optional<SampleEntry>> results(total_files);
	std::atomic<size_t> processed { 0 };
	std::atomic<size_t> pe_count { 0 };
	std::atomic<size_t> efg_ok_count { 0 };
	std::atomic<size_t> edgeless_count { 0 };
	std::mutex cout_mutex;

	BS::thread_pool pool(thread_count);
	for (size_t i = 0; i < total_files; ++i) {
		pool.detach_task([&, i] {
			const fs::path &p = file_paths[i];
			// 初筛: 非PE直接丢弃(不调用昂贵的generate_efg)
			if (!is_pe_header(p)) {
				processed.fetch_add(1);
				return;
			}
			pe_count.fetch_add(1);
			try {
				auto [ok, efg] = starlight_v3::generate_efg(p.string());
				if (ok) {
					bool edgeless = efg.edges_.empty();
					results[i] = SampleEntry { p, edgeless };
					efg_ok_count.fetch_add(1);
					if (edgeless) {
						edgeless_count.fetch_add(1);
					}
				}
			} catch (...) {
				// 个别样本异常则丢弃
			}
			size_t done = processed.fetch_add(1) + 1;
			if (done % 1000 == 0 || done == total_files) {
				std::lock_guard lock(cout_mutex);
				std::cout << "\r[Info] 已处理 " << done << "/" << total_files << std::flush;
			}
		});
	}
	pool.wait();
	std::cout << "\n[Info] PE文件=" << pe_count << ", EFG生成成功=" << efg_ok_count
			  << ", 其中edgeless=" << edgeless_count << std::endl;

	// 3. 收集有效样本到两个分组
	std::vector<SampleEntry> edgeless_samples;
	std::vector<SampleEntry> normal_samples;
	edgeless_samples.reserve(edgeless_count);
	normal_samples.reserve(efg_ok_count - edgeless_count);
	for (size_t i = 0; i < total_files; ++i) {
		if (results[i].has_value()) {
			if (results[i]->edgeless) {
				edgeless_samples.push_back(*results[i]);
			} else {
				normal_samples.push_back(*results[i]);
			}
		}
	}
	size_t e_count = edgeless_samples.size();
	size_t n_count = normal_samples.size();

	// 4. 按目标比例裁切
	//    目标: edgeless / 总 = target_ratio
	//    优先保留全部普通样本(普通样本稀缺), 再按比例补足edgeless; 若edgeless过多则裁掉edgeless
	//    当无法通过两类样本的组合达到目标比例时(某类完全缺失), 拒绝产出比例失真的数据集, 输出为空
	size_t keep_edgeless = 0, keep_normal = 0;
	if (target_ratio == 0.0) {
		// 全要普通
		keep_edgeless = 0;
		keep_normal = n_count;
	} else if (target_ratio == 1.0) {
		// 全要edgeless
		keep_edgeless = e_count;
		keep_normal = 0;
	} else if (e_count == 0 || n_count == 0) {
		// 某类完全缺失, 任何组合都无法达到目标比例(0<R<1), 输出为空
		std::cerr << "[Warning] 样本分布无法达到目标比例 " << target_ratio
				  << " (edgeless=" << e_count << " 普通=" << n_count
				  << "), 输出为空" << std::endl;
		keep_edgeless = 0;
		keep_normal = 0;
	} else {
		// 以普通样本数为基准: total_keep = n_count / (1-ratio), edgeless_keep = total_keep * ratio
		double total_keep = static_cast<double>(n_count) / (1.0 - target_ratio);
		keep_edgeless = static_cast<size_t>(total_keep * target_ratio + 0.5);
		keep_normal = n_count;
		if (keep_edgeless > e_count) {
			// edgeless不足, 全部保留, 比例达不到但最接近
			keep_edgeless = e_count;
		}
	}

	// 若edgeless过多(比例高于目标), 裁掉部分edgeless
	// 上面的计算已保证 keep_edgeless 不超过目标, 但若 e_count 占比本就低于目标则全保留
	// 实际最终比例
	double final_ratio = (keep_edgeless + keep_normal) > 0
		? static_cast<double>(keep_edgeless) / static_cast<double>(keep_edgeless + keep_normal)
		: 0.0;
	std::cout << "[Info] 保留 edgeless=" << keep_edgeless << " 普通=" << keep_normal
			  << " (实际比例=" << final_ratio << ")" << std::endl;

	// 4.5 若超过最大样本数, 按当前edgeless占比等比例缩裁
	size_t total_keep = keep_edgeless + keep_normal;
	if (max_samples > 0 && total_keep > max_samples) {
		// 按原占比缩放: 每类保留 round(该类 * max_samples / total_keep), 保证总数不超过max_samples
		size_t scaled_edgeless = static_cast<size_t>(
			static_cast<double>(keep_edgeless) * max_samples / total_keep + 0.5);
		size_t scaled_normal = static_cast<size_t>(
			static_cast<double>(keep_normal) * max_samples / total_keep + 0.5);
		// 取整误差可能使总和超限, 多余去掉普通样本(普通样本相对充裕)
		if (scaled_edgeless + scaled_normal > max_samples) {
			scaled_normal = max_samples - scaled_edgeless;
		}
		keep_edgeless = scaled_edgeless;
		keep_normal = scaled_normal;
		std::cout << "[Info] 超过最大样本数 " << max_samples
				  << ", 按比例缩裁后 edgeless=" << keep_edgeless
				  << " 普通=" << keep_normal << std::endl;
	}

	// 5. 随机抽取并拷贝
	//    使用固定种子保证可复现
	std::mt19937 rng(42);
	std::shuffle(edgeless_samples.begin(), edgeless_samples.end(), rng);
	std::shuffle(normal_samples.begin(), normal_samples.end(), rng);
	edgeless_samples.resize(keep_edgeless);
	normal_samples.resize(keep_normal);

	// 合并待拷贝列表
	std::vector<SampleEntry> to_copy;
	to_copy.reserve(keep_edgeless + keep_normal);
	for (auto &s : edgeless_samples)
		to_copy.push_back(std::move(s));
	for (auto &s : normal_samples)
		to_copy.push_back(std::move(s));

	std::cout << "[Info] 开始拷贝 " << to_copy.size() << " 个样本到 " << dst_dir << " ..." << std::endl;
	std::atomic<size_t> copied { 0 };
	std::atomic<size_t> copy_failed { 0 };
	std::atomic<size_t> duplicate { 0 };

	for (auto &sample : to_copy) {
		pool.detach_task([&, sample] {
			// 计算源文件MD5
			std::string md5 = file_md5(sample.src_path);
			if (md5.empty()) {
				copy_failed.fetch_add(1);
				copied.fetch_add(1);
				return;
			}
			// 目标文件名: [MD5].[原后缀]
			std::string ext = sample.src_path.extension().string();
			std::string dst_name = ext.empty() ? md5 : (md5 + ext);
			fs::path dst_path = dst_dir / dst_name;
			std::error_code ec;
			// skip_existing: 目标已存在(同MD5去重)则返回false且不报错, 并发安全
			bool ok = fs::copy_file(sample.src_path, dst_path, fs::copy_options::skip_existing, ec);
			if (ok) {
				copied.fetch_add(1);
			} else if (ec) {
				copy_failed.fetch_add(1);
			} else {
				duplicate.fetch_add(1); // 目标已存在, 跳过
			}
		});
	}
	pool.wait();

	std::cout << "[Info] 完成. 拷贝=" << copied.load() << " 失败=" << copy_failed.load()
			  << " 重复跳过=" << duplicate.load() << std::endl;
	return 0;
}
