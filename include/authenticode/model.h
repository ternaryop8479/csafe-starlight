/**
 * @file authenticode/model.h
 * @brief 白签名表模型: 签名者公钥哈希 -> 信任标签 的内存表与序列化
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_AUTHENTICODE_MODEL_H
#define CSAFE_STARLIGHT_V3_INCLUDE_AUTHENTICODE_MODEL_H

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>

namespace starlight_v3::authenticode {

/**
 * @brief 签名者公钥哈希主键(SHA256(SubjectPublicKeyInfo DER))
 */
using PubkeyHash = std::array<uint8_t, 32>;

/**
 * @brief 公钥哈希的unordered_map哈希器(std::array无默认std::hash特化)
 */
struct PubkeyHashHasher {
	size_t operator()(const PubkeyHash &hash) const noexcept {
		size_t lo = 0, hi = 0;
		std::memcpy(&lo, hash.data(), sizeof(lo));
		std::memcpy(&hi, hash.data() + sizeof(lo), sizeof(hi));
		return lo ^ (hi * 0x9e3779b97f4a7c15ULL); // 高低两半乘黄金比异或混合
	}
};

/**
 * @brief 白签名表模型
 *
 * 存储训练语料中经区分度筛选确认的"白名单签名者"。表随模型文件一并序列化,
 * 推理端据此将签名者身份折叠为单一置信度特征。
 */
class Model {

public:
	Model() = default;
	~Model() = default;

	/**
	 * @brief 写入一条白签名记录(已存在时仅更新CN展示串)
	 * @param pubkey_hash 签名者公钥哈希主键
	 * @param subject_cn 签名者CN(仅用于日志与人工审核展示)
	 */
	void insert(const PubkeyHash &pubkey_hash, const std::string &subject_cn);

	/**
	 * @brief 查询公钥哈希是否命中白签名表
	 */
	bool contains(const PubkeyHash &pubkey_hash) const;

	/**
	 * @brief 获取表内条目数
	 */
	size_t size() const;

	/**
	 * @brief 将整张表序列化为二进制(供嵌入模型文件)
	 * @return 序列化字节串
	 */
	std::string serialize() const;

	/**
	 * @brief 从二进制反序列化恢复白签名表
	 * @param data 序列化字节串
	 * @return 反序列化失败(截断/计数越界)返回空模型
	 */
	static Model deserialize(const std::string &data);

private:
	std::unordered_map<PubkeyHash, std::string, PubkeyHashHasher> entries_; ///< 公钥哈希 -> 签名者CN
};

} // namespace starlight_v3::authenticode

#endif
