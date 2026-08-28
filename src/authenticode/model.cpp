/**
 * @file authenticode/model.cpp
 * @brief 白签名表模型实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <cstring>

#include "authenticode/model.h"

namespace starlight_v3::authenticode {

namespace {

	// 序列化布局: count u32 + N × [pubkey_hash 32B | cn_len u16 | cn bytes]
	// 单条目固定34字节起步, 反序列化时以此做防御性计数校验
	constexpr size_t kEntryFixedSize = 32 + 2;

	void put_u32(std::string &out, uint32_t value) {
		char buf[4] = {};
		std::memcpy(buf, &value, sizeof(buf));
		out.append(buf, sizeof(buf));
	}

	void put_u16(std::string &out, uint16_t value) {
		char buf[2] = {};
		std::memcpy(buf, &value, sizeof(buf));
		out.append(buf, sizeof(buf));
	}

	bool get_u32(const char *data, size_t size, size_t &offset, uint32_t &value) {
		if (offset + 4 > size) {
			return false;
		}
		std::memcpy(&value, data + offset, 4);
		offset += 4;
		return true;
	}

	bool get_u16(const char *data, size_t size, size_t &offset, uint16_t &value) {
		if (offset + 2 > size) {
			return false;
		}
		std::memcpy(&value, data + offset, 2);
		offset += 2;
		return true;
	}

} // namespace

void Model::insert(const PubkeyHash &pubkey_hash, const std::string &subject_cn) {
	auto it = entries_.find(pubkey_hash);
	if (it != entries_.end()) {
		it->second = subject_cn; // 同主键重复出现时仅刷新CN展示串
		return;
	}
	entries_.emplace(pubkey_hash, subject_cn);
}

bool Model::contains(const PubkeyHash &pubkey_hash) const {
	return entries_.count(pubkey_hash) != 0;
}

size_t Model::size() const {
	return entries_.size();
}

std::string Model::serialize() const {
	std::string out;
	put_u32(out, static_cast<uint32_t>(entries_.size()));
	for (const auto &[hash, subject_cn] : entries_) {
		out.append(reinterpret_cast<const char *>(hash.data()), hash.size());
		put_u16(out, static_cast<uint16_t>(subject_cn.size()));
		out.append(subject_cn);
	}
	return out;
}

Model Model::deserialize(const std::string &data) {
	Model model;
	const char *raw = data.data();
	const size_t size = data.size();
	size_t offset = 0;
	uint32_t count = 0;
	if (!get_u32(raw, size, offset, count)) {
		return model;
	}
	// 防御: 每条目至少kEntryFixedSize字节, 计数超界视为数据损坏直接放弃
	if (static_cast<size_t>(count) > (size - offset) / kEntryFixedSize) {
		return model;
	}
	for (uint32_t i = 0; i < count; ++i) {
		PubkeyHash hash = {};
		if (offset + hash.size() > size) {
			return Model();
		}
		std::memcpy(hash.data(), raw + offset, hash.size());
		offset += hash.size();
		uint16_t cn_len = 0;
		if (!get_u16(raw, size, offset, cn_len)) {
			return Model();
		}
		if (offset + cn_len > size) {
			return Model();
		}
		model.entries_.emplace(hash, std::string(raw + offset, cn_len));
		offset += cn_len;
	}
	return model;
}

} // namespace starlight_v3::authenticode
