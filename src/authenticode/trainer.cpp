/**
 * @file authenticode/trainer.cpp
 * @brief 白签名表训练器实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include "authenticode/trainer.h"

namespace starlight_v3::authenticode {

Trainer::Trainer(const TrainerConfig &config, std::function<void(const std::string &)> log_callback)
	: config_(config), log_callback_(std::move(log_callback)) {
}

void Trainer::ingest(const pe::CertIdentity &identity, bool is_malware) {
	// 无签名/畸形blob的样本不参与身份聚合: 前者无信号, 后者身份不可信
	if (!identity.der_ok) {
		return;
	}
	std::lock_guard<std::mutex> lock(stats_mutex_);
	Stat &stat = stats_[identity.pubkey_hash];
	stat.subject_cn = identity.subject_cn;
	if (is_malware) {
		++stat.mal_count;
	} else {
		++stat.ben_count;
	}
}

Model Trainer::build() {
	Model model;
	SIZE_T white_count = 0;
	{
		std::lock_guard<std::mutex> lock(stats_mutex_);
		for (const auto &[hash, stat] : stats_) {
			const SIZE_T total = stat.mal_count + stat.ben_count;
			const double ben_ratio = total != 0 ? static_cast<double>(stat.ben_count) / static_cast<double>(total) : 0.0;
			// 区分度筛选: 良性侧占比与绝对样本量双达标才认定为白名单签名者,
			// 绝对量门槛防止"小样本偶然全良性"的签名者混入白表
			if (stat.ben_count >= config_.min_ben_count && ben_ratio >= config_.white_ben_ratio) {
				model.insert(hash, stat.subject_cn);
				++white_count;
			}
		}
	}
	log_by_callback("[Authenticode::Trainer::build()] 签名者总数=" + std::to_string(stats_.size())
		+ ", 入表白签名=" + std::to_string(white_count) + "\n");
	return model;
}

} // namespace starlight_v3::authenticode
