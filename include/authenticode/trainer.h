/**
 * @file authenticode/trainer.h
 * @brief 白签名表训练器: 聚合语料签名者黑白计数, 按区分度筛选生成白签名表
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_AUTHENTICODE_TRAINER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_AUTHENTICODE_TRAINER_H

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

#include "authenticode/model.h"
#include "basic/types.h"
#include "pe/authenticode.h"

namespace starlight_v3::authenticode {

/**
 * @brief 白签名表训练配置
 */
struct TrainerConfig {
	// 两字段均带默认值: 训练配置文件为可选(见starlight_v3.cpp的load_train_config),
	// 未指定authenticode_config.*时若无默认值则读取未初始化内存, 白表阈值将不可复现
	double white_ben_ratio = 0.75; ///< 判定为白签名的最低良性占比: ben/(ben+mal) >= 该值
	SIZE_T min_ben_count = 5; ///< 判定为白签名的最低良性样本数(防止小样本偶然命中)
};

/**
 * @brief 白签名表训练器
 *
 * 训练期对语料逐文件提取签名者身份并按黑白标签聚合计数,
 * build()时按区分度配置筛出"几乎只出现在良性侧且样本量足够"的签名者生成白签名表.
 * ingest设计为线程安全, 可由调用方的线程池并行喂入.
 */
class Trainer {

public:
	Trainer() = delete;
	~Trainer() = default;

	/**
	 * @brief 唯一构造函数
	 * @param config 白签名表训练配置
	 * @param log_callback 用于输出日志信息的回调接口
	 */
	Trainer(const TrainerConfig &config, std::function<void(const std::string &)> log_callback);

	/**
	 * @brief 喂入单个样本的签名者身份(线程安全)
	 * @param identity 从PE解析出的签名者身份(present/der_ok为false时自动跳过)
	 * @param is_malware 是否来自恶意数据集
	 */
	void ingest(const pe::CertIdentity &identity, bool is_malware);

	/**
	 * @brief 依据聚合计数与区分度配置构建白签名表
	 * @return 白签名表模型
	 */
	Model build();

private:
	/**
	 * @brief 单个签名者的黑白计数聚合
	 */
	struct Stat {
		SIZE_T mal_count = 0; ///< 恶意侧出现次数
		SIZE_T ben_count = 0; ///< 良性侧出现次数
		std::string subject_cn; ///< 签名者CN(取自最后一次观测)
	};

	TrainerConfig config_; ///< 训练配置
	std::function<void(const std::string &)> log_callback_; ///< 日志回调
	std::mutex log_mutex_; ///< 日志回调锁
	std::mutex stats_mutex_; ///< 聚合表锁(ingest并行喂入)
	std::unordered_map<PubkeyHash, Stat, PubkeyHashHasher> stats_; ///< 公钥哈希 -> 黑白计数聚合

	/**
	 * @brief 线程安全的日志封装
	 */
	inline void log_by_callback(const std::string &msg) {
		std::lock_guard<std::mutex> lock(log_mutex_);
		log_callback_(msg);
	}
};

} // namespace starlight_v3::authenticode

#endif
