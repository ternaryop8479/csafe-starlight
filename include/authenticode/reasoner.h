/**
 * @file authenticode/reasoner.h
 * @brief 白签名表推理器: 将签名者身份折叠为单一置信度特征
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_AUTHENTICODE_REASONER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_AUTHENTICODE_REASONER_H

#include "authenticode/model.h"
#include "pe/authenticode.h"

namespace starlight_v3::authenticode {

/**
 * @brief 白签名表推理器
 * @warning model的生命周期必须长于本对象(构造后不得销毁model)
 */
class Reasoner {

public:
	Reasoner() = delete;
	~Reasoner() = default;

	Reasoner(const Reasoner &) = delete;
	Reasoner &operator=(const Reasoner &) = delete;

	/**
	 * @brief 唯一构造函数
	 * @param model 已构建的白签名表模型
	 */
	explicit Reasoner(const Model &model);

	/**
	 * @brief 将签名者身份折叠为置信度特征
	 * @return 白表命中=1.0; 有签名未命中=0.5(有效但陌生, 弱可疑);
	 *         无签名或解析失败=0.0(完全无信号)
	 */
	double confidence(const pe::CertIdentity &identity) const;

private:
	const Model &model_; ///< 推理使用的白签名表模型
};

} // namespace starlight_v3::authenticode

#endif
