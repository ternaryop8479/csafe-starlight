/**
 * @file authenticode/reasoner.cpp
 * @brief 白签名表推理器实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include "authenticode/reasoner.h"

namespace starlight_v3::authenticode {

Reasoner::Reasoner(const Model &model) : model_(model) {
}

double Reasoner::confidence(const pe::CertIdentity &identity) const {
	if (!identity.present || !identity.der_ok) {
		return 0.0; // 无签名或blob畸形: 完全无信号
	}
	return model_.contains(identity.pubkey_hash) ? 1.0 : 0.5; // 白表命中 / 有效但陌生
}

} // namespace starlight_v3::authenticode
