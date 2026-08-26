/**
 * @file pe/authenticode.h
 * @brief PE属性证书(Authenticode)解析器: 定位安全目录并提取签名者身份
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_PE_AUTHENTICODE_H
#define CSAFE_STARLIGHT_V3_INCLUDE_PE_AUTHENTICODE_H

#include <array>
#include <cstdint>
#include <string>

#include "pe/view.h"

namespace starlight_v3::pe {

/**
 * @brief 从PE文件中提取出的签名者身份
 */
struct CertIdentity {
	bool present = false; ///< 安全目录存在且含非空证书blob
	bool der_ok = false; ///< PKCS#7解析成功并提取出签名者公钥(畸形blob时为false)
	std::array<uint8_t, 32> pubkey_hash = {}; ///< SHA256(签名者公钥SPKI DER), 仅der_ok时有效
	std::string issuer_cn; ///< 签发者CN(日志与训练聚合展示用)
	std::string subject_cn; ///< 签名者CN(日志与训练聚合展示用)
	uint32_t blob_size = 0; ///< 属性证书blob总大小(字节)
};

/**
 * @brief 解析PE的Authenticode签名, 提取签名者身份
 * @param pv 已加载的PE视图
 * @return 签名者身份; 未签名时present=false, 签名存在但blob畸形时present=true且der_ok=false,
 *         两者的区分度语义不同(前者为完全无信号, 后者为"有伪装意图"), 调用方需分别处理.
 * @note 解析使用OpenSSL(d2i_PKCS7/X509), 公钥哈希取SHA256(SubjectPublicKeyInfo DER),
 *       该值对同一证书的所有签名文件稳定, 可作为跨样本的身份主键.
 */
CertIdentity inspect_signature(const PeView &pv);

} // namespace starlight_v3::pe

#endif
