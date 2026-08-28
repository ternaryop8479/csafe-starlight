/**
 * @file pe/authenticode.cpp
 * @brief PE属性证书(Authenticode)解析器实现
 * @author ternaryop8479
 * @date 2026-08-26
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#include <cstring>
#include <memory>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "pe/authenticode.h"

namespace starlight_v3::pe {

namespace {

	// 属性证书blob头: dwLength(4) + wRevision(2) + wCertificateType(2), bCertificate自偏移8开始
	constexpr size_t kWinCertHeaderSize = 8;
	constexpr size_t kWinCertRevisionOffset = 4;
	constexpr size_t kWinCertTypeOffset = 6;
	constexpr uint16_t kWinCertTypePkcsSignedData = 0x0002;
	// wRevision合法取值(0x0200恰为type值0x0002的字节交换值，一并校验以免两字段偏移写反被掩盖)
	constexpr uint16_t kWinCertRevision1 = 0x0100;
	constexpr uint16_t kWinCertRevision2 = 0x0200;

	// 从blob指定偏移按小端读取整数(memcpy规避未对齐访问, 不做边界检查, 调用方须先完成边界校验)
	uint32_t read_le_u32(const uint8_t *base, size_t offset = 0) {
		uint32_t value = 0;
		std::memcpy(&value, base + offset, sizeof(value));
		return value;
	}

	uint16_t read_le_u16(const uint8_t *base, size_t offset = 0) {
		uint16_t value = 0;
		std::memcpy(&value, base + offset, sizeof(value));
		return value;
	}

	// 对字节串计算SHA256, 摘要失败时返回false
	// (全零哈希会把互不相关的签名者聚合成同一白表主键, 故必须让调用方能区分失败)
	bool sha256(const uint8_t *data, size_t len, std::array<uint8_t, 32> &out) {
		unsigned int out_len = 0;
		if (EVP_Digest(data, len, out.data(), &out_len, EVP_sha256(), nullptr) != 1) {
			return false;
		}
		return out_len == out.size();
	}

	// 从X509证书提取身份: 公钥SPKI DER的SHA256 + 签发者/签名者CN
	bool extract_identity(X509 *cert, CertIdentity &id) {
		if (cert == nullptr) {
			return false;
		}

		// 公钥 -> SubjectPublicKeyInfo DER -> SHA256作为跨样本稳定的身份主键
		EVP_PKEY *pkey = X509_get_pubkey(cert);
		if (pkey == nullptr) {
			return false;
		}
		unsigned char *spki_der = nullptr;
		const int spki_len = i2d_PUBKEY(pkey, &spki_der);
		EVP_PKEY_free(pkey);
		if (spki_len <= 0 || spki_der == nullptr) {
			return false;
		}
		const bool hash_ok = sha256(spki_der, static_cast<size_t>(spki_len), id.pubkey_hash);
		OPENSSL_free(spki_der);
		if (!hash_ok) {
			return false;
		}

		// 签发者/签名者CN(取不到时留空, 不影响主键)
		char cn[256] = {};
		if (X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_commonName, cn, sizeof(cn)) > 0) {
			id.issuer_cn = cn;
		}
		if (X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof(cn)) > 0) {
			id.subject_cn = cn;
		}
		return true;
	}

	// 从PKCS#7中按signer_info定位签名者的叶证书
	// 注意: 证书栈顺序无规范约束(混装叶证书/中间CA/根CA/时间戳证书)，取首张会把同一CA签发的
	// 不同厂商折叠成同一身份主键，故必须按issuer+serial精确定位
	X509 *find_signer_cert(PKCS7 *p7) {
		if (p7 == nullptr) {
			return nullptr;
		}
		// 必须先经PKCS7_get_signer_info确认内容类型: PKCS7::d是联合体, d.sign仅在signedData
		// (或signedAndEnveloped)下才是PKCS7_SIGNED*, 直接访问d.sign->cert会把其他类型的较小对象
		// 按PKCS7_SIGNED布局解读而越界读。该函数内部会校验类型, 非签名类型返回nullptr
		STACK_OF(PKCS7_SIGNER_INFO) *signer_infos = PKCS7_get_signer_info(p7);
		if (signer_infos == nullptr || sk_PKCS7_SIGNER_INFO_num(signer_infos) <= 0) {
			return nullptr;
		}
		if (p7->d.sign == nullptr) {
			return nullptr;
		}
		STACK_OF(X509) *certs = p7->d.sign->cert;
		if (certs == nullptr || sk_X509_num(certs) <= 0) {
			return nullptr;
		}
		// 单签名者场景取首个signer_info即可(多签名者的白表多键扩展留待后续)
		const PKCS7_SIGNER_INFO *signer_info = sk_PKCS7_SIGNER_INFO_value(signer_infos, 0);
		if (signer_info == nullptr || signer_info->issuer_and_serial == nullptr) {
			return nullptr;
		}
		return X509_find_by_issuer_and_serial(certs,
			signer_info->issuer_and_serial->issuer,
			signer_info->issuer_and_serial->serial);
	}

} // namespace

CertIdentity inspect_signature(const PeView &pv) {
	CertIdentity id;

	// 安全目录为数据目录第5项(下标4): 其rva字段实际是文件偏移而非RVA(PE规范如此定义)
	const PeView::Dir sec_dir = pv.data_dir(4);
	if (sec_dir.rva == 0 || sec_dir.size == 0 || static_cast<uint64_t>(sec_dir.rva) + sec_dir.size > pv.size()) {
		return id; // 未签名或blob越界: present保持false
	}
	id.present = true;
	id.blob_size = sec_dir.size;

	const uint8_t *blob = pv.data() + sec_dir.rva;

	// WIN_CERTIFICATE头校验: 修订号与类型均须合法, dwLength与目录Size一致(取小防御畸形值)
	if (sec_dir.size < kWinCertHeaderSize) {
		return id;
	}
	const uint32_t cert_length = read_le_u32(blob);
	const uint16_t cert_revision = read_le_u16(blob + kWinCertRevisionOffset);
	const uint16_t cert_type = read_le_u16(blob + kWinCertTypeOffset);
	if (cert_revision != kWinCertRevision1 && cert_revision != kWinCertRevision2) {
		return id;
	}
	if (cert_type != kWinCertTypePkcsSignedData) {
		return id;
	}
	// dwLength含8字节头, 小于头长说明blob畸形; 不设该下限则cert_length-8会回绕成近4GiB,
	// 使d2i_PKCS7被授权在文件缓冲区之外解析
	if (cert_length != 0 && cert_length < kWinCertHeaderSize) {
		return id;
	}
	// dwLength与目录Size取小者为准, 防御声明长度超出目录范围的畸形值
	const uint32_t pkcs7_len = (cert_length != 0 && cert_length <= sec_dir.size)
		? cert_length - kWinCertHeaderSize
		: sec_dir.size - kWinCertHeaderSize;

	// 解析PKCS#7: d2i_PKCS7消费的是bCertificate起始处的DER
	const uint8_t *der = blob + kWinCertHeaderSize;
	PKCS7 *p7 = d2i_PKCS7(nullptr, &der, pkcs7_len);
	if (p7 == nullptr) {
		ERR_clear_error(); // 畸形blob属预期情形, 清除错误栈避免污染后续解析
		return id;
	}
	// RAII: extract_identity内的std::string赋值可能抛异常, 裸PKCS7_free不异常安全
	const std::unique_ptr<PKCS7, decltype(&PKCS7_free)> p7_guard(p7, &PKCS7_free);

	// 按signer_info定位签名者的叶证书
	X509 *signer = find_signer_cert(p7);
	if (extract_identity(signer, id)) {
		id.der_ok = true;
	} else {
		ERR_clear_error();
	}
	return id;
}

} // namespace starlight_v3::pe
