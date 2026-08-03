/**
 * @file lgbm/detail/lgbm_handle.h
 * @brief LightGBM C API句柄的RAII封装与错误检查
 * @author ternaryop8479
 * @date 2026-08-03
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_LGBM_DETAIL_LGBM_HANDLE_H
#define CSAFE_STARLIGHT_V3_INCLUDE_LGBM_DETAIL_LGBM_HANDLE_H

#include <LightGBM/c_api.h>
#include <stdexcept>
#include <string>
#include <utility>

namespace starlight_v3::lgbm::detail {

/**
 * @brief 检查LightGBM C API的返回值，失败时抛出异常
 * @param ret LightGBM C API的返回值，0代表成功，-1代表失败
 * @throw std::runtime_error 调用失败时抛出，错误信息来自LGBM_GetLastError
 */
inline void check_lgbm_status(int ret) {
	if (ret != 0) {
		throw std::runtime_error("LightGBM C API call failed: " + std::string(LGBM_GetLastError()));
	}
}

/**
 * @brief Booster句柄的RAII封装，析构时自动调用LGBM_BoosterFree释放
 * @details 该类不可拷贝(句柄是C指针不能共享所有权)，只可移动
 */
struct BoosterHandleGuard {
	BoosterHandle handle = nullptr; ///< 被管理的Booster句柄

	BoosterHandleGuard() = default;
	explicit BoosterHandleGuard(BoosterHandle h) : handle(h) {}
	~BoosterHandleGuard() {
		if (handle) {
			LGBM_BoosterFree(handle);
		}
	}
	BoosterHandleGuard(const BoosterHandleGuard &) = delete;
	BoosterHandleGuard &operator=(const BoosterHandleGuard &) = delete;
	BoosterHandleGuard(BoosterHandleGuard &&other) noexcept : handle(other.handle) {
		other.handle = nullptr;
	}
	BoosterHandleGuard &operator=(BoosterHandleGuard &&other) noexcept {
		if (this != &other) {
			if (handle) {
				LGBM_BoosterFree(handle);
			}
			handle = other.handle;
			other.handle = nullptr;
		}
		return *this;
	}
};

/**
 * @brief Dataset句柄的RAII封装，析构时自动调用LGBM_DatasetFree释放
 * @details 该类不可拷贝(句柄是C指针不能共享所有权)，只可移动
 */
struct DatasetHandleGuard {
	DatasetHandle handle = nullptr; ///< 被管理的Dataset句柄

	DatasetHandleGuard() = default;
	explicit DatasetHandleGuard(DatasetHandle h) : handle(h) {}
	~DatasetHandleGuard() {
		if (handle) {
			LGBM_DatasetFree(handle);
		}
	}
	DatasetHandleGuard(const DatasetHandleGuard &) = delete;
	DatasetHandleGuard &operator=(const DatasetHandleGuard &) = delete;
	DatasetHandleGuard(DatasetHandleGuard &&other) noexcept : handle(other.handle) {
		other.handle = nullptr;
	}
	DatasetHandleGuard &operator=(DatasetHandleGuard &&other) noexcept {
		if (this != &other) {
			if (handle) {
				LGBM_DatasetFree(handle);
			}
			handle = other.handle;
			other.handle = nullptr;
		}
		return *this;
	}
};

} // namespace starlight_v3::lgbm::detail

#endif
