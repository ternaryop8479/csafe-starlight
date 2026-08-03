/**
 * @file reasoner.h
 * @brief 最终推理器接口声明(整合推理层)
 * @author ternaryop8479
 * @date 2026-08-03
 * @note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。
 */

#ifndef CSAFE_STARLIGHT_V3_INCLUDE_REASONER_H
#define CSAFE_STARLIGHT_V3_INCLUDE_REASONER_H

#include <string>

#include "basic/efg.h"
#include "basic/feat_pack.h"
#include "lgbm/reasoner.h"
#include "model.h"
#include "tspm/reasoner.h"

namespace starlight_v3 {

/**
 * @brief 最终推理结果
 * @details 包含LightGBM的最终判定、tosSPM引擎的原始结果(含证据树)以及本次分析的全部特征
 */
struct AnalysisResult {
	double final_score; ///< 最终恶意概率, 值域[0, 1], 越接近1越可能为恶意(LightGBM二分类输出)
	tspm::AnalysisResult tspm_result; ///< tosSPM引擎的推理结果(含证据树, 可交给extract_evidence_dot导出)
	FeatPack feats; ///< 本次分析提取的全部171维特征(可解释性/调试用)
};

/**
 * @brief 将推理结果的证据树导出为Graphviz DOT文件
 * @param result 推理结果
 * @param filename 输出的DOT文件路径(如"result.dot"), 可用"dot -Tpng x.dot -o out.png"渲染
 */
void extract_evidence_dot(const AnalysisResult &result, const std::string &filename);

/**
 * @brief 最终推理器(编排层)
 * @details 职责为整个推理流程的编排:
 * 1. 使用tosSPM模型推理(记录证据树);
 * 2. 从推理结果与EFG/PE文件中提取171维特征;
 * 3. 使用LightGBM模型对特征向量打分, 输出最终恶意概率.
 * 该对象持有LightGBM Booster句柄且持有模型引用, 禁止拷贝;
 * 多线程推理时请每个线程独立构造实例.
 * @warning model的生命周期必须长于本对象(构造后不得销毁model),
 * 严禁以临时Model对象构造本类(如Reasoner(Model::load_from_file(...)))
 */
class Reasoner {

public:
	/**
	 * @brief 唯一构造函数
	 * @param model 已加载的最终模型, 构造时同时初始化tosSPM推理器与LightGBM推理器
	 */
	explicit Reasoner(const Model &model);
	~Reasoner();

	Reasoner(const Reasoner &) = delete;
	Reasoner &operator=(const Reasoner &) = delete;

	/**
	 * @brief 对已知EFG进行分析(不提取PE特征, PE特征全零)
	 * @param efg 目标程序的EFG
	 * @return 分析结果
	 */
	AnalysisResult analyze_efg(const EFG &efg);

	/**
	 * @brief 对已知EFG进行分析(提取完整171维特征)
	 * @param efg 目标程序的EFG
	 * @param file_path 目标程序PE文件的路径, 用于提取PE静态特征
	 * @return 分析结果
	 */
	AnalysisResult analyze_efg(const EFG &efg, const std::string &file_path);

	/**
	 * @brief 对指定PE文件进行分析(内部自动生成EFG)
	 * @param file_path 目标程序PE文件的路径
	 * @return 分析结果
	 * @throw std::runtime_error EFG生成失败时抛出
	 */
	AnalysisResult analyze_file(const std::string &file_path);

private:
	const Model &model_; ///< 推理使用的最终模型
	tspm::Reasoner tspm_reasoner_; ///< tosSPM推理器
	lgbm::Reasoner lgbm_reasoner_; ///< LightGBM推理器
};

} // namespace starlight_v3

#endif
