# CSafe Starlight V3

基于 tosSPM 语义分析引擎 + LightGBM 集成学习的 Windows PE 恶意样本检测引擎。

该引擎从 PE 文件中提取外部调用流程图(EFG)，通过基于 [tosSpan 有向图频繁调用链挖掘算法](https://blog.ternaryop.top/archives/BcOfhQzF)的 tosSPM 引擎挖掘 API 调用链并构建 Trie 树模型，融合 214 维特征与 LightGBM 二分类打分，最终输出样本的恶意概率与可解释的证据树。

项目当前已集成进 [CFTQ 查杀云](https://cftq-cloud.nanoera.top/) 并保持云端病毒库实时更新。

## 项目简介

```
PE 文件 ──┬─► EFG 生成(反汇编控制流) ──┬─► EFG 特征(36维) ──────────────────────────────┐
          │                            └─► tosSPM 语义推理(调用链挖掘) ──► 特征(35维) ──┤
           └─► PE 静态特征及结构特征(91维+16维) ───────────────────────────────────┴─► 214维特征 ──► LightGBM 打分 ──► 三分类判定(安全/可疑/病毒) + 证据树
```

- **EFG 提取**：基于 Zydis 反汇编，从入口点遍历控制流，提取 API 调用图(含 thunk 跳板与 IAT 导入解析)
- **tosSPM 引擎**：基于 tosSpan 算法实现的频繁 API 调用链挖掘(支持跳过混淆 API)、Trie 树模型、DFS 风险推理、证据树导出
- **特征提取**：EFG 36 维 + tosSPM 35 维 + PE 静态 143 维 (静态特征 91 维，结构熵 16 维，签名置信度 2 维，Rich Header 10 维，.NET 24 维)，共 214 维
- **模型集成**：交叉验证生成特征，LightGBM 二分类训练与推理

## 项目外部依赖

| 依赖 | 用途 | 仓库 |
|---|---|---|
| [Zydis](https://github.com/zyantific/zydis) | x86/x64 反汇编解码 | https://github.com/zyantific/zydis |
| [pe-parse](https://github.com/trailofbits/pe-parse) | PE 文件解析 | https://github.com/trailofbits/pe-parse |
| [LightGBM](https://github.com/microsoft/LightGBM) | 梯度提升决策树训练/推理 | https://github.com/microsoft/LightGBM |
| [xxHash](https://github.com/Cyan4973/xxHash) | 调用链哈希(内置 vendored) | https://github.com/Cyan4973/xxHash |
| [BS::thread_pool](https://github.com/bshoshany/thread-pool) | 并行训练/推理(内置 vendored) | https://github.com/bshoshany/thread-pool |
| [OpenSSL](https://www.openssl.org/) | 数据集筛选工具的文件 MD5 计算 | https://github.com/openssl/openssl |

CMakeLists.txt依赖策略：优先探测系统已安装的 Zydis/pe-parse/LightGBM(仅 UNIX)；缺失时若启用 `CSAFE_FETCH_MISSING_DEPS`(默认开启)则自动从源码下载构建。xxHash 与 BS::thread_pool 为内置 vendored 依赖，直接编译。

> **OpenSSL**：编译器/工具链不预装(LLVM/MSVC/GCC/Clang/MinGW 均不内置)。仅构建 `dataset_filter` 时必需，需自行安装 `libssl-dev`(Linux) 或 vcpkg 安装 `openssl`(Windows)，引擎本体不依赖 OpenSSL(仅编译引擎静态库文件或cli工具的话需要修改CMakeLists.txt删掉openssl依赖)。

## 编译方法

要求：CMake ≥ 3.20，支持 C++20 的编译器。

```bash
# Release
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# Debug
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug -j
```

Windows(MSVC)：

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release -j
```

可选开关：

| 选项 | 默认 | 说明 |
|---|---|---|
| `CSAFE_FETCH_MISSING_DEPS` | ON | 缺失的外部依赖自动从源码下载构建 |
| `CSAFE_ENABLE_NATIVE_TUNE` | ON | Release 模式启用 `-march=native` 本机指令集优化 |

编译产物：

- `libstarlight_v3.a`：引擎静态库
- `starlight_v3`：命令行工具
- `dataset_filter`：数据集筛选工具(需 OpenSSL)

安装(供服务端集成)：

```bash
cmake --install build --prefix /usr/local
# 安装出 lib/libstarlight_v3.a 与全部头文件
```

## 命令行接口

```text
starlight_v3 train <malware_dir> <benign_dir> <model_path> <config_path> [max_train_samples] [version]
starlight_v3 score <model_path> <malware_dir> <benign_dir> [max_score_samples]
starlight_v3 infer <model_path> <target> [max_samples] [threads] [low_th] [high_th]
```

使用示例：

```bash
# 训练(需训练参数配置, version 为 YY.MM.DD 形式的病毒库日期标记)
./build/starlight_v3 train ./dataset/malware ./dataset/benign ./model.starlv3.bin ./default_train_param.conf 1000 26.08.20

# 跑分(评估模型)
./build/starlight_v3 score ./model.starlv3.bin ./dataset/malware ./dataset/benign

# 推理: 单个文件(未指定阈值时为二分类, 默认0.5)
./build/starlight_v3 infer ./model.starlv3.bin ./samples/virus.exe

# 推理: 文件夹(递归, 三分类: score>=high_th=病毒 / low_th<=score<high_th=可疑 / score<low_th=安全)
./build/starlight_v3 infer ./model.starlv3.bin ./samples/ 0 0 0.1 0.2
```

## 模型下载
详见[模型列表](ModelList.md)。

## 接口文档

这么简单的项目，自己读include/不就好了（bushi）

但是我的头文件注释和使用说明真的写的很全！不信你读一读（

## AI 使用声明

本项目的部分代码由 AI 辅助编写。AI 编写的文件已在文件头部通过 `@note 该文件主体为AI编写，人工负责精细审查并重排、规范源码。` 标注。所有 AI 生成代码均经过人工逐文件审查、编码风格对齐与逻辑核验。tosSPM 核心引擎(语义分析、调用链挖掘、推理算法)由人工实现。

## 版权声明

Copyright (C) 2026 ternaryop8479

本项目使用 [LGPL v3](LICENSE) 开源许可协议。
