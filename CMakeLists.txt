# CSafe Starlight V3 杀毒引擎构建脚本
#
# 目标产物:
#   - libstarlight_v3.a 静态库(引擎, 供服务端封装链接)
#   - starlight_v3 命令行工具(训练/跑分/推理)
#
# 构建模式:
#   - Release(默认): -O3 -DNDEBUG -fopenmp-simd(MSVC: /O2 /arch:AVX2)
#   - Debug: -O0 -g(MSVC: /Ob0 /Od)
#
# 依赖策略:
#   优先探测系统已安装的 Zydis/pe-parse/LightGBM(仅UNIX);
#   Windows或缺失时若 CSAFE_FETCH_MISSING_DEPS=ON 则自动从源码 FetchContent 下载构建.
#
# 用法:
#   Linux/macOS: cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
#   Windows(MSVC): cmake -S . -B build -G "Visual Studio 17 2022" -A x64 && cmake --build build --config Release
#   Windows(MinGW): cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release && cmake --build build -j

cmake_minimum_required(VERSION 3.20)
project(csafe_starlight_v3 VERSION 3.0.0 LANGUAGES C CXX)

# ---- 构建类型: 默认 Release ----
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type: Release/Debug" FORCE)
endif()

# ---- 全局编译标准 ----
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- 选项 ----
# 缺失的外部依赖库自动从源码下载构建
option(CSAFE_FETCH_MISSING_DEPS "自动下载构建缺失的外部依赖库" ON)
# Release模式启用本机指令集优化(-march=native), 在部署机本地构建时性能最佳
option(CSAFE_ENABLE_NATIVE_TUNE "Release模式启用本机指令集优化" ON)

# ---- 编译选项 ----
# 注意: tspm/reasoner.h 中使用了 #pragma omp declare simd
# 平台相关: GCC/Clang 用 -fopenmp-simd; MSVC 用 /openmp 的SIMD部分(msvc下pragma被忽略, 仅加优化标志)
# CMake 内置默认: Release=-O3 -DNDEBUG(MSVC为/Ob2 /O2), Debug=-g(MSVC为/Ob0 /Od), 这里只补充额外所需标志
if(MSVC)
	# MSVC: Debug默认已含/Od, Release默认已含/O2; 只需为Release补充开放MP
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		add_compile_options(/Ob0 /Od)
	else()
		add_compile_options(/O2 /arch:AVX2)
	endif()
else()
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		add_compile_options(-O0)
	else()
		add_compile_options(-fopenmp-simd)
		if(CSAFE_ENABLE_NATIVE_TUNE)
			add_compile_options(-march=native)
		endif()
	endif()
endif()

# ---- 线程 ----
find_package(Threads REQUIRED)

# ---- 外部依赖: xxHash(vendored) 与 BS_thread_pool(vendored) ----
# xxhash.c 自带 XXH_STATIC_LINKING_ONLY/XXH_IMPLEMENTATION 定义, 直接编译即可
add_library(xxhash STATIC src/external/xxhash/xxhash.c)
target_include_directories(xxhash PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/external/xxhash)

# BS_thread_pool 为 header-only, 通过 include 目录直接使用

# ---- 外部依赖: Zydis / pe-parse / LightGBM ----
# 优先探测系统库(仅UNIX常见); Windows下系统库通常不存在, 直接走FetchContent自动下载构建
include(FetchContent)

# ---- Zydis ----
if(UNIX)
	find_path(ZYDIS_INCLUDE_DIR NAMES Zydis/Zydis.h)
	find_library(ZYDIS_LIBRARY NAMES Zydis zydis)
endif()
if(ZYDIS_INCLUDE_DIR AND ZYDIS_LIBRARY)
	set(ZYDIS_FOUND_SYSTEM TRUE)
elseif(CSAFE_FETCH_MISSING_DEPS)
	message(STATUS "[WARN] Zydis 未安装, 尝试从源码下载构建...")
	FetchContent_Declare(zydis
		GIT_REPOSITORY https://github.com/zyantific/zydis.git
		GIT_TAG v4.1.0
		GIT_SHALLOW TRUE)
	set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
	set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
	FetchContent_MakeAvailable(zydis)
	set(ZYDIS_TARGET Zydis)
else()
	message(FATAL_ERROR "[ERROR] 未找到 Zydis, 请安装或启用 CSAFE_FETCH_MISSING_DEPS")
endif()

# ---- pe-parse ----
if(UNIX)
	find_path(PE_PARSE_INCLUDE_DIR NAMES pe-parse/parse.h)
	find_library(PE_PARSE_LIBRARY NAMES pe-parse peparse)
endif()
if(PE_PARSE_INCLUDE_DIR AND PE_PARSE_LIBRARY)
	set(PE_PARSE_FOUND_SYSTEM TRUE)
elseif(CSAFE_FETCH_MISSING_DEPS)
	message(STATUS "[WARN] pe-parse 未安装, 尝试从源码下载构建...")
	FetchContent_Declare(peparse
		GIT_REPOSITORY https://github.com/trailofbits/pe-parse.git
		GIT_TAG v2.1.1
		GIT_SHALLOW TRUE)
	FetchContent_MakeAvailable(peparse)
	set(PE_PARSE_TARGET pe-parse)
else()
	message(FATAL_ERROR "[ERROR] 未找到 pe-parse, 请安装或启用 CSAFE_FETCH_MISSING_DEPS")
endif()

# ---- LightGBM ----
if(UNIX)
	find_path(LIGHTGBM_INCLUDE_DIR NAMES LightGBM/c_api.h)
	find_library(LIGHTGBM_LIBRARY NAMES lightgbm)
	if(NOT LIGHTGBM_LIBRARY)
		find_file(LIGHTGBM_LIBRARY_SO NAMES lib_lightgbm.so lib_lightgbm.dylib PATHS /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64)
		if(LIGHTGBM_LIBRARY_SO)
			set(LIGHTGBM_LIBRARY ${LIGHTGBM_LIBRARY_SO})
		endif()
	endif()
endif()
if(LIGHTGBM_INCLUDE_DIR AND LIGHTGBM_LIBRARY)
	set(LIGHTGBM_FOUND_SYSTEM TRUE)
elseif(CSAFE_FETCH_MISSING_DEPS)
	message(STATUS "[WARN] LightGBM 未安装, 尝试从源码下载构建...")
	FetchContent_Declare(lightgbm
		GIT_REPOSITORY https://github.com/microsoft/LightGBM.git
		GIT_TAG v4.5.0
		GIT_SHALLOW TRUE)
	set(USE_GPU OFF CACHE BOOL "" FORCE)
	set(BUILD_STATIC_LIB ON CACHE BOOL "" FORCE)
	set(BUILD_CPP_TEST OFF CACHE BOOL "" FORCE)
	set(BUILD_PYTHON OFF CACHE BOOL "" FORCE)
	set(BUILD_CLI OFF CACHE BOOL "" FORCE)
	FetchContent_MakeAvailable(lightgbm)
	set(LIGHTGBM_TARGET _lightgbm)
else()
	message(FATAL_ERROR "[ERROR] 未找到 LightGBM, 请安装或启用 CSAFE_FETCH_MISSING_DEPS")
endif()

if(ZYDIS_FOUND_SYSTEM)
	add_library(dep_zydis UNKNOWN IMPORTED)
	set_target_properties(dep_zydis PROPERTIES
		IMPORTED_LOCATION ${ZYDIS_LIBRARY}
		INTERFACE_INCLUDE_DIRECTORIES ${ZYDIS_INCLUDE_DIR})
else()
	add_library(dep_zydis ALIAS ${ZYDIS_TARGET})
endif()

if(PE_PARSE_FOUND_SYSTEM)
	add_library(dep_peparse UNKNOWN IMPORTED)
	set_target_properties(dep_peparse PROPERTIES
		IMPORTED_LOCATION ${PE_PARSE_LIBRARY}
		INTERFACE_INCLUDE_DIRECTORIES ${PE_PARSE_INCLUDE_DIR})
else()
	add_library(dep_peparse ALIAS ${PE_PARSE_TARGET})
endif()

if(LIGHTGBM_FOUND_SYSTEM)
	add_library(dep_lightgbm UNKNOWN IMPORTED)
	set_target_properties(dep_lightgbm PROPERTIES
		IMPORTED_LOCATION ${LIGHTGBM_LIBRARY}
		INTERFACE_INCLUDE_DIRECTORIES ${LIGHTGBM_INCLUDE_DIR})
else()
	add_library(dep_lightgbm ALIAS ${LIGHTGBM_TARGET})
endif()

# ---- 引擎静态库 ----
# target名为starlight_v3_lib, 通过OUTPUT_NAME输出libstarlight_v3.a
# (可执行文件target名为starlight_v3, 两者target名不同不冲突)
add_library(starlight_v3_lib STATIC
	src/model.cpp
	src/reasoner.cpp
	src/trainer.cpp
	src/efg_generator.cpp
	src/basic/api_table.cpp
	src/tspm/reasoner.cpp
	src/tspm/trainer.cpp
	src/lgbm/feat_vector.cpp
	src/lgbm/reasoner.cpp
	src/lgbm/trainer.cpp
	src/lgbm/feat_extractor/efg.cpp
	src/lgbm/feat_extractor/pe.cpp
	src/lgbm/feat_extractor/tspm.cpp
)
set_target_properties(starlight_v3_lib PROPERTIES OUTPUT_NAME starlight_v3)

target_include_directories(starlight_v3_lib PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include
	${CMAKE_CURRENT_SOURCE_DIR}/include/external
)

target_link_libraries(starlight_v3_lib
	PUBLIC
		dep_zydis
		dep_peparse
		dep_lightgbm
		xxhash
		Threads::Threads
)

# ---- 命令行工具 ----
add_executable(starlight_v3 src/starlight_v3.cpp)
target_link_libraries(starlight_v3 PRIVATE starlight_v3_lib)

# ---- 安装规则(供服务端封装与模型训练发布使用) ----
include(GNUInstallDirs)
install(TARGETS starlight_v3_lib
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
