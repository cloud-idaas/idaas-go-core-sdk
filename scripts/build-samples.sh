#!/usr/bin/env bash
#
# build-samples.sh — 交叉编译 samples/ 目录下的 sample 程序为各平台二进制
#
# 用法：
#   ./scripts/build-samples.sh                            # 默认：所有 sample × (linux/amd64, linux/arm64)
#   ./scripts/build-samples.sh -s obtain_token            # 指定单个 sample（可省略 _sample 后缀）
#   ./scripts/build-samples.sh -s obtain -p linux/amd64   # 指定单个 sample + 单个平台
#   ./scripts/build-samples.sh -p linux/amd64,darwin/arm64 # 自定义平台列表
#   ./scripts/build-samples.sh -l                         # 列出所有可用的 sample
#   ./scripts/build-samples.sh -o /tmp/out                # 指定输出目录
#   ./scripts/build-samples.sh -h                         # 帮助
#
# 可用 sample（4 个）：
#   obtain_token_sample       —— 通用入口，覆盖全部 8 种 CLIENT authnMethod
#   device_code_sample        —— HUMAN identity 的 Device Code 流程
#   refresh_token_sample      —— refresh_token 续期
#   token_exchange_sample     —— RFC 8693 token exchange
#
# 输出文件命名：build/<sample>-<goos>-<goarch>[.exe]
#
# 设计说明：
#   - samples/ 下每个 .go 文件都是独立的 package main，必须单文件编译
#   - 默认使用 CGO_ENABLED=0 静态链接，可在任意 Linux 发行版直接运行
#   - 使用 -trimpath -ldflags "-s -w" 去除路径和符号信息，二进制更小、更干净

set -euo pipefail

# ---------------- 默认配置 ----------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SAMPLES_DIR="${REPO_ROOT}/samples"
OUTPUT_DIR="${REPO_ROOT}/build"
DEFAULT_PLATFORMS="linux/amd64,linux/arm64"

# ---------------- 颜色 ----------------
if [[ -t 1 ]]; then
    C_GREEN="\033[32m"; C_RED="\033[31m"; C_YELLOW="\033[33m"; C_CYAN="\033[36m"; C_RESET="\033[0m"
else
    C_GREEN=""; C_RED=""; C_YELLOW=""; C_CYAN=""; C_RESET=""
fi

log_info()  { echo -e "${C_CYAN}[INFO]${C_RESET}  $*"; }
log_ok()    { echo -e "${C_GREEN}[OK]${C_RESET}    $*"; }
log_warn()  { echo -e "${C_YELLOW}[WARN]${C_RESET}  $*"; }
log_error() { echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; }

# ---------------- 参数解析 ----------------
SAMPLE_FILTER=""
PLATFORMS="${DEFAULT_PLATFORMS}"
LIST_ONLY=false

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while getopts ":s:p:o:lh" opt; do
    case "${opt}" in
        s) SAMPLE_FILTER="${OPTARG}" ;;
        p) PLATFORMS="${OPTARG}" ;;
        o) OUTPUT_DIR="${OPTARG}" ;;
        l) LIST_ONLY=true ;;
        h) usage ;;
        \?) log_error "未知参数: -${OPTARG}"; usage ;;
        :)  log_error "参数 -${OPTARG} 需要一个值"; exit 1 ;;
    esac
done

# ---------------- 工具函数 ----------------
list_samples() {
    find "${SAMPLES_DIR}" -maxdepth 1 -name '*.go' -type f -exec basename {} .go \; | sort
}

# 匹配用户输入：精确名 / 补 _sample 后缀 / 子串模糊匹配
resolve_sample() {
    local input="$1"
    local all
    all="$(list_samples)"

    # 精确匹配
    if echo "${all}" | grep -qx "${input}"; then
        echo "${input}"; return 0
    fi
    # 补 _sample 后缀再匹配（如 obtain_token -> obtain_token_sample）
    if echo "${all}" | grep -qx "${input}_sample"; then
        echo "${input}_sample"; return 0
    fi
    # 子串模糊匹配（仅 1 个结果时接受）
    local fuzzy
    fuzzy="$(echo "${all}" | grep -F "${input}" || true)"
    if [[ -n "${fuzzy}" && "$(echo "${fuzzy}" | wc -l)" -eq 1 ]]; then
        echo "${fuzzy}"; return 0
    fi
    return 1
}

build_one() {
    local sample="$1" goos="$2" goarch="$3"
    local src="${SAMPLES_DIR}/${sample}.go"
    local ext=""
    [[ "${goos}" == "windows" ]] && ext=".exe"
    local out="${OUTPUT_DIR}/${sample}-${goos}-${goarch}${ext}"

    log_info "构建 ${sample} -> ${goos}/${goarch}"
    if CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
        go build -trimpath -ldflags "-s -w" -o "${out}" "${src}"; then
        local size
        size="$(du -h "${out}" | awk '{print $1}')"
        log_ok "已生成 ${out#${REPO_ROOT}/} (${size})"
    else
        log_error "构建失败: ${sample} ${goos}/${goarch}"
        return 1
    fi
}

# ---------------- 主流程 ----------------
cd "${REPO_ROOT}"

if [[ "${LIST_ONLY}" == "true" ]]; then
    echo "可用的 sample 列表："
    list_samples | sed 's/^/  - /'
    exit 0
fi

if [[ ! -d "${SAMPLES_DIR}" ]]; then
    log_error "samples 目录不存在: ${SAMPLES_DIR}"; exit 1
fi

# 解析要构建的 sample 列表
TARGET_SAMPLES=()
if [[ -n "${SAMPLE_FILTER}" ]]; then
    if resolved="$(resolve_sample "${SAMPLE_FILTER}")"; then
        TARGET_SAMPLES=("${resolved}")
    else
        log_error "未找到匹配 '${SAMPLE_FILTER}' 的 sample。使用 -l 查看可用列表。"
        exit 1
    fi
else
    while IFS= read -r line; do
        TARGET_SAMPLES+=("${line}")
    done < <(list_samples)
fi

# 解析平台列表（逗号分隔）
IFS=',' read -r -a PLATFORM_LIST <<< "${PLATFORMS}"

# ---------------- 清理历史构建结果 ----------------
# 每次构建前清空 OUTPUT_DIR 内容，保证产物目录干净。
# 仅清理目录内容、保留目录本身，避免 -o 指向被外部挂载/软链的目录被破坏。
clean_artifacts() {
    if [[ ! -d "${OUTPUT_DIR}" ]]; then
        return 0
    fi
    log_info "清理历史构建结果: ${OUTPUT_DIR}/*"
    find "${OUTPUT_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
}

mkdir -p "${OUTPUT_DIR}"
clean_artifacts

log_info "输出目录: ${OUTPUT_DIR}"
log_info "目标平台: ${PLATFORMS}"
log_info "目标 sample 数: ${#TARGET_SAMPLES[@]}"
echo

FAIL_COUNT=0
SUCCESS_COUNT=0
for sample in "${TARGET_SAMPLES[@]}"; do
    for platform in "${PLATFORM_LIST[@]}"; do
        goos="${platform%/*}"
        goarch="${platform#*/}"
        if [[ -z "${goos}" || -z "${goarch}" || "${goos}" == "${goarch}" ]]; then
            log_error "无效平台格式: '${platform}'（应为 goos/goarch，例如 linux/amd64）"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            continue
        fi
        if build_one "${sample}" "${goos}" "${goarch}"; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    done
done

echo
log_info "构建汇总: 成功 ${SUCCESS_COUNT}，失败 ${FAIL_COUNT}"
if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
fi

# 友好提示：列出本次产物
echo
log_info "本次产物："
ls -lh "${OUTPUT_DIR}" | tail -n +2 | awk '{printf "  %-10s %s\n", $5, $NF}'
