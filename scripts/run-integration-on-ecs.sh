#!/usr/bin/env bash
#
# run-integration-on-ecs.sh — 在阿里云 ECS 实例上一键跑 IDaaS 集成测试（默认 PKCS7）
#
# 为什么需要这个脚本：
#   PKCS7(clientDeployEnvironment=ALIBABA_CLOUD_ECS) 依赖 ECS 元数据服务 IMDSv2
#   (http://100.100.100.200)，该地址在 SDK 里硬编码，只有真正跑在 ECS 实例内才可达。
#   本脚本先探活，再跑用例，最后只输出脱敏后的令牌摘要。
#
# 用法：
#   ./scripts/run-integration-on-ecs.sh                        # 探活 IMDS + 跑 TestPkcs7
#   ./scripts/run-integration-on-ecs.sh -m all                 # 跑全部认证方式
#   ./scripts/run-integration-on-ecs.sh -m client_secret_basic,pca
#   ./scripts/run-integration-on-ecs.sh -u                     # 先 git pull --ff-only 再跑
#   ./scripts/run-integration-on-ecs.sh -k                     # 跳过 IMDS 探活（非 ECS 上硬跑）
#   ./scripts/run-integration-on-ecs.sh -n                     # dry-run：只打印将要执行的命令
#   ./scripts/run-integration-on-ecs.sh -h                     # 帮助
#
# 可选认证方式（对应 integration/testdata/<name>.json）：
#   client_secret_basic / client_secret_post / client_secret_jwt
#   private_key_jwt / pca / pkcs7 / oidc / all
#
# 退出码：0=全部通过  1=有用例失败  2=前置条件不满足（Go 缺失 / 探活失败 / 参数错误）

set -euo pipefail

# ---------------- 默认配置 ----------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INTEGRATION_DIR="./integration/"

IMDS_TOKEN_URL="http://100.100.100.200/latest/api/token"
IMDS_PROBE_TIMEOUT=3

METHOD="pkcs7"
PULL_FIRST=false
SKIP_PROBE=false
DRY_RUN=false

# ---------------- 颜色 ----------------
if [[ -t 1 ]]; then
    C_GREEN="\033[32m"; C_RED="\033[31m"; C_YELLOW="\033[33m"; C_CYAN="\033[36m"; C_BOLD="\033[1m"; C_RESET="\033[0m"
else
    C_GREEN=""; C_RED=""; C_YELLOW=""; C_CYAN=""; C_BOLD=""; C_RESET=""
fi

log_info()  { echo -e "${C_CYAN}[INFO]${C_RESET}  $*"; }
log_ok()    { echo -e "${C_GREEN}[OK]${C_RESET}    $*"; }
log_warn()  { echo -e "${C_YELLOW}[WARN]${C_RESET}  $*"; }
log_error() { echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; }

# 帮助即文件头注释块：从第 2 行起打到第一个非注释行为止，改参数时不用同步维护行号。
usage() {
    awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
    exit 0
}

# ---------------- 参数解析 ----------------
# 原实现在未知参数(\?)时调用 usage(退出 0)而非退出 2,
# 且缺少 `:` 分支处理 -m 缺参数(getopts 默认打印错误并继续)。
# 参数错误必须以非零退出码暴露,否则脚本静默用默认值继续跑。
while getopts ":m:uknh" opt; do
    case "${opt}" in
        m) METHOD="${OPTARG}" ;;
        u) PULL_FIRST=true ;;
        k) SKIP_PROBE=true ;;
        n) DRY_RUN=true ;;
        h) usage ;;
        \?) log_error "未知参数: -${OPTARG}"; exit 2 ;;
        :)  log_error "选项 -${OPTARG} 需要参数"; exit 2 ;;
    esac
done

# 认证方式 -> 测试函数名
resolve_test_name() {
    case "$1" in
        client_secret_basic)  echo "TestClientSecretBasic" ;;
        client_secret_post)   echo "TestClientSecretPost" ;;
        client_secret_jwt)    echo "TestClientSecretJwt" ;;
        private_key_jwt)      echo "TestPrivateKeyJwt" ;;
        pca)                  echo "TestPCA" ;;
        pkcs7)                echo "TestPkcs7" ;;
        oidc)                 echo "TestOidc" ;;
        all)                  echo "TestAllAuthnMethods" ;;
        *)                    return 1 ;;
    esac
}

TEST_NAMES=()
IFS=',' read -r -a METHOD_LIST <<< "${METHOD}"
for m in "${METHOD_LIST[@]}"; do
    m="$(echo "${m}" | tr -d '[:space:]')"
    [[ -z "${m}" ]] && continue
    if name="$(resolve_test_name "${m}")"; then
        TEST_NAMES+=("${name}")
        # -m all 映射到 TestAllAuthnMethods，但 TestAllAuthnMethods 的子用例排除了 plugin。
        # 为覆盖 plugin 认证方式，all 额外追加 TestPluginAuthn。
        if [[ "${m}" == "all" ]]; then
            TEST_NAMES+=("TestPluginAuthn")
        fi
    else
        log_error "未知认证方式: '${m}'（可选：client_secret_basic client_secret_post client_secret_jwt private_key_jwt pca pkcs7 all）"
        exit 2
    fi
done
if [[ ${#TEST_NAMES[@]} -eq 0 ]]; then
    log_error "没有可执行的用例"; exit 2
fi

cd "${REPO_ROOT}"

# ---------------- 前置检查 ----------------
if ! command -v go >/dev/null 2>&1; then
    log_error "未找到 go 命令，请先安装 Go（本 SDK 最低 1.18）"; exit 2
fi
log_info "Go: $(go version)"

# Dry-run 在任何有副作用的步骤（git pull、IMDS 探活、go test）之前短路退出，
# 避免传递 -n 仍修改工作树或发起 IMDS PUT 请求。
if [[ "${DRY_RUN}" == "true" ]]; then
    RUN_REGEX="$(IFS='|'; echo "${TEST_NAMES[*]}")"
    log_warn "dry-run，将执行以下命令但不会实际运行："
    echo "  go test -count=1 -tags integration -v -run '^(${RUN_REGEX})$' ${INTEGRATION_DIR}"
    exit 0
fi

if [[ "${PULL_FIRST}" == "true" ]]; then
    if git rev-parse --git-dir >/dev/null 2>&1; then
        log_info "拉取最新代码: git pull --ff-only"
        git pull --ff-only
    else
        log_warn "不是 git 仓库，跳过 -u"; exit 2
    fi
fi

# 凭证文件检查：非 PKCS7 的方式需要 client secret / 私钥
CRED_FILE="integration/testdata/.local/credentials.env"
needs_credentials() {
    case "$1" in
        TestPkcs7|TestOidc) return 1 ;;
        *) return 0 ;;
    esac
}
for name in "${TEST_NAMES[@]}"; do
    if needs_credentials "${name}" && [[ ! -f "${CRED_FILE}" ]] && [[ -z "${IDAAS_CLIENT_SECRET:-}" ]]; then
        log_warn "${name} 需要凭证，但 ${CRED_FILE} 不存在且未设置 IDAAS_CLIENT_SECRET"
        log_warn "  准备方式：cp integration/testdata/credentials.env.example ${CRED_FILE} 后填入真实值"
    fi
done

# OIDC 不吃 client secret，吃的是一个 ID Token 文件（COMPUTER 模式不回落 K8s 默认路径）
for name in "${TEST_NAMES[@]}"; do
    if [[ "${name}" == "TestOidc" && -z "${OIDC_TOKEN_FILE_PATH:-}" && ! -r /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
        log_warn "TestOidc 需要 ID Token 文件：export OIDC_TOKEN_FILE_PATH=/path/to/id-token.jwt"
        log_warn "  该 JWT 必须由服务端联邦凭证（ql_oidc_test）信任的 issuer 签发，否则服务端会拒绝断言"
    fi
done

# ---------------- IMDS 探活 ----------------
probe_imds() {
    if command -v curl >/dev/null 2>&1; then
        # 真实握手：IMDSv2 需要 PUT 取 token，能拿到非空 token 才算 ECS 可用
        local token
        token="$(curl -s -f --max-time "${IMDS_PROBE_TIMEOUT}" \
                    -X PUT -H "x-aliyun-ecs-metadata-token-ttl-seconds: 60" \
                    "${IMDS_TOKEN_URL}" || true)"
        if [[ -n "${token}" ]]; then
            log_ok "ECS 元数据服务可达（IMDSv2 token 获取成功，长度 ${#token}）"
            return 0
        fi
        return 1
    fi
    # 无 curl 时退化为 TCP 连通性探测
    # 原 /dev/tcp 探测无超时,若 100.100.100.200 路由黑洞
    # (非 ECS 机器常见),connect() 会挂起直到内核 TCP SYN 重传超时(~2min)。
    # 用 timeout 包裹,复用 IMDS_PROBE_TIMEOUT(3s)作为上限。
    if timeout "${IMDS_PROBE_TIMEOUT}" bash -c 'true <>/dev/tcp/100.100.100.200/80' 2>/dev/null; then
        log_ok "ECS 元数据服务端口可达（未安装 curl，仅做 TCP 探测）"
        return 0
    fi
    return 1
}

if [[ "${METHOD}" == *pkcs7* || "${METHOD}" == "all" ]]; then
    if [[ "${SKIP_PROBE}" == "true" ]]; then
        log_warn "已用 -k 跳过 IMDS 探活；非 ECS 环境上 PKCS7 必然失败"
    elif probe_imds; then
        :
    else
        log_error "ECS 元数据服务 ${IMDS_TOKEN_URL} 不可达"
        echo
        echo -e "${C_BOLD}PKCS7 只有在真实阿里云 ECS 实例内才能跑通，请确认：${C_RESET}"
        echo "  1. 当前机器确实是 ECS 实例（可 cat /sys/class/dmi/id/product_name 看是否为 Alinux/ECS 规格）"
        echo "  2. 实例元数据访问未被加固模式禁用、安全组/iptables 未拦截 100.100.100.200"
        echo "  3. 想先验证其它认证方式：$0 -m client_secret_basic"
        echo "  4. 明知不在 ECS 上仍要尝试：$0 -k"
        exit 2
    fi
fi

# ---------------- 执行 ----------------
RUN_ID="$(date +%Y%m%d-%H%M%S)"
# 用 mktemp 创建 0600 日志文件，避免令牌片段/clientId/服务端错误泄漏给同机其他用户。
LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/idaas-integration-${RUN_ID}.XXXXXX")"
# 锚定 -run 正则：^(...)$ 防止 pkcs7 误匹配 TestPkcs7AwsEc2、oidc 误匹配多云用例。
RUN_REGEX="$(IFS='|'; echo "${TEST_NAMES[*]}")"
GO_TEST_ARGS=(-count=1 -tags integration -v -run "^(${RUN_REGEX})$" "${INTEGRATION_DIR}")

log_info "用例: ${TEST_NAMES[*]}"
log_info "完整日志: ${LOG_FILE}"

set +e
go test "${GO_TEST_ARGS[@]}" 2>&1 | tee "${LOG_FILE}"
RC=${PIPESTATUS[0]}
set -e

# ---------------- 摘要（令牌已脱敏，避免落到 shell 历史/日志文件） ----------------
echo
log_info "${C_BOLD}结果摘要${C_RESET}"
grep -E "^(--- (PASS|FAIL|SKIP)|ok|FAIL)" "${LOG_FILE}" | sed 's/^/  /' || true
grep -E "✅ 获取成功|JWT header" "${LOG_FILE}" | sed 's/^/  /' || true

if [[ ${RC} -ne 0 ]]; then
    echo
    if grep -q "DnsLookupFailed\|no such host" "${LOG_FILE}"; then
        log_error "令牌域名解析失败：ECS 需能解析你的 IDaaS 实例域名，检查 VPC DNS / hosts 条目"
    elif grep -q "invalid_client\|unauthorized_client\|HTTP 4" "${LOG_FILE}"; then
        log_error "服务端拒绝：请确认应用联邦凭证名称与 clientDeployEnvironment 与服务端登记一致（如 ql_pkcs7_test）"
    fi
    exit 1
fi

# 退出码为 0 不等于真的跑过：用例可能被整体 skip（缺凭证 / 非 ECS），必须说清楚。
# 注意：Go 在所有子用例 SKIP 时仍对父测试（如 TestAllAuthnMethods）输出 --- PASS，
# 所以只统计带缩进的子用例行；无子用例时（简单测试）回退到顶层行。
sub_skips="$(grep -cE '^    +--- SKIP:' "${LOG_FILE}" || true)"
sub_passes="$(grep -cE '^    +--- PASS:' "${LOG_FILE}" || true)"
sub_fails="$(grep -cE '^    +--- FAIL:' "${LOG_FILE}" || true)"
# 无子用例行时（简单测试无子用例）回退到顶层行
if [[ "${sub_skips}" -eq 0 && "${sub_passes}" -eq 0 && "${sub_fails}" -eq 0 ]]; then
    sub_skips="$(grep -cE '^--- SKIP:' "${LOG_FILE}" || true)"
    sub_passes="$(grep -cE '^--- PASS:' "${LOG_FILE}" || true)"
fi
skips="${sub_skips}"; passes="${sub_passes}"
if [[ "${sub_fails}" -gt 0 ]]; then
    log_error "存在 ${sub_fails} 个失败的子用例"
    exit 1
fi
if [[ "${skips}" -gt 0 && "${passes}" -eq 0 ]]; then
    log_warn "没有用例真正执行（${skips} 个被跳过）。跳过原因见上方日志，通常是缺凭证或不在 ECS 上"
    exit 0
fi

log_ok "全部通过（PASS ${passes}，SKIP ${skips}）"
