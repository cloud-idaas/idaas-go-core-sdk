#!/usr/bin/env bash
#
# run-integration-item-by-item.sh — 逐项运行 integration/ 全部集成场景，输出结果矩阵。
#
# 为什么需要它：go test 一把跑完后，日志混在一起难以按场景逐项核对；本脚本每个场景
# 单独 -run、单独判定 PASS/SKIP/FAIL，FAIL 时只保留脱敏后的错误摘要行（code=...），
# 适合在测试机上把各场景逐一过一遍并记录结果。
#
# 用法：
#   ./scripts/run-integration-item-by-item.sh              # 跑全部场景
#   ./scripts/run-integration-item-by-item.sh -k M2M       # 只跑某分组(标签前缀匹配)
#   IDAAS_IT_BROWSER=on ./scripts/run-integration-item-by-item.sh   # 启用真实弹浏览器用例
#   IDAAS_IT_HUMAN_FLOW=on ./scripts/run-integration-item-by-item.sh # 启用人机扫码段(会阻塞)
#
# 前置：
#   1. integration/testdata/.local/ 已按 README 配好（缺哪个场景哪个 SKIP）；
#   2. OIDC 场景需新鲜的 ID Token：export OIDC_TOKEN_FILE_PATH=... （过期 token 会被服务端拒绝）；
#   3. 多云场景需在对应云上（探活失败自动 SKIP，不算失败）；
#   4. 负面用例需要 endpoint 可达（不可达时 SKIP 而非 FAIL）。
#
# 退出码：0=无 FAIL  1=存在 FAIL  2=前置条件错误（go 缺失等）

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

command -v go >/dev/null || { echo "go 不在 PATH" >&2; exit 2; }

# OIDC token 文件默认值（不存在则相关用例自然 SKIP，不阻断其他场景）
export OIDC_TOKEN_FILE_PATH="${OIDC_TOKEN_FILE_PATH:-$PWD/integration/testdata/.local/oidc-id-token.jwt}"

ONLY_GROUP="${2:-}"
[[ "${1:-}" == "-k" ]] || ONLY_GROUP=""

# 场景清单：分组|名称|go test -run 正则（TestPkcs7$ 用 $ 锚定，避免误匹配 TestPkcs7AwsEc2）
ITEMS=(
  "M2M|client_secret_basic|TestClientSecretBasic$"
  "M2M|client_secret_post|TestClientSecretPost$"
  "M2M|client_secret_jwt|TestClientSecretJwt$"
  "M2M|private_key_jwt|TestPrivateKeyJwt$"
  "M2M|pca|TestPCA$"
  "M2M|plugin|TestPluginAuthn$"
  "M2M|pkcs7@ECS|TestPkcs7$"
  "多云|pkcs7@AWS_EC2|TestPkcs7AwsEc2$"
  "多云|oidc@KUBERNETES|TestOidcKubernetes$"
  "多云|oidc@AZURE_VM|TestOidcAzureVm$"
  "多云|oidc@GOOGLE_VM|TestOidcGoogleVm$"
  "OIDC|oidc@COMPUTER|TestOidc$"
  "回归|all_authn_methods|TestAllAuthnMethods$"
  "链路|token_exchange(RFC8693)|TestTokenExchange$"
  "链路|factory_public_api|TestFactoryPublicApiFlow$"
  "链路|cache_reuse|TestCachedCredentialIsReused$"
  "链路|refresh_token|TestRefreshTokenRenewal$"
  "负面|wrong_client_secret|TestWrongClientSecretInvalidClient$"
  "安全|oidc_file_perm(warn-only)|TestFileOidcPermissionCheck_RealTokenFile$"
  "安全|browser_no_user_code_leak|TestOpenBrowser_RealSubprocess_NoUserCodeLeak$"
  "安全|human_device_flow@real_idp|TestHumanFederatedDeviceFlow_RealIdP$"
  "链路|factory_other_apis|TestFactoryOtherApis$"
  "链路|token_listener|TestTokenListener$"
  "链路|get_credential_with_context|TestGetCredentialWithContext$"
  "链路|get_credential_with_deadline|TestGetCredentialWithDeadline$"
  "链路|stale_value_behavior|TestStaleValueBehaviorConfig$"
  "负面|unsupported_deploy_env_pkcs7|TestUnsupportedDeployEnvironment_PKCS7$"
  "负面|unsupported_deploy_env_oidc|TestUnsupportedDeployEnvironment_OIDC$"
)

PASS=0; SKIP=0; FAIL=0
FAILED_LIST=()

green()  { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
red()    { printf '\033[31m%s\033[0m\n' "$1"; }

# redact_secrets: 对输出行做脱敏,防止 t.Fatal/t.Errorf 断言消息中的
# token / secret / JWT 落入日志文件或终端历史。
# - JWT 三段式 → ***JWT***
# - 40+ 字符的连续 base64/hex → ***REDACTED***
# 原 FAIL 分支直接打印 raw %v 断言行,未脱敏。
redact_secrets() {
  sed -E \
    -e 's/[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/***JWT***/g' \
    -e 's/[A-Za-z0-9+/_-]{40,}/***REDACTED***/g'
}

printf '== IDaaS 集成测试逐项矩阵 ==\n'
printf 'OIDC_TOKEN_FILE_PATH=%s\n\n' "$OIDC_TOKEN_FILE_PATH"

for item in "${ITEMS[@]}"; do
  IFS='|' read -r group name regex <<< "$item"
  [[ -n "$ONLY_GROUP" && "$group" != "$ONLY_GROUP"* ]] && continue

  out="$(go test -count=1 -tags integration -v -run "$regex" ./integration/ 2>&1)"
  # 顶层状态（无缩进的 --- PASS/FAIL/SKIP 行）
  top_status="$(grep -E "^--- (PASS|FAIL|SKIP):" <<< "$out" | tail -1 | awk '{print $2}' | tr -d ':')"
  # 子用例行（带缩进的    --- PASS/FAIL/SKIP 行）
  sub_fails="$(grep -cE "^    --- FAIL:" <<< "$out" || true)"
  sub_skips="$(grep -cE "^    --- SKIP:" <<< "$out" || true)"
  sub_passes="$(grep -cE "^    --- PASS:" <<< "$out" || true)"
  # 聚合子用例状态：
  # - 任一子用例 FAIL → FAIL
  # - 全部子用例 SKIP（有子用例但无 PASS）→ SKIP（覆盖 Go 对父测试仍输出 --- PASS 的坑）
  # - 否则沿用顶层状态
  if [[ "${sub_fails:-0}" -gt 0 || "$top_status" == "FAIL" ]]; then
    status="FAIL"
  elif [[ "${sub_skips:-0}" -gt 0 && "${sub_passes:-0}" -eq 0 ]]; then
    status="SKIP"
  else
    status="$top_status"
  fi
  case "$status" in
    PASS)  PASS=$((PASS+1));   printf '%s  [%s] %s\n' "$(green 'PASS')" "$group" "$name" ;;
    SKIP)  SKIP=$((SKIP+1));   printf '%s  [%s] %s — %s\n' "$(yellow 'SKIP')" "$group" "$name" \
             "$(grep '跳过' <<< "$out" | head -1 | sed -E 's/^[[:space:]]+[^:]*:[0-9]+:[[:space:]]*//; s/：.*//')" ;;
    FAIL)  FAIL=$((FAIL+1));   FAILED_LIST+=("$name")
             printf '%s  [%s] %s\n' "$(red 'FAIL')" "$group" "$name"
             if grep -qE "code=[A-Za-z]+ \| " <<< "$out"; then
               grep -E "code=[A-Za-z]+ \| " <<< "$out" | head -1 | sed 's/^ *          /       /' | redact_secrets
             else
               # 无 code= 行时打印测试自身的断言消息（t.Fatal/t.Errorf/子用例分支），
               # 否则矩阵只剩裸 "--- FAIL" 行，无法定位失败原因。
               # 断言消息可能含 token/secret 明文,经 redact_secrets 脱敏后输出。
               grep -E "^[[:space:]]+[A-Za-z0-9_]+_test\.go:[0-9]+:" <<< "$out" \
                 | grep -vE "✅|获取成功|来源|覆盖|authnMethod=" | tail -4 | sed 's/^[[:space:]]*/       /' | redact_secrets
             fi
             grep -E "^[[:space:]]*--- FAIL: " <<< "$out" | sed 's/^[[:space:]]*/       /'
             ;;
    *)     FAIL=$((FAIL+1));   FAILED_LIST+=("$name(无判定输出)")
             printf '%s  [%s] %s — 未捕获到 --- PASS/FAIL/SKIP 行（-run 正则或编译问题？）\n' "$(red 'ERROR')" "$group" "$name" ;;
  esac
done

# -k 指定的分组前缀若拼错(如 -k M2N),所有场景被 continue 跳过,
# PASS=SKIP=FAIL=0,脚本仍退出 0 并打印"逐项校验完成",掩盖零执行。
# 显式检测:选了分组但零匹配时以非零退出。
if [[ -n "$ONLY_GROUP" && "$PASS" -eq 0 && "$SKIP" -eq 0 && "$FAIL" -eq 0 ]]; then
  red "分组 '$ONLY_GROUP' 未匹配任何场景(可用分组: M2M 多云 OIDC 回归 链路 负面 安全)"
  exit 1
fi

echo
printf '合计: PASS=%d SKIP=%d FAIL=%d\n' "$PASS" "$SKIP" "$FAIL"
if (( FAIL > 0 )); then
  red  "存在 FAIL：${FAILED_LIST[*]}"
  echo "排查：SKIP 原因多为缺 .local 配置/不在对应云/未设开关；FAIL 看 code= 与服务端 requestId"
  exit 1
fi
green "逐项校验完成：无 FAIL（SKIP 项按前置条件清单补齐后可复跑）"
