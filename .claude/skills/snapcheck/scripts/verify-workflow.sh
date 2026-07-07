#!/usr/bin/env bash
# Verify SnapCheck agent skill workflow against test fixtures.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$ROOT"

if ! command -v snapcheck >/dev/null 2>&1; then
  pip install -e . -q
fi

FIXTURES="$ROOT/tests/fixtures"
FAIL=0

check_scan() {
  local path="$1"
  local profile="$2"
  local expect_critical="$3"  # "zero" or "positive"
  local label="$4"

  echo "→ $label"
  json=$(snapcheck scan "$path" --profile "$profile" --json 2>/dev/null)
  critical=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin)['health']['critical'])")
  score=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin)['health']['score'])")

  if [[ "$expect_critical" == "zero" && "$critical" != "0" ]]; then
    echo "  FAIL: expected critical=0, got $critical (score=$score)"
    FAIL=1
  elif [[ "$expect_critical" == "positive" && "$critical" == "0" ]]; then
    echo "  FAIL: expected critical>0, got 0 (score=$score)"
    FAIL=1
  else
    echo "  OK: critical=$critical score=$score"
  fi
}

check_exit() {
  local path="$1"
  local extra_args="$2"
  local expect_code="$3"
  local label="$4"

  echo "→ $label"
  set +e
  snapcheck scan "$path" $extra_args >/dev/null 2>&1
  code=$?
  set -e
  if [[ "$code" != "$expect_code" ]]; then
    echo "  FAIL: expected exit $expect_code, got $code"
    FAIL=1
  else
    echo "  OK: exit $code"
  fi
}

echo "=== SnapCheck skill workflow verification ==="

check_scan "$FIXTURES/clean" "git-repo" "zero" "clean project"
check_scan "$FIXTURES/git-repo" "git-repo" "positive" "git-repo with .env secret"
check_scan "$FIXTURES/json-secrets" "git-repo" "positive" "json passwords"
check_scan "$FIXTURES/server-profile" "server" "zero" "server SSH keys (expected)"
check_scan "$FIXTURES/webroot" "git-repo" "positive" "ovpn in webroot"

check_exit "$FIXTURES/git-repo" "--profile git-repo --fail-on-critical" "1" "fail-on-critical blocks"
check_exit "$FIXTURES/clean" "--profile git-repo --fail-on-critical" "0" "clean passes fail-on-critical"

echo "→ explain command"
if snapcheck explain --finding "Config Password" | grep -qi "password\|пароль"; then
  echo "  OK"
else
  echo "  FAIL: explain output empty"
  FAIL=1
fi

echo "→ teach ci command"
if snapcheck teach ci | grep -q "SnapCheck"; then
  echo "  OK"
else
  echo "  FAIL: teach ci missing YAML"
  FAIL=1
fi

echo "→ ci profile output"
ci_out=$(snapcheck scan "$FIXTURES/clean" --profile ci 2>/dev/null)
if echo "$ci_out" | grep -q "score="; then
  echo "  OK"
else
  echo "  FAIL: ci profile should output score= line"
  FAIL=1
fi

if [[ "$FAIL" == "0" ]]; then
  echo "=== ALL CHECKS PASSED ==="
  exit 0
else
  echo "=== SOME CHECKS FAILED ==="
  exit 1
fi