#!/usr/bin/env bash
# Run ON THE SENSOR (via SSM Session Manager) after switching bootstrap_mode=false.
# Passes only if arbitrary internet egress is blocked while CloudWatch Logs still works.
set -u
REGION="${AWS_REGION:-$(cat /etc/voidsentinel/region 2>/dev/null || echo ap-south-1)}"
pass=0; fail=0
check_blocked() {
  if curl -s -m 6 -o /dev/null "$1"; then echo "FAIL  reachable (should be blocked): $1"; fail=$((fail+1));
  else echo "PASS  blocked: $1"; pass=$((pass+1)); fi
}
check_open() {
  code=$(curl -s -m 8 -o /dev/null -w '%{http_code}' "$1")
  if [ "$code" != "000" ]; then echo "PASS  reachable via VPC endpoint (HTTP $code): $1"; pass=$((pass+1));
  else echo "FAIL  unreachable (should work): $1"; fail=$((fail+1)); fi
}
check_blocked "https://example.com"
check_blocked "http://example.com"
check_blocked "https://github.com"
check_blocked "https://1.1.1.1"
check_open "https://logs.${REGION}.amazonaws.com"
check_open "https://ssm.${REGION}.amazonaws.com"
echo "logs endpoint resolves to: $(getent hosts logs.${REGION}.amazonaws.com | awk '{print $1}' | head -1) (should be a private 10.50.x.x IP)"
systemctl is-active --quiet cowrie && echo "PASS  cowrie running" || { echo "FAIL  cowrie not running"; fail=$((fail+1)); }
systemctl is-active --quiet voidsentinel-collector && echo "PASS  collector running" || { echo "FAIL  collector not running"; fail=$((fail+1)); }
echo "----"; echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
