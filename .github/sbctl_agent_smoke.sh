#!/usr/bin/env bash
# Runs on the native Linux image builders against the released controller.
set -euo pipefail
umask 077
work=$(mktemp -d)
base=http://127.0.0.1:18881
controller='ghcr.io/domoxiaojun/sbctl@sha256:5c9ea2ebb7909103e8477bcc92f206268481754d99881956af34392f617bd862'
# shellcheck disable=SC2329 # Invoked by the EXIT trap.

cleanup() {
  docker rm -f sbctl-agent-ci sbctl-controller-ci >/dev/null 2>&1 || true
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir "$work/node"
cat > "$work/server.toml" <<TOML
public_base_url = "https://subscriptions.example.invalid"
allowed_origins = ["$base"]
secure_cookie = false
control_db = "/work/control.db"
traffic_db = "/work/traffic.db"
traffic_snapshot = "/work/traffic.json"
key_file = "/work/master.key"
public_dir = "/work/public"
inventory_file = "/work/inventory.json"
TOML
controller_args=(--user "$(id -u):$(id -g)" --network host --cap-drop ALL --read-only -v "$work:/work" -e SBCTL_CONFIG=/work/server.toml)
docker run --rm "${controller_args[@]}" "$controller" initialize --password-file /work/password
docker run -d --name sbctl-controller-ci "${controller_args[@]}" "$controller" serve --listen 127.0.0.1:18881 >/dev/null
curl -fsS --retry 15 --retry-connrefused --retry-delay 1 "$base/healthz" | jq -e '.version == "0.12.0-rc.1"' >/dev/null
http=(curl -fsS --max-time 8 -H "Origin: $base" -b "$work/session" -c "$work/session")
csrf=$(jq -Rs '{login_name:"admin",password:rtrimstr("\n")}' "$work/password" | "${http[@]}" --json @- "$base/api/v1/session" | jq -er .csrf_token)
http+=(-H "X-CSRF-Token: $csrf")
draft='{"id":"node_test","name":"Test","region":"test","location":"test","group_id":"grp_test","group_name":"Test","connection":{"address":"100.64.0.2"},"container":"sing-box","config_dir":"/etc/sing-box","public_host":""}'
jq -n --argjson d "$draft" --arg url "$base" '{draft:$d,control_url:$url}' | "${http[@]}" -H 'Idempotency-Key: ci-enroll-node-test' --json @- "$base/api/v1/nodes/enroll" | jq -er '.registration_code | "SBCTL_REGISTRATION_CODE=" + .' > "$work/node.env"
printf '%s\n' '{"outbounds":[{"type":"direct","tag":"direct"}]}' > "$work/node/config.json"
docker run -d --name sbctl-agent-ci --network host --cap-drop ALL --read-only --user "$(id -u):$(id -g)" -v "$work/node:/node" --env-file "$work/node.env" -e "SBCTL_CONTROL_URL=$base" -e SBCTL_NODE_ID=node_test -e SBCTL_STATE_DIR=/node/state sbctl-sing-box:test -c /node/config.json run >/dev/null
wait_for_live() {
  for _ in {1..30}; do
    if "${http[@]}" "$base/api/v1/traffic/live?node=node_test" | jq -e 'any(.nodes[]; .node_id == "node_test" and .fresh)' >/dev/null; then return 0; fi
    sleep 1
  done
  echo 'Timed out waiting for registered node telemetry' >&2
  return 1
}
wait_for_live
job=$(jq -n --argjson d "$draft" '{kind:"inspect",draft:$d,inspection_id:"",expected_version:0}' | "${http[@]}" -H 'Idempotency-Key: ci-inspect-node-test' --json @- "$base/api/v1/node-jobs" | jq -er .job_id)
for _ in {1..40}; do
  result=$("${http[@]}" "$base/api/v1/node-jobs/$job")
  case $(jq -er .state <<< "$result") in
    completed) echo 'Embedded Agent registered, pushed live traffic and returned the inspection receipt'; exit 0 ;;
    failed) jq '{state,error_code}' <<< "$result" >&2; exit 1 ;;
  esac
  sleep 1
done
echo 'Timed out waiting for inspection receipt' >&2
exit 1
