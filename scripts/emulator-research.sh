#!/usr/bin/env bash
set -euo pipefail

diagnostics="private/diagnostics"
output="private/output"
remote_dir="/data/local/tmp/xygj-darkdex"
logcat_pid=""
extractor_pid=""

collect_runtime_diagnostics() {
  local exit_code="$?"
  trap - EXIT
  set +e

  adb devices -l > "$diagnostics/adb-devices.txt" 2>&1
  adb shell ps -A | grep -F "$PACKAGE" \
    > "$diagnostics/app-processes.txt" 2>&1
  adb shell dumpsys activity exit-info "$PACKAGE" \
    > "$diagnostics/app-exit-info.txt" 2>&1
  adb shell dumpsys activity activities \
    > "$diagnostics/activity-state.txt" 2>&1
  adb shell dumpsys package "$PACKAGE" \
    > "$diagnostics/package-state.txt" 2>&1
  adb shell id > "$diagnostics/android-root-context.txt" 2>&1
  adb shell getenforce >> "$diagnostics/android-root-context.txt" 2>&1
  adb shell cat /proc/self/status \
    >> "$diagnostics/android-root-context.txt" 2>&1
  adb shell mount | grep -F ' /proc ' \
    >> "$diagnostics/android-root-context.txt" 2>&1
  adb pull /data/tombstones "$diagnostics/tombstones" \
    > "$diagnostics/tombstones-pull.txt" 2>&1

  if [[ -n "$extractor_pid" ]]; then
    kill "$extractor_pid" 2>/dev/null
    wait "$extractor_pid" 2>/dev/null
    adb shell "pkill -TERM -f '$remote_dir/libdd'" 2>/dev/null || true
  fi

  if [[ -n "$logcat_pid" ]]; then
    kill "$logcat_pid" 2>/dev/null
    wait "$logcat_pid" 2>/dev/null
  fi
  exit "$exit_code"
}

trap collect_runtime_diagnostics EXIT

set_result() {
  printf 'RESULT=%s\n' "$1" > "$diagnostics/result.txt"
}

record_properties() {
  for property in \
    ro.product.cpu.abi \
    ro.product.cpu.abilist \
    ro.product.cpu.abilist64 \
    ro.dalvik.vm.native.bridge \
    ro.enable.native.bridge.exec \
    ro.build.fingerprint \
    ro.build.type \
    ro.debuggable; do
    printf '%s=' "$property"
    adb shell getprop "$property" | tr -d '\r'
  done
}

record_properties > "$diagnostics/emulator-properties.txt"
adb devices -l > "$diagnostics/adb-devices.txt"

adb root > "$diagnostics/adb-root.txt" 2>&1 || true
adb wait-for-device
adb shell id >> "$diagnostics/adb-root.txt" 2>&1
if ! adb shell id | grep -q 'uid=0'; then
  set_result "EMULATOR_ROOT_UNAVAILABLE"
  exit 1
fi

adb shell setenforce 0 >> "$diagnostics/adb-root.txt" 2>&1 || true

apk_path="private/target.apk"
if [[ "${APK_VARIANT:-original}" == "x86-shell" ]]; then
  apk_path="private/target-x86.apk"
fi
printf 'apk_variant=%s\n' "${APK_VARIANT:-original}" \
  > "$diagnostics/apk-variant.txt"

if ! timeout --foreground --kill-after=30s 8m \
    adb install -r -g "$apk_path" \
    > "$diagnostics/apk-install.txt" 2>&1; then
  set_result "APK_INSTALL_FAILED"
  exit 1
fi

adb shell pm path "$PACKAGE" >> "$diagnostics/apk-install.txt" 2>&1
adb shell "rm -rf '$remote_dir' && mkdir -p '$remote_dir/dex'"
adb push private/libdd "$remote_dir/libdd" \
  > "$diagnostics/extractor-push.txt" 2>&1
adb shell chmod 700 "$remote_dir/libdd"

adb logcat -c
adb logcat -v threadtime > "$diagnostics/android-logcat.txt" 2>&1 &
logcat_pid="$!"

extract_rc=0
timeout --foreground --kill-after=30s 8m \
  adb shell "$remote_dir/libdd '$PACKAGE' '$remote_dir/dex'" \
  > "$diagnostics/extraction.txt" 2>&1 &
extractor_pid="$!"

adb shell am force-stop "$PACKAGE"
adb shell cmd package resolve-activity --brief \
  -a android.intent.action.MAIN \
  -c android.intent.category.LAUNCHER "$PACKAGE" \
  > "$diagnostics/launcher-activity.txt" 2>&1 || true

launcher_component="$(tr -d '\r' \
  < "$diagnostics/launcher-activity.txt" | tail -n 1)"
if [[ "$launcher_component" == */* ]]; then
  # Waiting for a fully drawn activity deadlocks while the extractor freezes
  # the process with ptrace. The non-waiting start only needs AMS acceptance.
  timeout --foreground --kill-after=5s 30s \
    adb shell am start -n "$launcher_component" \
    > "$diagnostics/app-launch.txt" 2>&1 || true
else
  timeout --foreground --kill-after=5s 30s \
    adb shell monkey -p "$PACKAGE" -c android.intent.category.LAUNCHER 1 \
    > "$diagnostics/app-launch.txt" 2>&1 || true
fi

process_seen=0
: > "$diagnostics/app-process-timeline.txt"
for ((second = 0; second < WARMUP_SECONDS; second++)); do
  pid="$(adb shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r' || true)"
  printf 'second=%s pid=%s\n' "$second" "$pid" \
    >> "$diagnostics/app-process-timeline.txt"
  if [[ -n "$pid" ]]; then
    process_seen=1
  fi
  sleep 1
done

wait "$extractor_pid" || extract_rc=$?
printf 'extract_rc=%s\n' "$extract_rc" \
  >> "$diagnostics/extraction.txt"

mkdir -p "$output"
adb pull "$remote_dir/dex" "$output/" \
  > "$diagnostics/extractor-pull.txt" 2>&1 || true
dex_count="$(find "$output" -type f -name '*.dex' | wc -l)"
printf 'dex_count=%s\n' "$dex_count" \
  >> "$diagnostics/extraction.txt"
if (( dex_count == 0 )); then
  if (( process_seen == 0 )); then
    set_result "APP_PROCESS_NOT_RUNNING"
  else
    set_result "NO_DEX_FOUND"
  fi
  exit 1
fi

find "$output" -type f -name '*.dex' \
  -exec sha256sum {} + > "$output/SHA256SUMS"
set_result "DEX_EXTRACTED count=$dex_count"
