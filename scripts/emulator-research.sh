#!/usr/bin/env bash
set -euo pipefail

diagnostics="private/diagnostics"
output="private/output"
remote_dir="/data/local/tmp/xygj-darkdex"

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

if ! timeout --foreground --kill-after=30s 8m \
    adb install -r -g private/target.apk \
    > "$diagnostics/apk-install.txt" 2>&1; then
  set_result "APK_INSTALL_FAILED"
  exit 1
fi

adb shell pm path "$PACKAGE" >> "$diagnostics/apk-install.txt" 2>&1
adb shell am force-stop "$PACKAGE"
adb shell monkey -p "$PACKAGE" -c android.intent.category.LAUNCHER 1 \
  > "$diagnostics/app-launch.txt" 2>&1 || true
sleep "$WARMUP_SECONDS"

adb shell ps -A | grep -F "$PACKAGE" \
  > "$diagnostics/app-processes.txt" || true
if ! adb shell pidof "$PACKAGE" > "$diagnostics/app-pid.txt" 2>&1; then
  set_result "APP_PROCESS_NOT_RUNNING"
  exit 1
fi

adb shell "rm -rf '$remote_dir' && mkdir -p '$remote_dir/dex'"
adb push private/libdd-x86_64 "$remote_dir/libdd" \
  > "$diagnostics/extractor-push.txt" 2>&1
adb shell chmod 700 "$remote_dir/libdd"

extract_rc=0
timeout --foreground --kill-after=30s 8m \
  adb shell "$remote_dir/libdd '$PACKAGE' '$remote_dir/dex'" \
  > "$diagnostics/extraction.txt" 2>&1 || extract_rc=$?
printf 'extract_rc=%s\n' "$extract_rc" \
  >> "$diagnostics/extraction.txt"

mkdir -p "$output"
adb pull "$remote_dir/dex" "$output/" \
  > "$diagnostics/extractor-pull.txt" 2>&1 || true
dex_count="$(find "$output" -type f -name '*.dex' | wc -l)"
printf 'dex_count=%s\n' "$dex_count" \
  >> "$diagnostics/extraction.txt"
if (( dex_count == 0 )); then
  set_result "NO_DEX_FOUND"
  exit 1
fi

find "$output" -type f -name '*.dex' \
  -exec sha256sum {} + > "$output/SHA256SUMS"
set_result "DEX_EXTRACTED count=$dex_count"
