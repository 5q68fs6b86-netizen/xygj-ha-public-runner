#!/usr/bin/env bash
set -euo pipefail

diagnostics="private/diagnostics"
output="private/output"
remote_dir="/data/local/tmp/xygj-darkdex"
logcat_pid=""
extractor_pid=""
relauncher_pid=""

collect_runtime_diagnostics() {
  local exit_code="$?"
  trap - EXIT
  set +e

  if [[ -n "$relauncher_pid" ]]; then
    kill "$relauncher_pid" 2>/dev/null
    wait "$relauncher_pid" 2>/dev/null
  fi

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
  adb shell getprop "wrap.${PACKAGE}" \
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

launch_app() {
  local launcher_component="$1"
  if [[ "$launcher_component" == */* ]]; then
    timeout --foreground --kill-after=5s 30s \
      adb shell am start -n "$launcher_component" \
      >> "$diagnostics/app-launch.txt" 2>&1 || true
  else
    timeout --foreground --kill-after=5s 30s \
      adb shell monkey -p "$PACKAGE" -c android.intent.category.LAUNCHER 1 \
      >> "$diagnostics/app-launch.txt" 2>&1 || true
  fi
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
# Record which shell objects the package actually exposes to the linker.
{
  printf '=== nativeLibraryDirectories listing ===\n'
  adb shell "pm path $PACKAGE | tr -d '\r' | sed 's/^package://' | while read -r p; do echo PATH=\$p; unzip -l \"\$p\" 2>/dev/null | grep -E 'libexec|libhts|ijm_lib' || true; done"
  printf '=== extracted lib dir ===\n'
  adb shell "ls -la /data/app/*/com.yueme.itv*/lib/x86_64/ 2>/dev/null || ls -la /data/app/*/*/lib/x86_64/ 2>/dev/null || true"
} > "$diagnostics/native-libs.txt" 2>&1 || true
adb shell "rm -rf '$remote_dir' && mkdir -p '$remote_dir/dex'"
adb push private/libdd "$remote_dir/libdd" \
  > "$diagnostics/extractor-push.txt" 2>&1
adb shell chmod 700 "$remote_dir/libdd"

# wrap.<package> is required for survival: JUMP_SLOT multi-patch alone still
# loses the <1s suicide race. wrap forces WrapperInit (slow boot preload),
# which keeps the process alive long enough for shell + packer to run.
# DarkDex now waits until /data/app maps appear and skips /system carves so
# the preload itself is not mistaken for business DEX.
if [[ -f private/libkillbypass.so ]]; then
  adb push private/libkillbypass.so "$remote_dir/libkillbypass.so" \
    >> "$diagnostics/extractor-push.txt" 2>&1
  adb shell chmod 755 "$remote_dir/libkillbypass.so"
  adb shell "cat > '$remote_dir/wrap.sh' <<'WRAP'
#!/system/bin/sh
export LD_PRELOAD=$remote_dir/libkillbypass.so
exec \"\$@\"
WRAP
chmod 755 '$remote_dir/wrap.sh'"
  adb shell setprop "wrap.${PACKAGE}" "$remote_dir/wrap.sh" \
    > "$diagnostics/wrap-property.txt" 2>&1 || true
  printf 'wrap_enabled=1 mode=survive_plus_filter\n' \
    >> "$diagnostics/wrap-property.txt"
else
  adb shell setprop "wrap.${PACKAGE}" "" >/dev/null 2>&1 || true
  printf 'wrap_enabled=0 reason=no_libkillbypass\n' \
    > "$diagnostics/wrap-property.txt"
fi

adb logcat -c
adb logcat -v threadtime > "$diagnostics/android-logcat.txt" 2>&1 &
logcat_pid="$!"

adb shell am force-stop "$PACKAGE"
adb shell cmd package resolve-activity --brief \
  -a android.intent.action.MAIN \
  -c android.intent.category.LAUNCHER "$PACKAGE" \
  > "$diagnostics/launcher-activity.txt" 2>&1 || true

launcher_component="$(tr -d '\r' \
  < "$diagnostics/launcher-activity.txt" | tail -n 1)"

: > "$diagnostics/app-launch.txt"
launch_app "$launcher_component"

# Keep relaunching while the shell anti-tamper still wins races. DarkDex
# itself waits for a stable PID and retries across generations.
(
  for ((i = 0; i < WARMUP_SECONDS + 120; i++)); do
    pid="$(adb shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r' || true)"
    if [[ -z "$pid" ]]; then
      launch_app "$launcher_component"
    fi
    sleep 1
  done
) > "$diagnostics/relauncher.txt" 2>&1 &
relauncher_pid="$!"

extract_rc=0
timeout --foreground --kill-after=30s 8m \
  adb shell "$remote_dir/libdd '$PACKAGE' '$remote_dir/dex'" \
  > "$diagnostics/extraction.txt" 2>&1 &
extractor_pid="$!"

process_seen=0
: > "$diagnostics/app-process-timeline.txt"
# Cover DarkDex's multi-attempt budget (~180s) plus a little slack.
monitor_seconds=$((WARMUP_SECONDS + 150))
if (( monitor_seconds > 240 )); then
  monitor_seconds=240
fi
for ((second = 0; second < monitor_seconds; second++)); do
  pid="$(adb shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r' || true)"
  printf 'second=%s pid=%s\n' "$second" "$pid" \
    >> "$diagnostics/app-process-timeline.txt"
  if [[ -n "$pid" ]]; then
    process_seen=1
  fi
  # Stop early once extractor exits successfully.
  if ! kill -0 "$extractor_pid" 2>/dev/null; then
    printf 'second=%s extractor_exited\n' "$second" \
      >> "$diagnostics/app-process-timeline.txt"
    break
  fi
  sleep 1
done

wait "$extractor_pid" || extract_rc=$?
extractor_pid=""
printf 'extract_rc=%s\n' "$extract_rc" \
  >> "$diagnostics/extraction.txt"

if [[ -n "$relauncher_pid" ]]; then
  kill "$relauncher_pid" 2>/dev/null || true
  wait "$relauncher_pid" 2>/dev/null || true
  relauncher_pid=""
fi

# Clear wrap so subsequent local debugging is not surprised.
adb shell setprop "wrap.${PACKAGE}" "" >/dev/null 2>&1 || true

mkdir -p "$output"
adb pull "$remote_dir/dex" "$output/" \
  > "$diagnostics/extractor-pull.txt" 2>&1 || true
dex_count="$(find "$output" -type f -name '*.dex' | wc -l)"
printf 'dex_count=%s\n' "$dex_count" \
  >> "$diagnostics/extraction.txt"

# Reject framework-only carves: require business markers in intel or strings.
# Reject framework-only carves: require business markers stronger than the
# package name itself (intel header always contains com.yueme.itv).
biz_hit=0
if [[ -f "$output/dex/intel.txt" ]]; then
  if grep -Eiq 'chinatelecom|smarthome|ehome\.|ehome/|21cn|xy_guanjia|ijiami|uyumao|secneo|getDeviceList|ZJ_Get|libexec' \
      "$output/dex/intel.txt"; then
    biz_hit=1
  fi
fi
if (( biz_hit == 0 && dex_count > 0 )); then
  if grep -REaiq 'chinatelecom|smarthome|ehome\.21cn|xy_guanjia|ijiami|getDeviceList|ZJ_GetDevice' \
      "$output/dex" --include='*.dex'; then
    biz_hit=1
  fi
fi
printf 'biz_hit=%s\n' "$biz_hit" >> "$diagnostics/extraction.txt"

if (( dex_count == 0 || biz_hit == 0 )); then
  if (( process_seen == 0 )); then
    set_result "APP_PROCESS_NOT_RUNNING"
  elif (( dex_count > 0 && biz_hit == 0 )); then
    set_result "FRAMEWORK_DEX_ONLY count=$dex_count"
  else
    set_result "NO_DEX_FOUND"
  fi
  exit 1
fi

find "$output" -type f -name '*.dex' \
  -exec sha256sum {} + > "$output/SHA256SUMS"
set_result "DEX_EXTRACTED count=$dex_count biz=1"
