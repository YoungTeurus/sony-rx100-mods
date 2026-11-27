#!/bin/sh
# Stage 7.3 Phase B persistent SD auto-boot worker for Sony DSC-RX100M7 1.00 (build 29110_03.2021050601).
# Runs in S2R-retained /tmp_bt tmpfs (expanded to 4096 KiB) without touching stock BT files.
# Strictly limited to verified M7 BusyBox v1.13.4 applets (NO timeout/sha256sum/printf/df/head/awk/tr/stat).
set -eu

bb="${MLV2_BB-/bin/busybox}"
disable_flag="${MLV2_DISABLE_FLAG:-/setting/disable_sd_boot}"
ram_root="${MLV2_RAM:-/tmp_bt}"
stage="${MLV2_STAGE:-/tmp_bt/mlv2}"
mods="${MLV2_MODS:-/tmp_bt/mods}"
daemon_dir="${MLV2_DAEMON_DIR:-/tmp_bt/.m7-s7-5d0000000001}"
reader="${MLV2_READER:-/setting/mlv2_card_read.elf}"
key_file="${MLV2_KEY:-/setting/mlv2_owner.key}"
ver_file="${MLV2_VERSION_FILE:-/version.txt}"
persist_src="${MLV2_PERSIST_SRC:-/setting/mlv2_precap.cfg}"
persist_gate_val="${MLV2_PERSIST_GATE_VALUE:-/setting/mlv2_precap.cfg}"
dev_node="${MLV2_DEV:-/dev/mmca1}"
proc_root="${MLV2_PROC:-/proc}"
wait_mount="${MLV2_WAIT_MOUNT:-15}"
wait_im="${MLV2_WAIT_IM:-120}"
wait_daemon="${MLV2_WAIT_DAEMON:-10}"
card_tries="${MLV2_CARD_TRIES:-15}"
run_once="${MLV2_ONCE:-0}"
keep_guard="${MLV2_KEEP_GUARD:-0}"
skip_mount="${MLV2_SKIP_MOUNT_CHECK:-0}"
skip_remount="${MLV2_SKIP_REMOUNT:-0}"
skip_blk="${MLV2_SKIP_DEV_BLK_CHECK:-0}"
skip_maps="${MLV2_SKIP_MAPS_CHECK:-0}"
target_build="29110_03.2021050601"

run_cmd() {
    if [ -n "$bb" ]; then
        "$bb" "$@"
    else
        "$@"
    fi
}

# Owner kill-switch check before doing anything.
if [ -e "$disable_flag" ] || [ -L "$disable_flag" ]; then
    exit 0
fi

# Target version gate before touching RAM.
if [ ! -f "$ver_file" ] || [ -L "$ver_file" ]; then
    exit 0
fi
vsz=$(run_cmd wc -c < "$ver_file" 2>/dev/null || echo 0)
vsz=$((vsz + 0))
ver=$(run_cmd cat "$ver_file" 2>/dev/null || true)
if [ "$vsz" -ne 19 ] || [ "$ver" != "$target_build" ]; then
    exit 0
fi

# Confine all writable paths strictly inside $ram_root: reject symlinks at EVERY component!
check_ram_child() {
    p="$1"
    case "$p" in
        "$ram_root"/*) ;;
        *) exit 0 ;;
    esac
    case "$p" in
        *'/..'|*'../'*|*'/.'|*'./'*|*'//'*|*'/'|'') exit 0 ;;
    esac
    rel="${p#$ram_root/}"
    cur="$ram_root"
    while [ -n "$rel" ]; do
        comp="${rel%%/*}"
        cur="$cur/$comp"
        if [ -L "$cur" ]; then
            exit 0
        fi
        case "$rel" in
            */*)
                if [ ! -d "$cur" ]; then
                    exit 0
                fi
                rel="${rel#*/}"
                ;;
            *)
                if [ -e "$cur" ] && [ ! -d "$cur" ]; then
                    exit 0
                fi
                rel=""
                ;;
        esac
    done
}

case "$ram_root" in
    /*) ;;
    *) exit 0 ;;
esac
case "$ram_root" in
    *'/..'|*'../'*|*'/.'|*'./'*|*'//'*|*'/'|'') exit 0 ;;
esac
if [ -L "$ram_root" ] || [ ! -d "$ram_root" ]; then
    exit 0
fi
check_ram_child "$stage"
check_ram_child "$mods"
check_ram_child "$daemon_dir"

# Verify volatile RAM tmpfs mount: exact unique mount row at $ram_root (tmpfs rw, not noexec)
# and ZERO conflicting or nested mounts under $ram_root/.
mount_ok() {
    m_tot=0
    m_ok=0
    m_nested=0
    mounts_file=""
    [ ! -L "$proc_root" ] && [ -d "$proc_root" ] || return 1
    if [ -e "$proc_root/$$" ] || [ -L "$proc_root/$$" ]; then
        [ ! -L "$proc_root/$$" ] && [ -d "$proc_root/$$" ] && \
            [ ! -L "$proc_root/$$/mounts" ] && [ -f "$proc_root/$$/mounts" ] && [ -r "$proc_root/$$/mounts" ] || return 1
        mounts_file="$proc_root/$$/mounts"
    elif [ ! -L "$proc_root/mounts" ] && [ -f "$proc_root/mounts" ] && [ -r "$proc_root/mounts" ]; then
        mounts_file="$proc_root/mounts"
    else
        return 1
    fi
    while read m_dev m_mnt m_fs m_opts m_rest; do
        if [ "$m_mnt" = "$ram_root" ]; then
            m_tot=$((m_tot + 1))
            if [ "$m_fs" = "tmpfs" ]; then
                case ",$m_opts," in
                    *,rw,*)
                        case ",$m_opts," in
                            *,noexec,*) ;;
                            *) m_ok=$((m_ok + 1)) ;;
                        esac
                        ;;
                esac
            fi
        else
            case "$m_mnt" in
                "$ram_root"/*) m_nested=1 ;;
            esac
        fi
    done < "$mounts_file"
    [ "$m_tot" -eq 1 ] && [ "$m_ok" -eq 1 ] && [ "$m_nested" -eq 0 ]
}

if [ "$skip_mount" -eq 0 ]; then
    remaining="$wait_mount"
    while :; do
        if mount_ok; then
            break
        fi
        if [ "$remaining" -le 0 ]; then exit 0; fi
        remaining=$((remaining - 1))
        run_cmd sleep 1
    done
    if [ "$skip_remount" -eq 0 ]; then
        run_cmd mount -o remount,size=4096k "$ram_root" 2>/dev/null || true
    fi
fi

umask 077
owns_stage=0
if [ ! -d "$stage" ]; then
    run_cmd mkdir "$stage" || exit 0
    owns_stage=1
elif [ -L "$stage" ]; then
    exit 0
fi

# Atomic lock with S2R live-owner idempotency and stale-lock recovery.
lock_dir="$stage/.boot.lock"
if ! run_cmd mkdir "$lock_dir" 2>/dev/null; then
    [ -d "$lock_dir" ] && [ ! -L "$lock_dir" ] || exit 0
    old_line=$(run_cmd cat "$lock_dir/owner" 2>/dev/null || true)
    old_pid="${old_line#worker }"
    case "$old_pid" in
        ""|*[!0-9]*|0*) exit 0 ;;
    esac
    if [ -d "$proc_root/$old_pid" ] && [ -e "$proc_root/$old_pid/stat" ]; then
        # Active worker (e.g. surviving S2R monitor loop): leave intact and exit cleanly.
        exit 0
    fi
    run_cmd rm -f "$lock_dir/owner" 2>/dev/null || true
    run_cmd rmdir "$lock_dir" 2>/dev/null || true
    run_cmd mkdir "$lock_dir" 2>/dev/null || exit 0
fi
run_cmd echo "worker $$" > "$lock_dir/owner" 2>/dev/null || true

# Reject symlinks, directories, FIFOs, devices, and sockets: ONLY absent or regular file allowed.
safe_leaf_ok() {
    [ ! -L "$1" ] && { [ ! -e "$1" ] || [ -f "$1" ]; }
}
fresh_leaf_ok() {
    [ ! -L "$1" ] && [ ! -e "$1" ]
}
reg_file_ok() {
    [ ! -L "$1" ] && [ -f "$1" ]
}

log_file="$stage/sd-boot.log"
log_lines=0
log_msg() {
    if [ "$log_lines" -ge 80 ] || ! safe_leaf_ok "$log_file"; then
        return 0
    fi
    log_lines=$((log_lines + 1))
    run_cmd echo "$1" >> "$log_file" 2>/dev/null || true
}

owns_mods=0
owns_daemon=0
guard_started=0
keep_running=0

release_lock() {
    run_cmd rm -f "$lock_dir/owner" 2>/dev/null || true
    run_cmd rmdir "$lock_dir" 2>/dev/null || true
}

cleanup() {
    if [ "$keep_running" -eq 1 ]; then
        run_cmd rm -f "$stage/card.tar" "$stage/card.tar.tmp" "$stage/check.log" "$stage/install.log"
        if [ "$keep_guard" -eq 0 ]; then
            run_cmd rm -f "$stage/guard" "$stage/mlv2_guard.elf" "$stage/mlv2.req"
        fi
        release_lock
        return 0
    fi
    if [ "$guard_started" -eq 1 ]; then
        if safe_leaf_ok "$stage/sd-disabled"; then
            : > "$stage/sd-disabled" 2>/dev/null || true
        fi
        if [ -d "$daemon_dir" ] && [ ! -L "$daemon_dir" ] && safe_leaf_ok "$daemon_dir/stop"; then
            : > "$daemon_dir/stop" 2>/dev/null || true
        fi
        run_cmd rm -f "$stage/card.tar" "$stage/card.tar.tmp" "$stage/check.log" "$stage/install.log"
        if [ "$keep_guard" -eq 0 ]; then
            run_cmd rm -f "$stage/guard" "$stage/mlv2_guard.elf" "$stage/mlv2.req"
        elif reg_file_ok "$stage/guard" && fresh_leaf_ok "$stage/mlv2_guard.elf"; then
            run_cmd mv -f "$stage/guard" "$stage/mlv2_guard.elf" 2>/dev/null || true
        fi
        release_lock
    else
        if [ "$owns_mods" -eq 1 ]; then
            run_cmd rm -f "$mods/PreCapture.mod" "$mods/mod_loader.log"
            run_cmd rmdir "$mods" 2>/dev/null || true
        fi
        if [ "$owns_daemon" -eq 1 ]; then
            run_cmd rm -f "$daemon_dir/daemon.elf" "$daemon_dir/ring.elf" \
                "$daemon_dir/daemon.pid" "$daemon_dir/daemon.log" "$daemon_dir/stop" \
                "$daemon_dir/disarm" "$daemon_dir/run.cfg" "$daemon_dir/run.cfg.tmp"
            run_cmd rmdir "$daemon_dir" 2>/dev/null || true
        fi
        run_cmd rm -f "$stage/card.tar" "$stage/card.tar.tmp" "$stage/guard" "$stage/mlv2_guard.elf" "$stage/mlv2.req" \
            "$stage/core.bin" "$stage/PreCapture.mod" "$stage/daemon" "$stage/ring.elf" \
            "$stage/check.log" "$stage/install.log" "$stage/sd-managed" \
            "$stage/precap.cfg" "$stage/precap.cfg.tmp" "$stage/persist-cfg" "$stage/persist-cfg.tmp"
        if [ "$owns_stage" -eq 1 ]; then
            run_cmd rm -f "$log_file"
        fi
        release_lock
        if [ "$owns_stage" -eq 1 ]; then
            run_cmd rmdir "$stage" 2>/dev/null || true
        fi
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if ! safe_leaf_ok "$log_file"; then
    exit 1
fi
: > "$log_file"
log_msg "MLV2_SD_START build=$target_build ram=$ram_root"

find_im_pid() {
    found=""
    for p in "$proc_root"/[1-9]*; do
        [ -e "$p/stat" ] || continue
        exe=$(run_cmd readlink "$p/exe" 2>/dev/null || true)
        [ "$exe" = "/usr/bin/im.elf" ] || continue
        pid="${p#$proc_root/}"
        if [ -n "$found" ]; then
            return 1
        fi
        found="$pid"
    done
    [ -n "$found" ] || return 1
    run_cmd echo "$found"
}

read_proc_starttime() {
    st_raw=$(run_cmd cat "$proc_root/$1/stat" 2>/dev/null || true)
    st_after="${st_raw##*) }"
    if [ -z "$st_raw" ] || [ "$st_after" = "$st_raw" ]; then
        return 1
    fi
    set -- $st_after
    if [ $# -lt 20 ]; then
        return 1
    fi
    shift 19
    case "$1" in
        ""|*[!0-9]*) return 1 ;;
    esac
    run_cmd echo "$1"
}

dev_ready() {
    if [ "$skip_blk" -eq 1 ]; then
        [ -e "$dev_node" ]
    else
        [ -b "$dev_node" ]
    fi
}

maps_ready() {
    if [ "$skip_maps" -eq 1 ]; then
        return 0
    fi
    run_cmd grep -q '/libtestcmd\.so$' "$proc_root/$1/maps" 2>/dev/null &&
        run_cmd grep -q '/viewUnified2\.so$' "$proc_root/$1/maps" 2>/dev/null
}

im_pid=""
im_st=""
rem="$wait_im"
while :; do
    if dev_ready && im_pid=$(find_im_pid) && im_st=$(read_proc_starttime "$im_pid") && maps_ready "$im_pid"; then
        break
    fi
    if [ "$rem" -le 0 ]; then
        log_msg "MLV2_SD_NOT_READY"
        exit 0
    fi
    rem=$((rem - 1))
    run_cmd sleep 1
done
log_msg "MLV2_IM_PID=$im_pid im_st=$im_st"

# S2R recovery check: if our daemon is ALREADY alive for this im.elf (e.g. lock was stale), do not re-install.
if reg_file_ok "$daemon_dir/daemon.pid"; then
    existing_dpid=$(run_cmd cat "$daemon_dir/daemon.pid" 2>/dev/null || true)
    case "$existing_dpid" in
        ""|*[!0-9]*|0*) existing_dpid="" ;;
    esac
    if [ -n "$existing_dpid" ] && \
       [ "$(run_cmd readlink "$proc_root/$existing_dpid/exe" 2>/dev/null || true)" = "$daemon_dir/daemon.elf" ] && \
       run_cmd grep -q ') [RSDT] ' "$proc_root/$existing_dpid/stat" 2>/dev/null; then
        log_msg "MLV2_SD_ALREADY_ACTIVE daemon_pid=$existing_dpid"
        keep_running=1
        exit 0
    fi
fi

tries="$card_tries"
while :; do
    rc=0
    "$reader" --extract --stage "$stage" --key "$key_file" --version-file "$ver_file" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        break
    fi
    if [ "$rc" -ne 3 ] || [ "$tries" -le 0 ]; then
        log_msg "MLV2_SD_PACKAGE_UNAVAILABLE rc=$rc"
        exit 0
    fi
    tries=$((tries - 1))
    run_cmd sleep 1
done

reg_file_ok "$stage/card.tar" || exit 1
for m in guard mlv2.req core.bin PreCapture.mod daemon ring.elf; do
    fresh_leaf_ok "$stage/$m" || exit 1
done
cd "$stage"
run_cmd tar -xf "$stage/card.tar"
run_cmd rm -f "$stage/card.tar"
for m in guard mlv2.req core.bin PreCapture.mod daemon ring.elf; do
    reg_file_ok "$stage/$m" || exit 1
done
run_cmd chmod 500 "$stage/guard" "$stage/daemon" "$stage/ring.elf"
run_cmd chmod 444 "$stage/core.bin" "$stage/mlv2.req" "$stage/PreCapture.mod"

safe_leaf_ok "$stage/check.log" || exit 1
run_cmd rm -f "$stage/check.log"
fresh_leaf_ok "$stage/check.log" || exit 1
"$stage/guard" check "$stage/mlv2.req" > "$stage/check.log" 2>&1 || {
    log_msg "MLV2_GUARD_CHECK_FAIL"
    exit 1
}
if ! run_cmd grep -q '^STATE hooks=stock rects=stock shim=zero$' "$stage/check.log" || \
   ! run_cmd grep -q '^MLV2_RESULT=0 changed=0$' "$stage/check.log"; then
    log_msg "MLV2_GUARD_NOT_STOCK"
    exit 1
fi
run_cmd rm -f "$stage/check.log"

check_ram_child "$mods"
if [ ! -d "$mods" ]; then
    run_cmd mkdir "$mods"
    owns_mods=1
fi
safe_leaf_ok "$mods/PreCapture.mod" || exit 1
run_cmd mv -f "$stage/PreCapture.mod" "$mods/PreCapture.mod"

check_ram_child "$daemon_dir"
if [ ! -d "$daemon_dir" ]; then
    run_cmd mkdir "$daemon_dir"
    owns_daemon=1
fi
for dleaf in stop disarm daemon.pid daemon.log daemon.elf ring.elf; do
    safe_leaf_ok "$daemon_dir/$dleaf" || exit 1
done
run_cmd rm -f "$daemon_dir/stop" "$daemon_dir/disarm" "$daemon_dir/daemon.pid" "$daemon_dir/daemon.log"
run_cmd mv -f "$stage/daemon" "$daemon_dir/daemon.elf"
run_cmd mv -f "$stage/ring.elf" "$daemon_dir/ring.elf"

restore_precap_cfg() {
    rec="S7PC1 0 5"
    if reg_file_ok "$persist_src"; then
        psz=$(run_cmd wc -c < "$persist_src" 2>/dev/null || echo 0)
        psz=$((psz + 0))
        plines=$(run_cmd wc -l < "$persist_src" 2>/dev/null || echo 0)
        plines=$((plines + 0))
        if [ "$plines" -eq 1 ]; then
            cand=$(run_cmd cat "$persist_src" 2>/dev/null || true)
            case "$cand" in
                "S7PC1 0 1"|"S7PC1 0 2"|"S7PC1 0 3"|"S7PC1 0 5"|"S7PC1 0 8"|\
                "S7PC1 1 1"|"S7PC1 1 2"|"S7PC1 1 3"|"S7PC1 1 5"|"S7PC1 1 8")
                    if [ "$psz" -eq 10 ]; then rec="$cand"; fi
                    ;;
                "S7PC1 0 10"|"S7PC1 1 10")
                    if [ "$psz" -eq 11 ]; then rec="$cand"; fi
                    ;;
            esac
        fi
    fi
    for cleaf in precap.cfg.tmp precap.cfg persist-cfg.tmp persist-cfg; do
        safe_leaf_ok "$stage/$cleaf" || return 1
    done
    run_cmd rm -f "$stage/precap.cfg.tmp" "$stage/persist-cfg.tmp"
    run_cmd echo "$rec" > "$stage/precap.cfg.tmp"
    run_cmd mv -f "$stage/precap.cfg.tmp" "$stage/precap.cfg"
    if [ -n "$persist_gate_val" ]; then
        run_cmd echo "$persist_gate_val" > "$stage/persist-cfg.tmp"
        run_cmd mv -f "$stage/persist-cfg.tmp" "$stage/persist-cfg"
    fi
    log_msg "MLV2_PRECAP_RESTORED=$rec"
}

restore_precap_cfg

"$reader" --present --key "$key_file" --version-file "$ver_file" >/dev/null 2>&1 || {
    log_msg "MLV2_SD_LOST_BEFORE_INSTALL"
    exit 0
}
safe_leaf_ok "$stage/sd-managed" && safe_leaf_ok "$stage/install.log" || exit 1
run_cmd rm -f "$stage/sd-managed" "$stage/install.log"
fresh_leaf_ok "$stage/sd-managed" && fresh_leaf_ok "$stage/install.log" || exit 1
: > "$stage/sd-managed"
log_msg "MLV2_GUARD_INSTALL_BEGIN"
guard_started=1
"$stage/guard" install "$stage/mlv2.req" > "$stage/install.log" 2>&1 || {
    log_msg "MLV2_GUARD_INSTALL_FAIL"
    exit 1
}
if ! run_cmd grep -q '^INSTALLED shim=' "$stage/install.log" || \
   ! run_cmd grep -q '^MLV2_RESULT=0 changed=1$' "$stage/install.log"; then
    log_msg "MLV2_GUARD_INSTALL_BAD_RESULT"
    exit 1
fi
run_cmd rm -f "$stage/install.log"
if [ "$keep_guard" -eq 0 ]; then
    run_cmd rm -f "$stage/guard" "$stage/mlv2.req"
else
    safe_leaf_ok "$stage/mlv2_guard.elf" || exit 1
    run_cmd mv -f "$stage/guard" "$stage/mlv2_guard.elf"
fi
log_msg "MLV2_SD_INSTALLED"

"$daemon_dir/daemon.elf" >/dev/null 2>&1 || {
    log_msg "MLV2_DAEMON_LAUNCH_FAIL"
    exit 1
}
dp_wait="$wait_daemon"
while [ ! -f "$daemon_dir/daemon.pid" ] && [ "$dp_wait" -gt 0 ]; do
    dp_wait=$((dp_wait - 1))
    run_cmd sleep 1
done
if ! reg_file_ok "$daemon_dir/daemon.pid"; then
    log_msg "MLV2_DAEMON_PID_MISSING"
    exit 1
fi
dpid=$(run_cmd cat "$daemon_dir/daemon.pid" 2>/dev/null || true)
case "$dpid" in
    ""|*[!0-9]*|0*)
        log_msg "MLV2_DAEMON_BAD_PID"
        exit 1
        ;;
esac
dexe=$(run_cmd readlink "$proc_root/$dpid/exe" 2>/dev/null || true)
if [ "$dexe" != "$daemon_dir/daemon.elf" ] || ! run_cmd grep -q ') [RSDT] ' "$proc_root/$dpid/stat" 2>/dev/null; then
    log_msg "MLV2_DAEMON_NOT_ALIVE pid=$dpid"
    exit 1
fi

boot_cnt=0
boot_ok=0
if reg_file_ok "$daemon_dir/daemon.log"; then
    while :; do
        line_nl=1
        if ! IFS= read -r bline; then
            line_nl=0
            [ -n "$bline" ] || break
        fi
        case "$bline" in
            "BOOT "*)
                boot_cnt=$((boot_cnt + 1))
                sp_n=0; sp_ok=0
                ip_n=0; ip_ok=0
                is_n=0; is_ok=0
                for tok in $bline; do
                    case "$tok" in
                        self_pid=*)
                            sp_n=$((sp_n + 1))
                            if [ "$tok" = "self_pid=$dpid" ]; then sp_ok=1; fi
                            ;;
                        im_pid=*)
                            ip_n=$((ip_n + 1))
                            if [ "$tok" = "im_pid=$im_pid" ]; then ip_ok=1; fi
                            ;;
                        im_st=*)
                            is_n=$((is_n + 1))
                            if [ "$tok" = "im_st=$im_st" ]; then is_ok=1; fi
                            ;;
                    esac
                done
                if [ "$line_nl" -eq 1 ] && [ "$sp_n" -eq 1 ] && [ "$sp_ok" -eq 1 ] && \
                   [ "$ip_n" -eq 1 ] && [ "$ip_ok" -eq 1 ] && \
                   [ "$is_n" -eq 1 ] && [ "$is_ok" -eq 1 ]; then
                    boot_ok=$((boot_ok + 1))
                fi
                ;;
        esac
        [ "$line_nl" -eq 1 ] || break
    done < "$daemon_dir/daemon.log"
fi
if [ "$boot_cnt" -ne 1 ] || [ "$boot_ok" -ne 1 ]; then
    log_msg "MLV2_DAEMON_BOOT_MISMATCH pid=$dpid"
    exit 1
fi
log_msg "MLV2_SD_READY daemon_pid=$dpid"

if [ "$run_once" -eq 1 ]; then
    keep_running=1
    exit 0
fi

miss_cnt=0
while [ "$(run_cmd readlink "$proc_root/$im_pid/exe" 2>/dev/null || true)" = "/usr/bin/im.elf" ] && \
      [ "$(read_proc_starttime "$im_pid" 2>/dev/null || true)" = "$im_st" ]; do
    if [ -e "$disable_flag" ] || [ -L "$disable_flag" ]; then
        if safe_leaf_ok "$stage/sd-disabled"; then
            : > "$stage/sd-disabled" 2>/dev/null || true
        fi
        log_msg "MLV2_SD_KILLSWITCH"
        break
    fi
    if [ -e "$stage/sd-disabled" ]; then
        miss_cnt=0
        if [ -e "$stage/sd-stopped" ] &&
            "$reader" --verify --key "$key_file" --version-file "$ver_file" >/dev/null 2>&1; then
            restore_precap_cfg
            run_cmd rm -f "$stage/sd-stopped" "$stage/sd-disabled"
            log_msg "MLV2_SD_REACTIVATED"
        fi
    elif "$reader" --present --key "$key_file" --version-file "$ver_file" >/dev/null 2>&1; then
        miss_cnt=0
    else
        # Debounce 2 consecutive misses (4s) so brief S2R MMC card re-enumeration never glitches.
        miss_cnt=$((miss_cnt + 1))
        if [ "$miss_cnt" -ge 2 ]; then
            run_cmd rm -f "$stage/sd-stopped" "$stage/sd-disabled"
            if safe_leaf_ok "$stage/sd-disabled"; then
                : > "$stage/sd-disabled"
            fi
            log_msg "MLV2_SD_REMOVED"
        fi
    fi
    run_cmd sleep 2
done
log_msg "MLV2_IM_EXITED"
