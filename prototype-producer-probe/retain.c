#include "sony_pins.h"

struct trace_context {
    u32 original[18], work[18];
    u32 vfp[65] __attribute__((aligned(8)));
    int attached, dirty;
};

static s32 trace_request(struct observer *o, u32 request, u32 data) {
    return call(26, request, o->trace_tid, 0, data, 0, 0);
}

static void retain_notice(struct observer *o, u32 stage, u32 detail, u32 extra) {
    u32 data[8] = {stage, detail, extra, o->trace_tid};
    emit(o, 13, data);
}

static void retain_unresolved(struct observer *o, u32 stage, u32 detail) {
#if M7_RAM_LATE_REGISTER
    late_flush(o);
#endif
#if M7_RAM_CONTINUOUS
    if (o->shutter_abort) {
        void (*abort_shutter)(struct observer *)=o->shutter_abort;
        o->shutter_abort=0;
        abort_shutter(o);
    }
#endif
#if M7_RAM_PROBE
    probe_flush(o);
#endif
    retain_notice(o, 98, stage, detail);
    /* Rewinding a partially executed Sony call would not undo its locks or reference. */
    for (;;) sleep_ms(1000);
}

static u32 append_decimal(char *out, u32 at, u32 value) {
    char digits[10];
    u32 n = 0;
    do { digits[n++] = '0' + value % 10; value /= 10; } while (value);
    while (n) out[at++] = digits[--n];
    return at;
}

static int check_media_pins(struct observer *o, const struct code_pin *pins, u32 count, u32 bias, u32 reason) {
    for (u32 i=0;i<count;++i) {
        unsigned char live[108];
        const struct code_pin *pin=&pins[i];
        if (pin->size>sizeof(live) || call(180,(u32)o->fd,(u32)live,pin->size,0,bias+pin->va,0)!=(s32)pin->size) {
            retain_notice(o,90,reason,i); return 0;
        }
        for (u32 j=0;j<pin->size;++j) if (live[j]!=pin->bytes[j]) {
            retain_notice(o,90,reason+1,i); return 0;
        }
    }
    return 1;
}

static int retain_preflight(struct observer *o) {
    char path[64] = "/proc/", buffer[32];
    u32 at = append_decimal(path, 6, m7_config.pid);
    const char task[] = "/task/", suffix[] = "/comm";
    for (u32 i = 0; i < 6; ++i) path[at++] = task[i];
    at = append_decimal(path, at, o->trace_tid);
    for (u32 i = 0; i < sizeof(suffix); ++i) path[at++] = suffix[i];
    s32 fd = call(5, (u32)path, 0, 0, 0, 0, 0);
    if (fd < 0) { retain_notice(o, 90, 1, (u32)fd); return 0; }
    s32 n = call(3, (u32)fd, (u32)buffer, sizeof(buffer), 0, 0, 0);
    call(6, (u32)fd, 0, 0, 0, 0, 0);
    int connecting=m7_config.retain_check>=10;
    const char *name = connecting && o->caller_kind==2 ? "ObjCntMgr\n" :
        m7_config.retain_check==7 || (connecting && o->caller_kind==1) ? "ObjStillRecorde\n" : "mwf_monitor_inp\n";
    u32 name_size=connecting && o->caller_kind==2 ? 10 : 16;
    if (n != (s32)name_size) { retain_notice(o, 90, 2, (u32)n); return 0; }
    for (u32 i = 0; i < name_size; ++i)
        if (buffer[i] != name[i]) { retain_notice(o, 90, 3, i); return 0; }
    for (u32 i = 0; i < sizeof(code_pins)/sizeof(code_pins[0]); ++i) {
        unsigned char live[108];
        const struct code_pin *pin = &code_pins[i];
        s32 size = call(180, (u32)o->fd, (u32)live, pin->size, 0, m7_config.bias + pin->va, 0);
        if (size != (s32)pin->size) { retain_notice(o, 90, 4, i); return 0; }
        for (u32 j = 0; j < pin->size; ++j)
            if (live[j] != pin->bytes[j]) { retain_notice(o, 90, 5, i); return 0; }
    }
    if (m7_config.retain_check == 3 || m7_config.retain_check == 4 ||
        (M7_RAM_COMMIT && m7_config.retain_check==11)) {
        for (u32 i = 0; i < sizeof(mpr_code_pins)/sizeof(mpr_code_pins[0]); ++i) {
            unsigned char live[44];
            const struct code_pin *pin = &mpr_code_pins[i];
            s32 size = call(180, (u32)o->fd, (u32)live, pin->size, 0, m7_config.mpr_bias+pin->va, 0);
            if (size != (s32)pin->size) { retain_notice(o, 90, 6, i); return 0; }
            for (u32 j = 0; j < pin->size; ++j)
                if (live[j] != pin->bytes[j]) { retain_notice(o, 90, 7, i); return 0; }
        }
    }
    if ((m7_config.retain_check == 5 || m7_config.retain_check == 7 || connecting) &&
        (!check_media_pins(o,media_code_pins,sizeof(media_code_pins)/sizeof(media_code_pins[0]),m7_config.bias,8) ||
         !check_media_pins(o,mprctrl_code_pins,sizeof(mprctrl_code_pins)/sizeof(mprctrl_code_pins[0]),m7_config.mprctrl_bias,10))) return 0;
    if ((m7_config.retain_check == 7 || connecting) &&
        (!check_media_pins(o,create_code_pins,sizeof(create_code_pins)/sizeof(create_code_pins[0]),m7_config.bias,24) ||
         !check_media_pins(o,route_code_pins,sizeof(route_code_pins)/sizeof(route_code_pins[0]),m7_config.bias,26) ||
         !check_media_pins(o,mwf_code_pins,sizeof(mwf_code_pins)/sizeof(mwf_code_pins[0]),m7_config.mwf_bias,28))) return 0;
    if (m7_config.retain_check == 8 &&
        !check_media_pins(o,end_register_code_pins,sizeof(end_register_code_pins)/sizeof(end_register_code_pins[0]),
                          m7_config.bias,32)) return 0;
    if (connecting &&
        (!check_media_pins(o,connect_code_pins,sizeof(connect_code_pins)/sizeof(connect_code_pins[0]),m7_config.bias,38) ||
         !check_media_pins(o,connect_mwf_code_pins,sizeof(connect_mwf_code_pins)/sizeof(connect_mwf_code_pins[0]),m7_config.mwf_bias,40) ||
         !check_media_pins(o,receiver_code_pins,sizeof(receiver_code_pins)/sizeof(receiver_code_pins[0]),m7_config.bias,42) ||
         !check_media_pins(o,receiver_mwf_code_pins,sizeof(receiver_mwf_code_pins)/sizeof(receiver_mwf_code_pins[0]),m7_config.mwf_bias,44) ||
         !check_media_pins(o,end_register_code_pins,sizeof(end_register_code_pins)/sizeof(end_register_code_pins[0]),m7_config.bias,46))) return 0;
    if (m7_config.retain_check==11 &&
        !check_media_pins(o,ram_capture_code_pins,sizeof(ram_capture_code_pins)/sizeof(ram_capture_code_pins[0]),m7_config.bias,48)) return 0;
    if (M7_RAM_CONTINUOUS && m7_config.retain_check==11 &&
        !check_media_pins(o,burst_cancel_code_pins,sizeof(burst_cancel_code_pins)/sizeof(burst_cancel_code_pins[0]),m7_config.bias,54)) return 0;
    if (m7_config.retain_check==12 &&
        (!check_media_pins(o,mode_code_pins,sizeof(mode_code_pins)/sizeof(mode_code_pins[0]),m7_config.bias,50) ||
         !check_media_pins(o,mode_mwf_code_pins,sizeof(mode_mwf_code_pins)/sizeof(mode_mwf_code_pins[0]),m7_config.mwf_bias,52))) return 0;
    retain_notice(o, 1, m7_config.bias, m7_config.pid);
    return 1;
}

static u32 wait_trace_stop(struct observer *o, u32 operation) {
    u32 status = 0, started = now(), reported = 0;
    for (;;) {
        s32 rc = call(114, o->trace_tid, (u32)&status, 0x40000001, 0, 0, 0);
#if M7_RAM_PRECAPTURE
        precap_save_sample(o);
#endif
        if (rc == (s32)o->trace_tid) return status;
        if (rc < 0 && rc != -4) retain_unresolved(o, operation, (u32)rc);
        if (!reported && now() - started >= 2000) {
            retain_notice(o, 97, operation, now() - started);
            reported = 1;
        }
#if M7_RAM_PRECAPTURE
        precap_wait(o,2);
#else
        sleep_ms(2);
#endif
    }
}

static void snapshot_sleep(struct observer *o, struct trace_context *t, u32 stage) {
    if (t->original[7] != 162) return;
    u32 sp = t->original[13];
    u32 data[8] = {stage, 0, t->original[17], t->original[1], 0, 0, 0, 0};
    for (u32 i = 0; i < 2; ++i) {
        u32 address = data[2+i];
        if (!(address & 3) && address >= sp && address-sp <= 0xf8 &&
            call(180, (u32)o->fd, (u32)&data[4+2*i], 8, 0, address, 0) == 8) data[1] |= 1u << i;
    }
    emit(o, 16, data);
}

static int trace_restore(struct observer *o, struct trace_context *t) {
    if (!t->attached) return 1;
    if (t->dirty) {
        snapshot_sleep(o, t, 2);
        u32 core[18], vfp[65] __attribute__((aligned(8)));
        if (trace_request(o, 28, (u32)t->vfp) != 0 || trace_request(o, 13, (u32)t->original) != 0 ||
            trace_request(o, 12, (u32)core) != 0 || trace_request(o, 27, (u32)vfp) != 0)
            retain_unresolved(o, 20, 1);
        for (u32 i = 0; i < 18; ++i)
            if (core[i] != t->original[i]) retain_unresolved(o, 20, i+2);
        for (u32 i = 0; i < 65; ++i)
            if (vfp[i] != t->vfp[i]) retain_unresolved(o, 21, i);
        retain_notice(o, 3, 18, 65);
    }
    if (trace_request(o, 17, 0) != 0) retain_unresolved(o, 22, 1);
    t->attached = 0;
    retain_notice(o, 4, 1, 0);
    return 1;
}

static int trace_begin(struct observer *o, struct trace_context *t) {
    s32 rc = trace_request(o, 16, 0);
    if (rc != 0) { retain_notice(o, 91, (u32)rc, 0); return 0; }
    t->attached = 1;
    u32 status = wait_trace_stop(o, 1);
    if (status != 0x137f) retain_unresolved(o, 2, status);
    if (trace_request(o, 12, (u32)t->original) != 0 || trace_request(o, 27, (u32)t->vfp) != 0) {
        retain_notice(o, 92, 1, 0);
        trace_restore(o, t);
        return 0;
    }
    u32 sp = t->original[13], cpsr = t->original[16];
    u32 data[8] = {2, t->original[15], sp, cpsr, t->original[7], t->original[17], o->trace_tid};
    emit(o, 13, data);
    for (u32 offset = 0; offset < 18; offset += 6) {
        u32 core[8] = {offset, 6};
        for (u32 i = 0; i < 6; ++i) core[2+i] = t->original[offset+i];
        emit(o, 15, core);
    }
    if ((sp & 7) || sp < 0x14000 || !private_range(o, sp-0x4000, 0x4000) ||
        (cpsr & 0x1f) != 0x10 || (cpsr & 0x01000200)) {
        retain_notice(o, 92, 2, 0);
        trace_restore(o, t);
        return 0;
    }
    snapshot_sleep(o, t, 1);
    return 1;
}

static int sony_call4(struct observer *o, struct trace_context *t, u32 operation,
                     u32 a0, u32 a1, u32 a2, u32 a3, u32 *result) {
    const u32 functions[] = {0, 0x108b20, 0xdd1dd9, 0xdd1595, 0x10fac4, 0x108b20, 0x10fac4, 0x10d8dc,
                            0x19e95c, 0x19e828, 0x19e664, 0x19dd5c, 0x19f614,
                            0x7c54d5, 0x19ec4c, 0xd4125d, 0xd411a1, 0xd410c5, 0x139b5,
                            0xa1a0e1, 0xa1e92d, 0x2f5d9, 0x30e99, 0x30ec5, 0x9a49, 0xa18da5,
                            0xd447a1,0xd447d5,0xa00a99,0x21f09,0x21e15,0x25975,0x2595d,0x21fdd,0xa1c4e1,0xa34be9,0x9fdf63};
    if (!operation || operation >= sizeof(functions)/sizeof(functions[0])) return 0;
    if (operation==36 && (!M7_RAM_CONTINUOUS || m7_config.retain_check!=11 || o->caller_kind!=0 || o->phase!=26)) return 0;
    if (m7_config.retain_check==14 && (o->caller_kind!=1 ||
        !(operation==24 || (operation>=29 && operation<=35)))) return 0;
    if (operation==35 && ((m7_config.retain_check!=11 && m7_config.retain_check!=14) || o->caller_kind!=1)) return 0;
    if ((m7_config.retain_check==10 || m7_config.retain_check==12) && (o->caller_kind!=1 ||
        !(operation==5 || operation==6 || operation==16 || operation==17 || (operation>=19 && operation<=24) || operation>=26))) return 0;
    if (m7_config.retain_check==11 && !(
        (o->caller_kind==0 && (operation<=7 || operation==25 || operation==36 ||
            (M7_RAM_COMMIT && operation>=8 && operation<=14))) ||
        (o->caller_kind==1 && (operation==5 || operation==6 || operation==16 || operation==17 ||
            (operation>=19 && operation<=24) || operation>=26)))) return 0;
    int copying = operation == 7, fsys = operation >= 8 && operation <= 14, media = operation >= 15 && operation <= 24;
    if (fsys && (m7_config.retain_check < 3 || !m7_config.mpr_bias)) return 0;
    if (media && m7_config.retain_check != 5 && m7_config.retain_check != 7 && m7_config.retain_check < 10) return 0;
    if (operation >= 19 && operation <= 24 && m7_config.retain_check != 7 && m7_config.retain_check < 10) return 0;
    if (operation == 25 && m7_config.retain_check != 8 && m7_config.retain_check != 11) return 0;
    if (operation >= 26 && operation<=35 && (m7_config.retain_check < 10 || o->caller_kind!=1)) return 0;
    if (operation >= 29 && operation <= 34 &&
        ((m7_config.retain_check!=11 && m7_config.retain_check!=12 && m7_config.retain_check!=14) || o->caller_kind!=1)) return 0;
    if (operation == 24 && !o->owner_pthread_bias) return 0;
    u32 call_sp = t->original[13] - (copying || fsys || media || m7_config.retain_check==7 ||
        (m7_config.retain_check>=10 && o->caller_kind==1) || operation==25 || operation==36 ? 4096 : 0);
    if (copying && (a0 != call_sp || !a2 || a2 > 4096)) return 0;
    u32 target = (operation == 24 ? o->owner_pthread_bias : (operation >= 21 && operation <= 23) || (operation >=29 && operation<=33) ? m7_config.mwf_bias : operation == 18 ? m7_config.mprctrl_bias :
                  fsys ? m7_config.mpr_bias : m7_config.bias) + functions[operation], trap = m7_config.bias + 0x55abc;
    u32 data[8] = {operation, target, a0, a1, a2, a3};
    if (!copying && !fsys) emit(o, 10, data);
    /* r12 after Sony is caller-saved; only the attach context belongs to the interrupted wait. */
    for (u32 i = 0; i < 18; ++i) t->work[i] = t->original[i];
    t->work[0] = a0; t->work[1] = a1; t->work[2] = a2; t->work[3] = a3;
    t->work[13] = call_sp;
    t->work[14] = trap | 1;
    t->work[15] = target & ~1u;
    t->work[16] = (t->work[16] & ~0x0700ffe0u) | (target & 1 ? 0x20 : 0);
    t->work[17] = 0xffffffff;
    t->dirty = 1;
    if (trace_request(o, 13, (u32)t->work) != 0) goto not_started;
    u32 verify[18];
    if (trace_request(o, 12, (u32)verify) != 0) goto not_started;
    for (u32 i = 0; i < 18; ++i)
        if (verify[i] != t->work[i]) goto not_started;
    u32 started = now();
#if M7_RAM_PRECAPTURE
    precap_save_sample(o);
#endif
    if (trace_request(o, 7, 0) != 0) goto not_started;
    u32 status = wait_trace_stop(o, 10+operation);
#if M7_RAM_PRECAPTURE
    precap_save_sample(o);
#endif
    if (status != 0x057f || trace_request(o, 12, (u32)t->work) != 0)
        retain_unresolved(o, 7, status);
    if ((t->work[15] != trap && t->work[15] != trap+2) || !(t->work[16] & 0x20) ||
        t->work[13] != call_sp) retain_unresolved(o, 8, t->work[15]);
    for (u32 i = 4; i <= 11; ++i)
        if (t->work[i] != t->original[i]) retain_unresolved(o, 9, i);
    data[1] = t->work[0]; data[2] = t->work[15]; data[3] = t->work[16];
    data[4] = now()-started; data[5] = t->work[13];
    if (!copying && !fsys) emit(o, 11, data);
#if M7_RAM_PRECAPTURE
    if (fsys && (operation==9 || operation==11)) precap_file_timing(o,operation,now()-started,t->work[0]);
#endif
    *result = t->work[0];
    return 1;
not_started:
    retain_notice(o, 94, operation, 0);
    return 0;
}

static int sony_call(struct observer *o, struct trace_context *t, u32 operation,
                     u32 a0, u32 a1, u32 a2, u32 *result) {
    return sony_call4(o,t,operation,a0,a1,a2,0,result);
}

static int try_lock(struct observer *o, struct trace_context *t, u32 operation, u32 mutex) {
    u32 result = 16;
    for (u32 i = 0; i < 8 && result == 16; ++i) {
        if (!sony_call(o, t, operation, mutex, 0, 0, &result)) return 0;
        if (result == 16) sleep_ms(5);
    }
    if (result != 0) retain_notice(o, 93, operation, result);
    return result == 0;
}

static void unlock_owned(struct observer *o, struct trace_context *t, u32 operation, u32 mutex) {
    u32 result;
    /* A failed setup has not resumed Sony; one cleanup attempt may still succeed. */
    if (!sony_call(o, t, operation, mutex, 0, 0, &result) &&
        !sony_call(o, t, operation, mutex, 0, 0, &result)) retain_unresolved(o, 32, operation);
    if (result != 0) retain_unresolved(o, 33, result);
}

static int pool_activity_allowed(u32 flags, int retained) {
    u32 active = flags & 255;
    /* EndRegister clears active while IsUsing keeps pools with retained images alive. */
    return active == 1 || (retained && active == 0);
}

static int retained_state(struct observer *o, const u32 *candidate, u32 stage, u32 mutex, u32 *users) {
    u32 root, pool, header[3], list[3], prefix[5], tail[3];
    if (!read_mem(o, m7_config.bias+0x1463800, &root, 4) || !private_range(o, root, 0x68) ||
        !read_mem(o, root+candidate[0]*4, &pool, 4) || pool != candidate[1] ||
        !read_mem(o, pool, header, 12) || header[0]+4 != mutex ||
        !pool_activity_allowed(header[1], stage >= 4) || header[2] != candidate[2] ||
        !read_mem(o, pool+0x70c4, list, 12)) return 0;
    u32 record = list[0], found = 0;
    for (u32 i = 0; i < 32 && record; ++i) {
        if (!read_mem(o, record, prefix, 20)) return 0;
        if (prefix[3] == candidate[4]) { found = 1; break; }
        record = prefix[1];
    }
    if (!found || record != candidate[3] || prefix[4] != candidate[5] ||
        !read_mem(o, record+0x168, tail, 12) || tail[2] >= 0x7fffffff ||
        (stage == 6 ? (tail[0] & 0xffff) > 1 : ((tail[0] & 0xffff) != 1 || (stage != 1 && !tail[2])))) return 0;
    *users = tail[2];
    u32 data[8] = {stage, pool, record, prefix[3], prefix[4], tail[0], tail[2], mutex};
    emit(o, 12, data);
    return 1;
}

static int retain_roundtrip(struct observer *o, const u32 *candidate) {
    struct trace_context t = {0};
    u32 root, root_lock, checked_root, checked_lock, pool, header[3];
    u32 before = 0, acquired = 0, released = 0, result, mutex = 0;
    int root_owned = 0, pool_owned = 0, reference_owned = 0, ok = 0;
    if (!trace_begin(o, &t)) return 0;
    if (!read_mem(o, m7_config.bias+0x1463800, &root, 4) ||
        !private_range(o, root, 0x68) || !read_mem(o, root+0x10, &root_lock, 4) ||
        !private_range(o, root_lock, 28)) goto cleanup;
    if (!try_lock(o, &t, 5, root_lock+4)) goto cleanup;
    root_owned = 1;
    /* EntryPoint deletes idle pools under the root lock, before their own mutex can protect them. */
    if (!read_mem(o, m7_config.bias+0x1463800, &checked_root, 4) || checked_root != root ||
        !read_mem(o, root+0x10, &checked_lock, 4) || checked_lock != root_lock ||
        !read_mem(o, root+candidate[0]*4, &pool, 4) || pool != candidate[1] ||
        !read_mem(o, pool, header, 12) || (header[1] & 255) != 1 ||
        header[2] != candidate[2] || !private_range(o, header[0], 28)) goto cleanup;
    mutex = header[0]+4;
    u32 guard[8] = {5, root, root_lock+4, pool, mutex, candidate[0], candidate[4], candidate[5]};
    emit(o, 13, guard);
    if (!try_lock(o, &t, 1, mutex)) goto cleanup;
    pool_owned = 1;
    if (!retained_state(o, candidate, 1, mutex, &before) || before >= 0x7ffffffe) goto cleanup;
    if (!sony_call(o, &t, 2, pool+0x70b4, candidate[4], 1, &result)) goto cleanup;
    if (!retained_state(o, candidate, 2, mutex, &acquired)) retain_unresolved(o, 30, 1);
    if (acquired == before && result != 0) goto cleanup;
    if (acquired != before+1 || result != 0) retain_unresolved(o, 30, result);
    reference_owned = 1;
    if (!sony_call(o, &t, 3, pool+0x70b4, candidate[4], 0, &result)) goto cleanup;
    if (!retained_state(o, candidate, 3, mutex, &released) || released != before || result != 0)
        retain_unresolved(o, 31, result);
    reference_owned = 0;
    ok = 1;
cleanup:
    if (reference_owned) {
        if (!sony_call(o, &t, 3, pool+0x70b4, candidate[4], 0, &result)) retain_unresolved(o, 34, 1);
        if (!retained_state(o, candidate, 3, mutex, &released) || released != before || result != 0)
            retain_unresolved(o, 34, result);
    }
    if (pool_owned) unlock_owned(o, &t, 4, mutex);
    if (root_owned) unlock_owned(o, &t, 6, root_lock+4);
    trace_restore(o, &t);
    return ok;
}
