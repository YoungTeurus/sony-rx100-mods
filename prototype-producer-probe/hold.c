#include "jpeg.c"

struct locked_frame {
    struct trace_context trace;
    u32 root_mutex, pool, mutex;
    int root_owned, pool_owned;
};

static void hold_unlock(struct observer *o, struct locked_frame *f) {
    if (f->pool_owned) unlock_owned(o, &f->trace, 4, f->mutex);
    if (f->root_owned) unlock_owned(o, &f->trace, 6, f->root_mutex);
    trace_restore(o, &f->trace);
    f->pool_owned = f->root_owned = 0;
}

static void hold_pool_notice(struct observer *o, struct locked_frame *f, const u32 *candidate,
                             u32 reason, const u32 *header, int retained) {
    u32 data[8] = {reason, candidate[4], candidate[0], f->pool,
                  header[0], header[1], header[2], (u32)retained};
    emit(o, 26, data);
}

static int hold_lock(struct observer *o, struct locked_frame *f, const u32 *candidate, int retained) {
    u32 root, root_lock, checked_root, checked_lock, header[3] = {0}, reason = 8;
    if (retained && !o->held_owned) goto refused;
    if (!trace_begin(o, &f->trace)) return 0;
    reason = 1;
    if (!read_mem(o, m7_config.bias+0x1463800, &root, 4) || !private_range(o, root, 0x68) ||
        !read_mem(o, root+0x10, &root_lock, 4) || !private_range(o, root_lock, 28)) goto refused;
    f->root_mutex = root_lock+4;
    reason = 10;
    if (!try_lock(o, &f->trace, 5, f->root_mutex)) goto refused;
    f->root_owned = 1;
    reason = 2;
    if (!read_mem(o, m7_config.bias+0x1463800, &checked_root, 4) || checked_root != root ||
        !read_mem(o, root+0x10, &checked_lock, 4) || checked_lock != root_lock) goto refused;
    reason = 3;
    if (candidate[0] >= 3 || !read_mem(o, root+candidate[0]*4, &f->pool, 4) ||
        f->pool != candidate[1]) goto refused;
    reason = 4;
    if (!read_mem(o, f->pool, header, 12)) goto refused;
    reason = 5;
    if (!pool_activity_allowed(header[1], retained)) goto refused;
    reason = 6;
    if (header[2] != candidate[2]) goto refused;
    reason = 7;
    if (!private_range(o, header[0], 28)) goto refused;
    f->mutex = header[0]+4;
    hold_pool_notice(o, f, candidate, 0, header, retained);
    u32 guard[8] = {5, root, f->root_mutex, f->pool, f->mutex, candidate[0], candidate[4], candidate[5]};
    emit(o, 13, guard);
    reason = 9;
    if (!try_lock(o, &f->trace, 1, f->mutex)) goto refused;
    f->pool_owned = 1;
    return 1;
refused:
    hold_pool_notice(o, f, candidate, reason, header, retained);
    return 0;
}

static void hold_unlock_mutexes(struct observer *o, struct locked_frame *f) {
    if (f->pool_owned) { unlock_owned(o,&f->trace,4,f->mutex); f->pool_owned=0; }
    if (f->root_owned) { unlock_owned(o,&f->trace,6,f->root_mutex); f->root_owned=0; }
}

static int hold_acquire(struct observer *o, const u32 *candidate) {
    struct locked_frame f = {0};
    u32 before, acquired, result;
    int ok = 0;
    if (!hold_lock(o, &f, candidate, 0)) goto done;
    if (!retained_state(o, candidate, 1, f.mutex, &before) || before >= 0x7ffffffe) goto done;
    if (!sony_call(o, &f.trace, 2, f.pool+0x70b4, candidate[4], 1, &result)) goto done;
    if (!retained_state(o, candidate, 2, f.mutex, &acquired)) retain_unresolved(o, 40, 1);
    if (acquired == before && result != 0) goto done;
    if (result || acquired != before+1) retain_unresolved(o, 40, result);
    for (u32 i = 0; i < 8; ++i) o->held_candidate[i] = candidate[i];
    o->held_owned = ok = 1;
done:
    hold_unlock(o, &f);
    return ok;
}

static int pixel_map_line(const char *line, u32 address, u32 size) {
    const char *p = line;
    u32 start = parse_hex(&p);
    if (*p++ != '-') return 0;
    u32 end = parse_hex(&p);
    if (*p++ != ' ' || p[0] != 'r' || p[2] != '-' || p[3] != 's' || p[4] != ' ') return 0;
    p += 5;
    for (u32 field = 0; field < 3; ++field) {
        while (*p && *p != ' ') ++p;
        while (*p == ' ') ++p;
    }
    const char name[] = "/dev/stream";
    for (u32 i = 0; i < sizeof(name)-1; ++i) if (*p++ != name[i]) return 0;
    if (*p == '2') ++p;
    return !*p && start >= 0x10000 && end <= 0xc0000000 && start <= address && address <= end && size <= end-address;
}

static int pixel_map(struct observer *o, u32 address, u32 size) {
    (void)o;
    if (address < 0x10000 || address >= 0xc0000000 || !size || size > 64*1024*1024 ||
        size > 0xc0000000-address) return 0;
    char path[32], buffer[512], line[256];
    proc_path(path, 1);
    s32 fd = call(5, (u32)path, 0, 0, 0, 0, 0);
    if (fd < 0) return 0;
    u32 used=0, skipped=0, total=0, found=0;
    while (total < 256*1024 && !found) {
        s32 n = call(3, (u32)fd, (u32)buffer, sizeof(buffer), 0, 0, 0);
        if (n <= 0 || n > (s32)sizeof(buffer)) break;
        total += (u32)n;
        for (s32 i=0; i<n; ++i) {
            if (buffer[i] == '\n') {
                line[used]=0;
                if (!skipped && pixel_map_line(line,address,size)) { found=1; break; }
                used=skipped=0;
            } else if (used+1 < sizeof(line)) line[used++]=buffer[i];
            else skipped=1;
        }
    }
    call(6, (u32)fd, 0, 0, 0, 0, 0);
    return found;
}

static int copy_pixels(struct observer *o, struct trace_context *t, u32 address, u32 size,
                       unsigned char *out, struct held_image *image) {
    u32 scratch = t->original[13]-4096, result;
    if (!sony_call(o,t,7,scratch,address,size,&result) || result != scratch) return 0;
    image->copies++;
    return read_mem(o,scratch,(u32 *)out,size);
}

static void hold_hash_progress(struct observer *o, struct locked_frame *f, u32 stage, struct held_image *image,
                               void (*progress_hook)(struct observer *,void *),void *context) {
    u32 metadata[8]={stage}, ready=0, header[2], status=2;
    u32 *body=metadata+5;
    unsigned char buffer[4096] __attribute__((aligned(4)));
    struct jpeg_scan scan = {0};
    u32 progress[8] = {stage, 0, o->held_candidate[4]};
    emit(o,19,progress);
    if (read_mem(o,o->held_candidate[3]+0x154,&ready,4)) {
        metadata[1]=ready&255;
        metadata[7]|=1;
    }
    if (read_mem(o,o->held_candidate[3]+0x20,metadata+2,12)) {
        metadata[7]|=2;
        if (metadata[2] && read_mem(o,metadata[2]+0x28,body,8)) metadata[7]|=4;
    }
    emit(o,20,metadata);
    /* Ordinary MakeStillInfo consumes this mapping without requiring bAnalyzed. */
    if ((metadata[7]&6) != 6) goto done;
    status=3;
    if (!pixel_map(o,body[0],body[1]) || body[1] < 8) goto done;
    status=4;
    if (!copy_pixels(o,&f->trace,body[0],8,(unsigned char *)header,image)) goto done;
    status=5;
    if (header[0] != 0x4944574d || header[1] < 8 || header[1] >= body[1]) goto done;
    image->address=body[0]+header[1];
    sha256_begin(&scan.sha);
    u32 limit=body[1]-header[1], offset=0;
    status=6;
    while (offset < limit && !scan.done && !scan.error) {
        if (progress_hook && !(offset&0xffff)) progress_hook(o,context);
        u32 n=limit-offset;
        if (n > sizeof(buffer)) n=sizeof(buffer);
        if (!copy_pixels(o,&f->trace,image->address+offset,n,buffer,image)) { status=4; goto done; }
        for (u32 i=0; i<n && !scan.done && !scan.error; ++i) jpeg_byte(&scan,buffer[i]);
        offset+=n;
    }
    if (!scan.done || scan.error) goto done;
    image->length=scan.length; image->width=scan.width; image->height=scan.height;
    sha256_finish(&scan.sha,image->digest);
    image->valid=1; status=1;
done:
    progress[1]=status; progress[2]=image->address; progress[3]=image->length;
    progress[4]=image->width; progress[5]=image->height; progress[6]=image->copies; progress[7]=body[0];
    emit(o,17,progress);
    if (image->valid) emit(o,18,image->digest);
}

static void hold_hash(struct observer *o,struct locked_frame *f,u32 stage,struct held_image *image) {
    hold_hash_progress(o,f,stage,image,0,0);
}

#include "commit.c"

static void hold_measure(struct observer *o) {
    struct locked_frame f = {0};
    u32 users;
    if (hold_lock(o,&f,o->held_candidate,1) && retained_state(o,o->held_candidate,4,f.mutex,&users))
        hold_hash(o,&f,1,&o->jpeg_before);
    hold_unlock(o,&f);
}

static int hold_complete(struct observer *o, int measure) {
    struct locked_frame f = {0};
    u32 before=0, after=0, result=0;
    int locked=0;
    for (u32 attempt=0; attempt<16; ++attempt) {
        if (hold_lock(o,&f,o->held_candidate,1)) { locked=1; break; }
        hold_unlock(o,&f);
        __aeabi_memclr(&f,sizeof(f));
        sleep_ms(20);
    }
    if (!locked) retain_unresolved(o,41,1);
    if (!retained_state(o,o->held_candidate,5,f.mutex,&before)) retain_unresolved(o,41,2);
    if (measure) hold_hash(o,&f,2,&o->jpeg_after);
    if (measure && (m7_config.retain_check==3 || m7_config.retain_check==4)) {
        if (o->commit_allowed) commit_write(o,&f);
        else o->commit_status=13;
    }
    if (!sony_call(o,&f.trace,3,f.pool+0x70b4,o->held_candidate[4],0,&result) &&
        !sony_call(o,&f.trace,3,f.pool+0x70b4,o->held_candidate[4],0,&result)) retain_unresolved(o,42,1);
    if (result != 0) retain_unresolved(o,42,result);
    /* A completed decrement must never be repeated, even if its post-read fails. */
    o->held_owned=0;
    int ok=retained_state(o,o->held_candidate,6,f.mutex,&after) && after+1 == before;
    hold_unlock(o,&f);
    return ok;
}

static int hold_finish(struct observer *o) { return hold_complete(o,1); }
static int hold_release(struct observer *o) { return hold_complete(o,0); }
