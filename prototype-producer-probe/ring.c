#include "../prototype-ring/src/pre_capture.c"

static void ring_notice(struct observer *o, u32 stage, u32 slot, u32 a, u32 b, u32 c, u32 d, u32 e) {
    u32 data[8]={stage,slot,slot<3?o->owners[slot].candidate[4]:0,a,b,c,d,e};
    emit(o,25,data);
}

static void ring_select(struct observer *o, u32 slot) {
    struct ring_owner *owner=&o->owners[slot];
    for (u32 i=0;i<8;++i) o->held_candidate[i]=owner->candidate[i];
    o->held_owned=owner->owned;
    o->jpeg_before=owner->before;
    __aeabi_memclr(&o->jpeg_after,sizeof(o->jpeg_after));
    o->commit_drive=o->commit_status=o->commit_written=o->commit_read=o->commit_reads=0;
    o->commit_sequence=slot;
    for (u32 i=0;i<8;++i) o->commit_digest[i]=0;
}

static int ring_capture_request(void *context, uint32_t ticket) {
    struct observer *o=context;
    if (o->pending_capture || o->ring_captured>=3) return 1;
    o->pending_capture=ticket;
    return 0;
}

static int ring_stop_request(void *context, uint32_t ticket) {
    struct observer *o=context;
    if (o->pending_stop) return 1;
    o->pending_stop=ticket;
    ring_notice(o,8,3,ticket,o->ring.state,o->ring.count,0,0);
    return 0;
}

static int ring_release_frame(void *context, const pc_frame *frame) {
    struct observer *o=context;
    if (!frame->lease || frame->lease>3 || frame->handle!=&o->owners[frame->lease-1]) return 1;
    u32 slot=frame->lease-1;
    struct ring_owner *owner=&o->owners[slot];
    ring_notice(o,6,slot,owner->owned,owner->released,0,0,0);
    int ok=owner->released && !owner->owned;
    if (owner->owned) {
        ring_select(o,slot);
        ok=hold_release(o);
        owner->owned=o->held_owned;
        owner->released=ok && !owner->owned;
    }
    ring_notice(o,7,slot,ok,owner->owned,owner->released,0,0);
    return ok?0:1;
}

static int ring_write_request(void *context, uint32_t ticket, const pc_frame *frame) {
    struct observer *o=context;
    if (o->pending_write || frame->lease<2 || frame->lease>3 ||
        frame->handle!=&o->owners[frame->lease-1]) return 1;
    o->pending_write=ticket;
    o->write_slot=frame->lease-1;
    ring_notice(o,13,o->write_slot,ticket,o->ring.state,o->ring.count,0,0);
    return 0;
}

static int ring_capture_one(struct observer *o, u32 slot) {
    u32 ticket=o->pending_capture;
    if (!ticket || slot>=3 || o->owners[slot].owned) return 0;
    o->pending_capture=0;
    o->retain_attempted=o->retain_ok=o->held_owned=0;
    __aeabi_memclr(&o->jpeg_before,sizeof(o->jpeg_before));
    __aeabi_memclr(&o->jpeg_after,sizeof(o->jpeg_after));
    for (u32 i=0;i<8;++i) o->held_candidate[i]=0;
    ring_notice(o,2,slot,ticket,o->ring.state,0,0,0);
    int ok=capture(o,slot==2?10:4+slot*2);
    struct ring_owner *owner=&o->owners[slot];
    if (o->held_owned) {
        for (u32 i=0;i<8;++i) owner->candidate[i]=o->held_candidate[i];
        owner->owned=1;
        if (slot) {
            hold_measure(o);
            owner->before=o->jpeg_before;
        }
    }
    ok=ok && o->retain_ok && owner->owned && (!slot || owner->before.valid);
    ring_notice(o,3,slot,ticket,ok,owner->owned,owner->before.valid,owner->candidate[5]);
    if (!ok) return 0;
    o->ring_captured++;
    pc_frame frame={slot+1,64u*1024*1024,(uint64_t)now()*1000000,owner};
    pc_result result=pc_frame_ready(&o->ring,ticket,&frame);
    ring_notice(o,4,slot,ticket,result,o->ring.state,o->ring.count,o->ring.used_bytes);
    return result==PC_OK && !frame.lease;
}

static int ring_save_one(struct observer *o) {
    u32 ticket=o->pending_write,slot=o->write_slot;
    if (!ticket || slot<1 || slot>2 || !o->owners[slot].owned) return 0;
    o->pending_write=0;
    ring_select(o,slot);
    o->phase=8;
    o->commit_allowed=1;
    ring_notice(o,10,slot,ticket,commit_name_token(o),o->ring.state,o->ring.count,0);
    int released=hold_finish(o);
    o->owners[slot].owned=o->held_owned;
    o->owners[slot].released=released && !o->held_owned;
    if (o->commit_status==1 && released && !o->held_owned) commit_verify(o);
    commit_result(o);
    int verified=o->commit_status==12 && released && !o->held_owned;
    ring_notice(o,11,slot,ticket,verified,o->commit_status,o->held_owned,released);
    pc_result result=pc_write_complete(&o->ring,ticket,verified);
    return verified && result==PC_OK;
}

static int ring_run(struct observer *o, int ready) {
    pc_config config={128u*1024*1024,64u*1024*1024,50,true};
    pc_backend backend={o,ring_capture_request,ring_stop_request,ring_release_frame,ring_write_request};
    int ok=0;
    if (!pc_init(&o->ring,config,backend,o->ring_slots,2)) goto cleanup;
    ring_notice(o,1,3,2,config.storage_bytes,config.max_frame_bytes,config.pre_percent,0);
    if (!ready || pc_arm(&o->ring)!=PC_OK || pc_focus_ready(&o->ring)!=PC_OK) goto cleanup;
    if (!ring_capture_one(o,0) || !ring_capture_one(o,1)) goto cleanup;
    u32 triggered=now();
    pc_result result=pc_trigger(&o->ring,(uint64_t)triggered*1000000);
    ring_notice(o,5,3,triggered,result,o->ring.state,o->ring.count,o->pending_capture);
    if (result!=PC_OK || !ring_capture_one(o,2)) goto cleanup;
    phase(o,12);
    if (!o->pending_stop || !subscription(o,1,1)) goto cleanup;
    u32 stop=o->pending_stop;
    o->pending_stop=0;
    result=pc_stopped(&o->ring,stop,true);
    ring_notice(o,9,3,stop,result,o->ring.state,o->ring.count,o->ring.in_flight);
    if (result!=PC_OK || !ring_save_one(o) || !ring_save_one(o)) goto cleanup;
    ok=o->ring.state==PC_DONE && o->ring.written_frames==2 && !o->ring.count;
cleanup:
    o->phase=12;
    o->commit_allowed=0;
    for (u32 slot=0;slot<3;++slot) if (o->owners[slot].owned) {
        pc_frame frame={slot+1,64u*1024*1024,0,&o->owners[slot]};
        if (ring_release_frame(o,&frame)!=0) ok=0;
    }
    u32 owned=0;
    for (u32 slot=0;slot<3;++slot) owned|=o->owners[slot].owned<<slot;
    o->held_owned=owned;
    o->retain_ok=ok && !owned;
    ring_notice(o,12,3,o->ring.state,o->ring.error,o->ring_captured,o->ring.written_frames,owned);
    return ok && !owned;
}
