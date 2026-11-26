/* A bounded shutter pulse can leave queued exposures after S2 is released. */
#if !M7_RAM_PROBE
#include "shutter_start.c"
#endif

#define RAM_BURST_LIMIT 8u
#define RAM_BURST_QUIET_MS 2000u

#if !M7_RAM_PROBE
static void session_stop_checkpoint(struct observer *o,struct connect_owner *c,u32 sample);
static void session_pin_checkpoint(struct observer *o,struct connect_owner *c,u32 sample);
#endif

static void burst_notice(struct observer *o,u32 stage,u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g) {
    u32 data[8]={stage,a,b,c,d,e,f,g},previous=o->phase;
    o->phase=25;emit(o,63,data);o->phase=previous;
}

static void burst_words(struct observer *o,u32 serial,u32 tag,const u32 *words,u32 count) {
    for (u32 off=0;off<count;off+=5) {
#if M7_RAM_PRECAPTURE
        precap_sample(o);
#endif
        u32 data[8]={serial,tag,off};
        for (u32 i=0;i<5 && off+i<count;++i) data[3+i]=words[off+i];
        emit(o,64,data);
    }
}

static int burst_wait_block(struct observer *o,u32 serial,u32 tag,u32 address,u32 *words,u32 count) {
    u32 size=count*4;
    int mapped=0,ok=0;
    if (count && count<=256 && !(address&3) && address>=0x10000 && address<=0xc0000000-size) {
        for (u32 i=0;i<m7_config.nranges;++i)
            if (address>=m7_config.ranges[i].start && address+size<=m7_config.ranges[i].end) mapped=1;
        for (u32 i=0;i<o->nadded;++i)
            if (address>=o->added[i].start && address+size<=o->added[i].end) mapped=1;
        /* Optional observations have their own read status; cleanup relies on the original checks. */
        if (mapped) ok=call(180,(u32)o->fd,(u32)words,size,0,address,0)==(s32)size;
    }
    burst_notice(o,13,serial,tag,address,count,ok,0,0);
    if (ok) burst_words(o,serial,tag,words,count);
    return ok;
}

static void burst_wait_diagnostics(struct observer *o,struct ram_capture *r,u32 serial) {
    const u32 *regs=r->owners.rec_trace.original,*held=o->held_candidate;
    u32 words[256],remote=0,signal=0,node=0,count=0;
    burst_wait_block(o,serial,6,regs[13],words,256);
    burst_wait_block(o,serial,7,r->owners.recorder.core,words,10);
    if (burst_wait_block(o,serial,8,r->owners.recorder.core+0x9c,words,1)) remote=words[0];
    if (remote>=0x10000 && remote<=0xc0000000-0x2050 &&
        burst_wait_block(o,serial,9,remote+0x2034,words,7)) signal=words[1];
    if (signal) burst_wait_block(o,serial,10,signal,words,16);
    burst_wait_block(o,serial,11,regs[6],words,16);
    burst_wait_block(o,serial,12,r->image,words,18);
    burst_wait_block(o,serial,13,r->info,words,13);
    burst_wait_block(o,serial,14,r->frame+0x2938,words,3);
    burst_wait_block(o,serial,15,held[1],words,3);
    if (burst_wait_block(o,serial,16,held[1]+0x70c4,words,3)) { node=words[0];count=words[2]; }
    burst_wait_block(o,serial,17,held[1]+0x70e8,words,1);
    burst_wait_block(o,serial,18,held[1]+0x71c8,words,1);
    burst_wait_block(o,serial,19,held[1]+0x71ec,words,4);
    burst_wait_block(o,serial,20,held[3],words,5);
    burst_wait_block(o,serial,21,held[3]+0x168,words,3);
    /* Other owners can run; this bounded observation never authorizes a Sony call or cleanup. */
    for (u32 i=0;node && i<count && i<RAM_BURST_LIMIT;++i) {
        u32 current=node;
        if (!burst_wait_block(o,serial,32+i*2,current,words,5)) break;
        node=words[1];
        if (current>0xc0000000-0x174 ||
            !burst_wait_block(o,serial,33+i*2,current+0x168,words,3)) break;
    }
}

#if !M7_RAM_PROBE
static void burst_abort_shutter(struct observer *o) {
    struct sd_start_command *start=o->shutter_state;
    u32 previous=o->phase;o->phase=25;
    release_buttons(o);ram_input(o,91);
    while (!start->done) { sd_start_poll(o,start); if (!start->done) sleep_ms(5); }
    o->shutter_state=0;o->phase=previous;
}

static int burst_shutter(struct observer *o,struct ram_capture *r) {
    u32 previous=o->phase;o->phase=25;
    ram_input(o,0);
    if (!sender(o,1,1)) retain_unresolved(o,190,1);
    observe(o,m7_config.focus_ms);ram_input(o,1);
    struct sd_start_command start={.started=now(),.status=0xffffffff};
    start.pid=call(2,0,0,0,0,0,0);
    if (!start.pid) { child_exec(2,1); return 0; }
    o->shutter_state=&start;o->shutter_abort=burst_abort_shutter;
    burst_notice(o,1,start.pid,0,0,0,0,0,0);
    u32 published=0,at=0,admitted=0;
    for (;;) {
        sd_start_poll(o,&start);
        subscription(o,0,0);
        if (!published && o->route[6]==15 && !o->route[0] && o->route[9]==1 && o->route[10]==1) {
            published=1;at=now();ram_input(o,2);
            burst_notice(o,2,start.pid,200,0,0,0,0,0);
        }
        if (published && (now()-at>=200 || start.killed || (start.done && !sd_start_ok(&start)))) break;
        if (start.done && !sd_start_ok(&start)) retain_unresolved(o,190,2);
        if (!published && now()-start.started>=1500) retain_unresolved(o,190,3);
        if (published && !admitted) {
            o->phase=19;
            struct trace_context *t=&r->owners.rec_trace;
            int hit=capture_trap_poll(o,t,&r->trap);
            if (hit<0) retain_unresolved(o,190,5);
            if (hit) {
                ram_words(o,11,t->original[15],t->original,18);
                if (t->original[16]&0x0600fc00) retain_unresolved(o,150,11);
                o->phase=25;ram_input(o,4);
                if (o->route[0] || o->route[6]!=15 || o->route[9]!=1 || o->route[10]!=1)
                    retain_unresolved(o,190,6);
                o->phase=19;
                /* BeginRegister must run during the pulse; JPEG hashing waits until S2 is up. */
                ram_capture_begin(o,r);admitted=1;
                burst_notice(o,6,5,1,r->capture,now()-at,m7_config.bias+0x9fc7d8,m7_config.bias+0xa14c98,0);
            }
            o->phase=25;
        }
        observe(o,5);
    }
    o->shutter_abort=0;
    r->shots=1;r->buttons=release_buttons(o);
    ram_input(o,3);
    while (!start.done) { sd_start_poll(o,&start); if (!start.done) sleep_ms(5); }
    o->shutter_state=0;
    burst_notice(o,3,sd_start_ok(&start),r->buttons,published,0,0,0,0);
    if (!sd_start_ok(&start) || !r->buttons || o->route[9] || o->route[10] || o->route[0])
        retain_unresolved(o,190,4);
    o->phase=previous;
    return admitted;
}

#endif

static void burst_registers(struct observer *o,struct trace_context *t,u32 serial) {
    if (trace_request(o,12,(u32)t->original) || trace_request(o,27,(u32)t->vfp))
        retain_unresolved(o,191,1);
    for (u32 i=0;i<18;++i) t->work[i]=t->original[i];
    t->dirty=0;
    burst_words(o,serial,1,t->original,18);burst_words(o,serial,2,t->vfp,65);
}

static void burst_unchanged(struct observer *o,struct trace_context *t,u32 serial) {
    u32 regs[18],vfp[65] __attribute__((aligned(8)));
    if (trace_request(o,12,(u32)regs) || trace_request(o,27,(u32)vfp)) retain_unresolved(o,191,2);
    for (u32 i=0;i<18;++i) if (regs[i]!=t->original[i]) retain_unresolved(o,191,3);
    for (u32 i=0;i<65;++i) if (vfp[i]!=t->vfp[i]) retain_unresolved(o,191,4);
    burst_words(o,serial,3,regs,18);burst_words(o,serial,4,vfp,65);
}

static void burst_own_stop(struct observer *o,u32 serial,u32 helper) {
    u32 info[32]={0};
    if (trace_request(o,0x4202,(u32)info)) retain_unresolved(o,192,1);
    burst_words(o,serial,5,info,32);
    if (info[0]!=19 || info[1] || info[2]!=0xfffffffa || info[3]!=helper)
        retain_unresolved(o,192,2);
}

/* This stop is read-only: no syscall-exit snapshot is installed or borrowed.
   The private SIGSTOP is consumed as a delivery stop, never delivered to im.elf. */
static int burst_boundary(struct observer *o,struct ram_capture *r,struct capture_trap *next,u32 frame) {
    struct trace_context *t=&r->owners.rec_trace;
    u32 previous=o->phase,started=now(),last=started,serial=0,pending=0,streak=0,diagnostics=0;
    u32 helper=(u32)call(20,0,0,0,0,0,0);
    if (!helper || helper>=0x80000000 || helper==m7_config.pid) retain_unresolved(o,192,3);
    o->phase=25;
    for (;;) {
#if M7_RAM_PRECAPTURE
        precap_sample(o);precap_tick(o,r);
#endif
#if M7_RAM_PROBE
        ram_probe_deadline(o,r,2,frame-1);
#endif
        u32 status=0;
        s32 waited=call(114,o->trace_tid,(u32)&status,0x40000001,0,0,0);
        if (waited==0 || waited==-4) {
#if !M7_RAM_PRECAPTURE
            if (now()-started>=15000u) retain_unresolved(o,193,frame);
#endif
            if (!pending && now()-last>=250) {
                ++serial;
                if (call(268,m7_config.pid,o->trace_tid,19,0,0,0)) retain_unresolved(o,192,4);
                pending=1;
                burst_notice(o,10,serial,helper,o->trace_tid,frame,now()-started,0,0);
            }
#if M7_RAM_PRECAPTURE
            precap_wait(o,10);
#else
            sleep_ms(10);
#endif
            continue;
        }
        if (waited!=(s32)o->trace_tid || (status!=0x057f && status!=0x137f))
            retain_unresolved(o,193,status);
        burst_registers(o,t,serial);
        burst_notice(o,11,serial,status,t->original[15],pending,frame,0,0);
        if (status==0x057f) {
            u32 live;
            if (t->original[15]!=next->address || (t->original[16]&0x3f)!=0x30 ||
                (t->original[16]&0x0600fc00) || !capture_trap_word(o,next->address,&live) || live!=next->patched)
                retain_unresolved(o,193,2);
            if (pending) {
                /* A signal queued just after the UDF stop must be consumed before the gate is removed. */
                if (trace_request(o,7,0)) retain_unresolved(o,192,5);
                u32 until=now();
                do {
#if M7_RAM_PRECAPTURE
                    precap_sample(o);
#endif
                    waited=call(114,o->trace_tid,(u32)&status,0x40000001,0,0,0);
                    if (waited==0 || waited==-4) {
#if M7_RAM_PRECAPTURE
                        precap_wait(o,5);
#else
                        sleep_ms(5);
#endif
                    }
                    else break;
                } while (now()-until<1000);
                if (waited!=(s32)o->trace_tid || status!=0x137f) retain_unresolved(o,192,6);
                burst_own_stop(o,serial,helper);burst_unchanged(o,t,serial);pending=0;
                burst_notice(o,12,serial,1,frame,0,0,0,0);
            }
            capture_trap_notice(o,next,11,0x057f,t->original[16]);
#if M7_RAM_PRECAPTURE
            r->ready_ms=now()-o->started;
            precap_flush_ready(o,r);
#endif
            burst_notice(o,5,frame,1,0,0,0,0,0);
            o->phase=previous;return 1;
        }
        if (!pending) retain_unresolved(o,192,7);
        burst_own_stop(o,serial,helper);pending=0;
        int idle=(t->original[16]&0x0100021f)==0x10 && !(t->original[13]&7) &&
            private_range(o,t->original[13],136) &&
            create_idle(o,t,&r->owners.recorder) && connect_queues(o,&r->owners,4,1);
        streak=idle?streak+1:0;
#if M7_RAM_PRECAPTURE
        if (!idle) precap_blocked(o,1,serial,t->original[15],t->original[17]);
#endif
        if (!idle && (!diagnostics || (diagnostics==1 && now()-started>=14000))) {
            burst_wait_diagnostics(o,r,serial);++diagnostics;
        }
        burst_unchanged(o,t,serial);
#if M7_RAM_PRECAPTURE
        precap_flush_ready(o,r);
        if (streak>=2 && now()-started>=RAM_BURST_QUIET_MS) precap_admission_idle(o);
#endif
        burst_notice(o,12,serial,0,frame,idle,streak,now()-started,0);
        if (streak>=2 && now()-started>=RAM_BURST_QUIET_MS
#if M7_RAM_PRECAPTURE
            && precap_boundary_done(o,r)
#endif
        ) {
            if (!capture_trap_restore(o,next)) retain_unresolved(o,194,1);
            o->phase=previous;
            trace_restore(o,t);
            burst_notice(o,5,frame,0,streak,now()-started,0,0,0);
            return 0;
        }
        if (trace_request(o,7,0)) retain_unresolved(o,192,8);
        last=now();
    }
}

static void burst_ready_image(struct observer *o,struct ram_capture *r) {
    u32 *regs=r->owners.rec_trace.original,info[13];
    ram_words(o,12,regs[15],regs,18);
    if (regs[15]!=m7_config.bias+0xa14c98 || regs[0] || regs[4]!=r->owners.recorder.core ||
        regs[13]!=regs[7]-0x88 || !private_range(o,regs[7],0x29b0) ||
        !ram_block(o,119,regs[5],info,13) || !ram_same_tuple(info,info[11],0) || r->mask!=0x200)
        retain_unresolved(o,196,1);
    r->capture=info[11];r->info=regs[5];
    ram_notice(o,2,r->capture,r->info,r->image,1,0x4100,1,r->mask);
}

#if !M7_RAM_PROBE
#if M7_RAM_LATE_REGISTER
static void burst_late_register(struct observer *o,struct connect_owner *c,u32 frame);
#endif

struct burst_frame {
    struct ram_capture capture;
    struct ring_owner owner;
};

#include "burst_cancel.c"

static void burst_refused_pool(struct observer *o,const u32 *list,u32 after) {
    u32 node=list[0];
    for (u32 n=0;node && n<list[2] && n<RAM_BURST_LIMIT;++n) {
        u32 prefix[5]={0},tail[3],tag=220+after*16+n*2;
        int prefix_ok=0,tail_ok=0;
        if (!(node&3) && node>=0x10000 && node<=0xc0000000-0x174) {
            prefix_ok=ram_block(o,tag,node,prefix,5);
            if (prefix_ok) tail_ok=ram_block(o,tag+1,node+0x168,tail,3);
        }
        burst_notice(o,16,after,n,node,prefix_ok,tail_ok,prefix[1],0);
        if (!prefix_ok || !tail_ok) break;
        node=prefix[1];
    }
}

static int burst_pool_check(struct observer *o,struct burst_frame *saved,u32 count,u32 after) {
    struct locked_frame f={0};
    u32 header[3]={0},list[3],rest,mode,notify[4],image[18],seen=0,previous=0;
    u32 pool=o->held_candidate[1],tag=130+after*32,read_header=0,read_list=0,reason=1;
    int ok=0;
    ram_monitor(o);
    if (!hold_lock(o,&f,o->held_candidate,1)) goto done;
    reason=2;
    if (!ram_block(o,tag,pool,header,3)) goto done;
    read_header=1;
    if (!ram_block(o,tag+1,pool+0x70c4,list,3)) goto done;
    read_list=1;
    if (!ram_block(o,tag+2,pool+0x71c8,&rest,1) ||
        !ram_block(o,tag+3,pool+0x70e8,&mode,1) ||
        !ram_block(o,tag+4,pool+0x71ec,notify,4) ||
        !ram_block(o,tag+6,saved[count-1].capture.image,image,18)) goto done;
    reason=3;
    u32 active=header[1]&255;
    if (header[2]!=0x4100 || active>1 || (after && active) || rest || list[2]!=count ||
        mode>3 || (!mode && notify[1]) || image[10]!=saved[count-1].capture.owners.recorder.manager+0x10 ||
        image[4]!=(active?0x4100u:0u) || (!active && (image[1] || image[3] || (image[11]&255)))) goto done;
    u32 node=list[0];
    for (u32 n=0;n<count;++n) {
        u32 index=count,prefix[5],tail[3];
        for (u32 i=0;i<count;++i) if (saved[i].owner.candidate[3]==node) index=i;
        reason=4;
        if (index==count || (seen&(1u<<index))) goto done;
        struct burst_frame *entry=&saved[index];
        const u32 *candidate=entry->owner.candidate;
        reason=5;
        if (!ram_block(o,tag+10+index*2,node,prefix,5) ||
            !ram_block(o,tag+11+index*2,node+0x168,tail,3)) goto done;
        reason=6;
        if (candidate[0]!=o->held_candidate[0] || candidate[1]!=pool || candidate[2]!=0x4100 ||
            entry->owner.owned!=1 || !entry->capture.completion || prefix[0]!=previous ||
            prefix[3]!=entry->capture.uid || prefix[4]!=entry->capture.capture ||
            prefix[3]!=candidate[4] || prefix[4]!=candidate[5] || tail[2]!=1 || (tail[1]&255) ||
            (tail[0]!=1 && !(active && tail[0]==0x10001)) ||
            (active && index+1==count && tail[0]!=0x10001)) goto done;
        seen|=1u<<index;previous=node;node=prefix[1];
    }
    reason=7;
    if (node || previous!=list[1] || seen!=(1u<<count)-1) goto done;
    reason=0;ok=1;
done:
    if (!ok && read_list && f.pool_owned) burst_refused_pool(o,list,after);
    burst_notice(o,14,after,count,pool,read_header,header[1],reason,ok);
    hold_unlock(o,&f);
    return ok;
}

static int session_continuous_frames(struct observer *o,struct connect_owner *c) {
    struct ram_capture r={0};r.owners=*c;
    struct burst_frame saved[RAM_BURST_LIMIT]={0};
    u32 previous=o->phase;
    if (!c->stock_connection || !c->ram_only || o->held_owned) retain_unresolved(o,195,1);
    burst_notice(o,0,2,RAM_BURST_LIMIT,200,RAM_BURST_QUIET_MS,250,m7_config.pid,c->rec_tid);
    o->phase=19;ram_monitor(o);
    if (!retain_preflight(o)) retain_unresolved(o,195,2);
    connect_caller(o,&r.owners,1);
    if (!connect_pair(o,&r.owners,3)) retain_unresolved(o,195,3);
    for (u32 frame=1;;++frame) {
        session_notice(o,10,frame,2,0,0,0,0,0);
        ram_notice(o,0,m7_config.bias,c->rec_tid,c->remote_tid,m7_config.monitor_tid,c->recorder.core,c->recorder.manager,0);
        if (!ram_precondition(o,&r)) retain_unresolved(o,195,4);
        ram_notice(o,1,c->source,c->destination,r.image,r.mask,r.grouping,c->rec_tid,c->remote_tid);
        if (frame==1) {
            if (!capture_trap_set(o,&r.trap,m7_config.bias+0x9fc7d8,0x0901f04f)) retain_unresolved(o,195,5);
            connect_caller(o,&r.owners,2);trace_restore(o,&r.owners.remote_trace);
            connect_caller(o,&r.owners,1);
            if (trace_request(o,7,0)) retain_unresolved(o,195,6);
            if (!burst_shutter(o,&r)) {
                ram_wait(o,&r,1);ram_capture_begin(o,&r);
                burst_notice(o,6,5,0,r.capture,0,m7_config.bias+0x9fc7d8,m7_config.bias+0xa14c98,0);
            }
        } else {
            burst_ready_image(o,&r);
        }
        ram_capture_body(o,&r);
        for (u32 i=0;i+1<frame;++i)
            if (saved[i].capture.uid==r.uid || saved[i].capture.capture==r.capture ||
                saved[i].owner.candidate[3]==o->held_candidate[3]) retain_unresolved(o,196,2);
        struct capture_trap next={0};
        o->phase=25;
        /* Burst exposures can all precede the first JPEG. Guard the next ready image. */
        burst_notice(o,4,frame,frame+1,m7_config.bias+0xa14c98,0,0,0,0);
        if (!capture_trap_set(o,&next,m7_config.bias+0xa14c98,0x531ef240)) retain_unresolved(o,195,7);
        o->phase=19;ram_continue(o,&r,4,0);
        int more=burst_boundary(o,&r,&next,frame+1);
        struct burst_frame *parked=&saved[frame-1];
        parked->capture=r;
        for (u32 i=0;i<8;++i) parked->owner.candidate[i]=o->held_candidate[i];
        parked->owner.before=o->jpeg_before;parked->owner.owned=o->held_owned;
        if (o->held_owned!=1) retain_unresolved(o,196,3);
        burst_notice(o,7,frame,o->held_candidate[1],o->held_candidate[3],r.uid,r.capture,1,o->jpeg_before.length);
        o->held_owned=0;
        if (!more) {
            if (!connect_pair(o,&r.owners,3)) retain_unresolved(o,195,10);
            session_stop_checkpoint(o,&r.owners,470);
            /* A pending tail can end the pool only after every member passes the ownership check. */
            for (u32 remaining=frame;remaining;--remaining) {
                u32 i=remaining-1;
                struct burst_frame *done=&saved[i];
                if (o->held_owned || done->owner.owned!=1) retain_unresolved(o,196,4);
                for (u32 j=0;j<8;++j) o->held_candidate[j]=done->owner.candidate[j];
                o->jpeg_before=done->owner.before;o->jpeg_after=(struct held_image){0};
                o->held_owned=1;
                burst_notice(o,8,i+1,o->held_candidate[1],o->held_candidate[3],
                             done->capture.uid,done->capture.capture,1,o->jpeg_before.length);
                if (remaining==frame) {
                    if (!burst_cancel_reserved(o,saved,frame)) retain_unresolved(o,198,1);
                    connect_release(o,&r.owners);
                    session_pin_checkpoint(o,&r.owners,473);
                    if (!burst_pool_check(o,saved,frame,0)) retain_unresolved(o,197,1);
                } else {
                    u32 active=0;
                    int read_ok=read_mem(o,o->held_candidate[1]+4,&active,4);
                    burst_notice(o,15,i+1,o->held_candidate[1],read_ok,active,0,0,0);
                    if (!read_ok || (active&255)) retain_unresolved(o,195,8);
                }
                if (ram_after(o,&done->capture)!=1) retain_unresolved(o,195,9);
                if (remaining==frame && !burst_pool_check(o,saved,frame,1)) retain_unresolved(o,197,2);
                if (!ram_release(o,&done->capture,0)) retain_unresolved(o,195,9);
                if (remaining==frame || remaining==1)
                    session_pin_checkpoint(o,&r.owners,remaining==frame?474:475);
                done->owner.owned=0;
#if M7_RAM_LATE_REGISTER
                if (remaining==frame && frame>1) burst_late_register(o,&r.owners,frame);
#endif
                connect_caller(o,&r.owners,1);
                ram_notice(o,9,1,0,1,0,1,1,1);
                session_notice(o,11,i+1,1,0,0,0,0,0);
            }
            burst_notice(o,9,frame>=2,frame,0,1,1,1,0);
            o->phase=previous;return frame>=2;
        }
        if (frame>=RAM_BURST_LIMIT) retain_unresolved(o,195,11);
        struct connect_owner owners=r.owners;
        r=(struct ram_capture){0};r.owners=owners;r.trap=next;r.shots=1;r.buttons=1;r.image_ready=1;
        o->jpeg_before=(struct held_image){0};o->jpeg_after=(struct held_image){0};
    }
}

#endif
