struct ram_capture {
    struct connect_owner owners;
    struct capture_trap trap;
    u32 image, mask, grouping, capture, uid, frame, info, users;
    u32 shots, completion, buttons, end_called, image_ready;
#if M7_RAM_PRECAPTURE || M7_RAM_PROBE
    u32 ready_ms;
#if M7_RAM_PROBE
    u32 drain_started;
#endif
#endif
};

static void ram_notice(struct observer *o,u32 stage,u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g) {
    u32 data[8]={stage,a,b,c,d,e,f,g};
    emit(o,49,data);
}

static void ram_words(struct observer *o,u32 tag,u32 address,const u32 *words,u32 count) {
    for (u32 off=0;off<count;off+=5) {
#if M7_RAM_PRECAPTURE
        precap_sample(o);
#endif
        u32 data[8]={tag,address,off};
        for (u32 i=0;i<5 && off+i<count;++i) data[3+i]=words[off+i];
        emit(o,50,data);
    }
}

static int ram_block(struct observer *o,u32 tag,u32 address,u32 *words,u32 count) {
    if (!read_mem(o,address,words,count*4)) return 0;
    ram_words(o,tag,address,words,count);
    return 1;
}

static void ram_monitor(struct observer *o) {
    o->trace_tid=m7_config.monitor_tid;
    o->owner_pthread_bias=0;
    o->caller_kind=0;
}

static void ram_tuple(u32 *info,u32 capture,u32 slot) {
    const u32 expected[13]={0,0x4100,0,1,0x4100,0,1,0xffffffff,0xffffffff,
                            0xffffffff,0xffffffff,0,2};
    for (u32 i=0;i<13;++i) info[i]=expected[i];
    info[11]=capture;
    info[3]=info[6]=slot;
}

static int ram_same_tuple(const u32 *info,u32 capture,u32 slot) {
    u32 expected[13]; ram_tuple(expected,capture,slot);
    for (u32 i=0;i<13;++i) if (info[i]!=expected[i]) return 0;
    return 1;
}

static int ram_precondition(struct observer *o,struct ram_capture *r) {
    struct connect_owner *c=&r->owners;
    u32 desc[16],image[18],flags[2],config[6],selector,remote,remote_flag;
    if (!ram_block(o,101,c->recorder.descriptor,desc,16) || desc[0]!=c->recorder.core ||
        desc[1]!=c->recorder.manager+0x10 || desc[12]!=0x4100 || desc[13] || desc[14]!=c->recorder.slot ||
        !ram_block(o,102,desc[3],image,18) || image[4]!=(r->image_ready?0x4100:0) ||
        (r->image_ready && (!c->ram_only || c->recorder.slot)) || image[10]!=c->recorder.manager+0x10 ||
        !ram_block(o,103,c->recorder.core+0x1cc,flags,2) || ((flags[1]&255) && flags[0]!=(c->ram_only?0x200:1)) ||
        !ram_block(o,104,c->recorder.manager+0x30,config,6) || config[0] ||
        !ram_block(o,105,c->recorder.manager+0x68,&selector,1) || selector!=0xffffffff ||
        !ram_block(o,106,c->recorder.core+0x9c,&remote,1) || !remote ||
        !ram_block(o,107,remote+0x2044,&remote_flag,1) || (remote_flag&255)) return 0;
    r->image=desc[3]; r->mask=flags[0]; r->grouping=flags[1]&255;
    if (c->mode_applied) {
        u32 state[14],info[19],count,table[4],found=0;
        if (!ram_block(o,114,c->remote.core+0x268,state,14) ||
            !ram_block(o,115,c->remote.core+0x1e0,info,19) ||
            !ram_block(o,116,m7_config.bias+0x145d57c,&count,1) || count>2 ||
            !ram_block(o,117,m7_config.bias+0x145d5c4,table,4) ||
            state[0]!=1 || state[1]!=1 || state[2]!=1 || state[13]==1 ||
            info[0]!=0x4100 || info[1]>2) return 0;
        for (u32 i=0;i<count;++i) if (table[i*2]==0x4100) {
            if (++found!=1 || table[i*2+1]!=1) return 0;
        }
        if (found!=1) return 0;
    }
    return 1;
}

static void ram_input(struct observer *o,u32 stage) {
    subscription(o,0,0);
    u32 data[8]={stage,o->route[0],o->route[5],o->route[7],o->route[9],o->route[10],o->route[6],0};
    emit(o,51,data);
}

static void ram_proc(struct observer *o,u32 role,u32 tid,u32 file) {
    char path[64]="/proc/";
    unsigned char bytes[513];
    const char task[]="/task/",*suffix=file==1?"/stat":file==2?"/syscall":"/wchan";
    u32 at=append_decimal(path,6,m7_config.pid),used=0,truncated=0;
    for (u32 i=0;i<6;++i) path[at++]=task[i];
    at=append_decimal(path,at,tid);
    for (u32 i=0;;++i) { path[at++]=suffix[i]; if (!suffix[i]) break; }
    s32 fd=call(5,(u32)path,0,0,0,0,0),n=0,closed=0;
    if (fd>=0) {
        n=call(3,(u32)fd,(u32)bytes,sizeof(bytes),0,0,0);
        closed=call(6,(u32)fd,0,0,0,0,0);
        if (n>0) { used=(u32)n>512?512:(u32)n; truncated=n>512; }
    }
    for (u32 offset=0;offset<used;offset+=16) {
        u32 size=used-offset<16?used-offset:16,data[8]={role,file,offset,size};
        for (u32 i=0;i<size;++i) data[4+i/4]|=(u32)bytes[offset+i]<<((i%4)*8);
        emit(o,53,data);
    }
    u32 data[8]={role,tid,file,fd<0?(u32)fd:0,(u32)n,(u32)closed,used,truncated};
    emit(o,52,data);
}

static void ram_timeout_snapshot(struct observer *o,struct ram_capture *r,u32 index,int hit) {
    struct connect_owner *c=&r->owners;
    u32 word=0,read_ok=capture_trap_word(o,r->trap.address,&word);
    u32 trap[4]={(u32)hit,r->trap.address,word,read_ok};
    ram_words(o,204,r->trap.address,trap,4);
    ram_input(o,90+index);
    u32 tids[4]={c->rec_tid,c->remote_tid,m7_config.monitor_tid,0},thread,header[16],join[3];
    if (ram_block(o,201,c->recorder.core+0x44,&thread,1) &&
        ram_block(o,202,thread,header,16) && header[0]==m7_config.mwf_bias+0x43088 &&
        header[1]==m7_config.bias+0xa16ae1 && header[2]==c->recorder.core &&
        header[6] && header[6]<0x80000000 && header[6]!=m7_config.pid &&
        ram_block(o,203,header[5],join,3) && join[0]==0x66888866 && join[1] && join[2]==header[6])
        tids[3]=header[6];
    for (u32 role=0;role<4;++role) if (tids[role])
        for (u32 file=1;file<=3;++file) ram_proc(o,role+1,tids[role],file);
    /* Running queues are diagnostic snapshots, never an idle/cleanup permission. */
    connect_queues(o,c,4,1);
    connect_queues(o,c,4,2);
}

static void ram_wait(struct observer *o,struct ram_capture *r,u32 index) {
    struct trace_context *t=&r->owners.rec_trace;
    u32 started=now();
    for (;;) {
#if M7_RAM_PRECAPTURE
        precap_sample(o);
#endif
        int hit=capture_trap_poll(o,t,&r->trap);
        if (hit==1) {
#if M7_RAM_PRECAPTURE
            if (r->trap.address==m7_config.bias+0xa14c98) r->ready_ms=now()-o->started;
#endif
            break;
        }
        if (hit<0 || now()-started>=15000) {
            ram_timeout_snapshot(o,r,index,hit);
            retain_unresolved(o,150,index);
        }
#if M7_RAM_PRECAPTURE
        precap_wait(o,10);
#else
        sleep_ms(10);
#endif
    }
    ram_words(o,10+index,t->original[15],t->original,18);
    if (t->original[16]&0x0600fc00) retain_unresolved(o,150,10+index);
}

static void ram_restore_trap(struct observer *o,struct ram_capture *r) {
    if (!capture_trap_restore(o,&r->trap)) retain_unresolved(o,151,r->trap.address);
}

static void ram_next_trap(struct observer *o,struct ram_capture *r,u32 va,u32 word) {
    ram_restore_trap(o,r);
    if (!capture_trap_set(o,&r->trap,m7_config.bias+va,word)) retain_unresolved(o,152,va);
}

static void ram_continue(struct observer *o,struct ram_capture *r,u32 index,int detach) {
    struct trace_context *t=&r->owners.rec_trace;
    u32 checked[18],vfp[65] __attribute__((aligned(8)));
    if (trace_request(o,13,(u32)t->work) || trace_request(o,12,(u32)checked) ||
        trace_request(o,27,(u32)vfp)) retain_unresolved(o,153,index);
    for (u32 i=0;i<18;++i) if (checked[i]!=t->work[i]) retain_unresolved(o,154,i);
    for (u32 i=0;i<65;++i) if (vfp[i]!=t->vfp[i]) retain_unresolved(o,155,i);
    ram_words(o,20+index,checked[15],checked,18);
    for (u32 i=0;i<18;++i) t->original[i]=checked[i];
    t->dirty=0;
    if (detach) trace_restore(o,t);
    else if (trace_request(o,7,0)) retain_unresolved(o,156,index);
}

static int ram_redirect(struct observer *o,struct ram_capture *r) {
    struct connect_owner *c=&r->owners;
    u32 *regs=c->rec_trace.original,original[13],info[13],checked[13],image[18],flags[2],ids[2];
    if (regs[5]!=c->recorder.core || regs[13]!=regs[7]-0x18 ||
        !private_range(o,regs[7],0x1a0) ||
        !ram_block(o,31,regs[7]+0x14,original,13) ||
        !ram_block(o,108,regs[7]+0xf4,ids,1) ||
        !ram_block(o,109,regs[7]+0x19c,ids+1,1) ||
        !ram_block(o,110,r->image,image,18) ||
        !ram_block(o,111,c->recorder.core+0x1cc,flags,2)) return 0;
    u32 boundary[8]={c->ram_only,regs[0],ids[0],ids[1],flags[0],flags[1]&255,original[12],regs[8]};
    ram_words(o,118,regs[7],boundary,8);
    if (ids[0]!=(c->ram_only?0x4100:0x1000) || ids[1]!=1 || image[4] ||
        image[10]!=c->recorder.manager+0x10 || flags[0]!=(c->ram_only?0x200:1) ||
        (r->grouping && flags[0]!=r->mask) ||
        (flags[1]&255)!=r->grouping) return 0;
    if (c->ram_only) {
        if (regs[0] || !ram_same_tuple(original,original[11],c->recorder.slot)) return 0;
    } else if (original[0] || original[1]!=0x1000 ||
        !original[2] || original[2]==0xffffffff || original[3] || original[4]!=0x1000 ||
        original[5]!=original[2] || original[6] || original[10]!=0xffffffff || original[12] ||
        (c->mode_applied==1 ? (original[7]!=0x4100 || original[8] || original[9]!=1) :
            (original[7]!=0xffffffff || original[8]!=0xffffffff || original[9]!=0xffffffff))) return 0;
    r->capture=regs[8]; r->info=regs[7]+0x14;
    ram_tuple(info,r->capture,c->recorder.slot);
    for (u32 i=0;i<13;++i)
        if (call(26,5,o->trace_tid,r->info+i*4,info[i],0,0)) retain_unresolved(o,157,i);
    if (!ram_block(o,32,r->info,checked,13) || !ram_same_tuple(checked,r->capture,c->recorder.slot))
        retain_unresolved(o,158,r->info);
    ram_notice(o,2,r->capture,r->info,r->image,1,0x4100,ids[1],flags[0]);
    return 1;
}

static int ram_candidate(struct observer *o,struct ram_capture *r,u32 *candidate) {
    u32 root,pools[3],matches=0;
    if (!ram_block(o,120,m7_config.bias+0x1463800,&root,1) ||
        !ram_block(o,121,root,pools,3)) return 0;
    for (u32 i=0;i<3;++i) if (pools[i]) {
        u32 header[3],list[3];
        if (!read_mem(o,pools[i],header,12) || header[2]!=0x4100) continue;
        if (!ram_block(o,122,pools[i],header,3) || !(header[1]&255) ||
            !ram_block(o,123,pools[i]+0x70c4,list,3) || list[2]>4096) return 0;
        u32 node=list[0],previous=0,visited=0;
        while (node && visited<list[2]) {
            u32 prefix[5],tail[3];
            if (!read_mem(o,node,prefix,20) || prefix[0]!=previous) return 0;
            if (prefix[3]==r->uid && prefix[4]==r->capture) {
                if (!ram_block(o,124,node,prefix,5) || !ram_block(o,125,node+0x168,tail,3) ||
                    (tail[0]&0xffff)!=1 || tail[2]!=1 || (tail[1]&255)) return 0;
                u32 found[8]={i,pools[i],0x4100,node,r->uid,r->capture,tail[0],tail[2]};
                for (u32 k=0;k<8;++k) candidate[k]=found[k];
                ++matches;
            }
            previous=node; node=prefix[1]; ++visited;
        }
        if (node || visited!=list[2] || (visited && previous!=list[1])) return 0;
    }
    return matches==1;
}

static int ram_image(struct observer *o,struct ram_capture *r) {
    u32 *regs=r->owners.rec_trace.original,head[4],info[13],uids[3],flags,candidate[8];
    /* Sony orders original-JPEG, JPEG, RAW; RAW+JPEG adds a second stock release. */
    if (regs[0] || regs[4]!=r->owners.recorder.core || regs[13]!=regs[7]-0x88 ||
        !private_range(o,regs[7],0x29b0) || !ram_block(o,34,regs[7],head,4) || head[1]!=r->owners.recorder.slot ||
        !ram_block(o,112,regs[5],info,13) || !ram_same_tuple(info,r->capture,r->owners.recorder.slot) ||
        !ram_block(o,33,regs[7]+0x2938,uids,3) || uids[r->owners.recorder.slot]!=head[3] ||
        !ram_block(o,35,regs[7]+0x29ac,&flags,1) || (flags&0xffffff)!=0x000101) return 0;
    r->frame=regs[7]; r->uid=head[3]; r->info=regs[5];
    if (!ram_candidate(o,r,candidate)) return 0;
    for (u32 i=0;i<3;++i) if (o->owners[i].owned &&
        (o->owners[i].candidate[3]==candidate[3] ||
         (o->owners[i].candidate[1]==candidate[1] && o->owners[i].candidate[4]==candidate[4]))) return 0;
#if M7_RAM_PROBE
    if (ram_probe_burst_enabled()) {
        r->users=candidate[7];
        ram_notice(o,10,r->capture,r->uid,r->ready_ms,candidate[1],candidate[3],r->users,0);
        return !o->held_owned;
    }
#endif
#if M7_RAM_PRECAPTURE
    if (!precap_keep_source(o,r)) {
        r->users=candidate[7];
        ram_notice(o,3,r->capture,r->uid,candidate[1],candidate[3],0,0,0);
        return !o->held_owned;
    }
#endif
    ram_monitor(o);
    int ok=hold_acquire(o,candidate);
#if M7_RAM_PRECAPTURE
    /* Pre-trigger frames keep their Sony lease; pixel hashing is deferred until selection. */
    if (!o->held_owned) ok=0;
#else
    if (ok) hold_measure(o);
    if (!o->held_owned || !o->jpeg_before.valid || o->jpeg_before.width!=5472 || o->jpeg_before.height!=3648) ok=0;
#endif
    r->users=candidate[7]+1;
    connect_caller(o,&r->owners,1);
    if (ok) ram_notice(o,3,r->capture,r->uid,candidate[1],candidate[3],o->jpeg_before.length,
                       o->jpeg_before.width,o->jpeg_before.height);
    return ok;
}

static int ram_completion(struct observer *o,struct ram_capture *r) {
    u32 *regs=r->owners.rec_trace.original,info[13],msg,body[6],pairs[8],keys=0;
    if (regs[5]!=r->owners.recorder.core || regs[13]!=regs[7]-8 ||
        !ram_block(o,36,regs[7],info,13) || !ram_same_tuple(info,r->capture,r->owners.recorder.slot) ||
        !ram_block(o,37,regs[7]+0x5c,&msg,1) || !ram_block(o,38,msg,body,6) ||
        body[1]!=0x3500 || body[2]!=0x10000004 || body[3]!=4 ||
        !ram_block(o,39,body[5],pairs,8)) return 0;
    for (u32 i=0;i<4;++i) {
        u32 key=pairs[i*2],param[2],value[4],payload[13],bit;
        if (key==0x1001) bit=1;
        else if (key==0x1002) bit=2;
        else if (key==0x100f) bit=4;
        else if (key==0x10000012) bit=8;
        else return 0;
        if ((keys&bit) || !ram_block(o,60+i,pairs[i*2+1],param,2)) return 0;
        if (bit==1 && (param[0] || param[1]!=m7_config.mwf_bias+0x42cec)) return 0;
        if (bit==2 && (param[0]!=r->capture || param[1]!=m7_config.mwf_bias+0x42cf8)) return 0;
        if (bit==8 && (param[0]!=0x200 || param[1]!=m7_config.mwf_bias+0x42cf8)) return 0;
        /* ParamMap stores Struct through ParamPointer; the next pair is unrelated. */
        if (bit==4 && (param[1]!=m7_config.mwf_bias+0x42c98 ||
            !ram_block(o,65,param[0],value,4) || value[1]!=m7_config.mwf_bias+0x42d10 ||
            value[2]!=52 || value[3]!=1 || !ram_block(o,64,value[0],payload,13) ||
            !ram_same_tuple(payload,r->capture,r->owners.recorder.slot))) return 0;
        keys|=bit;
    }
    return keys==15;
}

static int ram_after(struct observer *o,struct ram_capture *r) {
    struct locked_frame f={0};
    u32 state[10],tail[3],header[3];
    int ok=0;
    ram_monitor(o);
    if (!hold_lock(o,&f,o->held_candidate,1) || !end_snapshot(o,&f,5,state) ||
        !ram_block(o,41,o->held_candidate[3]+0x168,tail,3) ||
        !ram_block(o,42,o->held_candidate[1],header,3) || state[2]+1!=r->users || state[2]!=1) goto done;
    ram_notice(o,5,r->capture,r->uid,m7_config.bias+0xa126d8,0,state[2],1,0);
    hold_hash(o,&f,2,&o->jpeg_after);
    ok=o->jpeg_before.valid && o->jpeg_after.valid && o->jpeg_before.length==o->jpeg_after.length &&
       o->jpeg_before.width==o->jpeg_after.width && o->jpeg_before.height==o->jpeg_after.height;
    for (u32 i=0;i<8;++i) if (o->jpeg_before.digest[i]!=o->jpeg_after.digest[i]) ok=0;
    hold_unlock(o,&f);
    if (state[0]==1 && (state[1]&0xffffff)==0x10001) {
        r->end_called=1;
        if (!end_register_run(o)) return 0;
    } else if (state[0] || (state[1]&0xffffff)!=1) return 0;
    ram_notice(o,6,r->capture,r->uid,o->jpeg_after.length,o->jpeg_after.width,
               o->jpeg_after.height,ok,r->end_called);
    return ok?1:2;
done:
    hold_unlock(o,&f);
    return 0;
}

static int ram_release(struct observer *o,struct ram_capture *r,int across) {
    struct locked_frame f={0};
    u32 before=0,after=0,result,state[10],tail[3],header[3];
    int equal=1;
    if (!hold_lock(o,&f,o->held_candidate,1) || !end_snapshot(o,&f,6,state) || state[0] ||
        state[1]!=1 || state[2]!=1 || state[3] ||
        !retained_state(o,o->held_candidate,5,f.mutex,&before) ||
        !ram_block(o,43,o->held_candidate[3]+0x168,tail,3)) retain_unresolved(o,165,1);
    if (across) {
        o->jpeg_after=(struct held_image){0};
        hold_hash(o,&f,3,&o->jpeg_after);
        equal=o->jpeg_before.valid && o->jpeg_after.valid &&
            o->jpeg_before.length==o->jpeg_after.length && o->jpeg_before.width==o->jpeg_after.width &&
            o->jpeg_before.height==o->jpeg_after.height;
        for (u32 i=0;i<8;++i) if (o->jpeg_before.digest[i]!=o->jpeg_after.digest[i]) equal=0;
        ram_notice(o,8,r->capture,r->uid,o->jpeg_after.length,o->jpeg_after.width,o->jpeg_after.height,equal,0);
        if (M7_RAM_COMMIT && equal) {
            o->phase=8;
            commit_write(o,&f);
            o->phase=19;
        }
    }
    if (!sony_call(o,&f.trace,3,f.pool+0x70b4,r->uid,0,&result) || result) retain_unresolved(o,165,2);
    o->held_owned=0;
    if (!retained_state(o,o->held_candidate,6,f.mutex,&after) || after || before!=1 ||
        !ram_block(o,44,o->held_candidate[3]+0x168,tail,3) || tail[2] ||
        !ram_block(o,45,f.pool,header,3) || (header[1]&255)) retain_unresolved(o,165,3);
    ram_notice(o,7,r->capture,r->uid,before,after,o->held_owned,state[3],header[1]&255);
    hold_unlock(o,&f);
    if (M7_RAM_COMMIT && across) {
        if (o->commit_status==1) commit_verify(o);
        o->phase=8;commit_result(o);
        u32 committed[8]={1,o->commit_status,o->commit_written,o->commit_read,r->uid,r->capture,0,0};
        o->phase=23;emit(o,61,committed);o->phase=19;
    }
    return equal?1:2;
}

static void ram_capture_begin(struct observer *o,struct ram_capture *r) {
    if (!ram_redirect(o,r)) retain_unresolved(o,160,1);
    ram_next_trap(o,r,0xa14c98,0x531ef240);
    ram_continue(o,r,1,0);
}

static void ram_capture_offer(struct observer *o,struct ram_capture *r) {
    if (!ram_image(o,r)) retain_unresolved(o,161,1);
    ram_next_trap(o,r,0xa146f6,0xf0069602);
    r->owners.rec_trace.work[6]=0;
    r->owners.rec_trace.work[15]=m7_config.bias+0xa153d2;
    ram_continue(o,r,2,0);
#if M7_RAM_PROBE
    if (ram_probe_burst_enabled())
        ram_notice(o,11,r->capture,r->uid,r->ready_ms,now()-o->started,
                   m7_config.bias+0xa153d2,0,o->held_owned);
#endif
}

static void ram_capture_release(struct observer *o,struct ram_capture *r) {
    u32 *regs=r->owners.rec_trace.original,uids[3];
    if (regs[0]!=r->owners.recorder.manager || regs[2]!=1 || regs[3]!=r->info ||
        !ram_block(o,113,r->frame+0x2938,uids,3) || uids[r->owners.recorder.slot]!=r->uid)
        retain_unresolved(o,162,1);
    r->owners.rec_trace.work[1]=r->frame+0x2938;
    ram_notice(o,4,r->capture,r->uid,r->frame+0x2938,r->frame,1,regs[1],r->frame+0x2938);
    ram_next_trap(o,r,0xa126d8,0x00f0f8d5);
    ram_continue(o,r,3,0);
}

static void ram_capture_complete(struct observer *o,struct ram_capture *r) {
    if (!ram_completion(o,r)) retain_unresolved(o,163,1);
    r->completion=1;
    ram_restore_trap(o,r);
}

static void ram_capture_body(struct observer *o,struct ram_capture *r) {
    if (!r->image_ready) ram_wait(o,r,2);
    ram_capture_offer(o,r);
    ram_wait(o,r,3);
    ram_capture_release(o,r);
    ram_wait(o,r,4);
    ram_capture_complete(o,r);
}

static int ram_capture_run(struct observer *o,struct connect_owner *c,struct ram_capture *deferred) {
    struct ram_capture r={0};
    r.owners=*c;
    u32 previous=o->phase,reason=1;
    int ok=0;
    o->phase=19;
    ram_notice(o,0,m7_config.bias,c->rec_tid,c->remote_tid,m7_config.monitor_tid,c->recorder.core,c->recorder.manager,c->recorder.slot);
    if (!m7_config.monitor_tid || m7_config.monitor_tid==c->rec_tid || m7_config.monitor_tid==c->remote_tid ||
        o->held_owned) goto clean;
    ram_monitor(o);
    if (!retain_preflight(o)) goto clean;
    reason=2;
    connect_caller(o,&r.owners,1);
    if (!connect_pair(o,&r.owners,3)) goto clean;
    reason=3;
    if (!ram_precondition(o,&r)) goto clean;
    ram_notice(o,1,c->source,c->destination,r.image,r.mask,r.grouping,c->rec_tid,c->remote_tid);
    ram_input(o,0);
    reason=4;
    if (!capture_trap_set(o,&r.trap,m7_config.bias+0x9fc7d8,0x0901f04f)) goto clean;
    connect_caller(o,&r.owners,2);
    trace_restore(o,&r.owners.remote_trace);
    connect_caller(o,&r.owners,1);
    if (trace_request(o,7,0)) retain_unresolved(o,159,0);
    if (!sender(o,1,1)) retain_unresolved(o,159,1);
    observe(o,m7_config.focus_ms);
    ram_input(o,1);
    r.shots=1;
    if (!sender(o,2,1)) retain_unresolved(o,159,2);
    observe(o,80);
    ram_input(o,2);
    r.buttons=release_buttons(o);
    if (!r.buttons) retain_unresolved(o,159,3);
    ram_input(o,3);
    ram_wait(o,&r,1);
    ram_capture_begin(o,&r);
    ram_capture_body(o,&r);
    ram_continue(o,&r,4,1);
    if (!connect_pair(o,&r.owners,3)) retain_unresolved(o,164,1);
    connect_release(o,&r.owners);
    int after=ram_after(o,&r);
    if (!after) retain_unresolved(o,164,2);
    ok=after==1; reason=ok?0:6;
    if (ok && deferred) {
        *deferred=r;
        connect_caller(o,c,1);
        o->phase=previous;
        return 1;
    }
    if (!ram_release(o,&r,0)) retain_unresolved(o,165,4);
clean:
    if (r.owners.rec_trace.attached || r.owners.remote_trace.attached) connect_release(o,&r.owners);
    connect_caller(o,c,1);
    ram_notice(o,9,ok,reason,r.shots,o->held_owned,!r.trap.armed,r.buttons,r.completion);
    o->phase=previous;
    return ok;
}

static int ram_capture_connected(struct observer *o,struct connect_owner *c) {
    return ram_capture_run(o,c,0);
}
