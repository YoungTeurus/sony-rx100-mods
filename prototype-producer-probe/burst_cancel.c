struct burst_cancel_state {
    u32 header[3],list[3],rest,mode,notify[4],image[18];
    u32 nodes[RAM_BURST_LIMIT],prefix[RAM_BURST_LIMIT][5],tail[RAM_BURST_LIMIT][3];
};

static void cancel_notice(struct observer *o,u32 stage,u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g) {
    u32 data[8]={stage,a,b,c,d,e,f,g};emit(o,65,data);
}

static int cancel_owner(struct observer *o,struct ram_capture *r,u32 stage) {
    u32 manager,slot,accessor,desc,client;
    return end_owner(o,stage,&manager,&slot,&accessor) && manager==r->owners.recorder.manager && !slot &&
        read_mem(o,manager+4,&desc,4) && read_mem(o,desc+0xc,&client,4) && client==r->image;
}

static int cancel_snapshot(struct observer *o,struct burst_frame *saved,u32 count,u32 stage,
                           u32 reserved,struct burst_cancel_state *s,const struct burst_cancel_state *before) {
    u32 pool=o->held_candidate[1],tag=300+stage*64,seen=0,previous=0,found=0;
    struct ram_capture *r=&saved[count-1].capture;
    if (!ram_block(o,tag,pool,s->header,3) || !ram_block(o,tag+1,pool+0x70c4,s->list,3) ||
        !ram_block(o,tag+2,pool+0x71c8,&s->rest,1) || !ram_block(o,tag+3,pool+0x70e8,&s->mode,1) ||
        !ram_block(o,tag+4,pool+0x71ec,s->notify,4) || !ram_block(o,tag+6,r->image,s->image,18)) return 0;
    u32 active=stage<2;
    if ((s->header[1]&255)!=active || s->header[2]!=0x4100 || s->mode!=2 ||
        s->rest!=(stage<2?reserved:0) || s->list[2]!=count+(stage?0:reserved) || s->list[2]>RAM_BURST_LIMIT ||
        s->image[1]!=(stage?0:reserved) || s->image[3] || s->image[4]!=(active?0x4100u:0u) ||
        s->image[10]!=r->owners.recorder.manager+0x10 || (s->image[11]&255) || !s->image[17]) return 0;
    for (u32 i=0;i<4;++i) if (s->notify[i]) return 0;
    if (stage) {
        if (s->header[0]!=before->header[0] || (s->header[1]&~255u)!=(before->header[1]&~255u)) return 0;
        for (u32 i=0;i<18;++i) if (i!=1 && i!=4 && s->image[i]!=before->image[i]) return 0;
    }
    u32 node=s->list[0],prior=0;
    for (u32 n=0;n<s->list[2];++n) {
        u32 *prefix=s->prefix[n],*tail=s->tail[n],index=count;
        if (!private_range(o,node,0x1ac) || (node&3) ||
            !ram_block(o,tag+10+n*4,node,prefix,5) || !ram_block(o,tag+11+n*4,node+0x168,tail,3)) return 0;
        s->nodes[n]=node;
        if (prefix[0]!=previous || !prefix[3] || prefix[3]==0xffffffff || (tail[1]&255)) return 0;
        for (u32 j=0;j<n;++j)
            if (s->nodes[j]==node || s->prefix[j][3]==prefix[3] || s->prefix[j][4]==prefix[4]) return 0;
        for (u32 i=0;i<count;++i) if (saved[i].owner.candidate[3]==node) index=i;
        if (index<count) {
            struct burst_frame *f=&saved[index];const u32 *c=f->owner.candidate;
            if ((seen&(1u<<index)) || f->owner.owned!=1 || !f->capture.completion ||
                c[0]!=o->held_candidate[0] || c[1]!=pool || c[2]!=0x4100 ||
                c[4]!=prefix[3] || c[5]!=prefix[4] || f->capture.uid!=c[4] || f->capture.capture!=c[5] ||
                tail[0]!=1 || tail[2]!=1) return 0;
            seen|=1u<<index;
            if (stage) {
                u32 old=before->list[2];
                for (u32 j=0;j<before->list[2];++j) if (before->nodes[j]==node) old=j;
                if (old==before->list[2] || old<prior) return 0;
                prior=old+1;
                for (u32 j=2;j<5;++j) if (prefix[j]!=before->prefix[old][j]) return 0;
                for (u32 j=0;j<3;++j) if (tail[j]!=before->tail[old][j]) return 0;
            }
        } else {
            u32 images[4],resources[6];
            if (stage || tail[0]!=0x100 || tail[2] ||
                !ram_block(o,tag+12+n*4,node+0x20,images,4) ||
                !ram_block(o,tag+13+n*4,node+0x194,resources,6)) return 0;
            for (u32 j=0;j<4;++j) if (images[j]) return 0;
            for (u32 j=0;j<6;++j) if (resources[j]) return 0;
            ++found;
        }
        previous=node;node=prefix[1];
    }
    if (node || previous!=s->list[1] || seen!=(1u<<count)-1 || found!=(stage?0:reserved)) return 0;
    cancel_notice(o,1,stage,count,pool,s->list[2],s->rest,1,0);
    return 1;
}

static int burst_cancel_reserved(struct observer *o,struct burst_frame *saved,u32 count) {
    struct locked_frame f={0};struct burst_cancel_state before={0},after={0};
    struct ram_capture *r=&saved[count-1].capture;
    u32 phase=o->phase,pool=o->held_candidate[1],header[3],reserved=0,result=0xffffffff,reason=1;
    int ok=0;
    o->phase=26;ram_monitor(o);
    cancel_notice(o,0,count,pool,r->image,m7_config.pid,r->owners.rec_tid,r->owners.remote_tid,m7_config.monitor_tid);
    if (!hold_lock(o,&f,o->held_candidate,1) || f.trace.original[7]!=162) goto done;
    reason=2;
    if (!ram_block(o,280,pool,header,3) || !ram_block(o,281,pool+0x71c8,&reserved,1)) goto done;
    cancel_notice(o,8,count,pool,header[1],reserved,0,0,0);
    if (!reserved) { ok=1;reason=0;goto done; }
    reason=3;
    if (reserved>RAM_BURST_LIMIT-count || !cancel_snapshot(o,saved,count,0,reserved,&before,0)) goto done;
    reason=4;
    if (!cancel_owner(o,r,1)) goto done;
    /* Both producers remain at their proven idle stops; the synchronous dispatcher owns its locks. */
    hold_unlock_mutexes(o,&f);
    reason=5;
    if (!sony_call(o,&f.trace,36,r->image,0,0,&result)) goto done;
    cancel_notice(o,2,result,r->image,reserved,0,0,0,0);
    if (result) goto done;
    session_pin_checkpoint(o,&r->owners,471);
    trace_restore(o,&f.trace);__aeabi_memclr(&f,sizeof(f));
    reason=6;
    if (!hold_lock(o,&f,o->held_candidate,1) || f.trace.original[7]!=162) goto done;
    reason=7;
    if (!cancel_snapshot(o,saved,count,1,reserved,&after,&before)) goto done;
    reason=8;
    if (!cancel_owner(o,r,1)) goto done;
    hold_unlock_mutexes(o,&f);
    reason=9;
    /* Sony leaves the cancelled count until End; only that exact, fully inventoried remainder is allowed here. */
    if (!sony_call(o,&f.trace,25,r->owners.recorder.manager,0,1,&result)) goto done;
    cancel_notice(o,4,result,r->owners.recorder.manager,0,1,0,0,0);
    if (result) goto done;
    session_pin_checkpoint(o,&r->owners,472);
    trace_restore(o,&f.trace);__aeabi_memclr(&f,sizeof(f));
    reason=10;
    if (!hold_lock(o,&f,o->held_candidate,1) || f.trace.original[7]!=162) goto done;
    reason=11;
    if (!cancel_snapshot(o,saved,count,2,reserved,&after,&before) || !cancel_owner(o,r,3)) goto done;
    ok=1;reason=0;
done:
    hold_unlock(o,&f);
    cancel_notice(o,9,ok,reserved,reason,count,pool,0,0);
    o->phase=phase;
    return ok;
}
