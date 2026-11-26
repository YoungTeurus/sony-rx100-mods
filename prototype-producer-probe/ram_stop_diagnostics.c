/* Running owners can change these observations; they never authorize cleanup. */
static int session_stop_block(struct observer *o,u32 sample,u32 tag,u32 address,u32 *out,u32 count) {
    u32 size=count*4;int mapped=0,ok=0;
    if (count && count<=32 && !(address&3) && address>=0x10000 && address<=0xc0000000-size) {
        /* This singleton is in the pinned libObj BSS, outside the heap allowlist. */
        mapped=(tag==600 || tag==605) && count==1 && address==m7_config.bias+0x1426cc4;
        if ((tag==801 || tag==821) && count==1 && address==m7_config.bias+0x145e340) mapped=1;
        if (count==4 && (((tag==660 || tag==680) && address==m7_config.mwf_bias+0x45b4c) ||
                        ((tag==661 || tag==681) && address==m7_config.mwf_bias+0x45b84))) mapped=1;
        for (u32 i=0;i<m7_config.nranges;++i)
            if (address>=m7_config.ranges[i].start && address+size<=m7_config.ranges[i].end) mapped=1;
        for (u32 i=0;i<o->nadded;++i)
            if (address>=o->added[i].start && address+size<=o->added[i].end) mapped=1;
        if (mapped) ok=call(180,(u32)o->fd,(u32)out,size,0,address,0)==(s32)size;
    }
    start_notice(o,6,sample,tag,address,count,ok,0,0);
    if (ok) for (u32 off=0;off<count;off+=5) {
        u32 data[8]={sample,tag,address+4*off};
        for (u32 i=0;i<5 && off+i<count;++i) data[3+i]=out[off+i];
        emit(o,59,data);
    }
    return ok;
}

static void session_stop_queues(struct observer *o,u32 sample,u32 role,u32 core,u32 manager) {
    u32 tag=100+40*role,head[32],words[14],receivers[9]={0},count=role==0?8:role==1?9:4;
    if (!session_stop_block(o,sample,tag,core,head,32)) return;
    session_stop_block(o,sample,tag+1,head[2]+0x38,words,2);
    receivers[0]=head[5];receivers[1]=head[7];
    if (role==0) {
        if (session_stop_block(o,sample,tag+2,core+0x58,words,10)) {
            receivers[2]=words[1];receivers[3]=words[5];receivers[4]=words[9];
        }
        u32 descriptors[4];
        if (session_stop_block(o,sample,tag+22,manager,descriptors,4))
            for (u32 i=0;i<3;++i)
                if (session_stop_block(o,sample,tag+23+i,descriptors[i+1]+0x20,words,1)) receivers[i+5]=words[0];
    } else if (role==1) {
        if (session_stop_block(o,sample,tag+2,core+0x78,words,14))
            for (u32 i=0;i<7;++i) receivers[i+2]=words[i*2+1];
    } else { receivers[2]=head[19];receivers[3]=head[20]; }
    for (u32 i=0;i<count;++i)
        if (session_stop_block(o,sample,tag+3+i*2,receivers[i],words,6) && words[0]==m7_config.mwf_bias+0x42b78)
            session_stop_block(o,sample,tag+4+i*2,words[3],words,4);
    if (role && session_stop_block(o,sample,tag+22,core+(role==1?0x298:0x358),words,1))
        session_stop_block(o,sample,tag+23,words[0]+(role==1?0:8),words,role==1?4:1);
}

enum stop_record_observation { STOP_RECORDS_COMPLETE,STOP_RECORDS_LIMIT,STOP_RECORDS_CYCLE,
                               STOP_RECORDS_READ_FAILED,STOP_RECORDS_LINKS_CHANGED };

static void session_stop_records(struct observer *o,u32 sample,u32 pool) {
    u32 list[3]={0},nodes[RAM_BURST_LIMIT],prefix[5],tail[3],node=0,previous=0,count=0;
    u32 reason=STOP_RECORDS_READ_FAILED;
    if (!session_stop_block(o,sample,33,pool+0x70c4,list,3)) goto done;
    node=list[0];reason=STOP_RECORDS_LIMIT;
    if (list[2]>RAM_BURST_LIMIT) goto done;
    for (;count<list[2];) {
        reason=STOP_RECORDS_LINKS_CHANGED;
        if (!node) goto done;
        reason=STOP_RECORDS_CYCLE;
        for (u32 n=0;n<count;++n) if (node==nodes[n]) goto done;
        reason=STOP_RECORDS_READ_FAILED;
        if (!session_stop_block(o,sample,300+2*count,node,prefix,5) ||
            !session_stop_block(o,sample,301+2*count,node+0x168,tail,3)) goto done;
        start_notice(o,12,sample,count,prefix[3],prefix[4],tail[0],tail[1],tail[2]);
        nodes[count++]=node;
        reason=STOP_RECORDS_LINKS_CHANGED;
        if (prefix[0]!=previous) goto done;
        previous=node;node=prefix[1];
    }
    reason=node || previous!=list[1]?STOP_RECORDS_LINKS_CHANGED:STOP_RECORDS_COMPLETE;
done:
    start_notice(o,10,sample,pool,list[2],count,node,reason,0);
}

static void session_stop_capture_state(struct observer *o,u32 sample,u32 core,u32 manager,u32 remote) {
    u32 managers[4],desc[17],words[32];
    int have_manager=session_stop_block(o,sample,1,manager,managers,4);
    session_stop_block(o,sample,2,manager+0x30,words,21);
    session_stop_block(o,sample,3,manager+0x69c8,words,13);
    if (session_stop_block(o,sample,4,remote+0x268,words,14))
        start_notice(o,8,sample,words[0],words[1],words[2],0,0,0);
    session_stop_block(o,sample,5,core+0xfc,words,32);
    session_stop_block(o,sample,9,core+0x1c8,words,4);
    session_stop_block(o,sample,11,remote+0x1e0,words,19);
    if (session_stop_block(o,sample,12,core+0x94,words,4))
        session_stop_block(o,sample,13,words[2]+0x2034,words,7);
    if (have_manager) for (u32 slot=0;slot<3;++slot)
        if (session_stop_block(o,sample,16+slot,managers[slot+1],desc,17) &&
            desc[0]==core && desc[1]==manager+0x10) {
            if (session_stop_block(o,sample,20+slot,desc[3],words,18))
                start_notice(o,11,sample,slot,desc[3],words[1],words[2],words[3],words[4]);
            if (session_stop_block(o,sample,24+slot,desc[9],words,7) && words[0]==m7_config.mwf_bias+0x42fa0)
                session_stop_block(o,sample,28+slot,words[4],words,7);
        }
    u32 pool=o->held_candidate[1];
    session_stop_block(o,sample,32,pool,words,3);
    session_stop_records(o,sample,pool);
    session_stop_block(o,sample,34,pool+0x71c8,words,1);
    session_stop_block(o,sample,35,pool+0x70e8,words,1);
    session_stop_block(o,sample,36,pool+0x71ec,words,4);
}

#include "ram_pending_diagnostics.c"

static void session_pin_checkpoint(struct observer *o,struct connect_owner *c,u32 sample) {
    u32 previous=o->phase;o->phase=previous==26?26:21;
    u32 descriptor,words[17],image[5],pool[3];
    start_notice(o,7,0,sample,c->recorder.core,c->recorder.manager,c->remote.core,0,0);
    if (session_stop_block(o,sample,631,c->recorder.manager+4,&descriptor,1) &&
        session_stop_block(o,sample,16,descriptor,words,17) &&
        words[0]==c->recorder.core && words[1]==c->recorder.manager+0x10) {
        if (session_stop_block(o,sample,20,words[3],image,5))
            start_notice(o,11,sample,0,words[3],image[1],image[2],image[3],image[4]);
        session_pending_pin(o,sample,1,words[9]);
        session_pin_manager(o,sample,descriptor);
    }
    session_stop_block(o,sample,32,o->held_candidate[1],pool,3);
    session_capture_pins(o,sample,c->recorder.core);
    start_notice(o,7,1,sample,c->recorder.core,c->recorder.manager,c->remote.core,0,0);
    o->phase=previous;
}

static void session_stop_checkpoint(struct observer *o,struct connect_owner *c,u32 sample) {
    u32 previous=o->phase;o->phase=21;
    start_notice(o,7,0,sample,c->recorder.core,c->recorder.manager,c->remote.core,0,0);
    session_stop_capture_state(o,sample,c->recorder.core,c->recorder.manager,c->remote.core);
    session_pending_capture(o,sample,c->recorder.core,c->recorder.manager);
    session_pending_pins(o,sample,c->recorder.core,c->recorder.manager,c->remote.core);
    session_pending_topology(o,sample);
    start_notice(o,7,1,sample,c->recorder.core,c->recorder.manager,c->remote.core,0,0);
    o->phase=previous;
}

static void session_stop_diagnostics(struct observer *o,struct start_owner *c) {
    u32 previous=o->phase;o->phase=21;
    for (u32 sample=500;sample<502;++sample) {
        u32 words[8];
        start_notice(o,7,0,sample,c->caller.core,c->caller.manager,c->remote,c->source,0);
        session_stop_capture_state(o,sample,c->caller.core,c->caller.manager,c->remote);
        session_pending_capture(o,sample,c->caller.core,c->caller.manager);
        session_pending_pins(o,sample,c->caller.core,c->caller.manager,c->remote);
        session_pending_topology(o,sample);
        session_stop_block(o,sample,6,c->source+0xa0,words,8);
        session_stop_block(o,sample,7,c->source+0x100,words,6);
        session_stop_block(o,sample,8,c->source+0x3c4,words,2);
        session_stop_queues(o,sample,0,c->caller.core,c->caller.manager);
        session_stop_queues(o,sample,1,c->remote,0);
        session_stop_queues(o,sample,2,c->source,0);
        /* The late observer keeps the first thread dump; the repeated sample compares memory. */
        if (!M7_RAM_LATE_REGISTER || sample==500)
            for (u32 role=0;role<3;++role) for (u32 file=1;file<=3;++file)
                ram_proc(o,role+1,role==0?o->trace_tid:role==1?c->remote_tid:c->source_tid,file);
        start_notice(o,7,1,sample,c->caller.core,c->caller.manager,c->remote,c->source,0);
        if (sample==500) sleep_ms(200);
    }
    o->phase=previous;
}
