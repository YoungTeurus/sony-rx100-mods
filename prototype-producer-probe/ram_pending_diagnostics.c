/* These bounded observations do not authorize cancellation, End, or cleanup. */
enum pending_observation { PENDING_COMPLETE, PENDING_LIMIT, PENDING_CYCLE,
    PENDING_READ_FAILED, PENDING_CHANGED, PENDING_IDENTITY, PENDING_NOT_FOUND, PENDING_SUMMARY };

static void session_pending_message(struct observer *o,u32 sample,u32 tag,u32 role,
                                    u32 index,u32 body,u32 functions) {
    u32 head[6]={0},entries[16],param[4],info[13],flags=0,capture=0xffffffff;
    if (functions!=m7_config.mwf_bias+0x42bf0 ||
        !session_stop_block(o,sample,tag,body,head,6)) goto done;
    flags=1;
    if (!head[3] || head[3]>8 ||
        !session_stop_block(o,sample,tag+1,head[5],entries,head[3]*2)) goto done;
    for (u32 i=1;i<head[3];++i) if (entries[2*i]<=entries[2*i-2]) goto done;
    flags|=2;
    for (u32 i=0;i<head[3];++i) if (entries[2*i]==0x100f) {
        if (!session_stop_block(o,sample,tag+2,entries[2*i+1],param,4)) goto done;
        if (param[1]==m7_config.mwf_bias+0x42c98 &&
            !session_stop_block(o,sample,tag+3,param[0],param,4)) goto done;
        if (param[1]!=m7_config.mwf_bias+0x42d10 || param[2]!=52 || param[3]!=1 ||
            !session_stop_block(o,sample,tag+5,param[0],info,13)) goto done;
        flags|=4;capture=info[11];
        break;
    }
done:
    start_notice(o,13,sample,role,index,head[1],head[2],capture,flags);
}

static void session_pending_list(struct observer *o,u32 sample,u32 role,u32 address,
                                 const u32 *header,u32 delayed) {
    u32 count=header[2],node=header[0],prior=0,seen[RAM_BURST_LIMIT],observed=0;
    u32 words[4],again[3],reason=PENDING_LIMIT,base=role?500:1400;
    if (count>RAM_BURST_LIMIT) goto done;
    for (;observed<count;) {
        reason=PENDING_CHANGED;
        if (!node) goto done;
        reason=PENDING_CYCLE;
        for (u32 j=0;j<observed;++j) if (seen[j]==node) goto done;
        reason=PENDING_READ_FAILED;
        u32 tag=base+observed*8;
        if (!session_stop_block(o,sample,tag,node,words,4)) goto done;
        reason=PENDING_CHANGED;
        if (words[role?3:0]!=prior) goto done;
        session_pending_message(o,sample,tag+1,role,observed,words[role?0:2],words[role?1:3]);
        seen[observed++]=node;prior=node;node=words[role?2:1];
    }
    reason=PENDING_CHANGED;
    if (node || prior!=header[1]) goto done;
    reason=PENDING_READ_FAILED;
    if (!session_stop_block(o,sample,role?568:468,address,again,3)) goto done;
    reason=PENDING_CHANGED;
    for (u32 i=0;i<3;++i) if (again[i]!=header[i]) goto done;
    reason=PENDING_COMPLETE;
done:
    start_notice(o,14,sample,role,count,observed,node,reason,delayed);
}

static void session_pending_worker(struct observer *o,u32 sample,u32 core) {
    u32 roots[5],thread[16],receiver[12],list[4],handler[18],signal[16];
    u32 mask=0,tid=0,count=0xffffffff,handler_pending=0xffffffff,resource_pending=0xffffffff;
    if (!session_stop_block(o,sample,450,core+0x44,roots,5)) goto done;
    if (session_stop_block(o,sample,451,roots[0],thread,16) &&
        thread[0]==m7_config.mwf_bias+0x43088 && thread[1]==m7_config.bias+0xa16ae1 &&
        thread[2]==core && (thread[15]&0xffff)==0x2f && thread[6] && thread[6]<0x80000000) {
        tid=thread[6];mask|=1;
    }
    if (session_stop_block(o,sample,452,roots[2],receiver,12) &&
        receiver[0]==m7_config.mwf_bias+0x42b78 && receiver[11]==roots[3] &&
        session_stop_block(o,sample,453,receiver[3],list,4) && list[0]==m7_config.mwf_bias+0x430c8) {
        count=list[3];mask|=2;
        session_pending_list(o,sample,1,receiver[3]+4,list+1,0);
    }
    if (session_stop_block(o,sample,454,roots[3],handler,18) &&
        handler[0]==m7_config.bias+0x1392800 && handler[2]==m7_config.mwf_bias+0x43070) {
        handler_pending=handler[17]&255;mask|=4;
    }
    if (session_stop_block(o,sample,455,roots[4],signal,16) && signal[0]==m7_config.mwf_bias+0x43070) {
        resource_pending=signal[15]&255;mask|=8;
    }
done:
    /* Neither pending byte nor an empty receiver identifies the current worker call. */
    start_notice(o,15,sample,tid,count,handler_pending,resource_pending,mask,0);
    if (tid) { ram_proc(o,4,tid,1);ram_proc(o,4,tid,3); }
}

static void session_pending_capture(struct observer *o,u32 sample,u32 core,u32 manager) {
    u32 state[12],words[13];
    if (session_stop_block(o,sample,400,core+0x20c,state,12)) {
        session_pending_list(o,sample,0,core+0x20c,state,state[3]);
        if (state[3] && state[7]) session_stop_block(o,sample,469,state[7],words,13);
    }
    session_stop_block(o,sample,470,manager+0x6a5c,words,1);
    session_pending_worker(o,sample,core);
}

static int session_pending_status(struct observer *o,u32 sample,u32 tag,u32 address,u32 *body) {
    return session_stop_block(o,sample,tag,address,body,15) &&
        body[0]==m7_config.mwf_bias+0x42ff8 && body[8]==m7_config.bias+0x3c1419;
}

static void session_pending_pin(struct observer *o,u32 sample,u32 role,u32 pin) {
    u32 words[16],config[4],body[15],bits[2],nodes[8],address=0,id=0,mask=0;
    u32 status=0xffffffff,pending=0xffffffff,registered=0xffffffff;
    if (!session_stop_block(o,sample,610+role*4,pin,words,16) ||
        words[0]!=m7_config.mwf_bias+0x42fa0) goto done;
    pending=words[15];mask|=1;
    if (!session_stop_block(o,sample,611+role*4,words[6],config,4) ||
        config[0]!=m7_config.mwf_bias+0x42fe0 || config[1]!=m7_config.mwf_bias+0x43010) goto done;
    address=config[2];id=config[3];mask|=2;
    if (!session_pending_status(o,sample,612+role*4,address,body)) goto done;
    status=body[12];mask|=4;
    if (!id || id>=body[10] || id>256) goto done;
    u32 node=body[13],index=(id-1)/32;
    for (u32 i=0;i<=index;++i) {
        if (!node) goto done;
        for (u32 j=0;j<i;++j) if (nodes[j]==node) goto done;
        nodes[i]=node;
        if (!session_stop_block(o,sample,1300+role*8+i,node,bits,2)) goto done;
        node=bits[1];
    }
    registered=(bits[0]>>((id-1)%32))&1;mask|=8;
done:
    start_notice(o,18,sample,role,pin,address,id,status,pending);
    start_notice(o,19,sample,role,mask,registered,0,0,0);
}

#include "ram_pin_lifecycle.c"
#include "ram_camera_state.c"
#include "ram_capture_wait_state.c"

static void session_pending_pins(struct observer *o,u32 sample,u32 core,u32 manager,u32 remote) {
    u32 pointer,desc,wrapper[6];
    if (session_stop_block(o,sample,630,core+0x60,&pointer,1)) session_pending_pin(o,sample,0,pointer);
    if (session_stop_block(o,sample,631,manager+4,&desc,1)) {
        if (session_stop_block(o,sample,632,desc+0x24,&pointer,1)) session_pending_pin(o,sample,1,pointer);
        if (session_stop_block(o,sample,633,desc+0x28,&pointer,1)) session_stop_block(o,sample,634,pointer,wrapper,6);
        session_pin_manager(o,sample,desc);
    }
    if (session_stop_block(o,sample,635,remote+0x54,&pointer,1)) session_pending_pin(o,sample,2,pointer);
    session_capture_pins(o,sample,core);
    if (sample==470 || sample==500) {
        u32 camera=session_camera_state(o,sample,core);
        if (sample==470) session_capture_wait_state(o,sample,camera);
    }
}

static u32 session_pending_viewer(struct observer *o,u32 sample,u32 index,u32 tm,u32 root,u32 key,u32 *reason) {
    u32 node=root,parent=tm+0x4c,seen[16],row[6],viewer[2],store[2],body[15];
    u32 base=700+index*32,depth=0,low=0,high=0,have_low=0,have_high=0;
    for (;node && depth<16;++depth) {
        *reason=PENDING_CYCLE;
        for (u32 j=0;j<depth;++j) if (seen[j]==node) return 0;
        seen[depth]=node;
        *reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,base+depth,node,row,6)) return 0;
        *reason=PENDING_CHANGED;
        if (row[0]>1 || row[1]!=parent || (have_low && (s32)row[4]<=(s32)low) ||
            (have_high && (s32)row[4]>=(s32)high)) return 0;
        if (row[4]==key) break;
        parent=node;
        if ((s32)key<(s32)row[4]) { high=row[4];have_high=1;node=row[2]; }
        else { low=row[4];have_low=1;node=row[3]; }
    }
    *reason=node?PENDING_LIMIT:PENDING_NOT_FOUND;
    if (!node || depth==16) return 0;
    *reason=PENDING_IDENTITY;
    if (!session_stop_block(o,sample,base+16,row[5],viewer,2) || viewer[0]!=m7_config.mwf_bias+0x43028 ||
        !session_stop_block(o,sample,base+17,viewer[1],store,2) || store[0]!=m7_config.mwf_bias+0x43010 ||
        !session_pending_status(o,sample,base+18,store[1],body) || body[9]!=key) return 0;
    start_notice(o,17,sample,index,key,body[12],body[11],row[5],store[1]);
    *reason=PENDING_COMPLETE;return 1;
}

static void session_pending_topology(struct observer *o,u32 sample) {
    u32 tm=0,head[5]={0},map[6],vector[3],ids[16],again[6],count=0,observed=0;
    u32 reason=PENDING_READ_FAILED;
    if (!session_stop_block(o,sample,600,m7_config.bias+0x1426cc4,&tm,1) ||
        !session_stop_block(o,sample,601,tm,head,5)) goto done;
    reason=PENDING_IDENTITY;
    if (head[0]!=m7_config.bias+0xf00220) goto done;
    reason=PENDING_READ_FAILED;
    if (!session_stop_block(o,sample,602,tm+0x48,map,6) ||
        !session_stop_block(o,sample,603,tm+0x90,vector,3)) goto done;
    reason=PENDING_CHANGED;
    if ((vector[0]|vector[1]|vector[2])&3 || vector[1]<vector[0] || vector[2]<vector[1] ||
        (!vector[0] && (vector[1] || vector[2]))) goto done;
    count=(vector[1]-vector[0])/4;
    reason=PENDING_LIMIT;
    if (count>16 || map[5]>256) goto done;
    reason=PENDING_READ_FAILED;
    if (count && !session_stop_block(o,sample,604,vector[0],ids,count)) goto done;
    /* One detailed failure walk leaves journal space for delayed eight-frame bursts. */
    for (u32 i=0;sample==500 && i<count;++i) {
        u32 current;
        if (!session_pending_viewer(o,sample,i,tm,map[2],ids[i],&current)) { reason=current;goto done; }
        ++observed;
    }
    reason=PENDING_READ_FAILED;
    if (!session_stop_block(o,sample,605,m7_config.bias+0x1426cc4,again,1)) goto done;
    reason=PENDING_CHANGED;
    if (again[0]!=tm) goto done;
    reason=PENDING_READ_FAILED;
    if (!session_stop_block(o,sample,606,tm+0x90,again,3)) goto done;
    reason=PENDING_CHANGED;
    for (u32 i=0;i<3;++i) if (again[i]!=vector[i]) goto done;
    reason=PENDING_READ_FAILED;
    if (!session_stop_block(o,sample,607,tm+0x48,again,6)) goto done;
    reason=PENDING_CHANGED;
    for (u32 i=0;i<6;++i) if (again[i]!=map[i]) goto done;
    reason=observed==count?PENDING_COMPLETE:PENDING_SUMMARY;
done:
    start_notice(o,16,sample,tm,head[4],head[2],count,observed,reason);
}
