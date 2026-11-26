static int unused_source_main(void) __attribute__((unused));
#define SOURCE_ENTRY unused_source_main
#include "source_native.c"

#define START_POLLS 50

struct start_state {
    u32 status[8],life[6],state[2],remote[3],info[19],count,table[4];
};

struct start_owner {
    struct create_owner caller;
    u32 source,remote,source_tid,remote_tid,source_thread,remote_thread,uipc;
    u32 flags[17],resources[6];
    u32 recording_peer, allow_connected;
};

static void start_notice(struct observer *o,u32 stage,u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g) {
    u32 data[8]={stage,a,b,c,d,e,f,g};emit(o,58,data);
}

static int start_block(struct observer *o,u32 sample,u32 tag,u32 address,u32 *out,u32 count) {
    if (!count || count>32 || !read_mem(o,address,out,count*4)) return 0;
    for (u32 at=0;at<count;at+=5) {
        u32 data[8]={sample,tag,address+4*at};
        for (u32 i=0;i<5 && at+i<count;++i) data[3+i]=out[at+i];
        emit(o,59,data);
    }
    return 1;
}

static int start_thread(struct observer *o,u32 sample,u32 tag,u32 core,const u32 *head,const char *name,u32 class_id,u32 *tid) {
    u32 thread[16],join[3];
    if (!start_block(o,sample,tag,head[8],thread,16) ||
        !start_block(o,sample,tag+1,thread[5],join,3) ||
        thread[0]!=m7_config.mwf_bias+0x43088 || thread[1]!=m7_config.mwf_bias+0x291e1 ||
        thread[2]!=core || !thread[6] || thread[6]>=0x80000000 || thread[6]==m7_config.pid ||
        (thread[15]&0xffff)!=class_id || join[0]!=0x66888866 || !join[1] || join[2]!=thread[6]) return 0;
    for (u32 i=0;i<32;++i) {
        if (((unsigned char *)(thread+7))[i]!=name[i]) return 0;
        if (!name[i]) { *tid=thread[6];return 1; }
    }
    return 0;
}

static int start_pin(struct observer *o,u32 sample,u32 tag,u32 address,u32 sender,u32 receiver,u32 number,u32 peer) {
    u32 pin[7],s[2],r[2],sw[2],rw[3];
    return start_block(o,sample,tag,address,pin,7) &&
        pin[0]==m7_config.mwf_bias+0x42fa0 && pin[1]==8 && pin[2]==number && pin[3]==2 &&
        pin[4]==peer && pin[5]==sender &&
        start_block(o,sample,tag+1,sender,s,2) && s[0]==m7_config.mwf_bias+0x42ba8 &&
        start_block(o,sample,tag+2,receiver,r,2) && r[0]==m7_config.mwf_bias+0x42b78 &&
        start_block(o,sample,tag+3,s[1],sw,2) && start_block(o,sample,tag+4,r[1],rw,3) &&
        sw[0]==m7_config.mwf_bias+0x42bc0 && rw[0]==sw[0] && sw[1] && sw[1]==rw[2];
}

static int start_graph_state(struct observer *o,struct start_owner *c,u32 sample,int sd_required) {
    u32 sh[32],rh[32],routes[2],wrapper[6],callback[8],pin[7],flags[17],resources[6],state[2],type;
    u32 config[15];
    u32 source_tid=c->source_tid,remote_tid=c->remote_tid;
    const u32 sd[15]={0,0,1,0x1000,0x1000,0,0,0x1000,0x1000,0,0,
                     0xffffffff,0xffffffff,0xffffffff,0xffffffff};
    if (!start_block(o,sample,54,c->caller.manager+0x30,config,15)) return 0;
    if (sd_required) {
        for (u32 i=0;i<15;++i) if (i!=5 && i!=9 && config[i]!=sd[i]) return 0;
        if (!config[5] || config[5]==0xffffffff || config[5]!=config[9]) return 0;
    }
    if (!start_block(o,sample,20,c->source,sh,32) || !start_block(o,sample,21,c->remote,rh,32) ||
        sh[0]!=m7_config.bias+0x138dd00 || sh[30]!=0x4100 ||
        rh[0]!=m7_config.bias+0x1388968 || rh[17]!=0x4100 ||
        (sample && (sh[8]!=c->source_thread || rh[8]!=c->remote_thread)) ||
        !start_thread(o,sample,22,c->source,sh,"ObjMedia",0x31,&c->source_tid) ||
        !start_thread(o,sample,24,c->remote,rh,"ObjCntMgr",0x30,&c->remote_tid) ||
        c->source_tid==c->remote_tid || c->source_tid==o->trace_tid || c->remote_tid==o->trace_tid ||
        (sample && (c->source_tid!=source_tid || c->remote_tid!=remote_tid)) ||
        !start_block(o,sample,26,c->remote+0x98,routes,2) ||
        !start_pin(o,sample,30,sh[21],sh[17],sh[19],0,rh[26]) ||
        !start_pin(o,sample,35,sh[22],sh[18],sh[20],1,0) ||
        !start_pin(o,sample,40,rh[26],routes[0],routes[1],0,sh[21])) return 0;
    for (u32 i=0;i<2;++i)
        if (!start_block(o,sample,45+i,rh[20+i],pin,7) || pin[0]!=m7_config.mwf_bias+0x42fa0 ||
            pin[1]!=6 || pin[2]!=i || pin[3] || pin[4]!=(i?c->recording_peer:0)) return 0;
    if (!start_block(o,sample,47,sh[23],wrapper,6) || wrapper[0]!=m7_config.mwf_bias+0x42bc0 ||
        wrapper[2]!=0x318474 || wrapper[3]!=m7_config.bias+0xa41015 || wrapper[4]!=c->source ||
        !start_block(o,sample,48,wrapper[5],callback,8) || (callback[2]&4095)!=0x169 ||
        !((callback[3]>>8)&1) || callback[5]!=m7_config.mwf_bias+0x1efe5 || callback[6]!=sh[23]) return 0;
    u32 uipc=callback[2]-0x3169;
    if (uipc<0x10000 || uipc>0xbe000000 || (sample && uipc!=c->uipc)) return 0;
    c->uipc=uipc;
    if (!start_block(o,sample,49,c->source+0x21c,flags,17) ||
        !start_block(o,sample,50,c->source+0x350,resources,6) ||
        !start_block(o,sample,51,c->source+0x3c4,state,2) ||
        !start_block(o,sample,52,c->source+0x2f8,&type,1) || type!=1 ||
        !start_block(o,sample,53,c->source+0x84,&type,1) || !type) return 0;
    const unsigned char *bytes=(const unsigned char *)flags;
    if (bytes[3]>1 || bytes[0x10] || bytes[0x11] || bytes[0x26]!=1 || bytes[0x2a]!=1 ||
        bytes[0x41] || bytes[0x42]) return 0;
    if (!sample) {
        c->source_thread=sh[8];c->remote_thread=rh[8];
        for (u32 i=0;i<17;++i) c->flags[i]=flags[i];
        for (u32 i=0;i<6;++i) c->resources[i]=resources[i];
    } else {
        for (u32 i=0;i<17;++i) if (c->flags[i]!=flags[i]) return 0;
        if (sample==1 && (resources[3]!=c->resources[3] || resources[5]!=c->resources[5])) return 0;
    }
    return 1;
}

static int start_graph(struct observer *o,struct start_owner *c,u32 sample) {
    return start_graph_state(o,c,sample,1);
}

static int start_read_state(struct observer *o,struct start_owner *c,u32 sample,struct start_state *s) {
    return start_block(o,sample,0,c->source+0xa0,s->status,8) &&
        start_block(o,sample,1,c->source+0x100,s->life,6) &&
        start_block(o,sample,2,c->source+0x3c4,s->state,2) &&
        start_block(o,sample,3,c->remote+0x268,s->remote,3) &&
        start_block(o,sample,4,c->remote+0x1e0,s->info,19) &&
        start_block(o,sample,5,m7_config.bias+0x145d57c,&s->count,1) && s->count<=2 &&
        start_block(o,sample,6,m7_config.bias+0x145d5c4,s->table,4);
}

static int start_ready(const struct start_state *s,u32 active,u32 allow_connected) {
    u32 found=0;
    for (u32 i=0;i<s->count;++i) if (s->table[i*2]==0x4100) {
        if (++found!=1 || s->table[i*2+1]!=active) return 0;
    }
    if (found!=1 || s->remote[0]>(active && allow_connected?1u:0u) || s->remote[2]!=active ||
        s->status[4]!=1 || s->status[5] || s->life[2] || s->life[4] ||
        s->state[1]!=(active?8:1)) return 0;
    if (active) return !s->status[0] && s->status[1]==1 && s->status[2]==1 && s->status[3]==1 && s->status[6]==1 && !s->status[7] &&
        s->info[0]==0x4100 && s->info[1]<=2;
    return !s->status[0] && !s->status[1] && !s->status[2] && !s->status[3] && !s->status[6] && !s->status[7];
}

static int start_idle_queues(struct observer *o,struct start_owner *c,u32 sample,u32 who) {
    u32 core=who?c->remote:c->source,tag=100+who*40,head[32],signal[2],receivers[9],count=who?9:4;
    if (!start_block(o,sample,tag,core,head,32) || head[9]!=0xffffffff ||
        !start_block(o,sample,tag+1,head[2]+0x38,signal,2) || (signal[1]&255)) return 0;
    receivers[0]=head[5];receivers[1]=head[7];
    if (who) {
        u32 route[14];
        if (!start_block(o,sample,tag+2,core+0x78,route,14)) return 0;
        for (u32 i=0;i<7;++i) receivers[i+2]=route[i*2+1];
    } else { receivers[2]=head[19];receivers[3]=head[20]; }
    for (u32 i=0;i<count;++i) {
        u32 receiver[6],list[4];
        if (!start_block(o,sample,tag+3+i*2,receivers[i],receiver,6) ||
            receiver[0]!=m7_config.mwf_bias+0x42b78 || !receiver[3] ||
            !start_block(o,sample,tag+4+i*2,receiver[3],list,4) || list[1] || list[2] || list[3]) return 0;
    }
    u32 pointer,list[4];
    if (!start_block(o,sample,tag+22,core+(who?0x298:0x358),&pointer,1) || !pointer) return 0;
    if (who) return start_block(o,sample,tag+23,pointer,list,4) && !list[1] && !list[2] && !list[3];
    return start_block(o,sample,tag+23,pointer+8,list,1) && !list[0];
}

static int start_command(struct observer *o,struct start_owner *c,u32 command,u32 *returned) {
    struct trace_context t={0};
    int admitted=0;
    for (u32 attempt=1;attempt<=8;++attempt) {
        start_notice(o,2,command,attempt,0,0,0,0,0);
        if (trace_begin(o,&t) && create_idle(o,&t,&c->caller)) { admitted=1;break; }
        trace_restore(o,&t);t=(struct trace_context){0};sleep_ms(100);
    }
    if (!admitted) return 0;
    o->owner_pthread_bias=c->caller.pthread_bias;
    u32 scratch=t.original[13]-4096+256;
    u32 argv[8]={scratch+12,scratch+20,0,0x6f6d6572,0x00006574,
                 command==1?0x72617473:0x706f7473,command==1?0x74:0,0};
    int ok=commit_scratch(o,&t,256,(unsigned char *)argv,sizeof(argv)) &&
        create_block(o,60,scratch,argv,8) && create_cancel_state(o,&t,&c->caller,0);
    if (ok) ok=sony_call4(o,&t,35,2,scratch,0,0,returned);
    if (c->caller.cancel_owned) create_restore_cancel(o,&t,&c->caller);
    u32 frame[34],tls[3];
    if (t.dirty) {
        if (!create_block(o,8,t.original[13],frame,34) || !create_block(o,40,c->caller.tls,tls,3))
            retain_unresolved(o,181,command);
        for (u32 i=0;i<34;++i) if (frame[i]!=c->caller.frame[i]) retain_unresolved(o,181,i);
        for (u32 i=0;i<3;++i) if (tls[i]!=c->caller.tls_state[i]) retain_unresolved(o,182,i);
    }
    trace_restore(o,&t);
    start_notice(o,4,command,ok,*returned,0,0,0,0);
    return ok;
}

static int start_wait(struct observer *o,struct start_owner *c,u32 active,u32 base) {
    struct start_state s={0},previous={0};u32 streak=0;
    for (u32 i=0;i<START_POLLS;++i) {
        int read=start_read_state(o,c,base+i,&s);
        int ready=read && start_ready(&s,active,c->allow_connected) && start_idle_queues(o,c,base+i,0) && start_idle_queues(o,c,base+i,1);
        if (ready && streak) {
            int same=1;
            for (u32 n=0;n<sizeof(s);++n) if (((unsigned char *)&s)[n]!=((unsigned char *)&previous)[n]) same=0;
            if (!same) streak=0;
        }
        streak=ready?streak+1:0;
        if (ready) previous=s;
        start_notice(o,3,active,i,read,s.state[1],s.remote[2],streak,0);
        if (streak==2) return 1;
        sleep_ms(200);
    }
    return 0;
}

#ifndef START_ENTRY
#define START_ENTRY probe_main
#endif
int START_ENTRY(void) {
    struct observer o={0};struct start_owner c={0};struct route_snapshot route={0};
    if (m7_config.magic!=0x3143504d || m7_config.version!=6 || !m7_config.token ||
        !m7_config.pid || m7_config.pid>=0x80000000 || m7_config.retain_check!=14 ||
        m7_config.diagnose_only || m7_config.mpr_bias || m7_config.mprctrl_bias ||
        m7_config.bias<0x10000 || m7_config.bias>0xbe000000 || (m7_config.bias&4095) ||
        m7_config.mwf_bias<0x10000 || m7_config.mwf_bias>0xbe000000 || (m7_config.mwf_bias&4095) ||
        !m7_config.nranges || m7_config.nranges>MAX_RANGES || m7_config.monitor_tid>=0x80000000 ||
        m7_config.monitor_tid==m7_config.pid) return 2;
    for (u32 i=0;i<m7_config.nranges;++i) if (m7_config.ranges[i].start<0x10000 ||
        m7_config.ranges[i].end>0xc0000000 || m7_config.ranges[i].start>=m7_config.ranges[i].end) return 2;
    u32 action[5]={1,0,0,0,0};
    if (call(174,13,(u32)action,0,8,0,0) || call(174,1,(u32)action,0,8,0,0)) return 3;
    call(66,0,0,0,0,0,0);o.started=now();if (!o.started) return 4;
    char path[32];proc_path(path,0);o.fd=call(5,(u32)path,0,0,0,0,0);if (o.fd<0) return 5;
    o.caller_kind=1;
    int owner=create_discover_tid(&o) && create_find_owner(&o,&c.caller);
    int ready=subscription(&o,1,1);
    if (!ready && inactive_route(&o)) {
        u32 progress[8]={5,200,2000};emit(&o,4,progress);
        int pressed=source_s1(&o,1);if (pressed) sleep_ms(200);
        int released=source_s1(&o,0);
        if (pressed && released) { sleep_ms(2000);ready=wait_for_subscription(&o); }
    }
    phase(&o,21);
    start_notice(&o,0,m7_config.bias,m7_config.mwf_bias,m7_config.pid,o.trace_tid,START_POLLS,200,0);
    int admitted=0,started=0,inserted=0,stopped=0,restored=0;u32 returned=0,selected[2]={0},count=0;
    if (owner && ready) {
        source_notice(&o,0,m7_config.bias,m7_config.mwf_bias,m7_config.pid,50,16,2,0);
        admitted=source_sample(&o,0,selected) && selected[0] && selected[1];
        c.source=selected[0];c.remote=selected[1];
        u32 plan[8]={0,m7_config.bias,m7_config.pid,m7_config.bias+0x145d884,m7_config.bias+0x138d428,5,3,2};
        emit(&o,30,plan);
        if (admitted) admitted=route_sample(&o,&route,&count) && count==1 && start_graph(&o,&c,0);
        plan[0]=1;plan[1]=0;plan[2]=admitted;plan[3]=count;plan[4]=route.cursor;plan[5]=plan[6]=plan[7]=0;emit(&o,30,plan);
        if (admitted) admitted=check_media_pins(&o,start_code_pins,sizeof(start_code_pins)/sizeof(start_code_pins[0]),m7_config.bias,54) &&
            check_media_pins(&o,start_mwf_code_pins,sizeof(start_mwf_code_pins)/sizeof(start_mwf_code_pins[0]),m7_config.mwf_bias,56) &&
            check_media_pins(&o,start_uipc_code_pins,sizeof(start_uipc_code_pins)/sizeof(start_uipc_code_pins[0]),c.uipc,58) &&
            start_wait(&o,&c,0,0);
        start_notice(&o,1,admitted,c.source,c.remote,c.source_tid,c.remote_tid,c.uipc,0);
        if (admitted) {
            started=start_command(&o,&c,1,&returned);
            if (started) {
                inserted=start_wait(&o,&c,1,100);
                if (!start_graph(&o,&c,2)) retain_unresolved(&o,185,2);
                stopped=start_command(&o,&c,2,&returned);
                if (!stopped || !start_wait(&o,&c,0,200)) retain_unresolved(&o,183,2);
            }
            route.sample=1;route.cursor=0;
            restored=route_sample(&o,&route,&count) && count==1 && start_graph(&o,&c,1);
            plan[0]=1;plan[1]=1;plan[2]=restored;plan[3]=count;plan[4]=route.cursor;emit(&o,30,plan);
            if (restored) {
                plan[0]=2;plan[1]=route.count;plan[2]=2;plan[3]=plan[4]=0;emit(&o,30,plan);
                restored=source_sample(&o,1,selected) && selected[0]==c.source && selected[1]==c.remote;
            }
            if (!restored && started) retain_unresolved(&o,184,1);
            source_notice(&o,2,restored,0,0,0,0,0,0);
        }
    }
    int clear=subscription(&o,1,1);
    int ok=admitted && started && inserted && stopped && restored && clear && !o.io_errors;
    start_notice(&o,9,ok,admitted,started,inserted,stopped,restored,0);
    u32 final[8]={ok?0:7,o.reads,o.read_errors,0,0,o.io_errors,clear,0};emit(&o,9,final);
    call(6,(u32)o.fd,0,0,0,0,0);return final[0] || o.io_errors?7:0;
}
