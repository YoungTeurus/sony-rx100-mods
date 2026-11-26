static int unused_capture_main(void) __attribute__((unused));
#define probe_main unused_capture_main
#include "native.c"
#undef probe_main

static void source_notice(struct observer *o,u32 stage,u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g) {
    u32 data[8]={stage,a,b,c,d,e,f,g};
    emit(o,56,data);
}

static int source_block(struct observer *o,u32 sample,u32 tag,u32 address,u32 *out,u32 count) {
    int ok;
    if (!count || count>32) return 0;
    if ((tag==50 && address==m7_config.bias+0x145d900 && count==16) ||
        (tag==51 && address==m7_config.bias+0x145d954 && count==1)) {
        o->reads++;
        ok=call(180,(u32)o->fd,(u32)out,count*4,0,address,0)==(s32)count*4;
        if (!ok) o->read_errors++;
    } else ok=read_mem(o,address,out,count*4);
    if (!ok) {
        source_notice(o,90,sample,tag,address,count,0,0,0);
        return 0;
    }
    for (u32 offset=0;offset<count;offset+=5) {
        u32 data[8]={sample,tag,address+4*offset};
        for (u32 i=0;i<5 && offset+i<count;++i) data[3+i]=out[offset+i];
        emit(o,57,data);
    }
    return 1;
}

static int source_class(const u32 *row,const char *name) {
    const unsigned char *bytes=(const unsigned char *)row;
    if (!row[0]) return 0;
    for (u32 i=0;i<32;++i) {
        if (bytes[5+i]!=(unsigned char)name[i]) return 0;
        if (!name[i]) return 1;
    }
    return 0;
}

static int source_owner(struct observer *o,u32 sample,u32 tag,const u32 *head) {
    u32 thread[16],join[3];
    return source_block(o,sample,tag+1,head[8],thread,16) &&
        source_block(o,sample,tag+2,thread[5],join,3);
}

static int source_pin(struct observer *o,u32 sample,u32 tag,u32 address,u32 sender_address,u32 receiver_address) {
    u32 pin[7],peer[7],sender_data[2],receiver_data[2],wrapper[3];
    if (!source_block(o,sample,tag,address,pin,7) ||
        !source_block(o,sample,tag+1,sender_address,sender_data,2) ||
        !source_block(o,sample,tag+2,receiver_address,receiver_data,2) ||
        !source_block(o,sample,tag+3,sender_data[1],wrapper,2) ||
        !source_block(o,sample,tag+4,receiver_data[1],wrapper,3)) return 0;
    return !pin[4] || source_block(o,sample,tag+5,pin[4],peer,7);
}

static int source_sample(struct observer *o,u32 sample,u32 *selected) {
    u32 row[27],sources[10]={0},receivers[10]={0},array[16],classes[2]={0},count[2]={0};
    u32 source=0,remote=0,source_head[32]={0},remote_head[32]={0},source_tag=0,remote_tag=0;
    for (u32 entry=0;entry<50;++entry) {
        if (!source_block(o,sample,entry,m7_config.mwf_bias+0x4548c+entry*108,row,27)) return 0;
        int which=source_class(row,"ObjMedia") ? 0 : source_class(row,"ObjCntMgr") ? 1 : -1;
        if (which<0) continue;
        if (++classes[which]!=1 || row[16]>10) return 0;
        for (u32 i=0;i<10;++i) {
            if (which) receivers[i]=row[17+i]; else sources[i]=row[17+i];
            if (row[17+i]) count[which]++;
        }
        if (count[which]!=row[16]) return 0;
    }
    if (classes[0]!=1 || classes[1]!=1 || !source_block(o,sample,50,m7_config.bias+0x145d900,array,16) ||
        !source_block(o,sample,51,m7_config.bias+0x145d954,row,1)) return 0;
    for (u32 which=0;which<2;++which) for (u32 i=0;i<10;++i) {
        u32 address=which ? receivers[i] : sources[i],head[32],tag=100+100*which+i*10;
        if (!address) continue;
        if (!source_block(o,sample,tag,address,head,32)) return 0;
        if (!which && head[30]==0x4100) {
            if (source) return 0;
            source=address;source_tag=tag;
            for (u32 n=0;n<32;++n) source_head[n]=head[n];
        }
        if (which && head[0]==m7_config.bias+0x1388968) {
            if (remote) return 0;
            remote=address;remote_tag=tag;
            for (u32 n=0;n<32;++n) remote_head[n]=head[n];
        }
    }
    u32 fields[32],routes[2];
    if (source) {
        if (!source_owner(o,sample,source_tag,source_head) ||
            !source_block(o,sample,source_tag+3,source+0xa0,fields,8) ||
            !source_block(o,sample,source_tag+4,source+0x100,fields,6) ||
            !source_block(o,sample,source_tag+5,source+0x130,fields,19) ||
            !source_block(o,sample,source_tag+6,source+0x1d8,fields,2) ||
            !source_block(o,sample,source_tag+7,source+0x220,fields,12) ||
            !source_block(o,sample,source_tag+8,source+0x2f8,fields,1) ||
            !source_block(o,sample,source_tag+9,source+0x3c8,fields,2)) return 0;
        for (u32 i=0;i<2;++i)
            if (!source_pin(o,sample,400+i*10,source_head[21+i],source_head[17+i],source_head[19+i])) return 0;
        if (source_head[23]) {
            if (!source_block(o,sample,430,source_head[23],fields,6)) return 0;
            if (fields[5] && !source_block(o,sample,432,fields[5],fields,8)) return 0;
        }
        if (!source_block(o,sample,431,source+0x80,fields,2)) return 0;
        if (!source_block(o,sample,433,source+0x350,fields,3)) return 0;
    }
    if (remote) {
        if (!source_owner(o,sample,remote_tag,remote_head) ||
            !source_block(o,sample,remote_tag+3,remote+0x98,routes,2) ||
            !source_block(o,sample,remote_tag+4,remote+0x1e0,fields,19) ||
            !source_block(o,sample,remote_tag+5,remote+0x268,fields,3) ||
            !source_block(o,sample,remote_tag+6,remote+0x29c,fields,1) ||
            !source_pin(o,sample,420,remote_head[26],routes[0],routes[1])) return 0;
    }
    source_notice(o,1,sample,count[0],count[1],source,remote,0,0);
    if (selected) { selected[0]=source;selected[1]=remote; }
    return 1;
}

/* S1 wakes the existing capture route. Pool sampling would retain the entire capture payload. */
static int source_s1(struct observer *o,u32 pressed) {
    s32 pid=call(2,0,0,0,0,0,0);
    if (!pid) { child_exec(1,pressed);return 0; }
    u32 status=0xffffffff,elapsed=0,killed=0,reaped=0;
    if (pid>0) while (elapsed<1800) {
        s32 rc=call(114,(u32)pid,(u32)&status,1,0,0,0);
        if (rc==pid) { reaped=1;break; }
        if (rc<0 && rc!=-4) break;
        sleep_ms(5);elapsed+=5;
        if (elapsed==1500) { call(37,(u32)pid,9,0,0,0,0);killed=1; }
    }
    u32 data[8]={1,pressed,(u32)pid,status,killed,reaped,elapsed,0};
    emit(o,5,data);
    return pid>0 && reaped && !killed && !status;
}

#ifndef SOURCE_ENTRY
#define SOURCE_ENTRY probe_main
#endif
int SOURCE_ENTRY(void) {
    struct observer o={0};
    if (m7_config.magic!=0x3143504d || m7_config.version!=6 || !m7_config.token ||
        !m7_config.pid || m7_config.pid>0x7fffffff || m7_config.retain_check!=13 ||
        m7_config.diagnose_only || m7_config.monitor_tid || m7_config.mpr_bias || m7_config.mprctrl_bias ||
        m7_config.bias<0x10000 || m7_config.bias>0xbe000000 || (m7_config.bias&4095) ||
        m7_config.mwf_bias<0x10000 || m7_config.mwf_bias>0xbe000000 || (m7_config.mwf_bias&4095) ||
        !m7_config.nranges || m7_config.nranges>MAX_RANGES) return 2;
    for (u32 i=0;i<m7_config.nranges;++i)
        if (m7_config.ranges[i].start<0x10000 || m7_config.ranges[i].end>0xc0000000 ||
            m7_config.ranges[i].start>=m7_config.ranges[i].end) return 2;
    u32 action[5]={1,0,0,0,0};
    if (call(174,13,(u32)action,0,8,0,0) || call(174,1,(u32)action,0,8,0,0)) return 3;
    call(66,0,0,0,0,0,0);
    o.started=now();
    if (!o.started) return 4;
    char path[32];proc_path(path,0);
    o.fd=call(5,(u32)path,0,0,0,0,0);
    if (o.fd<0) return 5;
    int ready=subscription(&o,1,1);
    if (!ready && inactive_route(&o)) {
        u32 progress[8]={5,200,2000};emit(&o,4,progress);
        int pressed=source_s1(&o,1);
        if (pressed) sleep_ms(200);
        int released=source_s1(&o,0);
        if (pressed && released) { sleep_ms(2000);ready=wait_for_subscription(&o); }
    }
    int ok=0;
    if (ready) {
        phase(&o,21);
        source_notice(&o,0,m7_config.bias,m7_config.mwf_bias,m7_config.pid,50,16,2,0);
        ok=source_sample(&o,0,0);
        if (ok) { sleep_ms(20);ok=source_sample(&o,1,0); }
        source_notice(&o,2,ok,0,0,0,0,0,0);
    }
    int clear=subscription(&o,1,1);
    u32 final[8]={ok && clear && !o.io_errors ? 0 : 7,o.reads,o.read_errors,0,0,o.io_errors,clear,0};
    emit(&o,9,final);
    call(6,(u32)o.fd,0,0,0,0,0);
    return final[0] || o.io_errors ? 7 : 0;
}
