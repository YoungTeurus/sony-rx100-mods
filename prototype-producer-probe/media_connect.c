#define CONNECT_ATTEMPTS 8

struct connect_owner {
    struct create_owner recorder, remote;
    struct trace_context rec_trace, remote_trace;
    u32 rec_tid, remote_tid, registry_row, registry_slot;
    u32 wrapper, source, destination, wrapper_before[6], config_before[15], ordinary_before[16];
    u32 ordinary, created, connected, disconnected, total_attempts, attempt;
    u32 resource_before[12], accessors[5], inhibit;
    u32 mode_before[21], mode_applied, ram_only, stock_connection;
    u32 discovery_refusal[4];
};

static int ram_capture_connected(struct observer *, struct connect_owner *);

static void connect_notice(struct observer *o,u32 stage,u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g) {
    u32 data[8]={stage,a,b,c,d,e,f,g};
    emit(o,45,data);
}

static int connect_block(struct observer *o,u32 tag,u32 address,u32 *words,u32 count) {
    if (count>27 || !read_mem(o,address,words,count*4)) return 0;
    for (u32 offset=0;offset<count;offset+=5) {
        u32 data[8]={tag,address,offset};
        for (u32 i=0;i<5 && offset+i<count;++i) data[3+i]=words[offset+i];
        emit(o,46,data);
    }
    return 1;
}

static void connect_caller(struct observer *o,struct connect_owner *c,u32 who) {
    o->caller_kind=who;
    o->trace_tid=who==1?c->rec_tid:c->remote_tid;
    o->owner_pthread_bias=who==1?c->recorder.pthread_bias:c->remote.pthread_bias;
}

static int connect_discover(struct observer *o,struct connect_owner *c) {
    const char name[]="ObjCntMgr";
    u32 classes=0,found=0,row[27],head[22],route[4],thread[16],join[3];
    if (!create_find_owner(o,&c->recorder)) return 0;
    c->rec_tid=o->trace_tid;
    for (u32 entry=0;entry<50;++entry) {
        u32 address=m7_config.mwf_bias+0x4548c+entry*108,match=1,count=0;
        if (!read_mem(o,address,row,sizeof(row))) return 0;
        if (!row[0]) continue;
        for (u32 i=0;i<sizeof(name);++i) if (((unsigned char *)row)[5+i]!=name[i]) match=0;
        if (!match) continue;
        if (++classes!=1 || row[16]>10) return 0;
        for (u32 slot=0;slot<10;++slot) if (row[17+slot]) {
            for (u32 j=0;j<slot;++j) if (row[17+j]==row[17+slot]) return 0;
            count++;
            if (!read_mem(o,row[17+slot],head,sizeof(head))) return 0;
            if (head[0]!=m7_config.bias+0x1388968) continue;
            if (++found!=1 || head[17]!=0x4100) return 0;
            c->remote.core=row[17+slot]; c->registry_row=address; c->registry_slot=slot;
        }
        if (count!=row[16]) return 0;
    }
    if (classes!=1 || found!=1 || !connect_block(o,1,c->registry_row,row,27) ||
        row[17+c->registry_slot]!=c->remote.core || !connect_block(o,2,c->remote.core,head,22) ||
        !connect_block(o,3,c->remote.core+0x78,route,4) ||
        !connect_block(o,4,head[8],thread,16) || thread[0]!=m7_config.mwf_bias+0x43088 ||
        thread[1]!=m7_config.mwf_bias+0x291e1 || thread[2]!=c->remote.core ||
        !thread[6] || thread[6]>0x7fffffff || thread[6]==m7_config.pid || thread[6]==c->rec_tid ||
        !connect_block(o,5,thread[5],join,3) || join[0]!=0x66888866 || !join[1] || join[2]!=thread[6]) return 0;
    c->remote_tid=thread[6];
    if (!head[20] || head[20]==head[21]) return 0;
    for (u32 i=0;i<2;++i) {
        u32 pin[7];
        if (!connect_block(o,6+i,head[20+i],pin,7) || pin[0]!=m7_config.mwf_bias+0x42fa0 ||
            pin[1]!=6 || pin[2]!=i || pin[3] || pin[5]!=route[i*2]) return 0;
        if (pin[4]!=(c->stock_connection && i==1?c->source:0)) {
            c->discovery_refusal[0]=1; c->discovery_refusal[1]=i;
            c->discovery_refusal[2]=head[20+i]; c->discovery_refusal[3]=pin[4];
            return 0;
        }
    }
    u32 sender[2],receiver[2],sw[2],rw[3],list;
    if (!connect_block(o,8,route[2],sender,2) || sender[0]!=m7_config.mwf_bias+0x42ba8 ||
        !connect_block(o,9,route[3],receiver,2) || receiver[0]!=m7_config.mwf_bias+0x42b78 ||
        !connect_block(o,10,sender[1],sw,2) || !connect_block(o,11,receiver[1],rw,3) ||
        !sw[1] || sw[1]!=rw[2] || !connect_block(o,12,c->remote.core+0x298,&list,1) || !list) return 0;
    c->destination=head[21];
    connect_caller(o,c,2);
    int ok=retain_preflight(o);
    connect_caller(o,c,1);
    return ok;
}

static void connect_release(struct observer *o,struct connect_owner *c) {
    connect_caller(o,c,1);
    if (c->recorder.cancel_owned) create_restore_cancel(o,&c->rec_trace,&c->recorder);
    if (c->rec_trace.dirty) {
        u32 frame[34],tls[3];
        if (!create_block(o,8,c->rec_trace.original[13],frame,34) ||
            !create_block(o,40,c->recorder.tls,tls,3)) retain_unresolved(o,100,1);
        for (u32 i=0;i<34;++i) if (frame[i]!=c->recorder.frame[i]) retain_unresolved(o,100,i+2);
        for (u32 i=0;i<3;++i) if (tls[i]!=c->recorder.tls_state[i]) retain_unresolved(o,101,i);
    }
    trace_restore(o,&c->rec_trace);
    connect_caller(o,c,2);
    trace_restore(o,&c->remote_trace);
    connect_caller(o,c,1);
}

static int connect_queues(struct observer *o,struct connect_owner *c,u32 barrier,u32 who) {
    u32 owner=who==1?c->recorder.core:c->remote.core,receivers[9],mask=0,signal[2],head[10],ok=1;
    u32 count=who==1?8:9,tag=1900+barrier*1000+who*10;
    if (!connect_block(o,tag+1,owner,head,10) ||
        !connect_block(o,tag,head[2]+0x38,signal,2)) return 0;
    if (who==1) {
        u32 manager[4],enabled,route[10];
        if (!connect_block(o,1951+barrier*1000,c->recorder.manager,manager,4) || manager[0]!=owner ||
            !connect_block(o,1952+barrier*1000,owner+0x58,route,10) ||
            !connect_block(o,1956+barrier*1000,owner+0xb4,&enabled,1) || (enabled&255)!=1) return 0;
        receivers[0]=head[5]; receivers[1]=head[7];
        receivers[2]=route[1]; receivers[3]=route[5]; receivers[4]=route[9];
        for (u32 i=0;i<3;++i)
            if (!connect_block(o,1953+barrier*1000+i,manager[i+1]+0x20,&receivers[5+i],1)) return 0;
    } else {
        u32 route[14];
        if (!connect_block(o,1957+barrier*1000,owner+0x78,route,14)) return 0;
        receivers[0]=head[5]; receivers[1]=head[7];
        for (u32 i=0;i<7;++i) receivers[2+i]=route[1+i*2];
    }
    for (u32 i=0;i<count;++i) {
        u32 receiver[6],list[4];
        tag=1000+barrier*1000+who*100+i*2;
        if (!connect_block(o,tag,receivers[i],receiver,6) || receiver[0]!=m7_config.mwf_bias+0x42b78 ||
            !receiver[3] || !connect_block(o,tag+1,receiver[3],list,4)) return 0;
        if (!list[1] && !list[2] && !list[3]) mask|=1u<<i;
        else ok=0;
    }
    if (who==2) {
        u32 address,list[4];
        if (!read_mem(o,owner+0x298,&address,4) || !address ||
            !connect_block(o,1950+barrier*1000,address,list,4) || list[1] || list[2] || list[3]) ok=0;
    }
    if ((signal[1]&255) || head[9]!=0xffffffff) ok=0;
    u32 data[8]={barrier,who,who==1?c->rec_tid:c->remote_tid,owner,c->attempt,ok,mask,signal[1]&255};
    emit(o,47,data);
    return ok;
}

static int connect_state(struct observer *o,struct connect_owner *c,u32 barrier) {
    u32 desc[16],wrapper[6],source[7],dest[7],state[2],busy,config[15],ordinary[16],owner,manager,registered;
    if (!read_mem(o,c->recorder.core,&owner,4) || owner!=m7_config.bias+0x138d428 ||
        !read_mem(o,c->recorder.core+0xf0,&manager,4) || manager!=c->recorder.manager ||
        !read_mem(o,c->registry_row+0x44+c->registry_slot*4,&registered,4) || registered!=c->remote.core ||
        !read_mem(o,c->remote.core,&owner,4) || owner!=m7_config.bias+0x1388968 ||
        !connect_block(o,30,c->recorder.descriptor,desc,16) ||
        !connect_block(o,31,c->wrapper,wrapper,6) || !connect_block(o,32,c->source,source,7) ||
        !connect_block(o,33,c->destination,dest,7) || !connect_block(o,34,c->remote.core+0x268,state,2) ||
        !connect_block(o,35,manager+0x20,&busy,1) || !connect_block(o,36,manager+0x30,config,15) ||
        !connect_block(o,37,c->ordinary,ordinary,16)) return 0;
    if (desc[0]!=c->recorder.core || desc[1]!=manager+0x10 || desc[6]!=c->recorder.resource ||
        desc[9]!=c->source || desc[10]!=c->wrapper || desc[14]!=c->recorder.slot || (desc[15]&255) || (busy&255) ||
        wrapper[0]!=m7_config.bias+0x13927f0 || wrapper[1]!=c->source ||
        wrapper[2]!=c->wrapper_before[2] || (wrapper[5]&0xffffff) ||
        source[0]!=m7_config.mwf_bias+0x42fa0 || source[1]!=6 || source[2]!=c->recorder.slot || source[3]!=1 ||
        dest[0]!=m7_config.mwf_bias+0x42fa0 || dest[1]!=6 || dest[2]!=1 || dest[3]) return 0;
    for (u32 i=0;i<16;++i) if (ordinary[i]!=c->ordinary_before[i]) return 0;
    if (barrier==1 || barrier==3) return source[4]==c->destination && dest[4]==c->source &&
        wrapper[3]==c->destination && wrapper[4]==(c->stock_connection?c->wrapper_before[4]:0) && state[0]==1 &&
        (m7_config.retain_check==12 || c->mode_applied ? state[1]<=1 : !state[1]) && desc[12]==0x4100 && desc[13]==0;
    if (source[4] || dest[4] || state[0] || state[1]) return 0;
    for (u32 i=0;i<15;++i) if (config[i]!=c->config_before[i] &&
        !(c->mode_applied==1 && (c->ram_only?(i==5 || i==9):i==12) && !config[i])) return 0;
    return desc[12]==0xffffffff && desc[13]==0xffffffff;
}

static int connect_pair(struct observer *o,struct connect_owner *c,u32 barrier) {
    for (u32 attempt=1;attempt<=CONNECT_ATTEMPTS;++attempt) {
        c->attempt=attempt; c->total_attempts++;
        c->rec_trace=(struct trace_context){0}; c->remote_trace=(struct trace_context){0};
        connect_notice(o,10,barrier,attempt,0,0,0,0,0);
        connect_caller(o,c,1);
        int rec=trace_begin(o,&c->rec_trace) && create_idle(o,&c->rec_trace,&c->recorder),remote=0;
        if (rec) {
            connect_caller(o,c,2);
            remote=trace_begin(o,&c->remote_trace) && create_idle_for(o,&c->remote_trace,&c->remote,
                m7_config.bias+0x1388968,"ObjCntMgr",0x30);
        }
        if (rec && remote && connect_queues(o,c,barrier,1) && connect_queues(o,c,barrier,2) &&
            (!barrier || connect_state(o,c,barrier))) {
            u32 accessor;
            if (barrier && (!read_mem(o,c->recorder.resource+8,&accessor,4) || !accessor))
                retain_unresolved(o,114,barrier);
            connect_caller(o,c,1);
            return 1;
        }
        connect_release(o,c);
        if (attempt<CONNECT_ATTEMPTS) sleep_ms(250);
    }
    connect_notice(o,90,1,barrier,CONNECT_ATTEMPTS,0,0,0,0);
    return 0;
}

static int connect_select(struct observer *o,struct connect_owner *c) {
    u32 desc[16],pin[7],busy,mgr[4],head[22],dest[7],registered;
    if (!create_select_mode(o,&c->recorder,c->ram_only) || c->recorder.slot!=1 ||
        !connect_block(o,20,c->recorder.manager+0x30,c->config_before,15) ||
        !connect_block(o,21,c->recorder.descriptor,desc,16) || (desc[15]&255) ||
        !connect_block(o,22,desc[10],c->wrapper_before,6) ||
        !connect_block(o,23,desc[9],pin,7) || pin[0]!=m7_config.mwf_bias+0x42fa0 ||
        c->wrapper_before[3] || c->wrapper_before[4] || (c->wrapper_before[5]&0xffffff) ||
        !connect_block(o,24,c->recorder.manager+0x20,&busy,1) || (busy&255) ||
        !read_mem(o,c->recorder.manager,mgr,sizeof(mgr))) return 0;
    if (!connect_block(o,26,c->remote.core,head,22) || head[0]!=m7_config.bias+0x1388968 ||
        head[17]!=0x4100 || head[21]!=c->destination ||
        !read_mem(o,c->registry_row+0x44+c->registry_slot*4,&registered,4) || registered!=c->remote.core ||
        !connect_block(o,27,c->destination,dest,7) || dest[0]!=m7_config.mwf_bias+0x42fa0 ||
        dest[1]!=6 || dest[2]!=1 || dest[3] || dest[4] || pin[4] ||
        c->wrapper_before[0]!=m7_config.bias+0x13927f0 ||
        c->wrapper_before[1]!=desc[9] || !c->wrapper_before[2]) return 0;
    c->ordinary=mgr[1];
    if (!connect_block(o,25,c->ordinary,c->ordinary_before,16)) return 0;
    if (!connect_block(o,28,c->recorder.resource,c->resource_before,12)) return 0;
    for (u32 i=0;i<7;++i) if (c->resource_before[i]) return 0;
    c->wrapper=desc[10]; c->source=desc[9];
    return connect_state(o,c,0);
}

static int connect_owned(struct observer *o,struct connect_owner *c) {
    u32 resource[12],ids[3],accessor[10],queues[15],nqueues=0;
    const u32 bases[5]={0,0xb5,0xc5,0x97,0x1ac};
    const u32 callbacks[5]={0xa00fc5,0x9ffe75,0x9ffd8d,0x9ffca5,0x9ffbb5};
    const u32 forced[5]={0x9ffb81,0,0,0x9ffb81,0};
    struct create_owner *r=&c->recorder;
    if (!create_block(o,50,r->resource,resource,12) || resource[0] ||
        resource[1]!=(c->connected?r->core:0) || (!c->connected && resource[2]!=r->accessor) ||
        !create_block(o,51,r->descriptor+0x30,ids,3) ||
        ids[0]!=(c->connected?0xffffffff:0x4100) || ids[1]!=(c->connected?0xffffffff:0) || ids[2]!=1) return 0;
    for (u32 i=7;i<12;++i) if (resource[i]!=c->resource_before[i]) return 0;
    for (u32 i=0;i<r->prior_count;++i) if (resource[2]==r->prior_pointers[i]) return 0;
    for (u32 i=0;i<5;++i) {
        c->accessors[i]=resource[2+i];
        if (!c->connected && i) { if (c->accessors[i]) return 0; continue; }
        if (!c->accessors[i]) return 0;
        for (u32 j=0;j<i;++j) if (c->accessors[j]==c->accessors[i]) return 0;
        u32 tag=i?60+(i-1)*4:52;
        if (!create_block(o,tag,c->accessors[i],accessor,10) || accessor[0]!=m7_config.mwf_bias+0x42fb8 ||
            accessor[1]!=(i?bases[i]+c->inhibit:r->accessor_id) || accessor[2]!=(i?r->resource:r->core) ||
            accessor[3]!=m7_config.bias+callbacks[i] || accessor[4]!=(forced[i]?m7_config.bias+forced[i]:0) ||
            accessor[8] || accessor[9]!=0x2f) return 0;
        for (u32 j=0;j<3;++j) {
            u32 queue[4],address=accessor[5+j];
            for (u32 k=0;k<nqueues;++k) if (queues[k]==address) return 0;
            if (!create_block(o,tag+1+j,address,queue,4) || queue[1] || queue[2] || queue[3]) return 0;
            queues[nqueues++]=address;
        }
    }
    r->accessor=resource[2];
    r->retire_count=c->connected?5:1;
    for (u32 i=0;i<r->retire_count;++i) {
        r->retire_ids[i]=i?bases[i]+c->inhibit:r->accessor_id;
        r->retire_pointers[i]=c->accessors[i];
    }
    return 1;
}

static int connect_resource_restored(struct observer *o,struct connect_owner *c,u32 tag,u32 context) {
    u32 resource[12];
    if (!connect_block(o,tag,c->recorder.resource,resource,12)) return 0;
    for (u32 i=0;i<12;++i)
        if (resource[i]!=(i==1?context:c->resource_before[i])) return 0;
    return 1;
}

#include "media_config.c"

static int media_connect_flow(struct observer *o,int (*connected)(struct observer *,struct connect_owner *),u32 ram_only) {
    struct connect_owner c={0};
    c.ram_only=ram_only;
    struct create_owner *r=&c.recorder;
    struct trace_context *t=&c.rec_trace;
    u32 result=0,clean=1,ok=0,locked=0,accessor=0,scratch,unpublished=0,capture_ok=1;
    u32 old_media=0xffffffff,old_mmgr=0xffffffff;
    connect_notice(o,8,m7_config.bias,m7_config.mwf_bias,m7_config.mprctrl_bias,m7_config.pid,0,0,0);
    if (!connect_discover(o,&c)) {
        connect_notice(o,90,2,c.discovery_refusal[0],c.discovery_refusal[1],
            c.discovery_refusal[2],c.discovery_refusal[3],0,0);
        goto done;
    }
    connect_notice(o,0,r->core,r->manager,c.remote.core,c.rec_tid,c.remote_tid,1,CONNECT_ATTEMPTS);
    if (!connect_pair(o,&c,0)) goto done;
    o->owner_pthread_bias=r->pthread_bias;
    if (!create_cancel_state(o,t,r,0) || !sony_call(o,t,5,r->manager+0x6a0c,0,0,&result) || result) goto done;
    locked=1;
    if (!connect_select(o,&c)) goto done;
    scratch=t->original[13]-4096;
    u32 sentinel=0xffffffff;
    if (!commit_scratch(o,t,128,(unsigned char *)&sentinel,4) ||
        !sony_call(o,t,16,1,0x4100,scratch+128,&result) || result ||
        !create_block(o,6,scratch+128,&r->accessor_id,1) || !r->accessor_id || r->accessor_id==0xffffffff ||
        !commit_scratch(o,t,128,(unsigned char *)&sentinel,4) ||
        !sony_call(o,t,17,0x4100,scratch+128,0,&result) || result ||
        !create_block(o,57,scratch+128,&c.inhibit,1) || c.inhibit!=4 || !create_registry(o,t,r,0)) goto done;
    if (!sony_call4(o,t,19,r->manager,0x4100,1,r->core,&result)) goto done;
    if (!read_mem(o,r->resource+8,&accessor,4)) retain_unresolved(o,102,r->resource);
    if (result && !accessor) {
        if (!connect_state(o,&c,0) || !connect_resource_restored(o,&c,40,0) ||
            !create_registry(o,t,r,2)) retain_unresolved(o,113,result);
        goto done;
    }
    if (result || !accessor) retain_unresolved(o,103,result);
    r->accessor=accessor; c.created=1; clean=0;
    create_notice(o,6,result,1,r->resource,r->accessor_id);
    if (!create_owned(o,r,20) || !create_registry(o,t,r,1)) retain_unresolved(o,104,accessor);
    connect_notice(o,1,accessor,r->resource,r->descriptor,c.wrapper,c.source,c.destination,r->accessor_id);
    unlock_owned(o,t,6,r->manager+0x6a0c); locked=0;
    if (!sony_call(o,t,26,c.wrapper,c.destination,0,&result)) goto unstarted_connect;
    c.connected=1;
    connect_notice(o,2,accessor,c.wrapper,c.source,c.destination,0,0,0);
    connect_release(o,&c);
    if (connected) capture_ok=connected(o,&c);
    if (!connect_pair(o,&c,1)) retain_unresolved(o,106,1);
    connect_notice(o,3,accessor,c.attempt,3,0,0,0,0);
    o->owner_pthread_bias=r->pthread_bias;
    if (!create_cancel_state(o,t,r,0) || !sony_call(o,t,27,c.wrapper,0,0,&result)) retain_unresolved(o,107,27);
    c.disconnected=1;
    connect_notice(o,4,accessor,c.wrapper,c.source,c.destination,0,0,0);
    connect_release(o,&c);
    if (!connect_pair(o,&c,2)) retain_unresolved(o,108,2);
    connect_notice(o,5,accessor,c.attempt,3,0,0,0,0);
    o->owner_pthread_bias=r->pthread_bias;
    if (!create_cancel_state(o,t,r,0) || !sony_call(o,t,5,r->manager+0x6a0c,0,0,&result) || result)
        retain_unresolved(o,109,5);
    locked=1;
    if (c.mode_applied) media_config_finish(o,&c);
    if (!connect_state(o,&c,2) || !connect_owned(o,&c)) retain_unresolved(o,110,accessor);
    connect_notice(o,11,accessor,r->accessor,r->resource,r->retire_count,0,0,0);
    accessor=r->accessor;
    if (!create_registry(o,t,r,3)) retain_unresolved(o,116,accessor);
    create_restore_word(o,c.wrapper+0xc,c.destination,c.wrapper_before[3]);
    create_restore_word(o,c.wrapper+0x10,0,c.wrapper_before[4]);
retire:
    if (!sony_call(o,t,28,r->resource,0,0,&result) || result!=r->resource) retain_unresolved(o,111,28);
    connect_notice(o,6,accessor,r->resource,r->descriptor,0,0,0,0);
    if (!connect_resource_restored(o,&c,38,c.connected?r->core:0)) retain_unresolved(o,115,r->resource);
    create_restore_word(o,r->resource+4,c.connected?r->core:0,c.resource_before[1]);
    create_restore_word(o,r->descriptor+0x30,old_media,0xffffffff);
    create_restore_word(o,r->descriptor+0x34,old_mmgr,0xffffffff);
    if (!create_registry(o,t,r,2) || !connect_state(o,&c,2) || !connect_resource_restored(o,&c,39,0))
        retain_unresolved(o,112,accessor);
    r->accessor=0; c.created=0; clean=1; ok=!unpublished;
    goto done;
unstarted_connect:
    unpublished=1;
    connect_notice(o,90,3,0,26,0,0,0,0);
    if (!sony_call(o,t,5,r->manager+0x6a0c,0,0,&result) || result) retain_unresolved(o,105,5);
    locked=1;
    u32 source[7],dest[7],wrapper[6];
    if (!connect_owned(o,&c) || !connect_block(o,32,c.source,source,7) || source[4] ||
        !connect_block(o,33,c.destination,dest,7) || dest[4] ||
        !connect_block(o,31,c.wrapper,wrapper,6)) retain_unresolved(o,105,26);
    for (u32 i=0;i<6;++i) if (wrapper[i]!=c.wrapper_before[i]) retain_unresolved(o,105,i+30);
    old_media=0x4100; old_mmgr=0;
    goto retire;
done:
    connect_caller(o,&c,1);
    if (locked) unlock_owned(o,t,6,r->manager+0x6a0c);
    connect_release(o,&c);
    connect_notice(o,7,ok,clean,accessor,c.connected,c.disconnected,c.total_attempts,0);
    return ok && clean && capture_ok && !o->io_errors;
}

static int media_connect_run(struct observer *o) {
    return media_connect_flow(o,m7_config.retain_check==11 ? ram_capture_connected :
        m7_config.retain_check==12 ? media_config_roundtrip : 0,0);
}
