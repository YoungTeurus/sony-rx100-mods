#define CREATE_REGISTRY_LIMIT 512

struct create_owner {
    u32 core, manager, slot, descriptor, resource, accessor, accessor_id;
    u32 frame[34], pthread_bias, tls, tls_state[3];
    u32 cancel_owned;
    u32 prior_pointers[CREATE_REGISTRY_LIMIT], prior_count;
    u32 retire_count, retire_ids[5], retire_pointers[5];
};

static void create_notice(struct observer *o, u32 stage, u32 a, u32 b, u32 c, u32 d) {
    u32 data[8]={stage,a,b,c,d};
    emit(o,32,data);
}

static int create_block(struct observer *o, u32 tag, u32 address, u32 *out, u32 count) {
    if (!read_mem(o,address,out,count*4)) return 0;
    for (u32 offset=0;offset<count;offset+=5) {
        u32 data[8]={tag,address,offset};
        for (u32 i=0;i<5 && offset+i<count;++i) data[3+i]=out[offset+i];
        emit(o,33,data);
    }
    return 1;
}

static int create_find_owner(struct observer *o, struct create_owner *c) {
    u32 registry[5], count=0, vptr;
    if (!read_mem(o,m7_config.bias+0x145d884,registry,20)) return 0;
    for (u32 i=0;i<5;++i) if (registry[i]) { c->core=registry[i]; count++; }
    return count==1 && read_mem(o,c->core,&vptr,4) && vptr==m7_config.bias+0x138d428 &&
        read_mem(o,c->core+0xf0,&c->manager,4);
}

static int create_discover_tid(struct observer *o) {
    struct create_owner c={0};
    u32 thread_address,thread[7],join[3];
    if (!create_find_owner(o,&c) || !read_mem(o,c.core+0x20,&thread_address,4) ||
        !read_mem(o,thread_address,thread,sizeof(thread)) ||
        thread[0]!=m7_config.mwf_bias+0x43088 || thread[1]!=m7_config.mwf_bias+0x291e1 ||
        thread[2]!=c.core || !thread[6] || thread[6]>0x7fffffff || thread[6]==m7_config.pid ||
        !read_mem(o,thread[5],join,sizeof(join)) || join[0]!=0x66888866 || !join[1] || join[2]!=thread[6] ||
        (m7_config.retain_check!=11 && m7_config.monitor_tid && m7_config.monitor_tid!=thread[6])) return 0;
    o->trace_tid=thread[6];
    u32 data[8]={c.core,thread_address,thread[6],thread[5],join[1],c.manager};
    emit(o,36,data);
    return 1;
}

static int create_idle_for(struct observer *o, struct trace_context *t, struct create_owner *c,
                           u32 expected_vptr, const char *name, u32 tag) {
    u32 core[10], thread[16], join[3], signal[15], vptr;
    if (!create_block(o,1,c->core,core,10) || core[0]!=expected_vptr ||
        core[9]!=0xffffffff || !create_block(o,2,core[8],thread,16) ||
        thread[0]!=m7_config.mwf_bias+0x43088 || thread[1]!=m7_config.mwf_bias+0x291e1 ||
        thread[2]!=c->core || thread[6]!=o->trace_tid || (thread[15]&0xffff)!=tag ||
        !create_block(o,3,thread[5],join,3) || join[0]!=0x66888866 || !join[1] || join[2]!=o->trace_tid ||
        !create_block(o,4,core[2],signal,15) || !signal[14] ||
        !create_block(o,5,t->original[13],c->frame,34)) return 0;
    for (u32 i=0;i<32;++i) {
        if (((unsigned char *)(thread+7))[i]!=name[i]) return 0;
        if (!name[i]) break;
        if (i==31) return 0;
    }
    u32 pc=t->original[15], post=pc&0xfff;
    if (post!=0x144 && post!=0x146) return 0;
    c->pthread_bias=pc-(post==0x144?0xd144:0xd146);
    if (c->pthread_bias<0x10000 || c->pthread_bias>0xbe000000 || (c->pthread_bias&4095) ||
        !check_media_pins(o,pthread_code_pins,sizeof(pthread_code_pins)/sizeof(pthread_code_pins[0]),c->pthread_bias,30)) return 0;
    if (!(t->original[16]&0x20) || t->original[7]!=240 || t->original[14]!=c->pthread_bias+0x8ac9 ||
        t->original[17]!=core[2]+0xc || t->original[1]!=0x80 || t->original[3]!=0 ||
        t->original[6]!=core[2]+8 || t->original[9]!=signal[14]+4 ||
        t->original[2]!=c->frame[0] || t->original[12]!=240 ||
        (post==0x144 && t->original[0]!=t->original[17]) ||
        (post==0x146 && t->original[0]!=0 && t->original[0]!=0xfffffffc && t->original[0]!=0xfffffff5) ||
        c->frame[1]!=c->pthread_bias+0x8ac9 || c->frame[13]!=core[2] || c->frame[15]!=0xffffffff ||
        c->frame[16]!=t->original[13]+0x58 || c->frame[21]!=m7_config.mwf_bias+0x31919 ||
        c->frame[28]!=c->core || c->frame[31]!=t->original[13]+0x88 ||
        c->frame[33]!=m7_config.mwf_bias+0x296ed ||
        !read_mem(o,c->core,&vptr,4) || vptr!=core[0]) return 0;
    c->tls=join[1]+0x7c;
    if (!create_block(o,9,c->tls,c->tls_state,3) || c->tls_state[0]!=t->original[13]+0x20 ||
        c->frame[4]>3 || c->tls_state[2]!=(c->frame[4]|2) ||
        c->frame[8]!=c->pthread_bias+0x88cd || c->frame[9]!=t->original[13]+0x10) return 0;
    create_notice(o,1,c->core,c->manager,c->pthread_bias,pc);
    return 1;
}

static int create_idle(struct observer *o, struct trace_context *t, struct create_owner *c) {
    return create_idle_for(o,t,c,m7_config.bias+0x138d428,"ObjStillRecorder",0x2f);
}

static int create_select_mode(struct observer *o, struct create_owner *c,int detached_sd) {
    u32 mgr[4], config[15], desc[15], pin[7], wrapper[6], resource[5];
    const u32 expected[15]={0,0,1,0x1000,0x1000,0,0,0x1000,0x1000,0,0,
                           0xffffffff,0xffffffff,0xffffffff,0xffffffff};
    if (!read_mem(o,c->manager,mgr,16) || mgr[0]!=c->core ||
        !read_mem(o,c->manager+0x30,config,sizeof(config))) return 0;
    /* The first experiment builds a tuple from the observed ordinary-mode configuration. */
    for (u32 i=0;i<15;++i) {
        u32 value=detached_sd && (i==3 || i==4 || i==6 || i==7 || i==8 || i==10)?0xffffffff:expected[i];
        if (i!=5 && i!=9 && config[i]!=value) return 0;
    }
    if (!config[5] || config[5]==0xffffffff || config[5]!=config[9]) return 0;
    for (u32 slot=1;slot<3;++slot) {
        if (!mgr[slot+1] || !read_mem(o,mgr[slot+1],desc,sizeof(desc))) return 0;
        if (desc[0]!=c->core || desc[1]!=c->manager+0x10 || desc[14]!=slot) return 0;
        if (desc[12]!=0xffffffff || desc[13]!=0xffffffff) continue;
        if (!read_mem(o,desc[6],resource,sizeof(resource)) || !read_mem(o,desc[9],pin,sizeof(pin)) ||
            !read_mem(o,desc[10],wrapper,sizeof(wrapper))) return 0;
        if (resource[0] || resource[1] || resource[2] || resource[3] || resource[4] ||
            pin[1]!=6 || pin[2]!=slot || pin[3]!=1 || pin[4] || wrapper[1]!=desc[9] || wrapper[3]) continue;
        c->slot=slot; c->descriptor=mgr[slot+1]; c->resource=desc[6];
        create_notice(o,2,c->slot,c->descriptor,c->resource,desc[9]);
        return 1;
    }
    return 0;
}

static int create_select(struct observer *o,struct create_owner *c) {
    return create_select_mode(o,c,0);
}

static int create_registry(struct observer *o, struct trace_context *t, struct create_owner *c, u32 stage) {
    u32 result, list=0, header[4], verify[4], node, previous=0, matches=0, id_matches=0, visited=0;
    u32 retire_matches[5]={0};
    u32 reason=1, where=m7_config.mwf_bias+0x46a60, value=0, prior_unchanged=1;
    int ok=0;
    if (!sony_call(o,t,22,1,0,0,&result) || result) return 0;
    if (!read_mem(o,where,&list,4)) goto done;
    reason=2; where=list;
    if (!create_block(o,10+stage,list,header,4)) goto done;
    reason=3; value=header[3];
    if (header[3]>CREATE_REGISTRY_LIMIT) goto done;
    node=header[1];
    while (node && visited<header[3]) {
        u32 link[4], body[6], params[4], id=0, pointer=0, keys=0;
        reason=4; where=node; value=previous;
        if (!read_mem(o,node,link,16) || link[3]!=previous) goto done;
        reason=5; where=link[0]; value=0;
        if (!read_mem(o,link[0],body,24)) goto done;
        value=body[3];
        if (body[1] || body[2] || body[3]!=2) goto done;
        reason=6; where=body[5]; value=0;
        if (!read_mem(o,body[5],params,16)) goto done;
        for (u32 i=0;i<2;++i) {
            u32 param[2], key=params[i*2];
            reason=7; where=params[i*2+1]; value=key;
            if (!read_mem(o,params[i*2+1],param,8)) goto done;
            reason=8; value=param[1];
            if (key==0x1000 && param[1]==m7_config.mwf_bias+0x42cf8 && !(keys&1)) { id=param[0]; keys|=1; }
            else if (key==0x1001 && param[1]==m7_config.mwf_bias+0x42d04 && !(keys&2)) { pointer=param[0]; keys|=2; }
            else goto done;
        }
        reason=9; where=body[5]; value=keys;
        if (keys!=3) goto done;
        u32 data[8]={stage,list,node,previous,link[2],id,pointer,visited};
        emit(o,34,data);
        for (u32 i=0;i<c->retire_count && i<5;++i)
            if (id==c->retire_ids[i] && pointer==c->retire_pointers[i]) retire_matches[i]++;
        if (id==c->accessor_id) {
            if (stage==2 && !c->accessor &&
                (id_matches>=c->prior_count || c->prior_pointers[id_matches]!=pointer)) prior_unchanged=0;
            id_matches++;
            if (!stage) c->prior_pointers[c->prior_count++]=pointer;
        }
        if (id==c->accessor_id && pointer==c->accessor) matches++;
        previous=node; node=link[2]; visited++;
    }
    reason=10; where=node; value=visited;
    if (node || visited!=header[3] || previous!=header[2]) goto done;
    reason=11; where=list;
    if (!read_mem(o,list,verify,16)) goto done;
    reason=12;
    for (u32 i=0;i<4;++i) if (header[i]!=verify[i]) goto done;
    reason=13; value=matches;
    ok=stage==1 || stage==3 ? matches==1 : matches==0;
    if (stage==2 || stage==3) for (u32 i=0;i<c->retire_count && i<5;++i)
        if (retire_matches[i]!=(stage==3?1:0)) ok=0;
    if (stage==2 && !c->accessor) ok=ok && prior_unchanged && id_matches==c->prior_count;
    if (stage==1) for (u32 i=0;i<c->prior_count;++i)
        if (c->prior_pointers[i]==c->accessor) { ok=0; reason=14; value=c->accessor; }
done:
    if (!sony_call(o,t,23,0,0,0,&result) && !sony_call(o,t,23,0,0,0,&result)) retain_unresolved(o,70,stage);
    if (result) retain_unresolved(o,71,result);
    if (!ok) {
        u32 fault[8]={91,stage,reason,where,value,CREATE_REGISTRY_LIMIT,visited};
        emit(o,32,fault);
    }
    create_notice(o,stage==3?10:3+stage,ok,visited,id_matches,matches);
    return ok;
}

static int create_owned(struct observer *o, struct create_owner *c, u32 tag) {
    u32 resource[5], ids[3], accessor[10];
    if (!create_block(o,tag,c->resource,resource,5) || resource[0] || resource[1] ||
        resource[2]!=c->accessor || resource[3] || resource[4] ||
        !create_block(o,tag+1,c->descriptor+0x30,ids,3) ||
        ids[0]!=0x4100 || ids[1]!=0 || ids[2]!=c->slot ||
        !create_block(o,tag+2,c->accessor,accessor,10) ||
        accessor[0]!=m7_config.mwf_bias+0x42fb8 || accessor[1]!=c->accessor_id || accessor[2]!=c->core ||
        accessor[3]!=m7_config.bias+0xa00fc5 || accessor[4]!=m7_config.bias+0x9ffb81 ||
        accessor[8]!=0 || accessor[9]!=0x2f) return 0;
    for (u32 i=0;i<3;++i) {
        u32 queue[4];
        if (!create_block(o,tag+3+i,accessor[5+i],queue,4) || queue[1] || queue[2] || queue[3]) return 0;
    }
    return 1;
}

static void create_restore_word(struct observer *o, u32 address, u32 old, u32 value) {
    u32 current;
    if (!read_mem(o,address,&current,4) || current!=old) retain_unresolved(o,72,address);
    s32 rc=call(26,5,o->trace_tid,address,value,0,0);
    u32 read_ok=read_mem(o,address,&current,4);
    u32 data[8]={address,old,value,(u32)rc,current,read_ok};
    emit(o,35,data);
    if (rc || !read_ok || current!=value) retain_unresolved(o,73,address);
}

static int create_cancel_state(struct observer *o, struct trace_context *t,
                               struct create_owner *c, u32 stage) {
    u32 old[2]={0x4d374d50,0x4d374d50}, tls[3], result;
    u32 requested=stage ? c->tls_state[2]&1 : 1;
    u32 expected_old=stage ? 1 : c->tls_state[2]&1;
    if (!commit_scratch(o,t,192,(unsigned char *)old,sizeof(old)) ||
        !sony_call(o,t,24,requested,t->original[13]-4096+192,0,&result)) return 0;
    if (result) return 0;
    if (!stage) c->cancel_owned=1;
    if (!create_block(o,stage?46:41,t->original[13]-4096+192,old,2) ||
        old[0]!=expected_old || old[1]!=0x4d374d50) retain_unresolved(o,80,stage);
    if (!create_block(o,stage?45:43,c->tls,tls,3) ||
        tls[0]!=c->tls_state[0] || tls[1]!=c->tls_state[1] ||
        tls[2]!=(stage?c->tls_state[2]:c->tls_state[2]|1)) retain_unresolved(o,81,stage);
    u32 data[8]={stage,requested,old[0],c->tls,stage?c->tls_state[2]|1:c->tls_state[2],tls[2]};
    emit(o,37,data);
    if (stage) c->cancel_owned=0;
    return 1;
}

static void create_restore_cancel(struct observer *o, struct trace_context *t, struct create_owner *c) {
    u32 tls[3],frame[34];
    if (!create_block(o,42,t->original[13],frame,34)) retain_unresolved(o,82,0);
    for (u32 i=0;i<34;++i) if (frame[i]!=c->frame[i]) retain_unresolved(o,82,i+1);
    if (!create_block(o,44,c->tls,tls,3) || tls[0]!=c->tls_state[0] ||
        tls[1]!=c->tls_state[1] || tls[2]!=(c->tls_state[2]|1)) retain_unresolved(o,83,0);
    /* A pending cancellation belongs to the owner; do not erase it or enable unwinding in our call. */
    if (!create_cancel_state(o,t,c,1)) retain_unresolved(o,84,0);
}

static int media_create_run(struct observer *o) {
    struct create_owner c={0};
    struct trace_context t={0};
    struct route_snapshot snapshot={0};
    u32 result=0, count=0, accessor=0, scratch=0, tuple[16], expected[13], frame[34];
    int manager_owned=0, ok=0, baseline=0;
    create_notice(o,0,m7_config.bias,m7_config.mwf_bias,m7_config.mprctrl_bias,o->trace_tid);
    if (!create_find_owner(o,&c) || !trace_begin(o,&t)) goto done;
    if (!create_idle(o,&t,&c)) { create_notice(o,90,1,0,0,0); goto done; }
    o->owner_pthread_bias=c.pthread_bias;
    if (!create_cancel_state(o,&t,&c,0)) goto done;
    if (!sony_call(o,&t,5,c.manager+0x6a0c,0,0,&result) || result) goto done;
    manager_owned=1;
    u32 plan[8]={0,m7_config.bias,m7_config.pid,m7_config.bias+0x145d884,m7_config.bias+0x138d428,5,3,2};
    emit(o,30,plan);
    baseline=route_sample(o,&snapshot,&count);
    u32 sample[8]={1,0,baseline,count,snapshot.cursor};
    emit(o,30,sample);
    if (!baseline || count!=1 || !create_select(o,&c)) goto done;
    scratch=t.original[13]-4096;
    tuple[0]=0xffffffff;
    if (!commit_scratch(o,&t,128,(unsigned char *)tuple,4) ||
        !sony_call(o,&t,16,1,0x4100,scratch+128,&result) || result ||
        !create_block(o,6,scratch+128,&c.accessor_id,1) ||
        !c.accessor_id || c.accessor_id==0xffffffff || !create_registry(o,&t,&c,0)) goto done;
    if (!sony_call4(o,&t,19,c.manager,0x4100,c.slot,c.core,&result)) goto done;
    create_notice(o,6,result,c.slot,c.resource,c.accessor_id);
    if (result) goto done;
    if (!read_mem(o,c.resource+8,&accessor,4) || !accessor) retain_unresolved(o,74,c.resource);
    c.accessor=accessor;
    if (!create_owned(o,&c,20)) retain_unresolved(o,75,accessor);
    ok=create_registry(o,&t,&c,1);
    if (ok) {
        for (u32 i=0;i<16;++i) tuple[i]=0x4d374d50;
        tuple[15]=0x4100;
        ok=commit_scratch(o,&t,128,(unsigned char *)tuple,64) &&
            sony_call4(o,&t,20,c.manager,scratch+188,1,scratch+128,&result) &&
            create_block(o,7,scratch+128,tuple,16);
        const u32 wanted[13]={0,0x4100,0,0,0x4100,0,0,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0x4d374d50,2};
        for (u32 i=0;i<13;++i) expected[i]=wanted[i];
        expected[3]=expected[6]=c.slot;
        for (u32 i=0;i<13;++i) if (tuple[i]!=expected[i]) ok=0;
        if (tuple[13]!=0x4d374d50 || tuple[14]!=0x4d374d50 || tuple[15]!=0x4100) ok=0;
        create_notice(o,7,ok,tuple[12],tuple[11],c.slot);
    }
    if (!create_owned(o,&c,30)) retain_unresolved(o,76,accessor);
    /* D0 removes the registry pair and frees the accessor; its return is not a status. */
    if (!sony_call(o,&t,21,accessor,0,0,&result) && !sony_call(o,&t,21,accessor,0,0,&result))
        retain_unresolved(o,77,accessor);
    create_notice(o,8,accessor,result,0,0);
    create_restore_word(o,c.resource+8,accessor,0);
    create_restore_word(o,c.descriptor+0x30,0x4100,0xffffffff);
    create_restore_word(o,c.descriptor+0x34,0,0xffffffff);
    if (!create_registry(o,&t,&c,2)) ok=0;
    c.accessor=0;
done:
    if (manager_owned) {
        snapshot.sample=1; snapshot.cursor=0;
        int same=baseline && route_sample(o,&snapshot,&count);
        u32 sample[8]={1,1,same,count,snapshot.cursor};
        emit(o,30,sample);
        u32 finish[8]={2,snapshot.count,2};
        emit(o,30,finish);
        if (!same) ok=0;
        unlock_owned(o,&t,6,c.manager+0x6a0c);
    }
    if (c.cancel_owned) create_restore_cancel(o,&t,&c);
    if (t.dirty) {
        if (!create_block(o,8,t.original[13],frame,34)) retain_unresolved(o,78,1);
        for (u32 i=0;i<34;++i) if (frame[i]!=c.frame[i]) retain_unresolved(o,78,i+2);
        u32 tls[3];
        if (!create_block(o,40,c.tls,tls,3)) retain_unresolved(o,79,1);
        for (u32 i=0;i<3;++i) if (tls[i]!=c.tls_state[i]) retain_unresolved(o,79,i+2);
    }
    trace_restore(o,&t);
    create_notice(o,9,ok,c.slot,accessor,c.accessor);
    return ok;
}
