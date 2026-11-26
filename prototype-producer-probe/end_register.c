static void end_notice(struct observer *o, u32 stage, u32 a, u32 b, u32 c,
                       u32 d, u32 e, u32 f, u32 g) {
    u32 data[8]={stage,a,b,c,d,e,f,g};
    emit(o,38,data);
}

static int end_owner_refused(struct observer *o, u32 stage, u32 reason,
                             u32 address, u32 actual, u32 expected) {
    end_notice(o,90,stage,reason,address,actual,expected,0,0);
    return 0;
}

static int end_owner(struct observer *o, u32 stage, u32 *owner, u32 *slot_out, u32 *accessor) {
    u32 registry[5],core=0,count=0,manager,vptr,head[2],wrapper[6];
    u32 registry_address=m7_config.bias+0x145d884;
    if (!read_mem(o,registry_address,registry,sizeof(registry)))
        return end_owner_refused(o,stage,1,registry_address,0,sizeof(registry));
    for (u32 i=0;i<5;++i) if (registry[i]) { core=registry[i]; count++; }
    if (count!=1) return end_owner_refused(o,stage,2,registry_address,count,1);
    if (!read_mem(o,core,&vptr,4)) return end_owner_refused(o,stage,3,core,0,4);
    if (vptr!=m7_config.bias+0x138d428)
        return end_owner_refused(o,stage,4,core,vptr,m7_config.bias+0x138d428);
    if (!read_mem(o,core+0xf0,&manager,4)) return end_owner_refused(o,stage,5,core+0xf0,0,4);
    if (!read_mem(o,manager,&count,4)) return end_owner_refused(o,stage,6,manager,0,4);
    if (count!=core) return end_owner_refused(o,stage,7,manager,count,core);
    if (!read_mem(o,manager+0x10,head,8)) return end_owner_refused(o,stage,8,manager+0x10,0,8);
    if (head[0]!=m7_config.bias+0x138d198)
        return end_owner_refused(o,stage,9,manager+0x10,head[0],m7_config.bias+0x138d198);
    if (!read_mem(o,head[1],wrapper,sizeof(wrapper)))
        return end_owner_refused(o,stage,10,head[1],0,sizeof(wrapper));
    u32 data[8]={core,manager,vptr,manager+0x10,head[0],head[1],wrapper[0],wrapper[1]};
    emit(o,39,data);
    if (wrapper[0]!=m7_config.mwf_bias+0x42bc0)
        return end_owner_refused(o,stage,11,head[1],wrapper[0],m7_config.mwf_bias+0x42bc0);
    for (u32 i=1;i<6;++i) {
        u32 expected=i==1?0x013583cf:0;
        if (wrapper[i]!=expected) return end_owner_refused(o,stage,12,head[1]+4*i,wrapper[i],expected);
    }
    u32 matches=0,chosen=0,descriptor=0,client=0,client_words[18]={0};
    for (u32 slot=0;slot<3;++slot) {
        u32 desc,words[15];
        if (!read_mem(o,manager+4+slot*4,&desc,4))
            return end_owner_refused(o,stage,13,manager+4+slot*4,0,4);
        if (!read_mem(o,desc,words,sizeof(words))) return end_owner_refused(o,stage,13,desc,0,sizeof(words));
        if (words[12]!=o->held_candidate[2]) continue;
        if (words[0]!=core) return end_owner_refused(o,stage,14,desc,words[0],core);
        if (words[1]!=manager+0x10) return end_owner_refused(o,stage,15,desc+4,words[1],manager+0x10);
        if (words[14]!=slot) return end_owner_refused(o,stage,16,desc+0x38,words[14],slot);
        if (!read_mem(o,words[3],client_words,sizeof(client_words)))
            return end_owner_refused(o,stage,17,words[3],0,sizeof(client_words));
        matches++; chosen=slot; descriptor=desc; client=words[3];
    }
    if (matches!=1) return end_owner_refused(o,stage,18,manager+4,matches,1);
    u32 client_data[8]={stage,manager,chosen,descriptor,client,client_words[4],client_words[10],client_words[0]};
    emit(o,41,client_data);
    u32 cache[8]={stage,client,client_words[1],client_words[3],client_words[11]&255,client_words[17],0,0};
    emit(o,42,cache);
    if (client_words[10]!=manager+0x10)
        return end_owner_refused(o,stage,19,client+0x28,client_words[10],manager+0x10);
    if (!private_range(o,client_words[0],28)) return end_owner_refused(o,stage,20,client,client_words[0],28);
    if (!client_words[17]) return end_owner_refused(o,stage,21,client+0x44,0,1);
    u32 expected_media=stage==1?o->held_candidate[2]:0;
    if (client_words[4]!=expected_media)
        return end_owner_refused(o,stage,22,client+0x10,client_words[4],expected_media);
    if (stage==3) {
        if (client_words[1]) return end_owner_refused(o,stage,23,client+4,client_words[1],0);
        if (client_words[3]) return end_owner_refused(o,stage,23,client+0xc,client_words[3],0);
        if (client_words[11]&255) return end_owner_refused(o,stage,23,client+0x2c,client_words[11]&255,0);
    }
    *owner=manager; *slot_out=chosen; *accessor=manager+0x10;
    return 1;
}

static int end_snapshot(struct observer *o, struct locked_frame *f, u32 stage, u32 *state) {
    u32 prefix[5],flags[3],header[3],mode,rest,requester[4];
    const u32 *c=o->held_candidate;
    if (!o->held_owned || !read_mem(o,c[3],prefix,sizeof(prefix)) || prefix[3]!=c[4] || prefix[4]!=c[5] ||
        !read_mem(o,c[3]+0x168,flags,sizeof(flags)) || !read_mem(o,f->pool,header,sizeof(header)) ||
        header[2]!=c[2] || !read_mem(o,f->pool+0x70e8,&mode,4) ||
        !read_mem(o,f->pool+0x71c8,&rest,4) || !read_mem(o,f->pool+0x71ec,requester,sizeof(requester))) return 0;
    state[0]=header[1]&255; state[1]=flags[0]; state[2]=flags[2];
    state[3]=rest; state[4]=mode; state[5]=flags[1]&255;
    for (u32 i=0;i<4;++i) state[6+i]=requester[i];
    end_notice(o,stage,state[0],state[1],state[2],rest,mode,state[5],0);
    u32 data[8]={stage,mode,rest,requester[0],requester[1],requester[2],requester[3],0};
    emit(o,40,data);
    return (flags[0]&0xffff)==1 && flags[2]>0 && flags[2]<0x7fffffff && state[5]==0;
}

static int end_register_run(struct observer *o) {
    struct locked_frame f={0};
    u32 previous_phase=o->phase,accessor=0,manager=0,slot=0,checked=0,checked_manager=0,checked_slot=0,before[10]={0},after[10]={0},result=0xffffffff,reason=1;
    int ok=0;
    o->phase=16;
    end_notice(o,0,m7_config.bias,o->trace_tid,o->held_candidate[1],o->held_candidate[3],
               o->held_candidate[4],o->held_candidate[2],m7_config.mwf_bias);
    if (!o->held_owned) goto done;
    reason=2;
    if (!end_owner(o,1,&manager,&slot,&accessor)) goto done;
    reason=3;
    if (!hold_lock(o,&f,o->held_candidate,1)) goto done;
    reason=4;
    if (!end_snapshot(o,&f,1,before)) goto done;
    reason=5;
    if (before[0]!=1 || (before[1]&0x00ffffff)!=0x10001) goto done;
    reason=6;
    if (before[3]) goto done;
    reason=7;
    if (before[4]>3 || (before[4]==0 && before[7])) goto done;
    /* The synchronous StillPool dispatcher takes root/pool locks itself. */
    hold_unlock_mutexes(o,&f);
    reason=8;
    if (!sony_call(o,&f.trace,25,manager,slot,1,&result)) goto done;
    end_notice(o,2,result,manager,slot,1,0,0,0);
    trace_restore(o,&f.trace);
    __aeabi_memclr(&f,sizeof(f));
    reason=9;
    if (!hold_lock(o,&f,o->held_candidate,1)) goto done;
    reason=10;
    if (!end_owner(o,3,&checked_manager,&checked_slot,&checked) || checked!=accessor ||
        checked_manager!=manager || checked_slot!=slot || !end_snapshot(o,&f,3,after)) goto done;
    reason=11;
    if (result || after[0] || after[1]!=(before[1]&~0x10000u) || after[3] || after[4]!=before[4] ||
        after[2]>before[2]) goto done;
    for (u32 i=6;i<10;++i) if (before[i]!=after[i]) goto done;
    reason=0; ok=1;
done:
    hold_unlock(o,&f);
    end_notice(o,4,ok,reason,o->held_owned,0,0,0,0);
    o->phase=previous_phase;
    return ok;
}
