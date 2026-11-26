static void mode_notice(struct observer *o,u32 stage,u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g) {
    u32 data[8]={stage,a,b,c,d,e,f,g}; emit(o,54,data);
}

static int mode_block(struct observer *o,u32 tag,u32 address,u32 *words,u32 count) {
    if (!read_mem(o,address,words,count*4)) return 0;
    for (u32 offset=0;offset<count;offset+=5) {
        u32 data[8]={tag,address,offset};
        for (u32 i=0;i<5 && offset+i<count;++i) data[3+i]=words[offset+i];
        emit(o,55,data);
    }
    return 1;
}

static int mode_snapshot(struct observer *o,struct connect_owner *c,u32 stage,u32 *config,u32 *busy,u32 *remote) {
    u32 global,count,table[4],target;
    return mode_block(o,stage*10,c->recorder.manager+0x30,config,21) &&
        mode_block(o,stage*10+1,c->recorder.manager+0x69c8,busy,1) &&
        mode_block(o,stage*10+2,c->remote.core+0x268,remote,14) &&
        mode_block(o,stage*10+3,m7_config.bias+0x145d5a4,&global,1) &&
        mode_block(o,stage*10+4,m7_config.bias+0x145d57c,&count,1) && count<=2 &&
        mode_block(o,stage*10+5,m7_config.bias+0x145d5c4,table,4) &&
        mode_block(o,stage*10+6,m7_config.bias+0x145d528,&target,1);
}

static void mode_set(struct observer *o,struct connect_owner *c,u32 stage,const u32 *values) {
    struct trace_context *t=&c->rec_trace;
    const u32 keys[4]={0x1007,0x1008,0x1009,0x101a};
    u32 scratch=t->original[13]-4096,msg=scratch+256,param=scratch+264,result,zero[4]={0};
    if (!create_cancel_state(o,t,&c->recorder,0) ||
        !commit_scratch(o,t,256,(unsigned char *)zero,sizeof(zero)) ||
        !sony_call(o,t,29,msg,0x3500,0x2003,&result)) retain_unresolved(o,170,stage);
    for (u32 i=0;i<4;++i) {
        if (!sony_call(o,t,31,param,values[i],0,&result) ||
            !sony_call(o,t,33,msg,keys[i],param,&result) ||
            !sony_call(o,t,32,param,0,0,&result)) retain_unresolved(o,171,stage*10+i);
    }
    if (!sony_call(o,t,34,c->recorder.manager,msg,0,&result)) retain_unresolved(o,172,stage);
    mode_notice(o,stage,c->recorder.manager,msg,result,values[0],values[1],values[2],values[3]);
    if (!sony_call(o,t,30,msg,0,0,&result)) retain_unresolved(o,173,stage);
    c->mode_applied=1;
    connect_release(o,c);
}

static int mode_matches(struct connect_owner *c,const u32 *config,u32 busy,const u32 *remote,int ram) {
    u32 expected[21];
    for (u32 i=0;i<21;++i) expected[i]=c->mode_before[i];
    if (c->ram_only) {
        expected[3]=expected[4]=expected[7]=expected[8]=0x4100;
        expected[5]=expected[9]=0;expected[6]=expected[10]=c->recorder.slot;
        expected[17]=ram?0x4100:c->mode_before[17];
        expected[20]=1;
    } else if (ram) {
        expected[2]=expected[19]=0;
        expected[3]=expected[4]=expected[7]=expected[17]=0x4100;
        expected[5]=0;
        expected[6]=1;
        expected[18]=0xffffffff;
    } else { expected[11]=0x4100; expected[12]=0; expected[13]=1; }
    for (u32 i=0;i<21;++i) if (config[i]!=expected[i]) return 0;
    return !(busy&0x00ffff00) && remote[0]==1 &&
        (!ram || (remote[1]==1 && remote[2]<=1 && remote[13]!=1));
}

static int mode_pending_unchanged(struct connect_owner *c,const u32 *config,u32 busy,const u32 *remote) {
    for (u32 i=0;i<21;++i) {
        u32 expected=i==17?0x4100:i==18?0xffffffff:i==19?0:i==20?c->mode_before[i]|0x100:c->mode_before[i];
        if (config[i]!=expected) return 0;
    }
    return busy<=1 && remote[0]==1 && !remote[1] && !remote[2] && !remote[13];
}

static int mode_drain(struct observer *o,struct connect_owner *c,u32 stage,int ram) {
    u32 pending_samples=0;
    for (u32 attempt=1;attempt<=8;++attempt) {
        if (!connect_pair(o,c,3)) retain_unresolved(o,174,stage);
        u32 config[21],busy,remote[14];
        if (!mode_snapshot(o,c,stage,config,&busy,remote)) retain_unresolved(o,175,stage);
        int ready=mode_matches(c,config,busy,remote,ram);
        mode_notice(o,8,stage,attempt,ready,config[6],config[10],config[13],busy);
        if (ready) { mode_notice(o,stage,1,config[4],config[6],config[8],config[10],config[11],config[13]); return 1; }
        pending_samples=ram && mode_pending_unchanged(c,config,busy,remote)?pending_samples+1:0;
        if (pending_samples==2) {
            mode_notice(o,9,stage,attempt,config[20],busy,remote[1],remote[2],0);
            return 0;
        }
        connect_release(o,c);
        sleep_ms(250);
    }
    retain_unresolved(o,176,stage);
    return 0;
}

static int media_config_roundtrip(struct observer *o,struct connect_owner *c) {
    u32 previous=o->phase,busy,remote[14],size[5],ok=0,completed=0;
    o->phase=20;
    mode_notice(o,0,c->recorder.core,c->recorder.manager,c->remote.core,c->rec_tid,c->remote_tid,m7_config.bias,m7_config.mwf_bias);
    if (!connect_pair(o,c,3)) goto done;
    if (!mode_snapshot(o,c,1,c->mode_before,&busy,remote) ||
        !mode_block(o,17,c->recorder.core+0xfc,size,5) || (size[0]&255)!=1) goto done;
    for (u32 i=0;i<15;++i) if (c->mode_before[i]!=c->config_before[i]) goto done;
    if (c->mode_before[0] || c->mode_before[1] || c->mode_before[2]!=1 ||
        c->mode_before[4]!=0x1000 || c->mode_before[6] || c->mode_before[8]!=0x1000 || c->mode_before[10] ||
        c->mode_before[11]!=0xffffffff || c->mode_before[12]!=0xffffffff || c->mode_before[13]!=0xffffffff ||
        c->mode_before[14]!=0xffffffff || c->mode_before[15] || c->mode_before[16] ||
        c->mode_before[17]!=0x1000 || c->mode_before[19]!=1 ||
        (c->mode_before[20]&0xffff)!=1 || (busy&0x00ffff00)) goto done;
    /* With both pins connected, still mode requires the SD secondary during initialization. */
    const u32 ram[4]={0,0x4100,0xffffffff,0};
    mode_set(o,c,2,ram);
    ok=mode_drain(o,c,3,1);
    u32 sd[4]={c->mode_before[15],c->mode_before[17],c->mode_before[18],c->mode_before[19]};
    mode_set(o,c,4,sd);
    mode_drain(o,c,5,0);
    completed=1;
done:
    connect_release(o,c);
    mode_notice(o,6,ok,c->mode_applied,0,0,0,0,0);
    o->phase=previous;
    return completed;
}

static void media_config_finish(struct observer *o,struct connect_owner *c) {
    u32 previous=o->phase,config[21],busy,remote[14];
    o->phase=20;
    if (!mode_snapshot(o,c,7,config,&busy,remote) || (busy&0x00ffff00) || remote[0] || remote[1])
        retain_unresolved(o,177,0);
    for (u32 i=0;i<21;++i)
        if (config[i]!=((c->ram_only?(i==5 || i==9):i==12)?0:c->mode_before[i])) retain_unresolved(o,177,i+1);
    /* Disconnect clears auxiliary media/pin but leaves the old MMgr cache. */
    if (c->ram_only) {
        create_restore_word(o,c->recorder.manager+0x44,0,c->mode_before[5]);
        create_restore_word(o,c->recorder.manager+0x54,0,c->mode_before[9]);
    } else create_restore_word(o,c->recorder.manager+0x60,0,c->mode_before[12]);
    if (!mode_snapshot(o,c,9,config,&busy,remote)) retain_unresolved(o,178,0);
    for (u32 i=0;i<21;++i) if (config[i]!=c->mode_before[i]) retain_unresolved(o,178,i+1);
    c->mode_applied=2;
    mode_notice(o,7,1,c->recorder.manager,21,0,0,0,0);
    o->phase=previous;
}
