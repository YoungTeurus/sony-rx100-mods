struct capture_trap { u32 address, word, patched, armed; };

static void capture_trap_notice(struct observer *o,struct capture_trap *trap,
                                u32 stage,u32 value,u32 detail) {
    u32 data[8]={stage,o->trace_tid,trap->address,trap->word,trap->patched,value,detail,0};
    emit(o,48,data);
}

static int capture_trap_word(struct observer *o,u32 address,u32 *word) {
    return call(180,(u32)o->fd,(u32)word,4,0,address&~3u,0)==4;
}

static int capture_trap_set(struct observer *o,struct capture_trap *trap,u32 address,u32 expected_word) {
    u32 live,shift=(address&2u)*8;
    if (trap->armed || !o->trace_tid || address<0x10000 || address>=0xc0000000 || (address&1)) {
        capture_trap_notice(o,trap,90,0,1);
        return 0;
    }
    trap->address=address; trap->word=expected_word;
    trap->patched=(expected_word&~(0xffffu<<shift))|(0xde01u<<shift);
    if (trap->patched==expected_word || !capture_trap_word(o,address,&live) || live!=expected_word) {
        capture_trap_notice(o,trap,90,0,2);
        return 0;
    }
    s32 rc=call(26,4,o->trace_tid,address&~3u,trap->patched,0,0);
    /* Once POKETEXT was attempted, an unreadable word must keep the owner stopped. */
    trap->armed=1;
    if (!capture_trap_word(o,address,&live)) retain_unresolved(o,140,address);
    if (rc && live==expected_word) {
        trap->armed=0;
        capture_trap_notice(o,trap,90,(u32)rc,3);
        return 0;
    }
    if (rc || live!=trap->patched) retain_unresolved(o,141,live);
    capture_trap_notice(o,trap,10,0,address&~3u);
    return 1;
}

static int capture_trap_restore(struct observer *o,struct capture_trap *trap) {
    u32 live;
    if (!trap->armed) return 1;
    if (!capture_trap_word(o,trap->address,&live) || live!=trap->patched)
        retain_unresolved(o,142,trap->address);
    s32 rc=call(26,4,o->trace_tid,trap->address&~3u,trap->word,0,0);
    if (!capture_trap_word(o,trap->address,&live)) retain_unresolved(o,143,trap->address);
    if (rc && live==trap->patched) {
        capture_trap_notice(o,trap,90,(u32)rc,4);
        return 0;
    }
    if (rc || live!=trap->word) retain_unresolved(o,144,live);
    trap->armed=0;
    capture_trap_notice(o,trap,12,0,trap->address&~3u);
    return 1;
}

static int capture_trap_poll(struct observer *o,struct trace_context *t,struct capture_trap *trap) {
    u32 status=0,live;
    if (!trap->armed || !t->attached) {
        capture_trap_notice(o,trap,90,0,5);
        return -1;
    }
    s32 waited=call(114,o->trace_tid,(u32)&status,0x40000001,0,0,0);
    if (!waited || waited==-4) return 0;
    if (waited!=(s32)o->trace_tid || status!=0x057f) {
        capture_trap_notice(o,trap,90,status,6);
        retain_unresolved(o,145,(u32)waited);
    }
    if (call(26,12,o->trace_tid,0,(u32)t->original,0,0) ||
        call(26,27,o->trace_tid,0,(u32)t->vfp,0,0)) retain_unresolved(o,146,trap->address);
    if (t->original[15]!=trap->address || (t->original[16]&0x3f)!=0x30 ||
        !capture_trap_word(o,trap->address,&live) || live!=trap->patched)
        retain_unresolved(o,147,t->original[15]);
    for (u32 i=0;i<18;++i) t->work[i]=t->original[i];
    t->dirty=0;
    capture_trap_notice(o,trap,11,status,t->original[16]);
    return 1;
}
