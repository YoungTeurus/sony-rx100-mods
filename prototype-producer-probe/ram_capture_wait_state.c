struct capture_wait_observation {
    u32 state,manager,vector[3],worker[3],pointers[8],entries[8][2];
};

static void session_capture_wait_state(struct observer *o,u32 sample,u32 camera) {
    struct capture_wait_observation first={0},next={0};
    u32 mask=0,reason=PENDING_IDENTITY,count=0,observed=0;
    if (!camera) goto done;
    for (u32 pass=0;pass<2;++pass) {
        struct capture_wait_observation *s=pass?&next:&first;
        u32 tag=800+pass*20;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,tag,camera+0x18c,&s->state,1)) goto done;
        reason=pass?PENDING_CHANGED:PENDING_IDENTITY;
        if (s->state!=m7_config.bias+0x145d960) goto done;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,tag+1,m7_config.bias+0x145e340,&s->manager,1)) goto done;
        reason=PENDING_CHANGED;
        if (pass && s->manager!=first.manager) goto done;
        if (!pass) mask=1;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,tag+2,s->manager,s->vector,3) ||
            !session_stop_block(o,sample,tag+3,s->manager+0x70,s->worker,3)) goto done;
        reason=pass?PENDING_CHANGED:PENDING_IDENTITY;
        if ((s->vector[0]|s->vector[1]|s->vector[2])&3 || s->vector[1]<s->vector[0] ||
            s->vector[2]<s->vector[1] || s->vector[2]>0xc0000000 ||
            (!s->vector[0] && (s->vector[1] || s->vector[2])) ||
            (s->vector[0] && s->vector[0]<0x10000)) goto done;
        if (pass) for (u32 i=0;i<3;++i)
            if (s->vector[i]!=first.vector[i] || s->worker[i]!=first.worker[i]) goto done;
        count=(s->vector[1]-s->vector[0])/4;
        reason=PENDING_LIMIT;
        if (count>8) goto done;
        if (!pass) mask|=2;
        reason=PENDING_READ_FAILED;
        if (count && !session_stop_block(o,sample,tag+4,s->vector[0],s->pointers,count)) goto done;
        if (pass) {
            reason=PENDING_CHANGED;
            for (u32 i=0;i<count;++i) if (s->pointers[i]!=first.pointers[i]) goto done;
        }
        for (u32 i=0;i<count;++i) {
            reason=PENDING_CYCLE;
            for (u32 j=0;j<i;++j) if (s->pointers[i]==s->pointers[j]) goto done;
            reason=PENDING_READ_FAILED;
            if (!session_stop_block(o,sample,tag+5+i,s->pointers[i],s->entries[i],2)) goto done;
            reason=PENDING_CHANGED;
            if (pass && (s->entries[i][0]!=first.entries[i][0] ||
                         s->entries[i][1]!=first.entries[i][1])) goto done;
            if (!pass) ++observed;
        }
        if (!pass) mask|=4;
    }
    mask|=8;reason=PENDING_COMPLETE;
    for (u32 i=0;i<count;++i)
        start_notice(o,26,sample,i,first.pointers[i],first.entries[i][0],first.entries[i][1],0,0);
done:
    /* Async admission can follow matching reads; this is not a completion barrier. */
    start_notice(o,25,sample,mask==15?first.manager:0,mask==15?count:0xffffffff,
                 observed,mask==15?first.worker[2]:0xffffffff,mask,reason);
}
