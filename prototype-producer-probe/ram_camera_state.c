struct camera_observation {
    u32 registry[4],owner[4],core,input,pins[2][6],vptr,pin,sender,counts[2],pending;
};

static u32 session_camera_state(struct observer *o,u32 sample,u32 core) {
    struct camera_observation first={0},next={0};
    u32 mask=0,reason=PENDING_READ_FAILED,row=m7_config.mwf_bias+0x45b4c;
    for (u32 pass=0;pass<2;++pass) {
        struct camera_observation *s=pass?&next:&first;
        u32 tag=660+pass*20;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,tag,row,s->registry,4) ||
            !session_stop_block(o,sample,tag+1,row+0x38,s->owner,4)) goto done;
        reason=PENDING_IDENTITY;
        for (u32 i=0;i<10;++i)
            if (((unsigned char *)s->registry)[5+i]!=(unsigned char)"ObjCamera"[i]) goto done;
        if (s->owner[0]!=m7_config.bias+0xad663d || s->owner[2]!=1 || !s->owner[3]) goto done;
        if (!pass) mask=1;
        reason=PENDING_CHANGED;
        if (pass && s->owner[3]!=first.owner[3]) goto done;
        u32 camera=s->owner[3];
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,tag+2,core,&s->core,1) ||
            !session_stop_block(o,sample,tag+3,core+0x70,&s->input,1)) goto done;
        reason=PENDING_IDENTITY;
        if (s->core!=m7_config.bias+0x138d428 || !s->input) goto done;
        reason=PENDING_CHANGED;
        if (pass && s->input!=first.input) goto done;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,tag+4,s->input,s->pins[0],6)) goto done;
        u32 *p=s->pins[0];
        reason=PENDING_IDENTITY;
        if (p[0]!=m7_config.mwf_bias+0x42fa0 || p[1]!=9 || p[2] || p[3] ||
            !p[4] || p[4]==s->input) goto done;
        reason=PENDING_CHANGED;
        if (pass && p[4]!=first.pins[0][4]) goto done;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,tag+5,p[4],s->pins[1],6) ||
            !session_stop_block(o,sample,tag+6,camera,&s->vptr,1)) goto done;
        p=s->pins[1];reason=PENDING_IDENTITY;
        if (p[0]!=m7_config.mwf_bias+0x42fa0 || p[1]!=9 || p[2] || p[3]!=1 ||
            p[4]!=s->input || !p[5] || s->vptr!=m7_config.bias+0x1390490) goto done;
        if (!pass) mask|=2;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,tag+7,camera+0x68,&s->pin,1) ||
            !session_stop_block(o,sample,tag+8,camera+0x8c,&s->sender,1)) goto done;
        reason=PENDING_IDENTITY;
        if (s->pin!=s->pins[0][4] || s->sender!=p[5]) goto done;
        if (!pass) mask|=4;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,tag+9,camera+0x1bc,s->counts,1) ||
            !session_stop_block(o,sample,tag+10,camera+0x1dc,s->counts+1,1) ||
            !session_stop_block(o,sample,tag+11,s->pin+0x3c,&s->pending,1)) goto done;
        if (!pass) mask|=8;
    }
    reason=PENDING_CHANGED;
    for (u32 i=0;i<4;++i) if (first.registry[i]!=next.registry[i] || first.owner[i]!=next.owner[i]) goto done;
    for (u32 role=0;role<2;++role)
        for (u32 i=0;i<6;++i) if (first.pins[role][i]!=next.pins[role][i]) goto done;
    if (first.core!=next.core || first.input!=next.input || first.vptr!=next.vptr ||
        first.pin!=next.pin || first.sender!=next.sender || first.counts[0]!=next.counts[0] ||
        first.counts[1]!=next.counts[1] || first.pending!=next.pending) goto done;
    mask|=16;reason=PENDING_COMPLETE;
done:
    /* Matching reads identify observations, not completion or permission to clear a credit. */
    start_notice(o,22,sample,mask==31?first.owner[3]:0,mask==31?first.pin:0,
                 mask==31?first.counts[0]:0xffffffff,mask==31?first.counts[1]:0xffffffff,mask,reason);
    return mask==31?first.owner[3]:0;
}
