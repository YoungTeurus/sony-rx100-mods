static void session_pin_manager(struct observer *o,u32 sample,u32 descriptor) {
    u32 roots[3]={0},state[6]={0},again[6],pin[16],pending,repeat[3],mask=0;
    if (!session_stop_block(o,sample,640,descriptor+0x24,roots,3) ||
        !session_stop_block(o,sample,641,roots[2],state,6)) goto done;
    mask=1;
    if (state[4]!=roots[0] || state[5]>1 || (state[3]&255)>1) goto done;
    mask|=2;
    if (!session_stop_block(o,sample,642,roots[0],pin,16) ||
        pin[0]!=m7_config.mwf_bias+0x42fa0) goto done;
    mask|=4;
    if (!session_stop_block(o,sample,643,roots[2],again,6) ||
        !session_stop_block(o,sample,644,descriptor+0x24,repeat,3) ||
        !session_stop_block(o,sample,645,roots[0]+0x3c,&pending,1)) goto done;
    if (repeat[0]==roots[0] && repeat[2]==roots[2] && state[2]==again[2] &&
        (state[3]&255)==(again[3]&255) && state[4]==again[4] && state[5]==again[5] && pending==pin[15]) mask|=8;
done:
    start_notice(o,20,sample,roots[2],state[2],state[3]&255,state[4],state[5],mask);
}

struct capture_pin_observation {
    u32 core,roots[3],pins[2][16],configs[2][4],body[15],bits[2];
};

static void session_capture_pins(struct observer *o,u32 sample,u32 core) {
    struct capture_pin_observation first={0},next={0};
    u32 input=0,peer=0,mask=0,reason=PENDING_READ_FAILED;
    for (u32 pass=0;pass<2;++pass) {
        struct capture_pin_observation *s=pass?&next:&first;
        if (!session_stop_block(o,sample,pass?650:648,core,&s->core,1) ||
            !session_stop_block(o,sample,pass?651:649,core+0x68,s->roots,3)) goto done;
        reason=PENDING_IDENTITY;
        if (s->core!=m7_config.bias+0x138d428) goto done;
        if (!pass) { input=s->roots[2];mask=1; }
        reason=PENDING_CHANGED;
        if (s->roots[2]!=input) goto done;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,pass?652:622,input,s->pins[0],16)) goto done;
        u32 *p=s->pins[0];
        reason=PENDING_IDENTITY;
        if (p[0]!=m7_config.mwf_bias+0x42fa0 || p[1]!=9 || p[2] || p[3] ||
            p[5]!=s->roots[0] || !p[4] || p[4]==input) goto done;
        if (!pass) peer=p[4];
        reason=PENDING_CHANGED;
        if (p[4]!=peer) goto done;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,pass?653:626,peer,s->pins[1],16)) goto done;
        p=s->pins[1];reason=PENDING_IDENTITY;
        if (p[0]!=m7_config.mwf_bias+0x42fa0 || p[1]!=9 || p[3]!=1 || p[4]!=input) goto done;
        if (!pass) mask|=2;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,pass?654:623,s->pins[0][6],s->configs[0],4) ||
            !session_stop_block(o,sample,pass?655:627,s->pins[1][6],s->configs[1],4)) goto done;
        reason=PENDING_IDENTITY;
        for (u32 i=0;i<2;++i) if (s->configs[i][0]!=m7_config.mwf_bias+0x42fe0 ||
            s->configs[i][1]!=m7_config.mwf_bias+0x43010) goto done;
        if (s->configs[0][2]!=s->configs[1][2] || s->configs[0][3]==s->configs[1][3]) goto done;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,pass?656:624,s->configs[0][2],s->body,15)) goto done;
        reason=PENDING_IDENTITY;
        if (s->body[0]!=m7_config.mwf_bias+0x42ff8 || s->body[8]!=m7_config.bias+0x3c1419 ||
            s->body[11]!=1) goto done;
        for (u32 i=0;i<2;++i) if (!s->configs[i][3] || s->configs[i][3]>=s->body[10]) goto done;
        reason=PENDING_LIMIT;
        if (s->body[10]>33) goto done;
        reason=PENDING_READ_FAILED;
        if (!session_stop_block(o,sample,pass?657:1324,s->body[13],s->bits,2)) goto done;
        reason=PENDING_LIMIT;
        if (s->bits[1]) goto done;
        if (!pass) mask|=4;
    }
    reason=PENDING_CHANGED;
    if (first.core!=next.core) goto done;
    for (u32 i=0;i<3;++i) if (first.roots[i]!=next.roots[i]) goto done;
    for (u32 role=0;role<2;++role) {
        for (u32 i=0;i<7;++i) if (first.pins[role][i]!=next.pins[role][i]) goto done;
        if (first.pins[role][15]!=next.pins[role][15]) goto done;
        for (u32 i=0;i<4;++i) if (first.configs[role][i]!=next.configs[role][i]) goto done;
    }
    if (first.body[0]!=next.body[0]) goto done;
    for (u32 i=8;i<15;++i) if (first.body[i]!=next.body[i]) goto done;
    for (u32 i=0;i<2;++i) if (first.bits[i]!=next.bits[i]) goto done;
    mask|=8;reason=PENDING_COMPLETE;
done:
    /* Matching reads identify this pair; they do not prove quiescence or name the peer's object. */
    if ((mask&7)==7) for (u32 role=0;role<2;++role) {
        u32 id=first.configs[role][3];
        start_notice(o,18,sample,role+3,role?peer:input,first.configs[role][2],id,first.body[12],first.pins[role][15]);
        start_notice(o,19,sample,role+3,mask,(first.bits[0]>>(id-1))&1,0,0,0);
    }
    start_notice(o,21,sample,input,peer,first.configs[0][3],first.configs[1][3],mask,reason);
}
