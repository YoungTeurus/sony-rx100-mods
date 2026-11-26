struct route_snapshot { u32 entries[192][7], count, cursor, sample; };

static int route_record(struct observer *o, struct route_snapshot *snapshot, u32 tag, u32 address,
                        const u32 *words, u32 count) {
    u32 data[8]={snapshot->sample,tag,address};
    for (u32 i=0;i<count;++i) data[3+i]=words[i];
    emit(o,31,data);
    if (snapshot->cursor>=192) return 0;
    if (snapshot->sample) {
        if (snapshot->cursor>=snapshot->count) return 0;
        for (u32 i=0;i<7;++i)
            if (snapshot->entries[snapshot->cursor][i]!=data[1+i]) return 0;
    } else {
        for (u32 i=0;i<7;++i) snapshot->entries[snapshot->cursor][i]=data[1+i];
        snapshot->count++;
    }
    snapshot->cursor++;
    return !o->io_errors;
}

static int route_block(struct observer *o, struct route_snapshot *snapshot, u32 tag, u32 address,
                       u32 *words, u32 count) {
    if (!read_mem(o,address,words,count*4)) return 0;
    for (u32 i=0;i<count;i+=5)
        if (!route_record(o,snapshot,tag+i/5,address+4*i,words+i,count-i<5?count-i:5)) return 0;
    return 1;
}

static int route_sample(struct observer *o, struct route_snapshot *snapshot, u32 *recorders) {
    u32 registry[5];
    *recorders=0;
    if (!route_block(o,snapshot,0,m7_config.bias+0x145d884,registry,5)) return 0;
    for (u32 i=0;i<5;++i) if (registry[i]) {
        u32 core=registry[i], identity[2], mgr[4], config[15];
        if (!private_range(o,core,0x230) || !read_mem(o,core,identity,4) ||
            !read_mem(o,core+0xf0,identity+1,4) ||
            !route_record(o,snapshot,10+i,core,identity,2) || identity[0]!=m7_config.bias+0x138d428) return 0;
        if (!route_block(o,snapshot,20+i*4,identity[1],mgr,4) || mgr[0]!=core ||
            !route_block(o,snapshot,21+i*4,identity[1]+0x30,config,15)) return 0;
        for (u32 slot=0;slot<3;++slot) if (mgr[slot+1]) {
            u32 tag=100+i*60+slot*20, desc[15], wrapper[6], pin[7], peer[7], resource[5];
            if (!route_block(o,snapshot,tag,mgr[slot+1],desc,15) || desc[0]!=core ||
                desc[1]!=identity[1]+0x10 || desc[14]!=slot) return 0;
            if (desc[10] && !route_block(o,snapshot,tag+4,desc[10],wrapper,6)) return 0;
            if (desc[9]) {
                if (!route_block(o,snapshot,tag+6,desc[9],pin,7)) return 0;
                if (pin[4] && !route_block(o,snapshot,tag+8,pin[4],peer,7)) return 0;
            }
            if (desc[6] && !route_block(o,snapshot,tag+10,desc[6],resource,5)) return 0;
        }
        (*recorders)++;
    }
    return !snapshot->sample || snapshot->cursor==snapshot->count;
}

static int media_route_run(struct observer *o) {
    struct route_snapshot snapshot={0};
    u32 data[8]={0,m7_config.bias,m7_config.pid,m7_config.bias+0x145d884,m7_config.bias+0x138d428,5,3,2};
    emit(o,30,data);
    for (u32 sample=0;sample<2;++sample) {
        snapshot.sample=sample;
        snapshot.cursor=0;
        u32 recorders=0;
        int ok=route_sample(o,&snapshot,&recorders);
        data[0]=1; data[1]=sample; data[2]=ok; data[3]=recorders; data[4]=snapshot.cursor;
        data[5]=data[6]=data[7]=0;
        emit(o,30,data);
        if (!ok) return 0;
        if (!sample) sleep_ms(20);
    }
    data[0]=2; data[1]=snapshot.count; data[2]=2; data[3]=data[4]=0;
    emit(o,30,data);
    return 1;
}
