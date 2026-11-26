static int media_get(struct observer *o, struct trace_context *t, u32 media, u32 operation, u32 selector) {
    unsigned char buffer[256] __attribute__((aligned(4)));
    u32 output=t->original[13]-4096+128, result=0xffffffff, size=operation==15?200:operation==18?0:4;
    for (u32 i=0;i<sizeof(buffer);++i) buffer[i]=255;
    ((u32 *)buffer)[63]=0x4d374d50;
    u32 data[8]={media,operation,selector,result,0xffffffff,size,0,0};
    if (size && !commit_scratch(o,t,128,buffer,sizeof(buffer))) { data[7]=1; goto report; }
    if (!sony_call(o,t,operation,operation==16?selector:media,
                   operation==16?media:operation==18?0:output,operation==16?output:0,&result)) {
        data[7]=2; goto report;
    }
    data[3]=result;
    if (size) {
        if (!read_mem(o,output,(u32 *)buffer,sizeof(buffer))) { data[7]=3; goto report; }
        if (((u32 *)buffer)[63]!=0x4d374d50) { data[7]=4; goto report; }
        data[4]=((u32 *)buffer)[0];
    } else data[4]=result;
    data[6]=1;
report:
    emit(o,27,data);
    if (operation==15 && data[6]) for (u32 offset=0;offset<200;offset+=24) {
        u32 chunk[8]={media,offset};
        for (u32 i=0;i<24 && offset+i<200;++i)
            chunk[2+i/4]|=(u32)buffer[offset+i]<<(8*(i%4));
        emit(o,28,chunk);
    }
    return data[6]!=0;
}

static int media_run(struct observer *o) {
    const u32 ids[3]={0x1000,0x4000,0x4100};
    u32 data[8]={0,m7_config.mprctrl_bias,0x1000,0x4000,0x4100,3,5,0}, completed=0;
    emit(o,29,data);
    for (u32 i=0;i<3;++i) {
        struct trace_context t={0};
        u32 count=0;
        int ok=trace_begin(o,&t);
        if (ok) for (u32 query=0;query<5;++query) {
            u32 operation=query==0?15:query<3?16:query==3?17:18;
            ok=media_get(o,&t,ids[i],operation,query==2?1:0);
            if (!ok) break;
            count++;
        }
        data[0]=1; data[1]=ids[i]; data[2]=ok; data[3]=count;
        data[4]=data[5]=data[6]=data[7]=0;
        emit(o,29,data);
        trace_restore(o,&t);
        if (!ok) break;
        completed++;
    }
    data[0]=2; data[1]=completed; data[2]=3; data[3]=0;
    emit(o,29,data);
    return completed==3;
}
