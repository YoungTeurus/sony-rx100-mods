struct receiver_snapshot { u32 sample, cursor, count, words[3072]; };

static void receiver_notice(struct observer *o,u32 stage,u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g) {
    u32 data[8]={stage,a,b,c,d,e,f,g};
    emit(o,43,data);
}

static int receiver_failure(struct observer *o,struct receiver_snapshot *s,u32 reason,
                            u32 address,u32 actual,u32 expected) {
    receiver_notice(o,90,s->sample,reason,address,actual,expected,0,0);
    return 0;
}

static int receiver_block(struct observer *o,struct receiver_snapshot *s,u32 tag,u32 address,u32 *words,u32 count) {
    if (count>27 || !read_mem(o,address,words,count*4)) return receiver_failure(o,s,1,address,0,count*4);
    if (s->cursor+count>3072) return receiver_failure(o,s,2,address,s->cursor+count,3072);
    for (u32 i=0;i<count;++i) {
        if (s->sample && (s->cursor>=s->count || s->words[s->cursor]!=words[i]))
            return receiver_failure(o,s,3,address+4*i,words[i],s->cursor<s->count?s->words[s->cursor]:0);
        s->words[s->cursor++]=words[i];
    }
    if (!s->sample) s->count=s->cursor;
    for (u32 offset=0;offset<count;offset+=5) {
        u32 data[8]={s->sample,tag,address+4*offset};
        for (u32 i=0;i<5 && offset+i<count;++i) data[3+i]=words[offset+i];
        emit(o,44,data);
    }
    return 1;
}

static int receiver_sample(struct observer *o,struct receiver_snapshot *s,u32 *classes,u32 *instances,u32 *receivers) {
    const char name[]="ObjCntMgr";
    u32 table=m7_config.mwf_bias+0x4548c;
    *classes=*instances=*receivers=0;
    for (u32 entry=0;entry<50;++entry) {
        u32 row[27],same=1;
        if (!receiver_block(o,s,entry,table+entry*0x6c,row,27)) return 0;
        if (!row[0]) continue;
        for (u32 i=0;i<sizeof(name);++i) if (((unsigned char *)row)[5+i]!=name[i]) same=0;
        if (!same) continue;
        if (++*classes!=1 || row[16]>10) return receiver_failure(o,s,4,table+entry*0x6c,*classes,row[16]);
        u32 seen[10],count=0;
        for (u32 slot=0;slot<10;++slot) if (row[17+slot]) {
            u32 object=row[17+slot],head[22],route[4],work_list,tag=100+slot*20;
            for (u32 j=0;j<count;++j) if (seen[j]==object) return receiver_failure(o,s,5,object,slot,j);
            seen[count++]=object;
            if (!receiver_block(o,s,tag,object,head,22)) return 0;
            (*instances)++;
            if (head[0]!=m7_config.bias+0x1388968) continue;
            if (head[17]!=0x4100) return receiver_failure(o,s,6,object+0x44,head[17],0x4100);
            if (!receiver_block(o,s,tag+1,object+0x78,route,4)) return 0;
            if (!head[20] || head[20]==head[21]) return receiver_failure(o,s,7,object+0x50,head[20],head[21]);
            for (u32 index=0;index<2;++index) {
                u32 pin[7],peer[7],sender[2],receiver[2],send_wrapper[2],recv_wrapper[3];
                u32 pt=tag+2+index*6;
                if (!receiver_block(o,s,pt,head[20+index],pin,7)) return 0;
                if (pin[0]!=m7_config.mwf_bias+0x42fa0 || pin[1]!=6 || pin[2]!=index || pin[3] ||
                    pin[5]!=route[2*index]) return receiver_failure(o,s,8,head[20+index],pin[0],m7_config.mwf_bias+0x42fa0);
                if (pin[4] && !receiver_block(o,s,pt+1,pin[4],peer,7)) return 0;
                if (!receiver_block(o,s,pt+2,route[2*index],sender,2) ||
                    !receiver_block(o,s,pt+3,route[2*index+1],receiver,2)) return 0;
                if (sender[0]!=m7_config.mwf_bias+0x42ba8 || receiver[0]!=m7_config.mwf_bias+0x42b78)
                    return receiver_failure(o,s,9,route[2*index],sender[0],m7_config.mwf_bias+0x42ba8);
                if (!receiver_block(o,s,pt+4,sender[1],send_wrapper,2) ||
                    !receiver_block(o,s,pt+5,receiver[1],recv_wrapper,3)) return 0;
            }
            if (!receiver_block(o,s,tag+14,object+0x298,&work_list,1)) return 0;
            (*receivers)++;
        }
        if (count!=row[16]) return receiver_failure(o,s,10,table+entry*0x6c+0x40,count,row[16]);
    }
    return !s->sample || s->cursor==s->count;
}

static int receiver_run(struct observer *o) {
    struct receiver_snapshot snapshot={0};
    u32 classes=0,instances=0,receivers=0;
    receiver_notice(o,0,m7_config.bias,m7_config.mwf_bias,m7_config.mwf_bias+0x4548c,50,0x6c,2,0);
    for (u32 sample=0;sample<2;++sample) {
        snapshot.sample=sample; snapshot.cursor=0;
        int ok=receiver_sample(o,&snapshot,&classes,&instances,&receivers);
        receiver_notice(o,1,sample,ok,classes,instances,receivers,snapshot.cursor,0);
        if (!ok) return 0;
        if (!sample) sleep_ms(20);
    }
    receiver_notice(o,2,classes,instances,receivers,snapshot.count,0,0,0);
    return !o->io_errors;
}
