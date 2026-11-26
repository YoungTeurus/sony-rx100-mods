static u32 commit_name_token(struct observer *o) {
    return o->commit_sequence ? (m7_config.token^(o->commit_sequence<<20))|0x80000000 : m7_config.token;
}

static void commit_notice(struct observer *o, u32 stage, u32 a, u32 b, u32 c) {
    u32 data[8]={stage,a,b,c,o->held_candidate[4],commit_name_token(o),o->commit_drive,o->commit_status};
    emit(o,21,data);
}

static void commit_result(struct observer *o) {
    commit_notice(o,10,o->commit_status,o->commit_written,o->commit_read);
}

static int commit_scratch(struct observer *o, struct trace_context *t, u32 offset,
                          const unsigned char *bytes, u32 size) {
    unsigned char verify[256] __attribute__((aligned(4)));
    if (!size || size>sizeof(verify) || (offset&3) || (size&3) || offset+size>512) return 0;
    u32 scratch=t->original[13]-4096+offset;
    for (u32 i=0;i<size;i+=4) {
        u32 word=0;
        for (u32 j=0;j<4;++j) word|=(u32)bytes[i+j]<<(8*j);
        if (call(26,5,o->trace_tid,scratch+i,word,0,0)!=0) return 0;
    }
    if (!read_mem(o,scratch,(u32 *)verify,size)) return 0;
    for (u32 i=0;i<size;++i) if (verify[i]!=bytes[i]) return 0;
    return 1;
}

static int commit_path(struct observer *o, struct trace_context *t) {
    const char hex[]="0123456789ABCDEF";
    unsigned char path[68]={0};
    path[0]=(unsigned char)o->commit_drive; path[1]=':'; path[2]='\\'; path[3]='P'; path[4]='C';
    for (u32 i=0;i<6;++i) path[5+i]=hex[(commit_name_token(o)>>(20-4*i))&15];
    path[11]='.'; path[12]='J'; path[13]='P'; path[14]='G';
    return commit_scratch(o,t,0,path,sizeof(path));
}

static int commit_sd_drive(struct observer *o, struct trace_context *t) {
    u32 mask=0, complete=1, scratch=t->original[13]-4096;
    const unsigned char zero[56]={0};
    for (u32 index=0;index<5;++index) {
        unsigned char path[256] __attribute__((aligned(4)))={0};
        u32 data[8]={index,0,0,0,0xffffffff,0,0,0}, info[14]={0}, copied=0;
        if (!commit_scratch(o,t,256,zero,sizeof(zero))) { data[7]=1; goto report; }
        if (!sony_call(o,t,13,index,scratch+256,0,&data[1])) { data[7]=2; goto report; }
        if (!read_mem(o,scratch+256,&data[2],4)) { data[7]=3; goto report; }
        if (data[1]>1 || data[1]!=(data[2]!=0)) { data[7]=4; goto report; }
        if (!data[2]) goto report;
        /* The MMgr owns this inline path; copy it before another Sony call. */
        if (!read_mem(o,data[2],(u32 *)path,sizeof(path))) { data[7]=5; goto report; }
        while (data[6]<sizeof(path) && path[data[6]]) data[6]++;
        if (data[6]==sizeof(path)) { data[7]=6; goto report; }
        copied=1;
        if (!data[6]) goto report;
        if (!commit_scratch(o,t,0,path,sizeof(path))) { data[7]=7; goto report; }
        if (!sony_call(o,t,8,scratch,0,0,&data[3])) { data[7]=8; goto report; }
        if (!data[3]) goto report;
        if (data[3]>='a' && data[3]<='z') data[3]-='a'-'A';
        if (data[3]<'A' || data[3]>'Z') { data[7]=9; goto report; }
        if (!sony_call(o,t,14,data[3],scratch+256,0,&data[4])) { data[7]=10; goto report; }
        if (data[4]!=0) { complete=0; goto report; }
        if (!read_mem(o,scratch+256,info,sizeof(info))) { data[7]=11; goto report; }
        data[5]=info[0];
        u32 type=info[0]>>16;
        if (type==0x8400 || type==0x8401 || type==0x8402 || type==0x84ff) {
            mask|=1u<<(data[3]-'A');
            if (info[0]&0x43) complete=0;
        }
report:
        if (data[7]) complete=0;
        emit(o,23,data);
        if (copied) for (u32 offset=0;offset<=data[6];offset+=24) {
            u32 chunk[8]={index,offset};
            for (u32 j=0;j<24 && offset+j<=data[6];++j)
                chunk[2+j/4]|=(u32)path[offset+j]<<(8*(j%4));
            emit(o,24,chunk);
        }
    }
    u32 count=0, drive=0;
    for (u32 i=0;i<26;++i) if (mask&(1u<<i)) { count++; drive='A'+i; }
    o->commit_drive=complete && count==1 ? drive : 0;
    commit_notice(o,2,o->commit_drive,count,5);
    return o->commit_drive!=0;
}

static int commit_open(struct observer *o, struct trace_context *t, u32 flags, u32 stage,
                       u32 *handle, u32 *result) {
    u32 scratch=t->original[13]-4096;
    if (!sony_call(o,t,9,scratch,scratch+64,flags,result)) return 0;
    if (*result==0 && !read_mem(o,scratch+64,handle,4)) retain_unresolved(o,50,stage);
    commit_notice(o,stage,*result,*result==0?*handle:0,flags);
    return 1;
}

static void commit_close(struct observer *o, struct trace_context *t, u32 handle, u32 stage) {
    u32 result;
    if (!sony_call(o,t,11,handle,0,0,&result) && !sony_call(o,t,11,handle,0,0,&result))
        retain_unresolved(o,51,stage);
    commit_notice(o,stage,result,handle,0);
    if (result!=0) retain_unresolved(o,52,result);
}

static void commit_write(struct observer *o, struct locked_frame *f) {
    struct held_image *a=&o->jpeg_before,*b=&o->jpeg_after;
    o->commit_status=2;
    commit_notice(o,1,m7_config.mpr_bias,b->address,b->length);
    if (!a->valid || !b->valid || a->address!=b->address || a->length!=b->length ||
        a->width!=b->width || a->height!=b->height) return;
    for (u32 i=0;i<8;++i) if (a->digest[i]!=b->digest[i]) return;
    u32 result,handle=0;
    o->commit_status=3;
    if (!commit_sd_drive(o,&f->trace)) return;
    o->commit_status=4;
    if (!commit_path(o,&f->trace)) return;
    o->commit_status=6;
    if (!commit_open(o,&f->trace,1,3,&handle,&result)) return;
    if (result==0) {
        commit_close(o,&f->trace,handle,11);
        o->commit_status=5;
        return;
    }
    if (result!=0x80000051) return;
    o->commit_status=7;
    if (!commit_open(o,&f->trace,7,4,&handle,&result) || result!=0) return;
    o->commit_status=8;
    while (o->commit_written<b->length) {
        u32 n=b->length-o->commit_written;
        if (n>1024*1024) n=1024*1024;
        if (!sony_call(o,&f->trace,10,handle,b->address+o->commit_written,n,&result)) {
            commit_notice(o,15,10,0,n);
            break;
        }
        if ((s32)result>0 && result<=n) o->commit_written+=result;
        if (result!=n) { commit_notice(o,14,10,result,n); break; }
    }
    commit_notice(o,5,o->commit_written,b->length,result);
    commit_close(o,&f->trace,handle,6);
    if (o->commit_written==b->length) o->commit_status=1;
}

static void commit_verify(struct observer *o) {
    struct trace_context t={0};
    struct jpeg_scan hash={0};
    unsigned char buffer[3968] __attribute__((aligned(4)));
    u32 result,handle=0;
    o->phase=9;
    o->commit_status=9;
    if (!trace_begin(o,&t)) goto done;
    if (!commit_path(o,&t)) { o->commit_status=4; goto done; }
    if (!commit_open(o,&t,1,7,&handle,&result) || result!=0) goto done;
    o->commit_status=10;
    sha256_begin(&hash.sha);
#if M7_RAM_PRECAPTURE
    precap_progress(o,3,0,0);
#endif
    u32 scratch=t.original[13]-4096+128;
    while (o->commit_read<o->commit_written) {
        u32 n=o->commit_written-o->commit_read;
        if (n>sizeof(buffer)) n=sizeof(buffer);
        if (!sony_call(o,&t,12,handle,scratch,n,&result)) {
            commit_notice(o,15,12,0,n);
            goto close;
        }
        o->commit_reads++;
        if (!result || result>n) { commit_notice(o,14,12,result,n); goto close; }
        if (!read_mem(o,scratch,(u32 *)buffer,result)) {
            commit_notice(o,16,180,scratch,result);
            goto close;
        }
        for (u32 i=0;i<result;++i) sha256_byte(&hash.sha,buffer[i]);
        o->commit_read+=result;
#if M7_RAM_PRECAPTURE
        precap_progress(o,3,o->commit_read,0);
#endif
    }
    if (!sony_call(o,&t,12,handle,scratch,1,&result)) goto close;
    o->commit_reads++;
    commit_notice(o,8,o->commit_read,o->commit_reads,result);
    if (result!=0) goto close;
#if M7_RAM_PRECAPTURE
    u32 compare_at=now();
#endif
    sha256_finish(&hash.sha,o->commit_digest);
    o->commit_status=12;
    for (u32 i=0;i<8;++i)
        if (o->commit_digest[i]!=o->jpeg_after.digest[i]) o->commit_status=11;
#if M7_RAM_PRECAPTURE
    precap_file_timing(o,15,now()-compare_at,o->commit_status);
#endif
close:
    commit_close(o,&t,handle,9);
    if (o->commit_status==12 || o->commit_status==11) emit(o,22,o->commit_digest);
done:
#if M7_RAM_PRECAPTURE
    precap_progress(o,3,o->commit_read,1);
#endif
    trace_restore(o,&t);
    o->phase=8;
}
