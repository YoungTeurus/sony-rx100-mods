struct sha256_state { u32 h[8], bytes, used; unsigned char block[64]; };

static u32 rotate(u32 value, u32 n) { return (value >> n) | (value << (32-n)); }

static void sha256_block(struct sha256_state *s) {
    static const u32 k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    u32 w[64];
    for (u32 i = 0; i < 16; ++i) {
        const unsigned char *p = s->block+4*i;
        w[i] = ((u32)p[0]<<24) | ((u32)p[1]<<16) | ((u32)p[2]<<8) | p[3];
    }
    for (u32 i = 16; i < 64; ++i)
        w[i] = w[i-16]+(rotate(w[i-15],7)^rotate(w[i-15],18)^(w[i-15]>>3))+
               w[i-7]+(rotate(w[i-2],17)^rotate(w[i-2],19)^(w[i-2]>>10));
    u32 a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for (u32 i = 0; i < 64; ++i) {
        u32 t1 = h+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        u32 t2 = (rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}

static void sha256_begin(struct sha256_state *s) {
    const u32 initial[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                           0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    for (u32 i = 0; i < 8; ++i) s->h[i] = initial[i];
    s->bytes = s->used = 0;
}

static void sha256_byte(struct sha256_state *s, unsigned char value) {
    s->block[s->used++] = value;
    s->bytes++;
    if (s->used == 64) { sha256_block(s); s->used = 0; }
}

static void sha256_finish(struct sha256_state *s, u32 *out) {
    u32 bits = s->bytes*8;
    sha256_byte(s, 128);
    while (s->used != 56) sha256_byte(s, 0);
    for (u32 i = 0; i < 4; ++i) sha256_byte(s, 0);
    for (u32 i = 0; i < 4; ++i) sha256_byte(s, (unsigned char)(bits >> (24-i*8)));
    for (u32 i = 0; i < 8; ++i) out[i] = s->h[i];
}

struct jpeg_scan {
    struct sha256_state sha;
    u32 state, marker, remaining, segment_at, length, width, height, sof, sos, done, error;
};

static int jpeg_sof(u32 marker) {
    return marker >= 0xc0 && marker <= 0xcf && marker != 0xc4 && marker != 0xc8 && marker != 0xcc;
}

static void jpeg_marker(struct jpeg_scan *s, u32 value) {
    if (value == 0xff) return;
    if (value == 0xd9) {
        s->done = s->sof && s->sos && s->width && s->height;
        s->error = !s->done;
    } else if (value == 0x01) s->state = 2;
    else if (value == 0 || (value >= 0xd0 && value <= 0xd8)) s->error = 1;
    else { s->marker = value; s->state = 4; }
}

static void jpeg_byte(struct jpeg_scan *s, unsigned char value) {
    sha256_byte(&s->sha, value);
    s->length++;
    switch (s->state) {
    case 0: if (value != 0xff) s->error=1; else s->state=1; break;
    case 1: if (value != 0xd8) s->error=1; else s->state=2; break;
    case 2: if (value != 0xff) s->error=1; else s->state=3; break;
    case 3: jpeg_marker(s,value); break;
    case 4: s->remaining = (u32)value<<8; s->state=5; break;
    case 5:
        s->remaining |= value;
        if (s->remaining < 2 || (jpeg_sof(s->marker) && s->remaining < 11) ||
            (s->marker == 0xda && (s->remaining < 8 || !s->sof))) { s->error=1; break; }
        s->remaining -= 2; s->segment_at=0;
        s->state = s->remaining ? 6 : 2;
        break;
    case 6:
        if (jpeg_sof(s->marker)) {
            if (s->segment_at == 0 && value != 8 && value != 12) s->error=1;
            if (s->segment_at == 1) s->height=(u32)value<<8;
            if (s->segment_at == 2) s->height|=value;
            if (s->segment_at == 3) s->width=(u32)value<<8;
            if (s->segment_at == 4) s->width|=value;
        }
        s->segment_at++;
        if (!--s->remaining) {
            if (jpeg_sof(s->marker)) s->sof=1;
            if (s->marker == 0xda) { s->sos=1; s->state=7; }
            else s->state=2;
        }
        break;
    case 7: if (value == 0xff) s->state=8; break;
    case 8:
        if (!value || (value >= 0xd0 && value <= 0xd7)) s->state=7;
        else if (value != 0xff) jpeg_marker(s,value);
        break;
    default: s->error=1;
    }
}
