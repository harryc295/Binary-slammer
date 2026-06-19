#pragma once
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

// Compact public-domain MD5 (RFC 1321)
namespace md5 {

struct Ctx { uint32_t s[4]; uint64_t n; uint8_t buf[64]; };

#define MD5_ROL(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define MD5_FF(a,b,c,d,x,s,t) (a = (b)+MD5_ROL((a)+((b&c)|(~b&d))+(x)+(t),(s)))
#define MD5_GG(a,b,c,d,x,s,t) (a = (b)+MD5_ROL((a)+((b&d)|(c&~d))+(x)+(t),(s)))
#define MD5_HH(a,b,c,d,x,s,t) (a = (b)+MD5_ROL((a)+(b^c^d)+(x)+(t),(s)))
#define MD5_II(a,b,c,d,x,s,t) (a = (b)+MD5_ROL((a)+(c^(b|~d))+(x)+(t),(s)))

inline void transform(uint32_t s[4], const uint8_t blk[64]) {
    uint32_t a=s[0],b=s[1],c=s[2],d=s[3],x[16];
    for(int i=0;i<16;++i) memcpy(&x[i],blk+4*i,4);
    MD5_FF(a,b,c,d,x[ 0], 7,0xd76aa478); MD5_FF(d,a,b,c,x[ 1],12,0xe8c7b756);
    MD5_FF(c,d,a,b,x[ 2],17,0x242070db); MD5_FF(b,c,d,a,x[ 3],22,0xc1bdceee);
    MD5_FF(a,b,c,d,x[ 4], 7,0xf57c0faf); MD5_FF(d,a,b,c,x[ 5],12,0x4787c62a);
    MD5_FF(c,d,a,b,x[ 6],17,0xa8304613); MD5_FF(b,c,d,a,x[ 7],22,0xfd469501);
    MD5_FF(a,b,c,d,x[ 8], 7,0x698098d8); MD5_FF(d,a,b,c,x[ 9],12,0x8b44f7af);
    MD5_FF(c,d,a,b,x[10],17,0xffff5bb1); MD5_FF(b,c,d,a,x[11],22,0x895cd7be);
    MD5_FF(a,b,c,d,x[12], 7,0x6b901122); MD5_FF(d,a,b,c,x[13],12,0xfd987193);
    MD5_FF(c,d,a,b,x[14],17,0xa679438e); MD5_FF(b,c,d,a,x[15],22,0x49b40821);
    MD5_GG(a,b,c,d,x[ 1], 5,0xf61e2562); MD5_GG(d,a,b,c,x[ 6], 9,0xc040b340);
    MD5_GG(c,d,a,b,x[11],14,0x265e5a51); MD5_GG(b,c,d,a,x[ 0],20,0xe9b6c7aa);
    MD5_GG(a,b,c,d,x[ 5], 5,0xd62f105d); MD5_GG(d,a,b,c,x[10], 9,0x02441453);
    MD5_GG(c,d,a,b,x[15],14,0xd8a1e681); MD5_GG(b,c,d,a,x[ 4],20,0xe7d3fbc8);
    MD5_GG(a,b,c,d,x[ 9], 5,0x21e1cde6); MD5_GG(d,a,b,c,x[14], 9,0xc33707d6);
    MD5_GG(c,d,a,b,x[ 3],14,0xf4d50d87); MD5_GG(b,c,d,a,x[ 8],20,0x455a14ed);
    MD5_GG(a,b,c,d,x[13], 5,0xa9e3e905); MD5_GG(d,a,b,c,x[ 2], 9,0xfcefa3f8);
    MD5_GG(c,d,a,b,x[ 7],14,0x676f02d9); MD5_GG(b,c,d,a,x[12],20,0x8d2a4c8a);
    MD5_HH(a,b,c,d,x[ 5], 4,0xfffa3942); MD5_HH(d,a,b,c,x[ 8],11,0x8771f681);
    MD5_HH(c,d,a,b,x[11],16,0x6d9d6122); MD5_HH(b,c,d,a,x[14],23,0xfde5380c);
    MD5_HH(a,b,c,d,x[ 1], 4,0xa4beea44); MD5_HH(d,a,b,c,x[ 4],11,0x4bdecfa9);
    MD5_HH(c,d,a,b,x[ 7],16,0xf6bb4b60); MD5_HH(b,c,d,a,x[10],23,0xbebfbc70);
    MD5_HH(a,b,c,d,x[13], 4,0x289b7ec6); MD5_HH(d,a,b,c,x[ 0],11,0xeaa127fa);
    MD5_HH(c,d,a,b,x[ 3],16,0xd4ef3085); MD5_HH(b,c,d,a,x[ 6],23,0x04881d05);
    MD5_HH(a,b,c,d,x[ 9], 4,0xd9d4d039); MD5_HH(d,a,b,c,x[12],11,0xe6db99e5);
    MD5_HH(c,d,a,b,x[15],16,0x1fa27cf8); MD5_HH(b,c,d,a,x[ 2],23,0xc4ac5665);
    MD5_II(a,b,c,d,x[ 0], 6,0xf4292244); MD5_II(d,a,b,c,x[ 7],10,0x432aff97);
    MD5_II(c,d,a,b,x[14],15,0xab9423a7); MD5_II(b,c,d,a,x[ 5],21,0xfc93a039);
    MD5_II(a,b,c,d,x[12], 6,0x655b59c3); MD5_II(d,a,b,c,x[ 3],10,0x8f0ccc92);
    MD5_II(c,d,a,b,x[10],15,0xffeff47d); MD5_II(b,c,d,a,x[ 1],21,0x85845dd1);
    MD5_II(a,b,c,d,x[ 8], 6,0x6fa87e4f); MD5_II(d,a,b,c,x[15],10,0xfe2ce6e0);
    MD5_II(c,d,a,b,x[ 6],15,0xa3014314); MD5_II(b,c,d,a,x[13],21,0x4e0811a1);
    MD5_II(a,b,c,d,x[ 4], 6,0xf7537e82); MD5_II(d,a,b,c,x[11],10,0xbd3af235);
    MD5_II(c,d,a,b,x[ 2],15,0x2ad7d2bb); MD5_II(b,c,d,a,x[ 9],21,0xeb86d391);
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d;
}

#undef MD5_ROL
#undef MD5_FF
#undef MD5_GG
#undef MD5_HH
#undef MD5_II

inline void init(Ctx &c) {
    c.s[0]=0x67452301; c.s[1]=0xefcdab89; c.s[2]=0x98badcfe; c.s[3]=0x10325476;
    c.n = 0;
}

inline void update(Ctx &c, const void *data, size_t len) {
    const auto *p = static_cast<const uint8_t*>(data);
    size_t off = (size_t)(c.n & 63);
    c.n += (uint64_t)len;
    if (off) {
        size_t need = 64 - off;
        if (len < need) { memcpy(c.buf+off, p, len); return; }
        memcpy(c.buf+off, p, need); transform(c.s, c.buf);
        p += need; len -= need;
    }
    for (; len >= 64; p += 64, len -= 64) transform(c.s, p);
    if (len) memcpy(c.buf, p, len);
}

inline std::string finalize(Ctx &c) {
    uint64_t bits = c.n * 8;
    uint8_t pad[64]{}; pad[0] = 0x80;
    size_t off = (size_t)(c.n & 63);
    size_t padlen = (off < 56) ? (56 - off) : (120 - off);
    update(c, pad, padlen);
    uint8_t bc[8]; for (int i=0;i<8;i++) bc[i]=(uint8_t)(bits>>(8*i));
    update(c, bc, 8);
    uint8_t raw[16];
    for (int i=0;i<4;i++) { raw[4*i]=(uint8_t)c.s[i]; raw[4*i+1]=(uint8_t)(c.s[i]>>8); raw[4*i+2]=(uint8_t)(c.s[i]>>16); raw[4*i+3]=(uint8_t)(c.s[i]>>24); }
    char hex[33]; for (int i=0;i<16;i++) snprintf(hex+2*i,3,"%02x",raw[i]);
    return std::string(hex, 32);
}

inline std::string hash(const void *data, size_t len) { Ctx c; init(c); update(c, data, len); return finalize(c); }
inline std::string hash(const std::string &s)         { return hash(s.data(), s.size()); }
inline std::string hash(const std::vector<uint8_t> &v){ return hash(v.data(), v.size()); }

} // namespace md5
