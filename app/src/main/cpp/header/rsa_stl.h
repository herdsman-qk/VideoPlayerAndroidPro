//created by kee
//modified by kee on 7/1/2025

#include <bits/stdc++.h>
using namespace std;


namespace KEE_ENC {
        // -----------------------start aes_defs----------------------
        #ifndef _AES_DEFS_
        #define _AES_DEFS_
        typedef unsigned char   u1byte; // an 8 bit unsigned character type
        typedef unsigned short  u2byte; // a 16 bit unsigned integer type
        typedef unsigned long   u4byte; // a 32 bit unsigned integer type

        typedef signed char     s1byte; // an 8 bit signed character type
        typedef signed short    s2byte; // a 16 bit signed integer type
        typedef signed long     s4byte; // a 32 bit signed integer type
        #define LITTLE_ENDIAN
        enum dir_flag { ENC = 1, DEC = 2, BOTH = 3 };
        #   define  inline  __inline
        #   define  STATIC  static
        #   define  false   0
        #   define  true    1
        #   define AESREF   alg_struct
        #   define  IFREF   FILE*
        #   define  OFREF   FILE*
        #   define  IFILE   FILE*
        #   define  OFILE   FILE*
        #ifdef _MSC_VER
        #  pragma intrinsic(_lrotr,_lrotl)
        #  define rotr(x,n) _lrotr(x,n)
        #  define rotl(x,n) _lrotl(x,n)
        #else
        #define rotr(x,n)   (((x) >> ((int)((n) & 0x1f))) | ((x) << ((int)((32 - ((n) & 0x1f))))))
        #define rotl(x,n)   (((x) << ((int)((n) & 0x1f))) | ((x) >> ((int)((32 - ((n) & 0x1f))))))
        #endif
        #define bswap(x)    (rotl(x, 8) & 0x00ff00ff | rotr(x, 8) & 0xff00ff00)
        #ifdef  LITTLE_ENDIAN
        #define u4byte_in(x)        (*(u4byte*)(x))
        #define u4byte_out(x, v)    (*(u4byte*)(x) = (v))
        #else
        #define u4byte_in(x)        bswap(*(u4byte)(x))
        #define u4byte_out(x, v)    (*(u4byte*)(x) = bswap(v))
        #endif

        #endif //_AES_DEFS_
        // --------------------------end aes_defs---------------------

        // -----------------------start rijndael-----------------------------
        #ifndef RIJNDAEL_H
        #define RIJNDAEL_H
        enum dir_flag mode;


        STATIC u4byte  k_len;
        STATIC u4byte  e_key[64];
        STATIC u4byte  d_key[64];

        STATIC u1byte  pow_tab[256];
        STATIC u1byte  log_tab[256];
        STATIC u1byte  sbx_tab[256];
        STATIC u1byte  isb_tab[256];
        STATIC u4byte  rco_tab[ 10];
        STATIC u4byte  ft_tab[4][256];
        STATIC u4byte  it_tab[4][256];

        #ifdef  LARGE_TABLES
          STATIC u4byte  fl_tab[4][256];
          STATIC u4byte  il_tab[4][256];
        #endif

        STATIC u4byte  tab_gen = 0;

        inline u1byte f_mult(u1byte a, u1byte b)
        {   u1byte aa = log_tab[a], cc = aa + log_tab[b];

            return pow_tab[cc + (cc < aa ? 1 : 0)];

        }

        // Extract byte from a 32 bit quantity (little endian notation)

        #define byte(x,n)   ((u1byte)((x) >> (8 * (n))))

        #define ff_mult(a,b)    (a && b ? f_mult(a, b) : 0)

        #define f_rn(bo, bi, n, k)                          \
            bo[n] =  ft_tab[0][byte(bi[n],0)] ^             \
                     ft_tab[1][byte(bi[(n + 1) & 3],1)] ^   \
                     ft_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
                     ft_tab[3][byte(bi[(n + 3) & 3],3)] ^ *(k + n)

        #define i_rn(bo, bi, n, k)                          \
            bo[n] =  it_tab[0][byte(bi[n],0)] ^             \
                     it_tab[1][byte(bi[(n + 3) & 3],1)] ^   \
                     it_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
                     it_tab[3][byte(bi[(n + 1) & 3],3)] ^ *(k + n)

        #ifdef LARGE_TABLES

        #define ls_box(x)                \
            ( fl_tab[0][byte(x, 0)] ^    \
              fl_tab[1][byte(x, 1)] ^    \
              fl_tab[2][byte(x, 2)] ^    \
              fl_tab[3][byte(x, 3)] )

        #define f_rl(bo, bi, n, k)                          \
            bo[n] =  fl_tab[0][byte(bi[n],0)] ^             \
                     fl_tab[1][byte(bi[(n + 1) & 3],1)] ^   \
                     fl_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
                     fl_tab[3][byte(bi[(n + 3) & 3],3)] ^ *(k + n)

        #define i_rl(bo, bi, n, k)                          \
            bo[n] =  il_tab[0][byte(bi[n],0)] ^             \
                     il_tab[1][byte(bi[(n + 3) & 3],1)] ^   \
                     il_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
                     il_tab[3][byte(bi[(n + 1) & 3],3)] ^ *(k + n)

        #else

        #define ls_box(x)                            \
            ((u4byte)sbx_tab[byte(x, 0)] <<  0) ^    \
            ((u4byte)sbx_tab[byte(x, 1)] <<  8) ^    \
            ((u4byte)sbx_tab[byte(x, 2)] << 16) ^    \
            ((u4byte)sbx_tab[byte(x, 3)] << 24)

        #define f_rl(bo, bi, n, k)                                      \
            bo[n] = (u4byte)sbx_tab[byte(bi[n],0)] ^                    \
                rotl(((u4byte)sbx_tab[byte(bi[(n + 1) & 3],1)]),  8) ^  \
                rotl(((u4byte)sbx_tab[byte(bi[(n + 2) & 3],2)]), 16) ^  \
                rotl(((u4byte)sbx_tab[byte(bi[(n + 3) & 3],3)]), 24) ^ *(k + n)

        #define i_rl(bo, bi, n, k)                                      \
            bo[n] = (u4byte)isb_tab[byte(bi[n],0)] ^                    \
                rotl(((u4byte)isb_tab[byte(bi[(n + 3) & 3],1)]),  8) ^  \
                rotl(((u4byte)isb_tab[byte(bi[(n + 2) & 3],2)]), 16) ^  \
                rotl(((u4byte)isb_tab[byte(bi[(n + 1) & 3],3)]), 24) ^ *(k + n)

        #endif

        STATIC void gen_tabs(void)
        {   u4byte  i, t;
            u1byte  p, q;

            // log and power tables for GF(2**8) finite field with
            // 0x011b as modular polynomial - the simplest prmitive
            // root is 0x03, used here to generate the tables

            for(i = 0,p = 1; i < 256; ++i)
            {
                pow_tab[i] = (u1byte)p; log_tab[p] = (u1byte)i;

                p ^=  (p << 1) ^ (p & 0x80 ? 0x01b : 0);
            }

            log_tab[1] = 0;

            for(i = 0,p = 1; i < 10; ++i)
            {
                rco_tab[i] = p;

                p = (p << 1) ^ (p & 0x80 ? 0x01b : 0);
            }

            for(i = 0; i < 256; ++i)
            {
                p = (i ? pow_tab[255 - log_tab[i]] : 0);
                q  = ((p >> 7) | (p << 1)) ^ ((p >> 6) | (p << 2));
                p ^= 0x63 ^ q ^ ((q >> 6) | (q << 2));
                sbx_tab[i] = p; isb_tab[p] = (u1byte)i;
            }

            for(i = 0; i < 256; ++i)
            {
                p = sbx_tab[i];

        #ifdef  LARGE_TABLES

                t = p; fl_tab[0][i] = t;
                fl_tab[1][i] = rotl(t,  8);
                fl_tab[2][i] = rotl(t, 16);
                fl_tab[3][i] = rotl(t, 24);
        #endif
                t = ((u4byte)ff_mult(2, p)) |
                    ((u4byte)p <<  8) |
                    ((u4byte)p << 16) |
                    ((u4byte)ff_mult(3, p) << 24);

                ft_tab[0][i] = t;
                ft_tab[1][i] = rotl(t,  8);
                ft_tab[2][i] = rotl(t, 16);
                ft_tab[3][i] = rotl(t, 24);

                p = isb_tab[i];

        #ifdef  LARGE_TABLES

                t = p; il_tab[0][i] = t;
                il_tab[1][i] = rotl(t,  8);
                il_tab[2][i] = rotl(t, 16);
                il_tab[3][i] = rotl(t, 24);
        #endif
                t = ((u4byte)ff_mult(14, p)) |
                    ((u4byte)ff_mult( 9, p) <<  8) |
                    ((u4byte)ff_mult(13, p) << 16) |
                    ((u4byte)ff_mult(11, p) << 24);

                it_tab[0][i] = t;
                it_tab[1][i] = rotl(t,  8);
                it_tab[2][i] = rotl(t, 16);
                it_tab[3][i] = rotl(t, 24);
            }

            tab_gen = 1;
        }

        #define star_x(x) (((x) & 0x7f7f7f7f) << 1) ^ ((((x) & 0x80808080) >> 7) * 0x1b)

        #define imix_col(y,x)       \
            u   = star_x(x);        \
            v   = star_x(u);        \
            w   = star_x(v);        \
            t   = w ^ (x);          \
           (y)  = u ^ v ^ w;        \
           (y) ^= rotr(u ^ t,  8) ^ \
                  rotr(v ^ t, 16) ^ \
                  rotr(t,24)



        // initialise the key schedule from the user supplied key

        #define loop4(i)                                    \
        {   t = rotr(t,  8); t = ls_box(t) ^ rco_tab[i];    \
            t ^= e_key[4 * i];     e_key[4 * i + 4] = t;    \
            t ^= e_key[4 * i + 1]; e_key[4 * i + 5] = t;    \
            t ^= e_key[4 * i + 2]; e_key[4 * i + 6] = t;    \
            t ^= e_key[4 * i + 3]; e_key[4 * i + 7] = t;    \
        }

        #define loop6(i)                                    \
        {   t = rotr(t,  8); t = ls_box(t) ^ rco_tab[i];    \
            t ^= e_key[6 * i];     e_key[6 * i + 6] = t;    \
            t ^= e_key[6 * i + 1]; e_key[6 * i + 7] = t;    \
            t ^= e_key[6 * i + 2]; e_key[6 * i + 8] = t;    \
            t ^= e_key[6 * i + 3]; e_key[6 * i + 9] = t;    \
            t ^= e_key[6 * i + 4]; e_key[6 * i + 10] = t;   \
            t ^= e_key[6 * i + 5]; e_key[6 * i + 11] = t;   \
        }

        #define loop8(i)                                    \
        {   t = rotr(t,  8); ; t = ls_box(t) ^ rco_tab[i];  \
            t ^= e_key[8 * i];     e_key[8 * i + 8] = t;    \
            t ^= e_key[8 * i + 1]; e_key[8 * i + 9] = t;    \
            t ^= e_key[8 * i + 2]; e_key[8 * i + 10] = t;   \
            t ^= e_key[8 * i + 3]; e_key[8 * i + 11] = t;   \
            t  = e_key[8 * i + 4] ^ ls_box(t);    \
            e_key[8 * i + 12] = t;                \
            t ^= e_key[8 * i + 5]; e_key[8 * i + 13] = t;   \
            t ^= e_key[8 * i + 6]; e_key[8 * i + 14] = t;   \
            t ^= e_key[8 * i + 7]; e_key[8 * i + 15] = t;   \
        }

        void set_key(const u1byte in_key[], const u4byte key_len, const enum dir_flag f)
        {   u4byte  i, t, u, v, w;

            if(!tab_gen)

                gen_tabs();

            mode = f;

            k_len = (key_len + 31) / 32;

            e_key[0] = u4byte_in(in_key     );
            e_key[1] = u4byte_in(in_key +  4);
            e_key[2] = u4byte_in(in_key +  8);
            e_key[3] = u4byte_in(in_key + 12);

        #if(0)

            {   u4byte  *k1, *k2, *km, *rcp;
                if(k_len > 4)
                {
                    e_key[4] = u4byte_in(in_key + 16);
                    e_key[5] = u4byte_in(in_key + 20);
                }

                if(k_len > 6)
                {
                    e_key[6] = u4byte_in(in_key + 24);
                    e_key[7] = u4byte_in(in_key + 28);
                }

                rcp = rco_tab; k1 = e_key;
                k2 = k1 + k_len;
                km = k1 + 5 * k_len + 24;
                t = *(k2 - 1);

                switch(k_len)
                {
                    case 4: while(k2 < km)
                            {
                                t = ls_box(rotr(t,  8)) ^ *rcp++;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                            }
                            break;

                    case 6: while(k2 < km)
                            {
                                t = ls_box(rotr(t,  8)) ^ *rcp++;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                            }
                            break;

                    case 8: while(k2 < km)
                            {
                                t = ls_box(rotr(t,  8)) ^ *rcp++;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t = ls_box(t);
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                                t ^= *k1++; *k2++ = t;
                            }
                            break;
                }
            }

        #else

            switch(k_len)
            {
                case 4: t = e_key[3];
                        for(i = 0; i < 10; ++i)
                            loop4(i);
                        break;

                case 6: e_key[4] = u4byte_in(in_key + 16);
                        t = e_key[5] = u4byte_in(in_key + 20);
                        for(i = 0; i < 8; ++i)
                            loop6(i);
                        break;

                case 8: e_key[4] = u4byte_in(in_key + 16);
                        e_key[5] = u4byte_in(in_key + 20);
                        e_key[6] = u4byte_in(in_key + 24);
                        t = e_key[7] = u4byte_in(in_key + 28);
                        for(i = 0; i < 7; ++i)
                            loop8(i);
                        break;
            }

        #endif

            if(mode != ENC)
            {
                d_key[0] = e_key[0]; d_key[1] = e_key[1];
                d_key[2] = e_key[2]; d_key[3] = e_key[3];

                for(i = 4; i < 4 * k_len + 24; ++i)
                {
                    imix_col(d_key[i], e_key[i]);
                }
            }

            return;
        }

        // encrypt a block of text

        #define f_nround(bo, bi, k) \
            f_rn(bo, bi, 0, k);     \
            f_rn(bo, bi, 1, k);     \
            f_rn(bo, bi, 2, k);     \
            f_rn(bo, bi, 3, k);     \
            k += 4

        #define f_lround(bo, bi, k) \
            f_rl(bo, bi, 0, k);     \
            f_rl(bo, bi, 1, k);     \
            f_rl(bo, bi, 2, k);     \
            f_rl(bo, bi, 3, k)

        void encrypt(const u1byte in_blk[16], u1byte out_blk[16])
        {   u4byte  b0[4], b1[4], *kp;

            b0[0] = u4byte_in(in_blk    ) ^ e_key[0];
            b0[1] = u4byte_in(in_blk +  4) ^ e_key[1];
            b0[2] = u4byte_in(in_blk + 8) ^ e_key[2];
            b0[3] = u4byte_in(in_blk + 12) ^ e_key[3];

            kp = e_key + 4;

            if(k_len > 6)
            {
                f_nround(b1, b0, kp); f_nround(b0, b1, kp);
            }

            if(k_len > 4)
            {
                f_nround(b1, b0, kp); f_nround(b0, b1, kp);
            }

            f_nround(b1, b0, kp); f_nround(b0, b1, kp);
            f_nround(b1, b0, kp); f_nround(b0, b1, kp);
            f_nround(b1, b0, kp); f_nround(b0, b1, kp);
            f_nround(b1, b0, kp); f_nround(b0, b1, kp);
            f_nround(b1, b0, kp); f_lround(b0, b1, kp);

            u4byte_out(out_blk,      b0[0]); u4byte_out(out_blk +  4, b0[1]);
            u4byte_out(out_blk +  8, b0[2]); u4byte_out(out_blk + 12, b0[3]);
        }

        // decrypt a block of text

        #define i_nround(bo, bi, k) \
            i_rn(bo, bi, 0, k);     \
            i_rn(bo, bi, 1, k);     \
            i_rn(bo, bi, 2, k);     \
            i_rn(bo, bi, 3, k);     \
            k -= 4

        #define i_lround(bo, bi, k) \
            i_rl(bo, bi, 0, k);     \
            i_rl(bo, bi, 1, k);     \
            i_rl(bo, bi, 2, k);     \
            i_rl(bo, bi, 3, k)

        void decrypt(const u1byte in_blk[16], u1byte out_blk[16])
        {   u4byte  b0[4], b1[4], *kp;

            b0[0] = u4byte_in(in_blk     ) ^ e_key[4 * k_len + 24];
            b0[1] = u4byte_in(in_blk +  4) ^ e_key[4 * k_len + 25];
            b0[2] = u4byte_in(in_blk +  8) ^ e_key[4 * k_len + 26];
            b0[3] = u4byte_in(in_blk + 12) ^ e_key[4 * k_len + 27];

            kp = d_key + 4 * (k_len + 5);

            if(k_len > 6)
            {
                i_nround(b1, b0, kp); i_nround(b0, b1, kp);
            }

            if(k_len > 4)
            {
                i_nround(b1, b0, kp); i_nround(b0, b1, kp);
            }

            i_nround(b1, b0, kp); i_nround(b0, b1, kp);
            i_nround(b1, b0, kp); i_nround(b0, b1, kp);
            i_nround(b1, b0, kp); i_nround(b0, b1, kp);
            i_nround(b1, b0, kp); i_nround(b0, b1, kp);
            i_nround(b1, b0, kp); i_lround(b0, b1, kp);

            u4byte_out(out_blk,     b0[0]); u4byte_out(out_blk +  4, b0[1]);
            u4byte_out(out_blk + 8, b0[2]); u4byte_out(out_blk + 12, b0[3]);
        }
        #endif // RIJNDAEL_H
        // --------------------end rijndael--------------------

        // -------------------start sha1----------------------
        #ifndef _SHA1_H
        #define _SHA1_H


        typedef   unsigned int     sha1_32t;

        #define SHA1_BLOCK_SIZE  64
        #define SHA1_DIGEST_SIZE 20

        typedef struct
        {   sha1_32t count[2];
            sha1_32t hash[5];
            sha1_32t wbuf[16];
        } sha1_ctx;

        #define SHA_LITTLE_ENDIAN   1234 /* byte 0 is least significant (i386) */
        #define SHA_BIG_ENDIAN      4321 /* byte 0 is most significant (mc68k) */

        #define PLATFORM_BYTE_ORDER SHA_LITTLE_ENDIAN

        #define rotl32(x,n) (((x) << n) | ((x) >> (32 - n)))

        #if (PLATFORM_BYTE_ORDER == SHA_BIG_ENDIAN)
        #define swap_b32(x) (x)
        #else
        #define swap_b32(x) ((rotl32((x), 8) & 0x00ff00ff) | (rotl32((x), 24) & 0xff00ff00))
        #endif

        #define SHA1_MASK   (SHA1_BLOCK_SIZE - 1)

        /* reverse byte order in 32-bit words   */

        #define ch(x,y,z)       (((x) & (y)) ^ (~(x) & (z)))
        #define parity(x,y,z)   ((x) ^ (y) ^ (z))
        #define maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

        /* A normal version as set out in the FIPS. This version uses   */
        /* partial loop unrolling and is optimised for the Pentium 4    */

        #define rnd(f,k)    \
            t = a; a = rotl32(a,5) + f(b,c,d) + e + k + w[i]; \
            e = d; d = c; c = rotl32(b, 30); b = t

        void sha1_compile(sha1_ctx ctx[1])
        {   sha1_32t    w[80], i, a, b, c, d, e, t;

            /* note that words are compiled from the buffer into 32-bit */
            /* words in big-endian order so an order reversal is needed */
            /* here on little endian machines                           */
            for(i = 0; i < SHA1_BLOCK_SIZE / 4; ++i)
                w[i] = swap_b32(ctx->wbuf[i]);

            for(i = SHA1_BLOCK_SIZE / 4; i < 80; ++i)
                w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

            a = ctx->hash[0];
            b = ctx->hash[1];
            c = ctx->hash[2];
            d = ctx->hash[3];
            e = ctx->hash[4];

            for(i = 0; i < 20; ++i)
            {
                rnd(ch, 0x5a827999);
            }

            for(i = 20; i < 40; ++i)
            {
                rnd(parity, 0x6ed9eba1);
            }

            for(i = 40; i < 60; ++i)
            {
                rnd(maj, 0x8f1bbcdc);
            }

            for(i = 60; i < 80; ++i)
            {
                rnd(parity, 0xca62c1d6);
            }

            ctx->hash[0] += a;
            ctx->hash[1] += b;
            ctx->hash[2] += c;
            ctx->hash[3] += d;
            ctx->hash[4] += e;
        }

        void sha1_begin(sha1_ctx ctx[1])
        {
            ctx->count[0] = ctx->count[1] = 0;
            ctx->hash[0] = 0x67452301;
            ctx->hash[1] = 0xefcdab89;
            ctx->hash[2] = 0x98badcfe;
            ctx->hash[3] = 0x10325476;
            ctx->hash[4] = 0xc3d2e1f0;
        }

        /* SHA1 hash data in an array of bytes into hash buffer and call the        */
        /* hash_compile function as required.                                       */

        void sha1_hash(const unsigned char data[], unsigned int len, sha1_ctx ctx[1])
        {   sha1_32t pos = (sha1_32t)(ctx->count[0] & SHA1_MASK),
                     space = SHA1_BLOCK_SIZE - pos;
            const unsigned char *sp = data;

            if((ctx->count[0] += len) < len)
                ++(ctx->count[1]);

            while(len >= space)     /* tranfer whole blocks while possible  */
            {
                memcpy(((unsigned char*)ctx->wbuf) + pos, sp, space);
                sp += space; len -= space; space = SHA1_BLOCK_SIZE; pos = 0;
                sha1_compile(ctx);
            }

            memcpy(((unsigned char*)ctx->wbuf) + pos, sp, len);
        }

        /* SHA1 final padding and digest calculation  */

        #if (PLATFORM_BYTE_ORDER == SHA_LITTLE_ENDIAN)
        static sha1_32t  mask[4] =
                {   0x00000000, 0x000000ff, 0x0000ffff, 0x00ffffff };
        static sha1_32t  bits[4] =
                {   0x00000080, 0x00008000, 0x00800000, 0x80000000 };
        #else
        static sha1_32t  mask[4] =
                {   0x00000000, 0xff000000, 0xffff0000, 0xffffff00 };
        static sha1_32t  bits[4] =
                {   0x80000000, 0x00800000, 0x00008000, 0x00000080 };
        #endif

        void sha1_end(unsigned char hval[], sha1_ctx ctx[1])
        {   sha1_32t    i = (sha1_32t)(ctx->count[0] & SHA1_MASK);

            /* mask out the rest of any partial 32-bit word and then set    */
            /* the next byte to 0x80. On big-endian machines any bytes in   */
            /* the buffer will be at the top end of 32 bit words, on little */
            /* endian machines they will be at the bottom. Hence the AND    */
            /* and OR masks above are reversed for little endian systems    */
                /* Note that we can always add the first padding byte at this	*/
                /* because the buffer always contains at least one empty slot	*/
            ctx->wbuf[i >> 2] = (ctx->wbuf[i >> 2] & mask[i & 3]) | bits[i & 3];

            /* we need 9 or more empty positions, one for the padding byte  */
            /* (above) and eight for the length count.  If there is not     */
            /* enough space pad and empty the buffer                        */
            if(i > SHA1_BLOCK_SIZE - 9)
            {
                if(i < 60) ctx->wbuf[15] = 0;
                sha1_compile(ctx);
                i = 0;
            }
            else    /* compute a word index for the empty buffer positions  */
                i = (i >> 2) + 1;

            while(i < 14) /* and zero pad all but last two positions      */
                ctx->wbuf[i++] = 0;

            /* assemble the eight byte counter in in big-endian format		*/
            ctx->wbuf[14] = swap_b32((ctx->count[1] << 3) | (ctx->count[0] >> 29));
            ctx->wbuf[15] = swap_b32(ctx->count[0] << 3);

            sha1_compile(ctx);

            /* extract the hash value as bytes in case the hash buffer is   */
            /* misaligned for 32-bit words                                  */
            for(i = 0; i < SHA1_DIGEST_SIZE; ++i)
                hval[i] = (unsigned char)(ctx->hash[i >> 2] >> 8 * (~i & 3));
        }

        void sha1(unsigned char hval[], const unsigned char data[], unsigned int len)
        {   sha1_ctx    cx[1];

            sha1_begin(cx); sha1_hash(data, len, cx); sha1_end(hval, cx);
        }
        #endif
        // ---------------end sha1---------------

        // ------------------start utils---------------------
        #ifndef HEADER_UTILS_H
        #define HEADER_UTILS_H

        void cleanse(void *ptr, unsigned int len);

        unsigned char cleanse_ctr = 0;

        void cleanse(void *ptr, unsigned int len) {
                unsigned char *p = (unsigned char *)ptr;
                unsigned int loop = len, ctr = cleanse_ctr;
                while(loop--) {
                        *(p++) = (unsigned char)ctr;
                        ctr += (17 + ((intptr_t)p & 0xF));
                }
                p=(unsigned char *) memchr((unsigned char *)ptr, (unsigned char)ctr, len);
                if(p) ctr += (63 + (intptr_t)p);
                cleanse_ctr = (unsigned char)ctr;
        }

        #endif //_SHA1_H
        // --------------end utils----------------

        // --------------------start bn------------------
        #ifndef _HEADER_BN_H_
        #define _HEADER_BN_H_

        #define BN_ULLONG	unsigned __int64
        #define BN_ULONG	unsigned long
        #define BN_LONG		long
        #define BN_BITS		64
        #define BN_BYTES	4
        #define BN_BITS2	32
        #define BN_BITS4	16
        #define BN_MASK		(0xffffffffffffffffLL)
        #define BN_MASK2	(0xffffffffL)
        #define BN_MASK2l	(0xffff)
        #define BN_TBIT		(0x80000000L)
        #define BN_DEFAULT_BITS	1280
        #define BN_FLG_MALLOCED		0x01
        #define BN_FLG_STATIC_DATA	0x02
        #define BN_FLG_CONSTTIME	0x04
        #define BN_get_flags(b,n)	((b)->flags&(n))

        typedef struct bignum_st BIGNUM;
        typedef struct bignum_ctx BN_CTX;
        typedef struct bn_mont_ctx_st BN_MONT_CTX;
        typedef struct bn_gencb_st BN_GENCB;
        void BN_with_flags(BIGNUM *dest,const BIGNUM *b, int n);
        struct bignum_st
                {
                BN_ULONG *d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
                int top;	/* Index of last used d +1. */
                /* The next are internal book keeping for bn_expand. */
                int dmax;	/* Size of the d array. */
                int neg;	/* one if the number is negative */
                int flags;/* negative?positive*/
                };

        /* Used for montgomery multiplication */
        struct bn_mont_ctx_st
                {
                int ri;        /* number of bits in R */
                BIGNUM RR;     /* used to convert to montgomery form */
                BIGNUM N;      /* The modulus */
                BIGNUM Ni;     /* R*(1/R mod N) - N*Ni = 1
                                * (Ni is only stored for bignum algorithm) */
                BN_ULONG n0;   /* least significant word of Ni */
                int flags;
                };

        /* Used for slow "generation" functions. */
        struct bn_gencb_st
                {
                unsigned int ver;	/* To handle binary (in)compatibility */
                void *arg;		/* callback-specific data */
                union
                        {
                        /* if(ver==1) - handles old style callbacks */
                        void (*cb_1)(int, int, void *);
                        /* if(ver==2) - new callback style */
                        int (*cb_2)(int, int, BN_GENCB *);
                        } cb;
                };
        int BN_GENCB_call(BN_GENCB *cb, int a, int b);
        /* Macro to populate a BN_GENCB structure with a "new"-style callback */
        #define BN_GENCB_set(gencb, callback, cb_arg) { \
                        BN_GENCB *tmp_gencb = (gencb); \
                        tmp_gencb->ver = 2; \
                        tmp_gencb->arg = (cb_arg); \
                        tmp_gencb->cb.cb_2 = (callback); }

        #define BN_prime_checks 0
        int BN_prime_checks_for_size(int b);
        #define BN_num_bytes(a)	((BN_num_bits(a)+7)/8)
        #define BN_abs_is_word(a,w) ((((a)->top == 1) && ((a)->d[0] == (BN_ULONG)(w))) || \
                                        (((w) == 0) && ((a)->top == 0)))
        #define BN_is_zero(a)       ((a)->top == 0)
        #define BN_is_one(a)        (BN_abs_is_word((a),1) && !(a)->neg)
        #define BN_is_word(a,w)     (BN_abs_is_word((a),(w)) && (!(w) || !(a)->neg))
        #define BN_is_odd(a)	    (((a)->top > 0) && ((a)->d[0] & 1))
        #define BN_one(a)	(BN_set_word((a),1))
        #define BN_zero(a)	(BN_set_word((a),0))
        const BIGNUM *BN_value_one(void);
        BN_CTX *BN_CTX_new(void);
        void	BN_CTX_free(BN_CTX *c);
        void	BN_CTX_start(BN_CTX *ctx);
        BIGNUM *BN_CTX_get(BN_CTX *ctx);
        void	BN_CTX_end(BN_CTX *ctx);
        int     BN_rand(BIGNUM *rnd, int bits, int top,int bottom);
        int     BN_pseudo_rand(BIGNUM *rnd, int bits, int top,int bottom);
        int	BN_rand_range(BIGNUM *rnd, BIGNUM *range);
        int	BN_pseudo_rand_range(BIGNUM *rnd, BIGNUM *range);
        int	BN_num_bits(const BIGNUM *a);
        int	BN_num_bits_word(BN_ULONG);
        BIGNUM *BN_new(void);
        void	BN_init(BIGNUM *);
        BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
        BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
        int	BN_bn2bin(const BIGNUM *a, unsigned char *to);
        int	BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
        int	BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
        int	BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
        int	BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
        int	BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
        int	BN_sqr(BIGNUM *r, const BIGNUM *a,BN_CTX *ctx);
        void	BN_set_negative(BIGNUM *b, int n);
        #define BN_is_negative(a) ((a)->neg != 0)

        int	BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
                BN_CTX *ctx);
        #define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
        int	BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
        int	BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
        int	BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
        int	BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
        int	BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
        int	BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                const BIGNUM *m, BN_CTX *ctx);
        int	BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);

        BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
        int	BN_mul_word(BIGNUM *a, BN_ULONG w);
        int	BN_add_word(BIGNUM *a, BN_ULONG w);
        int	BN_sub_word(BIGNUM *a, BN_ULONG w);
        int	BN_set_word(BIGNUM *a, BN_ULONG w);
        BN_ULONG BN_get_word(const BIGNUM *a);

        int	BN_cmp(const BIGNUM *a, const BIGNUM *b);
        void	BN_free(BIGNUM *a);
        int	BN_is_bit_set(const BIGNUM *a, int n);
        int	BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
        int	BN_lshift1(BIGNUM *r, const BIGNUM *a);
        int	BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                const BIGNUM *m, BN_CTX *ctx);
        int	BN_mask_bits(BIGNUM *a,int n);
        int	BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
        int	BN_rshift1(BIGNUM *r, const BIGNUM *a);
        int	BN_ucmp(const BIGNUM *a, const BIGNUM *b);
        int	BN_set_bit(BIGNUM *a, int n);
        int	BN_gcd(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,BN_CTX *ctx);
        BIGNUM *BN_mod_inverse(BIGNUM *ret,
                const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
        BIGNUM *BN_mod_sqrt(BIGNUM *ret,
                const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);

        /* Newer versions */
        //int	BN_generate_prime_ex(BIGNUM *ret,int bits,int safe, const BIGNUM *add,
        //		const BIGNUM *rem, int prime, BN_GENCB *cb);
        int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe,
                const BIGNUM *add, const BIGNUM *rem);
        int	BN_is_prime_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx, BN_GENCB *cb);
        int	BN_is_prime_fasttest_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx,
                        int do_trial_division);

        BN_MONT_CTX *BN_MONT_CTX_new(void );
        void BN_MONT_CTX_init(BN_MONT_CTX *ctx);
        int BN_mod_mul_montgomery(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,
                BN_MONT_CTX *mont, BN_CTX *ctx);
        #define BN_to_montgomery(r,a,mont,ctx)	BN_mod_mul_montgomery(\
                (r),(a),&((mont)->RR),(mont),(ctx))
        int BN_from_montgomery(BIGNUM *r,const BIGNUM *a,
                BN_MONT_CTX *mont, BN_CTX *ctx);
        void BN_MONT_CTX_free(BN_MONT_CTX *mont);
        int BN_MONT_CTX_set(BN_MONT_CTX *mont,const BIGNUM *mod,BN_CTX *ctx);
        BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to,BN_MONT_CTX *from);
        BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock,
                                                const BIGNUM *mod, BN_CTX *ctx);
        int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                            const BIGNUM *m, BN_CTX *ctx);
        int RAND_bytes(unsigned char *buf, int num);
        void BN_clear(BIGNUM *a);
        /* library internal functions */
        #define bn_expand(a,bits) ((((((bits+BN_BITS2-1))/BN_BITS2)) <= (a)->dmax)?\
                (a):bn_expand2((a),(bits+BN_BITS2-1)/BN_BITS2))
        #define bn_wexpand(a,words) (((words) <= (a)->dmax)?(a):bn_expand2((a),(words)))
        BIGNUM *bn_expand2(BIGNUM *a, int words);
        #define bn_pollute(a)
        #define bn_check_top(a)
        #define bn_fix_top(a)		bn_correct_top(a)

        void bn_correct_top(BIGNUM *a);
        BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
        BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
        void     bn_sqr_words(BN_ULONG *rp, const BN_ULONG *ap, int num);
        BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d);
        BN_ULONG bn_add_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);
        BN_ULONG bn_sub_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);



        #define BN_window_bits_for_exponent_size(b) \
                        ((b) > 671 ? 6 : \
                         (b) > 239 ? 5 : \
                         (b) >  79 ? 4 : \
                         (b) >  23 ? 3 : 1)
        #define MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH	( 64 )
        #define MOD_EXP_CTIME_MIN_CACHE_LINE_MASK	(MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - 1)
        #define BN_window_bits_for_ctime_exponent_size(b) \
                        ((b) > 937 ? 6 : \
                         (b) > 306 ? 5 : \
                         (b) >  89 ? 4 : \
                         (b) >  22 ? 3 : 1)
        #define BN_MAX_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE	(6)
        #define BN_MULL_SIZE_NORMAL			(16) /* 32 */
        #define BN_MUL_RECURSIVE_SIZE_NORMAL		(16) /* 32 less than */
        #define BN_SQR_RECURSIVE_SIZE_NORMAL		(16) /* 32 */
        #define BN_MONT_CTX_SET_SIZE_WORD		(64) /* 32 */
        /*************************************************************
         * Using the long long type
         */
        #define Lw(t)    (((BN_ULONG)(t))&BN_MASK2)
        #define Hw(t)    (((BN_ULONG)((t)>>BN_BITS2))&BN_MASK2)
        #define bn_clear_top2max(a)
        /*
        void mul_add(BN_ULONG *r,const BN_ULONG a,BN_ULONG w,BN_ULONG *c);
        void mul(BN_ULONG *r,const BN_ULONG a,BN_ULONG w,BN_ULONG *c);
        void sqr(BN_ULONG *r0,BN_ULONG *r1,const BN_ULONG a);
        */
        void bn_mul_normal(BN_ULONG *r,BN_ULONG *a,int na,BN_ULONG *b,int nb);
        void bn_sqr_normal(BN_ULONG *r, const BN_ULONG *a, int n, BN_ULONG *tmp);
        int bn_cmp_words(const BN_ULONG *a,const BN_ULONG *b,int n);
        int bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b,
                int cl, int dl);
        void bn_mul_recursive(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b,int n2,
                int dna,int dnb,BN_ULONG *t);
        void bn_mul_part_recursive(BN_ULONG *r,BN_ULONG *a,BN_ULONG *b,
                int n,int tna,int tnb,BN_ULONG *t);
        void bn_sqr_recursive(BN_ULONG *r,const BN_ULONG *a, int n2, BN_ULONG *t);
        BN_ULONG bn_add_part_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                int cl, int dl);
        BN_ULONG bn_sub_part_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                int cl, int dl);

        //add

        int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
                {
                const BIGNUM *tmp;
                int a_neg = a->neg, ret;

                bn_check_top(a);
                bn_check_top(b);
                if (a_neg ^ b->neg)
                        {
                        if (a_neg)
                                { tmp=a; a=b; b=tmp; }
                        if (BN_ucmp(a,b) < 0)
                                {
                                if (!BN_usub(r,b,a)) return(0);
                                r->neg=1;
                                }
                        else
                                {
                                if (!BN_usub(r,a,b)) return(0);
                                r->neg=0;
                                }
                        return(1);
                        }

                ret = BN_uadd(r,a,b);
                r->neg = a_neg;
                bn_check_top(r);
                return ret;
                }

        int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
                {
                int max,min,dif;
                BN_ULONG *ap,*bp,*rp,carry,t1,t2;
                const BIGNUM *tmp;

                bn_check_top(a);
                bn_check_top(b);

                if (a->top < b->top)
                        { tmp=a; a=b; b=tmp; }
                max = a->top;
                min = b->top;
                dif = max - min;

                if (bn_wexpand(r,max+1) == NULL)
                        return 0;

                r->top=max;
                ap=a->d;
                bp=b->d;
                rp=r->d;

                carry=bn_add_words(rp,ap,bp,min);
                rp+=min;
                ap+=min;
                bp+=min;

                if (carry)
                        {
                        while (dif)
                                {
                                dif--;
                                t1 = *(ap++);
                                t2 = (t1+1) & BN_MASK2;
                                *(rp++) = t2;
                                if (t2)
                                        {
                                        carry=0;
                                        break;
                                        }
                                }
                        if (carry)
                                {
                                *rp = 1;
                                r->top++;
                                }
                        }
                if (dif && rp != ap)
                        while (dif--)
                                /* copy remaining words if ap != rp */
                                *(rp++) = *(ap++);
                r->neg = 0;
                bn_check_top(r);
                return 1;
                }

        /* unsigned subtraction of b from a, a must be larger than b. */
        int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
                {
                int max,min,dif;
                register BN_ULONG t1,t2,*ap,*bp,*rp;
                int i,carry;
                bn_check_top(a);
                bn_check_top(b);
                max = a->top;
                min = b->top;
                dif = max - min;

                if (dif < 0)	/* hmm... should not be happening */
                        return(0);

                if (bn_wexpand(r,max) == NULL) return(0);

                ap=a->d;
                bp=b->d;
                rp=r->d;

                carry=0;
                for (i = min; i != 0; i--)
                        {
                        t1= *(ap++);
                        t2= *(bp++);
                        if (carry)
                                {
                                carry=(t1 <= t2);
                                t1=(t1-t2-1)&BN_MASK2;
                                }
                        else
                                {
                                carry=(t1 < t2);
                                t1=(t1-t2)&BN_MASK2;
                                }
                        *(rp++)=t1&BN_MASK2;
                        }
                if (carry) /* subtracted */
                        {
                        if (!dif)
                                /* error: a < b */
                                return 0;
                        while (dif)
                                {
                                dif--;
                                t1 = *(ap++);
                                t2 = (t1-1)&BN_MASK2;
                                *(rp++) = t2;
                                if (t1)
                                        break;
                                }
                        }
                if (rp != ap)
                        {
                        for (;;)
                                {
                                if (!dif--) break;
                                rp[0]=ap[0];
                                if (!dif--) break;
                                rp[1]=ap[1];
                                if (!dif--) break;
                                rp[2]=ap[2];
                                if (!dif--) break;
                                rp[3]=ap[3];
                                rp+=4;
                                ap+=4;
                                }
                        }
                r->top=max;
                r->neg=0;
                bn_correct_top(r);
                return(1);
                }

        int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
                {
                int max;
                int add=0,neg=0;
                const BIGNUM *tmp;

                bn_check_top(a);
                bn_check_top(b);
                if (a->neg)
                        {
                        if (b->neg)
                                { tmp=a; a=b; b=tmp; }
                        else
                                { add=1; neg=1; }
                        }
                else
                        {
                        if (b->neg) { add=1; neg=0; }
                        }

                if (add)
                        {
                        if (!BN_uadd(r,a,b)) return(0);
                        r->neg=neg;
                        return(1);
                        }

                /* We are actually doing a - b :-) */
                max=(a->top > b->top)?a->top:b->top;
                if (bn_wexpand(r,max) == NULL) return(0);
                if (BN_ucmp(a,b) < 0)
                        {
                        if (!BN_usub(r,b,a)) return(0);
                        r->neg=1;
                        }
                else
                        {
                        if (!BN_usub(r,a,b)) return(0);
                        r->neg=0;
                        }
                bn_check_top(r);
                return(1);
                }


        /* maximum precomputation table size for *variable* sliding windows */
        #define TABLE_SIZE	32
        int BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                            const BIGNUM *m, BN_CTX *ctx)
                {
                int i,j,bits,ret=0,wstart,wend,window,wvalue;
                int start=1;
                BIGNUM *d,*r;
                const BIGNUM *aa;
                /* Table of variables obtained from 'ctx' */
                BIGNUM *val[TABLE_SIZE];
                BN_MONT_CTX *mont=NULL;

                if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0)
                {
                        return BN_mod_exp_mont_consttime(rr, a, p, m, ctx);
                }

                bn_check_top(a);
                bn_check_top(p);
                bn_check_top(m);

                if (!BN_is_odd(m))
                        return(0);
                bits=BN_num_bits(p);
                if (bits == 0)
                        {
                        ret = BN_one(rr);
                        return ret;
                        }

                BN_CTX_start(ctx);
                d = BN_CTX_get(ctx);
                r = BN_CTX_get(ctx);
                val[0] = BN_CTX_get(ctx);
                if (!d || !r || !val[0]) goto err;

                /* If this is not done, things will break in the montgomery
                 * part */


                        {
                        if ((mont=BN_MONT_CTX_new()) == NULL) goto err;
                        if (!BN_MONT_CTX_set(mont,m,ctx)) goto err;
                        }

                if (a->neg || BN_ucmp(a,m) >= 0)
                        {
                        if (!BN_nnmod(val[0],a,m,ctx))
                                goto err;
                        aa= val[0];
                        }
                else
                        aa=a;
                if (BN_is_zero(aa))
                        {
                        BN_zero(rr);
                        ret = 1;
                        goto err;
                        }
                if (!BN_to_montgomery(val[0],aa,mont,ctx)) goto err; /* 1 */

                window = BN_window_bits_for_exponent_size(bits);
                if (window > 1)
                        {
                        if (!BN_mod_mul_montgomery(d,val[0],val[0],mont,ctx)) goto err; /* 2 */
                        j=1<<(window-1);
                        for (i=1; i<j; i++)
                                {
                                if(((val[i] = BN_CTX_get(ctx)) == NULL) ||
                                                !BN_mod_mul_montgomery(val[i],val[i-1],
                                                        d,mont,ctx))
                                        goto err;
                                }
                        }

                start=1;	/* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
                wvalue=0;	/* The 'value' of the window */
                wstart=bits-1;	/* The top bit of the window */
                wend=0;		/* The bottom bit of the window */

                if (!BN_to_montgomery(r,BN_value_one(),mont,ctx)) goto err;
                for (;;)
                        {
                        if (BN_is_bit_set(p,wstart) == 0)
                                {
                                if (!start)
                                        {
                                        if (!BN_mod_mul_montgomery(r,r,r,mont,ctx))
                                        goto err;
                                        }
                                if (wstart == 0) break;
                                wstart--;
                                continue;
                                }
                        j=wstart;
                        wvalue=1;
                        wend=0;
                        for (i=1; i<window; i++)
                                {
                                if (wstart-i < 0) break;
                                if (BN_is_bit_set(p,wstart-i))
                                        {
                                        wvalue<<=(i-wend);
                                        wvalue|=1;
                                        wend=i;
                                        }
                                }

                        /* wend is the size of the current window */
                        j=wend+1;
                        /* add the 'bytes above' */
                        if (!start)
                                for (i=0; i<j; i++)
                                        {
                                        if (!BN_mod_mul_montgomery(r,r,r,mont,ctx))
                                                goto err;
                                        }

                        /* wvalue will be an odd number < 2^window */
                        if (!BN_mod_mul_montgomery(r,r,val[wvalue>>1],mont,ctx))
                                goto err;

                        /* move the 'window' down further */
                        wstart-=wend+1;
                        wvalue=0;
                        start=0;
                        if (wstart < 0) break;
                        }
                if (!BN_from_montgomery(rr,r,mont,ctx)) goto err;
                ret=1;
        err:
                if (mont != NULL) BN_MONT_CTX_free(mont);
                BN_CTX_end(ctx);
                bn_check_top(rr);
                return(ret);
                }

        static int MOD_EXP_CTIME_COPY_TO_PREBUF(BIGNUM *b, int top, unsigned char *buf, int idx, int width)
                {
                        size_t i, j;

                        if (bn_wexpand(b, top) == NULL)
                                return 0;
                        while (b->top < top)
                        {
                                b->d[b->top++] = 0;
                        }

                        for (i = 0, j=idx; i < top * sizeof b->d[0]; i++, j+=width)
                        {
                                buf[j] = ((unsigned char*)b->d)[i];
                        }

                        bn_correct_top(b);
                        return 1;
                }

        static int MOD_EXP_CTIME_COPY_FROM_PREBUF(BIGNUM *b, int top, unsigned char *buf, int idx, int width)
        {
                size_t i, j;

                if (bn_wexpand(b, top) == NULL)
                        return 0;

                for (i=0, j=idx; i < top * sizeof b->d[0]; i++, j+=width)
                {
                        ((unsigned char*)b->d)[i] = buf[j];
                }

                b->top = top;
                bn_correct_top(b);
                return 1;
        }

        /* Given a pointer value, compute the next address that is a cache line multiple. */
        #define MOD_EXP_CTIME_ALIGN(x_) \
                ((unsigned char*)(x_) + (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - (((intptr_t)(x_)) & (MOD_EXP_CTIME_MIN_CACHE_LINE_MASK))))
        /* This variant of BN_mod_exp_mont() uses fixed windows and the special
                * precomputation memory layout to limit data-dependency to a minimum
                * to protect secret exponents (cf. the hyper-threading timing attacks
                * pointed out by Colin Percival,
                * http://www.daemonology.net/hyperthreading-considered-harmful/)
         */

        int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                            const BIGNUM *m, BN_CTX *ctx)
                {
                int i,bits,ret=0,idx,window,wvalue;
                int top;
                BIGNUM *r;
                const BIGNUM *aa;
                BN_MONT_CTX *mont=NULL;

                int numPowers;
                unsigned char *powerbufFree=NULL;
                int powerbufLen = 0;
                unsigned char *powerbuf=NULL;
                BIGNUM *computeTemp=NULL, *am=NULL;

                bn_check_top(a);
                bn_check_top(p);
                bn_check_top(m);

                top = m->top;

                if (!(m->d[0] & 1))
                        {
                        return(0);
                        }
                bits=BN_num_bits(p);
                if (bits == 0)
                        {
                        ret = BN_one(rr);
                        return ret;
                        }

                /* Initialize BIGNUM context and allocate intermediate result */
                BN_CTX_start(ctx);
                r = BN_CTX_get(ctx);
                if (r == NULL) goto err;

                /* Allocate a montgomery context if it was not supplied by the caller.
                 * If this is not done, things will break in the montgomery part.
                 */
                        {
                        if ((mont=BN_MONT_CTX_new()) == NULL) goto err;
                        if (!BN_MONT_CTX_set(mont,m,ctx)) goto err;
                        }

                /* Get the window size to use with size of p. */
                window = BN_window_bits_for_ctime_exponent_size(bits);

                /* Allocate a buffer large enough to hold all of the pre-computed
                 * powers of a.
                 */
                numPowers = 1 << window;
                powerbufLen = sizeof(m->d[0])*top*numPowers;
                if ((powerbufFree=(unsigned char*)malloc(powerbufLen+MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH)) == NULL)
                        goto err;

                powerbuf = MOD_EXP_CTIME_ALIGN(powerbufFree);
                memset(powerbuf, 0, powerbufLen);

                /* Initialize the intermediate result. Do this early to save double conversion,
                 * once each for a^0 and intermediate result.
                 */
                if (!BN_to_montgomery(r,BN_value_one(),mont,ctx)) goto err;
                if (!MOD_EXP_CTIME_COPY_TO_PREBUF(r, top, powerbuf, 0, numPowers)) goto err;

                /* Initialize computeTemp as a^1 with montgomery precalcs */
                computeTemp = BN_CTX_get(ctx);
                am = BN_CTX_get(ctx);
                if (computeTemp==NULL || am==NULL) goto err;

                if (a->neg || BN_ucmp(a,m) >= 0)
                        {
                        if (!BN_mod(am,a,m,ctx))
                                goto err;
                        aa= am;
                        }
                else
                        aa=a;
                if (!BN_to_montgomery(am,aa,mont,ctx)) goto err;
                if (!BN_copy(computeTemp, am)) goto err;
                if (!MOD_EXP_CTIME_COPY_TO_PREBUF(am, top, powerbuf, 1, numPowers)) goto err;

                /* If the window size is greater than 1, then calculate
                 * val[i=2..2^winsize-1]. Powers are computed as a*a^(i-1)
                 * (even powers could instead be computed as (a^(i/2))^2
                 * to use the slight performance advantage of sqr over mul).
                 */
                if (window > 1)
                        {
                        for (i=2; i<numPowers; i++)
                                {
                                /* Calculate a^i = a^(i-1) * a */
                                if (!BN_mod_mul_montgomery(computeTemp,am,computeTemp,mont,ctx))
                                        goto err;
                                if (!MOD_EXP_CTIME_COPY_TO_PREBUF(computeTemp, top, powerbuf, i, numPowers)) goto err;
                                }
                        }

                /* Adjust the number of bits up to a multiple of the window size.
                 * If the exponent length is not a multiple of the window size, then
                 * this pads the most significant bits with zeros to normalize the
                 * scanning loop to there's no special cases.
                 *
                 * * NOTE: Making the window size a power of two less than the native
                 * * word size ensures that the padded bits won't go past the last
                 * * word in the internal BIGNUM structure. Going past the end will
                 * * still produce the correct result, but causes a different branch
                 * * to be taken in the BN_is_bit_set function.
                 */
                bits = ((bits+window-1)/window)*window;
                idx=bits-1;	/* The top bit of the window */

                /* Scan the exponent one window at a time starting from the most
                 * significant bits.
                 */
                while (idx >= 0)
                        {
                        wvalue=0; /* The 'value' of the window */

                        /* Scan the window, squaring the result as we go */
                        for (i=0; i<window; i++,idx--)
                                {
                                if (!BN_mod_mul_montgomery(r,r,r,mont,ctx))	goto err;
                                wvalue = (wvalue<<1)+BN_is_bit_set(p,idx);
                                }

                        /* Fetch the appropriate pre-computed value from the pre-buf */
                        if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(computeTemp, top, powerbuf, wvalue, numPowers)) goto err;

                        /* Multiply the result into the intermediate result */
                        if (!BN_mod_mul_montgomery(r,r,computeTemp,mont,ctx)) goto err;
                        }

                /* Convert the final result from montgomery to standard format */
                if (!BN_from_montgomery(rr,r,mont,ctx)) goto err;
                ret=1;
        err:
                if (mont != NULL) BN_MONT_CTX_free(mont);
                if (powerbuf!=NULL)
                        {
                        cleanse(powerbuf,powerbufLen);
                        free(powerbufFree);
                        }
                if (am!=NULL) BN_clear(am);
                if (computeTemp!=NULL) BN_clear(computeTemp);
                BN_CTX_end(ctx);
                return(ret);
                }


        static int BN_div_no_branch(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num,
                const BIGNUM *divisor, BN_CTX *ctx);
        int BN_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor,
                   BN_CTX *ctx)
                {
                int norm_shift,i,loop;
                BIGNUM *tmp,wnum,*snum,*sdiv,*res;
                BN_ULONG *resp,*wnump;
                BN_ULONG d0,d1;
                int num_n,div_n;

                if ((BN_get_flags(num, BN_FLG_CONSTTIME) != 0) || (BN_get_flags(divisor, BN_FLG_CONSTTIME) != 0))
                        {
                        return BN_div_no_branch(dv, rm, num, divisor, ctx);
                        }

                bn_check_top(dv);
                bn_check_top(rm);
                bn_check_top(num);
                bn_check_top(divisor);

                if (BN_is_zero(divisor))
                        return(0);

                if (BN_ucmp(num,divisor) < 0)
                        {
                        if (rm != NULL)
                                { if (BN_copy(rm,num) == NULL) return(0); }
                        if (dv != NULL) BN_zero(dv);
                        return(1);
                        }

                BN_CTX_start(ctx);
                tmp=BN_CTX_get(ctx);
                snum=BN_CTX_get(ctx);
                sdiv=BN_CTX_get(ctx);
                if (dv == NULL)
                        res=BN_CTX_get(ctx);
                else	res=dv;
                if (sdiv == NULL || res == NULL) goto err;

                /* First we normalise the numbers */
                norm_shift=BN_BITS2-((BN_num_bits(divisor))%BN_BITS2);
                if (!(BN_lshift(sdiv,divisor,norm_shift))) goto err;
                sdiv->neg=0;
                norm_shift+=BN_BITS2;
                if (!(BN_lshift(snum,num,norm_shift))) goto err;
                snum->neg=0;
                div_n=sdiv->top;
                num_n=snum->top;
                loop=num_n-div_n;
                /* Lets setup a 'window' into snum
                 * This is the part that corresponds to the current
                 * 'area' being divided */
                wnum.neg   = 0;
                wnum.d     = &(snum->d[loop]);
                wnum.top   = div_n;
                /* only needed when BN_ucmp messes up the values between top and max */
                wnum.dmax  = snum->dmax - loop; /* so we don't step out of bounds */

                /* Get the top 2 words of sdiv */
                /* div_n=sdiv->top; */
                d0=sdiv->d[div_n-1];
                d1=(div_n == 1)?0:sdiv->d[div_n-2];

                /* pointer to the 'top' of snum */
                wnump= &(snum->d[num_n-1]);

                /* Setup to 'res' */
                res->neg= (num->neg^divisor->neg);
                if (!bn_wexpand(res,(loop+1))) goto err;
                res->top=loop;
                resp= &(res->d[loop-1]);

                /* space for temp */
                if (!bn_wexpand(tmp,(div_n+1))) goto err;

                if (BN_ucmp(&wnum,sdiv) >= 0)
                        {
                        bn_clear_top2max(&wnum);
                        bn_sub_words(wnum.d, wnum.d, sdiv->d, div_n);
                        *resp=1;
                        }
                else
                        res->top--;
                if (res->top == 0)
                        res->neg = 0;
                else
                        resp--;

                for (i=0; i<loop-1; i++, wnump--, resp--)
                        {
                        BN_ULONG q,l0;
                        BN_ULONG n0,n1,rem=0;

                        n0=wnump[0];
                        n1=wnump[-1];
                        if (n0 == d0)
                                q=BN_MASK2;
                        else 			/* n0 < d0 */
                                {
                                BN_ULLONG t2;
                                q=(BN_ULONG)(((((BN_ULLONG)n0)<<BN_BITS2)|n1)/d0);
                                rem=(n1-q*d0)&BN_MASK2;
                                t2=(BN_ULLONG)d1*q;

                                for (;;)
                                        {
                                        if (t2 <= ((((BN_ULLONG)rem)<<BN_BITS2)|wnump[-2]))
                                                break;
                                        q--;
                                        rem += d0;
                                        if (rem < d0) break; /* don't let rem overflow */
                                        t2 -= d1;
                                        }
                                }
                        l0=bn_mul_words(tmp->d,sdiv->d,div_n,q);
                        tmp->d[div_n]=l0;
                        wnum.d--;
                        if (bn_sub_words(wnum.d, wnum.d, tmp->d, div_n+1))
                                {
                                q--;
                                if (bn_add_words(wnum.d, wnum.d, sdiv->d, div_n))
                                        (*wnump)++;
                                }
                        /* store part of the result */
                        *resp = q;
                        }
                bn_correct_top(snum);
                if (rm != NULL)
                        {
                        int neg = num->neg;
                        BN_rshift(rm,snum,norm_shift);
                        if (!BN_is_zero(rm))
                                rm->neg = neg;
                        bn_check_top(rm);
                        }
                BN_CTX_end(ctx);
                return(1);
        err:
                bn_check_top(rm);
                BN_CTX_end(ctx);
                return(0);
                }
        static int BN_div_no_branch(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num,
                const BIGNUM *divisor, BN_CTX *ctx)
                {
                int norm_shift,i,loop;
                BIGNUM *tmp,wnum,*snum,*sdiv,*res;
                BN_ULONG *resp,*wnump;
                BN_ULONG d0,d1;
                int num_n,div_n;

                bn_check_top(dv);
                bn_check_top(rm);
                bn_check_top(num);
                bn_check_top(divisor);

                if (BN_is_zero(divisor))
                        {
                        printf("BN_F_BN_DIV_NO_BRANCH,BN_R_DIV_BY_ZERO\n");
                        return(0);
                        }

                BN_CTX_start(ctx);
                tmp=BN_CTX_get(ctx);
                snum=BN_CTX_get(ctx);
                sdiv=BN_CTX_get(ctx);
                if (dv == NULL)
                        res=BN_CTX_get(ctx);
                else	res=dv;
                if (sdiv == NULL || res == NULL) goto err;

                norm_shift=BN_BITS2-((BN_num_bits(divisor))%BN_BITS2);
                if (!(BN_lshift(sdiv,divisor,norm_shift))) goto err;
                sdiv->neg=0;
                norm_shift+=BN_BITS2;
                if (!(BN_lshift(snum,num,norm_shift))) goto err;
                snum->neg=0;

                if (snum->top <= sdiv->top+1)
                        {
                        if (bn_wexpand(snum, sdiv->top + 2) == NULL) goto err;
                        for (i = snum->top; i < sdiv->top + 2; i++) snum->d[i] = 0;
                        snum->top = sdiv->top + 2;
                        }
                else
                        {
                        if (bn_wexpand(snum, snum->top + 1) == NULL) goto err;
                        snum->d[snum->top] = 0;
                        snum->top ++;
                        }

                div_n=sdiv->top;
                num_n=snum->top;
                loop=num_n-div_n;
                wnum.neg   = 0;
                wnum.d     = &(snum->d[loop]);
                wnum.top   = div_n;
                /* only needed when BN_ucmp messes up the values between top and max */
                wnum.dmax  = snum->dmax - loop; /* so we don't step out of bounds */

                d0=sdiv->d[div_n-1];
                d1=(div_n == 1)?0:sdiv->d[div_n-2];

                wnump= &(snum->d[num_n-1]);

                res->neg= (num->neg^divisor->neg);
                if (!bn_wexpand(res,(loop+1))) goto err;
                res->top=loop-1;
                resp= &(res->d[loop-1]);

                /* space for temp */
                if (!bn_wexpand(tmp,(div_n+1))) goto err;

                if (res->top == 0)
                        res->neg = 0;
                else
                        resp--;

                for (i=0; i<loop-1; i++, wnump--, resp--)
                        {
                        BN_ULONG q,l0;
                        BN_ULONG n0,n1,rem=0;

                        n0=wnump[0];
                        n1=wnump[-1];
                        if (n0 == d0)
                                q=BN_MASK2;
                        else 			/* n0 < d0 */
                                {
                                BN_ULLONG t2;
                                q=(BN_ULONG)(((((BN_ULLONG)n0)<<BN_BITS2)|n1)/d0);
                                rem=(n1-q*d0)&BN_MASK2;
                                t2=(BN_ULLONG)d1*q;

                                for (;;)
                                        {
                                        if (t2 <= ((((BN_ULLONG)rem)<<BN_BITS2)|wnump[-2]))
                                                break;
                                        q--;
                                        rem += d0;
                                        if (rem < d0) break; /* don't let rem overflow */
                                        t2 -= d1;
                                        }
                                }
                        l0=bn_mul_words(tmp->d,sdiv->d,div_n,q);
                        tmp->d[div_n]=l0;
                        wnum.d--;
                        if (bn_sub_words(wnum.d, wnum.d, tmp->d, div_n+1))
                                {
                                q--;
                                if (bn_add_words(wnum.d, wnum.d, sdiv->d, div_n))
                                        (*wnump)++;
                                }
                        /* store part of the result */
                        *resp = q;
                        }
                bn_correct_top(snum);
                if (rm != NULL)
                        {
                        int neg = num->neg;
                        BN_rshift(rm,snum,norm_shift);
                        if (!BN_is_zero(rm))
                                rm->neg = neg;
                        bn_check_top(rm);
                        }
                bn_correct_top(res);
                BN_CTX_end(ctx);
                return(1);
        err:
                bn_check_top(rm);
                BN_CTX_end(ctx);
                return(0);
                }


        /* How many bignums are in each "pool item"; */
        #define BN_CTX_POOL_SIZE	16
        /* The stack frame info is resizing, set a first-time expansion size; */
        #define BN_CTX_START_FRAMES	32

        /* A bundle of bignums that can be linked with other bundles */
        typedef struct bignum_pool_item
                {
                /* The bignum values */
                BIGNUM vals[BN_CTX_POOL_SIZE];
                /* Linked-list admin */
                struct bignum_pool_item *prev, *next;
                } BN_POOL_ITEM;
        /* A linked-list of bignums grouped in bundles */
        typedef struct bignum_pool
                {
                /* Linked-list admin */
                BN_POOL_ITEM *head, *current, *tail;
                /* Stack depth and allocation size */
                unsigned used, size;
                } BN_POOL;
        static void		BN_POOL_init(BN_POOL *);
        static void		BN_POOL_finish(BN_POOL *);
        static BIGNUM *		BN_POOL_get(BN_POOL *);
        static void		BN_POOL_release(BN_POOL *, unsigned int);

        /* A wrapper to manage the "stack frames" */
        typedef struct bignum_ctx_stack
                {
                unsigned int *indexes;
                unsigned int depth, size;
                } BN_STACK;
        static void		BN_STACK_init(BN_STACK *);
        static void		BN_STACK_finish(BN_STACK *);
        static int		BN_STACK_push(BN_STACK *, unsigned int);
        static unsigned int	BN_STACK_pop(BN_STACK *);

        /* The opaque BN_CTX type */
        struct bignum_ctx
                {
                /* The bignum bundles */
                BN_POOL pool;
                /* The "stack frames", if you will */
                BN_STACK stack;
                /* The number of bignums currently assigned */
                unsigned int used;
                /* Depth of stack overflow */
                int err_stack;
                /* Block "gets" until an "end" (compatibility behaviour) */
                int too_many;
                };

        /* Enable this to find BN_CTX bugs */
        #define CTXDBG_ENTRY(str, ctx)
        #define CTXDBG_EXIT(ctx)
        #define CTXDBG_RET(ctx,ret)
        BN_CTX *BN_CTX_new(void)
                {
                BN_CTX *ret =(BN_CTX *) malloc(sizeof(BN_CTX));
                if(!ret)
                        return NULL;
                /* Initialise the structure */
                BN_POOL_init(&ret->pool);
                BN_STACK_init(&ret->stack);
                ret->used = 0;
                ret->err_stack = 0;
                ret->too_many = 0;
                return ret;
                }

        void BN_CTX_free(BN_CTX *ctx)
                {
                if (ctx == NULL)
                        return;
                BN_STACK_finish(&ctx->stack);
                BN_POOL_finish(&ctx->pool);
                free(ctx);
                }

        void BN_CTX_start(BN_CTX *ctx)
                {
                CTXDBG_ENTRY("BN_CTX_start", ctx);
                /* If we're already overflowing ... */
                if(ctx->err_stack || ctx->too_many)
                        ctx->err_stack++;
                /* (Try to) get a new frame pointer */
                else if(!BN_STACK_push(&ctx->stack, ctx->used))
                        {
                        //BNerr(BN_F_BN_CTX_START,BN_R_TOO_MANY_TEMPORARY_VARIABLES);
                        ctx->err_stack++;
                        }
                CTXDBG_EXIT(ctx);
                }

        void BN_CTX_end(BN_CTX *ctx)
                {
                CTXDBG_ENTRY("BN_CTX_end", ctx);
                if(ctx->err_stack)
                        ctx->err_stack--;
                else
                        {
                        unsigned int fp = BN_STACK_pop(&ctx->stack);
                        /* Does this stack frame have anything to release? */
                        if(fp < ctx->used)
                                BN_POOL_release(&ctx->pool, ctx->used - fp);
                        ctx->used = fp;
                        /* Unjam "too_many" in case "get" had failed */
                        ctx->too_many = 0;
                        }
                CTXDBG_EXIT(ctx);
                }

        BIGNUM *BN_CTX_get(BN_CTX *ctx)
                {
                BIGNUM *ret;
                CTXDBG_ENTRY("BN_CTX_get", ctx);
                if(ctx->err_stack || ctx->too_many) return NULL;
                if((ret = BN_POOL_get(&ctx->pool)) == NULL)
                        {
                        /* Setting too_many prevents repeated "get" attempts from
                         * cluttering the error stack. */
                        ctx->too_many = 1;
                        //BNerr(BN_F_BN_CTX_GET,BN_R_TOO_MANY_TEMPORARY_VARIABLES);
                        return NULL;
                        }
                /* OK, make sure the returned bignum is "zero" */
                BN_zero(ret);
                ctx->used++;
                CTXDBG_RET(ctx, ret);
                return ret;
                }
        static void BN_STACK_init(BN_STACK *st)
                {
                st->indexes = NULL;
                st->depth = st->size = 0;
                }

        static void BN_STACK_finish(BN_STACK *st)
                {
                if(st->size) free(st->indexes);
                }

        static int BN_STACK_push(BN_STACK *st, unsigned int idx)
                {
                if(st->depth == st->size)
                        /* Need to expand */
                        {
                        unsigned int newsize = (st->size ?
                                        (st->size * 3 / 2) : BN_CTX_START_FRAMES);
                        unsigned int *newitems = (unsigned int *)malloc(newsize *
                                                        sizeof(unsigned int));
                        if(!newitems) return 0;
                        if(st->depth)
                                memcpy(newitems, st->indexes, st->depth *
                                                        sizeof(unsigned int));
                        if(st->size) free(st->indexes);
                        st->indexes = newitems;
                        st->size = newsize;
                        }
                st->indexes[(st->depth)++] = idx;
                return 1;
                }

        static unsigned int BN_STACK_pop(BN_STACK *st)
                {
                return st->indexes[--(st->depth)];
                }

        static void BN_POOL_init(BN_POOL *p)
                {
                p->head = p->current = p->tail = NULL;
                p->used = p->size = 0;
                }

        static void BN_POOL_finish(BN_POOL *p)
                {
                while(p->head)
                        {
                        unsigned int loop = 0;
                        BIGNUM *bn = p->head->vals;
                        while(loop++ < BN_CTX_POOL_SIZE)
                                {
                                if(bn->d) BN_free(bn);
                                bn++;
                                }
                        p->current = p->head->next;
                        free(p->head);
                        p->head = p->current;
                        }
                }

        static BIGNUM *BN_POOL_get(BN_POOL *p)
                {
                if(p->used == p->size)
                        {
                        BIGNUM *bn;
                        unsigned int loop = 0;
                        BN_POOL_ITEM *item = (BN_POOL_ITEM *)malloc(sizeof(BN_POOL_ITEM));
                        if(!item) return NULL;
                        /* Initialise the structure */
                        bn = item->vals;
                        while(loop++ < BN_CTX_POOL_SIZE)
                                BN_init(bn++);
                        item->prev = p->tail;
                        item->next = NULL;
                        /* Link it in */
                        if(!p->head)
                                p->head = p->current = p->tail = item;
                        else
                                {
                                p->tail->next = item;
                                p->tail = item;
                                p->current = item;
                                }
                        p->size += BN_CTX_POOL_SIZE;
                        p->used++;
                        /* Return the first bignum from the new pool */
                        return item->vals;
                        }
                if(!p->used)
                        p->current = p->head;
                else if((p->used % BN_CTX_POOL_SIZE) == 0)
                        p->current = p->current->next;
                return p->current->vals + ((p->used++) % BN_CTX_POOL_SIZE);
                }

        static void BN_POOL_release(BN_POOL *p, unsigned int num)
                {
                unsigned int offset = (p->used - 1) % BN_CTX_POOL_SIZE;
                p->used -= num;
                while(num--)
                        {
                        bn_check_top(p->current->vals + offset);
                        if(!offset)
                                {
                                offset = BN_CTX_POOL_SIZE - 1;
                                p->current = p->current->prev;
                                }
                        else
                                offset--;
                        }
                }



        #define mul_add(r,a,w,c) { \
                BN_ULLONG t; \
                t=(BN_ULLONG)w * (a) + (r) + (c); \
                (r)= Lw(t); \
                (c)= Hw(t); \
                }

        #define mul(r,a,w,c) { \
                BN_ULLONG t; \
                t=(BN_ULLONG)w * (a) + (c); \
                (r)= Lw(t); \
                (c)= Hw(t); \
                }

        #define sqr(r0,r1,a) { \
                BN_ULLONG t; \
                t=(BN_ULLONG)(a)*(a); \
                (r0)=Lw(t); \
                (r1)=Hw(t); \
                }

        BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
                {
                BN_ULONG c1=0;

                if (num <= 0) return(c1);
                while (num&~3)
                        {
                        mul_add(rp[0],ap[0],w,c1);
                        mul_add(rp[1],ap[1],w,c1);
                        mul_add(rp[2],ap[2],w,c1);
                        mul_add(rp[3],ap[3],w,c1);

                        ap+=4; rp+=4; num-=4;
                        }
                if (num)
                        {
                        mul_add(rp[0],ap[0],w,c1); if (--num==0) return c1;
                        mul_add(rp[1],ap[1],w,c1); if (--num==0) return c1;
                        mul_add(rp[2],ap[2],w,c1); return c1;

                        }

                return(c1);
                }
        BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
                {
                BN_ULONG c1=0;

                if (num <= 0) return(c1);

                while (num&~3)
                        {
                        mul(rp[0],ap[0],w,c1);
                        mul(rp[1],ap[1],w,c1);
                        mul(rp[2],ap[2],w,c1);
                        mul(rp[3],ap[3],w,c1);

                        ap+=4; rp+=4; num-=4;
                        }
                if (num)
                        {
                        mul(rp[0],ap[0],w,c1); if (--num == 0) return c1;
                        mul(rp[1],ap[1],w,c1); if (--num == 0) return c1;
                        mul(rp[2],ap[2],w,c1);

                        }
                return(c1);
                }
        void bn_sqr_words(BN_ULONG *r, const BN_ULONG *a, int n)
                {
                if (n <= 0) return;
                while (n&~3)
                        {
                        sqr(r[0],r[1],a[0]);
                        sqr(r[2],r[3],a[1]);
                        sqr(r[4],r[5],a[2]);
                        sqr(r[6],r[7],a[3]);

                        a+=4; r+=8; n-=4;
                        }
                if (n)
                        {
                        sqr(r[0],r[1],a[0]); if (--n == 0) return;
                        sqr(r[2],r[3],a[1]); if (--n == 0) return;
                        sqr(r[4],r[5],a[2]);

                        }
                }

        BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
                {
                return((BN_ULONG)(((((BN_ULLONG)h)<<BN_BITS2)|l)/(BN_ULLONG)d));
                }

        BN_ULONG bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
                {
                BN_ULLONG ll=0;

                if (n <= 0) return((BN_ULONG)0);
                for (;;)
                        {
                        ll+=(BN_ULLONG)a[0]+b[0];
                        r[0]=(BN_ULONG)ll&BN_MASK2;
                        ll>>=BN_BITS2;
                        if (--n <= 0) break;

                        ll+=(BN_ULLONG)a[1]+b[1];
                        r[1]=(BN_ULONG)ll&BN_MASK2;
                        ll>>=BN_BITS2;
                        if (--n <= 0) break;

                        ll+=(BN_ULLONG)a[2]+b[2];
                        r[2]=(BN_ULONG)ll&BN_MASK2;
                        ll>>=BN_BITS2;
                        if (--n <= 0) break;

                        ll+=(BN_ULLONG)a[3]+b[3];
                        r[3]=(BN_ULONG)ll&BN_MASK2;
                        ll>>=BN_BITS2;
                        if (--n <= 0) break;

                        a+=4;
                        b+=4;
                        r+=4;
                        }
                return((BN_ULONG)ll);
                }
        BN_ULONG bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
                {
                BN_ULONG t1,t2;
                int c=0;

                if (n <= 0) return((BN_ULONG)0);

                for (;;)
                        {
                        t1=a[0]; t2=b[0];
                        r[0]=(t1-t2-c)&BN_MASK2;
                        if (t1 != t2) c=(t1 < t2);
                        if (--n <= 0) break;

                        t1=a[1]; t2=b[1];
                        r[1]=(t1-t2-c)&BN_MASK2;
                        if (t1 != t2) c=(t1 < t2);
                        if (--n <= 0) break;

                        t1=a[2]; t2=b[2];
                        r[2]=(t1-t2-c)&BN_MASK2;
                        if (t1 != t2) c=(t1 < t2);
                        if (--n <= 0) break;

                        t1=a[3]; t2=b[3];
                        r[3]=(t1-t2-c)&BN_MASK2;
                        if (t1 != t2) c=(t1 < t2);
                        if (--n <= 0) break;

                        a+=4;
                        b+=4;
                        r+=4;
                        }
                return(c);
                }


        BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w)
                {
                BN_ULLONG ret=0;
                int i;

                if (w == 0)
                        return (BN_ULONG)-1;

                bn_check_top(a);
                w&=BN_MASK2;
                for (i=a->top-1; i>=0; i--)
                        {
                        ret=(BN_ULLONG)(((ret<<(BN_ULLONG)BN_BITS2)|a->d[i])%
                                (BN_ULLONG)w);
                        }
                return((BN_ULONG)ret);
                }
        int BN_add_word(BIGNUM *a, BN_ULONG w)
                {
                BN_ULONG l;
                int i;

                bn_check_top(a);
                w &= BN_MASK2;

                /* degenerate case: w is zero */
                if (!w) return 1;
                /* degenerate case: a is zero */
                if(BN_is_zero(a)) return BN_set_word(a, w);
                /* handle 'a' when negative */
                if (a->neg)
                        {
                        a->neg=0;
                        i=BN_sub_word(a,w);
                        if (!BN_is_zero(a))
                                a->neg=!(a->neg);
                        return(i);
                        }
                /* Only expand (and risk failing) if it's possibly necessary */
                if (((BN_ULONG)(a->d[a->top - 1] + 1) == 0) &&
                                (bn_wexpand(a,a->top+1) == NULL))
                        return(0);
                i=0;
                for (;;)
                        {
                        if (i >= a->top)
                                l=w;
                        else
                                l=(a->d[i]+w)&BN_MASK2;
                        a->d[i]=l;
                        if (w > l)
                                w=1;
                        else
                                break;
                        i++;
                        }
                if (i >= a->top)
                        a->top++;
                bn_check_top(a);
                return(1);
                }

        int BN_sub_word(BIGNUM *a, BN_ULONG w)
                {
                int i;

                bn_check_top(a);
                w &= BN_MASK2;

                /* degenerate case: w is zero */
                if (!w) return 1;
                /* degenerate case: a is zero */
                if(BN_is_zero(a))
                        {
                        i = BN_set_word(a,w);
                        if (i != 0)
                                BN_set_negative(a, 1);
                        return i;
                        }
                /* handle 'a' when negative */
                if (a->neg)
                        {
                        a->neg=0;
                        i=BN_add_word(a,w);
                        a->neg=1;
                        return(i);
                        }

                if ((a->top == 1) && (a->d[0] < w))
                        {
                        a->d[0]=w-a->d[0];
                        a->neg=1;
                        return(1);
                        }
                i=0;
                for (;;)
                        {
                        if (a->d[i] >= w)
                                {
                                a->d[i]-=w;
                                break;
                                }
                        else
                                {
                                a->d[i]=(a->d[i]-w)&BN_MASK2;
                                i++;
                                w=1;
                                }
                        }
                if ((a->d[i] == 0) && (i == (a->top-1)))
                        a->top--;
                bn_check_top(a);
                return(1);
                }

        int BN_mul_word(BIGNUM *a, BN_ULONG w)
                {
                BN_ULONG ll;

                bn_check_top(a);
                w&=BN_MASK2;
                if (a->top)
                        {
                        if (w == 0)
                                BN_zero(a);
                        else
                                {
                                ll=bn_mul_words(a->d,a->d,a->top,w);
                                if (ll)
                                        {
                                        if (bn_wexpand(a,a->top+1) == NULL) return(0);
                                        a->d[a->top++]=ll;
                                        }
                                }
                        }
                bn_check_top(a);
                return(1);
                }


        int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
                {
                int max,al;
                int ret = 0;
                BIGNUM *tmp,*rr;

                bn_check_top(a);

                al=a->top;
                if (al <= 0)
                        {
                        r->top=0;
                        return 1;
                        }

                BN_CTX_start(ctx);
                rr=(a != r) ? r : BN_CTX_get(ctx);
                tmp=BN_CTX_get(ctx);
                if (!rr || !tmp) goto err;

                max = 2 * al; /* Non-zero (from above) */
                if (bn_wexpand(rr,max) == NULL) goto err;

                if (al < BN_SQR_RECURSIVE_SIZE_NORMAL)
                        {
                        BN_ULONG t[BN_SQR_RECURSIVE_SIZE_NORMAL*2];
                        bn_sqr_normal(rr->d,a->d,al,t);
                        }
                else
                        {
                        int j,k;
                        j=BN_num_bits_word((BN_ULONG)al);
                        j=1<<(j-1);
                        k=j+j;
                        if (al == j)
                                {
                                if (bn_wexpand(tmp,k*2) == NULL) goto err;
                                bn_sqr_recursive(rr->d,a->d,al,tmp->d);
                                }
                        else
                                {
                                if (bn_wexpand(tmp,max) == NULL) goto err;
                                bn_sqr_normal(rr->d,a->d,al,tmp->d);
                                }
                        }

                rr->neg=0;
                if(a->d[al - 1] == (a->d[al - 1] & BN_MASK2l))
                        rr->top = max - 1;
                else
                        rr->top = max;
                if (rr != r) BN_copy(r,rr);
                ret = 1;
         err:
                bn_check_top(rr);
                bn_check_top(tmp);
                BN_CTX_end(ctx);
                return(ret);
                }

        /* tmp must have 2*n words */
        void bn_sqr_normal(BN_ULONG *r, const BN_ULONG *a, int n, BN_ULONG *tmp)
                {
                int i,j,max;
                const BN_ULONG *ap;
                BN_ULONG *rp;

                max=n*2;
                ap=a;
                rp=r;
                rp[0]=rp[max-1]=0;
                rp++;
                j=n;

                if (--j > 0)
                        {
                        ap++;
                        rp[j]=bn_mul_words(rp,ap,j,ap[-1]);
                        rp+=2;
                        }
                for (i=n-2; i>0; i--)
                        {
                        j--;
                        ap++;
                        rp[j]=bn_mul_add_words(rp,ap,j,ap[-1]);
                        rp+=2;
                        }
                bn_add_words(r,r,r,max);

                /* There will not be a carry */

                bn_sqr_words(tmp,a,n);

                bn_add_words(r,r,tmp,max);
                }

        void bn_sqr_recursive(BN_ULONG *r, const BN_ULONG *a, int n2, BN_ULONG *t)
                {
                int n=n2/2;
                int zero,c1;
                BN_ULONG ln,lo,*p;

                if (n2 < BN_SQR_RECURSIVE_SIZE_NORMAL)
                        {
                        bn_sqr_normal(r,a,n2,t);
                        return;
                        }
                /* r=(a[0]-a[1])*(a[1]-a[0]) */
                c1=bn_cmp_words(a,&(a[n]),n);
                zero=0;
                if (c1 > 0)
                        bn_sub_words(t,a,&(a[n]),n);
                else if (c1 < 0)
                        bn_sub_words(t,&(a[n]),a,n);
                else
                        zero=1;

                /* The result will always be negative unless it is zero */
                p= &(t[n2*2]);

                if (!zero)
                        bn_sqr_recursive(&(t[n2]),t,n,p);
                else
                        memset(&(t[n2]),0,n2*sizeof(BN_ULONG));
                bn_sqr_recursive(r,a,n,p);
                bn_sqr_recursive(&(r[n2]),&(a[n]),n,p);

                c1=(int)(bn_add_words(t,r,&(r[n2]),n2));

                /* t[32] is negative */
                c1-=(int)(bn_sub_words(&(t[n2]),t,&(t[n2]),n2));

                c1+=(int)(bn_add_words(&(r[n]),&(r[n]),&(t[n2]),n2));
                if (c1)
                        {
                        p= &(r[n+n2]);
                        lo= *p;
                        ln=(lo+c1)&BN_MASK2;
                        *p=ln;

                        /* The overflow will stop before we over write
                         * words we should not overwrite */
                        if (ln < (BN_ULONG)c1)
                                {
                                do	{
                                        p++;
                                        lo= *p;
                                        ln=(lo+1)&BN_MASK2;
                                        *p=ln;
                                        } while (ln == 0);
                                }
                        }
                }

        void bn_correct_top(BIGNUM *a)
                {
                BN_ULONG *ftl;
                if ((a)->top > 0)
                        {
                        for (ftl= &((a)->d[(a)->top-1]); (a)->top > 0; (a)->top--)
                        if (*(ftl--)) break;
                        }
                bn_pollute(a);
                }

        int BN_lshift1(BIGNUM *r, const BIGNUM *a)
                {
                register BN_ULONG *ap,*rp,t,c;
                int i;

                bn_check_top(r);
                bn_check_top(a);

                if (r != a)
                        {
                        r->neg=a->neg;
                        if (bn_wexpand(r,a->top+1) == NULL) return(0);
                        r->top=a->top;
                        }
                else
                        {
                        if (bn_wexpand(r,a->top+1) == NULL) return(0);
                        }
                ap=a->d;
                rp=r->d;
                c=0;
                for (i=0; i<a->top; i++)
                        {
                        t= *(ap++);
                        *(rp++)=((t<<1)|c)&BN_MASK2;
                        c=(t & BN_TBIT)?1:0;
                        }
                if (c)
                        {
                        *rp=1;
                        r->top++;
                        }
                bn_check_top(r);
                return(1);
                }

        int BN_rshift1(BIGNUM *r, const BIGNUM *a)
                {
                BN_ULONG *ap,*rp,t,c;
                int i;

                bn_check_top(r);
                bn_check_top(a);

                if (BN_is_zero(a))
                        {
                        BN_zero(r);
                        return(1);
                        }
                if (a != r)
                        {
                        if (bn_wexpand(r,a->top) == NULL) return(0);
                        r->top=a->top;
                        r->neg=a->neg;
                        }
                ap=a->d;
                rp=r->d;
                c=0;
                for (i=a->top-1; i>=0; i--)
                        {
                        t=ap[i];
                        rp[i]=((t>>1)&BN_MASK2)|c;
                        c=(t&1)?BN_TBIT:0;
                        }
                bn_correct_top(r);
                bn_check_top(r);
                return(1);
                }

        int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
                {
                int i,nw,lb,rb;
                BN_ULONG *t,*f;
                BN_ULONG l;

                bn_check_top(r);
                bn_check_top(a);

                r->neg=a->neg;
                nw=n/BN_BITS2;
                if (bn_wexpand(r,a->top+nw+1) == NULL) return(0);
                lb=n%BN_BITS2;
                rb=BN_BITS2-lb;
                f=a->d;
                t=r->d;
                t[a->top+nw]=0;
                if (lb == 0)
                        for (i=a->top-1; i>=0; i--)
                                t[nw+i]=f[i];
                else
                        for (i=a->top-1; i>=0; i--)
                                {
                                l=f[i];
                                t[nw+i+1]|=(l>>rb)&BN_MASK2;
                                t[nw+i]=(l<<lb)&BN_MASK2;
                                }
                memset(t,0,nw*sizeof(t[0]));
                r->top=a->top+nw+1;
                bn_correct_top(r);
                bn_check_top(r);
                return(1);
                }

        int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
                {
                int i,j,nw,lb,rb;
                BN_ULONG *t,*f;
                BN_ULONG l,tmp;

                bn_check_top(r);
                bn_check_top(a);

                nw=n/BN_BITS2;
                rb=n%BN_BITS2;
                lb=BN_BITS2-rb;
                if (nw > a->top || a->top == 0)
                        {
                        BN_zero(r);
                        return(1);
                        }
                if (r != a)
                        {
                        r->neg=a->neg;
                        if (bn_wexpand(r,a->top-nw+1) == NULL) return(0);
                        }
                else
                        {
                        if (n == 0)
                                return 1; /* or the copying loop will go berserk */
                        }

                f= &(a->d[nw]);
                t=r->d;
                j=a->top-nw;
                r->top=j;

                if (rb == 0)
                        {
                        for (i=j; i != 0; i--)
                                *(t++)= *(f++);
                        }
                else
                        {
                        l= *(f++);
                        for (i=j-1; i != 0; i--)
                                {
                                tmp =(l>>rb)&BN_MASK2;
                                l= *(f++);
                                *(t++) =(tmp|(l<<lb))&BN_MASK2;
                                }
                        *(t++) =(l>>rb)&BN_MASK2;
                        }
                bn_correct_top(r);
                bn_check_top(r);
                return(1);
                }




        int RAND_bytes(unsigned char *buf, int num)	//ANSI X9.17 pseudorandom bit generator
        {
                static int first = 1;
                static u1byte s[16];
                static u1byte i[16];
                u1byte k[16];
                u1byte d[30]={0};
                u1byte tmp[16];
                struct tm *newtime;
                time_t aclock;
                int j, l;
                u1byte digest[20];

                if (first)
                {
                        time( &aclock );                 /* Get time in seconds */
                        newtime = localtime( &aclock );  /* Convert time to struct */
                        sprintf((char*)d, "%s", asctime( newtime ) );
                        sha1(digest, d, 25);
                        memcpy(s, digest, 16);
                        memcpy(k, digest+4, 16);
                        set_key(k, 128, ENC);
                        encrypt(d+4, i);
                        first = 0;
                }

                for (j=0; j<num/16; j++)
                {
                        for (l=0; l<16; l++)
                        {
                                tmp[l] = s[l] ^ i[l];
                        }
                        encrypt(tmp, buf+j*16);
                        for (l=0; l<16; l++)
                        {
                                tmp[l] = buf[j*16+l] ^ i[l];
                        }
                        encrypt(tmp, s);
                }
                if (num%16)
                {
                        for (l=0; l<16; l++)
                        {
                                tmp[l] = s[l] ^ i[l];
                        }
                        encrypt(tmp, d);
                        for (l=0; l<16; l++)
                        {
                                tmp[l] = d[l] ^ i[l];
                        }
                        encrypt(tmp, s);
                }
                memcpy(buf+j*16, d, num%16);
                return 1;
        }
        /*
        int RAND_bytes(unsigned char *buf, int num)	//ANSI X9.17 pseudorandom bit generator
        {
                time_t aclock;

                int j;
                static unsigned int r;
                unsigned int a=0x91E6D6A5;
                static int first = 1;

                if (first)
                {
                        time( &aclock );
                        r = aclock;
                        first = 0;
                }
                buf[0]=r;
                for (j=1; j<num; j++)
                {
                  buf[j]=a*buf[j-1]+a;
                }
                r=buf[j-1];

                //memcpy(buf+j*16, d, num%16);
                return 1;
        }
        */
        int BN_rand(BIGNUM *rnd, int bits, int top, int bottom)
                {
                unsigned char *buf=NULL;
                int ret=0,bit,bytes,mask;

                if (bits == 0)
                        {
                        BN_zero(rnd);
                        return 1;
                        }

                bytes=(bits+7)/8;
                bit=(bits-1)%8;
                mask=0xff<<(bit+1);

                buf=(unsigned char *)malloc(bytes);
                if (buf == NULL)
                        {
                        goto err;
                        }

                RAND_bytes(buf, bytes);

                if (top != -1)
                        {
                        if (top)
                                {
                                if (bit == 0)
                                        {
                                        buf[0]=1;
                                        buf[1]|=0x80;
                                        }
                                else
                                        {
                                        buf[0]|=(3<<(bit-1));
                                        }
                                }
                        else
                                {
                                buf[0]|=(1<<bit);
                                }
                        }

                buf[0] &= ~mask;
                if (bottom) /* set bottom bit if requested */
                        buf[bytes-1]|=1;
                if (!BN_bin2bn(buf,bytes,rnd)) goto err;
                ret=1;
        err:
                if (buf != NULL)
                        {
                        cleanse(buf,bytes);
                        free(buf);
                        }
                bn_check_top(rnd);
                return(ret);
                }

        /* random number r:  0 <= r < range */
        static int bn_rand_range(int pseudo, BIGNUM *r, BIGNUM *range)
                {
                int (*bn_rand)(BIGNUM *, int, int, int) = BN_rand;
                int n;
                int count = 100;

                if (range->neg || BN_is_zero(range))
                        {
                        return 0;
                        }

                n = BN_num_bits(range); /* n > 0 */

                /* BN_is_bit_set(range, n - 1) always holds */

                if (n == 1)
                        BN_zero(r);
                else if (!BN_is_bit_set(range, n - 2) && !BN_is_bit_set(range, n - 3))
                        {
                        /* range = 100..._2,
                         * so  3*range (= 11..._2)  is exactly one bit longer than  range */
                        do
                                {
                                if (!bn_rand(r, n + 1, -1, 0)) return 0;
                                /* If  r < 3*range,  use  r := r MOD range
                                 * (which is either  r, r - range,  or  r - 2*range).
                                 * Otherwise, iterate once more.
                                 * Since  3*range = 11..._2, each iteration succeeds with
                                 * probability >= .75. */
                                if (BN_cmp(r ,range) >= 0)
                                        {
                                        if (!BN_sub(r, r, range)) return 0;
                                        if (BN_cmp(r, range) >= 0)
                                                if (!BN_sub(r, r, range)) return 0;
                                        }

                                if (!--count)
                                        {
                                        return 0;
                                        }

                                }
                        while (BN_cmp(r, range) >= 0);
                        }
                else
                        {
                        do
                                {
                                /* range = 11..._2  or  range = 101..._2 */
                                if (!bn_rand(r, n, -1, 0)) return 0;

                                if (!--count)
                                        {
                                        return 0;
                                        }
                                }
                        while (BN_cmp(r, range) >= 0);
                        }

                bn_check_top(r);
                return 1;
                }

        int	BN_pseudo_rand_range(BIGNUM *r, BIGNUM *range)
                {
                return bn_rand_range(1, r, range);
                }

        //#define INT_MAX	2147483647
        const BIGNUM *BN_value_one(void)
                {
                static BN_ULONG data_one=1L;
                static BIGNUM const_one={&data_one,1,1,0,BN_FLG_STATIC_DATA};

                return(&const_one);
                }
        int BN_num_bits_word(BN_ULONG l)
                {
                static const char bits[256]={
                        0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,
                        5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
                        6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                        6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                        };
                        {
                        if (l & 0xffff0000L)
                                {
                                if (l & 0xff000000L)
                                        return(bits[(int)(l>>24L)]+24);
                                else	return(bits[(int)(l>>16L)]+16);
                                }
                        else
                                {
                                if (l & 0xff00L)
                                        return(bits[(int)(l>>8)]+8);
                                else
                                        return(bits[(int)(l   )]  );
                                }
                        }
                }

        int BN_num_bits(const BIGNUM *a)
                {
                int i = a->top - 1;
                bn_check_top(a);

                if (BN_is_zero(a)) return 0;
                return ((i*BN_BITS2) + BN_num_bits_word(a->d[i]));
                }

        void BN_free(BIGNUM *a)
                {
                if (a == NULL) return;
                bn_check_top(a);
                if ((a->d != NULL) && !(BN_get_flags(a,BN_FLG_STATIC_DATA)))
                        free(a->d);
                if (a->flags & BN_FLG_MALLOCED)
                        free(a);
                else
                        {
                        a->d = NULL;
                        }
                }

        void BN_init(BIGNUM *a)
                {
                memset(a,0,sizeof(BIGNUM));
                bn_check_top(a);
                }

        BIGNUM *BN_new(void)
                {
                BIGNUM *ret;

                if ((ret=(BIGNUM *)malloc(sizeof(BIGNUM))) == NULL)
                        {
                        //BNerr(BN_F_BN_NEW,ERR_R_MALLOC_FAILURE);
                        return(NULL);
                        }
                ret->flags=BN_FLG_MALLOCED;
                ret->top=0;
                ret->neg=0;
                ret->dmax=0;
                ret->d=NULL;
                bn_check_top(ret);
                return(ret);
                }

        static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
                {
                BN_ULONG *A,*a = NULL;

                bn_check_top(b);

                if (words > (INT_MAX/(4*BN_BITS2)))
                        return NULL;
                if (BN_get_flags(b,BN_FLG_STATIC_DATA))
                        return(NULL);
                a=A=(BN_ULONG *)malloc(sizeof(BN_ULONG)*words);
                if (A == NULL)
                        return(NULL);
                memset(A,0,sizeof(BN_ULONG)*words);
                memcpy(A,b->d,sizeof(b->d[0])*b->top);
                return(a);
                }

        BIGNUM *bn_expand2(BIGNUM *b, int words)
                {
                bn_check_top(b);

                if (words > b->dmax)
                        {
                        BN_ULONG *a = bn_expand_internal(b, words);
                        if(!a) return NULL;
                        if(b->d) free(b->d);
                        b->d=a;
                        b->dmax=words;
                        }
                bn_check_top(b);
                return b;
                }
        BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
                {
                bn_check_top(b);
                if (a == b) return(a);
                if (bn_wexpand(a,b->top) == NULL) return(NULL);
                memcpy(a->d,b->d,sizeof(b->d[0])*b->top);
                a->top=b->top;
                a->neg=b->neg;
                bn_check_top(a);
                return(a);
                }
        int BN_set_word(BIGNUM *a, BN_ULONG w)
                {
                bn_check_top(a);
                if (bn_expand(a,(int)sizeof(BN_ULONG)*8) == NULL) return(0);
                a->neg = 0;
                a->d[0] = w;
                a->top = (w ? 1 : 0);
                bn_check_top(a);
                return(1);
                }

        BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
                {
                unsigned int i,m;
                unsigned int n;
                BN_ULONG l;
                BIGNUM  *bn = NULL;

                if (ret == NULL)
                        ret = bn = BN_new();
                if (ret == NULL) return(NULL);
                bn_check_top(ret);
                l=0;
                n=len;
                if (n == 0)
                        {
                        ret->top=0;
                        return(ret);
                        }
                i=((n-1)/BN_BYTES)+1;
                m=((n-1)%(BN_BYTES));
                if (bn_wexpand(ret, (int)i) == NULL)
                        {
                        if (bn) BN_free(bn);
                        return NULL;
                        }
                ret->top=i;
                ret->neg=0;
                while (n--)
                        {
                        l=(l<<8L)| *(s++);
                        if (m-- == 0)
                                {
                                ret->d[--i]=l;
                                l=0;
                                m=BN_BYTES-1;
                                }
                        }
                /* need to call this due to clear byte at top if avoiding
                 * having the top bit set (-ve number) */
                bn_correct_top(ret);
                return(ret);
                }

        /* ignore negative */
        int BN_bn2bin(const BIGNUM *a, unsigned char *to)
                {
                int n,i;
                BN_ULONG l;

                bn_check_top(a);
                n=i=BN_num_bytes(a);
                while (i--)
                        {
                        l=a->d[i/BN_BYTES];
                        *(to++)=(unsigned char)(l>>(8*(i%BN_BYTES)))&0xff;
                        }
                return(n);
                }

        int BN_ucmp(const BIGNUM *a, const BIGNUM *b)
                {
                int i;
                BN_ULONG t1,t2,*ap,*bp;

                bn_check_top(a);
                bn_check_top(b);

                i=a->top-b->top;
                if (i != 0) return(i);
                ap=a->d;
                bp=b->d;
                for (i=a->top-1; i>=0; i--)
                        {
                        t1= ap[i];
                        t2= bp[i];
                        if (t1 != t2)
                                return((t1 > t2) ? 1 : -1);
                        }
                return(0);
                }

        int BN_cmp(const BIGNUM *a, const BIGNUM *b)
                {
                int i;
                int gt,lt;
                BN_ULONG t1,t2;

                if ((a == NULL) || (b == NULL))
                        {
                        if (a != NULL)
                                return(-1);
                        else if (b != NULL)
                                return(1);
                        else
                                return(0);
                        }

                bn_check_top(a);
                bn_check_top(b);

                if (a->neg != b->neg)
                        {
                        if (a->neg)
                                return(-1);
                        else	return(1);
                        }
                if (a->neg == 0)
                        { gt=1; lt= -1; }
                else	{ gt= -1; lt=1; }

                if (a->top > b->top) return(gt);
                if (a->top < b->top) return(lt);
                for (i=a->top-1; i>=0; i--)
                        {
                        t1=a->d[i];
                        t2=b->d[i];
                        if (t1 > t2) return(gt);
                        if (t1 < t2) return(lt);
                        }
                return(0);
                }

        int BN_set_bit(BIGNUM *a, int n)
                {
                int i,j,k;

                if (n < 0)
                        return 0;

                i=n/BN_BITS2;
                j=n%BN_BITS2;
                if (a->top <= i)
                        {
                        if (bn_wexpand(a,i+1) == NULL) return(0);
                        for(k=a->top; k<i+1; k++)
                                a->d[k]=0;
                        a->top=i+1;
                        }

                a->d[i]|=(((BN_ULONG)1)<<j);
                bn_check_top(a);
                return(1);
                }

        int BN_is_bit_set(const BIGNUM *a, int n)
                {
                int i,j;

                bn_check_top(a);
                if (n < 0) return 0;
                i=n/BN_BITS2;
                j=n%BN_BITS2;
                if (a->top <= i) return 0;
                return(((a->d[i])>>j)&((BN_ULONG)1));
                }
        void BN_set_negative(BIGNUM *a, int b)
                {
                if (b && !BN_is_zero(a))
                        a->neg = 1;
                else
                        a->neg = 0;
                }

        int bn_cmp_words(const BN_ULONG *a, const BN_ULONG *b, int n)
                {
                int i;
                BN_ULONG aa,bb;

                aa=a[n-1];
                bb=b[n-1];
                if (aa != bb) return((aa > bb)?1:-1);
                for (i=n-2; i>=0; i--)
                        {
                        aa=a[i];
                        bb=b[i];
                        if (aa != bb) return((aa > bb)?1:-1);
                        }
                return(0);
                }

        int bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b,
                int cl, int dl)
                {
                int n,i;
                n = cl-1;

                if (dl < 0)
                        {
                        for (i=dl; i<0; i++)
                                {
                                if (b[n-i] != 0)
                                        return -1; /* a < b */
                                }
                        }
                if (dl > 0)
                        {
                        for (i=dl; i>0; i--)
                                {
                                if (a[n+i] != 0)
                                        return 1; /* a > b */
                                }
                        }
                return bn_cmp_words(a,b,cl);
                }

        void BN_clear(BIGNUM *a)
        {
                bn_check_top(a);
                if (a->d != NULL)
                        memset(a->d,0,a->dmax*sizeof(a->d[0]));
                a->top=0;
                a->neg=0;
                }

        int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                                  BN_MONT_CTX *mont, BN_CTX *ctx)
                {
                BIGNUM *tmp;
                int ret=0;

                BN_CTX_start(ctx);
                tmp = BN_CTX_get(ctx);
                if (tmp == NULL) goto err;

                bn_check_top(tmp);

                if (a == b)
                        {
                        if (!BN_sqr(tmp,a,ctx)) goto err;
                        }
                else
                        {
                        if (!BN_mul(tmp,a,b,ctx)) goto err;
                        }
                if (!BN_from_montgomery(r,tmp,mont,ctx)) goto err;

                bn_check_top(r);
                ret=1;
        err:
                BN_CTX_end(ctx);
                return(ret);
                }

        int BN_from_montgomery(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
                     BN_CTX *ctx)
                {
                int retn=0;

                BIGNUM *n,*r;
                BN_ULONG *ap,*np,*rp,n0,v,*nrp;
                int al,nl,max,i,x,ri;

                BN_CTX_start(ctx);
                if ((r = BN_CTX_get(ctx)) == NULL) goto err;

                if (!BN_copy(r,a)) goto err;
                n= &(mont->N);

                ap=a->d;
                /* mont->ri is the size of mont->N in bits (rounded up
                   to the word size) */
                al=ri=mont->ri/BN_BITS2;

                nl=n->top;
                if ((al == 0) || (nl == 0)) { r->top=0; return(1); }

                max=(nl+al+1); /* allow for overflow (no?) XXX */
                if (bn_wexpand(r,max) == NULL) goto err;

                r->neg=a->neg^n->neg;
                np=n->d;
                rp=r->d;
                nrp= &(r->d[nl]);

                for (i=r->top; i<max; i++) /* memset? XXX */
                        r->d[i]=0;
                r->top=max;
                n0=mont->n0;

                for (i=0; i<nl; i++)
                        {
                        v=bn_mul_add_words(rp,np,nl,(rp[0]*n0)&BN_MASK2);
                        nrp++;
                        rp++;
                        if (((nrp[-1]+=v)&BN_MASK2) >= v)
                                continue;
                        else
                                {
                                if (((++nrp[0])&BN_MASK2) != 0) continue;
                                if (((++nrp[1])&BN_MASK2) != 0) continue;
                                for (x=2; (((++nrp[x])&BN_MASK2) == 0); x++) ;
                                }
                        }
                bn_correct_top(r);

                if (r->top <= ri)
                        {
                        ret->top=0;
                        retn=1;
                        goto err;
                        }
                al=r->top-ri;

                if (bn_wexpand(ret,ri) == NULL) goto err;
                x=0-(((al-ri)>>(sizeof(al)*8-1))&1);
                ret->top=x=(ri&~x)|(al&x);	/* min(ri,al) */
                ret->neg=r->neg;

                rp=ret->d;
                ap=&(r->d[ri]);

                {
                unsigned int m1,m2;

                v=bn_sub_words(rp,ap,np,ri);
                m1=0-(unsigned int)(((al-ri)>>(sizeof(al)*8-1))&1);	/* al<ri */
                m2=0-(unsigned int)(((ri-al)>>(sizeof(al)*8-1))&1);	/* al>ri */
                m1|=m2;			/* (al!=ri) */
                m1|=(0-(unsigned int)v);	/* (al!=ri || v) */
                m1&=~m2;		/* (al!=ri || v) && !al>ri */
                nrp=(BN_ULONG *)(((intptr_t)rp&~m1)|((intptr_t)ap&m1));
                }

                for (i=0,ri-=4; i<ri; i+=4)
                        {
                        BN_ULONG t1,t2,t3,t4;

                        t1=nrp[i+0];
                        t2=nrp[i+1];
                        t3=nrp[i+2];	ap[i+0]=0;
                        t4=nrp[i+3];	ap[i+1]=0;
                        rp[i+0]=t1;	ap[i+2]=0;
                        rp[i+1]=t2;	ap[i+3]=0;
                        rp[i+2]=t3;
                        rp[i+3]=t4;
                        }
                for (ri+=4; i<ri; i++)
                        rp[i]=nrp[i], ap[i]=0;
                bn_correct_top(r);
                bn_correct_top(ret);
                retn=1;
                bn_check_top(ret);
         err:
                BN_CTX_end(ctx);
                return(retn);
                }

        BN_MONT_CTX *BN_MONT_CTX_new(void)
                {
                BN_MONT_CTX *ret;

                if ((ret=(BN_MONT_CTX *)malloc(sizeof(BN_MONT_CTX))) == NULL)
                        return(NULL);

                BN_MONT_CTX_init(ret);
                ret->flags=BN_FLG_MALLOCED;
                return(ret);
                }

        void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
                {
                ctx->ri=0;
                BN_init(&(ctx->RR));
                BN_init(&(ctx->N));
                BN_init(&(ctx->Ni));
                ctx->flags=0;
                }

        void BN_MONT_CTX_free(BN_MONT_CTX *mont)
                {
                if(mont == NULL)
                    return;

                BN_free(&(mont->RR));
                BN_free(&(mont->N));
                BN_free(&(mont->Ni));
                if (mont->flags & BN_FLG_MALLOCED)
                        free(mont);
                }
        BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock,
                                                const BIGNUM *mod, BN_CTX *ctx)
                {
                int got_write_lock = 0;
                BN_MONT_CTX *ret;

                if (!*pmont)
                        {
                        got_write_lock = 1;

                        if (!*pmont)
                                {
                                ret = BN_MONT_CTX_new();
                                if (ret && !BN_MONT_CTX_set(ret, mod, ctx))
                                        BN_MONT_CTX_free(ret);
                                else
                                        *pmont = ret;
                                }
                        }

                ret = *pmont;
                return ret;
                }

        int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
                {
                int ret = 0;
                BIGNUM *Ri,*R;

                BN_CTX_start(ctx);
                if((Ri = BN_CTX_get(ctx)) == NULL) goto err;
                R= &(mont->RR);					/* grab RR as a temp */
                if (!BN_copy(&(mont->N),mod)) goto err;		/* Set N */
                mont->N.neg = 0;

                        {
                        BIGNUM tmod;
                        BN_ULONG buf[2];

                        mont->ri=(BN_num_bits(mod)+(BN_BITS2-1))/BN_BITS2*BN_BITS2;
                        BN_zero(R);
                        if (!(BN_set_bit(R,BN_BITS2))) goto err;	/* R */

                        buf[0]=mod->d[0]; /* tmod = N mod word size */
                        buf[1]=0;
                        tmod.d=buf;
                        tmod.top = buf[0] != 0 ? 1 : 0;
                        tmod.dmax=2;
                        tmod.neg=0;
                                                                /* Ri = R^-1 mod N*/
                        if ((BN_mod_inverse(Ri,R,&tmod,ctx)) == NULL)
                                goto err;
                        if (!BN_lshift(Ri,Ri,BN_BITS2)) goto err; /* R*Ri */
                        if (!BN_is_zero(Ri))
                                {
                                if (!BN_sub_word(Ri,1)) goto err;
                                }
                        else /* if N mod word size == 1 */
                                {
                                if (!BN_set_word(Ri,BN_MASK2)) goto err;  /* Ri-- (mod word size) */
                                }
                        if (!BN_div(Ri,NULL,Ri,&tmod,ctx)) goto err;
                        /* Ni = (R*Ri-1)/N,
                         * keep only least significant word: */
                        mont->n0 = (Ri->top > 0) ? Ri->d[0] : 0;
                        }
                /* setup RR for conversions */
                BN_zero(&(mont->RR));
                if (!BN_set_bit(&(mont->RR),mont->ri*2)) goto err;
                if (!BN_mod(&(mont->RR),&(mont->RR),&(mont->N),ctx)) goto err;

                ret = 1;
        err:
                BN_CTX_end(ctx);
                return ret;
                }


        int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
                {
                if (!(BN_mod(r,m,d,ctx)))
                        return 0;
                if (!r->neg)
                        return 1;
                return (d->neg ? BN_sub : BN_add)(r, r, d);
        }

        int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
                {
                if (!BN_add(r, a, b)) return 0;
                return BN_nnmod(r, r, m, ctx);
                }
        int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
                {
                if (!BN_sub(r, a, b)) return 0;
                return BN_nnmod(r, r, m, ctx);
                }
        /* slow but works */
        int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
                BN_CTX *ctx)
                {
                BIGNUM *t;
                int ret=0;

                bn_check_top(a);
                bn_check_top(b);
                bn_check_top(m);

                BN_CTX_start(ctx);
                if ((t = BN_CTX_get(ctx)) == NULL) goto err;
                if (a == b)
                        { if (!BN_sqr(t,a,ctx)) goto err; }
                else
                        { if (!BN_mul(t,a,b,ctx)) goto err; }
                if (!BN_nnmod(r,t,m,ctx)) goto err;
                bn_check_top(r);
                ret=1;
        err:
                BN_CTX_end(ctx);
                return(ret);
                }


        int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
                {
                if (!BN_sqr(r, a, ctx)) return 0;
                /* r->neg == 0,  thus we don't need BN_nnmod */
                return BN_mod(r, r, m, ctx);
                }

        void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int n)
        {
            (dest)->d=(b)->d;
            (dest)->top=(b)->top;
            (dest)->dmax=(b)->dmax;
            (dest)->neg=(b)->neg;
            (dest)->flags=(((dest)->flags & BN_FLG_MALLOCED)|((b)->flags & ~BN_FLG_MALLOCED)|BN_FLG_STATIC_DATA | (n));
        }

        static BIGNUM *euclid(BIGNUM *a, BIGNUM *b);

        int BN_gcd(BIGNUM *r, const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx)
                {
                BIGNUM *a,*b,*t;
                int ret=0;

                bn_check_top(in_a);
                bn_check_top(in_b);

                BN_CTX_start(ctx);
                a = BN_CTX_get(ctx);
                b = BN_CTX_get(ctx);
                if (a == NULL || b == NULL) goto err;

                if (BN_copy(a,in_a) == NULL) goto err;
                if (BN_copy(b,in_b) == NULL) goto err;
                a->neg = 0;
                b->neg = 0;

                if (BN_cmp(a,b) < 0) { t=a; a=b; b=t; }
                t=euclid(a,b);
                if (t == NULL) goto err;

                if (BN_copy(r,t) == NULL) goto err;
                ret=1;
        err:
                BN_CTX_end(ctx);
                bn_check_top(r);
                return(ret);
                }

        static BIGNUM *euclid(BIGNUM *a, BIGNUM *b)
                {
                BIGNUM *t;
                int shifts=0;

                bn_check_top(a);
                bn_check_top(b);

                /* 0 <= b <= a */
                while (!BN_is_zero(b))
                        {
                        /* 0 < b <= a */

                        if (BN_is_odd(a))
                                {
                                if (BN_is_odd(b))
                                        {
                                        if (!BN_sub(a,a,b)) goto err;
                                        if (!BN_rshift1(a,a)) goto err;
                                        if (BN_cmp(a,b) < 0)
                                                { t=a; a=b; b=t; }
                                        }
                                else		/* a odd - b even */
                                        {
                                        if (!BN_rshift1(b,b)) goto err;
                                        if (BN_cmp(a,b) < 0)
                                                { t=a; a=b; b=t; }
                                        }
                                }
                        else			/* a is even */
                                {
                                if (BN_is_odd(b))
                                        {
                                        if (!BN_rshift1(a,a)) goto err;
                                        if (BN_cmp(a,b) < 0)
                                                { t=a; a=b; b=t; }
                                        }
                                else		/* a even - b even */
                                        {
                                        if (!BN_rshift1(a,a)) goto err;
                                        if (!BN_rshift1(b,b)) goto err;
                                        shifts++;
                                        }
                                }
                        /* 0 <= b <= a */
                        }

                if (shifts)
                        {
                        if (!BN_lshift(a,a,shifts)) goto err;
                        }
                bn_check_top(a);
                return(a);
        err:
                return(NULL);
                }
        static BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
                const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
        BIGNUM *BN_mod_inverse(BIGNUM *in,
                const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
                {
                BIGNUM *A,*B,*X,*Y,*M,*D,*T,*R=NULL;
                BIGNUM *ret=NULL;
                int sign;

                if ((BN_get_flags(a, BN_FLG_CONSTTIME) != 0) || (BN_get_flags(n, BN_FLG_CONSTTIME) != 0))
                        {
        //		return BN_mod_inverse_no_branch(in, a, n, ctx);
                        }

                bn_check_top(a);
                bn_check_top(n);

                BN_CTX_start(ctx);
                A = BN_CTX_get(ctx);
                B = BN_CTX_get(ctx);
                X = BN_CTX_get(ctx);
                D = BN_CTX_get(ctx);
                M = BN_CTX_get(ctx);
                Y = BN_CTX_get(ctx);
                T = BN_CTX_get(ctx);
                if (T == NULL) goto err;

                if (in == NULL)
                        R=BN_new();
                else
                        R=in;
                if (R == NULL) goto err;

                BN_one(X);
                BN_zero(Y);
                if (BN_copy(B,a) == NULL) goto err;
                if (BN_copy(A,n) == NULL) goto err;
                A->neg = 0;
                if (B->neg || (BN_ucmp(B, A) >= 0))
                        {
                        if (!BN_nnmod(B, B, A, ctx)) goto err;
                        }
                sign = -1;

                if (BN_is_odd(n) && (BN_num_bits(n) <= (BN_BITS <= 32 ? 450 : 2048)))
                        {
                        int shift;

                        while (!BN_is_zero(B))
                                {
                                shift = 0;
                                while (!BN_is_bit_set(B, shift)) /* note that 0 < B */
                                        {
                                        shift++;

                                        if (BN_is_odd(X))
                                                {
                                                if (!BN_uadd(X, X, n)) goto err;
                                                }
                                        if (!BN_rshift1(X, X)) goto err;
                                        }
                                if (shift > 0)
                                        {
                                        if (!BN_rshift(B, B, shift)) goto err;
                                        }
                                shift = 0;
                                while (!BN_is_bit_set(A, shift)) /* note that 0 < A */
                                        {
                                        shift++;

                                        if (BN_is_odd(Y))
                                                {
                                                if (!BN_uadd(Y, Y, n)) goto err;
                                                }
                                        /* now Y is even */
                                        if (!BN_rshift1(Y, Y)) goto err;
                                        }
                                if (shift > 0)
                                        {
                                        if (!BN_rshift(A, A, shift)) goto err;
                                        }

                                if (BN_ucmp(B, A) >= 0)
                                        {
                                        if (!BN_uadd(X, X, Y)) goto err;
                                        if (!BN_usub(B, B, A)) goto err;
                                        }
                                else
                                        {
                                        /*  sign*(X + Y)*a == A - B  (mod |n|) */
                                        if (!BN_uadd(Y, Y, X)) goto err;
                                        /* as above, BN_mod_add_quick(Y, Y, X, n) would slow things down */
                                        if (!BN_usub(A, A, B)) goto err;
                                        }
                                }
                        }
                else
                        {
                        /* general inversion algorithm */

                        while (!BN_is_zero(B))
                                {
                                BIGNUM *tmp;

                                if (BN_num_bits(A) == BN_num_bits(B))
                                        {
                                        if (!BN_one(D)) goto err;
                                        if (!BN_sub(M,A,B)) goto err;
                                        }
                                else if (BN_num_bits(A) == BN_num_bits(B) + 1)
                                        {
                                        /* A/B is 1, 2, or 3 */
                                        if (!BN_lshift1(T,B)) goto err;
                                        if (BN_ucmp(A,T) < 0)
                                                {
                                                /* A < 2*B, so D=1 */
                                                if (!BN_one(D)) goto err;
                                                if (!BN_sub(M,A,B)) goto err;
                                                }
                                        else
                                                {
                                                /* A >= 2*B, so D=2 or D=3 */
                                                if (!BN_sub(M,A,T)) goto err;
                                                if (!BN_add(D,T,B)) goto err; /* use D (:= 3*B) as temp */
                                                if (BN_ucmp(A,D) < 0)
                                                        {
                                                        /* A < 3*B, so D=2 */
                                                        if (!BN_set_word(D,2)) goto err;
                                                        /* M (= A - 2*B) already has the correct value */
                                                        }
                                                else
                                                        {
                                                        /* only D=3 remains */
                                                        if (!BN_set_word(D,3)) goto err;
                                                        /* currently  M = A - 2*B,  but we need  M = A - 3*B */
                                                        if (!BN_sub(M,M,B)) goto err;
                                                        }
                                                }
                                        }
                                else
                                        {
                                        if (!BN_div(D,M,A,B,ctx)) goto err;
                                        }

                                tmp=A; /* keep the BIGNUM object, the value does not matter */
                                A=B;
                                B=M;
                                /* most of the time D is very small, so we can optimize tmp := D*X+Y */
                                if (BN_is_one(D))
                                        {
                                        if (!BN_add(tmp,X,Y)) goto err;
                                        }
                                else
                                        {
                                        if (BN_is_word(D,2))
                                                {
                                                if (!BN_lshift1(tmp,X)) goto err;
                                                }
                                        else if (BN_is_word(D,4))
                                                {
                                                if (!BN_lshift(tmp,X,2)) goto err;
                                                }
                                        else if (D->top == 1)
                                                {
                                                if (!BN_copy(tmp,X)) goto err;
                                                if (!BN_mul_word(tmp,D->d[0])) goto err;
                                                }
                                        else
                                                {
                                                if (!BN_mul(tmp,D,X,ctx)) goto err;
                                                }
                                        if (!BN_add(tmp,tmp,Y)) goto err;
                                        }

                                M=Y; /* keep the BIGNUM object, the value does not matter */
                                Y=X;
                                X=tmp;
                                sign = -sign;
                                }
                        }
                if (sign < 0)
                        {
                        if (!BN_sub(Y,n,Y)) goto err;
                        }
                if (BN_is_one(A))
                        {
                        /* Y*a == 1  (mod |n|) */
                        if (!Y->neg && BN_ucmp(Y,n) < 0)
                                {
                                if (!BN_copy(R,Y)) goto err;
                                }
                        else
                                {
                                if (!BN_nnmod(R,Y,n,ctx)) goto err;
                                }
                        }
                else
                        goto err;
                ret=R;
        err:
                if ((ret == NULL) && (in == NULL)) BN_free(R);
                BN_CTX_end(ctx);
                bn_check_top(ret);
                return(ret);
                }

        static BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
                const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
                {
                BIGNUM *A,*B,*X,*Y,*M,*D,*T,*R=NULL;
                BIGNUM local_A, local_B;
                BIGNUM *pA, *pB;
                BIGNUM *ret=NULL;
                int sign;

                bn_check_top(a);
                bn_check_top(n);

                BN_CTX_start(ctx);
                A = BN_CTX_get(ctx);
                B = BN_CTX_get(ctx);
                X = BN_CTX_get(ctx);
                D = BN_CTX_get(ctx);
                M = BN_CTX_get(ctx);
                Y = BN_CTX_get(ctx);
                T = BN_CTX_get(ctx);
                if (T == NULL) goto err;

                if (in == NULL)
                        R=BN_new();
                else
                        R=in;
                if (R == NULL) goto err;

                BN_one(X);
                BN_zero(Y);
                if (BN_copy(B,a) == NULL) goto err;
                if (BN_copy(A,n) == NULL) goto err;
                A->neg = 0;

                if (B->neg || (BN_ucmp(B, A) >= 0))
                        {
                        pB = &local_B;
                        BN_with_flags(pB, B, BN_FLG_CONSTTIME);
                        if (!BN_nnmod(B, pB, A, ctx)) goto err;
                        }
                sign = -1;

                while (!BN_is_zero(B))
                        {
                        BIGNUM *tmp;

                        pA = &local_A;
                        BN_with_flags(pA, A, BN_FLG_CONSTTIME);

                        if (!BN_div(D,M,pA,B,ctx)) goto err;
                        tmp=A; /* keep the BIGNUM object, the value does not matter */

                        A=B;
                        B=M;

                        if (!BN_mul(tmp,D,X,ctx)) goto err;
                        if (!BN_add(tmp,tmp,Y)) goto err;

                        M=Y; /* keep the BIGNUM object, the value does not matter */
                        Y=X;
                        X=tmp;
                        sign = -sign;
                        }

                if (sign < 0)
                        {
                        if (!BN_sub(Y,n,Y)) goto err;
                        }
                if (BN_is_one(A))
                        {
                        if (!Y->neg && BN_ucmp(Y,n) < 0)
                                {
                                if (!BN_copy(R,Y)) goto err;
                                }
                        else
                                {
                                if (!BN_nnmod(R,Y,n,ctx)) goto err;
                                }
                        }
                else
                        {
                        printf("BN_F_BN_MOD_INVERSE_NO_BRANCH,BN_R_NO_INVERSE\n");
                        goto err;
                        }
                ret=R;
        err:
                if ((ret == NULL) && (in == NULL)) BN_free(R);
                BN_CTX_end(ctx);
                bn_check_top(ret);
                return(ret);
                }

        BN_ULONG bn_sub_part_words(BN_ULONG *r,
                const BN_ULONG *a, const BN_ULONG *b,
                int cl, int dl)
                {
                BN_ULONG c, t;

                c = bn_sub_words(r, a, b, cl);

                if (dl == 0)
                        return c;

                r += cl;
                a += cl;
                b += cl;

                if (dl < 0)
                        {
                        for (;;)
                                {
                                t = b[0];
                                r[0] = (0-t-c)&BN_MASK2;
                                if (t != 0) c=1;
                                if (++dl >= 0) break;

                                t = b[1];
                                r[1] = (0-t-c)&BN_MASK2;
                                if (t != 0) c=1;
                                if (++dl >= 0) break;

                                t = b[2];
                                r[2] = (0-t-c)&BN_MASK2;
                                if (t != 0) c=1;
                                if (++dl >= 0) break;

                                t = b[3];
                                r[3] = (0-t-c)&BN_MASK2;
                                if (t != 0) c=1;
                                if (++dl >= 0) break;

                                b += 4;
                                r += 4;
                                }
                        }
                else
                        {
                        int save_dl = dl;
                        while(c)
                                {
                                t = a[0];
                                r[0] = (t-c)&BN_MASK2;
                                if (t != 0) c=0;
                                if (--dl <= 0) break;

                                t = a[1];
                                r[1] = (t-c)&BN_MASK2;
                                if (t != 0) c=0;
                                if (--dl <= 0) break;

                                t = a[2];
                                r[2] = (t-c)&BN_MASK2;
                                if (t != 0) c=0;
                                if (--dl <= 0) break;

                                t = a[3];
                                r[3] = (t-c)&BN_MASK2;
                                if (t != 0) c=0;
                                if (--dl <= 0) break;

                                save_dl = dl;
                                a += 4;
                                r += 4;
                                }
                        if (dl > 0)
                                {
                                if (save_dl > dl)
                                        {
                                        switch (save_dl - dl)
                                                {
                                        case 1:
                                                r[1] = a[1];
                                                if (--dl <= 0) break;
                                        case 2:
                                                r[2] = a[2];
                                                if (--dl <= 0) break;
                                        case 3:
                                                r[3] = a[3];
                                                if (--dl <= 0) break;
                                                }
                                        a += 4;
                                        r += 4;
                                        }
                                }
                        if (dl > 0)
                                {
                                for(;;)
                                        {
                                        r[0] = a[0];
                                        if (--dl <= 0) break;
                                        r[1] = a[1];
                                        if (--dl <= 0) break;
                                        r[2] = a[2];
                                        if (--dl <= 0) break;
                                        r[3] = a[3];
                                        if (--dl <= 0) break;

                                        a += 4;
                                        r += 4;
                                        }
                                }
                        }
                return c;
                }

        void bn_mul_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2,
                int dna, int dnb, BN_ULONG *t)
                {
                int n=n2/2,c1,c2;
                int tna=n+dna, tnb=n+dnb;
                unsigned int neg,zero;
                BN_ULONG ln,lo,*p;

                /* Else do normal multiply */
                if (n2 < BN_MUL_RECURSIVE_SIZE_NORMAL)
                        {
                        bn_mul_normal(r,a,n2+dna,b,n2+dnb);
                        if ((dna + dnb) < 0)
                                memset(&r[2*n2 + dna + dnb], 0,
                                        sizeof(BN_ULONG) * -(dna + dnb));
                        return;
                        }
                /* r=(a[0]-a[1])*(b[1]-b[0]) */
                c1=bn_cmp_part_words(a,&(a[n]),tna,n-tna);
                c2=bn_cmp_part_words(&(b[n]),b,tnb,tnb-n);
                zero=neg=0;
                switch (c1*3+c2)
                        {
                case -4:
                        bn_sub_part_words(t,      &(a[n]),a,      tna,tna-n); /* - */
                        bn_sub_part_words(&(t[n]),b,      &(b[n]),tnb,n-tnb); /* - */
                        break;
                case -3:
                        zero=1;
                        break;
                case -2:
                        bn_sub_part_words(t,      &(a[n]),a,      tna,tna-n); /* - */
                        bn_sub_part_words(&(t[n]),&(b[n]),b,      tnb,tnb-n); /* + */
                        neg=1;
                        break;
                case -1:
                case 0:
                case 1:
                        zero=1;
                        break;
                case 2:
                        bn_sub_part_words(t,      a,      &(a[n]),tna,n-tna); /* + */
                        bn_sub_part_words(&(t[n]),b,      &(b[n]),tnb,n-tnb); /* - */
                        neg=1;
                        break;
                case 3:
                        zero=1;
                        break;
                case 4:
                        bn_sub_part_words(t,      a,      &(a[n]),tna,n-tna);
                        bn_sub_part_words(&(t[n]),&(b[n]),b,      tnb,tnb-n);
                        break;
                        }
                p= &(t[n2*2]);
                if (!zero)
                        bn_mul_recursive(&(t[n2]),t,&(t[n]),n,0,0,p);
                else
                        memset(&(t[n2]),0,n2*sizeof(BN_ULONG));
                bn_mul_recursive(r,a,b,n,0,0,p);
                bn_mul_recursive(&(r[n2]),&(a[n]),&(b[n]),n,dna,dnb,p);

                c1=(int)(bn_add_words(t,r,&(r[n2]),n2));

                if (neg) /* if t[32] is negative */
                        {
                        c1-=(int)(bn_sub_words(&(t[n2]),t,&(t[n2]),n2));
                        }
                else
                        {
                        /* Might have a carry */
                        c1+=(int)(bn_add_words(&(t[n2]),&(t[n2]),t,n2));
                        }

                c1+=(int)(bn_add_words(&(r[n]),&(r[n]),&(t[n2]),n2));
                if (c1)
                        {
                        p= &(r[n+n2]);
                        lo= *p;
                        ln=(lo+c1)&BN_MASK2;
                        *p=ln;

                        if (ln < (BN_ULONG)c1)
                                {
                                do	{
                                        p++;
                                        lo= *p;
                                        ln=(lo+1)&BN_MASK2;
                                        *p=ln;
                                        } while (ln == 0);
                                }
                        }
                }

        void bn_mul_part_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n,
                     int tna, int tnb, BN_ULONG *t)
                {
                int i,j,n2=n*2;
                int c1,c2,neg,zero;
                BN_ULONG ln,lo,*p;

                if (n < 8)
                        {
                        bn_mul_normal(r,a,n+tna,b,n+tnb);
                        return;
                        }

                /* r=(a[0]-a[1])*(b[1]-b[0]) */
                c1=bn_cmp_part_words(a,&(a[n]),tna,n-tna);
                c2=bn_cmp_part_words(&(b[n]),b,tnb,tnb-n);
                zero=neg=0;
                switch (c1*3+c2)
                        {
                case -4:
                        bn_sub_part_words(t,      &(a[n]),a,      tna,tna-n); /* - */
                        bn_sub_part_words(&(t[n]),b,      &(b[n]),tnb,n-tnb); /* - */
                        break;
                case -3:
                        zero=1;
                        /* break; */
                case -2:
                        bn_sub_part_words(t,      &(a[n]),a,      tna,tna-n); /* - */
                        bn_sub_part_words(&(t[n]),&(b[n]),b,      tnb,tnb-n); /* + */
                        neg=1;
                        break;
                case -1:
                case 0:
                case 1:
                        zero=1;
                        /* break; */
                case 2:
                        bn_sub_part_words(t,      a,      &(a[n]),tna,n-tna); /* + */
                        bn_sub_part_words(&(t[n]),b,      &(b[n]),tnb,n-tnb); /* - */
                        neg=1;
                        break;
                case 3:
                        zero=1;
                        /* break; */
                case 4:
                        bn_sub_part_words(t,      a,      &(a[n]),tna,n-tna);
                        bn_sub_part_words(&(t[n]),&(b[n]),b,      tnb,tnb-n);
                        break;
                        }
                p= &(t[n2*2]);
                bn_mul_recursive(&(t[n2]),t,&(t[n]),n,0,0,p);
                bn_mul_recursive(r,a,b,n,0,0,p);
                i=n/2;
                if (tna > tnb)
                        j = tna - i;
                else
                        j = tnb - i;
                if (j == 0)
                        {
                        bn_mul_recursive(&(r[n2]),&(a[n]),&(b[n]),
                                i,tna-i,tnb-i,p);
                        memset(&(r[n2+i*2]),0,sizeof(BN_ULONG)*(n2-i*2));
                        }
                else if (j > 0) /* eg, n == 16, i == 8 and tn == 11 */
                                {
                                bn_mul_part_recursive(&(r[n2]),&(a[n]),&(b[n]),
                                        i,tna-i,tnb-i,p);
                                memset(&(r[n2+tna+tnb]),0,
                                        sizeof(BN_ULONG)*(n2-tna-tnb));
                                }
                else /* (j < 0) eg, n == 16, i == 8 and tn == 5 */
                        {
                        memset(&(r[n2]),0,sizeof(BN_ULONG)*n2);
                        if (tna < BN_MUL_RECURSIVE_SIZE_NORMAL
                                && tnb < BN_MUL_RECURSIVE_SIZE_NORMAL)
                                {
                                bn_mul_normal(&(r[n2]),&(a[n]),tna,&(b[n]),tnb);
                                }
                        else
                                {
                                for (;;)
                                        {
                                        i/=2;
                                        if (i <= tna && tna == tnb)
                                                {
                                                bn_mul_recursive(&(r[n2]),
                                                        &(a[n]),&(b[n]),
                                                        i,tna-i,tnb-i,p);
                                                break;
                                                }
                                        else if (i < tna || i < tnb)
                                                {
                                                bn_mul_part_recursive(&(r[n2]),
                                                        &(a[n]),&(b[n]),
                                                        i,tna-i,tnb-i,p);
                                                break;
                                                }
                                        }
                                }
                        }

                c1=(int)(bn_add_words(t,r,&(r[n2]),n2));

                if (neg) /* if t[32] is negative */
                        {
                        c1-=(int)(bn_sub_words(&(t[n2]),t,&(t[n2]),n2));
                        }
                else
                        {
                        /* Might have a carry */
                        c1+=(int)(bn_add_words(&(t[n2]),&(t[n2]),t,n2));
                        }
                c1+=(int)(bn_add_words(&(r[n]),&(r[n]),&(t[n2]),n2));
                if (c1)
                        {
                        p= &(r[n+n2]);
                        lo= *p;
                        ln=(lo+c1)&BN_MASK2;
                        *p=ln;

                        if (ln < (BN_ULONG)c1)
                                {
                                do	{
                                        p++;
                                        lo= *p;
                                        ln=(lo+1)&BN_MASK2;
                                        *p=ln;
                                        } while (ln == 0);
                                }
                        }
                }

        int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
                {
                int ret=0;
                int top,al,bl;
                BIGNUM *rr;
                int i;
                BIGNUM *t=NULL;
                int j=0,k;
                bn_check_top(a);
                bn_check_top(b);
                bn_check_top(r);

                al=a->top;
                bl=b->top;

                if ((al == 0) || (bl == 0))
                        {
                        BN_zero(r);
                        return(1);
                        }
                top=al+bl;

                BN_CTX_start(ctx);
                if ((r == a) || (r == b))
                        {
                        if ((rr = BN_CTX_get(ctx)) == NULL) goto err;
                        }
                else
                        rr = r;
                rr->neg=a->neg^b->neg;

                i = al-bl;
                if ((al >= BN_MULL_SIZE_NORMAL) && (bl >= BN_MULL_SIZE_NORMAL))
                        {
                        if (i >= -1 && i <= 1)
                                {
                                int sav_j =0;
                                /* Find out the power of two lower or equal
                                   to the longest of the two numbers */
                                if (i >= 0)
                                        {
                                        j = BN_num_bits_word((BN_ULONG)al);
                                        }
                                if (i == -1)
                                        {
                                        j = BN_num_bits_word((BN_ULONG)bl);
                                        }
                                sav_j = j;
                                j = 1<<(j-1);
                                k = j+j;
                                t = BN_CTX_get(ctx);
                                if (al > j || bl > j)
                                        {
                                        bn_wexpand(t,k*4);
                                        bn_wexpand(rr,k*4);
                                        bn_mul_part_recursive(rr->d,a->d,b->d,
                                                j,al-j,bl-j,t->d);
                                        }
                                else	/* al <= j || bl <= j */
                                        {
                                        bn_wexpand(t,k*2);
                                        bn_wexpand(rr,k*2);
                                        bn_mul_recursive(rr->d,a->d,b->d,
                                                j,al-j,bl-j,t->d);
                                        }
                                rr->top=top;
                                goto end;
                                }
                        }
                if (bn_wexpand(rr,top) == NULL) goto err;
                rr->top=top;
                bn_mul_normal(rr->d,a->d,al,b->d,bl);

        end:
                bn_correct_top(rr);
                if (r != rr) BN_copy(r,rr);
                ret=1;
        err:
                bn_check_top(r);
                BN_CTX_end(ctx);
                return(ret);
                }

        void bn_mul_normal(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb)
                {
                BN_ULONG *rr;

                if (na < nb)
                        {
                        int itmp;
                        BN_ULONG *ltmp;

                        itmp=na; na=nb; nb=itmp;
                        ltmp=a;   a=b;   b=ltmp;

                        }
                rr= &(r[na]);
                if (nb <= 0)
                        {
                        (void)bn_mul_words(r,a,na,0);
                        return;
                        }
                else
                        rr[0]=bn_mul_words(r,a,na,b[0]);

                for (;;)
                        {
                        if (--nb <= 0) return;
                        rr[1]=bn_mul_add_words(&(r[1]),a,na,b[1]);
                        if (--nb <= 0) return;
                        rr[2]=bn_mul_add_words(&(r[2]),a,na,b[2]);
                        if (--nb <= 0) return;
                        rr[3]=bn_mul_add_words(&(r[3]),a,na,b[3]);
                        if (--nb <= 0) return;
                        rr[4]=bn_mul_add_words(&(r[4]),a,na,b[4]);
                        rr+=4;
                        r+=4;
                        b+=4;
                        }
                }

        #define NUMPRIMES 2048
        static const unsigned int primes[NUMPRIMES]=
                {
                   2,   3,   5,   7,  11,  13,  17,  19,
                  23,  29,  31,  37,  41,  43,  47,  53,
                  59,  61,  67,  71,  73,  79,  83,  89,
                  97, 101, 103, 107, 109, 113, 127, 131,
                 137, 139, 149, 151, 157, 163, 167, 173,
                 179, 181, 191, 193, 197, 199, 211, 223,
                 227, 229, 233, 239, 241, 251, 257, 263,
                 269, 271, 277, 281, 283, 293, 307, 311,
                 313, 317, 331, 337, 347, 349, 353, 359,
                 367, 373, 379, 383, 389, 397, 401, 409,
                 419, 421, 431, 433, 439, 443, 449, 457,
                 461, 463, 467, 479, 487, 491, 499, 503,
                 509, 521, 523, 541, 547, 557, 563, 569,
                 571, 577, 587, 593, 599, 601, 607, 613,
                 617, 619, 631, 641, 643, 647, 653, 659,
                 661, 673, 677, 683, 691, 701, 709, 719,
                 727, 733, 739, 743, 751, 757, 761, 769,
                 773, 787, 797, 809, 811, 821, 823, 827,
                 829, 839, 853, 857, 859, 863, 877, 881,
                 883, 887, 907, 911, 919, 929, 937, 941,
                 947, 953, 967, 971, 977, 983, 991, 997,
                1009,1013,1019,1021,1031,1033,1039,1049,
                1051,1061,1063,1069,1087,1091,1093,1097,
                1103,1109,1117,1123,1129,1151,1153,1163,
                1171,1181,1187,1193,1201,1213,1217,1223,
                1229,1231,1237,1249,1259,1277,1279,1283,
                1289,1291,1297,1301,1303,1307,1319,1321,
                1327,1361,1367,1373,1381,1399,1409,1423,
                1427,1429,1433,1439,1447,1451,1453,1459,
                1471,1481,1483,1487,1489,1493,1499,1511,
                1523,1531,1543,1549,1553,1559,1567,1571,
                1579,1583,1597,1601,1607,1609,1613,1619,
                1621,1627,1637,1657,1663,1667,1669,1693,
                1697,1699,1709,1721,1723,1733,1741,1747,
                1753,1759,1777,1783,1787,1789,1801,1811,
                1823,1831,1847,1861,1867,1871,1873,1877,
                1879,1889,1901,1907,1913,1931,1933,1949,
                1951,1973,1979,1987,1993,1997,1999,2003,
                2011,2017,2027,2029,2039,2053,2063,2069,
                2081,2083,2087,2089,2099,2111,2113,2129,
                2131,2137,2141,2143,2153,2161,2179,2203,
                2207,2213,2221,2237,2239,2243,2251,2267,
                2269,2273,2281,2287,2293,2297,2309,2311,
                2333,2339,2341,2347,2351,2357,2371,2377,
                2381,2383,2389,2393,2399,2411,2417,2423,
                2437,2441,2447,2459,2467,2473,2477,2503,
                2521,2531,2539,2543,2549,2551,2557,2579,
                2591,2593,2609,2617,2621,2633,2647,2657,
                2659,2663,2671,2677,2683,2687,2689,2693,
                2699,2707,2711,2713,2719,2729,2731,2741,
                2749,2753,2767,2777,2789,2791,2797,2801,
                2803,2819,2833,2837,2843,2851,2857,2861,
                2879,2887,2897,2903,2909,2917,2927,2939,
                2953,2957,2963,2969,2971,2999,3001,3011,
                3019,3023,3037,3041,3049,3061,3067,3079,
                3083,3089,3109,3119,3121,3137,3163,3167,
                3169,3181,3187,3191,3203,3209,3217,3221,
                3229,3251,3253,3257,3259,3271,3299,3301,
                3307,3313,3319,3323,3329,3331,3343,3347,
                3359,3361,3371,3373,3389,3391,3407,3413,
                3433,3449,3457,3461,3463,3467,3469,3491,
                3499,3511,3517,3527,3529,3533,3539,3541,
                3547,3557,3559,3571,3581,3583,3593,3607,
                3613,3617,3623,3631,3637,3643,3659,3671,
                3673,3677,3691,3697,3701,3709,3719,3727,
                3733,3739,3761,3767,3769,3779,3793,3797,
                3803,3821,3823,3833,3847,3851,3853,3863,
                3877,3881,3889,3907,3911,3917,3919,3923,
                3929,3931,3943,3947,3967,3989,4001,4003,
                4007,4013,4019,4021,4027,4049,4051,4057,
                4073,4079,4091,4093,4099,4111,4127,4129,
                4133,4139,4153,4157,4159,4177,4201,4211,
                4217,4219,4229,4231,4241,4243,4253,4259,
                4261,4271,4273,4283,4289,4297,4327,4337,
                4339,4349,4357,4363,4373,4391,4397,4409,
                4421,4423,4441,4447,4451,4457,4463,4481,
                4483,4493,4507,4513,4517,4519,4523,4547,
                4549,4561,4567,4583,4591,4597,4603,4621,
                4637,4639,4643,4649,4651,4657,4663,4673,
                4679,4691,4703,4721,4723,4729,4733,4751,
                4759,4783,4787,4789,4793,4799,4801,4813,
                4817,4831,4861,4871,4877,4889,4903,4909,
                4919,4931,4933,4937,4943,4951,4957,4967,
                4969,4973,4987,4993,4999,5003,5009,5011,
                5021,5023,5039,5051,5059,5077,5081,5087,
                5099,5101,5107,5113,5119,5147,5153,5167,
                5171,5179,5189,5197,5209,5227,5231,5233,
                5237,5261,5273,5279,5281,5297,5303,5309,
                5323,5333,5347,5351,5381,5387,5393,5399,
                5407,5413,5417,5419,5431,5437,5441,5443,
                5449,5471,5477,5479,5483,5501,5503,5507,
                5519,5521,5527,5531,5557,5563,5569,5573,
                5581,5591,5623,5639,5641,5647,5651,5653,
                5657,5659,5669,5683,5689,5693,5701,5711,
                5717,5737,5741,5743,5749,5779,5783,5791,
                5801,5807,5813,5821,5827,5839,5843,5849,
                5851,5857,5861,5867,5869,5879,5881,5897,
                5903,5923,5927,5939,5953,5981,5987,6007,
                6011,6029,6037,6043,6047,6053,6067,6073,
                6079,6089,6091,6101,6113,6121,6131,6133,
                6143,6151,6163,6173,6197,6199,6203,6211,
                6217,6221,6229,6247,6257,6263,6269,6271,
                6277,6287,6299,6301,6311,6317,6323,6329,
                6337,6343,6353,6359,6361,6367,6373,6379,
                6389,6397,6421,6427,6449,6451,6469,6473,
                6481,6491,6521,6529,6547,6551,6553,6563,
                6569,6571,6577,6581,6599,6607,6619,6637,
                6653,6659,6661,6673,6679,6689,6691,6701,
                6703,6709,6719,6733,6737,6761,6763,6779,
                6781,6791,6793,6803,6823,6827,6829,6833,
                6841,6857,6863,6869,6871,6883,6899,6907,
                6911,6917,6947,6949,6959,6961,6967,6971,
                6977,6983,6991,6997,7001,7013,7019,7027,
                7039,7043,7057,7069,7079,7103,7109,7121,
                7127,7129,7151,7159,7177,7187,7193,7207,
                7211,7213,7219,7229,7237,7243,7247,7253,
                7283,7297,7307,7309,7321,7331,7333,7349,
                7351,7369,7393,7411,7417,7433,7451,7457,
                7459,7477,7481,7487,7489,7499,7507,7517,
                7523,7529,7537,7541,7547,7549,7559,7561,
                7573,7577,7583,7589,7591,7603,7607,7621,
                7639,7643,7649,7669,7673,7681,7687,7691,
                7699,7703,7717,7723,7727,7741,7753,7757,
                7759,7789,7793,7817,7823,7829,7841,7853,
                7867,7873,7877,7879,7883,7901,7907,7919,
                7927,7933,7937,7949,7951,7963,7993,8009,
                8011,8017,8039,8053,8059,8069,8081,8087,
                8089,8093,8101,8111,8117,8123,8147,8161,
                8167,8171,8179,8191,8209,8219,8221,8231,
                8233,8237,8243,8263,8269,8273,8287,8291,
                8293,8297,8311,8317,8329,8353,8363,8369,
                8377,8387,8389,8419,8423,8429,8431,8443,
                8447,8461,8467,8501,8513,8521,8527,8537,
                8539,8543,8563,8573,8581,8597,8599,8609,
                8623,8627,8629,8641,8647,8663,8669,8677,
                8681,8689,8693,8699,8707,8713,8719,8731,
                8737,8741,8747,8753,8761,8779,8783,8803,
                8807,8819,8821,8831,8837,8839,8849,8861,
                8863,8867,8887,8893,8923,8929,8933,8941,
                8951,8963,8969,8971,8999,9001,9007,9011,
                9013,9029,9041,9043,9049,9059,9067,9091,
                9103,9109,9127,9133,9137,9151,9157,9161,
                9173,9181,9187,9199,9203,9209,9221,9227,
                9239,9241,9257,9277,9281,9283,9293,9311,
                9319,9323,9337,9341,9343,9349,9371,9377,
                9391,9397,9403,9413,9419,9421,9431,9433,
                9437,9439,9461,9463,9467,9473,9479,9491,
                9497,9511,9521,9533,9539,9547,9551,9587,
                9601,9613,9619,9623,9629,9631,9643,9649,
                9661,9677,9679,9689,9697,9719,9721,9733,
                9739,9743,9749,9767,9769,9781,9787,9791,
                9803,9811,9817,9829,9833,9839,9851,9857,
                9859,9871,9883,9887,9901,9907,9923,9929,
                9931,9941,9949,9967,9973,10007,10009,10037,
                10039,10061,10067,10069,10079,10091,10093,10099,
                10103,10111,10133,10139,10141,10151,10159,10163,
                10169,10177,10181,10193,10211,10223,10243,10247,
                10253,10259,10267,10271,10273,10289,10301,10303,
                10313,10321,10331,10333,10337,10343,10357,10369,
                10391,10399,10427,10429,10433,10453,10457,10459,
                10463,10477,10487,10499,10501,10513,10529,10531,
                10559,10567,10589,10597,10601,10607,10613,10627,
                10631,10639,10651,10657,10663,10667,10687,10691,
                10709,10711,10723,10729,10733,10739,10753,10771,
                10781,10789,10799,10831,10837,10847,10853,10859,
                10861,10867,10883,10889,10891,10903,10909,10937,
                10939,10949,10957,10973,10979,10987,10993,11003,
                11027,11047,11057,11059,11069,11071,11083,11087,
                11093,11113,11117,11119,11131,11149,11159,11161,
                11171,11173,11177,11197,11213,11239,11243,11251,
                11257,11261,11273,11279,11287,11299,11311,11317,
                11321,11329,11351,11353,11369,11383,11393,11399,
                11411,11423,11437,11443,11447,11467,11471,11483,
                11489,11491,11497,11503,11519,11527,11549,11551,
                11579,11587,11593,11597,11617,11621,11633,11657,
                11677,11681,11689,11699,11701,11717,11719,11731,
                11743,11777,11779,11783,11789,11801,11807,11813,
                11821,11827,11831,11833,11839,11863,11867,11887,
                11897,11903,11909,11923,11927,11933,11939,11941,
                11953,11959,11969,11971,11981,11987,12007,12011,
                12037,12041,12043,12049,12071,12073,12097,12101,
                12107,12109,12113,12119,12143,12149,12157,12161,
                12163,12197,12203,12211,12227,12239,12241,12251,
                12253,12263,12269,12277,12281,12289,12301,12323,
                12329,12343,12347,12373,12377,12379,12391,12401,
                12409,12413,12421,12433,12437,12451,12457,12473,
                12479,12487,12491,12497,12503,12511,12517,12527,
                12539,12541,12547,12553,12569,12577,12583,12589,
                12601,12611,12613,12619,12637,12641,12647,12653,
                12659,12671,12689,12697,12703,12713,12721,12739,
                12743,12757,12763,12781,12791,12799,12809,12821,
                12823,12829,12841,12853,12889,12893,12899,12907,
                12911,12917,12919,12923,12941,12953,12959,12967,
                12973,12979,12983,13001,13003,13007,13009,13033,
                13037,13043,13049,13063,13093,13099,13103,13109,
                13121,13127,13147,13151,13159,13163,13171,13177,
                13183,13187,13217,13219,13229,13241,13249,13259,
                13267,13291,13297,13309,13313,13327,13331,13337,
                13339,13367,13381,13397,13399,13411,13417,13421,
                13441,13451,13457,13463,13469,13477,13487,13499,
                13513,13523,13537,13553,13567,13577,13591,13597,
                13613,13619,13627,13633,13649,13669,13679,13681,
                13687,13691,13693,13697,13709,13711,13721,13723,
                13729,13751,13757,13759,13763,13781,13789,13799,
                13807,13829,13831,13841,13859,13873,13877,13879,
                13883,13901,13903,13907,13913,13921,13931,13933,
                13963,13967,13997,13999,14009,14011,14029,14033,
                14051,14057,14071,14081,14083,14087,14107,14143,
                14149,14153,14159,14173,14177,14197,14207,14221,
                14243,14249,14251,14281,14293,14303,14321,14323,
                14327,14341,14347,14369,14387,14389,14401,14407,
                14411,14419,14423,14431,14437,14447,14449,14461,
                14479,14489,14503,14519,14533,14537,14543,14549,
                14551,14557,14561,14563,14591,14593,14621,14627,
                14629,14633,14639,14653,14657,14669,14683,14699,
                14713,14717,14723,14731,14737,14741,14747,14753,
                14759,14767,14771,14779,14783,14797,14813,14821,
                14827,14831,14843,14851,14867,14869,14879,14887,
                14891,14897,14923,14929,14939,14947,14951,14957,
                14969,14983,15013,15017,15031,15053,15061,15073,
                15077,15083,15091,15101,15107,15121,15131,15137,
                15139,15149,15161,15173,15187,15193,15199,15217,
                15227,15233,15241,15259,15263,15269,15271,15277,
                15287,15289,15299,15307,15313,15319,15329,15331,
                15349,15359,15361,15373,15377,15383,15391,15401,
                15413,15427,15439,15443,15451,15461,15467,15473,
                15493,15497,15511,15527,15541,15551,15559,15569,
                15581,15583,15601,15607,15619,15629,15641,15643,
                15647,15649,15661,15667,15671,15679,15683,15727,
                15731,15733,15737,15739,15749,15761,15767,15773,
                15787,15791,15797,15803,15809,15817,15823,15859,
                15877,15881,15887,15889,15901,15907,15913,15919,
                15923,15937,15959,15971,15973,15991,16001,16007,
                16033,16057,16061,16063,16067,16069,16073,16087,
                16091,16097,16103,16111,16127,16139,16141,16183,
                16187,16189,16193,16217,16223,16229,16231,16249,
                16253,16267,16273,16301,16319,16333,16339,16349,
                16361,16363,16369,16381,16411,16417,16421,16427,
                16433,16447,16451,16453,16477,16481,16487,16493,
                16519,16529,16547,16553,16561,16567,16573,16603,
                16607,16619,16631,16633,16649,16651,16657,16661,
                16673,16691,16693,16699,16703,16729,16741,16747,
                16759,16763,16787,16811,16823,16829,16831,16843,
                16871,16879,16883,16889,16901,16903,16921,16927,
                16931,16937,16943,16963,16979,16981,16987,16993,
                17011,17021,17027,17029,17033,17041,17047,17053,
                17077,17093,17099,17107,17117,17123,17137,17159,
                17167,17183,17189,17191,17203,17207,17209,17231,
                17239,17257,17291,17293,17299,17317,17321,17327,
                17333,17341,17351,17359,17377,17383,17387,17389,
                17393,17401,17417,17419,17431,17443,17449,17467,
                17471,17477,17483,17489,17491,17497,17509,17519,
                17539,17551,17569,17573,17579,17581,17597,17599,
                17609,17623,17627,17657,17659,17669,17681,17683,
                17707,17713,17729,17737,17747,17749,17761,17783,
                17789,17791,17807,17827,17837,17839,17851,17863,
                };

        static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
                const BIGNUM *a1_odd, int k, BN_CTX *ctx, BN_MONT_CTX *mont);
        static int probable_prime(BIGNUM *rnd, int bits);

        #define BN_prime_checks_for_size(b) \
            ((b) >= 1300 ?  2 : \
            (b) >=  850 ?  3 : \
            (b) >=  650 ?  4 : \
            (b) >=  550 ?  5 : \
            (b) >=  450 ?  6 : \
            (b) >=  400 ?  7 : \
            (b) >=  350 ?  8 : \
            (b) >=  300 ?  9 : \
            (b) >=  250 ? 12 : \
            (b) >=  200 ? 15 : \
            (b) >=  150 ? 18 : \
            27)




        int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe,
                const BIGNUM *add, const BIGNUM *rem)
                {
                BIGNUM *t;
                int found=0;
                int i;
                BN_CTX *ctx;
                int checks = BN_prime_checks_for_size(bits);

                ctx=BN_CTX_new();
                if (ctx == NULL) goto err;
                BN_CTX_start(ctx);
                t = BN_CTX_get(ctx);
                if(!t) goto err;
        loop:
                /* make a random number and set the top and bottom bits */
                        {
                        if (!probable_prime(ret,bits)) goto err;
                        }



                        {
                        i=BN_is_prime_fasttest_ex(ret,checks,ctx,0);
                        if (i == -1) goto err;
                        if (i == 0) goto loop;
                        }
                /* we have a prime :-) */
                found = 1;
        err:
                if (ctx != NULL)
                        {
                        BN_CTX_end(ctx);
                        BN_CTX_free(ctx);
                        }
                bn_check_top(ret);
                return found;
        }

        int BN_is_prime_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed)
                {
                return BN_is_prime_fasttest_ex(a, checks, ctx_passed, 0);
                }

        int BN_is_prime_fasttest_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed,
                        int do_trial_division)
                {
                int i, j, ret = -1;
                int k;
                BN_CTX *ctx = NULL;
                BIGNUM *A1, *A1_odd, *check; /* taken from ctx */
                BN_MONT_CTX *mont = NULL;
                const BIGNUM *A = NULL;

                if (BN_cmp(a, BN_value_one()) <= 0)
                        return 0;

                if (checks == BN_prime_checks)
                        checks = BN_prime_checks_for_size(BN_num_bits(a));

                /* first look for small factors */
                if (!BN_is_odd(a))
                        /* a is even => a is prime if and only if a == 2 */
                        return BN_is_word(a, 2);
                if (do_trial_division)
                        {
                        for (i = 1; i < NUMPRIMES; i++)
                                if (BN_mod_word(a, primes[i]) == 0)
                                        return 0;
                        }

                if (ctx_passed != NULL)
                        ctx = ctx_passed;
                else
                        if ((ctx=BN_CTX_new()) == NULL)
                                goto err;
                BN_CTX_start(ctx);

                /* A := abs(a) */
                if (a->neg)
                        {
                        BIGNUM *t;
                        if ((t = BN_CTX_get(ctx)) == NULL) goto err;
                        BN_copy(t, a);
                        t->neg = 0;
                        A = t;
                        }
                else
                        A = a;
                A1 = BN_CTX_get(ctx);
                A1_odd = BN_CTX_get(ctx);
                check = BN_CTX_get(ctx);
                if (check == NULL) goto err;

                /* compute A1 := A - 1 */
                if (!BN_copy(A1, A))
                        goto err;
                if (!BN_sub_word(A1, 1))
                        goto err;
                if (BN_is_zero(A1))
                        {
                        ret = 0;
                        goto err;
                        }

                /* write  A1  as  A1_odd * 2^k */
                k = 1;
                while (!BN_is_bit_set(A1, k))
                        k++;
                if (!BN_rshift(A1_odd, A1, k))
                        goto err;

                /* Montgomery setup for computations mod A */
                mont = BN_MONT_CTX_new();
                if (mont == NULL)
                        goto err;
                if (!BN_MONT_CTX_set(mont, A, ctx))
                        goto err;

                for (i = 0; i < checks; i++)
                        {
                        if (!BN_pseudo_rand_range(check, A1))
                                goto err;
                        if (!BN_add_word(check, 1))
                                goto err;
                        /* now 1 <= check < A */

                        j = witness(check, A, A1, A1_odd, k, ctx, mont);
                        if (j == -1) goto err;
                        if (j)
                                {
                                ret=0;
                                goto err;
                                }

                        }
                ret=1;
        err:
                if (ctx != NULL)
                        {
                        BN_CTX_end(ctx);
                        if (ctx_passed == NULL)
                                BN_CTX_free(ctx);
                        }
                if (mont != NULL)
                        BN_MONT_CTX_free(mont);

                return(ret);
                }

        static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
                const BIGNUM *a1_odd, int k, BN_CTX *ctx, BN_MONT_CTX *mont)
                {
                if (!BN_mod_exp_mont(w, w, a1_odd, a, ctx)) /* w := w^a1_odd mod a */
                        return -1;
                if (BN_is_one(w))
                        return 0; /* probably prime */
                if (BN_cmp(w, a1) == 0)
                        return 0; /* w == -1 (mod a),  'a' is probably prime */
                while (--k)
                        {
                        if (!BN_mod_mul(w, w, w, a, ctx)) /* w := w^2 mod a */
                                return -1;
                        if (BN_is_one(w))
                                return 1; /* 'a' is composite, otherwise a previous 'w' would
                                           * have been == -1 (mod 'a') */
                        if (BN_cmp(w, a1) == 0)
                                return 0; /* w == -1 (mod a), 'a' is probably prime */
                        }
                /* If we get here, 'w' is the (a-1)/2-th power of the original 'w',
                 * and it is neither -1 nor +1 -- so 'a' cannot be prime */
                bn_check_top(w);
                return 1;
                }



        static int probable_prime(BIGNUM *rnd, int bits)

                {

                        int i;

                        BN_ULONG mods[NUMPRIMES];

                        BN_ULONG delta,maxdelta;

        again:

                        if (!BN_rand(rnd,bits,1,1))
                        return(0);

                        /* we now have a random number 'rand' to test. */

                        for (i=1; i<NUMPRIMES; i++)

                        mods[i]=(BN_ULONG)BN_mod_word(rnd,(BN_ULONG)primes[i]);

                        maxdelta=BN_MASK2 - primes[NUMPRIMES-1];

                        delta=0;

                        loop:
                        for (i=1; i<NUMPRIMES; i++)

                        {

                        /* check that rnd is not a prime and also

                        * that gcd(rnd-1,primes) == 1 (except for 2) */

                        if (((mods[i]+delta)%primes[i]) <= 1)

                                {

                                delta+=2;

                                if (delta > maxdelta) goto again;

                                goto loop;

                                }

                                }

                                if (!BN_add_word(rnd,delta))
                                return(0);

                                bn_check_top(rnd);

                                return(1);

                }

        #endif        //_HEADER_BN_H_ todo
        //-------------------- end bn---------------------
        
        #ifndef HEADER_RSA_H
        #define HEADER_RSA_H

        typedef struct rsa_st RSA;
        struct rsa_st
                {
                int pad;
                BIGNUM *n;
                BIGNUM *e;
                BIGNUM *d;
                BIGNUM *p;
                BIGNUM *q;
                BIGNUM *dmp1;//d mod p-1
                BIGNUM *dmq1;//d mod q-1
                BIGNUM *iqmp;//inverse(q) mod p//q^-1 mod p
                int flags;

                };

        #define RSA_MAX_KEY_BITS	1024
        #define RSA_MAX_MODULUS_BITS	16384
        #define RSA_SMALL_MODULUS_BITS	3072
        #define RSA_MAX_PUBEXP_BITS	64 /* exponent limit enforced for "large" modulus only */
        #define RSA_3	0x3L
        #define RSA_17  0x11L
        #define RSA_F4	0x10001L
        #define RSA_FLAG_CACHE_PUBLIC		0x0002
        #define RSA_FLAG_CACHE_PRIVATE		0x0004
        #define RSA_FLAG_THREAD_SAFE		0x0010
        #define RSA_FLAG_EXT_PKEY			0x0020
        #define RSA_FLAG_NO_CONSTTIME		0x0100
        #define RSA_PKCS1_PADDING		1
        #define RSA_SSLV23_PADDING		2
        #define RSA_NO_PADDING			3
        #define RSA_PKCS1_OAEP_PADDING	4
        #define RSA_X931_PADDING		5
        #define RSA_PKCS1_PADDING_SIZE		11
        #define RSA_F_RSA_GENERATE_KEY				 105
        #define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1		 108
        #define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1		 112
        #define RSA_F_RSA_PADDING_ADD_NONE			 107
        #define RSA_F_RSA_PADDING_CHECK_NONE			 111
        #define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2		 109
        #define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2		 113
        #define RSA_F_RSA_PADDING_ADD_SSLV23			 110
        #define RSA_F_RSA_PADDING_ADD_X931			 127
        #define RSA_F_RSA_PADDING_CHECK_SSLV23			 114
        #define RSA_F_RSA_PADDING_CHECK_X931			 128

        RSA*	RSA_new();
        void	RSA_free(RSA *rsa);

        int	RSA_encode_key(RSA* rsa, unsigned char **out, int *out_len, int is_priv);
        RSA*	RSA_decode_key(unsigned char *in, int in_len, int is_priv);

        RSA*	RSA_generate_key(int bit_len);
        int	RSA_public_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
        int	RSA_private_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
        int	RSA_public_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
        int	RSA_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
        int 	RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
                        const unsigned char *from, int flen);
        int 	RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
                        const unsigned char *from, int flen, int num);
        int 	RSA_padding_add_PKCS1_type_2(unsigned char *to,int tlen,
                        const unsigned char *f,int fl);
        int 	RSA_padding_check_PKCS1_type_2(unsigned char *to,int tlen,
                        const unsigned char *f,int fl,int rsa_len);
        int 	RSA_padding_add_SSLv23(unsigned char *to,int tlen,
                        const unsigned char *f,int fl);
        int 	RSA_padding_check_SSLv23(unsigned char *to,int tlen,
                        const unsigned char *f,int fl,int rsa_len);
        int 	RSA_padding_add_X931(unsigned char *to,int tlen,
                        const unsigned char *f,int fl);
        int 	RSA_padding_check_X931(unsigned char *to,int tlen,
                        const unsigned char *f,int fl,int rsa_len);
        int 	RSA_padding_add_none(unsigned char *to, int tlen,
                        const unsigned char *from, int flen);
        int 	RSA_padding_check_none(unsigned char *to, int tlen,
                        const unsigned char *from, int flen, int num);
        int		RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
                        const unsigned char *from, int flen,
                        const unsigned char *param, int plen);
        int		RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
                        const unsigned char *from, int flen, int num,
                        const unsigned char *param, int plen);
        int		RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
                        const unsigned char *EM, int sLen);
        int		RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
                        const unsigned char *mHash, int sLen);
        int		RSA_size(const RSA *rsa);


        static int rsa_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value);

        RSA* RSA_generate_key(int bit_len)
                {

                BIGNUM *bn = BN_new();
                RSA *rsa = RSA_new();
                if(!bn || !rsa) goto err;

                if(!BN_set_word(bn, RSA_F4) || !rsa_generate_key_ex(rsa, bit_len, bn))
                        goto err;

                BN_free(bn);

                return rsa;
        err:
                if (bn) BN_free(bn);
                if (rsa) RSA_free(rsa);

                return NULL;
                }

        //bitsÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â²ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â· nÃƒÆ’Ã� â€™Ãƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â© ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¹ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¾ÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚ÂºÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â£
        //eÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â²ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â· 2ÃƒÆ’Ã� â€™Ãƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â©16ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â½ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â°ÃƒÆ’Ã� â€™Ãƒâ€¦Ã‚Â¸+1
        //dÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â²ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â· nÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â±ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â¡ ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â°ÃƒÆ’Ã� â€™Ãƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¼ÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¶ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â­ÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â´ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚ÂÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â� ÃƒÆ’Ã� â€™Ãƒâ€� Ã¢â‚¬â„¢ÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¿ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚ÂºÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â£
        //
        //
        static int rsa_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value)
        {
                BIGNUM *r0=NULL,*r1=NULL,*r2=NULL,*r3=NULL,*tmp;
                BIGNUM local_r0,local_d,local_p;
                BIGNUM *pr0,*d,*p;
                int bitsp,bitsq,ok= -1;
                BN_CTX *ctx=NULL;

                ctx=BN_CTX_new();
                if (ctx == NULL) goto err;
                BN_CTX_start(ctx);
                r0 = BN_CTX_get(ctx);
                r1 = BN_CTX_get(ctx);
                r2 = BN_CTX_get(ctx);
                r3 = BN_CTX_get(ctx);
                if (r3 == NULL) goto err;

                bitsp=(bits+1)/2;
                bitsq=bits-bitsp;

                /* We need the RSA components non-NULL */
                if(!rsa->n && ((rsa->n=BN_new()) == NULL)) goto err;
                if(!rsa->d && ((rsa->d=BN_new()) == NULL)) goto err;
                if(!rsa->e && ((rsa->e=BN_new()) == NULL)) goto err;
                if(!rsa->p && ((rsa->p=BN_new()) == NULL)) goto err;
                if(!rsa->q && ((rsa->q=BN_new()) == NULL)) goto err;
                if(!rsa->dmp1 && ((rsa->dmp1=BN_new()) == NULL)) goto err;
                if(!rsa->dmq1 && ((rsa->dmq1=BN_new()) == NULL)) goto err;
                if(!rsa->iqmp && ((rsa->iqmp=BN_new()) == NULL)) goto err;

                BN_copy(rsa->e, e_value);

                /* generate p and q */
                for (;;)
                        {
                        if(!BN_generate_prime_ex(rsa->p, bitsp, 0, NULL, NULL))
                                goto err;
                        if (!BN_sub(r2,rsa->p,BN_value_one())) goto err;
                        if (!BN_gcd(r1,r2,rsa->e,ctx)) goto err;
                        if (BN_is_one(r1)) break;
                        }
                for (;;)
                        {
                        /* When generating ridiculously small keys, we can get stuck
                         * continually regenerating the same prime values. Check for
                         * this and bail if it happens 3 times. */
                        unsigned int degenerate = 0;
                        do
                                {
                                if(!BN_generate_prime_ex(rsa->q, bitsq, 0, NULL, NULL))
                                        goto err;
                                } while((BN_cmp(rsa->p, rsa->q) == 0) && (++degenerate < 3));
                        if(degenerate == 3)
                                {
                                ok = 0; /* we set our own err */
                                goto err;
                                }
                        if (!BN_sub(r2,rsa->q,BN_value_one())) goto err;
                        if (!BN_gcd(r1,r2,rsa->e,ctx)) goto err;
                        if (BN_is_one(r1))
                                break;
                        }
                if (BN_cmp(rsa->p,rsa->q) < 0)
                        {
                        tmp=rsa->p;
                        rsa->p=rsa->q;
                        rsa->q=tmp;
                        }

                /* calculate n */
                if (!BN_mul(rsa->n,rsa->p,rsa->q,ctx)) goto err;

                /* calculate d */
                if (!BN_sub(r1,rsa->p,BN_value_one())) goto err;	/* p-1 */
                if (!BN_sub(r2,rsa->q,BN_value_one())) goto err;	/* q-1 */
                if (!BN_mul(r0,r1,r2,ctx)) goto err;	/* (p-1)(q-1) */
                if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
                        {
                          pr0 = &local_r0;
                          BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);
                        }
                else
                  pr0 = r0;
                if (!BN_mod_inverse(rsa->d,rsa->e,pr0,ctx)) goto err;	/* d */

                /* set up d for correct BN_FLG_CONSTTIME flag */
                if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
                        {
                        d = &local_d;
                        BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
                        }
                else
                        d = rsa->d;

                /* calculate d mod (p-1) */
                if (!BN_mod(rsa->dmp1,d,r1,ctx)) goto err;

                /* calculate d mod (q-1) */
                if (!BN_mod(rsa->dmq1,d,r2,ctx)) goto err;

                /* calculate inverse of q mod p */
                if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
                        {
                        p = &local_p;
                        BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);
                        }
                else
                        p = rsa->p;
                if (!BN_mod_inverse(rsa->iqmp,rsa->q,p,ctx)) goto err;

                ok=1;
        err:
                if (ok == -1)
                        {
                        ok=0;
                        }
                if (ctx != NULL)
                        {
                        BN_CTX_end(ctx);
                        BN_CTX_free(ctx);
                        }

                return ok;
                }

        #define CRYPTO_LOCK_RSA			9

        RSA *RSA_new()
                {
                RSA *ret;


                ret=(RSA *)malloc(sizeof(RSA));
                if (ret == NULL)
                        {
                        return NULL;
                        }
                ret->pad=0;
                ret->n=NULL;
                ret->e=NULL;
                ret->d=NULL;
                ret->p=NULL;
                ret->q=NULL;
                ret->dmp1=NULL;
                ret->dmq1=NULL;
                ret->iqmp=NULL;

                ret->flags= 0;
                return(ret);
                }

        void RSA_free(RSA *rsa)
                {

                if (rsa == NULL) return;
                if (rsa->n != NULL) BN_free(rsa->n);
                if (rsa->e != NULL) BN_free(rsa->e);
                if (rsa->d != NULL) BN_free(rsa->d);
                if (rsa->p != NULL) BN_free(rsa->p);
                if (rsa->q != NULL) BN_free(rsa->q);
                if (rsa->dmp1 != NULL) BN_free(rsa->dmp1);
                if (rsa->dmq1 != NULL) BN_free(rsa->dmq1);
                if (rsa->iqmp != NULL) BN_free(rsa->iqmp);
                free(rsa);
                }

        int RSA_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
                {
                BIGNUM *r1,*R,*m1,*vrfy;
                BIGNUM local_dmp1, local_dmq1;
                BIGNUM *dmp1, *dmq1;
                int ret=0;

                BN_CTX_start(ctx);
                r1 = BN_CTX_get(ctx);
                m1 = BN_CTX_get(ctx);
                vrfy = BN_CTX_get(ctx);
                R = BN_CTX_get(ctx);


                if (!BN_mod(r1,I,rsa->q,ctx)) goto err;

                if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
                        {
                        dmq1 = &local_dmq1;
                        BN_with_flags(dmq1, rsa->dmq1, BN_FLG_CONSTTIME);
                        }
                else
                        dmq1 = rsa->dmq1;


                if (!BN_mod_exp_mont(m1,r1,dmq1,rsa->q,ctx)) goto err;

                if (!BN_mod(r1,I,rsa->p,ctx)) goto err;


                if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
                {
                        dmp1 = &local_dmp1;
                        BN_with_flags(dmp1, rsa->dmp1, BN_FLG_CONSTTIME);
                        }
                else
                        dmp1 = rsa->dmp1;

                if (!BN_mod_exp_mont(r0,r1,dmp1,rsa->p,ctx)) goto err;

                if (!BN_sub(r0,r0,m1)) goto err;
                /* This will help stop the size of r0 increasing, which does
                 * affect the multiply if it optimised for a power of 2 size */
                if (BN_is_negative(r0))
                        if (!BN_add(r0,r0,rsa->p)) goto err;

                if (!BN_mul(r1,r0,rsa->iqmp,ctx)) goto err;
                if (!BN_mod(r0,r1,rsa->p,ctx)) goto err;
                /* If p < q it is occasionally possible for the correction of
                 * adding 'p' if r0 is negative above to leave the result still
                 * negative. This can break the private key operations: the following
                 * second correction should *always* correct this rare occurrence.
                 * This will *never* happen with PKILIB generated keys because
                 * they ensure p > q [steve]
                 */

                if (BN_is_negative(r0))
                        if (!BN_add(r0,r0,rsa->p)) goto err;


                if (!BN_mul(r1,r0,rsa->q,ctx)) goto err;
                if (!BN_add(r0,r1,m1)) goto err;
                if (!BN_mul(R,rsa->p,rsa->q,ctx)) goto err;


                if (rsa->e && rsa->n)
                        {
                        if (!BN_mod_exp_mont(vrfy,r0,rsa->e,rsa->n,ctx)) goto err;
                        /* If 'I' was greater than (or equal to) rsa->n, the operation
                         * will be equivalent to using 'I mod n'. However, the result of
                         * the verify will *always* be less than 'n' so we don't check
                         * for absolute equality, just congruency. */
                        if (!BN_sub(vrfy, vrfy, I)) goto err;
                        if (!BN_mod(vrfy, vrfy, rsa->n, ctx)) goto err;
                        if (BN_is_negative(vrfy))
                                if (!BN_add(vrfy, vrfy, rsa->n)) goto err;
                        if (!BN_is_zero(vrfy)) {
                                /* 'I' and 'vrfy' aren't congruent mod n. Don't leak
                                 * miscalculated CRT output, just do a raw (slower)
                                 * mod_exp and return that instead. */

                                BIGNUM local_d;
                                BIGNUM *d = NULL;
                                if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
                                        d = &local_d;
                                        BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
                                } else d = rsa->d;
                                if (!BN_mod_exp_mont(r0,I,d,rsa->n,ctx)) goto err;
                        }
                }
                ret=1;
        err:
                BN_CTX_end(ctx);
                return(ret);
                }

        int RSA_size(const RSA *rsa)
                {
                return(BN_num_bytes(rsa->n));
                }

        int RSA_init(RSA *rsa)
                {
                rsa->flags|=RSA_FLAG_CACHE_PUBLIC|RSA_FLAG_CACHE_PRIVATE;
                return(1);
                }


        /* data encrypt */
        /*
          ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚ÂÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â·ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚ÂmÃƒÆ’Ã� â€™Ãƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â© ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¿ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚ÂÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â±ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¨ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â²ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â· nÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¸ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â³ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³ÃƒÆ’Ã� â€™Ãƒâ€¦Ã‚Â¾ ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¿ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚ÂÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â·ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â² ÃƒÆ’Ã� â€™Ãƒâ€¦Ã‚Â� ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¯ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â´ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â´ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³ÃƒÆ’Ã� â€™Ãƒâ€¦Ã‚Â¾!!!!!flenÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¼ ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¸ÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â� ÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚ÂºÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â£
          fromÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¼ ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚ÂÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â·ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â,toÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â²ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â· ÃƒÆ’Ã� â€™Ãƒâ€¦Ã‚Â� ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â·ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â·ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â,rsaÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â²ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â· ÃƒÆ’Ã� â€™Ãƒâ€¦Ã‚Â� ÃƒÆ’Ã� â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â»ÃƒÆ’Ã� â€™Ãƒâ€¦Ã¢â‚¬â„¢,paddingÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚ÂªÃƒÆ’Ã� â€™ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¼
        */
        int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to,
                     RSA *rsa, int padding)
                {
                BIGNUM *f,*ret;
                int i,j,k,num=0,r= -1;
                unsigned char *buf=NULL;
                BN_CTX *ctx=NULL;
                if (BN_num_bits(rsa->n) > RSA_MAX_MODULUS_BITS)
                        return -1;
                if (BN_ucmp(rsa->n, rsa->e) <= 0)
                        return -1;

                /* for large moduli, enforce exponent limit */
                if (BN_num_bits(rsa->n) > RSA_SMALL_MODULUS_BITS)
                        {
                        if (BN_num_bits(rsa->e) > RSA_MAX_PUBEXP_BITS)
                                return -1;
                        }

                if ((ctx=BN_CTX_new()) == NULL) goto err;
                BN_CTX_start(ctx);
                f = BN_CTX_get(ctx);
                ret = BN_CTX_get(ctx);
                num=BN_num_bytes(rsa->n);
                buf = (unsigned char *)malloc(num);
                if (!f || !ret || !buf)
                        goto err;

                switch (padding) {
                        case RSA_PKCS1_OAEP_PADDING:
                                i=RSA_padding_add_PKCS1_OAEP(buf,num,from,flen,NULL,0);
                                break;
                        case RSA_PKCS1_PADDING:
                                i=RSA_padding_add_PKCS1_type_2(buf,num,from,flen);
                                break;
                        case RSA_SSLV23_PADDING:
                                i=RSA_padding_add_SSLv23(buf,num,from,flen);
                                break;
                        case RSA_NO_PADDING:
                                i=RSA_padding_add_none(buf,num,from,flen);
                                break;
                        default:
                                goto err;
                }

                if (i <= 0) goto err;

                if (BN_bin2bn(buf,num,f) == NULL) goto err;

                if (BN_ucmp(f, rsa->n) >= 0)
                        goto err;

                //MONT_HELPER(rsa, ctx, n, rsa->flags & RSA_FLAG_CACHE_PUBLIC, goto err);

                if (!BN_mod_exp_mont(ret,f,rsa->e,rsa->n,ctx)) goto err;
                j=BN_num_bytes(ret);
                i=BN_bn2bin(ret,&(to[num-j]));
                for (k=0; k<(num-i); k++) to[k]=0;

                r=num;
        err:
                if (ctx != NULL)
                        {
                        BN_CTX_end(ctx);
                        BN_CTX_free(ctx);
                        }
                if (buf != NULL)
                        {
                        cleanse(buf,num);
                        free(buf);
                        }
                return(r);
        }

        /* data decrypt */
        int RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
                     RSA *rsa, int padding)
                {
                BIGNUM *f, *ret, *br;
                int j,num=0,r= -1;
                unsigned char *p;
                unsigned char *buf=NULL;
                BN_CTX *ctx=NULL;
                if((ctx = BN_CTX_new()) == NULL) goto err;
                BN_CTX_start(ctx);
                f   = BN_CTX_get(ctx);
                br  = BN_CTX_get(ctx);
                ret = BN_CTX_get(ctx);
                num = BN_num_bytes(rsa->n);
                buf = (unsigned char *)malloc(num);
                if(!f || !ret || !buf)
                        goto err;

                if (flen > num)
                        goto err;

                /* make data into a big number */
                if (BN_bin2bn(from,(int)flen,f) == NULL) goto err;
                if (BN_ucmp(f, rsa->n) >= 0)
                        goto err;

                /* do the decrypt */
                if ( (rsa->flags & RSA_FLAG_EXT_PKEY) ||
                        ((rsa->p != NULL) &&
                        (rsa->q != NULL) &&
                        (rsa->dmp1 != NULL) &&
                        (rsa->dmq1 != NULL) &&
                        (rsa->iqmp != NULL)) )
                        {
                        if (!RSA_mod_exp(ret, f, rsa, ctx)) goto err;
                        }
                else
                        {
                        BIGNUM local_d;
                        BIGNUM *d = NULL;

                        if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
                                {
                                d = &local_d;
                                BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
                                }
                        else
                                d = rsa->d;

                        //MONT_HELPER(rsa, ctx, n, rsa->flags & RSA_FLAG_CACHE_PUBLIC, goto err);
                        if (!BN_mod_exp_mont(ret,f,d,rsa->n,ctx))
                          goto err;
                        }

                p=buf;
                j=BN_bn2bin(ret,p); /* j is only used with no-padding mode */

                switch (padding)
                        {
                case RSA_PKCS1_OAEP_PADDING:
                        r=RSA_padding_check_PKCS1_OAEP(to,num,buf,j,num,NULL,0);
                        break;
                case RSA_PKCS1_PADDING:
                        r=RSA_padding_check_PKCS1_type_2(to,num,buf,j,num);
                        break;
                case RSA_SSLV23_PADDING:
                        r=RSA_padding_check_SSLv23(to,num,buf,j,num);
                        break;
                case RSA_NO_PADDING:
                        r=RSA_padding_check_none(to,num,buf,j,num);
                        break;

                default:
                        goto err;
                        }
        err:
                if (ctx != NULL)
                        {
                        BN_CTX_end(ctx);
                        BN_CTX_free(ctx);
                        }
                if (buf != NULL)
                        {
                        cleanse(buf,num);
                        free(buf);
                        }
                return(r);
                }

        /* sign */
        int RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
                     RSA *rsa, int padding) {
                BIGNUM *f, *ret, *br, *res;
                int i,j,k,num=0,r= -1;
                unsigned char *buf=NULL;
                BN_CTX *ctx=NULL;
                if ((ctx=BN_CTX_new()) == NULL) goto err;
                BN_CTX_start(ctx);
                f   = BN_CTX_get(ctx);
                br  = BN_CTX_get(ctx);
                ret = BN_CTX_get(ctx);
                num = BN_num_bytes(rsa->n);
                buf = (unsigned char *)malloc(num);
                if(!f || !ret || !buf)
                        goto err;
                switch (padding) {
                        case RSA_PKCS1_OAEP_PADDING:
                                i=RSA_padding_add_PKCS1_OAEP(buf,num,from,flen,NULL,0);
                                break;
                        case RSA_PKCS1_PADDING:
                                i=RSA_padding_add_PKCS1_type_1(buf,num,from,flen);
                                break;
                        case RSA_X931_PADDING:
                                i=RSA_padding_add_X931(buf,num,from,flen);
                                break;
                        case RSA_NO_PADDING:
                                i=RSA_padding_add_none(buf,num,from,flen);
                                break;

                        default:
                                goto err;
                }

                if (i <= 0) goto err;

                if (BN_bin2bn(buf,num,f) == NULL) goto err;

                if (BN_ucmp(f, rsa->n) >= 0)
                        goto err;

                if ( (rsa->flags & RSA_FLAG_EXT_PKEY) ||
                        ((rsa->p != NULL) &&
                        (rsa->q != NULL) &&
                        (rsa->dmp1 != NULL) &&
                        (rsa->dmq1 != NULL) &&
                        (rsa->iqmp != NULL)) ) {
                        if (!RSA_mod_exp(ret, f, rsa, ctx)) goto err;
                } else {
                        BIGNUM local_d;
                        BIGNUM *d = NULL;

                        if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
                                BN_init(&local_d);
                                d = &local_d;
                                BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
                        } else d = rsa->d;
                        //MONT_HELPER(rsa, ctx, n, rsa->flags & RSA_FLAG_CACHE_PUBLIC, goto err);

                        if (!BN_mod_exp_mont(ret,f,d,rsa->n,ctx)) goto err;
                }

                res = ret;

                j=BN_num_bytes(res);
                i=BN_bn2bin(res,&(to[num-j]));
                for (k=0; k<(num-i); k++)
                        to[k]=0;

                r=num;
        err:
                if (ctx != NULL)
                        {
                        BN_CTX_end(ctx);
                        BN_CTX_free(ctx);
                        }
                if (buf != NULL)
                        {
                        cleanse(buf,num);
                        free(buf);
                        }
                return(r);
                }

        /* verify */
        int RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
                     RSA *rsa, int padding)
                {
                BIGNUM *f,*ret;
                int i,num=0,r= -1;
                unsigned char *p;
                unsigned char *buf=NULL;
                BN_CTX *ctx=NULL;

                if (BN_num_bits(rsa->n) > RSA_MAX_MODULUS_BITS)
                        return -1;

                if (BN_ucmp(rsa->n, rsa->e) <= 0)
                        return -1;

                /* for large moduli, enforce exponent limit */
                if (BN_num_bits(rsa->n) > RSA_SMALL_MODULUS_BITS)
                        {
                        if (BN_num_bits(rsa->e) > RSA_MAX_PUBEXP_BITS)
                                return -1;
                        }

                if((ctx = BN_CTX_new()) == NULL) goto err;
                BN_CTX_start(ctx);
                f = BN_CTX_get(ctx);
                ret = BN_CTX_get(ctx);
                num=BN_num_bytes(rsa->n);
                buf = (unsigned char *)malloc(num);
                if(!f || !ret || !buf)
                        goto err;

                if (flen > num)
                        goto err;

                if (BN_bin2bn(from,flen,f) == NULL) goto err;

                if (BN_ucmp(f, rsa->n) >= 0)
                        goto err;

                //MONT_HELPER(rsa, ctx, n, rsa->flags & RSA_FLAG_CACHE_PUBLIC, goto err);

                if (!BN_mod_exp_mont(ret,f,rsa->e,rsa->n,ctx)) goto err;
                p=buf;
                i=BN_bn2bin(ret,p);

                switch (padding)
                        {
                case RSA_PKCS1_OAEP_PADDING:
                        r=RSA_padding_check_PKCS1_OAEP(to,num,buf,i,num,NULL,0);
                        break;
                case RSA_PKCS1_PADDING:
                        r=RSA_padding_check_PKCS1_type_1(to,num,buf,i,num);
                        break;
                case RSA_X931_PADDING:
                        r=RSA_padding_check_X931(to,num,buf,i,num);
                        break;
                case RSA_NO_PADDING:
                        r=RSA_padding_check_none(to,num,buf,i,num);
                        break;

                default:
                        goto err;
                        }

        err:
                if (ctx != NULL)
                        {
                        BN_CTX_end(ctx);
                        BN_CTX_free(ctx);
                        }
                if (buf != NULL)
                        {
                        cleanse(buf,num);
                        free(buf);
                        }
                return(r);
                }

        int RSA_sign(const unsigned char *mHash, unsigned char *sigret, RSA *rsa) {
                int				i,ret=1,num=0;
                unsigned char	*em;
                int				emLen = RSA_size(rsa);
                em = (unsigned char *)malloc(emLen+1);
                if (em == NULL) {
                        return(0);
                }
                num=BN_num_bytes(rsa->n);
                i = RSA_padding_add_PKCS1_PSS(rsa, em, mHash, -1);

                if (i <= 0) return(0);
                i=RSA_private_encrypt(emLen,em,sigret,rsa,RSA_NO_PADDING);

                if (i <= 0) ret=0;

                if (em != NULL)
                {
                        cleanse(em,(unsigned int)emLen+1);
                        free(em);
                }
                return(ret);
        }

        int RSA_verify(const unsigned char *m, unsigned char *sigbuf, RSA *rsa) {
            int i,ret=1;
                unsigned char *em;

                if (128 != (unsigned int)RSA_size(rsa)) {
                        return(0);
                }
                em=(unsigned char *)malloc(128);
                if (em == NULL) {
                        goto err;
                }
                //  from sign(sigbuf) recover digest(em)
                i=RSA_public_decrypt(128,sigbuf,em,rsa,RSA_NO_PADDING);
                ret = RSA_verify_PKCS1_PSS(rsa, m, em, -1);
                if (i <= 0) goto err;
        err:
                if (em != NULL) {
                        cleanse(em, 128);
                        free(em);
                }
                return(ret);
        }


        static const unsigned char zeroes[] = {0,0,0,0,0,0,0,0};

        int RSA_padding_add_none(unsigned char *to, int tlen,
                const unsigned char *from, int flen)
        {
                if (flen > tlen)
                        return(0);

                if (flen < tlen)
                        return(0);

                memcpy(to,from,(unsigned int)flen);
                return(1);
        }

        int RSA_padding_check_none(unsigned char *to, int tlen,
                const unsigned char *from, int flen, int num)
        {

                if (flen > tlen)
                        return(-1);

                memset(to,0,tlen-flen);
                memcpy(to+tlen-flen,from,flen);
                return(tlen);
        }

        int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
                     const unsigned char *from, int flen)
        {
                int j;
                unsigned char *p;

                if (flen > (tlen-RSA_PKCS1_PADDING_SIZE))
                        return(0);

                p=(unsigned char *)to;

                *(p++)=0;
                *(p++)=1; /* Private Key BT (Block Type) */

                /* pad out with 0xff data */
                j=tlen-3-flen;
                memset(p,0xff,j);
                p+=j;
                *(p++)='\0';
                memcpy(p,from,(unsigned int)flen);
                return(1);
        }

        int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
                     const unsigned char *from, int flen, int num)
        {
                int i,j;
                const unsigned char *p;

                p=from;
                if ((num != (flen+1)) || (*(p++) != 01))
                        return(-1);

                /* scan over padding data */
                j=flen-1; /* one for type. */
                for (i=0; i<j; i++)
                {
                        if (*p != 0xff) /* should decrypt to 0xff */
                        {
                                if (*p == 0)
                                        { p++; break; }
                                else
                                        return(-1);
                        }
                        p++;
                }

                if (i == j)
                        return(-1);

                if (i < 8)
                        return(-1);
                i++; /* Skip over the '\0' */
                j-=i;
                if (j > tlen)
                        return(-1);
                memcpy(to,p,(unsigned int)j);

                return(j);
        }

        int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
                     const unsigned char *from, int flen)
        {
                int i,j;
                unsigned char *p;

                if (flen > (tlen-11))
                        return(0);

                p=(unsigned char *)to;

                *(p++)=0;
                *(p++)=2; /* Public Key BT (Block Type) */

                /* pad out with non-zero random data */
                j=tlen-3-flen;

                if (RAND_bytes(p,j) <= 0)
                        return(0);
                for (i=0; i<j; i++)
                {
                        if (*p == '\0')
                                do	{
                                        if (RAND_bytes(p,1) <= 0)
                                                return(0);
                                        } while (*p == '\0');
                        p++;
                }

                *(p++)='\0';

                memcpy(p,from,(unsigned int)flen);
                return(1);
        }

        int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
                     const unsigned char *from, int flen, int num)
        {
                int i,j;
                const unsigned char *p;

                p=from;
                if ((num != (flen+1)) || (*(p++) != 02))
                        return(-1);

        #ifdef PKCS1_CHECK
                return(num-11);
        #endif

                /* scan over padding data */
                j=flen-1; /* one for type. */
                for (i=0; i<j; i++)
                        if (*(p++) == 0) break;

                if (i == j)
                        return(-1);

                if (i < 8)
                        return(-1);
                i++; /* Skip over the '\0' */
                j-=i;
                if (j > tlen)
                        return(-1);
                memcpy(to,p,(unsigned int)j);

                return(j);
        }

        int RSA_padding_add_SSLv23(unsigned char *to, int tlen,
                const unsigned char *from, int flen)
        {
                int i,j;
                unsigned char *p;

                if (flen > (tlen-11))
                        return(0);

                p=(unsigned char *)to;

                *(p++)=0;
                *(p++)=2; /* Public Key BT (Block Type) */

                /* pad out with non-zero random data */
                j=tlen-3-8-flen;

                if (RAND_bytes(p,j) <= 0)
                        return(0);
                for (i=0; i<j; i++)
                {
                        if (*p == '\0')
                                do	{
                                        if (RAND_bytes(p,1) <= 0)
                                                return(0);
                                        } while (*p == '\0');
                        p++;
                }

                memset(p,3,8);
                p+=8;
                *(p++)='\0';

                memcpy(p,from,(unsigned int)flen);
                return(1);
        }

        int RSA_padding_check_SSLv23(unsigned char *to, int tlen,
                const unsigned char *from, int flen, int num)
        {
                int i,j,k;
                const unsigned char *p;

                p=from;
                if (flen < 10)
                        return(-1);
                if ((num != (flen+1)) || (*(p++) != 02))
                        return(-1);

                /* scan over padding data */
                j=flen-1; /* one for type */
                for (i=0; i<j; i++)
                        if (*(p++) == 0) break;

                if ((i == j) || (i < 8))
                        return(-1);
                for (k= -8; k<0; k++)
                {
                        if (p[k] !=  0x03) break;
                }
                if (k == -1)
                        return(-1);

                i++; /* Skip over the '\0' */
                j-=i;
                if (j > tlen)
                        return(-1);
                memcpy(to,p,(unsigned int)j);

                return(j);
        }

        int RSA_padding_add_X931(unsigned char *to, int tlen,
                     const unsigned char *from, int flen)
        {
                int j;
                unsigned char *p;

                /* Absolute minimum amount of padding is 1 header nibble, 1 padding
                 * nibble and 2 trailer bytes: but 1 hash if is already in 'from'.
                 */

                j = tlen - flen - 2;

                if (j < 0)
                        return -1;

                p=(unsigned char *)to;

                /* If no padding start and end nibbles are in one byte */
                if (j == 0)
                        *p++ = 0x6A;
                else
                {
                        *p++ = 0x6B;
                        if (j > 1)
                        {
                                memset(p, 0xBB, j - 1);
                                p += j - 1;
                        }
                        *p++ = 0xBA;
                }
                memcpy(p,from,(unsigned int)flen);
                p += flen;
                *p = 0xCC;
                return(1);
        }

        int RSA_padding_check_X931(unsigned char *to, int tlen,
                     const unsigned char *from, int flen, int num)
        {
                int i = 0,j;
                const unsigned char *p;

                p=from;
                if ((num != flen) || ((*p != 0x6A) && (*p != 0x6B)))
                        return -1;

                if (*p++ == 0x6B)
                {
                        j=flen-3;
                        for (i = 0; i < j; i++)
                        {
                                unsigned char c = *p++;
                                if (c == 0xBA)
                                        break;
                                if (c != 0xBB)
                                        return -1;
                        }

                        j -= i;

                        if (i == 0)
                                return -1;

                }
                else j = flen - 2;

                if (p[j] != 0xCC)
                        return -1;

                memcpy(to,p,(unsigned int)j);

                return(j);
        }

        int MGF1(unsigned char *mask, long len, const unsigned char *seed, long seedlen)
                {
                long i, outlen = 0;
                unsigned char cnt[4];
                sha1_ctx cx[1];
                unsigned char md[SHA1_DIGEST_SIZE];
                int mdlen;

                //EVP_MD_CTX_init(&c);
                mdlen = SHA1_DIGEST_SIZE;
                for (i = 0; outlen < len; i++)
                        {
                        cnt[0] = (unsigned char)((i >> 24) & 255);
                        cnt[1] = (unsigned char)((i >> 16) & 255);
                        cnt[2] = (unsigned char)((i >> 8)) & 255;
                        cnt[3] = (unsigned char)(i & 255);
                        //EVP_DigestInit_ex(&c,dgst, NULL);
                        sha1_begin(cx);
                        //EVP_DigestUpdate(&c, seed, seedlen);
                        sha1_hash(seed, seedlen, cx);
                        //EVP_DigestUpdate(&c, cnt, 4);
                        sha1_hash(cnt, 4, cx);
                        if (outlen + mdlen <= len)
                                {
                                //EVP_DigestFinal_ex(&c, mask + outlen, NULL);
                                sha1_end(mask + outlen, cx);
                                outlen += mdlen;
                                }
                        else
                                {
                                //EVP_DigestFinal_ex(&c, md, NULL);
                                sha1_end(md, cx);
                                memcpy(mask + outlen, md, len - outlen);
                                outlen = len;
                                }
                        }
                //EVP_MD_CTX_cleanup(&c);
                return 0;
                }

        int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
                const unsigned char *from, int flen,
                const unsigned char *param, int plen)
                {
                int i, emlen = tlen - 1;
                unsigned char *db, *seed;
                unsigned char *dbmask, seedmask[SHA1_DIGEST_SIZE];

                if (flen > emlen - 2 * SHA1_DIGEST_SIZE - 1)
                        {
                        return 0;
                        }

                if (emlen < 2 * SHA1_DIGEST_SIZE + 1)
                        {
                        return 0;
                        }

                dbmask = (unsigned char *)malloc(emlen - SHA1_DIGEST_SIZE);
                if (dbmask == NULL)
                        {
                        return 0;
                        }

                to[0] = 0;
                seed = to + 1;
                db = to + SHA1_DIGEST_SIZE + 1;

                //EVP_Digest((void *)param, plen, db, NULL, EVP_sha1(), NULL);
                sha1(db, param, plen);

                memset(db + SHA1_DIGEST_SIZE, 0,
                        emlen - flen - 2 * SHA1_DIGEST_SIZE - 1);
                db[emlen - flen - SHA1_DIGEST_SIZE - 1] = 0x01;
                memcpy(db + emlen - flen - SHA1_DIGEST_SIZE, from, (unsigned int) flen);
                if (RAND_bytes(seed, SHA1_DIGEST_SIZE) <= 0)
                        return 0;

                MGF1(dbmask, emlen - SHA1_DIGEST_SIZE, seed, SHA1_DIGEST_SIZE);
                for (i = 0; i < emlen - SHA1_DIGEST_SIZE; i++)
                        db[i] ^= dbmask[i];

                MGF1(seedmask, SHA1_DIGEST_SIZE, db, emlen - SHA1_DIGEST_SIZE);
                for (i = 0; i < SHA1_DIGEST_SIZE; i++)
                        seed[i] ^= seedmask[i];

                free(dbmask);
                return 1;
                }

        int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
                const unsigned char *from, int flen, int num,
                const unsigned char *param, int plen)
                {
                int i, dblen, mlen = -1;
                const unsigned char *maskeddb;
                int lzero;
                unsigned char *db = NULL, seed[SHA1_DIGEST_SIZE], phash[SHA1_DIGEST_SIZE];
                int bad = 0;

                if (--num < 2 * SHA1_DIGEST_SIZE + 1)
                        /* 'num' is the length of the modulus, i.e. does not depend on the
                         * particular ciphertext. */
                        goto decoding_err;

                lzero = num - flen;
                if (lzero < 0)
                        {
                        /* lzero == -1 */

                        /* signalling this error immediately after detection might allow
                         * for side-channel attacks (e.g. timing if 'plen' is huge
                         * -- cf. James H. Manger, "A Chosen Ciphertext Attack on RSA Optimal
                         * Asymmetric Encryption Padding (OAEP) [...]", CRYPTO 2001),
                         * so we use a 'bad' flag */
                        bad = 1;
                        lzero = 0;
                        }
                maskeddb = from - lzero + SHA1_DIGEST_SIZE;

                dblen = num - SHA1_DIGEST_SIZE;
                db = (unsigned char *)malloc(dblen);
                if (db == NULL)
                        {
                        return -1;
                        }

                MGF1(seed, SHA1_DIGEST_SIZE, maskeddb, dblen);
                for (i = lzero; i < SHA1_DIGEST_SIZE; i++)
                        seed[i] ^= from[i - lzero];

                MGF1(db, dblen, seed, SHA1_DIGEST_SIZE);
                for (i = 0; i < dblen; i++)
                        db[i] ^= maskeddb[i];

                //EVP_Digest((void *)param, plen, phash, NULL, EVP_sha1(), NULL);
                sha1(phash, param, plen);

                if (memcmp(db, phash, SHA1_DIGEST_SIZE) != 0 || bad)
                        goto decoding_err;
                else
                        {
                        for (i = SHA1_DIGEST_SIZE; i < dblen; i++)
                                if (db[i] != 0x00)
                                        break;
                        if (db[i] != 0x01 || i++ >= dblen)
                                goto decoding_err;
                        else
                                {
                                /* everything looks OK */

                                mlen = dblen - i;
                                if (tlen < mlen)
                                        {
                                        mlen = -1;
                                        }
                                else
                                        memcpy(to, db + i, mlen);
                                }
                        }
                free(db);
                return mlen;

        decoding_err:
                /* to avoid chosen ciphertext attacks, the error message should not reveal
                 * which kind of decoding error happened */
                if (db != NULL) free(db);
                return -1;
                }

        int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
                                const unsigned char *EM, int sLen)
                {
                int i;
                int ret = 0;
                int hLen, maskedDBLen, MSBits, emLen;
                const unsigned char *H;
                unsigned char *DB = NULL;
                sha1_ctx cx[1];
                unsigned char H_[SHA1_DIGEST_SIZE];

                hLen = SHA1_DIGEST_SIZE;
                /*
                 * Negative sLen has special meanings:
                 *	-1	sLen == hLen
                 *	-2	salt length is autorecovered from signature
                 *	-N	reserved
                 */
                if      (sLen == -1)	sLen = hLen;
                else if (sLen == -2)	sLen = -2;
                else if (sLen < -2)
                        {
                        goto err;
                        }

                MSBits = (BN_num_bits(rsa->n) - 1) & 0x7;
                emLen = RSA_size(rsa);
                if (EM[0] & (0xFF << MSBits))
                        {
                        goto err;
                        }
                if (MSBits == 0)
                        {
                        EM++;
                        emLen--;
                        }
                if (emLen < (hLen + sLen + 2)) /* sLen can be small negative */
                        {
                        goto err;
                        }
                if (EM[emLen - 1] != 0xbc)
                        {
                        goto err;
                        }
                maskedDBLen = emLen - hLen - 1;
                H = EM + maskedDBLen;
                DB = (unsigned char *)malloc(maskedDBLen);
                if (!DB)
                        {
                        goto err;
                        }
                MGF1(DB, maskedDBLen, H, hLen);
                for (i = 0; i < maskedDBLen; i++)
                        DB[i] ^= EM[i];
                if (MSBits)
                        DB[0] &= 0xFF >> (8 - MSBits);
                for (i = 0; DB[i] == 0 && i < (maskedDBLen-1); i++) ;
                if (DB[i++] != 0x1)
                        {
                        goto err;
                        }
                if (sLen >= 0 && (maskedDBLen - i) != sLen)
                        {
                        goto err;
                        }
                //EVP_MD_CTX_init(&ctx);
                //EVP_DigestInit_ex(&ctx, Hash, NULL);
                sha1_begin(cx);
                //EVP_DigestUpdate(&ctx, zeroes, sizeof zeroes);
                sha1_hash(zeroes, sizeof zeroes, cx);
                //EVP_DigestUpdate(&ctx, mHash, hLen);
                sha1_hash(mHash, hLen, cx);
                if (maskedDBLen - i)
                        sha1_hash(DB + i, maskedDBLen - i, cx);
                        //EVP_DigestUpdate(&ctx, DB + i, maskedDBLen - i);
                //EVP_DigestFinal(&ctx, H_, NULL);
                sha1_end(H_, cx);
                //EVP_MD_CTX_cleanup(&ctx);
                if (memcmp(H_, H, hLen))
                        {
                        ret = 0;
                        }
                else
                        ret = 1;

                err:
                if (DB)
                        free(DB);

                return ret;

                }

        int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
                                const unsigned char *mHash, int sLen) {
                int i;
                int ret = 0;
                int hLen, maskedDBLen, MSBits, emLen;
                unsigned char *H, *salt = NULL, *p;
                sha1_ctx cx[1];;

                hLen = SHA1_DIGEST_SIZE;
                /*
                 * Negative sLen has special meanings:
                 *	-1	sLen == hLen
                 *	-2	salt length is maximized
                 *	-N	reserved
                 */
                if      (sLen == -1)	sLen = hLen;
                else if (sLen == -2)	sLen = -2;
                else if (sLen < -2) {
                        goto err;
                }

                MSBits = (BN_num_bits(rsa->n) - 1) & 0x7;
                emLen = RSA_size(rsa);
                if (MSBits == 0) {
                        *EM++ = 0;
                        emLen--;
                }
                if (sLen == -2) {
                        sLen = emLen - hLen - 2;
                } else if (emLen < (hLen + sLen + 2)) {
                        goto err;
                }
                if (sLen > 0) {
                salt = (unsigned char *)malloc(sLen);
                        if (!salt) {
                                goto err;
                        }
                        if (!RAND_bytes(salt, sLen))
                                goto err;
                        }
                maskedDBLen = emLen - hLen - 1;
                H = EM + maskedDBLen;
                //EVP_MD_CTX_init(&ctx);
                //EVP_DigestInit_ex(&ctx, Hash, NULL);
                sha1_begin(cx);
                //EVP_DigestUpdate(&ctx, zeroes, sizeof zeroes);
                sha1_hash(zeroes, sizeof zeroes, cx);
                //EVP_DigestUpdate(&ctx, mHash, hLen);
                sha1_hash(mHash, hLen, cx);
                if (sLen) sha1_hash(salt, sLen, cx);
                //EVP_DigestUpdate(&ctx, salt, sLen);
                //EVP_DigestFinal(&ctx, H, NULL);
                sha1_end(H, cx);
                //EVP_MD_CTX_cleanup(&ctx);

                /* Generate dbMask in place then perform XOR on it */
                MGF1(EM, maskedDBLen, H, hLen);

                p = EM;

                /* Initial PS XORs with all zeroes which is a NOP so just update
                 * pointer. Note from a test above this value is guaranteed to
                 * be non-negative.
                 */
                p += emLen - sLen - hLen - 2;
                *p++ ^= 0x1;
                if (sLen > 0)
                        {
                        for (i = 0; i < sLen; i++)
                                *p++ ^= salt[i];
                        }
                if (MSBits)
                        EM[0] &= 0xFF >> (8 - MSBits);

                /* H is already in place so just set final 0xbc */

                EM[emLen - 1] = 0xbc;

                ret = 1;

                err:
                if (salt)
                        free(salt);

                return ret;

        }

        #endif // HEADER_RSA_H
};
using namespace KEE_ENC;

