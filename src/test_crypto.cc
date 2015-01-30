

#include "defs.h"
#include "diag.h"
#include "misc.h"
#include "config.h"
#include "crypto.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>


typedef unsigned char uchar;

Config *config;

#define HEX(x)		(((x)>9) ? (x) + 'A' - 10 : (x) + '0')

static void
hex_encode(const unsigned char *in, int inlen, char *out, int outlen){
    int i;

    if( inlen > outlen/2 ) inlen = outlen/2;

    for(i=0; i<inlen; i++){
        int c = in[i];
        *out++ = HEX(c>>4);
        *out++ = HEX(c&0xF);
    }
    DEBUG("%d %d", inlen, outlen);
    if( outlen > inlen * 2 ) *out = 0;

}


int
main(int, char**){
    EVP_MD_CTX _ctx;
    char hash[32], buf[256];

    debug_enabled = 1;

    EVP_DigestInit(   &_ctx, EVP_md5() );
    EVP_DigestUpdate( &_ctx, "foo", 3 );
    EVP_DigestFinal(  &_ctx, (uchar*)hash, 0 );

    hex_encode((uchar*)hash, 16, buf, sizeof(buf) );
    //buf[32] = 0;
    printf("=> %s\n", buf);

    memset(buf, 0, sizeof(buf));

    HashMD5 m;
    m.hex( (uchar*)"foo", 3, buf, 256 );
    printf("=> %s\n", buf);

    
}

