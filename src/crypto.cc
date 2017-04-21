/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Mar-13 20:38 (EDT)
  Function: crypto
*/

#define CURRENT_SUBSYSTEM	'y'

#include "defs.h"
#include "diag.h"
#include "misc.h"
#include "config.h"
#include "hrtime.h"
#include "crypto.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "y2db_crypto.pb.h"


#define ALGORITHM "x-acy-aes-2"

#define HEX(x)		(((x)>9) ? (x) + 'A' - 10 : (x) + '0')

void
hex_encode(const unsigned char *in, int inlen, char *out, int outlen){
    int i;

    if( inlen > outlen/2 ) inlen = outlen/2;

    for(i=0; i<inlen; i++){
        int c = in[i];
        *out++ = HEX(c>>4);
        *out++ = HEX(c&0xF);
    }

    // null terminate if there's room
    if( outlen > inlen * 2 ) *out = 0;
}


Hash::Hash(){
    _size = 0;
    _done = 0;
}


HashSHA1::HashSHA1(void){
    EVP_DigestInit( &_ctx, EVP_sha1() );
}

HashSHA256::HashSHA256(void){
    EVP_DigestInit( &_ctx, EVP_sha256() );
}

HashMD5::HashMD5(void){
    EVP_DigestInit( &_ctx, EVP_md5() );
}


void
Hash::update(const uchar *d, int len){
    EVP_DigestUpdate( &_ctx, d, len );
}

void
Hash::file(const char *file){

    FILE *f = fopen(file, "r");
    if( !f ){
        VERBOSE("cannot open %s", file);
        return;
    }
    while(1){
        uchar buf[1024];
        int r = fread(buf, 1, sizeof(buf), f);
        if( r<1 ) break;
        update( buf, r );
    }
    fclose(f);
}

void
Hash::_digest(void){
    if( !_done ){
        EVP_DigestFinal( &_ctx, _hash, 0 );
        _done = 1;
    }
}

void
Hash::iterate(void){
    // hash of the hash

    // NB: Final does a cleanup, which blows away md
    const EVP_MD *md = EVP_MD_CTX_md( &_ctx );

    _digest();
    EVP_DigestInit( &_ctx, md );
    EVP_DigestUpdate( &_ctx, _hash, hlen() );
}

void
Hash::digest(char *d, int len){

    _digest();
    if( len > hlen() ) len = hlen();
    memcpy(d, _hash, len);
}

void
Hash::digest64(char *d, int len){

    _digest();
    base64_encode(_hash, hlen(), d, len);
}

void
Hash::digesthex(char *d, int len){

    _digest();
    hex_encode(_hash, hlen(), d, len);
}

void
Hash::bin(const uchar *in, int inlen, char *out, int outlen){
    update(in, inlen);
    digest(out, outlen);
}
void
Hash::hex(const uchar *in, int inlen, char *out, int outlen){
    update(in, inlen);
    digesthex(out, outlen);
}
void
Hash::b64(const uchar *in, int inlen, char *out, int outlen){
    update(in, inlen);
    digest64(out, outlen);
}

//################################################################

void
md5_bin(const uchar *in, int inlen, char *out, int outlen){
    HashMD5 m;
    m.bin(in, inlen, out, outlen);
}

void
hmac_sha256(const char *key, int keylen, const char *in, int inlen, string *out){

    HMAC_CTX hmx;
    HMAC_Init( &hmx, key, keylen, EVP_sha256() );
    HMAC_Update( &hmx, (uchar*) in, inlen );

    out->resize( 32 );
    int len;

    HMAC_Final( &hmx, (uchar*) out->data(), (uint*)&len );
    HMAC_CTX_cleanup( &hmx );
}

//################################################################

void
random_bytes(char *out, int outlen){
    static int f = open("/dev/urandom", O_RDONLY);
    if( f == - 1 ) FATAL("cannot open random");
    read(f, out, outlen);

    uint x = random();
    for(int i=0; i<outlen; i++){
        // in case the device has been tampered with
        out[i] ^= x;
        x = (x<<1) | (x>>31);
    }
}

void
random_text(char *out, int outlen){
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    random_bytes(out, outlen);

    for(int i=0; i<outlen; i++){
        int c = out[i] & 0x3F;
        out[i] = charset[c];
    }
}

//################################################################

static void
_key(int64_t seq, const char *nonce, int nlen, char *out, int outlen){
    HashSHA256 h;
    char buf[32];

    snprintf(buf, sizeof(buf), "%016llX", seq);

    h.update( "key1", 4 );
    h.update( config->secret.data(), config->secret.size() );
    h.update( buf, strlen(buf) );
    h.update( nonce, nlen );
    h.update( "1yek", 4 );
    h.iterate();
    h.digest( out, outlen );
}

static void
_iv(const char *key, int keylen, int64_t seq, char *out, int outlen){
    HashSHA256 h;
    char buf[32];

    snprintf(buf, sizeof(buf), "%016llX", seq);

    h.update( "iv", 2 );
    h.update( key, keylen );
    h.update( buf, strlen(buf) );
    h.update( key, keylen );
    h.update( "vi", 2 );
    h.digest( out, outlen );
}


static bool
_acp_encrypt(const char *in, int inlen, ACPEncrypt *res){

    if( ! config ) return 0;
    if( config->secret.empty() ) return 0;

    // pick seqno, nonce, generate key + iv
    int64_t seqno = hr_usec();
    char nonce[48], key[16], iv[16];

    random_bytes(nonce, sizeof(nonce));
    _key(seqno, nonce, sizeof(nonce), key, sizeof(key));
    _iv(key, sizeof(key), seqno, iv, sizeof(iv));

    res->set_algorithm( ALGORITHM );
    res->set_seqno( seqno );
    res->set_nonce( nonce, 48 );
    res->set_length( inlen );

    // prepare output buffer - pad to blocksize
    // NB: EncryptFinal appends pkcs padding
    int len = inlen;
    len += 16 - (len&15);
    string *wbuf = res->mutable_ciphertext();
    wbuf->resize( len );

    // encrypt
    EVP_CIPHER_CTX ctx;
    EVP_EncryptInit(   &ctx, EVP_aes_128_cbc(), (uchar*)key, (uchar*)iv);
    EVP_EncryptUpdate( &ctx, (uchar*)wbuf->data(), &len, (uchar*)in, inlen );
    EVP_EncryptFinal(  &ctx, (uchar*)wbuf->data() + len, &len );

    // hmac
    string *hbuf = res->mutable_hmac();
    hmac_sha256( key, sizeof(key), wbuf->data(), wbuf->size(), hbuf );

    DEBUG("encrypted %d", res->length());
    return 1;
}

static int
_acp_decrypt(ACPEncrypt *req, char *out, int outlen){

    // derive key, iv
    char key[16], iv[16];
    string *nonce = req->mutable_nonce();
    _key(req->seqno(), nonce->data(), nonce->size(), key, sizeof(key));
    _iv(key, sizeof(key), req->seqno(), iv, sizeof(iv));

    if( req->algorithm() != ALGORITHM ){
        VERBOSE("cannot decrypt: invalid algorithm");
        return 0;
    }

    // verify hmac
    string hmac;
    hmac_sha256( key, sizeof(key), req->ciphertext().data(), req->ciphertext().size(), &hmac );
    if( hmac != req->hmac() ){
        VERBOSE("cannot decrypt: hmac mismatch");
        return 0;
    }

    // decrypt
    EVP_CIPHER_CTX ctx;
    int l, len;
    EVP_DecryptInit(   &ctx, EVP_aes_128_cbc(), (uchar*)key, (uchar*)iv);
    EVP_DecryptUpdate( &ctx, (uchar*)out, &len, (uchar*)req->ciphertext().data(), req->ciphertext().size() );
    EVP_DecryptFinal(  &ctx, (uchar*)req->ciphertext().data() + len, &l );
    len += l;

    // double check
    if( len != req->length() ){
        VERBOSE("cannot decrypt: corrupt");
        return 0;
    }

    DEBUG("decrypted %d", len);
    return len;
}

//################################################################

int
acp_encrypt(const char *in, int inlen, char *out, int outlen){
    ACPEncrypt res;

    if( !_acp_encrypt(in, inlen, &res) ) return 0;
    if( outlen < res.ByteSize() ) 	 return 0;	// won't fit

    res.SerializeWithCachedSizesToArray( (uchar*) out );
    return res.ByteSize();
}

int
acp_encrypt(const char *in, int inlen, string *out){
    ACPEncrypt res;

    if( !_acp_encrypt(in, inlen, &res) ) return 0;

    res.SerializeToString( out );
    return res.ByteSize();
}

int
acp_decrypt(const char *in, int inlen, char *out, int outlen){
    ACPEncrypt req;

    req.ParsePartialFromArray( in, inlen );
    if( ! req.IsInitialized() ) return 0;

    return _acp_decrypt(&req, out, outlen);
}

int
acp_decrypt(const char *in, int inlen, string *out){
    ACPEncrypt req;

    req.ParsePartialFromArray( in, inlen );
    if( ! req.IsInitialized() ) return 0;

    out->resize( req.length() );
    return _acp_decrypt( &req, (char*)out->data(), out->size() );
}

