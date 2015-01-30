/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Mar-13 20:36 (EDT)
  Function: crypto
*/

#ifndef __fbdb_crypto_h_
#define __fbdb_crypto_h_

extern "C" {
#include <openssl/evp.h>
}

class Hash {
protected:
    EVP_MD_CTX	_ctx;
    int		_size;
    bool	_done;
    uchar	_hash[64];

    void _digest(void);

public:
    Hash(void);

    void file(const char *file);
    void update(const uchar *, int);
    void update(const char *d, int l) { update( (uchar*)d, l); }
    void iterate(void);
    void digest(char *, int);
    void digest64(char *, int);
    void digesthex(char *, int);
    int  size(void) const {return _size; }
    virtual int hlen(void) const = 0;

    void bin(const uchar *, int, char *, int);
    void hex(const uchar *, int, char *, int);
    void b64(const uchar *, int, char *, int);
};


class HashSHA1 : public Hash {
public:
    HashSHA1(void);
    virtual int  hlen(void) const {return 20;}
};

class HashSHA256 : public Hash {
public:
    HashSHA256(void);
    virtual int  hlen(void) const {return 32;}
};

class HashMD5 : public Hash {
public:
    HashMD5(void);
    virtual int  hlen(void) const {return 16;}
};

extern void md5_bin( const uchar *, int, char *, int);
extern int  acp_encrypt(const char *in, int inlen, char *out, int outlen);
extern int  acp_encrypt(const char *in, int inlen, string *out);
extern int  acp_decrypt(const char *in, int inlen, char *out, int outlen);
extern int  acp_decrypt(const char *in, int inlen, string *out);


#endif // __fbdb_crypto_h_
