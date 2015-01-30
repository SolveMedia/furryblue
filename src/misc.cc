/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Mar-24 12:32 (EDT)
  Function: misc utils

*/

#define CURRENT_SUBSYSTEM	'y'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "hrtime.h"
#include "network.h"
#include "crypto.h"
#include "lock.h"

#include <sys/types.h>
#include <poll.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/loadavg.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <string>
#include <deque>
using std::string;
using std::deque;

static Mutex lock;
static int seqno = 42;


struct Gunk {
    int t;
    int i;
    short p;
    short n;
};

void
unique(string *dst){
    char buf[32];
    struct Gunk g;

    g.t = lr_now();
    g.i = myipv4;
    g.p = getpid();

    lock.lock();
    g.n = seqno ++;
    lock.unlock();

    base64_encode((uchar*)&g, sizeof(g), buf, sizeof(buf));

    dst->append(buf);

}

void
hexdump(const char *txt, const uchar *d, int l){

    if( txt ) fprintf(stderr, "%s:\n", txt);
    for(int i=0; i<l; i++){
        fprintf(stderr, " %02X", d[i]);
        if( (i%16)==15 && i!=l-1 ) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n\n");
}

int
current_load(void){
    double load[3];

    getloadavg( load, 3 );

    return (int)(load[1] * 1000);
}

void
split(const string &src, char delim, deque<string> *dst){
    int pos=0, len=0, i;

    // search for delim, push onto queue
    for(i=0; i<src.size(); i++){
        if( src[i] != delim ){
            len ++;
            continue;
        }
        if( len )
            dst->push_back( string(src,pos,len) );

        pos = i+1;
        len = 0;
    }

    // grab text after last delim
    if( pos < src.size() ){
        dst->push_back( string(src,pos) );
    }
}

uint
shard_hash(const string& key){
    uint h;
    md5_bin( (uchar*)key.data(), key.size(), (char*)&h, sizeof(h) );
    return ntohl(h);
}

