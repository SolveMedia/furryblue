/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 21:46 (EST)
  Function: send lots+lots of put requests

*/


#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "network.h"
#include "netutil.h"
#include "hrtime.h"
#include "clientio.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "y2db_getset.pb.h"

extern void clientio_init(int);
extern int clientio_underway(void);
void another(void);
void sendreq(void);

#define THREADS	4
#define TIMEOUT	5
#define CONCURR 100
#define NUMPROC 1
#define NUMREQ	10000

/*
  -c 100 => 7000/sec
*/

Config *config = 0;
const char *database = "test3";
int num_sent = 0;
int numreq   = NUMREQ;
int pid;
NetAddr dstaddr;



class Distribute : public ClientIO {
public:
    ACPY2DistReply    result;

    Distribute(const NetAddr&, const ACPY2DistRequest*);
    virtual ~Distribute();
    virtual void on_error(void);
    virtual void on_success(void);

};

int
main(int argc, char **argv){
    extern char *optarg;
    extern int optind;
    int c;
    struct in_addr a;
    struct hostent *he;


    int v = inet_aton("127.0.0.1", &a);
    dstaddr.ipv4 = a.s_addr;
    dstaddr.port = 3508;
    dstaddr.name = "localhost";
    pid = getpid();
    srand48(pid);

    int concur  = CONCURR;
    int nthread = THREADS;

    // -d debug
    // -c concur
    // -n numreq
    // -t threads
    // -m database
    // -h addr
     while( (c = getopt(argc, argv, "c:dh:m:n:t:")) != -1 ){
	 switch(c){
	 case 'd':
             debug_enabled = 1;
             break;
         case 'c':
             concur = atoi( optarg );
             break;
         case 'n':
             numreq = atoi( optarg );
             break;
         case 't':
             nthread = atoi( optarg );
             break;
         case 'm':
             database = optarg;
             break;
         case 'h':
             he = gethostbyname( optarg );
             if( !he || !he->h_length ){
                 FATAL("cannot resolve %s", optarg );
             }

             dstaddr.ipv4 = ((struct in_addr *)*he->h_addr_list)->s_addr;
             dstaddr.name = optarg;
             break;
         }
     }
     argc -= optind;
     argv += optind;

    clientio_init(nthread);

    hrtime_t t0 = hr_now();

    for(int i=0; i<concur; i++)
        another();

    while( num_sent < numreq )
        usleep(1000);

    int count = 0;
    while( clientio_underway() )
        usleep(1000);

    hrtime_t dt = hr_now() - t0;

    printf( "elapsed\t%.2f\n", dt / 1000000000.0 );
    printf( "req/sec\t%.2f\n", numreq * 1000000000.0 / dt );
}

int
shard(const string& k){
    unsigned long hash = 5381;
    int c;

    int len = k.size();
    const char *buf = k.data();

    while( len-- ){
        c = *buf++;
        hash = ((hash << 5) + hash) ^ c; /* hash * 33 xor c */
    }
    return hash & 0x7FFFFFFF;

}


void
build_req(ACPY2DistRequest *req){

    int64_t now = hr_usec();

    req->set_hop( 0 );
    req->set_expire( now + 1000000 );
    req->set_sender( "localhost" );
    ACPY2MapDatum *d = req->mutable_data();

    // unique key
    char buf[32];
    snprintf(buf, sizeof(buf), "key-%x", lrand48());
    DEBUG("key %s", buf);

    d->set_map( database );
    d->set_key( buf );
    d->set_shard( lrand48() << 1 ); // shard(d->key()) );
    d->set_version( now );
    d->set_value( buf );
}

void
sendreq(void){
    ACPY2DistRequest req;
    ACPY2DistReply   res;

    build_req( &req );
    make_request( "127.0.0.1", PHMT_Y2_DIST, 5, &req, &res);
}


//################################################################
// generate request
void
another(void){

    if( num_sent >= numreq ) return;
    ATOMIC_ADD32(num_sent, 1);

    DEBUG("another");

    ACPY2DistRequest req;
    build_req( &req );
    new Distribute( dstaddr, &req );
}


//################################################################

Distribute::Distribute(const NetAddr& addr, const ACPY2DistRequest *req)
    : ClientIO(addr, PHMT_Y2_DIST, req) {

    _res    = &result;

    DEBUG("sending to %s", addr.name.c_str());

    _lock.lock();
    set_timeout(TIMEOUT);
    start();
    _lock.unlock();
}

Distribute::~Distribute(){
    DEBUG("done");
}

void
Distribute::on_error(void){
    discard();
    another();
}

void
Distribute::on_success(void){
    discard();
    another();
}
