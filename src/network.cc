/*
  Copyright (c) 2008 by Jeff Weisberg
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2008-Dec-28 14:40 (EST)
  Function: network requests
*/

#define CURRENT_SUBSYSTEM	'N'

#include "defs.h"
#include "diag.h"
#include "thread.h"
#include "config.h"
#include "lock.h"
#include "misc.h"
#include "hrtime.h"
#include "network.h"
#include "netutil.h"
#include "runmode.h"
#include "peers.h"
#include "crypto.h"
#include "stats.h"

#include "std_reply.pb.h"
#include "heartbeat.pb.h"

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/loadavg.h>
#include <sys/sendfile.h>


#define READ_TIMEOUT	30
#define WRITE_TIMEOUT	30
#define LISTEN		128
#define ALPHA           0.75


static int handle_unknown(NTD*);
static int handle_status(NTD*);
static int handle_hbreq(NTD*);
static int report_status(NTD*);
static int report_peers(NTD*);
static int report_json(NTD*);
static int report_load(NTD*);

extern void install_handler(int, void(*)(int));
extern int  y2_status(NTD*);
extern int  api_get(NTD*);
extern int  api_put(NTD*);
extern int  api_check(NTD*);

extern int  report_ring_txt(NTD *);
extern int  report_ring_json(NTD *);
extern int  job_nrunning(void), task_nrunning(void);
extern void job_shutdown(void), task_shutdown(void);

void hexdump(const char *, const uchar *, int);

Stats stats;

static struct {
    int (*fnc)(NTD*);
    // ... ?
} request_handler[] = {
    { handle_status  },		// status
    { 0 },
    { handle_hbreq   },		// heartbeat request
    { 0 },
    { 0 },
    { 0 },	// 5
    { 0 }, { 0 }, { 0 }, { 0 }, { 0 },	// 10
    { 0 }, { 0 }, { 0 }, { 0 }, { 0 },	// 15
    { 0 }, { 0 }, { 0 }, { 0 }, { 0 },	// 20
    { 0 }, { 0 }, { 0 }, { 0 }, { 0 },	// 25
    { 0 }, { 0 }, { 0 }, { 0 }, { 0 },	// 30

    { 0 },
    { y2_status },		// 32 - kibitz
    { api_get },
    { api_put },
    { api_check },

    // ...
};

static struct {
    const char *url;
    int (*fnc)(NTD *);
} http_handler[] = {
    { "/status",     report_status     },
    { "/peers",      report_peers      },
    { "/json",       report_json       },
    { "/loadave",    report_load       },
    { "/ring",       report_ring_txt   },
    { "/ring.json",  report_ring_json  },
    // stats
    // ...
};


class ThreadData {
public:
    int	      idx;
    int	      fd;
    int       busy;
    float     util;
    time_t    timeout;
    time_t    time_update;
    pthread_t pid;
    jmp_buf   jmp_abort;
    bool      doingio;
    int64_t   nreq, ntcp, nudp, nread, nwrite;

    ThreadData(){
        busy = 0; util = 0; timeout = 0; pid = 0; time_update = 0; doingio = 0;
        nreq = ntcp = nudp = nread = nwrite = 0;
    }

};

int nthread;
static ThreadData *thread_data;


// where am I? for heartbeats
int      myport = 0;
uint32_t myipv4 = 0;
uint32_t myipv4pin = 0;
NetAddr  mynetaddr;

int tcp4s_fd=0, tcp4c_fd=0, udp4s_fd=0, udp4c_fd=0, con_fd=0;

// statistics
float  net_busyness    = 0;
float  net_utiliz      = 0;
float  net_load_metric = 0;
float  net_req_per_sec = 0;
int    net_timeouts    = 0;
time_t last_timeout    = 0;


/****************************************************************/

static void
sigalarm(int sig){
    int i;
    pthread_t self = pthread_self();
    time_t nowt    = lr_now();
    int thno = -1;

    DEBUG("timeout");

    for(i=0; i<nthread; i++){
        if( thread_data[i].pid == self ) thno = i;
    }
    if( thno == -1 ) return;

    // if a lot of things are timing out, something might be hung
    // put the system into a fast windown+restart

    if( !thread_data[thno].doingio ){

        if( last_timeout + 3600 < nowt ){
            // been a while, reset
            net_timeouts = 0;
        }

        net_timeouts ++;
        last_timeout = nowt;

        if( net_timeouts > 20 ){
            runmode.errored();
        }
    }

    DEBUG("aborting request");
    longjmp( thread_data[thno].jmp_abort, 1 );
}

static void
sigother(int sig){
    int i;
    pthread_t self = pthread_self();

#if 1
    runmode.errored();
    BUG("caught sig %d", sig);
    sleep(1);

#else
    DEBUG("caught sig %d", sig);

    for(i=0; i<nthread; i++){
        if( thread_data[i].pid == self ){
            BUG("signal %d in thread %d", sig, thread_data[i].pid);
            thread_data[i].timeout = 0;
            longjmp( thread_data[i].jmp_abort, 1 );
        }
    }
#endif
}


/****************************************************************/
// quick+dirty. not fully RFC compliant
// just enough to export some data to argus
static void
network_http(NTD *ntd){

    // parse url
    char *url = ntd->gpbuf_in + 4;
    int urllen = 0;

    for(int i=0; url[i] != ' ' && url[i] != '\n' && i<ntd->in_size-4; i++){
        urllen ++;
    }
    url[urllen] = 0;

    DEBUG("url %s", url);

    int (*fnc)(NTD*) = 0;
    for(int i=0; i<ELEMENTSIN(http_handler); i++){
        if( !strcmp(url, http_handler[i].url) ){
            fnc = http_handler[i].fnc;
            break;
        }
    }

    if( !fnc ){
#       define RESPONSE "HTTP/1.0 404 Not Found\r\nServer: AC/FurryBlueDB\r\n\r\n"
        write_to(ntd->fd, RESPONSE, sizeof(RESPONSE)-1, WRITE_TIMEOUT);
#       undef  RESPONSE
        return;
    }

    // process req
    int rl = fnc(ntd);

    // respond
#   define RESPONSE "HTTP/1.0 200 OK\r\nServer: AC/FurryBlueDB\r\nContent-Type: text/plain\r\n\r\n"
    write_to(ntd->fd, RESPONSE, sizeof(RESPONSE)-1, WRITE_TIMEOUT);
#   undef  RESPONSE

    write_to(ntd->fd, ntd->gpbuf_out, rl, WRITE_TIMEOUT);
}


static int
network_process(int idx, NTD *ntd){
    protocol_header *ph = (protocol_header*) ntd->gpbuf_in;

    if( !strncmp( ntd->gpbuf_in, "GET ", 4) ){
        network_http(ntd);
        return 0;
    }

    if( ph->version != PHVERSION ) return 0;

    int (*fnc)(NTD*);
    int mt = ph->type;
    DEBUG("processing request");
    if( mt >= ELEMENTSIN(request_handler) ){
        fnc = handle_unknown;
    }else{
        fnc = request_handler[mt].fnc;
    }
    if( !fnc ) fnc = handle_unknown;

    if( fnc == api_get ) thread_data[idx].nread  ++;
    if( fnc == api_put ) thread_data[idx].nwrite ++;

    return fnc(ntd);
}

// well, almost any, ours or http
int
read_any_proto(NTD *ntd, int reqp, int to){
    protocol_header *ph = (protocol_header*) ntd->gpbuf_in;
    int len  = 0;

    // read header
    // int i = read_to(ntd->fd, ntd->gpbuf_in, ntd->in_size, READ_TIMEOUT);
    int i = read(ntd->fd, ntd->gpbuf_in, ntd->in_size);
    if( i > 0 ) len = i;

    if( reqp && i > 4 && !strncmp( ntd->gpbuf_in, "GET ", 4) ){
        DEBUG("http request");

        // read http request
        while(1){
            // do we have entire req?
            if( strstr(ntd->gpbuf_in, "\r\n\r\n") ) break;
            if( strstr(ntd->gpbuf_in, "\n\n") )     break;

            int rl = ntd->in_size - len;
            if( !rl ) return 0;
            // i = read_to(ntd->fd, ntd->gpbuf_in + len, rl, READ_TIMEOUT);
            i = read(ntd->fd, ntd->gpbuf_in + len, rl);
            if( i > 0 ) len += i;

            if( !i ){
                return 0; // eof
            }
            if( i < 1 ){
		if( errno == EINTR ) continue;
		DEBUG("read error");
		return 0;
	    }
        }

        network_http(ntd);
        return 0;
    }

    if( len < sizeof(protocol_header) ){
	DEBUG("read header failed");
	return 0;
    }

    // convert buffer from network byte order
    cvt_header_from_network( ph );

    // validate
    if( ph->version != PHVERSION ){
	VERBOSE("invalid request recvd. unknown version(%d)", ph->version);
	return 0;
    }

    if( ph->data_length > ntd->in_size - sizeof(protocol_header) ){
        ntd->in_resize( ph->data_length + sizeof(protocol_header) );
        ph = (protocol_header*) ntd->gpbuf_in;
    }

    // read gpb
    if( ph->data_length ){

        DEBUG("reading protobuf");

        int tlen  = ph->data_length + sizeof(protocol_header);
        char *buf = ntd->gpbuf_in;

        while( len < tlen ){
            int rlen = tlen - len;
            // i = read_to(ntd->fd, buf + len, rlen, READ_TIMEOUT);
            i = read(ntd->fd, buf + len, rlen);
            if( i < 1 ){
                if( errno == EINTR ) continue;
                DEBUG("read error");
                return 0;
            }
            len += i;
        }

        ntd->have_data = 1;

        if( ph->flags & PHFLAG_DATA_ENCR ){
            // decrypt
            int l = acp_decrypt( ntd->gpbuf_in + sizeof(protocol_header), ph->data_length,
                                 ntd->gpbuf_in + sizeof(protocol_header), ntd->in_size - sizeof(protocol_header));

            ph->data_length = l;
            if( !l ){
                DEBUG("decrypt failed");
                return 0;
            }
        }
    }

    return 1;

}

static void *
network_tcp_read_req(int idx, int fd){
    ThreadData *td = thread_data + idx;
    NTD ntd;

    ntd.fd = fd;
    ntd.is_tcp = 1;

    socklen_t sal = sizeof(ntd.peer);
    getpeername(fd, (sockaddr*)&ntd.peer, &sal);

    td->doingio = 1;
    td->timeout = lr_now() + READ_TIMEOUT;

    int r = read_any_proto(&ntd, 1, READ_TIMEOUT);
    td->doingio = 0;
    td->timeout = 0;

    if( r ){
        int rl = network_process(idx, &ntd);
        if( rl ){
            td->doingio = 1;
            td->timeout = lr_now() + WRITE_TIMEOUT;
            // int i = write_to(fd, ntd.gpbuf_out, rl, WRITE_TIMEOUT);
            int i = write( fd, ntd.gpbuf_out, rl );
            td->doingio = 0;
            td->timeout = 0;

            if( i != rl )
                DEBUG("write response failed %d", errno);
        }
    }
    close(fd);
    return 0;
}


static void *
network_tcp4(void *x){
    int idx = (int)(intptr_t)x;
    ThreadData *td = thread_data + idx;
    int fd = td->fd;
    struct sockaddr_in sa;
    socklen_t l = sizeof(sa);
    hrtime_t t0=0, t1=0, t2=hr_now();

    while(1){
	if( runmode.mode() == RUN_MODE_EXITING ) break;

        t0 = t2;
        td->busy = 0;
	int nfd = accept(fd, (sockaddr *)&sa, &l);
	t1 = hr_now();
        td->busy = 1;

	if(nfd == -1){
	    DEBUG("accept failed");
	    continue;
	}

	if( !config->check_acl( (sockaddr*)&sa ) ){
	    VERBOSE("network connection refused from %s", inet_ntoa(sa.sin_addr) );
	    close(nfd);
	    continue;
	}

	DEBUG("new connection from %s", inet_ntoa(sa.sin_addr) );

        td->nreq ++;
        td->ntcp ++;

        init_tcp(nfd);
        // set_nbio(fd);

        if( ! setjmp( td->jmp_abort ) ){
            network_tcp_read_req( idx, nfd );
        }else{
            // got a timeout | signal
            VERBOSE("aborted processing request");
            td->doingio = 0;
            td->timeout = 0;
            // ...
        }

	t2 = hr_now();
        time_t lt2 = lr_now();

        float b = (t2 == t0) ? 0 : ((float)(t2 - t1)) / ((float)(t2 - t0));

        if( td->time_update > lt2 - 2 ){
            td->util = (td->util + b) / 2;
        }else{
            td->util = b;
        }

        td->timeout = 0;
        td->time_update = lt2;

    }

    close(fd);
    td->fd = 0;
}

static void *
network_udp4(void *x){
    int idx = (int)(intptr_t)x;
    ThreadData *td = thread_data + idx;
    int fd = td->fd;
    NTD ntd;
    socklen_t l = sizeof(struct sockaddr_in);
    protocol_header *ph = (protocol_header*) ntd.gpbuf_in;

    ntd.fd = fd;

    while(1){
	if( runmode.mode() == RUN_MODE_EXITING ) break;

        ntd.have_data = 0;
        int i = recvfrom(fd, ntd.gpbuf_in, ntd.in_size, 0, (sockaddr*)&ntd.peer, &l);

        if( i < 0 ) continue;

	if( !config->check_acl( (sockaddr*)&ntd.peer ) ){
	    VERBOSE("network connection refused from %s", inet_ntoa(ntd.peer.sin_addr) );
	    continue;
	}

	DEBUG("new udp from %s", inet_ntoa(ntd.peer.sin_addr) );

        // hexdump("recvd ", (uchar*)ntd.gpbuf_in, i);

        cvt_header_from_network( (protocol_header*) ntd.gpbuf_in );

        if( ph->data_length < ntd.in_size - sizeof(protocol_header) ){
            ntd.have_data = 1;
        }

        td->nreq ++;
        td->nudp ++;
        int rl = network_process(idx, &ntd);
        if( rl ) sendto(fd, ntd.gpbuf_out, rl, 0, (sockaddr*)&ntd.peer, sizeof(ntd.peer));
    }

    close(fd);
    td->fd = 0;
}

static int
open_tcp(int port){
    struct sockaddr_in sa;

    int s = socket(PF_INET, SOCK_STREAM, 0);
    if( s == -1 ){
	FATAL("cannot create tcp4 socket");
    }

    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    sa.sin_addr.s_addr = INADDR_ANY;

    int i = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    i = bind(s, (sockaddr*)&sa, sizeof(sa));
    if( i == -1 ){
	FATAL("cannot bind to tcp4 port");
    }
    listen(s, LISTEN);

    return s;
}

static int
open_udp(int port){
    struct sockaddr_in sa;

    int s = socket(PF_INET, SOCK_DGRAM, 0);
    if( s == -1 ){
	FATAL("cannot create udp4 socket");
    }
    int i = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    i = 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &i, sizeof(i));

    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    sa.sin_addr.s_addr = INADDR_ANY;

    i = bind(s, (sockaddr*)&sa, sizeof(sa));
    if( i == -1 ){
	FATAL("cannot bind to udp4 port");
    }

    return s;
}

void
network_init(void){

    mynetaddr.ipv4 = myipv4;
    mynetaddr.port = myport;
    mynetaddr.name = myserver_id;

    // open sockets
    //  *s* => server-to-server; *c* => client-to-server
    if( config->tcp_threads ){
        tcp4s_fd = open_tcp(myport);
        tcp4c_fd = open_tcp(myport + 1);
    }
    if( config->udp_threads ){
        udp4s_fd = open_udp(myport);
        udp4c_fd = open_udp(myport + 1);
    }
    // RSN - ipv6

    // increase descriptor limit
    struct rlimit fdrl;
    getrlimit(RLIMIT_NOFILE, &fdrl);
    fdrl.rlim_cur = 65535;
    setrlimit(RLIMIT_NOFILE, &fdrl);
    DEBUG("limit fd %d, %d", fdrl.rlim_cur, fdrl.rlim_max);

    // install alarm handler
    // NB: other handlers are installed in deamon.cc/daemon_siginit
    install_handler( SIGALRM, sigalarm );
    install_handler( SIGABRT, sigother );
    install_handler( SIGFPE,  sigother );
    install_handler( SIGBUS,  sigother );

    VERBOSE("starting network on tcp/%d as id %s (%s)", myport, myserver_id.c_str(), config->environment.c_str());

    int i;
    int tidx=0;

    nthread = 2 * config->tcp_threads + 2 * config->udp_threads;
    thread_data = new ThreadData[ nthread ];

    for(i=0; i<config->tcp_threads; i++){
        thread_data[tidx].fd  = tcp4s_fd;
        thread_data[tidx].idx = tidx;
        thread_data[tidx].pid = start_thread(network_tcp4, (void*)(intptr_t)tidx, 255);
        tidx ++;
    }
    for(i=0; i<config->tcp_threads; i++){
        thread_data[tidx].fd  = tcp4c_fd;
        thread_data[tidx].idx = tidx;
        thread_data[tidx].pid = start_thread(network_tcp4, (void*)(intptr_t)tidx, 255);
        tidx ++;
    }
    for(i=0; i<config->udp_threads; i++){
        thread_data[tidx].fd  = udp4s_fd;
        thread_data[tidx].idx = tidx;
        thread_data[tidx].pid = start_thread(network_udp4, (void*)(intptr_t)tidx, 255);
        tidx ++;
    }
    for(i=0; i<config->udp_threads; i++){
        thread_data[tidx].fd  = udp4c_fd;
        thread_data[tidx].idx = tidx;
        thread_data[tidx].pid = start_thread(network_udp4, (void*)(intptr_t)tidx, 255);
        tidx ++;
    }
}

void
network_manage(void){
    time_t prevt = lr_now(), nowt;
    int64_t preq = 0;

    extern bool partition_safe_to_stop;
    extern bool merkle_safe_to_stop;

    while(1){
        nowt = lr_now();

        switch(runmode.mode()){
        case RUN_MODE_WINDDOWN:
            // are we done?
            if( partition_safe_to_stop && merkle_safe_to_stop ){
                runmode.wounddown();
                VERBOSE("windown complete - exiting");
                break;
            }

            // try to abort anything running
            if( nowt - prevt > 10 ){

                prevt = nowt;
            }
            break;

        case RUN_MODE_EXITING:

            if( tcp4s_fd || tcp4c_fd || udp4s_fd || udp4c_fd ){
		// tell network_accept threads to finish
		DEBUG("shutting network down");
                if( tcp4s_fd ) close(tcp4s_fd);
                if( tcp4c_fd ) close(tcp4c_fd);
                if( udp4s_fd ) close(udp4s_fd);
                if( udp4c_fd ) close(udp4c_fd);

                tcp4s_fd = tcp4c_fd = udp4s_fd = udp4c_fd = 0;
            }

            int nactive = 0;
            for(int i=0; i<nthread; i++){
                if( thread_data[i].fd ) nactive ++;
            }

            if( !nactive ){
		DEBUG("network finished");
		return;
	    }
            break;
        }

        // determine stats
        if( nowt != prevt ){
            int64_t nreq=0, nread=0, nwrite=0;
            int nbusy=0, nutil=0;
            float tutil=0;

            for(int i=0; i<nthread; i++){
                nbusy  += thread_data[i].busy;
                nreq   += thread_data[i].nreq;
                nread  += thread_data[i].nread;
                nwrite += thread_data[i].nwrite;
                if( thread_data[i].time_update > nowt - 5 ){
                    tutil += thread_data[i].util;
                    nutil ++;
                }
            }

            stats.reqs   = nreq;
            stats.reads  = nread;
            stats.writes = nwrite;

	    float b = (float)nbusy / nthread;
            float u = nutil ? tutil / nutil : 0;
	    net_busyness    = ALPHA * net_busyness + (1.0 - ALPHA) * b;
	    net_utiliz      = ALPHA * net_utiliz   + (1.0 - ALPHA) * u;
	    net_load_metric = sqrt( ( (net_busyness + 1.0) * (net_utiliz + 1.0) - 1.0 ) / 3.0 );

            float rps = (nreq - preq) / (float)(nowt - prevt);
            net_req_per_sec = ALPHA * net_req_per_sec + (1.0 - ALPHA) * rps;

            DEBUG("busy: %f, util: %f; rps: nreq %lld, preq %lld, rps %.4f => %.4f", net_busyness, net_utiliz, nreq, preq, rps, net_req_per_sec);
            prevt = nowt;
            preq  = nreq;

            // RSN - more stats...
        }

        // kill any hung threads
        for(int i=0; i<nthread; i++){
            if( thread_data[i].timeout && thread_data[i].timeout < nowt ){
                BUG("notifying unresponsive thread %d", thread_data[i].pid);
                thread_data[i].timeout = 0;
                pthread_kill(thread_data[i].pid, SIGALRM);
            }
        }


	sleep(1);
    }
}

//################################################################

static int
report_status(NTD *ntd){
    return snprintf(ntd->gpbuf_out, ntd->out_size, "OK\n");
}

static int
report_load(NTD *ntd){
    return snprintf(ntd->gpbuf_out, ntd->out_size, "loadave: %f\n", current_load() / 1000.0 );
}


static int
report_peers(NTD *ntd){
    return peerdb->report(ntd);
}

static int
report_json(NTD *ntd){
    string buf;

    buf.append( "{}\n" );

    ntd->out_resize( buf.size() );
    memcpy(ntd->gpbuf_out, buf.c_str(), buf.size());
    return buf.size();
}


//################################################################

// invalid request
static int
handle_unknown(NTD* ntd){
    protocol_header *phi = (protocol_header*) ntd->gpbuf_in;
    protocol_header *pho = (protocol_header*) ntd->gpbuf_out;

    if( !(phi->flags & PHFLAG_WANTREPLY) ) return 0;

    ntd_copy_header_for_reply(ntd);
    pho->flags   = PHFLAG_ISREPLY | PHFLAG_ISERROR;

    cvt_header_to_network( pho );
    return sizeof(protocol_header);
}

// status request (eg. from monitoring system)
static int
handle_status(NTD* ntd){
    protocol_header *phi = (protocol_header*) ntd->gpbuf_in;
    protocol_header *pho = (protocol_header*) ntd->gpbuf_out;
    ACPStdReply g;

    if( !(phi->flags & PHFLAG_WANTREPLY) ) return 0;

    if( runmode.mode() != RUN_LOLA_RUN ){
        g.set_status_code( 500 );
        g.set_status_message( "shutdown underway" );
    }else{
        g.set_status_code( 200 );
        g.set_status_message( "OK" );
    }

    g.SerializeToArray( ntd->out_data(), ntd->data_size() );
    ntd_copy_header_for_reply(ntd);
    pho->data_length = g.GetCachedSize();

    cvt_header_to_network( pho );
    return sizeof(protocol_header) + g.GetCachedSize();
}

// hb request (eg. from yenta)
static int
handle_hbreq(NTD* ntd){
    protocol_header *phi = (protocol_header*) ntd->gpbuf_in;
    protocol_header *pho = (protocol_header*) ntd->gpbuf_out;
    ACPHeartBeat g;
    struct statvfs vfs;

    if( !(phi->flags & PHFLAG_WANTREPLY) ) return 0;

    if( runmode.mode() != RUN_LOLA_RUN ){
	g.set_status_code( 500 );
	g.set_status_message( "shutdown underway" );
    }else{
	g.set_status_code( 200 );
	g.set_status_message( "Awesome" );
        g.set_sort_metric( current_load() );
    }

    g.set_subsystem( MYNAME );
    g.set_hostname( myhostname );
    g.set_environment( config->environment.c_str() );
    g.set_timestamp( lr_now() );
    g.set_port( myport );
    g.set_server_id( myserver_id.c_str() );
    g.set_process_id( getpid() );

    // determine disk space available
    if( ! statvfs( config->basedir.c_str(), &vfs ) ){
        g.set_capacity_metric( vfs.f_bavail / 2048 );	// MB avail
    }

    DEBUG("sending hb: %s", g.ShortDebugString().c_str());
    g.SerializeToArray( ntd->out_data(), ntd->data_size() );
    ntd_copy_header_for_reply(ntd);
    pho->data_length = g.GetCachedSize();

    cvt_header_to_network( pho );
    return sizeof(protocol_header) + g.GetCachedSize();
}

int
reply_ok(NTD *ntd){
    protocol_header *phi = (protocol_header*) ntd->gpbuf_in;
    protocol_header *pho = (protocol_header*) ntd->gpbuf_out;
    ACPStdReply g;

    if( !(phi->flags & PHFLAG_WANTREPLY) ) return 0;

    ntd_copy_header_for_reply(ntd);

    g.set_status_code( 200 );
    g.set_status_message( "OK" );
    g.SerializeToArray( ntd->out_data(), ntd->data_size() );
    pho->data_length = g.GetCachedSize();

    cvt_header_to_network( pho );
    return sizeof(protocol_header) + g.GetCachedSize();
}

int
reply_error(NTD *ntd, int code, const char *msg){
    protocol_header *phi = (protocol_header*) ntd->gpbuf_in;
    protocol_header *pho = (protocol_header*) ntd->gpbuf_out;
    ACPStdReply g;

    VERBOSE("sending reply error %d %s", code, msg);

    if( !(phi->flags & PHFLAG_WANTREPLY) ) return 0;

    ntd_copy_header_for_reply(ntd);
    phi->flags   = PHFLAG_ISREPLY | PHFLAG_ISERROR;

    g.set_status_code( code );
    g.set_status_message( msg );
    g.SerializeToArray( ntd->out_data(), ntd->data_size() );
    pho->data_length = g.GetCachedSize();

    cvt_header_to_network( pho );
    return sizeof(protocol_header) + g.GetCachedSize();
}
