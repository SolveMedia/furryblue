/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Dec-08 12:04 (EST)
  Function: 

*/
#define CURRENT_SUBSYSTEM	'I'

#include "defs.h"
#include "diag.h"
#include "thread.h"
#include "lock.h"
#include "misc.h"
#include "hrtime.h"
#include "network.h"
#include "netutil.h"
#include "runmode.h"
#include "clientio.h"
#include "crypto.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/loadavg.h>
#include <poll.h>

#include <vector>
using std::vector;

#define MAXPOLL	1024
#define BUFSIZE	8192
#define INSANE	1048576

#define STATE_PENDING		0
#define STATE_CONNECTING	1
#define STATE_WRITING		2
#define STATE_READING		3
#define STATE_WORKING		4
#define STATE_TRASH		5

static Mutex polllock;	// lock on the poll
static RWLock dslock;	// lock on our data structures

static vector<ClientIO*> clvec;	// [fd]
static int clstart = 0;



static void* clientio_loop(void*);


void
clientio_init(int nthr){
    // threads is passed in so we can use this from testing code
    // start several threads
    for(int i=0; i<nthr; i++){
        start_thread( clientio_loop, (void*)(long long)i, 63 );
    }
}

int
clientio_underway(void){
    int n = 0;

    dslock.r_lock();
    int size = clvec.size();

    for(int i=0; i<size; i++){
        ClientIO *c = clvec[i];
        if(!c) continue;
        n ++;
    }
    dslock.w_unlock();
    //VERBOSE("underway %d", n);
    return n;
}

// build pollfd struct from our clients
int
build_pfd(struct pollfd *pfd){
    int n = 0;

    int size = clvec.size();
    // we only do MAX per iter, keep track of where we leave off
    // so they all get attention
    if( clstart >= size ) clstart = 0;

    for(int i=0; i<size; i++){
        if( n >= MAXPOLL ) break;
        ClientIO *c = clvec[clstart];
        clstart = (clstart + 1) % size;

        if( !c ) continue;
        if( c->_lock.trylock() ) continue;	// busy, skip

        if( c->_polling ){
            c->_lock.unlock();
            continue;
        }

        switch( c->_state ){
        case STATE_CONNECTING:
        case STATE_WRITING:
            c->_polling = 1;
            pfd[n].fd = c->_fd;
            pfd[n].events = POLLOUT;
            n ++;
            break;

        case STATE_READING:
            c->_polling = 1;
            pfd[n].fd = c->_fd;
            pfd[n].events = POLLIN;
            n ++;
            break;

        default:
            break;
        }
        c->_lock.unlock();
    }

    return n;
}

void
process_pfd(struct pollfd *pfd, int npfd){
    lrtime_t now = lr_now();

    for(int i=0; i<npfd; i++){
        int fd = pfd[i].fd;
        ClientIO *c = 0;

        dslock.r_lock();
        if( fd < clvec.size() ) c = clvec[fd];
        dslock.r_unlock();

        // is the client still here?
        if( !c ) continue;
        c->_lock.lock();

        DEBUG("%x", pfd[i].revents);
        if( pfd[i].revents & (POLLHUP | POLLERR) ){
            c->do_error("pollerr");
        }
        else if( pfd[i].revents & POLLIN ){
            c->do_read();
        }
        else if( pfd[i].revents & POLLOUT ){
            if( c->_state == STATE_CONNECTING )
                c->do_connect();
            else
                c->do_write();
        }
        else if( c->_timeout < now ){
            c->do_timeout();
        }

        if( c->_state == STATE_TRASH ){
            delete c;
            continue;
        }

        c->_polling = 0;
        c->_lock.unlock();
    }
}

void*
clientio_loop(void* x){
    struct pollfd pfd[MAXPOLL];
    int npfd;

    while(1){
        // figure out what to do
        polllock.lock();
        dslock.r_lock();
        npfd = build_pfd( pfd );
        dslock.r_unlock();
        polllock.unlock();

        //DEBUG("poll");
        // if there is nothing to do, 1 thread sleeps quickly, the others sleep longer
        if( npfd || !x ){
            int p = poll(pfd, npfd, 100/* millisec*/);
            // # avail, 0=>timeout, -1=>error
            // process
            process_pfd(pfd, npfd);
        }else{
            sleep( 1 + (long long)x );
        }

    }
}

//################################################################

/*
  usage
  create a subclass with on_error, on_success

  c = new MyIO( ... )
  c->start()
  // ...
  c->discard()
*/

/*
  we speak only our own  protocol
    connect
    send request
    read response
    done
*/

ClientIO::ClientIO(const NetAddr& addr, int reqno, const google::protobuf::Message *req){

    _addr        = addr;
    _fd          = 0;
    _state       = STATE_PENDING;
    _timeout     = 0;
    _rel_timeout = 0;
    _rlen        = 0;
    _wrpos       = 0;
    _polling     = 0;

    // serialize to write buffer
    // prepend proto header

    string buf;
    req->SerializeToString( &buf );

    int is_enc = 0;
    if( ! addr.same_dc ){
        int sz = acp_encrypt( buf.data(), buf.size(), &buf );
        DEBUG("encrypt req %d", sz);
        is_enc = 1;
    }

    _wbuf.reserve( sizeof(protocol_header) + buf.size() );
    _wbuf.append( sizeof(protocol_header), 0 );
    _wbuf.append( buf );

    protocol_header *pho = (protocol_header*) _wbuf.data();
    pho->version        = PHVERSION;
    pho->flags          = is_enc ? (PHFLAG_WANTREPLY | PHFLAG_DATA_ENCR) : PHFLAG_WANTREPLY;
    pho->type           = reqno;
    pho->msgidno        = random_n(0xFFFFFFFF);
    pho->auth_length    = 0;
    pho->content_length = 0;
    pho->data_length    = buf.size();

    cvt_header_to_network( pho );
}

ClientIO::~ClientIO(){
    _close();
}

void
ClientIO::start(void){
    struct sockaddr_in sa;

    // open socket + start connecting

    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(_addr.port);
    sa.sin_addr.s_addr = _addr.ipv4;

    _fd = socket(PF_INET, SOCK_STREAM, 0);
    if( _fd == -1 ){
	FATAL("cannot create tcp4 socket: %s", strerror(errno));
    }

    DEBUG("connect %s %d => %d", inet_ntoa(sa.sin_addr), _addr.port, _fd);

    init_tcp(_fd);
    set_nbio(_fd);

    dslock.w_lock();
    if( _fd >= clvec.size() )
        clvec.resize( _fd + 1, 0 );

    if( clvec[_fd] ){
        FATAL("client fd already marked as in-use (%d)", _fd);
    }

    clvec[_fd] = this;
    dslock.w_unlock();

    int i = connect(_fd, (sockaddr*)&sa, sizeof(sa));
    if( i == -1 && errno != EINPROGRESS ){
        DEBUG("cannot connect: %s", strerror(errno));
        do_error("connect failed");
    }

    _wrpos = 0;
    _rlen  = 0;
    _rbuf.clear();
    _rbuf.reserve( BUFSIZE );
    _state = STATE_CONNECTING;
    if( _rel_timeout ) _timeout = lr_now() + _rel_timeout;

}

void
ClientIO::set_timeout(lrtime_t rto){
    _rel_timeout = rto;
    if(rto) _timeout = lr_now() + rto;
}

void
ClientIO::discard(void){
    _state = STATE_TRASH;
    DEBUG("discard");
}

void
ClientIO::retry(const NetAddr& addr){

    _addr    = addr;
    _timeout = 0;
    _state   = STATE_PENDING;
    _rlen    = 0;
    _wrpos   = 0;

    start();
}

// the rest are all called with the lock already held

void
ClientIO::do_connect(void){

    int opt, optlen = sizeof(opt);
    getsockopt(_fd, SOL_SOCKET, SO_ERROR, (void*)&opt, (socklen_t*)&optlen);

    if( opt ){
        do_error("connect failed");
        return;
    }

    DEBUG("connected");
    _state = STATE_WRITING;
    _wrpos = 0;
}

void
ClientIO::do_write(void){

    int len = _wbuf.size() - _wrpos;
    int w = write(_fd, _wbuf.data(), len);
    if( w == -1 ){
        if( errno == EINTR || errno == EAGAIN ) return;
        do_error("write failed");
        return;
    }

    _wrpos += w;

    DEBUG("wrote %d", w);
    if( _wrpos >= _wbuf.size() && _state == STATE_WRITING ){
        _state = STATE_READING;
    }
}

void
ClientIO::do_read(void){
    char buf[BUFSIZE];
    int rlen;

    if( _rlen )
        rlen = _rlen;
    else{
        rlen = BUFSIZE;
    }

    int l = rlen - _rbuf.size();
    if( l > BUFSIZE ) l = BUFSIZE;
    int r = read(_fd, buf, l);

    if( r == -1 ){
        if( errno == EINTR || errno == EAGAIN ) return;
        do_error("read failed");
        return;
    }
    if( r == 0 ){
        do_error("eof");
        return;
    }

    DEBUG("read %d", r);
    _rbuf.append(buf, r);

    if( !_rlen && (_rbuf.size() >= sizeof(protocol_header)) ){
        protocol_header *ph = (protocol_header*) _rbuf.data();
        _rlen = sizeof(protocol_header) + ntohl(ph->auth_length) + ntohl(ph->data_length) + ntohl(ph->content_length);
        if( _rlen >= INSANE || ntohl(ph->version) != PHVERSION ){
            do_error("corrupt read");
            return;
        }
    }


    if( _rlen && (_rbuf.size() >= _rlen) && (_state == STATE_READING) ){
        _state = STATE_WORKING;
        do_work();
    }
}

void
ClientIO::do_timeout(void){
    do_error("time out");
}

void
ClientIO::do_error(const char *msg){

    _close();
    DEBUG("client %s io failed: %s", _addr.name.c_str(), msg);

    on_error();
}

void
ClientIO::do_work(void){

    _close();

    DEBUG("working");
    protocol_header *ph = (protocol_header*) _rbuf.data();
    cvt_header_from_network( ph );

    if( ph->flags & PHFLAG_ISERROR ){
        on_error();
        return;
    }

    // decrypt
    if( ph->flags & PHFLAG_DATA_ENCR ){
        int l = acp_decrypt( _rbuf.data() + sizeof(protocol_header), ph->data_length,
                             (char*)_rbuf.data() + sizeof(protocol_header), _rbuf.size() - sizeof(protocol_header));

        ph->data_length = l;

        if( !l ){
            DEBUG("decrypt failed");
            on_error();
            return;
        }
    }

    // deserialize response
    int off = sizeof(protocol_header) + ph->auth_length;
    DEBUG("reply sz %d, al %d, dl %d, cl %d", _rbuf.size(), ph->auth_length, ph->data_length, ph->content_length);
    _res->ParsePartialFromArray( _rbuf.data() + off, ph->data_length );

    on_success();
}

void
ClientIO::_close(void){

    if( !_fd ) return;

    dslock.w_lock();
    clvec[ _fd ] = 0;
    dslock.w_unlock();
    close(_fd);
    _fd = 0;
}


