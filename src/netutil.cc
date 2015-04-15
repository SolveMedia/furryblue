/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Mar-19 13:20 (EDT)
  Function: network protocol

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
#include "crypto.h"

#include "y2db_getset.pb.h"
#include "y2db_check.pb.h"
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <strings.h>



int
parse_net_addr(const char *addr, NetAddr *na){
    struct in_addr a;
    char buf[64];

    strncpy(buf, addr, sizeof(buf));
    char *colon = index(buf, ':');
    int port = PORT_YENTA2;

    if(colon){
        *colon = 0;
        port = atoi(colon + 1);
    }

    int v = inet_aton(buf, &a);
    if( !v ) return 0;		// RSN - look it up in peerdb?

    na->ipv4 = a.s_addr;
    na->port = port;

    return 1;
}


int
read_to(int fd, char *buf, int len, int to){
    struct pollfd pf[1];

    pf[0].fd = fd;
    pf[0].events = POLLIN;
    pf[0].revents = 0;

    // timeout is msec
    int r = poll( pf, 1, to * 1000 );
    // 0 => TO, -1 => error, else # fds

    if( r < 0 ) return -1;
    if( r == 0 ){
        errno = ETIME;
        return -1;
    }

    if( pf[0].revents & POLLIN ){
        int r = read(fd, buf, len);
        return r;
    }

    return 0;
}

int
write_to(int fd, const char *buf, int len, int to){
    struct pollfd pf[1];
    int sent = 0;

    while( sent != len ){
        pf[0].fd = fd;
        pf[0].events = POLLOUT;
        pf[0].revents = 0;

        // timeout is msec
        int r = poll( pf, 1, to * 1000 );
        // 0 => TO, -1 => error, else # fds

        if( r < 0 ) return -1;
        if( r == 0 ){
            errno = ETIME;
            return -1;
        }

        if( pf[0].revents & POLLOUT ){
            int s = write(fd, buf, len);
            if( s == -1 && errno == EAGAIN ) continue;
            if( s < 1 ) return -1;
            sent += s;
        }
    }

    return sent;
}


int
sendfile_to(int dst, int src, int len, int to){
    struct pollfd pf[1];
    off_t off = 0;

    while( off != len ){
        pf[0].fd = dst;
        pf[0].events = POLLOUT;
        pf[0].revents = 0;

        int r = poll( pf, 1, to * 1000 );

        if( r < 0 ) return -1;
        if( r == 0 ){
            errno = ETIME;
            return -1;
        }

        if( pf[0].revents & POLLOUT ){
            int s = sendfile(dst, src, &off, len - off);
            if( s == -1 && errno == EAGAIN ) continue;
            if( s < 1 ) return -1;
        }
    }

    return off;
}

void
init_tcp(int fd){

    int size = 1024 * 1024;	// is default max. ndd -set /dev/tcp tcp_max_buf X" to increase

    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    // disable nagle
    int i = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &i, sizeof(i));
}

void
set_nbio(int fd){
    // make non-blocking
    fcntl(fd, F_SETFL, O_NDELAY);
}


int
tcp_connect(NetAddr *na, int to){
    struct sockaddr_in sa;
    struct pollfd pf[1];

    // RSN - ipv6

    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(na->port);
    sa.sin_addr.s_addr = na->ipv4;

    DEBUG("connect %s %d", inet_ntoa(sa.sin_addr), na->port);

    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if( fd == -1 ){
	FATAL("cannot create tcp4 socket: %s", strerror(errno));
    }

    init_tcp(fd);
    set_nbio(fd);

    int i = connect(fd, (sockaddr*)&sa, sizeof(sa));
    if( i == -1 && errno != EINPROGRESS ){
        DEBUG("cannot connect: %s", strerror(errno));
        close(fd);
        return -1;
    }

    pf[0].fd = fd;
    pf[0].events = POLLOUT;
    pf[0].revents = 0;

    int r = poll( pf, 1, to * 1000 );
    if( r <= 0 ){
        // time out
        close(fd);
        if( r == 0 ) errno = ETIME;
        return -1;
    }

    // man page says:
    //     int getsockopt(int s, int level, int optname, void *optval, int *optlen);
    // compiler complains:
    //     error:   initializing argument 5 of `int getsockopt(int, int, int, void*, socklen_t*)'

    int opt, optlen = sizeof(opt);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&opt, (socklen_t*)&optlen);

    if( (pf[0].revents & (POLLERR | POLLHUP | POLLNVAL)) || opt ){
        DEBUG("connect failed %x, %x", pf[0].revents, opt);
        close(fd);
        return -1;
    }

    return fd;
}

// serialize request into ntd
int
serialize_request(NTD *ntd, int reqno, bool enc, google::protobuf::Message *g, int contlen){

    int gsz = g->ByteSize();

    // serial proto buf
    ntd->out_resize( gsz + 1024 );

    g->SerializeWithCachedSizesToArray( (uchar*) ntd->out_data() );

    protocol_header *pho = (protocol_header*) ntd->gpbuf_out;

    if( enc && config ){
        // encrypt
        gsz = acp_encrypt( ntd->out_data(), gsz, ntd->out_data(), ntd->out_size );
        DEBUG("encrypt request %d", gsz);
        pho->flags          = PHFLAG_WANTREPLY | PHFLAG_DATA_ENCR;
    }else{
        pho->flags          = PHFLAG_WANTREPLY;
    }

    pho->version        = PHVERSION;
    pho->type           = reqno;
    pho->msgidno        = random_n(0xFFFFFFFF);
    pho->data_length    = gsz;
    pho->content_length = contlen;
    pho->auth_length    = 0;

    int wsz = sizeof(protocol_header) + gsz;

    cvt_header_to_network( pho );

    return wsz;
}

// serialize reply into ntd
int
serialize_reply(NTD *ntd, google::protobuf::Message *g, int contlen){
    protocol_header *phi = (protocol_header*) ntd->gpbuf_in;

    if( !(phi->flags & PHFLAG_WANTREPLY) ) return 0;

    int gsz = g->ByteSize();

    // serial proto buf
    ntd->out_resize( gsz + 1024 );
    protocol_header *pho = (protocol_header*) ntd->gpbuf_out;
    ntd_copy_header_for_reply(ntd);

    g->SerializeWithCachedSizesToArray( (uchar*) ntd->out_data() );

    if( phi->flags & PHFLAG_DATA_ENCR ){
        // encrypt
        gsz = acp_encrypt( ntd->out_data(), gsz, ntd->out_data(), ntd->out_size );
        DEBUG("encrypt reply %d", gsz);
        pho->flags          = PHFLAG_ISREPLY | PHFLAG_DATA_ENCR;
    }else{
        pho->flags          = PHFLAG_ISREPLY;
    }

    pho->data_length    = gsz;
    pho->content_length = contlen;
    pho->auth_length    = 0;

    cvt_header_to_network( pho );

    int rsz = sizeof(protocol_header) + gsz;

    return rsz;
}

int
write_request(NTD *ntd, int reqno, bool enc, google::protobuf::Message *g, int contlen, int to){

    int wsz = serialize_request(ntd, reqno, enc, g, contlen);
    if( !wsz ) return 0;

    int i = write_to(ntd->fd, ntd->gpbuf_out, wsz, to);
    if( i != wsz ) return -1;

    return wsz;
}

int
write_reply(NTD *ntd, google::protobuf::Message *g, int contlen, int to){

    int rsz = serialize_reply(ntd, g, contlen );
    if( !rsz ) return 0;

    int i = write_to(ntd->fd, ntd->gpbuf_out, rsz, to );
    if( i != rsz ) return -1;

    return rsz;
}

int
read_proto(NTD *ntd, int reqp, int to){
    protocol_header *ph = (protocol_header*) ntd->gpbuf_in;

    // read header
    int i = read_to(ntd->fd, ntd->gpbuf_in, sizeof(protocol_header), to);

    if( i != sizeof(protocol_header) ){
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

        DEBUG("reading protobuf %d", ph->data_length);

        int len = 0;
        char *buf = ntd->gpbuf_in + sizeof(protocol_header);

        while( len < ph->data_length ){
            int rlen = ph->data_length - len;
            i = read_to(ntd->fd, buf + len, rlen, to);
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

            DEBUG("decrypt %d -> %d", ph->data_length, l);
            ph->data_length = l;

            if( !l ){
                DEBUG("decrypt failed");
                return 0;
            }

        }
    }

    return 1;
}

int
make_request(NetAddr *addr, int reqno, int to, google::protobuf::Message *g, google::protobuf::Message *res){
    NTD ntd;
    protocol_header *pho = (protocol_header*) ntd.gpbuf_out;
    int s = 0;

    int fd = tcp_connect(addr, to);
    if( fd < 0 ) return 0;

    ntd.fd = fd;

    // connect + send request
    s = write_request(&ntd, reqno, !addr->same_dc, g, 0, to);
    if( s < 1 ){
        close(fd);
        return 0;
    }

    // read reply
    s = read_proto(&ntd, 0, to);
    close(fd);

    if( s < 1 ){
        return 0;
    }

    protocol_header *phi = (protocol_header*) ntd.gpbuf_in;

    if( phi->flags & PHFLAG_ISERROR ){
        return 0;
    }

    DEBUG("recvd %d", phi->data_length);
    res->ParsePartialFromArray( ntd.in_data(), phi->data_length );
    DEBUG("recv l=%d, %s", phi->data_length, res->ShortDebugString().c_str());

    return 1;
}

int
make_request(const char *addr, int reqno, int to, google::protobuf::Message *g, google::protobuf::Message *res){
    NetAddr na;

    if( !parse_net_addr(addr, &na) ) return 0;
    return make_request(&na, reqno, to, g, res);
}
