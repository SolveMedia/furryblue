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
#include "runmode.h"
#include "peers.h"

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
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/loadavg.h>
#include <sys/sendfile.h>
#include <strings.h>


// toss + forget, do not wait for a response
void
toss_request(int fd, const sockaddr_in *sa, int reqno, google::protobuf::Message *g){
    char *buf;

    string gout;
    g->SerializeToString( &gout );
    int gsz = gout.length();
    buf = (char*)malloc( sizeof(protocol_header) + gsz );
    protocol_header *pho = (protocol_header*) buf;

    pho->version        = PHVERSION;
    pho->type           = reqno;
    pho->flags          = 0;
    pho->msgidno        = random_n(0xFFFFFFFF);
    pho->auth_length    = 0;
    pho->content_length = 0;
    pho->data_length    = gsz;

    cvt_header_to_network( pho );

    memcpy(buf + sizeof(protocol_header), gout.c_str(), gsz);

    int efd = fd;
    if( fd == 0 ){
        // create transient socket
        efd = socket(PF_INET, SOCK_DGRAM, 0);
    }

    DEBUG("sending udp");
    sendto(efd, buf, sizeof(protocol_header) + gsz, 0, (sockaddr*)sa, sizeof(sockaddr_in));

    free( buf );
    if( fd == 0 ) close(efd );
}

void
toss_request(int fd, NetAddr *na, int reqno, google::protobuf::Message *g){
    struct sockaddr_in sa;

    // RSN - ipv6

    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(na->port);
    sa.sin_addr.s_addr = na->ipv4;

    toss_request(fd, &sa, reqno, g);
}

void
toss_request(int fd, const char *addr, int reqno, google::protobuf::Message *g){
    NetAddr na;

    if( !parse_net_addr(addr, &na) ) return;
    toss_request(fd, &na, reqno, g);
}


