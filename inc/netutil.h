/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-19 00:03 (EST)
  Function: 

*/

#ifndef __fbdb_netutil_h_
#define __fbdb_netutil_h_

extern int parse_net_addr(const char *, NetAddr *);

extern int  tcp_connect(NetAddr *, int);
extern int  read_to(int, char *, int, int);
extern int  write_to(int, const char *, int, int);
extern int  sendfile_to(int, int, int, int);
extern void init_tcp(int);
extern void set_nbio(int);

extern int make_request(const char *, int, int, google::protobuf::Message *, google::protobuf::Message *);
extern int make_request(NetAddr *,    int, int, google::protobuf::Message *, google::protobuf::Message *);
extern int serialize_reply(NTD *, google::protobuf::Message *, int);

static inline void
cvt_header_from_network(protocol_header *ph){

    ph->version        = ntohl(ph->version);
    ph->type           = ntohl(ph->type);
    ph->msgidno        = ntohl(ph->msgidno);
    ph->auth_length    = ntohl(ph->auth_length);
    ph->data_length    = ntohl(ph->data_length);
    ph->content_length = ntohl(ph->content_length);
    ph->flags          = ntohl(ph->flags);
}

static inline void
cvt_header_to_network(protocol_header *ph){

    ph->version        = htonl(ph->version);
    ph->type           = htonl(ph->type);
    ph->msgidno        = htonl(ph->msgidno);
    ph->auth_length    = htonl(ph->auth_length);
    ph->data_length    = htonl(ph->data_length);
    ph->content_length = htonl(ph->content_length);
    ph->flags          = htonl(ph->flags);
}


#endif /* __fbdb_netutil_h_ */

