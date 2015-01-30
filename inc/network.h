/*
  Copyright (c) 2008 by Jeff Weisberg
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2008-Dec-28 12:58 (EST)
  Function: 
*/

#ifndef __fbdb_network_h_
#define __fbdb_network_h_

#include "std_reply.pb.h"

#include <sys/socket.h>
#include <netinet/in.h>

#include <string>
#include <stdint.h>

using std::string;

#define PORT_YENTA2	3508

typedef unsigned char uchar;

struct NetAddr {
    int		port;
    uint32_t	ipv4;
    uchar	ipv6[16];
    string	name;
    bool	same_dc;
    bool	same_rack;

    bool is_self(void);
};


// see also: AC::Protocol

// on-the-wire protocol header
typedef struct {
    uint32_t	  version;
    uint32_t	  type;
     int32_t	  auth_length;
     int32_t	  data_length;
     int32_t	  content_length;
    uint32_t	  msgidno;
    uint32_t	  flags;

# define PHVERSION		0x41433032
# define PHMT_STATUS		0
# define PHMT_HEARTBEAT		1
# define PHMT_HEARTBEATREQ	2
# define PHMT_Y2_STATUS		32
# define PHMT_Y2_GET		33
# define PHMT_Y2_DIST		34
# define PHMT_Y2_CHECK		35


// ...
# define PHFLAG_ISREPLY		0x1
# define PHFLAG_WANTREPLY	0x2
# define PHFLAG_ISERROR		0x4
# define PHFLAG_DATA_ENCR	0x8
# define PHFLAG_CONT_ENCR	0x10
} protocol_header;

class NTD {
public:
    int                 fd;
    bool		have_data;
    bool		is_tcp;
    int			in_size;
    int			out_size;
    char                *gpbuf_in;
    char                *gpbuf_out;
    struct sockaddr_in  peer;
    // ...

    NTD(int i, int o){ _alloc(i,o); }
    NTD(void)        { _alloc(2048, 2048); }
    void _alloc(int i, int o){
        fd = 0; have_data = 0; is_tcp = 0;
        gpbuf_in = (char*)malloc(i); gpbuf_out = (char*)malloc(o);
        in_size = i; out_size = o;
    }
    ~NTD(){ if(in_size) free(gpbuf_in); if(out_size) free(gpbuf_out); };

    char * in_data()   { return gpbuf_in  + sizeof(protocol_header); }
    char * out_data()  { return gpbuf_out + sizeof(protocol_header); }
    int data_size()    { return out_size - sizeof(protocol_header); }

    void in_resize(int sz){  if(sz > in_size){  gpbuf_in  = (char*)realloc(gpbuf_in,  sz); in_size  = sz; } }
    void out_resize(int sz){ if(sz > out_size){ gpbuf_out = (char*)realloc(gpbuf_out, sz); out_size = sz; } }
};


extern float net_busyness, net_utiliz, net_load_metric, net_req_per_sec;
extern long long net_requests, net_puzzles;

extern int      myport;
extern uint32_t myipv4, myipv4pin;
extern char     myhostname[];
extern string   myserver_id;
extern string   mydatacenter;
extern NetAddr  mynetaddr;
extern string   myipandport;
extern string   myrack;
extern int 	udp4s_fd, udp4c_fd;


extern void network_init(void);
extern void network_manage(void);
extern int  tcp_read_proto(int, int);

extern int  reply_ok(NTD*);
extern int  reply_error(NTD*, int, const char*);
extern int  write_request(NTD*, int reqno, google::protobuf::Message *g, int contlen, int to);
extern int  write_reply(NTD *, google::protobuf::Message *g, int contlen, int to);
extern void toss_request(int, NetAddr*,    int, google::protobuf::Message *);
extern void toss_request(int, const char*, int, google::protobuf::Message *);
extern void toss_request(int, const sockaddr_in*, int, google::protobuf::Message *);
extern int  make_request(NetAddr *, int, google::protobuf::Message *, int);
extern int  make_request(const char *, int, google::protobuf::Message *, int);

static inline void ntd_copy_header_for_reply(struct NTD *ntd){
    protocol_header *pi = (protocol_header*)ntd->gpbuf_in;
    protocol_header *po = (protocol_header*)ntd->gpbuf_out;

    po->version        = PHVERSION;
    po->msgidno        = pi->msgidno;
    po->type           = pi->type;
    po->flags          = PHFLAG_ISREPLY;
    po->auth_length    = 0;
    po->content_length = 0;
    po->data_length    = 0;

}


#endif // __fbdb_network_h_
