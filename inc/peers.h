/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Mar-14 13:45 (EDT)
  Function: peer data

*/

#ifndef __fbdb_peers_h_
#define __fbdb_peers_h_

#include "lock.h"
#include <list>
#include <string>
using std::list;
using std::string;

class ACPY2Status;
class ACPY2StatusReply;


#define PEER_STATUS_UNK		0
#define PEER_STATUS_UP		1
#define PEER_STATUS_MAYBEDN	2
#define PEER_STATUS_DN		3
#define PEER_STATUS_SCEPTICAL	4
#define PEER_STATUS_DEAD	5


class Peer {
    // local status + timestamps
    int			_status;
    bool		_available;
    int			_num_fail;
    hrtime_t		_last_try;
    hrtime_t		_last_up;
    hrtime_t		_last_conf;

    const char 		*_id;		// server_id
    ACPY2Status 	*_gstatus;

public:
    NetAddr		bestaddr;

protected:
    Peer(const ACPY2Status *);
    ~Peer();

    void update(const ACPY2Status*);		// update with new info
    void set_is_up(void);
    void set_is_down(void);
    void set_maybe_down(void);
    void status_reply(ACPY2Status*) const ;	// add status to reply
public:
    int  status(void) const { return _status; }
    bool is_up(void) const { return _status == PEER_STATUS_UP; }
    bool is_avail(void) const { return (_status == PEER_STATUS_UP) && _available; }
    const char *get_id(void) const { return _id; }
    bool has_db(const char *) const;
    bool is_uptodate(void) const;
    int64_t last_conf(void) const { return _last_conf; }
    const string& get_datacenter(void) const;
    const string& get_rack(void) const ;


    DISALLOW_COPY(Peer);

    friend class PeerDB;
};

/****************************************************************/

class PeerDB {

    RWLock	_lock;
    list<Peer*>	_allpeers;
    list<Peer*>	_sceptical;
    list<Peer*> _graveyard;

    void _upgrade(Peer*);	// sceptical -> allpeers
    void _kill(Peer*);		// * -> graveyard
    Peer *_find(const char *);

public:
    void add_peer(ACPY2Status*g);
    void add_sceptical(ACPY2Status*g);
    void reply_peers(ACPY2StatusReply *);
    Peer *find(const char *);
    NetAddr *find_addr(const char*);
    bool is_it_up(const char *);
    int current_load(const char *);
    Peer *random(void);
    void peer_up(const char*);
    void peer_dn(const char*);
    void cleanup(void);
    int  report(NTD*);
    void getall( list<NetAddr> *);

protected:
    PeerDB();
    ~PeerDB();
    DISALLOW_COPY(PeerDB);

    friend void peerdb_init(void);
};

extern PeerDB *peerdb;

void about_myself(ACPY2Status *);

extern void ring_server_update(const Peer*, const char *);


#endif // __fbdb_peers_h_

