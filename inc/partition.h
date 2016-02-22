/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-20 11:28 (EST)
  Function: 

*/

#ifndef __fbdb_partition_h_
#define __fbdb_partition_h_

#include "lock.h"
#include <string>
#include <vector>
using std::string;
using std::vector;

class Ring;
class Peer;
class Database;
class ACPY2DistRequest;
class ACPY2RingConfReply;

class RP_Server {

public:
    string		id;
    string		datacenter;
    string		rack;
    NetAddr		bestaddr;
    bool		is_up;
    bool		is_avail;
    bool		is_uptodate;
    int64_t		last_conf;

    RP_Server(const Peer*);
    RP_Server(const char *);
    void update_ring_conf(const Peer *);
    void json(std::ostringstream&) const;
};

class RP_DC {
public:
    string		_name;
    vector<RP_Server*>	_server;
    bool		_is_boundary;	// only the "boundary" slots are saved and exported to clients

    RP_DC(const string& d) : _name(d) { _is_boundary = 0; }
};

class Partition {
public:
    vector<RP_DC*>	_dc;		// [0] is local
    vector<RP_Server*>	_server;	// all servers in this partition, local+remote

    uint		_shard;		// = shard_start = treeid
    bool		_is_local;
    int64_t		_stablever;	// config version of finished repartitioning

    RP_DC* find_datacenter(const string &);
    Partition(int, int);
    ~Partition();
};

// glossary
//   Ring      = a consistent hash ring
//   Partition = a "sector" of the ring, gets assigned to a list of servers
//   shard     = hash(key) [32 bits]
//   treeid    = shard_start (shifted) of the partition [16 bits]
//   part      = index into ring->_part

class Ring {
    Database		*_be;
    mutable RWLock	_lock;
    vector<Partition*>	*_part;
    vector<RP_Server*>	_server;	// all servers configured for this database
    int			_replicas;
    int			_ringbits;
    int64_t		_version;	// ring config version
    int64_t		_stablever;	// config version of finished repartitioning
    // coordinate reconfigurer with repartitioner
    Mutex		_relock1;	// mutual exclusion: reconfig vs repart
    Mutex		_relock2;	// avoid race condition set/clr restop
    bool		_restop;	// request repartitioner to stop, so we can reconfig

public:
    int  num_parts()        const;
    int  partno(uint shard) const;
    int  treeid(int part)   const;
    bool is_local(int part) const;
    const char *name(void)  const;
    int  conf_replicas(void) const { return _replicas; }
    int  conf_ringbits(void) const { return _ringbits; }

    int  distrib(int part, ACPY2DistRequest*);	// in distrib.cc

    bool server_is_known(RP_Server *);
    void maybe_add_server(RP_Server *s);
    void maybe_del_server(RP_Server *s);
    void maybe_reconfig(void);
    RP_Server *random_peer(int part, const NetAddr *b=0);		// for AE
    bool report_txt(std::ostringstream&) const;
    bool report_json(std::ostringstream&) const;
    void get_conf(ACPY2RingConfReply*) const;
    void repartitioner(void);
    bool repartitioner_expand(int, int, int*, int64_t*);
    bool repartitioner_contract(int, int, int*, int64_t*);
    bool repartitioner_shuffle(int*, int64_t*);
    bool is_stable(void) const;
    void shutdown(void);

private:
    void configure(void);
    bool _server_is_known(RP_Server *);
    void repartition_init(const vector<Partition*> *, const vector<Partition*> *, int64_t, int64_t);
    void repartition_done(int, int64_t);
    void repartition_clean(int);
    void repartition_save();

    Ring(Database*, const DBConf*);
    ~Ring();
    friend class Database;
    friend class Distribute;

    DISALLOW_COPY(Ring);
};

extern bool ring_setbits(const char *, int, string *);
extern bool ring_setreplicas(const char *, int, string *);
extern bool ring_addnode(const char *, const char *, uint, string *);
extern bool ring_rmnode(const char *, const char *, string *);


#endif /* __fbdb_partition_h_ */
