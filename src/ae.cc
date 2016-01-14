/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Dec-01 16:48 (EST)
  Function: anti-entropy

*/
#define CURRENT_SUBSYSTEM	'A'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "lock.h"
#include "network.h"
#include "netutil.h"
#include "hrtime.h"
#include "dbwire.h"
#include "merkle.h"
#include "expire.h"
#include "partition.h"
#include "database.h"
#include "stats.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "y2db_getset.pb.h"
#include "y2db_check.pb.h"

#define TIMEOUT		30
#define TOONEW		(60 * 1000000)	// 1 minute, microsecs
#define MAXFETCH	64
#define BIGLIST		10240
#define MAXERR		20


// this gets run periodically via store_maint()
bool
Database::ae(void){
    bool ok = 1;
    int npart = _ring->num_parts();
    int nsync = 0;

    DEBUG("ae %s %d", _name.c_str(), npart);
    for(int p=0; p<npart; p++ ){
        if( !_ring->is_local(p) ) continue;
        int treeid = _ring->treeid(p);
        // compare merkle tree with random peer
        RP_Server *s = _ring->random_peer(p);
        if( !s ) continue;
        int r = _merk->ae(p, treeid, & s->bestaddr, &nsync);
        if( !r ) ok = 0;
        VERBOSE("ae %s ok=%d synced=%d", _name.c_str(), r, nsync);
    }
}

RP_Server *
Ring::random_peer(int part, const NetAddr *butnot){
    vector<RP_Server*> *srvr;
    RP_Server *best=0, *plocal=0, *pfar=0, *pood=0;
    int nlocal=1, nfar=0, nood=1;

    _lock.r_lock();

    if( !_part ){
        srvr = &_server;
    }else if( part < _part->size() && part >= 0 ){
        srvr = & _part->at(part)->_server;
    }else{
        _lock.r_unlock();
        return 0;
    }

    // look for an up to date peer, (usually) prefer local
    // use an out-of-date peer only if we have to
    // NB: if we never used ood peers, we'd have a bootstrap deadlock
    for(int i=0; i<srvr->size(); i++){
        RP_Server *s = srvr->at(i);

        if( !s->is_up ) continue;
        // but don't use this one
        if( & s->bestaddr == butnot ) continue;

        if( ! s->is_uptodate ){
            if( !pood || !random_n(nood) ) pood = s;
            nood ++;
        }
        else if( s->bestaddr.same_dc ){
            if( !plocal || !random_n(nlocal) ) plocal = s;
            nlocal ++;
        }
        else{
            if( !pfar || !random_n(nfar) ) pfar = s;
            nfar ++;
        }
    }
    _lock.r_unlock();

    if( !random_n(8) && pfar ) best = pfar;
    if( !best ) best = plocal;
    if( !best ) best = pfar;
    if( !best ) best = pood;

    return best;
}


struct ToDo {
    int64_t	version;
    int		level;
};

static void
add_todo(deque<ToDo*> &dq, int l, int64_t v){
    ToDo *t = new ToDo;
    t->level   = l;
    t->version = v;
    dq.push_back(t);
}

static int
highest_level(ACPY2CheckReply &r){
    int h=0;

    for(int i=0; i<r.check_size(); i++){
        int l = r.check(i).level();
        if( l > h ) h = l;
    }
    return h;
}

// RSN - multithread

bool
Merkle::ae(int part, int treeid, NetAddr *peer, int *nsync){
    bool ok  = 1;
    int errs = 0;
    ACPY2CheckRequest req;
    ACPY2CheckReply   res;
    deque<ToDo*>      badnode;
    deque<string>     needkey;
    MerkleCache       cache;
    hrtime_t tnew = lr_usec() - TOONEW;

    DEBUG("AE check %s[%d](%d) with %s", _be->_name.c_str(), part, treeid, peer->name.c_str());

    req.set_map( _be->_name );
    req.set_treeid( treeid );
    req.set_maxresult( 256 );
    *nsync = 0;

    // start at the root
    add_todo( badnode, MERKLE_HEIGHT - MERKLE_BUILD, 0 );

    while( !badnode.empty() ){
        // process nodes in LIFO order - walks in DFS order, and keeps list small
        // FIFO order => breadth-first => big list
        ToDo *t = badnode.back();
        badnode.pop_back();
        DEBUG(" check node %02d_%012llX", t->level, t->version);
        // build request + send to peer
        req.set_level( t->level );
        req.set_version( t->version );
        delete t;

        int r = make_request(peer, PHMT_Y2_CHECK, TIMEOUT, &req, &res);
        if( !r ){
            DEBUG(" conversation failed");
            ok = 0;
            if( ++errs > MAXERR ) return 0;
            continue;
        }
        errs = 0;
        // compare results
        // find highest level result, ignore others
        int highest = highest_level(res);
        DEBUG("  got %d looking at %d", res.check_size(), highest);

        for(int i=0; i<res.check_size(); i++){
            ACPY2CheckValue *c = res.mutable_check(i);
            if( c->level() < highest ) continue;
            if( c->version() > tnew )  continue;	// too new, don't bother

            if( c->level() > MERKLE_HEIGHT ){
                // do we need this key?
                DEBUG("  node %02d_%012llX", c->level(), c->version());

                int  npart = _be->_ring->partno( c->shard() );
                bool local = (npart == part) || _be->_ring->is_local(npart);
                if( !local ) continue;

                if( _be->want_it(c->key(), c->version()) ){
                    needkey.push_back( c->key() );
                    DEBUG("   need key %s", c->key().c_str());

                    if( needkey.size() >= BIGLIST ){
                        // process keys
                        if( ! ae_fetch(part, &needkey, peer) ) ok = 0;
                    }
                }
            }else{
                // check the hash
                if( c->isvalid() && !compare_result( &cache, c ) ){
                    // hash mismatch
                    add_todo( badnode, c->level(), c->version() );
                    DEBUG("  node %02d_%012llX  => ne", c->level(), c->version());
                }else{
                    // hash same
                    DEBUG("  node %02d_%012llX  => OK", c->level(), c->version());
                }
            }

            // RSN - also check that our hashes are correct
        }
    }

    *nsync = needkey.size();
    if( ! ae_fetch( part, &needkey, peer ) ) ok = 0;

    return ok;
}

bool
Merkle::ae_fetch(int part, deque<string> *dk, NetAddr *peer){
    bool ok  = 1;
    int errs = 0;
    ACPY2GetSet getreq;

    // fetch missing keys
    // RSN - multiple threads, multiple peers
    while( !dk->empty() ){
        string key = dk->front();
        dk->pop_front();

        // bundle up a bunch of requests
        ACPY2MapDatum *d = getreq.add_data();
        d->set_map( _be->_name );
        d->set_key( key );

        if( getreq.data_size() >= MAXFETCH || dk->empty() ){
            int r = make_request(peer, PHMT_Y2_GET, TIMEOUT, &getreq, &getreq);
            if( !r ){
                DEBUG(" conversation failed");
                // failed - try another server
                RP_Server *s = _be->_ring->random_peer(part, peer);
                if( s ){
                    r = make_request(& s->bestaddr, PHMT_Y2_GET, TIMEOUT, &getreq, &getreq);
                    if( r ){
                        // new peer worked, switch
                        peer = & s->bestaddr;
                    }
                }
                if( !r ){
                    ok = 0;
                    if( ++errs > MAXERR ) return 0;	// give up
                    continue;
                }
            }
            // process results
            for(int i=0; i<getreq.data_size(); i++){
                ACPY2MapDatum *r = getreq.mutable_data(i);
                DEBUG("   put %s", r->key().c_str());
                _be->put( r, (int*)0);
                INCSTAT( ae_fetched );
            }

            getreq.Clear();
            errs = 0;
        }
    }

    return ok;
}
