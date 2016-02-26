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
#include "runmode.h"
#include "thread.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "y2db_getset.pb.h"
#include "y2db_check.pb.h"

#define TIMEOUT		30
#define TOONEW		(60 * 1000000)	// 1 minute, microsecs
#define MAXFETCH	256
#define MAXRESULTS	1024
#define MAXERR		20
#define MAXTHREAD	10


// this gets run periodically via store_maint()
bool
Database::ae(void){
    bool ok = 1;
    int npart = _ring->num_parts();
    uint64_t nsync = 0;
    uint64_t mism  = 0;

    DEBUG("ae %s %d", _name.c_str(), npart);
    for(int p=0; p<npart; p++ ){
        if( !_ring->is_local(p) ) continue;
        int treeid = _ring->treeid(p);
        // compare merkle tree with random peer
        RP_Server *s = _ring->random_peer(p);
        if( !s ) continue;
        int r = _merk->ae(p, treeid, & s->bestaddr, &nsync, &mism);
        if( !r ) ok = 0;
        VERBOSE("ae %s ok=%d mismatch=%lld synced=%lld", _name.c_str(), r, mism, nsync);
    }

    return ok;
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

/****************************************************************/


struct ToDo {
    uint64_t	version;
    int		level;
};

class BadNode {
    bool         emptyp;;
    deque<ToDo*> dq;
    Mutex	 lock;
public:
    void add(int level, uint64_t ver);
    bool empty(void);
    ToDo *pop(void);
};

bool
BadNode::empty(void){

    return emptyp;
}

void
BadNode::add(int l, uint64_t v){

    lock.lock();

    ToDo *t = new ToDo;
    t->level   = l;
    t->version = v;
    dq.push_back(t);
    emptyp = 0;

    lock.unlock();
}

ToDo*
BadNode::pop(void){
    ToDo *t = 0;

    // process nodes in LIFO order - walks in DFS order, and keeps list small
    // FIFO order => breadth-first => big list

    lock.lock();
    if( dq.empty() ){
        emptyp = 1;
    }else{
        t = dq.back();
        dq.pop_back();
    }
    lock.unlock();
    return t;
}

class Tinfo {
public:
    Merkle  *mk;
    BadNode *bn;
    NetAddr *peer;
    int      part;
    int      treeid;
    bool     ok;
    bool     active;
    int64_t  mismatch;
    int64_t  nsynced;

    Tinfo(){ ok = 1; active = 0; mismatch = 0; nsynced = 0; mk = 0; bn = 0;}
};


static int
highest_level(ACPY2CheckReply &r){
    int h=0;

    for(int i=0; i<r.check_size(); i++){
        int l = r.check(i).level();
        if( l > h ) h = l;
    }
    return h;
}

void
ae_work_start( Tinfo *ti ){
    ti->mk->ae_work( ti );
}

/****************************************************************/

void
Merkle::ae_work(Tinfo *ti){
    ACPY2CheckRequest  req;
    ACPY2CheckReply    res;
    ACPY2GetSet        getreq;
    MerkleCache        cache;
    BadNode           *badnode = ti->bn;
    hrtime_t           tnew    = lr_usec() - TOONEW;
    int                errs    = 0;

    ti->active = 1;
    req.set_map( _be->_name );
    req.set_treeid( ti->treeid );
    req.set_maxresult( MAXRESULTS );


    while( 1 ){
        stats.last_ae_time = lr_now();
        if( runmode.is_stopping() ) break;

        ToDo *t = badnode->pop();
        if( !t ){
            sleep(5);
            t = badnode->pop();
        }
        if( !t ) break;

        if( t->level < 11 ) DEBUG(" check node %02d_%016llX", t->level, t->version);
        // build request + send to peer
        req.set_level(   t->level );
        req.set_version( t->version );
        delete t;

        int r = make_request(ti->peer, PHMT_Y2_CHECK, TIMEOUT, &req, &res);
        if( !r ){
            DEBUG(" conversation failed");
            ti->ok = 0;

            if( ++errs > MAXERR ) break;
            continue;
        }
        errs = 0;
        // compare results
        // find highest level result, ignore others
        int highest = highest_level(res);
        // DEBUG("  got %d looking at %d", res.check_size(), highest);

        for(int i=0; i<res.check_size(); i++){
            ACPY2CheckValue *c = res.mutable_check(i);
            if( c->level() < highest ) continue;
            if( c->version() > tnew )  continue;	// too new, don't bother

            if( c->level() > MERKLE_HEIGHT ){
                // do we need this key?
                // DEBUG("  node %02d_%016llX", c->level(), c->version());

                int  npart = _be->_ring->partno( c->shard() );
                bool local = (npart == ti->part) || _be->_ring->is_local(npart);
                if( !local ) continue;

                if( _be->want_it(c->key(), c->version()) ){
                    ti->nsynced  ++;

                    ACPY2MapDatum *d = getreq.add_data();
                    d->set_map( _be->_name );
                    d->set_key( c->key() );
                    d->set_version( c->version() );

                    //DEBUG("   need key %s", c->key().c_str());

                    if( getreq.data_size() >= MAXFETCH ){
                        // process keys
                        if( ! ae_fetch(ti->part, &getreq, ti->peer) ) ti->ok = 0;
                    }
                }else{
                    // we went this far for a key we don't want,
                    // make sure it is in the merkle tree
                    if( req.level() != 0 ){
                        add( c->key(), ti->treeid, c->shard(), c->version() );
                        fix( ti->treeid, c->level(), c->version() );
                    }
                }
            }else{

                // check the hash
                if( c->isvalid() && !compare_result( &cache, c ) ){
                    // hash mismatch
                    badnode->add( c->level(), c->version() );
                    ti->mismatch ++;
                    // DEBUG("  node %02d_%016llX  => ne", c->level(), c->version());
                }else{
                    // hash same
                    // DEBUG("  node %02d_%016llX  => OK", c->level(), c->version());
                }
            }
        }
    }

    if( ! ae_fetch( ti->part, &getreq, ti->peer ) ) ti->ok = 0;
    ti->active = 0;
}


bool
Merkle::ae(int part, int treeid, NetAddr *peer, uint64_t *nsync, uint64_t *mism){
    bool    ok       = 1;
    int64_t mismatch = 0;
    int64_t synced   = 0;
    Tinfo   ti[MAXTHREAD];
    BadNode badnode;

    DEBUG("AE check %s[%d](%d) with %s", _be->_name.c_str(), part, treeid, peer->name.c_str());

    *nsync = 0;
    *mism  = 0;

    // init helper thread info
    for(int i=0; i<MAXTHREAD; i++){
        ti[i].mk     = this;
        ti[i].bn     = &badnode;
        ti[i].peer   = peer;
        ti[i].treeid = treeid;
        ti[i].part   = part;
    }

    // start at the root
    badnode.add( MERKLE_HEIGHT - MERKLE_BUILD, 0 );

    // start/restart threads
    // start one thread, wait. if still work to do, start another, wait, etc.
    while(1){
        if( runmode.is_stopping() ) break;
        if( badnode.empty() )       break;

        for(int i=0; i<MAXTHREAD; i++){
            if( runmode.is_stopping() ) break;
            if( badnode.empty() )       break;
            if( ti[i].active )          continue;

            DEBUG("starting ae thread");
            start_thread( (void* (*)(void*))ae_work_start, (void*)(ti + i), 0 );

            // exponentially increase delay before starting more
            int d = (1<<i) * 30;
            if( d < 60 )  d = 60;
            if( d > 600 ) d = 600;
            for(int j=0; j<d; j++){
                sleep(1);
                if( runmode.is_stopping() ) break;
                if( badnode.empty() )       break;

            }
        }
    }

    // wait until all threads done
    for(int i=0; i<MAXTHREAD; i++){
        while( ti[i].active ) sleep(1);
        mismatch += ti[i].mismatch;
        synced   += ti[i].nsynced;
        if( ! ti[i].ok ) ok = 0;
    }

    *mism  = mismatch;
    *nsync = synced;
    return ok;
}


bool
Merkle::ae_fetch(int part, ACPY2GetSet *req, NetAddr *peer){
    bool ok  = 1;
    int errs = 0;

    if( req->data_size() == 0 ) return 1;

    int r = make_request(peer, PHMT_Y2_GET, TIMEOUT, req, req);

    if( !r ){
        DEBUG(" conversation failed");
        // failed - try another server
        RP_Server *s = _be->_ring->random_peer(part, peer);
        if( s ){
            r = make_request(& s->bestaddr, PHMT_Y2_GET, TIMEOUT, req, req);
        }
        if( !r ){
            ok = 0;
        }
    }

    if( ok ){
        // process results
        for(int i=0; i<req->data_size(); i++){
            ACPY2MapDatum *r = req->mutable_data(i);
            //DEBUG("   put %s", r->key().c_str());
            _be->put( r, (int*)0);
            INCSTAT( ae_fetched );
        }
    }


    req->Clear();

    return ok;
}

