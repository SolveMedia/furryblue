/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-25 14:43 (EST)
  Function: distribute data

*/

#define CURRENT_SUBSYSTEM	'L'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "lock.h"
#include "network.h"
#include "hrtime.h"
#include "dbwire.h"
#include "merkle.h"
#include "expire.h"
#include "partition.h"
#include "database.h"
#include "clientio.h"
#include "stats.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <deque>
using std::deque;
#include <algorithm>

#include "y2db_getset.pb.h"

#define MAXHOP		5
#define MAXTRY		3
#define TIMEOUT		15

extern RP_Server * find_server(const char *id);


class Distribute : public ClientIO {
public:
    ACPY2DistReply    result;
    Ring             *ring;
    deque<RP_Server*>*servers;
    const char       *info;
    int		      retries;
    int               count;
    int		      maxseen;
    int 	      hops;
    bool	      andmore;

    Distribute(Ring *, const ACPY2DistRequest *, deque<RP_Server*>*, const char *, int, bool);
    virtual ~Distribute();
    virtual void on_error(void);
    virtual void on_success(void);
    void another(void);

};

Distribute::Distribute(Ring *r, const ACPY2DistRequest *req, deque<RP_Server*>* dq, const char *in, int ms, bool am)
    : ClientIO(dq->front()->bestaddr, PHMT_Y2_DIST, req) {

    dq->pop_front();
    servers = dq;
    _res    = &result;
    andmore = am;
    retries = 0;
    maxseen = ms;
    info    = in;
    hops    = req->hop();

    DEBUG("sending to %s %s", info, _addr.name.c_str());

    _lock.lock();
    set_timeout(TIMEOUT);
    start();
    _lock.unlock();
}

Distribute::~Distribute(){
    DEBUG("done");
    delete servers;
}

//################################################################

void
Distribute::on_error(void){

    DEBUG("error");
    INCSTAT( distrib_errs );
    if( ++retries > MAXTRY )
        another();
    else
        start();
}

void
Distribute::on_success(void){

    // check reply
    int rc = result.result_code();

    if( andmore ){
        // normal data distribution
        // keep sending it until it is well distributed (others already saw it)
        if( rc == DBPUTST_DONE )
            another();
        else if( --maxseen > 0 ){
            INCSTAT( distrib_seen );
            // another, but skip ahead
            for(int i=0; i<=hops; i++){
                if( servers->size() > 1 ) servers->pop_front();
            }
            another();
        }else
            discard();
    }else{
        // repartition data migration
        // keep sending until someone confirms they have a copy
        if( rc == DBPUTST_DONE || rc == DBPUTST_HAVE )
            discard();
        else
            another();
    }
}

void
Distribute::another(void){

    // send to next server on list

    retries = 0;

    if( servers->empty() ){
        discard();
        return;
    }

    RP_Server *s = servers->front();
    servers->pop_front();

    DEBUG("sending next to %s", s->bestaddr.name.c_str());
    retry( s->bestaddr );
}

//################################################################

int
Database::distrib(int part, ACPY2DistRequest *req){
    return _ring->distrib(part, req);
}

int
Ring::distrib(int part, ACPY2DistRequest *req){

    DEBUG("distrib");
    if( req->has_sender() && req->hop() > MAXHOP )
        return 0;
    if( req->has_expire() && req->expire() < hr_usec() )
        return 0;

    INCSTAT( distrib );

    // determine distribution strategy
    /*
      no sender		=> 1 random local (until haveit or wantit)

      parted:
      hops==0		=> 1 faraway(1 to each DC), 1 random local(until haveit)
      hops==1, from far	=> 1 random local (until haveit)

      not parted:
      hops==0		=> 1 faraway(1 to each DC), 2 random local(until haveit)
      hops==1, from far	=> 2 random local (until haveit)

      else		=> orderly local (until haveit)

      orderly = all servers have the list in the same order
                and start to the right of themself
                eg: if we are server #6 => [7 8 9 10 1 2 3 4 5]
    */

    deque<RP_Server*>  *nearby=0, *faraway=0, *midway=0;

    RP_Server *sender = 0;
    bool fromfar = 0;
    bool andmore = 1;
    bool orderly = 0;
    bool sendfar = 0;
    int  flip    = 0;
    int  midflip = 0;
    int  maxsee  = 2;

    if( req->has_sender() ){
        sender = find_server( req->sender().c_str() );
        if( sender && ! sender->bestaddr.same_dc ) fromfar = 1;

        if( req->hop() == 0 ) sendfar = 1;
        if( req->hop() > 1  ) orderly = 1;
        if( req->hop() == 1 && !fromfar ) orderly = 1;
        DEBUG("strategy: sender %s, h %d, ff %d, am %d, ord %d, sf %d", sender?sender->id.c_str():"?", req->hop(), fromfar, andmore, orderly, sendfar);
    }else{
        andmore = 0;
        DEBUG("strategy .");
    }

    // update request
    req->set_hop( req->hop() + 1 );
    req->set_sender( myserver_id );


    nearby = new deque<RP_Server*>;
    if( sendfar )
        faraway = new deque<RP_Server*>;

    _lock.r_lock();

    // build deques of local+remote servers to send to

    if( _part ){
        if( _replicas < 4 ) maxsee = 1;
        Partition *p = _part->at(part);
        bool seenme = 0;

        // NB: if we are set up for rack-aware, there is likely
        // only one capable server per rack. ergo, no need for
        // seperate this-rack/other-racks queues

        // all local
        for(int i=0; i<p->_dc[0]->_server.size(); i++){
            RP_Server *s = p->_dc[0]->_server[i];
            if( s->bestaddr.is_self() ){ seenme = 1; continue; }
            if( !s->is_up )   continue;
            if( s == sender ) continue;

            if( seenme && orderly ){
                nearby->push_front(s);
                flip ++;
            }else
                nearby->push_back(s);
        }

        // faraway
        for(int d=1; d<p->_dc.size(); d++){
            if( !faraway ) break;
            int size = p->_dc[d]->_server.size();
            int n = random();
            for(int i=0; i<p->_dc[0]->_server.size(); i++){
                RP_Server *s =  p->_dc[d]->_server[(i + n) % size];
                if( !s->is_up )   continue;
                if( s == sender ) continue;

                faraway->push_back(s);
                break;
            }
        }

    }else{
        midway = new deque<RP_Server*>;	// this datacenter, different rack

        RP_Server *prev = 0;
        bool seenme = 0;

        for(int i=0; i<_server.size(); i++){
            RP_Server *s = _server[i];
            if( s->bestaddr.is_self() ){ seenme = 1; continue; }
            if( !s->is_up )   continue;
            if( s == sender ) continue;

            if( !s->bestaddr.same_rack && s->bestaddr.same_dc ){
                // some per other rack
                if( prev && prev->rack == s->rack ) continue;
                if( random_n(2) ) continue;	// QQQ
                if( seenme && orderly ){
                    midway->push_front(s);
                    midflip ++;
                }else
                    midway->push_back(s);
            }
            else if( s->bestaddr.same_dc ){
                // all in this dc, this rack
                if( seenme && orderly ){
                    nearby->push_front(s);
                    flip ++;
                }else
                    nearby->push_back(s);
            }else if( faraway ){
                // one per faraway DC
                if( prev && prev->datacenter == s->datacenter ) continue;
                // count servers in this DC
                int nhere = 0;
                for(int x=i; x<_server.size(); x++){
                    if( s->datacenter == _server[x]->datacenter ) nhere ++;
                    else break;
                }
                // pick one
                int n = random();
                for(int x=0; x<nhere; x++){
                    s = _server[ i + (n+x) % nhere ];
                    if( !s->is_up ) continue;
                    faraway->push_back(s);
                    break;
                }
                i += nhere - 1;
            }
            prev = s;
        }
    }

    _lock.r_unlock();

    // NB: ~distribute() will free the deques when finished
    if( faraway ){
        if( faraway->empty() )
            delete faraway;
        else{
            new Distribute(this, req, faraway, "faraway", 2, andmore);
        }
    }

    if( midway ){
        if( midway->empty() )
            delete midway;
        else{
            if( orderly )
                std::reverse(midway->begin(), midway->begin() + midflip - 1);
            else
                std::random_shuffle( midway->begin(), midway->end() );

            new Distribute(this, req, midway, "midway", maxsee, andmore);
        }
    }

    if( nearby->empty() )
        delete nearby;
    else{
        if( orderly )
            std::reverse(nearby->begin(), nearby->begin() + flip - 1);
        else
            std::random_shuffle( nearby->begin(), nearby->end() );

        new Distribute(this, req, nearby, "nearby", maxsee, andmore);
    }


}

