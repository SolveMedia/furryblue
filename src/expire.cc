/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-19 12:31 (EST)
  Function: data expiration

*/

#define CURRENT_SUBSYSTEM	'D'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "thread.h"
#include "network.h"
#include "hrtime.h"
#include "lock.h"
#include "merkle.h"
#include "expire.h"
#include "partition.h"
#include "database.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>

#include "y2db_check.pb.h"


#define TBUCK 	0xFFFFFFF	// ~5 minutes

// one maintenance thread per tree
static void*
expire_maint(void *x){
    Expire *e = (Expire*)x;

    sleep(30);

    while(1){
        e->flush();
        e->expire();
        sleep(60);	// XXX - configurable
    }
}

//################################################################

Expire::Expire(Database* be){
    _be = be;
    _pq = new ExpireQueue;

    start_thread( expire_maint, (void*)this, 0 );
    // QQQ - do expires in seperate thread?
}

void
Expire::add(const string& key, int64_t exp){

    exp += TBUCK;
    exp &= ~ TBUCK;

    // queue record
    ExpireNote *no = new ExpireNote(key, exp);
    _lock.lock();
    _pq->push(no);
    _lock.unlock();
}

void
Expire::flush_put(const string& eky, deque<string> *dv){

    // remove dupes
    std::sort(   dv->begin(), dv->end() );
    std::unique( dv->begin(), dv->end() );

    // serialize. \0 delimited
    string val;
    for(int i=0; i<dv->size(); i++){
        if( !val.empty() ) val.append(1,'\0');
        val.append( dv->at(i) );
    }
    _be->_put('x', eky, val);
    DEBUG("flush node %s [%d]", eky.c_str(), dv->size());

    dv->clear();
}

void
Expire::flush(void){

    _lock.lock();
    ExpireQueue *q = _pq;
    _pq = new ExpireQueue;
    _lock.unlock();

    char buf[32];
    string eky;
    string val;
    deque<string> vq;
    int64_t exp = 0;
    int n = 0;

    while( !q->empty() ){
        ExpireNote *no = q->top();
        q->pop();

        if( no->exp != exp ){
            if( exp ){
                // save previous
                flush_put(eky, &vq);
            }
            // get
            exp = no->exp;
            snprintf(buf, sizeof(buf), "%016llx", exp);
            eky = buf;
            _be->_get('x', eky, &val);
            split(val, '\0', &vq);
        }
        // add to current
        vq.push_back( no->key );
        delete no;
        n ++;
    }

    // save
    if( val.size() ){
        flush_put(eky, &vq);
    }

    delete q;

    if( n )
        DEBUG("flushed %d", n);
}

void
Expire::expire(void){
    expire_edge();
    expire_spec();
}

//################################################################

class ExpireELR : public LambdaRange {
    Database *be;
public:
    ExpireELR(Database *b) {be = b;}
    virtual bool call(const string&, const string&);
};

bool
ExpireELR::call(const string& key, const string& val){

    // parse merkle-tree leaf node
    ACPY2MerkleLeaf l;
    l.ParsePartialFromString(val);

    // delete all keys in node
    for(int i=0; i<l.rec_size(); i++){
        ACPY2MerkleLeafRec *rec = l.mutable_rec(i);
        be->remove(rec->key(), rec->version());
    }

    return 1;
}

void
Expire::expire_edge(void){
    char buf[32];
    string start, end;

    // get merkle leaves < expire_time
    // 'm', 10/<part>/<time>

    if( ! _be->_expire ) return;
    int npart = _be->_ring->num_parts();
    int64_t texp = hr_usec() - _be->_expire;

    for(int i=0; i<npart; i++){
        int pn = _be->_ring->treeid(i);
        snprintf(buf, sizeof(buf), "10/%04X/", pn);
        start = buf;
        snprintf(buf, sizeof(buf), "10/%04X/%012llX", pn, texp>>16);
        end   = buf;
        ExpireELR ef(_be);

        DEBUG("expire edge %s - %s", start.c_str(), end.c_str());
        _be->_range('m', start, end, &ef);
    }
}

//################################################################

class ExpireSLR : public LambdaRange {
    Database *be;
public:
    ExpireSLR(Database *b) {be = b;}
    virtual bool call(const string&, const string&);
};

bool
ExpireSLR::call(const string& key, const string& val){

    DEBUG("expiring node %s [%d]", key.c_str(), val.size());
    // parse expire node
    deque<string> l;
    split(val, '\0', &l);

    for(int i=0; i<l.size(); i++){
        DEBUG("%s", l[i].c_str());
        be->remove( key, 0 );
    }

    // remove the node
    be->del_internal('x', key);
    return 1;
}

void
Expire::expire_spec(void){
    char buf[32];
    string start, end;

    int64_t texp = hr_usec();
    snprintf(buf, sizeof(buf), "%016llx", texp);
    end = buf;
    start = "";
    ExpireSLR ef(_be);

    // get expire nodes < now
    DEBUG("expire spec 0 - %s", end.c_str());
    _be->_range('x', start, end, &ef);
}
