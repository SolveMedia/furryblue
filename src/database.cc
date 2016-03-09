/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 11:15 (EST)
  Function: database

*/

#define CURRENT_SUBSYSTEM	'D'

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

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "y2db_getset.pb.h"
#include "y2db_check.pb.h"


#define TOONEW		(60 * 1000000)	// 1 minute, microsecs
#define NDBLOCK 1029
Mutex datalock[NDBLOCK];


extern bool db_uptodate;
extern bool run_program(ACPY2MapDatum *req);


Database::Database(DBConf *cf){

    // convert to microsecs
    _expire = cf->expire * 1000000LL;
    _name   = cf->name;
    _merk   = new Merkle(this);
    _expr   = new Expire(this);
    _ring   = new Ring(this, cf);

    DEBUG("cf expire %d", cf->expire);
}

Database::~Database(){
    delete _merk;
    delete _expr;
    delete _ring;
}

void
Database::configure(void){
    _ring->configure();
}

int64_t
Database::ring_version(void) const {
    return _ring->_version;
}

int
Database::get(ACPY2MapDatum *res){
    string val;

    _get('d', res->key(), &val);
    DEBUG("get '%s' -> [%d]", res->key().c_str(), val.size());
    if( !val.size() ){
        DEBUG("not found");
        return 0;			// not found
    }
    if( val.size() < sizeof(DBRecord) ){
        DEBUG("data is corrupt");
        return 0;
    }

    DBRecord *dr = (DBRecord*) val.data();

    if( res->has_version() && res->version() != dr->ver ){
        DEBUG("ver not found");
        // someone asked for this particular version, but we do not have.
        // make sure our merkle is not misreporting
        if( db_uptodate ){
            int shard  = shard_hash( res->key() );
            int part   = _ring->partno( res->shard() );
            int treeid = _ring->treeid(part);
            VERBOSE("how odd key/ver not found %016llx %s", res->version(), res->key().c_str());
            _merk->del( res->key(), treeid, shard, res->version() );
        }
        return 0;	// wrong version
    }
    if( dr->expire && dr->expire < lr_usec() ){
        DEBUG("expired");
        return 0;				// expired
    }

    // build result
    res->set_version( dr->ver );
    res->set_shard(   dr->shard );
    res->set_expire(  dr->expire );
    res->set_value(   dr->value, val.size() - sizeof(DBRecord) );

    // RSN - process types

    return 1;
}

// 0 => want it
int
Database::want_it(const string& key, int64_t ver){

    string old;
    _get('d', key, &old);
    if( old.empty() ) return DBPUTST_WANT;		// == 0, don't have

    DBRecord *pr = (DBRecord*) old.data();

    if( ver < pr->ver ) return DBPUTST_OLD;		// our copy is newer
    if( ver > pr->ver ) return DBPUTST_WANT;		// our copy is stale, we want it
    return DBPUTST_HAVE;
}

// 0 => stored ok
// * => did not want
int
Database::put(ACPY2MapDatum *req, int *opart){

    // expired?
    int64_t now = lr_usec();
    int64_t exp = req->has_expire() ? req->expire() : 0;

    if( !exp && _expire ) exp = now + _expire;
    if( exp && exp < now ){
        DEBUG("already expired");
        return DBPUTST_OLD;
    }

    // fill in missing
    if( !req->has_version() ) req->set_version( hr_usec() );
    if( !req->has_shard() )   req->set_shard(   shard_hash( req->key() ) );

    // determine partition from shard
    int part = _ring->partno( req->shard() );
    if( opart ) *opart = part;
    int treeid = _ring->treeid(part);
    int lockno = req->shard() % NDBLOCK;

    hrtime_t t0 = hr_usec();
    DEBUG("shard %x part %d tree %x lock %d", req->shard(), part, treeid, lockno);
    // is this partition on this server?
    if( !_ring->is_local(part) ){
        DEBUG("not local");
        return DBPUTST_NOTME;
    }
    // get current ver
    string old;
    DBRecord *pr = 0;

    datalock[ lockno ].lock();
    hrtime_t t1 = hr_usec();

    _get('d', req->key(), &old);
    hrtime_t t2 = hr_usec();

    pr = (DBRecord*) old.data();

    if( old.size() ){
        // check versions
        if( pr->ver >= req->version() ){
            DEBUG("outdated version");
            datalock[ lockno ].unlock();
            return DBPUTST_HAVE;
        }

        _merk->del( req->key(), treeid, pr->shard, pr->ver );
    }
    hrtime_t t3 = hr_usec();

    // run update program?
    //   update + prog | insert + no value
    if( req->program_size() && (old.size() || ! req->has_value()) ){

        int dsize = old.size() - sizeof(DBRecord);
        if( dsize > 0 ){
            // get current value
            req->set_value( pr->value, dsize );
        }
        // run prog. it should alter req->value
        if( !run_program( req ) ){
            // failed
            datalock[ lockno ].unlock();
            return DBPUTST_BAD;
        }
    }
    hrtime_t t4 = hr_usec();

    // only the origin runs the program
    // remove it, and only propagate the value
    req->clear_program();

    // build record to insert
    int dsize = req->value().size();
    int rsize = sizeof(DBRecord) + dsize;
    DBRecord *nr = (DBRecord*) malloc( rsize );
    nr->ver    = req->version();
    nr->expire = exp;
    nr->shard  = req->shard();
    nr->type   = dsize ? DBTYP_DATA : DBTYP_DELETED;
    memcpy(nr->value, req->value().data(), dsize);

    DEBUG("put '%s' [%d]", req->key().c_str(), rsize);
    hrtime_t t5 = hr_usec();

    _put('d', req->key(), rsize, (uchar*)nr);
    hrtime_t t6 = hr_usec();

    _merk->add( req->key(), treeid, req->shard(), req->version() );
    hrtime_t t7 = hr_usec();
    datalock[ lockno ].unlock();

    // only add it, if it is not the default expire
    if( req->has_expire() ) _expr->add( req->key(), exp );

    // VERBOSE("timing: %d %d %d %d %d %d %d", (int)(t1-t0), (int)(t2-t1), (int)(t3-t2), (int)(t4-t3), (int)(t5-t4), (int)(t6-t5), (int)(t7-t6));
    free(nr);
    return DBPUTST_DONE;
}

// actually remove, not tombstone
// used primarily for key expiration
int
Database::remove(const string &key, int64_t ver){

    string old;

    // RSN - lock something

    _get('d', key, &old);
    if( ! old.size() ) return 0;

    DBRecord *pr = (DBRecord*) old.data();

    // verify version or expiration
    if( ver ){
        if( pr->ver != ver ) return 0;
    }else{
        int64_t unow = lr_usec();
        if( pr->expire > unow ) return 0;
    }

    // RSN - determine partition from shard
    int treeid = 0;

    // delete: data, then merkle
    DEBUG("del '%s'", key.c_str());
    _del('d', key);
    _merk->del( key, treeid, pr->shard, ver );

    return 1;
}

/*
  sub:
    d	- data
    m	- merkle tree
    x	- expiration data
    p	- partitioning
*/

int
Database::get_internal(char sub, const string& key, string *res){
    return _get(sub, key, res);
}
int
Database::set_internal(char sub, const string& key, int len, const uchar* data){
    return _put(sub, key, len, data);
}
int
Database::del_internal(char sub, const string& key){
    return _del(sub, key);
}

void
Database::upgrade(void){
    _merk->upgrade();
}

int
Database::get_merkle(int level, int treeid, int64_t ver, int maxresult, ACPY2CheckReply *res){

    int nm = _merk->get(level, treeid, ver, res);

    if( !nm && db_uptodate && _ring->is_stable() ){
        // nothing here, but someone was looking.
        VERBOSE("how odd. nothing here. %X %d %016llX", treeid, level, ver);
        _merk->fix(treeid, level, ver); // check for problem
        return 0;
    }

    if( !maxresult ) maxresult = 64;

    if( level == MERKLE_HEIGHT ) return nm;	// nothing else to add
    if( maxresult && nm >= maxresult )
        return nm;

    int cpos = 0;

    // parts of the tree will be sparse, gather up extra results in the sparse areas
    for(int cl=level+1; cl<=MERKLE_HEIGHT; cl++){
        int epos = res->check_size();
        int ng = 0;
        int nextsize = 0;

        for( ; cpos<epos; cpos++){
            ACPY2CheckValue *mv = res->mutable_check(cpos);

            int nr = _merk->get(cl, treeid, mv->version(), res);

            // sanity check
            bool fixme = 0;
            int expected;
            if( cl < MERKLE_HEIGHT ){
                expected = mv->children();
                if( nr > 16 ) fixme = 1;
            }else{
                expected = mv->keycount();
            }
            if( nr != expected ) fixme = 1;
            if(  mv->children() && !mv->keycount() ) fixme = 1;
            if( !mv->children() &&  mv->keycount() ) fixme = 1;

            if( fixme && db_uptodate && _ring->is_stable() && (mv->version() < lr_usec() - TOONEW) ){
                VERBOSE("how odd. got merkle: nr %d, expected %d [%d %04X %016llX]", nr, expected, cl, treeid, mv->version() );
                _merk->fix(treeid, cl, mv->version());
            }

            ng += nr;
            if( cl >= MERKLE_HEIGHT - 1 )
                nextsize += mv->has_keycount() ? mv->keycount() : 1;
            else
                nextsize += mv->has_children() ? mv->children() : 1;


            DEBUG("get %02X_%016llX => [ch %d, kc %lld] %d (%d)", cl, mv->version(), mv->children(), mv->keycount(), nr, res->check_size());
        }

        nm += ng;

        DEBUG("clev %d nm %d ng %d, nx %d", cl, nm, ng, nextsize);
        if( ng == 0 ) break;				// dead end
        if( nm > maxresult ) break;			// that is enough
        if( nm + nextsize > 2 * maxresult ) break;

    }

    return nm;
}

