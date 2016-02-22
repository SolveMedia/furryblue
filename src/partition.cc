/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-24 14:43 (EST)
  Function:

*/

#define CURRENT_SUBSYSTEM	'R'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "thread.h"
#include "network.h"
#include "netutil.h"
#include "hrtime.h"
#include "peers.h"
#include "store.h"
#include "partition.h"
#include "database.h"
#include "merkle.h"
#include "runmode.h"


#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#include "y2db_getset.pb.h"
#include "y2db_ring.pb.h"

#include <map>
using std::map;
#include <algorithm>
#include <sstream>

#define CURRENT_VERSION		1	// on disk config format version


bool partition_safe_to_stop = 1;// for map<char*>

struct CStrComp {
    bool operator() (const char* lhs, const char* rhs) const {
        return strcmp(lhs, rhs) < 0;
    }
};

// all servers
typedef map<const char *, RP_Server*, CStrComp> SrvrMap;
static SrvrMap allsrvr;

// all rings
static vector<Ring*> allring;

RP_Server *find_or_add_server(const char *, const char *, const char *);


//################################################################

static void*
ring_maint(void*){

    sleep(10);
    partition_safe_to_stop = 0;

    // periodically, see if we need to adjust configs
    while(1){
        if( runmode.is_stopping() ){
            // make sure all threads are in a safe state before shutting down
            for(int i=0; i<allring.size(); i++){
                allring[i]->shutdown();
            }
            partition_safe_to_stop = 1;
            return 0;
        }else{
            for(int i=0; i<allring.size(); i++){
                allring[i]->maybe_reconfig();
            }
        }

        sleep(15);
    }
}

// per database partition maint thread
static void *
repart_maint(void *x){
    Ring *r = (Ring*)x;
    r->repartitioner();
}

void
ring_init(void){

    // make sure current server is known
    find_or_add_server( myserver_id.c_str() , mydatacenter.c_str(), myrack.c_str() );

    start_thread(ring_maint, 0, 0);
}

//################################################################

RP_Server *
find_server(const char *id){
    SrvrMap::iterator it = allsrvr.find( id );
    if( it == allsrvr.end() ) return 0;
    return it->second;
}

RP_Server *
find_or_add_server(const char *name, const char *dc, const char *rack){
    RP_Server *s = find_server(name);
    if(s) return s;

    DEBUG("new server %s", name);
    s = new RP_Server(name);
    s->datacenter = dc;
    s->rack       = rack;
    allsrvr[ s->id.c_str() ] = s;
    return s;
}

static Ring *
find_ring(const char *name){
    for(int i=0; i<allring.size(); i++){
        Ring *r = allring[i];
        if( ! strcmp(r->name(), name) ) return r;
    }
    return 0;
}

// peerdb updates are sent here
void
ring_server_update(const Peer* p, const char *msg){

    // known server?
    RP_Server *s = find_server( p->get_id() );
    if( !s ){
        // add it
        s = new RP_Server(p);
        DEBUG("new server %s", p->get_id());
        allsrvr[ s->id.c_str() ] = s;
        s->update_ring_conf(p);
        return;
    }

    // update status + addr
    if( p->bestaddr.ipv4 != s->bestaddr.ipv4 ){
        ATOMIC_SET32(s->bestaddr.ipv4, p->bestaddr.ipv4);
    }

    // changed db list?
    if( s->last_conf < p->last_conf() ){
        DEBUG("update server %s (%s)", p->get_id(), msg);
        s->update_ring_conf(p);
    }

    s->is_uptodate        = p->is_uptodate();
    s->is_up              = p->is_up();
    s->is_avail		  = p->is_avail();
    s->last_conf          = p->last_conf();
    s->bestaddr.port      = p->bestaddr.port;
    s->bestaddr.same_dc   = p->bestaddr.same_dc;
    s->bestaddr.same_rack = p->bestaddr.same_rack;
}

//################################################################

RP_Server::RP_Server(const Peer *p){
    id          = p->get_id();
    datacenter  = p->get_datacenter();
    rack	= p->get_rack();
    bestaddr    = p->bestaddr;
    is_up       = p->is_up();
    is_avail    = p->is_avail();
    is_uptodate = p->is_uptodate();
    last_conf   = p->last_conf();
}

RP_Server::RP_Server(const char *name){
    id            = name;
    is_up         = 0;
    is_avail      = 0;
    is_uptodate   = 0;
    last_conf     = 0;
    bestaddr.name = name;

    if( myserver_id == name ){
        bestaddr.ipv4      = myipv4pin ? myipv4pin : myipv4;
        bestaddr.port      = myport;
        bestaddr.same_dc   = 1;
        bestaddr.same_rack = 1;
    }
}

void
RP_Server::update_ring_conf(const Peer *p){

    for(int i=0; i<allring.size(); i++){
        Ring *r = allring[i];
        const char *name = r->name();

        if( p->has_db(name) ){
            r->maybe_add_server(this);
        }else{
            r->maybe_del_server(this);
        }
    }
}

bool
Ring::_server_is_known(RP_Server *s){

    for(int i=0; i<_server.size(); i++){
        if( _server[i] == s ){
            return 1;
        }
    }

    return 0;
}

bool
Ring::server_is_known(RP_Server *s){

    _lock.r_lock();
    bool r = _server_is_known(s);
    _lock.r_unlock();
    return r;
}

// sort by datacenter, local servers first, then by rack
static bool
server_sort_compare(const RP_Server *a, const RP_Server *b){

    if( a->datacenter == mydatacenter && b->datacenter != mydatacenter ) return 1;
    if( a->datacenter != mydatacenter && b->datacenter == mydatacenter ) return 0;

    if( a->datacenter < b->datacenter ) return 1;
    if( a->datacenter > b->datacenter ) return 0;

    if( a->rack < b->rack ) return 1;
    if( a->rack > b->rack ) return 0;

    if( a->bestaddr.name < b->bestaddr.name ) return 1;

    return 0;
}

void
Ring::maybe_add_server(RP_Server *s){

    if( server_is_known(s) ) return;

    _lock.w_lock();
    if( !server_is_known(s) ){
        _server.push_back(s);
        // keep the list in order
        std::sort( _server.begin(), _server.end(), server_sort_compare );
    }
    _lock.w_unlock();
}

void
Ring::maybe_del_server(RP_Server *s){

    if( !server_is_known(s) ) return;

    _lock.w_lock();
    std::remove( _server.begin(), _server.end(), s );
    _lock.w_unlock();
}


//################################################################

Ring::Ring(Database* be, const DBConf *cf){
    _be = be;

    allring.push_back(this);
    _replicas  = cf->replicas;
    _ringbits  = cf->ringbits;
    _restop    = 0;
    _version   = 0;
    _stablever = 0;
    _part      = 0;
}

void
Ring::configure(void){
    maybe_reconfig();
    start_thread( repart_maint, (void*)this, 0 );
}

Ring::~Ring(){
    if(_part) delete _part;
}

int
Ring::num_parts() const {

    if( !_part ) return 1;

    _lock.r_lock();
    int n = _part ? _part->size() : 1;
    _lock.r_unlock();
    return n;
}

const char *
Ring::name(void) const {
    return _be->_name.c_str();
}

bool
Ring::is_local(int part) const {

    if( !_part || !_replicas ) return 1;

    _lock.r_lock();
    bool r = _part ? 0 : 1;
    if( _part && part < _part->size() && part >= 0 ){
        r = _part->at(part)->_is_local;
    }
    _lock.r_unlock();

    return r;
}

int
Ring::treeid(int part) const {

    if( !_part ) return 0;

    _lock.r_lock();
    int t = 0;
    if( _part && part < _part->size() && part >= 0 )
        t = _part->at(part)->_shard >> 16;
    _lock.r_unlock();
    return t;
}

static bool
part_comp_shard(const Partition *a, int b){
    return a->_shard < b;
}

// binary search to determine which partition this shard is in
int
Ring::partno(uint shard) const {
    int n;

    if( !_part ) return 0;

    _lock.r_lock();
    if( _part ){
        vector<Partition*>::const_iterator it = std::lower_bound( _part->begin(), _part->end(), shard, part_comp_shard );
        if( it != _part->end() ){
            n = it - _part->begin();
        }else{
            n = 0;
        }
    }
    _lock.r_unlock();
    return n;
}

// we good?
bool
Ring::is_stable(void) const {

    if( !_part ) return 1;
    return _stablever == _version;
}

//################################################################

Partition::Partition(int n, int bits){
    // add local datacenter
    RP_DC *dc  = new RP_DC(mydatacenter);
    _is_local  = 0;
    _shard     = 0;
    _stablever = 0;
    _shard     = n << (32 - bits);

    _dc.resize(1);
    _dc[0] = dc;

}

Partition::~Partition(){

    for(int i=0; i<_dc.size(); i++){
        delete _dc[i];
    }
}

RP_DC *
Partition::find_datacenter(const string &dc){

    for(int i=0; i<_dc.size(); i++){
        if( _dc[i]->_name == dc ){
            return _dc[i];
        }
    }
    return 0;
}

// add partition
static void
part_insert(vector<Partition*> *tp, int bits, const string& server, const string& datacenter, const string& rack, uint shard ){

    int slot = shard >> (32 - bits);

    Partition *p = tp->at(slot);

    if( myserver_id == server ) p->_is_local = 1;

    // find dc
    RP_DC *dc = p->find_datacenter( datacenter );

    if( !dc ){
        DEBUG("add dc %s", datacenter.c_str());
        // add this dc to all parts
        for(int i=0; i<tp->size(); i++){
            RP_DC *d = new RP_DC(datacenter);
            tp->at(i)->_dc.push_back(d);
            if( i == slot ) dc = d;
        }
    }

    // add server
    DEBUG("dc %s slot %d + %s", dc->_name.c_str(), slot, server.c_str(), dc->_server.size() );
    RP_Server *s = find_or_add_server( server.c_str(), datacenter.c_str(), rack.c_str() );
    dc->_server.push_back(s);
    dc->_is_boundary = 1;
    p->_server.push_back(s);

}


// fill in servers into the remaining empty slots
static void
interpolate(vector<Partition*> *tp){

    int size = tp->size();

    for(int i=0; i<size; i++){
        Partition *p = tp->at(i);
        for(int d=0; d<p->_dc.size(); d++){
            RP_DC *dc = p->_dc[d];
            if( dc->_is_boundary ) continue;	// already has servers

            // walk backwards until we find something
            for(int j=0; j<size; j++){
                int pos = (i - j + size) % size;
                Partition *lp = tp->at(pos);
                RP_DC *ldc = lp->_dc[d];
                if( ldc->_server.empty() ) continue;

                // copy servers
                dc->_server.resize( ldc->_server.size() );
                for(int s=0; s<ldc->_server.size(); s++)
                    dc->_server[s] = ldc->_server[s];

                if( !d && lp->_is_local ) p->_is_local = 1;
                break;
            }
        }

        // and fill in servers
        for(int d=0; d<p->_dc.size(); d++){
            RP_DC *dc = p->_dc[d];
            if( dc->_is_boundary ) continue;	// already has servers
            for(int s=0; s<dc->_server.size(); s++)
                p->_server.push_back( dc->_server[s] );
        }
    }
}

static bool
server_is_compat_here(const vector<RP_Server*> *servers, const RP_Server *s, bool tryrack){

    // is it already on this slot?
    // is it in the same rack

    for(int i=0; i<servers->size(); i++){
        RP_Server *chk = servers->at(i);

        if( s->id == chk->id ) return 0;
        if( tryrack && s->rack == chk->rack ) return 0;
    }

    return 1;
}

static int
add_replicas_for(vector<Partition*> *tp, int replicas, int pn, int start, int dn, bool tryrack){

    Partition *p = tp->at(pn);
    RP_DC *dc = p->_dc[dn];

    // have enough servers already?
    if( dc->_server.size() >= replicas ) return start;

    // walk forwards, looking for suitable servers
    int size = tp->size();
    for(int i=0; i<size; i++){
        int pos = (start + i + 1) % size;
        Partition *t = tp->at( pos );
        RP_DC *tdc = t->_dc[dn];
        if( ! tdc->_is_boundary ) continue;
        RP_Server *s = tdc->_server[0];
        // can we use this server?
        if( server_is_compat_here( & dc->_server, s, tryrack ) ){
            DEBUG("slot %d + %s", pn, s->id.c_str());
            dc->_server.push_back(s);
            p->_server.push_back(s);
            if( s->bestaddr.is_self() ) p->_is_local = 1;
            if( dc->_server.size() >= replicas ) return pos;
        }
    }
    return start;
}

static void
add_replicas(vector<Partition*> *tp, int replicas){

    int start = 0;

    for(int i=0; i<tp->size(); i++){
        Partition *p = tp->at(i);
        for(int d=0; d<p->_dc.size(); d++){
            RP_DC *dc = p->_dc[d];
            if( ! dc->_is_boundary ) continue;

            // first, try to be rack aware
            // if we can't, do the best we can
            // start each search where we left off
            start = add_replicas_for( tp, replicas, i, start, d, 1 );
            start = add_replicas_for( tp, replicas, i, start, d, 0 );
        }
    }
}

//################################################################
static void
repart_db_set(Database *db, const char *tag, int n, int len, uchar* data){
    char buf[16];
    snprintf(buf, sizeof(buf), "%X", n);
    string key = tag;
    key.append(":");
    key.append(buf);

    if(len)
        db->set_internal('p', key, len, data);
    else
        db->del_internal('p', key);
}

static void
repart_db_get(Database *db, const char *tag, int n, string *res){
    char buf[16];
    snprintf(buf, sizeof(buf), "%X", n);
    string key = tag;
    key.append(":");
    key.append(buf);

    db->get_internal('p', key, res);
}

static void
repart_db_set_ver(Database *db, const char *tag, int n, int64_t ver){
    repart_db_set(db, tag, n, sizeof(int64_t), (uchar*)&ver);
}

static int64_t
repart_db_get_ver(Database *db, const char *tag, int n){
    int64_t ver = 0;
    string r;
    repart_db_get(db, tag, n, &r);
    if( r.size() == sizeof(ver) )
        memcpy(&ver, r.data(), sizeof(ver) );
    return ver;
}

void
Ring::repartition_done(int n, int64_t ver){
    repart_db_set_ver(_be, "ver", n, ver);
    repart_db_set(_be, "nver",  n, 0, 0);
    repart_db_set(_be, "check", n, 0, 0);
}

void
Ring::repartition_clean(int n){
    // clear out state
    repart_db_set(_be, "ver",   n, 0, 0);
    repart_db_set(_be, "nver",  n, 0, 0);
    repart_db_set(_be, "check", n, 0, 0);
    // partition vars...
}

void
Ring::repartition_init(const vector<Partition*> *oldp, const vector<Partition*> *newp, int64_t oldv, int64_t newv){

    int nsize = newp ? newp->size() : 0;
    int osize = oldp ? oldp->size() : 0;

    if( newp && osize == nsize ){
        // compare partitions, mark unchanged parts
        // so we don't spend time analyzing them
        for(int i=0; i<nsize; i++){
            Partition *p = newp->at(i);
            if( newp->at(i)->_is_local == oldp->at(i)->_is_local ){
                if( p->_stablever == oldv ){
                    // partition does not need to be changed. mark as good
                    repartition_done(i, newv);
                    p->_stablever = newv;
                }else{
                    // force repartitioner to do over
                    repartition_clean(i);
                }
            }
        }
    }else{
        // remove data for all old parts
        //DEBUG("clean old");
        for(int i=0; i<osize; i++){
            repartition_clean( i );
        }
    }
}

bool
Ring::repartitioner_shuffle(int *idx, int64_t *ver){
    Partition *p = 0;

    //DEBUG("repart %s %d %lld %p", _be->_name.c_str(), *idx, *ver, _part);
    if( _part ){
        //DEBUG("idx %d of %d", *idx, _part->size());
        if( *idx < _part->size() )
            p = _part->at(*idx);
    }
    bool done = 0;

    if( p ){
        if( p->_stablever == _version ) done = 1;
    }else{
        if( _stablever == _version )    done = 1;
    }

    if( !done && !*ver ){
        // load from disk
        int64_t dv = repart_db_get_ver(_be, "ver",   *idx);
        int64_t pv = repart_db_get_ver(_be, "nver",  *idx);
        int64_t cv = repart_db_get_ver(_be, "check", *idx);

        if( dv == _version ){
            // this partition is up to date
            done = 1;
        }else if( pv == _version ){
            // resume where we left off
            *ver = cv;
        }
        // else start repartitioning from 0
    }

    if( !done ){
        //DEBUG("part %s %d %lld", _be->_name.c_str(), *idx, *ver);
        done = _be->_merk->repartition(p->_shard, ver);
    }

    if( !done ){
        // save checkpoint
        repart_db_set_ver(_be, "nver",  *idx, _version);
        repart_db_set_ver(_be, "check", *idx, *ver);
    }

    if( done ){
        // this partition is now up to date
        if( p && p->_stablever != _version ){
            p->_stablever = _version;
            repartition_done(*idx, _version);
        }
        (*idx)++;
        *ver = 0;
        if( !_part || *idx >= _part->size() ){
            // finished repartitioning
            *idx = 0;
            DEBUG("stable %s %lld", _be->_name.c_str(), _version);
            return 1;
        }
    }

    return 0;
}

bool
Ring::repartitioner_expand(int obits, int nbits, int *idx, int64_t *ver){
    return repartitioner_shuffle(idx, ver);
}

bool
Ring::repartitioner_contract(int obits, int nbits, int *idx, int64_t *ver){

    int size  = 1 << obits;
    int shard = *idx << (32 - obits);
    int nidx  = *idx >> (obits - nbits);
    Partition *p = _part ? _part->at( nidx ) : 0;
    if( p && p->_shard != p->_shard ) p = 0;

    bool done = 0;

    if( p && p->_stablever == _version ) done = 1;

    // there is no place to store checkpoints on the disappearing parts
    if( p && !done && !*ver ){
        // load from disk
        int64_t dv = repart_db_get_ver(_be, "ver",   nidx);
        int64_t pv = repart_db_get_ver(_be, "nver",  nidx);
        int64_t cv = repart_db_get_ver(_be, "check", nidx);

        if( dv == _version ){
            // this partition is up to date
            done = 1;
        }else if( pv == _version ){
            // resume where we left off
            *ver = cv;
        }
        // else start repartitioning from 0
    }

    if( !done )
        done = _be->_merk->repartition(shard, ver);

    if( p && !done ){
        // save checkpoint
        repart_db_set_ver(_be, "nver",  nidx, _version);
        repart_db_set_ver(_be, "check", nidx, *ver);
    }

    if( done ){
        // this partition is now up to date
        if( p && p->_stablever != _version ){
            p->_stablever = _version;
            repartition_done(nidx, _version);
        }
        (*idx)++;
        *ver = 0;
        if( *idx >= size ){
            // finished repartitioning
            *idx = 0;
            return 1;
        }
    }

    return 0;
}


void
Ring::repartitioner(void){
    bool allgood = 0;

    while(1){
        _relock2.lock();
        _relock1.lock();
        _relock2.unlock();

        int idx = 0;
        int64_t ver = 0;
        allgood = 0;

        while(1){
            if( _restop ) break;	// a reconfigure is pending
            if( runmode.is_stopping() ) break;

            int obits, nbits=_part ? _ringbits : 0;
            if( _stablever == _version ){
                obits = nbits;
            }else{
                obits = repart_db_get_ver(_be, "bits", 0);
            }

            //DEBUG("%s o %d n %d %d/%lld idx %p", _be->_name.c_str(), obits, nbits, idx, ver, &idx);

            if( obits == nbits )
                allgood = repartitioner_shuffle(&idx, &ver);

            if( obits < nbits )
                allgood = repartitioner_expand(obits, nbits, &idx, &ver);

            if( obits > nbits )
                allgood = repartitioner_contract(obits, nbits, &idx, &ver);

            //DEBUG("%s o %d n %d %d/%lld ag %d", _be->_name.c_str(), obits, nbits, idx, ver, allgood);
            if( allgood ){
                if( _stablever != _version ){
                    repart_db_set_ver(_be, "bits", 0, nbits );
                    _stablever = _version;
                    VERBOSE("database %s partitions are now stable", _be->_name.c_str());
                }
                break;
            }
        }
        _relock1.unlock();

        if( runmode.is_stopping() ) return;

        // we are all good+stable
        if( allgood ) sleep(30);
    }
}

//################################################################

void
Ring::shutdown(void){

    _relock2.lock();
    _relock1.lock();
    _relock2.unlock();

    return;
    // NB: _relock1 is held
}

// reconfigure
void
Ring::maybe_reconfig(void){
    bool changed = 0;
    ACPY2MapDatum gconf;
    ACPY2RingConf rcf;

    // did conf change?
    gconf.set_key( _be->_name );
    store_get( "_conf", &gconf );
    if( gconf.version() <= _version ) return;	// no changes
    // there are often several changes made in quick succession, wait a bit
    if( _part && gconf.version() > hr_usec() - 120*1000000 ) return;

    // parse + validate conf
    rcf.ParsePartialFromString( gconf.value() );
    if( ! rcf.IsInitialized() || rcf.version() != CURRENT_VERSION ){
        PROBLEM("invalid ring conf");
        return;
    }

    // build tmp ring
    int bits = rcf.ringbits();
    if( bits > 16 ) bits = 16;	// because more is silly (and slow)
    int slots = 1 << bits;
    int replicas = rcf.replicas();
    if( replicas < 0 ) replicas = 0;
    if( !replicas && !_replicas ) return;	// nothing to do

    DEBUG("bits %d, slots %d, replicas %d", bits, slots, replicas);

    // tell repartitioner to wind down
    _relock2.lock();
    _restop = 1;

    vector<Partition*> *tpart = 0;

    if( replicas ){
        tpart = new vector<Partition*>;
        tpart->resize( slots );
        for(int i=0; i<slots; i++){
            Partition *p  = new Partition(i, bits);
            tpart->at(i)  = p;
            p->_stablever = repart_db_get_ver(_be, "ver", i);
        }
        for(int i=0; i<rcf.part_size(); i++){
            ACPY2RingPartConf *pcf = rcf.mutable_part(i);
            for(int j=0; j<pcf->shard_size(); j++){
                part_insert( tpart, bits, pcf->server(), pcf->datacenter(), pcf->rack(), pcf->shard(j) );
            }
        }

        add_replicas( tpart, replicas );
        interpolate( tpart );
    }

    // wait for repartitioner
    _relock1.lock();
    _relock2.unlock();
    _restop = 0;

    repartition_init( _part, tpart, _version, gconf.version() );

    // wlock + swap
    _lock.w_lock();
    vector<Partition*> *oldp = _part;
    _part = tpart;
    _replicas = replicas;
    _ringbits = bits;
    _version  = gconf.version();

    _lock.w_unlock();

    if( oldp ) delete oldp;

    // restart repartitioner
    _relock1.unlock();

    VERBOSE("database %s reconfigured", _be->_name.c_str());

}

//################################################################

// export various info

bool
Ring::report_txt(std::ostringstream& dst) const {

    if( !_part ) return 0;

    _lock.r_lock();
    dst << "# " << _be->_name << "\n";

    for(int i=0; i<_part->size(); i++){
        Partition *p = _part->at(i);

        dst << p->_shard << "\t" << (p->_is_local ? "+" : ".");
        dst << (p->_dc[0]->_is_boundary ? "-" : ".");

        for(int s=0; s<p->_server.size(); s++){
            dst << " " << p->_server[s]->id;
        }
        dst << "\n";
    }

    _lock.r_unlock();

    return 1;
}

int
report_ring_txt(NTD *ntd){

    std::ostringstream out;

    for(int i=0; i<allring.size(); i++){
        allring[i]->report_txt( out );
    }

    int sz = out.str().length();
    ntd->out_resize( sz + 1 );
    memcpy(ntd->gpbuf_out, out.str().c_str(), sz);

    return sz;
}

extern "C" const char *inet_ntoa(uint32_t);

void
RP_Server::json(std::ostringstream& dst) const {

    dst << "{\"id\": "   << "\"" << id << "\", "
        << "\"up\": "    << (is_up ? "1" : "0")
        << "\"port\": "  << bestaddr.port << ", "
        << "\"addr\": "  << "\"" << inet_ntoa(bestaddr.ipv4) << "\"}";
}

bool
Ring::report_json(std::ostringstream& dst) const {

    if( !_part ) return 0;

    // is_boundary?
    // all DC? this DC?

    _lock.r_lock();
    dst << "{ \"database\": " << "\"" << _be->_name << "\", ";
    dst << "\"version\": "    << _version   << ", ";
    dst << "\"stablever\": "  << _stablever << ", ";
    dst << "\"replicas\": "   << _replicas  << ", ";
    dst << "\"ringbits\": "   << _ringbits  << ", ";
    dst << "\"ring\": [\n";

    for(int i=0; i<_part->size(); i++){
        Partition *p = _part->at(i);
        if( i ) dst << ",\n";

        dst << "  {\"shard\": " << p->_shard << ", \"server\": [";

        for(int s=0; s<p->_server.size(); s++){
            if( s ) dst << ", ";
            // QQQ - serverid or more server info?
            dst << "\"" << p->_server[s]->id << "\"";
            // p->_server[s]->json(dst);
        }
        dst << "] }";
    }

    dst << "\n ]}";
    _lock.r_unlock();

    return 1;
}

int
report_ring_json(NTD *ntd){
    int n = 0;

    std::ostringstream out;

    out << "[";
    for(int i=0; i<allring.size(); i++){
        if( n ) out << ",\n";
        if( allring[i]->report_json( out ) ) n++;
    }
    out << "]\n";

    int sz = out.str().length();
    ntd->out_resize( sz + 1 );
    memcpy(ntd->gpbuf_out, out.str().c_str(), sz);

    return sz;
}

void
Ring::get_conf(ACPY2RingConfReply *res) const {

    if( !_part ) return;

    _lock.r_lock();
    res->set_version( _version );

    for(int i=0; i<_part->size(); i++){
        Partition *p = _part->at(i);
        RP_DC *dc = p->_dc[0];

        if( ! dc->_is_boundary ) continue;

        ACPY2RingPart *r = res->add_part();
        r->set_shard( p->_shard );
        int n = dc->_server.size();

        for(int s=0; s<n; s++){
            r->add_server( dc->_server[s]->id );
        }
    }

    _lock.r_unlock();
}

int
y2_ringcf(NTD *ntd){
    protocol_header *phi = (protocol_header*) ntd->gpbuf_in;
    ACPY2RingConfReq   req;
    ACPY2RingConfReply res;

    if( !(phi->flags & PHFLAG_WANTREPLY) ) return 0;

    // parse request
    req.ParsePartialFromArray( ntd->in_data(), phi->data_length );
    DEBUG("req l=%d, %s", phi->data_length, req.ShortDebugString().c_str());

    if( ! req.IsInitialized() ){
        DEBUG("invalid request. missing required fields");
        return 0;
    }

    for(int i=0; i<allring.size(); i++){
        if( req.map() == allring[i]->name() ) allring[i]->get_conf( &res );
    }

    DEBUG("res %s", res.ShortDebugString().c_str());

    // serialize + reply
    return serialize_reply(ntd, &res, 0);
}


//################################################################

// user maint commands

static bool
get_ringcf(const char *db, ACPY2RingConf *rcf, string *err){
    ACPY2MapDatum gconf;

    gconf.set_key( db );
    if( !store_get("_conf", &gconf) ){
        err->assign("cannot get conf");
        return 0;
    }

    // parse + validate conf
    rcf->ParsePartialFromString( gconf.value() );
    if( ! rcf->IsInitialized() || rcf->version() != CURRENT_VERSION ){
        PROBLEM("invalid ring conf");
        err->assign("invalid ring conf");
        return 0;
    }

    return 1;
}

static bool
set_ringcf(const char *db, const ACPY2RingConf *rcf, string *err){
    ACPY2MapDatum gconf;

    gconf.set_map( "_conf" );
    gconf.set_key( db );
    gconf.set_version( hr_usec() );
    gconf.set_shard( 0 );
    rcf->SerializeToString( gconf.mutable_value() );

    store_put( "_conf", &gconf, 0, 0 );
    return 1;
}

static bool
init_ringcf(const char *db, ACPY2RingConf *rcf, string *err){
    Ring *r = find_ring( db );

    if( !r ){
        err->assign("cannot find database");
        return 0;
    }
    if( ! r->conf_replicas() ){
        err->assign("database not configured for replicas");
        return 0;
    }
    rcf->set_version(  CURRENT_VERSION );
    rcf->set_replicas( r->conf_replicas() );
    int b = r->conf_ringbits();
    if( b < 4 ) b = 4;
    rcf->set_ringbits( b );

    return 1;
}

bool
ring_setbits(const char *db, int bits, string *err){
    ACPY2RingConf rcf;

    if( bits > 16 || bits < 1 ){
        err->assign("invalid number of bits");
        return 0;
    }

    if( !get_ringcf(db, &rcf, err) && !init_ringcf(db, &rcf, err) ) return 0;

    rcf.set_ringbits( bits );
    return set_ringcf( db, &rcf, err );
}

bool
ring_setreplicas(const char *db, int reps, string *err){
    ACPY2RingConf rcf;

    if( reps < 0 ){
        err->assign("invalid number of replicas");
        return 0;
    }

    if( !get_ringcf(db, &rcf, err) && !init_ringcf(db, &rcf, err) ) return 0;

    rcf.set_replicas( reps );
    return set_ringcf( db, &rcf, err );
}


bool
ring_addnode(const char *db, const char *server, uint shard, string *err){
    ACPY2RingConf rcf;

    if( !get_ringcf(db, &rcf, err) && !init_ringcf(db, &rcf, err) ) return 0;

    RP_Server *s = find_server( server );
    if( !s ){
        err->assign( "cannot find server" );
        return 0;
    }
    int nshard = 0;
    ACPY2RingPartConf *rec = 0;

    // add shard to existing record?
    for(int i=0; i<rcf.part_size(); i++){
        ACPY2RingPartConf *r = rcf.mutable_part(i);
        if( r->server() == server ){
            rec = r;
        }

        nshard += r->shard_size();
    }

    if( !rec ){
        rec = rcf.add_part();
        rec->set_server( server );
        rec->set_datacenter( s->datacenter );
        rec->set_rack( s->rack );
    }

    rec->add_shard( shard );
    nshard ++;

    // do we need more bits?
    if( (1 << rcf.ringbits()) <= nshard * 4 ){
        rcf.set_ringbits( ceil(log(nshard * 4.0) / log(2.0)) );
    }

    VERBOSE("add to ring %s: %d bits, %d shards", db, rcf.ringbits(), nshard);

    return set_ringcf( db, &rcf, err );
}

bool
ring_rmnode(const char *db, const char *server, string *err){
    ACPY2RingConf rcf;

    if( ! get_ringcf(db, &rcf, err) ) return 0;


    // delete server by moving to end, then deleting
    int keep = 0;
    int nshard = 0;

    for(int i=0; i<rcf.part_size(); i++){
        ACPY2RingPartConf *rec = rcf.mutable_part(i);

        if( rec->server() == server ){
            // delete elem
        }else{
            if( keep < i ){
                rcf.mutable_part()->SwapElements(i, keep);
            }
            keep ++;
            nshard += rec->shard_size();
        }
    }
    rcf.mutable_part()->DeleteSubrange(keep, rcf.part_size() - keep);

    VERBOSE("remove from ring %s: %d bits, %d shards", db, rcf.ringbits(), nshard);

    return set_ringcf( db, &rcf, err );
}

bool
ring_rebalance(const char *db){
    // RSN
    return 0;
}

