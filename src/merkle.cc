/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-19 12:31 (EST)
  Function: merkle trees

*/

#define CURRENT_SUBSYSTEM	'M'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "thread.h"
#include "crypto.h"
#include "network.h"
#include "hrtime.h"
#include "merkle.h"
#include "expire.h"
#include "database.h"
#include "partition.h"
#include "runmode.h"
#include "stats.h"
#include "dbwire.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "y2db_check.pb.h"
#include "y2db_getset.pb.h"

#include <algorithm>

#define F16		0xFFFFFFFFFFFFFFFFLL
#define LEAFCACHE

void hex_encode(const unsigned char *in, int inlen, char *out, int outlen);

bool merkle_safe_to_stop = 0;

// one maintenance thread per tree
static void*
merkle_flusher(void *x){
    Merkle *m = (Merkle*)x;

    sleep(10);

    while(1){
        m->flush();
        sleep(5);
    }
}

//################################################################


static inline uint64_t
merkle_number(int64_t ver){

    // <48bit ver>
    return (ver >> 16);
}

static inline uint64_t
merkle_level_version(int l, uint64_t ver){
    // merkle number masked for specified level
    uint64_t mask = F16 << ((MERKLE_HEIGHT - l + 4)<<2);
    return ver & mask;
}

static inline void
merkle_key(int l, int treeid, uint64_t ver, string *k){
    char buf[32];

    // expire expects to see "10/tree/ver..."
    // <level>/<treeid>/<ver&mask> => 10/1234/000123456789
    snprintf(buf, sizeof(buf), "%02X/%04X/%012llX", l, treeid, merkle_number(merkle_level_version(l, ver)));
    k->assign(buf);
}

static inline int
merkle_lock_number(int l, int treeid, uint64_t ver){
    return (merkle_level_version(l, ver) | treeid) % MERKLE_NLOCK;
}

static inline int
merkle_slot(int l, int64_t ver){
    return (merkle_number(ver) >> ((MERKLE_HEIGHT - l) << 2)) & 0xF;
}

//################################################################

Merkle::Merkle(Database* be){
    _be  = be;
    _mnm = new MerkleChangeQ;

    start_thread( merkle_flusher, (void*)this, 0 );
    // RSN - configurable - run more threads
}

//################################################################

static bool
leafrec_compare(const ACPY2MerkleLeafRec &a, const ACPY2MerkleLeafRec &b){

    if( a.version() < b.version() ) return 1;
    if( a.version() > b.version() ) return 0;
    if( a.key()     < b.key()     ) return 1;
    return 0;
}

static bool
leafrec_equal(const ACPY2MerkleLeafRec &a, const ACPY2MerkleLeafRec &b){

    if( a.version() != b.version() ) return 0;
    if( a.key()     != b.key()     ) return 0;
    return 1;
}



// add entry to merkle tree
// add/update leaf entry now, queue higher level updates
void
Merkle::add(const string& key, int treeid, int shard, int64_t ver){
    string mkey;
    merkle_key(MERKLE_HEIGHT, treeid, ver, &mkey);
    int ln = merkle_lock_number(MERKLE_HEIGHT, treeid, ver);

    ACPY2MerkleLeaf l;

    DEBUG("leaf %d %016llX => %s %d", treeid, ver, mkey.c_str(), ln);

    // get leaf node, append, write
    _nlock[ln].lock();

#ifdef LEAFCACHE
    string *val = leafcache_get(ln, mkey);
    l.ParsePartialFromString( *val );
#else
    string val;
    _be->_get('m', mkey, &val);
    l.ParsePartialFromString(val);
#endif

    // check not already in
    int i;
    bool found=0;
    for(i=0; i<l.rec_size(); i++){
        ACPY2MerkleLeafRec *rec = l.mutable_rec(i);
        if( rec->version() == ver && rec->key() == key ){
            found = 1;
            break;
        }
    }

    if( !found ){
        ACPY2MerkleLeafRec *rec = l.add_rec();
        rec->set_key(     key );
        rec->set_version( ver );
        rec->set_shard(   shard );
        // keep them in sorted order
        if( l.rec_size() > 1 ){
            google::protobuf::RepeatedPtrField<ACPY2MerkleLeafRec> *lc = l.mutable_rec();
            std::sort( lc->begin(), lc->end(), leafrec_compare );
        }
    }

#ifdef LEAFCACHE
    l.SerializeToString( val );
    leafcache_set(ln, treeid, ver, l.rec_size() );
#else
    l.SerializeToString( &val );
    _be->_put('m', mkey, val);
    // queue higher nodes
    q_leafnext( treeid, ver, l.rec_size(), &val );
#endif


    _nlock[ln].unlock();

}

// remove entry from merkle tree
// update leaf entry now, queue higher level updates
void
Merkle::del(const string& key, int treeid, int shard, int64_t ver){
    string mkey;
    merkle_key(MERKLE_HEIGHT, treeid, ver, &mkey);
    int ln = merkle_lock_number(MERKLE_HEIGHT, treeid, ver);

    string *val;
    ACPY2MerkleLeaf l;
    int keep = 0;

    DEBUG("leaf %016llX => %s", ver, mkey.c_str());

    // get leaf node, del, write
    _nlock[ln].lock();

#ifdef LEAFCACHE
    val = leafcache_get(ln, mkey);

#else
    string sval;
    val = &sval;

    _be->_get('m', mkey, val);
#endif

    l.ParsePartialFromString(*val);

    // DEBUG("l=%d, %s", val.size(), l.ShortDebugString().c_str());

    // move deleted elems to front
    for(int i=0; i<l.rec_size(); i++){
        ACPY2MerkleLeafRec *rec = l.mutable_rec(i);

        if( rec->version() == ver && rec->key() == key ){
            // delete elem
        }else{
            if( keep < i ){
                l.mutable_rec()->SwapElements(i, keep);
            }
            ++keep;
        }
    }
    l.mutable_rec()->DeleteSubrange(keep, l.rec_size() - keep);

    // DEBUG("l=%d, %s", val.size(), l.ShortDebugString().c_str());

    if( l.rec_size() ){
        l.SerializeToString( val );
    }else{
        val->clear();
    }

#ifdef LEAFCACHE
    leafcache_set(ln, treeid, ver, l.rec_size() );
#else
    if( ! val->empty() ){
        _be->_put('m', mkey, *val);
    }else{
        _be->_del('m', mkey);
    }
    // queue higher nodes
    q_leafnext( treeid, ver, l.rec_size(), val );
#endif


    _nlock[ln].unlock();
}

// same as del, with checks + cleaning
void
Merkle::fix(int treeid, int64_t ver){

    string mkey;
    merkle_key(MERKLE_HEIGHT, treeid, ver, &mkey);
    int ln = merkle_lock_number(MERKLE_HEIGHT, treeid, ver);

    string *val;
    ACPY2MerkleLeaf l;

    DEBUG("leaf %016llX => %s", ver, mkey.c_str());

    // get leaf node, del, write
    _nlock[ln].lock();

#ifdef LEAFCACHE
    val = leafcache_get(ln, mkey);

#else
    string sval;
    val = &sval;

    _be->_get('m', mkey, val);
#endif

    l.ParsePartialFromString(*val);
    int oldsize = l.rec_size();

    if( oldsize > 1 ){
        // sort
        google::protobuf::RepeatedPtrField<ACPY2MerkleLeafRec> *lc = l.mutable_rec();
        std::sort( lc->begin(), lc->end(), leafrec_compare );

        // dupes?
        int keep = 1;
        for(int i=1; i<l.rec_size(); i++){
            ACPY2MerkleLeafRec *prev = l.mutable_rec(i-1);
            ACPY2MerkleLeafRec *rec  = l.mutable_rec(i);

            if( rec->version() == prev->version() && rec->key() == prev->key() ){
                // delete elem
            }else{
                if( keep < i ){
                    l.mutable_rec()->SwapElements(i, keep);
                }
                ++keep;
            }
        }
        l.mutable_rec()->DeleteSubrange(keep, l.rec_size() - keep);
    }

    int newsize = l.rec_size();

    if( l.rec_size() ){
        l.SerializeToString( val );
    }else{
        val->clear();
    }

#ifdef LEAFCACHE
    leafcache_set(ln, treeid, ver, l.rec_size(), 1 );
#else
    if( ! val->empty() ){
        _be->_put('m', mkey, *val);
    }else{
        _be->_del('m', mkey);
    }
    // queue higher nodes
    q_leafnext( treeid, ver, l.rec_size(), val, 1 );
#endif

    _nlock[ln].unlock();

    DEBUG(" changed %d -> %d", oldsize, newsize);
}

string *
Merkle::leafcache_get(int ln, const string& mkey){

    MerkleLeafCache *c = & _cache[ln];

    // do we already have it?
    if( c->_mkey == mkey )
        return & c->_data;

    // is there something else here? flush it
    if( ! c->_mkey.empty() )
        leafcache_flush(ln);

    // fetch
    c->_mkey  = mkey;
    c->_fixme = 0;
    _be->_get('m', mkey, & c->_data);

    merkle_safe_to_stop = 0;
    return & c->_data;
}

void
Merkle::leafcache_set(int ln, int treeid, int64_t ver, int count, bool fixme){

    MerkleLeafCache *c = & _cache[ln];

    c->_treeid = treeid;
    c->_count  = count;
    c->_ver    = ver;

    if( fixme ) c->_fixme = 1;
}

void
Merkle::leafcache_flush(int ln){

    MerkleLeafCache *c = & _cache[ln];

    if( c->_mkey.empty() ) return;

    if( c->_data.empty() )
        _be->_del('m', c->_mkey);
    else
        _be->_put('m', c->_mkey, c->_data);

    // add leaf
    q_leafnext( c->_treeid, c->_ver, c->_count, & c->_data, c->_fixme );

    c->_fixme = 0;
    c->_data.clear();
    c->_mkey.clear();

}

bool
Merkle::leafcache_maybe_flush(int ln){
    // if we can get the lock, flush it

    if( runmode.is_stopping() )
        _nlock[ln].lock();
    else
        if( _nlock[ln].trylock() ) return 0;

    leafcache_flush(ln);
    _nlock[ln].unlock();
    return 1;
}


void
Merkle::q_leafnext(int treeid, uint64_t ver, int keycount, const string *rec, bool fix){

    merkle_safe_to_stop = 0;

    MerkleChange * no = new MerkleChange;

    if( !keycount && rec->size() || keycount && !rec->size() )
        PROBLEM("leafnext confusion count %d, size %d", keycount, rec->size());

    if( rec->size() )
        md5_bin( (uchar*) rec->data(), rec->size(), (char*) no->_hash, MERKLE_HASHLEN );
    else
        memset(no->_hash, 0, MERKLE_HASHLEN);

    no->_level    = MERKLE_HEIGHT;
    no->_ver	  = merkle_level_version(MERKLE_HEIGHT, ver);
    no->_treeid   = treeid;
    no->_children = 1;
    no->_keycount = keycount;
    no->_fixme    = fix;

    char buf[64];
    hex_encode( no->_hash, MERKLE_HASHLEN, buf, sizeof(buf));
    DEBUG("qln %d_%012llX %d, %d [%s]", no->_level, no->_ver, keycount, rec->size(), buf);


    _lock.lock();
    _mnm->push_back(no);
    _lock.unlock();

}

static bool
sort_node_compare(const MerkleNode &a, const MerkleNode &b){
    if( a.slot < b.slot ) return 1;
    return 0;
}

static bool
clean_fix_merkle_node(string *val){

    MerkleNode *mn = (MerkleNode*) val->data();
    int nn = val->size() / sizeof(MerkleNode);

    bool changed  = 0;
    bool unsorted = 0;
    int i, j;

    for(i=0; i<nn; i++){
        if( !mn[i].children || !mn[i].keycount ){
            // remove empty
            memmove( mn+i, mn+i+1, sizeof(MerkleNode) );
            val->resize( (nn-1) * sizeof(MerkleNode) );
            nn --;
            i --;
            changed = 1;
            continue;
        }

        for(j=i+1; j<nn; j++){
            if( mn[i].slot > mn[j].slot ) unsorted = 1;
            if( mn[i].slot == mn[j].slot ){
                // remove dupe
                memmove( mn+j, mn+j+1, sizeof(MerkleNode) );
                val->resize( (nn-1) * sizeof(MerkleNode) );
                nn --;
                changed = 1;
            }
        }
    }
    if( unsorted ){
        std::sort( mn, mn + nn, sort_node_compare );
        changed = 1;
    }

    return changed;
}

void
Merkle::fix(int treeid, int level, int64_t ver){
    // get node, check, and fix

    treeid &= 0xFFFF;

    if( level == MERKLE_HEIGHT ){
        fix( treeid, ver );
        return ;
    }

    return ;

    // climb down and find a leaf, fix it
    string mkey, val;

    while( level != MERKLE_HEIGHT ){
        merkle_key(level, treeid, ver, &mkey);
        int ln = merkle_lock_number(level, treeid, ver);
        _nlock[ln].lock();
        _be->_get('m', mkey, &val);
        _nlock[ln].unlock();

        // pick next node to fetch

        if( val.empty() ) return;

        MerkleNode *mn = (MerkleNode*) val.data();
        int nn = val.size() / sizeof(MerkleNode);
        int i  = random_n(nn);

        uint64_t mask = F16 << ((MERKLE_HEIGHT - level + 4) << 2);
        uint64_t nver = ver & mask;
        int slshift = (MERKLE_HEIGHT - level + 3) << 2;
        ver = nver | ((int64_t)mn[i].slot << slshift);
        level ++;
    }

    fix( treeid, ver );

}

// update on disk data with new info
static bool
update_node(MerkleChange *no, string *val){

    bool changed = 0;

    // which slot?
    int slot = merkle_slot(no->_level, no->_ver);

    MerkleNode *mn = (MerkleNode*) val->data();
    int nn = val->size() / sizeof(MerkleNode);
    int i=0, j;

    if( nn > 16 ) no->_fixme = 1;

    if( !no->_fixme ){
        // search
        for(i=0; i<nn; i++){
            if( mn[i].slot == slot ) break;
        }

        // quick check for dupe
        for(j=i+1; j<nn; j++){
            if( mn[j].slot == slot ) no->_fixme = 1;
        }
    }

    if( no->_fixme ){
        // check for dupes, unsorted
        changed = clean_fix_merkle_node( val );

        nn = val->size() / sizeof(MerkleNode);

        // re-search
        for(i=0; i<nn; i++){
            if( mn[i].slot == slot ) break;
        }
    }

    if( no->_children ){
        bool resort = 0;
        // not found? append
        if( i == nn ){
            val->resize( (i+1) * sizeof(MerkleNode) );
            mn = (MerkleNode*) val->data();
            nn ++;
            changed = 1;
            resort  = 1;
        }else{
            if( memcmp(no->_hash, mn[i].hash, MERKLE_HASHLEN) ) changed = 1;
            if( no->_keycount != mn[i].keycount ) changed = 1;
            if( no->_children != mn[i].children ) changed = 1;
        }

        // update
        mn[i].slot     = slot;
        mn[i].children = no->_children;
        mn[i].keycount = no->_keycount;
        memcpy(mn[i].hash, no->_hash, MERKLE_HASHLEN);

        if( resort )
            std::sort( mn, mn + nn, sort_node_compare );

    }else{
        // remove empty entry
        if( i != nn ){
            if( i != nn - 1 )
                memmove( mn+i, mn+i+1, sizeof(MerkleNode) );
            val->resize( (nn-1) * sizeof(MerkleNode) );
            changed = 1;
        }
    }

    if( changed ) DEBUG("  changed node %d_%016llX slot %d ch %d kc %d", no->_level, no->_ver, slot, no->_children, no->_keycount);
    if( no->_fixme && changed ) VERBOSE("  fixed merkle node %d_%016llX", no->_level, no->_ver);

    return changed;
}

// aggregate values for this block of info
static void
aggr_nodes(int level, int treeid, uint64_t ver, const string *val, MerkleChange *res){

    res->_children = 0;
    res->_keycount = 0;
    res->_level    = level;
    res->_treeid   = treeid;
    res->_ver      = merkle_level_version(level, ver);

    memset(res->_hash, 0, MERKLE_HASHLEN);

    MerkleNode *mn = (MerkleNode*) val->data();
    int nn = val->size() / sizeof(MerkleNode);

    for(int i=0; i<nn; i++){
        res->_children ++;
        res->_keycount += mn[i].keycount;

        // hash is xor of child hashes
        for(int j=0; j<MERKLE_HASHLEN; j++){
            res->_hash[j] ^= mn[i].hash[j];
        }
    }

    char buf[64];
    hex_encode( res->_hash, MERKLE_HASHLEN, buf, sizeof(buf));
    DEBUG("\t[%s]", buf );
}


// process one clump of notes
// add result back to list
// list should already be properly sorted
bool
Merkle::apply_updates(MerkleChangeQ *l){

    if( l->empty() ) return 0;
    MerkleChange *no = l->front();
    l->pop_front();

    int level = no->_level - 1;
    if( level < MERKLE_HEIGHT - MERKLE_BUILD ){
        delete no;
        return 0;
    }

    string mkey;
    merkle_key(level, no->_treeid, no->_ver, &mkey);
    int ln = merkle_lock_number(level, no->_treeid, no->_ver);
    DEBUG("node %s", mkey.c_str());

    string val;
    // get
    _nlock[ln].lock();
    _be->_get('m', mkey, &val);
    bool changed = update_node(no, &val);
    bool fixme   = no->_fixme;

    int64_t aver = merkle_level_version(level, no->_ver);

    // anything else to add?
    while( !l->empty() ){
        MerkleChange *nx = l->front();
        // same batch?
        if( no->_level != nx->_level ) break;
        if( no->_treeid != nx->_treeid ) break;
        if( aver != merkle_level_version(level, nx->_ver) ) break;

        l->pop_front();

        // update
        DEBUG("+node %s", mkey.c_str());
        bool c = update_node(nx, &val);
        if(c) changed = 1;
        if( nx->_fixme ) fixme = 1;
        delete nx;
    }

    if( changed ){
        // insert
        _be->_put('m', mkey, val);
    }
    _nlock[ln].unlock();

    if( !changed && !fixme ){
        delete no;
        return 0;
    }

    aggr_nodes(level, no->_treeid, no->_ver, &val, no);
    no->_fixme = fixme;
    // as long as list started sorted, it will still be sorted after appending
    l->push_back(no);

    return 1;
}

static bool
sort_compare_note(const MerkleChange *a, const MerkleChange *b){
    // sort by level descending, mkno ascending
    if( a->_level > b->_level ) return 1;
    if( a->_level < b->_level ) return 0;
    if( a->_ver   < b->_ver   ) return 1;
    return 0;
}


void
Merkle::flush(void){

    // flush leaf cache
    bool leavesflushed = 1;

#ifdef LEAFCACHE
    for(int i=0; i<MERKLE_NLOCK; i++){
        bool r = leafcache_maybe_flush(i);
        if( !r ) leavesflushed = 0;
    }
#endif

    _lock.lock();
    MerkleChangeQ *mnm = _mnm;
    if( mnm->empty() ){
        if( leavesflushed ) merkle_safe_to_stop = 1;
        _lock.unlock();
        return;
    }
    // swap, so other threads don't block
    _mnm = new MerkleChangeQ;
    _lock.unlock();

    // sort + process
    std::stable_sort( mnm->begin(), mnm->end(), sort_compare_note );

    while( !mnm->empty() ){
        apply_updates( mnm );
    }

    delete mnm;

}

//################################################################

static inline int
_get_leaf(const string& map, int level, int treeid, int64_t ver, const string& val, ACPY2CheckReply *res){
    ACPY2MerkleLeaf l;
    l.ParsePartialFromString(val);

    // copy records from leaf-node into result
    for(int i=0; i<l.rec_size(); i++){
        ACPY2MerkleLeafRec *rec = l.mutable_rec(i);
        ACPY2CheckValue    *rv  = res->add_check();

        rv->set_treeid( treeid );
        rv->set_shard( rec->shard() );
        rv->set_level( MERKLE_HEIGHT + 1 );
        rv->set_version( rec->version() );
        rv->set_map( map );
        rv->set_keycount( 1 );
        rv->set_key( rec->key() );
        rv->set_isvalid( 1 );		// leaf-nodes are always good

        //DEBUG("+L %02X_%016llX", level, rec->version() );
    }

    return l.rec_size();
}

static inline int
_get_upper(const string& map, int level, int treeid, int64_t ver, const string& val, ACPY2CheckReply *res, bool stable){
    MerkleNode *mn = (MerkleNode*) val.data();
    int nn = val.size() / sizeof(MerkleNode);

    uint64_t mask = F16 << ((MERKLE_HEIGHT - level + 4) << 2);
    uint64_t nver = ver & mask;
    int slshift = (MERKLE_HEIGHT - level + 3) << 2;

    for(int i=0; i<nn; i++){
        ACPY2CheckValue *rv  = res->add_check();
        rv->set_treeid( treeid );
        rv->set_level( level + 1 );
        rv->set_version( nver | ((int64_t)mn[i].slot << slshift) );
        rv->set_map( map );
        rv->set_keycount( mn[i].keycount );
        rv->set_children( mn[i].children );
        rv->set_hash( (char*) mn[i].hash, MERKLE_HASHLEN );
        rv->set_isvalid( stable );

        //DEBUG("+%d %02X_%016llX->%d=%d", mn[i].slot, level+1, rv->version(), mn[i].children, mn[i].keycount);
    }

    return nn;
}

int
Merkle::get(int level, int treeid, int64_t ver, ACPY2CheckReply *res){

    treeid &= 0xFFFF;
    string mkey;
    merkle_key(level, treeid, ver, &mkey);

    string val;
    _be->_get('m', mkey, &val);
    // DEBUG("mget %s [%d]", mkey.c_str(), val.size());
    if( val.empty() ) return 0;

    if( level == MERKLE_HEIGHT ){
        return _get_leaf( _be->_name, level, treeid, ver, val, res);
    }else{
        return _get_upper(_be->_name, level, treeid, ver, val, res, _be->_ring->is_stable());
    }
}

//################################################################


bool
Merkle::compare_result(MerkleCache *cache, ACPY2CheckValue *r){
    // cache

    int level = r->level() - 1;
    int64_t nlv = merkle_level_version(level, r->version());

    // use cache?
    if( cache->level == level && cache->ver == nlv ){
        // use cache
    }else{
        string mkey;
        merkle_key(level, r->treeid(), r->version(), &mkey);
        // fetch
        _be->_get('m', mkey, &cache->data);
        cache->level  = level;
        cache->treeid = r->treeid();
        cache->ver    = nlv;
    }

    int slot = merkle_slot(r->level(), r->version());

    MerkleNode *mn = (MerkleNode*) cache->data.data();
    int nn = cache->data.size() / sizeof(MerkleNode);

    // find requested slot + compare
    for(int i=0; i<nn; i++){
        if( slot == mn[i].slot ){
            const unsigned char *rh = (unsigned char *)r->hash().data();
            int res = memcmp(rh, mn[i].hash, MERKLE_HASHLEN);
            //DEBUG("hash %02X/%04X/%012llX %02X%02X %s %02X%02X",
            //      level, r->treeid(), r->version(),
            //      mn[i].hash[0], mn[i].hash[1],
            //      (res? "!=" : "=="),
            //      rh[0], rh[1]);
            return !res;
        }
    }

    // slot not found
    // DEBUG("slot %d not found", slot);
    return 0;
}

//################################################################

class MerkDeleteLR : public LambdaRange {
public:
    Database	*be;
    Ring	*ring;
    Merkle	*merk;
    uint64_t	count;
public:
    MerkDeleteLR(Database *b, Ring *r, Merkle *m) { be = b; ring = r; merk = m; count = 0; }
    virtual bool call(const string &, const string &);
};

bool
MerkDeleteLR::call(const string &key, const string &val) {
    be->_del('m', key);
    count ++;
    return 1;
}



class MerkUpgradeLR : public LambdaRange {
public:
    Database	*be;
    Ring	*ring;
    Merkle	*merk;
    uint64_t	count;
public:
    MerkUpgradeLR(Database *b, Ring *r, Merkle *m) { be = b; ring = r; merk = m; count = 0; }
    virtual bool call(const string&, const string&);
};

bool
MerkUpgradeLR::call(const string& key, const string& val){
    // val is DBRecord
    DBRecord *dr = (DBRecord*) val.data();

    int part   = ring->partno( dr->shard );
    int treeid = ring->treeid(part);

    merk->add( key, treeid, dr->shard, dr->ver );
    DEBUG("add key %s", key.c_str());
    count ++;

    if( count % 10000 == 0 ){
        merk->flush();
        VERBOSE("upgrading merkle tree");
    }

    return 1;
}

// XXX - does not work? range seems to lose things
void
Merkle::upgrade(void){
    string start, end = "\xFF\xFF";

    VERBOSE("upgrading merkle tree");

    // delete current merkle tree
    MerkDeleteLR delf(_be, _be->_ring, _be->_merk);
    _be->_range('m', start, end, &delf);
    VERBOSE("removed %lld nodes", delf.count);

    // fetch all keys and rebuild
    VERBOSE("rebuilding merkle tree");
    MerkUpgradeLR upgf(_be, _be->_ring, _be->_merk);
    _be->_range('d', start, end, &upgf);
    runmode.shutdown();
    _be->_merk->flush();
    VERBOSE("added %lld keys", upgf.count);
    VERBOSE("upgrade complete");
}


//################################################################

#define MAXITER 10240

class MerkRepartLR : public LambdaRange {
public:
    Database	*be;
    Ring	*ring;
    Merkle	*merk;
    int		count;
    int		treeid;
    int64_t	lastver;
public:
    MerkRepartLR(Database *b, Ring *r, Merkle *m) { be = b; ring = r; merk = m; count=0; }
    virtual bool call(const string&, const string&);
};

bool
MerkRepartLR::call(const string& key, const string& val){
    // val is leaf node {key,version,shard}
    // iterate keys

    ACPY2MerkleLeaf l;
    l.ParsePartialFromString(val);

    // copy records from leaf-node into result
    for(int i=0; i<l.rec_size(); i++){
        ACPY2MerkleLeafRec *rec = l.mutable_rec(i);
        lastver = rec->version();
        count ++;

        int newpart   = ring->partno( rec->shard() );
        int newtree   = ring->treeid( newpart );
        bool newlocal = ring->is_local( newpart );

        if( !newlocal ){
            // RSN - async distrib, delete only after confirmation
            // distrib + delete

            // get the data + build a distrib request
            ACPY2DistRequest put;
            put.set_hop( 10 );	// prevent wide redistribution
            put.set_expire( lr_usec() + 10000000 );
            ACPY2MapDatum *dat = put.mutable_data();
            dat->set_map( be->_name );
            dat->set_key( rec->key() );
            dat->set_shard( rec->shard() );
            be->get( dat );

            be->distrib(treeid, &put);
            be->remove( rec->key(), rec->version() );
            count += 9;
            INCSTAT( repart_rmed );
        }else if( newtree != treeid ){
            merk->add( rec->key(), newtree, rec->shard(), rec->version() );
            merk->del( rec->key(), treeid,  rec->shard(), rec->version() );
            INCSTAT( repart_changed );
        }
    }

    if( count >= MAXITER ) return 0;
    return 1;
}

bool
Merkle::repartition(int treeid, int64_t *ver){

    // iterate 10/tree/ver - end | maxiter
    //  iterate keys
    //   part1 = new part
    //   still local?
    //     next if part0 == part1
    //     add( part1, ... )
    //     del( part0, ... )
    //   else
    //     distrib to new server

    MerkRepartLR ef(_be, _be->_ring, _be->_merk);
    ef.lastver = *ver;
    ef.treeid  = treeid;

    string start, end;
    merkle_key(MERKLE_HEIGHT, treeid, *ver, &start);
    merkle_key(MERKLE_HEIGHT, treeid+1, 0,  &end);

    bool ret = _be->_range('m', start, end, &ef);

    *ver = ef.lastver;
    return ret;
}
