/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-17 10:49 (EST)
  Function: merkle trees

*/

#ifndef __fbdb_merkle_h_
#define __fbdb_merkle_h_

#include "lock.h"

#include <vector>
#include <deque>
using std::vector;
using std::deque;

#define MERKLE_NLOCK	137	// sharded locks
#define MERKLE_HEIGHT	12	// pretend the tree is this high, but don't build it all
#define MERKLE_BUILD	12 	// build tree on the version only, not the part
#define MERKLE_HASHLEN	16	// md5 is this big


// on disk format of non-leaf nodes
struct MerkleNode {
    uint64_t	slot     : 4;
    uint64_t	children : 5;
    uint64_t	extra    : 1;	// extra bit, extra fun!
    uint64_t	keycount : 54;

    uint8_t    	hash[MERKLE_HASHLEN];
};


struct NetAddr;
class Database;
class ACPY2CheckReply;
class ACPY2CheckValue;
class ACPY2GetSet;

class Tinfo;

// changes that need to be applied
class MerkleChange {
public:
    int64_t	_keycount;
    uint64_t	_ver;
    int		_treeid;
    int		_level;
    int		_children;
    bool	_fixme;
    uint8_t    	_hash[MERKLE_HASHLEN];
};

class MerkleLeafCache {
public:
    string	_mkey;
    string	_data;
    int		_count;
    int 	_treeid;
    uint64_t 	_ver;
    bool	_fixme;
    bool	_dirty;
};

// too speed up AE checks
struct MerkleCache {
    uint64_t	ver;
    int 	level;
    int		treeid;
    string	data;
};

typedef deque<MerkleChange*>		 MerkleChangeQ;

class Merkle {
    Mutex            _lock;			// to protect this object's queues
    Mutex            _nlock[MERKLE_NLOCK]; 	// to protect on disk nodes (sharded)
    MerkleLeafCache  _cache[MERKLE_NLOCK];
    Database        *_be;
    MerkleChangeQ   *_mnm;			// queue of non-leaf nodes to update

public:
    Merkle(Database*);
    void add(const string&, int, int, int64_t);
    void del(const string&, int, int, int64_t);
    bool exists(const string&, int, int, int64_t);
    void fix(int, int64_t);
    void fix(int, int, int64_t);
    int  get(int, int, int64_t, ACPY2CheckReply *);
    void flush(void);
    void check(void);
    bool ae(int, int, NetAddr*, uint64_t*, uint64_t*);
    bool ae_fetch(int, int, ACPY2GetSet*, NetAddr*);
    void ae_work(Tinfo*);
    bool compare_result(MerkleCache*, ACPY2CheckValue*);
    bool repartition(int, int64_t*);
    void upgrade(void);
private:
    void q_leafnext(int, uint64_t, int, const string *, bool fix=0);
    bool apply_update_maybe(MerkleChange*, MerkleChange*);
    bool apply_updates(MerkleChangeQ*);
    string *leafcache_get(int, const string&);
    void leafcache_set(int, int, int64_t, int, bool fix=0);
    void leafcache_flush(int);
    bool leafcache_maybe_flush(int);

    DISALLOW_COPY(Merkle);
};


#endif /* __fbdb_merkle_h_ */
