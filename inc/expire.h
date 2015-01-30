/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-19 12:19 (EST)
  Function: data expiration

*/

#ifndef __fbdb_expire_h_
#define __fbdb_expire_h_

#include "lock.h"
#include <queue>
#include <deque>
using std::priority_queue;

class Database;

class ExpireNote {
public:
    string 	key;
    int64_t	exp;

    ExpireNote(const string& k, int64_t e) : key(k) { exp = e; }

    // does not matter whether this sorts ascending or descending
    struct comparator {
      bool operator () (ExpireNote* a, ExpireNote* b) {
          return a->exp < b->exp;
      }
    };
};


typedef priority_queue<ExpireNote*, std::deque<ExpireNote*>, ExpireNote::comparator> ExpireQueue;

class Expire {
    Mutex	_lock;
    Database	*_be;
    ExpireQueue *_pq;

public:
    Expire(Database*);

    void flush(void);
    void add(const string& key, int64_t exp);
    void expire(void);
private:
    void flush_put(const string&, deque<string> *);
    void expire_edge(void);
    void expire_spec(void);
};


#endif /* __fbdb_expire_h_ */
