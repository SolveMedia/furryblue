/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 11:17 (EST)
  Function: 

*/

#ifndef __fbdb_database_h_
#define __fbdb_database_h_

class DBConf;
class ACPY2MapDatum;
class ACPY2CheckReply;
class ACPY2DistRequest;
class Merkle;
class Expire;
class Lambda;
class Ring;

// closure standin
class LambdaRange {
public:
    virtual bool call(const string&, const string&) = 0;
};

#define DBPUTST_DONE	0	// data was accepted, and saved
#define DBPUTST_BAD	1	// invalid
#define DBPUTST_OLD	2	// expired, ...
#define DBPUTST_NOTME 	3	// wrong server
#define DBPUTST_HAVE	4	// already have this

class Database {
protected:
    string	_name;
    Merkle	*_merk;
    Expire	*_expr;
    Ring	*_ring;
    int64_t	_expire;

    Database(DBConf*);
    virtual int  _get(char, const string&, string *) = 0;
    virtual int  _put(char, const string&, int, const uchar*) = 0;
    virtual int  _del(char, const string&) = 0;
    virtual bool _range(char, const string &, const string&, LambdaRange *) = 0;

    int _put(char c, const string& k, const string& v){ _put(c, k, v.size(), (const uchar*)v.data()); }

public:
    virtual ~Database();

    int  get(ACPY2MapDatum *res);
    int  put(ACPY2MapDatum *req, int*);
    bool want_it(const string&, int64_t);
    int  remove(const string&, int64_t);
    int  expire(int64_t max);
    int  get_internal(char, const string& key, string *res);
    int  set_internal(char, const string& key, int, const uchar*);
    int  del_internal(char, const string& key);
    int  get_merkle(int level, int shard, int64_t ver, int, ACPY2CheckReply*);
    int  distrib(int, ACPY2DistRequest*);
    bool ae(void);
    void configure(void);
    int64_t ring_version(void) const;

    friend class BackendConf;
    friend class Merkle;
    friend class Expire;
    friend class Ring;
    friend class MerkRepartLR;

    DISALLOW_COPY(Database);
};

#define MKSUBKEY(k, sub, key)	 \
    string k; 			 \
    k.reserve( key.size() + 2 ); \
    k.append(1, sub);		 \
    k.append(key)


// each backend installs a factory config

typedef Database *(*mkBE_f)(DBConf *);
class BackendConf {

public:
    BackendConf(const char *, mkBE_f);

    static Database* create(DBConf *);
};


#endif /* __fbdb_database_h_ */
