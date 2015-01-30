/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 11:56 (EST)
  Function: leveldb backend

*/
#define CURRENT_SUBSYSTEM	'b'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "network.h"
#include "merkle.h"
#include "expire.h"
#include "database.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "leveldb/db.h"


class BE_LevelDB : public Database {
private:
    leveldb::DB*        _db;

public:
    virtual int  _get(char, const string& , string *);
    virtual int  _put(char, const string& , int, const uchar *);
    virtual int  _del(char, const string& );
    virtual bool _range(char, const string &, const string&, LambdaRange *);

    BE_LevelDB(DBConf*);
    virtual ~BE_LevelDB();

    DISALLOW_COPY(BE_LevelDB);
};


static Database *create_be(DBConf *);

static const BackendConf _be_leveldb_conf( "leveldb", create_be );

// create a new leveldb database
static Database *
create_be(DBConf *cf){

    return new BE_LevelDB(cf);
}

//################################################################

BE_LevelDB::BE_LevelDB(DBConf *cf) : Database(cf) {

    leveldb::Options options;
    options.create_if_missing = true;
    leveldb::Status status = leveldb::DB::Open(options, cf->pathname.c_str(), &_db);

    if( !status.ok() ){
        FATAL("cannot open db '%s': %s", cf->pathname.c_str(), status.ToString().c_str());
    }

    VERBOSE("opened database '%s'", cf->pathname.c_str());
}

BE_LevelDB::~BE_LevelDB(){
    _merk->flush();
    _expr->flush();
    delete _db;
    _db = 0;
    DEBUG("closed");
}

int
BE_LevelDB::_get(char sub, const string& key, string *res){
    MKSUBKEY(k, sub, key);

    leveldb::Status s = _db->Get(leveldb::ReadOptions(), k, res);
    return s.ok();
}

int
BE_LevelDB::_put(char sub, const string& key, int len, const uchar *data){
    MKSUBKEY(k, sub, key);

    // DEBUG("=>%s", k.c_str());
    leveldb::Slice ds( (char*)data, len);
    leveldb::Status s = _db->Put(leveldb::WriteOptions(), k, ds);
    return s.ok();
}

int
BE_LevelDB::_del(char sub, const string& key){
    MKSUBKEY(k, sub, key);

    _db->Delete(leveldb::WriteOptions(), k);
    return 1;
}

bool
BE_LevelDB::_range(char sub, const string& start, const string& end, LambdaRange *lr){
    MKSUBKEY(k, sub, start);
    bool ret = 1;

    leveldb::Iterator* it = _db->NewIterator(leveldb::ReadOptions());
    for (it->Seek(k); it->Valid(); it->Next()) {

        leveldb::Slice kks = it->key();
        // check + remove prefix
        if( kks[0] != sub ) break;
        kks.remove_prefix(1);

        string kk = kks.ToString();
        if( end.compare(kk) < 0 ) break;
        string kv = it->value().ToString();

        int ok = lr->call( kk, kv );
        if( !ok ){
            ret = 0;
            break;
        }
    }

    delete it;
    return ret;	// 0 => terminated prematurely, 1 => reached end
}

