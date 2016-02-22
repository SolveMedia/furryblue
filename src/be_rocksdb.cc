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

#include "rocksdb/db.h"


class BE_RocksDB : public Database {
private:
    rocksdb::DB*        _db;

public:
    virtual int  _get(char, const string& , string *);
    virtual int  _put(char, const string& , int, const uchar *);
    virtual int  _del(char, const string& );
    virtual bool _range(char, const string &, const string&, LambdaRange *);

    BE_RocksDB(DBConf*);
    virtual ~BE_RocksDB();

    DISALLOW_COPY(BE_RocksDB);
};


static Database *create_be(DBConf *);

static const BackendConf _be_rocksdb_conf( "rocksdb", create_be );

// create a new rocksdb database
static Database *
create_be(DBConf *cf){

    return new BE_RocksDB(cf);
}

//################################################################

BE_RocksDB::BE_RocksDB(DBConf *cf) : Database(cf) {

    rocksdb::Options options;

    // options.statistics = rocksdb::CreateDBStatistics();

    options.write_buffer_size           =  16 * 1024 * 1024;
    options.target_file_size_base       = 256 * 1024 * 1024;
    //options.compaction_readahead_size = 2 * 1024 * 1024;
    options.max_write_buffer_number     = 4;
    options.target_file_size_multiplier = 10;
    options.max_background_compactions  = 4;

    options.create_if_missing = true;

    rocksdb::Status status = rocksdb::DB::Open(options, cf->pathname.c_str(), &_db);

    if( !status.ok() ){
        FATAL("cannot open db '%s': %s", cf->pathname.c_str(), status.ToString().c_str());
    }

    VERBOSE("opened database '%s'", cf->pathname.c_str());
}

BE_RocksDB::~BE_RocksDB(){
    _merk->flush();
    _expr->flush();
    delete _db;
    _db = 0;
    DEBUG("closed");
}

int
BE_RocksDB::_get(char sub, const string& key, string *res){
    MKSUBKEY(k, sub, key);

    rocksdb::Status s = _db->Get(rocksdb::ReadOptions(), k, res);
    return s.ok();
}

int
BE_RocksDB::_put(char sub, const string& key, int len, const uchar *data){
    MKSUBKEY(k, sub, key);

    // DEBUG("=>%s", k.c_str());
    rocksdb::Slice ds( (char*)data, len);
    rocksdb::Status s = _db->Put(rocksdb::WriteOptions(), k, ds);
    return s.ok();
}

int
BE_RocksDB::_del(char sub, const string& key){
    MKSUBKEY(k, sub, key);

    _db->Delete(rocksdb::WriteOptions(), k);
    return 1;
}

bool
BE_RocksDB::_range(char sub, const string& start, const string& end, LambdaRange *lr){
    MKSUBKEY(k, sub, start);
    bool ret = 1;

    rocksdb::Iterator* it = _db->NewIterator(rocksdb::ReadOptions());
    for (it->Seek(k); it->Valid(); it->Next()) {

        rocksdb::Slice kks = it->key();

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

