/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 11:14 (EST)
  Function: storage subsystem
*/

#define CURRENT_SUBSYSTEM	's'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "thread.h"
#include "network.h"
#include "store.h"
#include "database.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "y2db_getset.pb.h"

extern bool db_uptodate;
static void store_ae(void);

class DBS {
public:
    const char *name;
    Database   *be;

    ~DBS(){ delete be; }
};

static DBS *dbs = 0;
static int ndb  = 0;
static pthread_t maint_tid = 0;


void
store_exit(void){
    // close databases
    ndb = 0;
    pthread_cancel( maint_tid );
    sleep(1);
    delete [] dbs;
}

static void*
store_maint(void*){

    sleep(10);	// so we can discover some peers

    while(1){
        if(ndb) store_ae();
        sleep(5);
    }
}

void
store_init(void){

    int n = config->dbs.size();
    dbs = new DBS[n];

    // for each db in config file
    //   create + save
    int i = 0;
    for(DBCf_List::iterator it=config->dbs.begin(); it != config->dbs.end(); it++){
        DBConf *d   = *it;
        Database *b = BackendConf::create( d );
        if(!b) continue;

        dbs[i].name = d->name.c_str();
        dbs[i].be   = b;
        ndb = ++i;
    }

    // the partition configurer needs to access the databaase
    // so it can't be done in the ctor
    for(int n=0; n<ndb; n++){
        dbs[n].be->configure();
    }


    maint_tid = start_thread(store_maint, 0, 0);
    atexit( store_exit );
}

static Database *
find(const char *name){

    // NB: the list is expected to be quite small
    // no need for a fancier search

    for(int i=0; i<ndb; i++){
        if( !strcmp(name, dbs[i].name) )
            return dbs[i].be;
    }

    return 0;
}


//################################################################

int
store_get(const char *db, ACPY2MapDatum *res){
    Database *be = find(db);
    if(!be) return 0;

    res->set_conf_time( be->ring_version() );
    return be->get(res);
}

int
store_put(const char *db, ACPY2MapDatum *req, int64_t* cft, int *part){
    Database *be = find(db);
    if(!be) return 0;

    if( cft ) *cft = be->ring_version();
    return be->put(req, part);
}

#if 0
int
store_remove(const char *db, const string& key, int shard, int64_t ver){
    Database *be = find(db);
    if(!be) return 0;

    return be->remove(key, shard, ver);
}
#endif

int
store_get_merkle(const char *db, int level, int treeid, int64_t ver, int max, ACPY2CheckReply *res){
    Database *be = find(db);
    if(!be) return 0;

    return be->get_merkle(level, treeid, ver, max, res);
}

int
store_get_internal(const char *db, char sub, const string& key, string *res){
    Database *be = find(db);
    if(!be) return 0;

    return be->get_internal(sub, key, res);
}

int
store_set_internal(const char *db, char sub, const string& key, int len, uchar *data){
    Database *be = find(db);
    if(!be) return 0;

    return be->set_internal(sub, key, len, data);
}

int
store_distrib(const char *db, int part, ACPY2DistRequest *req){
    Database *be = find(db);
    if(!be) return 0;

    // currently, we can only do hinted-handoff if the db is known
    // RSN - hinted-double-handoff if the db is unknown

    return be->distrib(part, req);
}


//################################################################

static void
store_ae(void){
    bool ok = 1;

    for(int i=0; i<ndb; i++){
        if( dbs[i].be->ae() ) ok = 0;
    }

    // we are up to date if all databases AEed ok
    if( ok ){
        db_uptodate = 1;
        sleep(25);	// we're good, no need to check too often
    }
}
