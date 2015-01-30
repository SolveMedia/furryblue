/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 16:45 (EST)
  Function: server functions

*/

#define CURRENT_SUBSYSTEM	'S'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "network.h"
#include "netutil.h"
#include "hrtime.h"
#include "database.h"
#include "store.h"
#include "stats.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "y2db_getset.pb.h"
#include "y2db_check.pb.h"

#define TIMEOUT	5

// someone wants our data
int
api_get(NTD *ntd){
    protocol_header *phi = (protocol_header*) ntd->gpbuf_in;
    ACPY2GetSet req;

    if( !(phi->flags & PHFLAG_WANTREPLY) ) return 0;

    // parse request
    req.ParsePartialFromArray( ntd->in_data(), phi->data_length );
    DEBUG("req l=%d, %s", phi->data_length, req.ShortDebugString().c_str());

    if( ! req.IsInitialized() ){
        DEBUG("invalid request. missing required fields");
        return 0;
    }

    // iterate requests
    for(int i=0; i<req.data_size(); i++){
        ACPY2MapDatum *d = req.mutable_data(i);
        store_get( d->map().c_str(), d);
    }

    DEBUG("res l=%d, %s", phi->data_length, req.ShortDebugString().c_str());

    // serialize + reply
    return serialize_reply(ntd, &req, 0);
}

// someone wants to give us data
int
api_put(NTD *ntd){
    protocol_header *phi = (protocol_header*) ntd->gpbuf_in;
    ACPY2DistRequest req;
    ACPY2DistReply   res;


    // parse request
    req.ParsePartialFromArray( ntd->in_data(), phi->data_length );
    DEBUG("l=%d, %s", phi->data_length, req.ShortDebugString().c_str());

    if( ! req.IsInitialized() ){
        DEBUG("invalid request. missing required fields");
        return 0;
    }

    // process requests
    // NB: put may alter request (for a read/modify/write request)
    ACPY2MapDatum *d = req.mutable_data();
    int part = -1;
    int64_t conft = 0;
    int rc   = store_put( d->map().c_str(), d, &conft, &part );

    //DEBUG("put => %d, %d", rc, req.hop());

    if( rc == DBPUTST_DONE || !req.hop() ){
        store_distrib( d->map().c_str(), part, &req );
    }

    if( phi->flags & PHFLAG_WANTREPLY ){
        // build reply
        res.set_status_code( 200 );
        res.set_status_message( "OK" );
        res.set_result_code( rc );
        if( conft ) res.set_conf_time( conft );

        // serialize + reply
        return serialize_reply(ntd, &res, 0);
    }


    // nothing else to send
    return 0;
}


int
api_check(NTD *ntd){
    protocol_header *phi = (protocol_header*) ntd->gpbuf_in;
    ACPY2CheckRequest req;
    ACPY2CheckReply   res;

    if( !(phi->flags & PHFLAG_WANTREPLY) ) return 0;

    // parse request
    req.ParsePartialFromArray( ntd->in_data(), phi->data_length );
    DEBUG("l=%d, %s", phi->data_length, req.ShortDebugString().c_str());

    if( ! req.IsInitialized() ){
        DEBUG("invalid request. missing required fields");
        return 0;
    }

    store_get_merkle( req.map().c_str(), req.level(), req.treeid(), req.version(), req.maxresult(), &res );

    // serialize + reply
    return serialize_reply(ntd, &res, 0);
}

