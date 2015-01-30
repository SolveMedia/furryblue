/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Dec-04 16:27 (EST)
  Function: 

*/


#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "network.h"
#include "netutil.h"
#include "hrtime.h"
#include "config.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "y2db_getset.pb.h"
#include "y2db_ring.pb.h"


struct T {
    const char *server;
    const char *dc;
    const char *rack;
    uint shard;
};

struct T tc[] = {

    { "fbdb@gefiltedev1-r10.ccsphl", "ccsphl", "r1", 0 <<28 },
    { "fbdb@gefiltedev1-r10.ccsphl", "ccsphl", "r1", 1 <<28 },
    { "fbdb@gefiltedev1-r10.ccsphl", "ccsphl", "r1", 2 <<28 },
    { "fbdb@gefiltedev1-r10.ccsphl", "ccsphl", "r1", 3 <<28 },
    { "fbdb@gefiltedev1-r10.ccsphl", "ccsphl", "r1", 4 <<28 },
    { "fbdb@gefiltedev1-r10.ccsphl", "ccsphl", "r1", 5 <<28 },
    { "fbdb@gefiltedev1-r10.ccsphl", "ccsphl", "r1", 6 <<28 },
    { "fbdb@gefiltedev1-r10.ccsphl", "ccsphl", "r1", 7 <<28 },

    { "fbdb@gefiltedev1-r9.ccsphl", "ccsphl", "r1", 8 <<28 },
    { "fbdb@gefiltedev1-r9.ccsphl", "ccsphl", "r1", 9 <<28 },
    { "fbdb@gefiltedev1-r9.ccsphl", "ccsphl", "r1", 10 <<28 },
    { "fbdb@gefiltedev1-r9.ccsphl", "ccsphl", "r1", 11 <<28 },
    { "fbdb@black-and-white.ccsphl", "ccsphl", "r1", 12 <<28 },
    { "fbdb@black-and-white.ccsphl", "ccsphl", "r1", 13 <<28 },
    { "fbdb@black-and-white.ccsphl", "ccsphl", "r1", 14 <<28 },
    { "fbdb@black-and-white.ccsphl", "ccsphl", "r1", 15 <<28 },
};

Config *config = 0;

int
main(int argc, char **argv){
    ACPY2DistRequest req;
    ACPY2DistReply   res;
    ACPY2RingConf    conf;


    conf.set_version(  1 );
    conf.set_ringbits( 5 );
    conf.set_replicas( 2 );

    for(int i=0; i<ELEMENTSIN(tc); i++){
        ACPY2RingPartConf *c = conf.add_part();

        c->set_server(     tc[i].server );
        c->set_datacenter( tc[i].dc );
        c->set_rack(       tc[i].rack );
        c->add_shard(      tc[i].shard );
    }

    string val;
    conf.SerializeToString( &val );

    int64_t now = hr_now() / 1000;

    debug_enabled = 1;

    req.set_hop( 0 );
    req.set_expire( now + 1000000 );
    req.set_sender( "localhost" );
    ACPY2MapDatum *d = req.mutable_data();

    d->set_map( "_conf" );
    d->set_key( "test3" );
    d->set_shard( 0 );
    d->set_version( now );
    d->set_value( val );

    make_request( "127.0.0.1", PHMT_Y2_DIST, 5, &req, &res);
}

