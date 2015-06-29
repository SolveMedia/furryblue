/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 21:46 (EST)
  Function: 

*/


#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "network.h"
#include "netutil.h"
#include "hrtime.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "y2db_getset.pb.h"

Config *config = 0;

int
main(int argc, char **argv){
    ACPY2DistRequest req;
    ACPY2DistReply   res;

    int64_t now = hr_now() / 1000;

    debug_enabled = 1;
    srandom( getpid() );

    req.set_hop( 0 );
    req.set_expire( now + 1000000 );
    req.set_sender( "localhost" );
    ACPY2MapDatum *d = req.mutable_data();

    d->set_map( "cmdb" );
    d->set_key( "foobar" );
    d->set_shard( random() << 1 );
    d->set_version( now );
    d->set_value( "abc123" );
    // d->set_expire( now + 10 * 1000000LL );

    if( argc > 1 )
        d->set_key( argv[1] );
    if( argc > 2 )
        d->set_value( argv[2] );

    make_request( "127.0.0.1", PHMT_Y2_DIST, 5, &req, &res);
}
