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
#include "config.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "y2db_getset.pb.h"

Config *config = 0;

int
main(int argc, char **argv){
    ACPY2GetSet      req;
    ACPY2GetSet      res;

    debug_enabled = 1;

    ACPY2MapDatum *d = req.add_data();

    d->set_map( "test3" );
    d->set_key( "foobar" );
    d->set_shard( 0 );

    if( argc > 1 )
        d->set_map( argv[1] );

    if( argc > 2 )
        d->set_key( argv[2] );

    make_request( "127.0.0.1", PHMT_Y2_GET, 5, &req, &res);

}
