/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 21:46 (EST)
  Function: 

*/


#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "network.h"
#include "netutil.h"
#include "hrtime.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "y2db_check.pb.h"


int
main(int argc, char **argv){
    extern char *optarg;
    extern int optind;
    ACPY2CheckRequest req;
    ACPY2CheckReply   res;
    int c;
    int numtree=1;
    const char *host = "127.0.0.1";
    const char *map  = "test3";

    // -d debug
    // -n numtree
    // -m database
    // -h addr
     while( (c = getopt(argc, argv, "c:dh:m:n:t:")) != -1 ){
	 switch(c){
	 case 'd':
             debug_enabled = 1;
             break;
         case 'n':
             numtree = atoi( optarg );
             break;
         case 'm':
             map = optarg;
             break;
         case 'h':
             host = optarg;
             break;
         }
     }
     argc -= optind;
     argv += optind;


    for(int t=0; t<numtree; t++){
        req.set_map( map );
        req.set_treeid( t<<12 );
        req.set_level( 0 );
        req.set_version( 0 );
        req.set_maxresult( 64 );

        make_request( host, PHMT_Y2_CHECK, 5, &req, &res);

        // display results
        for(int i=0; i<res.check_size(); i++){
            ACPY2CheckValue *r = res.mutable_check(i);

            printf("<%04X>%02X_%016llX %2d %4d ",
                   r->treeid(), r->level(), r->version(), r->children(), r->keycount());

            if( r->has_key() ){
                printf("{%s}\n", r->key().c_str());
            }else if( r->has_hash() ){
                uchar *h = (uchar*) r->hash().data();
                printf("[");
                for(int i=0; i<16; i++){
                    printf("%02x", h[i]);
                }
                printf("]\n");
            }else{
                printf("<?>\n");
            }
        }
    }
}
