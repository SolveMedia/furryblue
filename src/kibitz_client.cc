/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Mar-14 15:53 (EDT)
  Function: kibitz client

*/

// YIDDISH-ENGLISH GLOSSARY
//     Kibitz - Gossip. Casual information exchange with ones peers.

// we keep track of peer nodes by randomly kibitzing (gossiping)
// with other nodes


#define CURRENT_SUBSYSTEM	'k'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "network.h"
#include "netutil.h"
#include "runmode.h"
#include "thread.h"
#include "peers.h"

#include "y2db_status.pb.h"

#include <strings.h>
#include <unistd.h>


#define TIMEOUT		15



static void *periodic(void*);
static void *kibitz_with_random_peer(void*);



void
kibitz_init(void){

    start_thread(periodic, 0, 0);
}


static void *
periodic(void *notused){

    while(1){
        if( runmode.mode() == RUN_MODE_EXITING ) return 0;

        start_thread(kibitz_with_random_peer, 0, 0);
        sleep(5);
    }
}

static NetAddr *
random_peer(void){

    // find a nice peer to talk to
    Peer *p = peerdb->random();
    if( p ) return & p->bestaddr;

    NetAddr *peer = 0;
    int n = 0;

    // use a seed
    for(NetAddr_List::iterator it=config->seedpeers.begin(); it != config->seedpeers.end(); it++){
        NetAddr *a = *it;

        if( a->is_self() ) continue;

        if( !peer ) peer = a;
        if( random_n(++n) == 0 ) peer = a;
    }

    return peer;
}


static void*
kibitz_with_random_peer(void *notused){
    NTD ntd;
    ACPY2StatusRequest req;
    ACPY2StatusReply   res;

    NetAddr *peer = random_peer();
    if( !peer ) return 0;

    DEBUG("kibitz with peer %s", peer->name.c_str());

    about_myself( req.mutable_myself() );

    int r = make_request(peer, PHMT_Y2_STATUS, TIMEOUT, &req, &res );

    if( r ){
        if( ! res.IsInitialized() ){
            DEBUG("invalid request. missing required fields");
        }else{
            DEBUG("found %d peers", res.status_size());

            for(int i=0; i<res.status_size(); i++){
                ACPY2Status *s = res.mutable_status(i);
                peerdb->add_peer( s );
            }
        }
    }

    // update status of the random peer
    if( r ){
        peerdb->peer_up( peer->name.c_str() );
    }else{
        peerdb->peer_dn( peer->name.c_str() );
    }

    DEBUG("done");
    return 0;
}
