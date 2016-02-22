/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Mar-17 16:17 (EDT)
  Function: 

*/

#define CURRENT_SUBSYSTEM	'p'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "network.h"
#include "runmode.h"
#include "thread.h"
#include "peers.h"

#include "y2db_status.pb.h"

#include <netinet/in.h>
#include <strings.h>

#define MAXFAIL		2


static void
copy_status(const ACPY2Status *src, ACPY2Status *dst){

    dst->CopyFrom( *src );
}


Peer::Peer(const ACPY2Status *g){

    _gstatus  = new ACPY2Status;
    copy_status(g, _gstatus);

    _num_fail  = 0;
    _last_try  = 0;
    _last_up   = 0;
    _available = 0;
    _id        = _gstatus->server_id().c_str();
    _last_conf = _gstatus->timeconf();

    switch( g->status() ){
    case 200:
    case 102:
        _status = PEER_STATUS_UP;
        break;
    default:
        _status = PEER_STATUS_DN;
    }

    // determine best addr
    const ACPIPPort *best = 0;
    for(int i=0; i<g->ip_size(); i++){
        const ACPIPPort *ip = & g->ip(i);
        if( ip->has_natdom() ){
            if( ! mydatacenter.compare(ip->natdom()) ){
                best    = ip;
            }
        }else{
            if( !best ) best = ip;
        }
    }
    if( best ){
        bestaddr.ipv4      = ntohl(best->ipv4());
        bestaddr.port      = best->port();
        bestaddr.name      = g->server_id().c_str();
        bestaddr.same_dc   = (mydatacenter == g->datacenter()) ? 1 : 0;
        bestaddr.same_rack = (myrack == g->rack()) ? 1 : 0;
    }

    ring_server_update( this, "new" );
}

Peer::~Peer(){
    delete _gstatus;
}


void
Peer::update(const ACPY2Status *g){

    if( g->timesent() < _gstatus->timesent() ) return;

    copy_status( g, _gstatus );
    _id = _gstatus->server_id().c_str();
    int64_t oldcft = _last_conf;
    _last_conf     = _gstatus->timeconf();
    _available     = _gstatus->status() == 200;

    ring_server_update( this, "cft" );
}

void
Peer::status_reply(ACPY2Status *g) const{

    copy_status( _gstatus, g);

    g->set_via( myserver_id.c_str() );

    string path = g->path().c_str();
    path.append(" ");
    path.append( myserver_id.c_str() );
    g->set_path( path.c_str() );
}

void
Peer::set_is_up(void){

    int oldstatus = _status;
    _num_fail = 0;
    _status   = PEER_STATUS_UP;
    _last_up  = _last_try = lr_now();

    if( _status != oldstatus ) ring_server_update( this, "up" );
}

void
Peer::set_is_down(void){

    int oldstatus = _status;
    _status = PEER_STATUS_DN;
    _gstatus->set_status( 0 );
    _gstatus->set_timesent( _last_try );

    if( _status != oldstatus ) ring_server_update( this, "dn" );
}

void
Peer::set_maybe_down(void){

    _num_fail ++;
    if( _status != PEER_STATUS_DN ) _status   = PEER_STATUS_MAYBEDN;
    _last_try = lr_now();

    if( _num_fail > MAXFAIL ) set_is_down();

}

// does this peer have this db?
bool
Peer::has_db(const char *db) const {

    for(int i=0; i<_gstatus->database_size(); i++){
        if( _gstatus->database(i) == db ) return 1;
    }
    return 0;
}


bool
Peer::is_uptodate(void) const {
    return _gstatus->uptodate();
}

const string&
Peer::get_datacenter(void) const {
    return _gstatus->datacenter();
}

const string&
Peer::get_rack(void) const {
    return _gstatus->rack();
}


