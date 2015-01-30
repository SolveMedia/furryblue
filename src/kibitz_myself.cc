/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Mar-14 15:57 (EDT)
  Function: 

*/

#define CURRENT_SUBSYSTEM	'k'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "runmode.h"
#include "network.h"
#include "hrtime.h"

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/loadavg.h>
#include <unistd.h>


#include "std_ipport.pb.h"
#include "y2db_status.pb.h"

#include <strings.h>

#define BOOTTIME	60


char     myhostname[256];
string   myserver_id;
string   mydatacenter;
string   myipandport;
string	 myrack;

static hrtime_t starttime = 0;
static hrtime_t conftime  = 0;
static char     pinhost[256];


bool db_uptodate = 0;


bool
NetAddr::is_self(void){

    if( ipv4 == myipv4pin )   return 1;
    if( ipv4 == myipv4 )      return 1;
    if( name == myserver_id ) return 1;

    return 0;
}

void
myself_init(void){
    char buf[16];
    struct hostent *he;

    starttime = lr_now();
    conftime  = lr_now();

    myport = config->port_server;
    if( !myport ){
	FATAL("cannot determine port to use");
    }
    // determine hostname + ip addr
    gethostname( myhostname, sizeof(myhostname));
    he = gethostbyname( myhostname );
    if( !he || !he->h_length ){
	FATAL("cannot determine my ipv4 addr");
    }
    myipv4 = ((struct in_addr *)*he->h_addr_list)->s_addr;

    myipandport = inet_ntoa(*((struct in_addr *)he->h_addr_list[0]));
    myipandport.append(":");
    snprintf(buf, sizeof(buf), "%d", myport);
    myipandport.append(buf);

    DEBUG("hostname %s, ip %x => %s", myhostname, myipv4, myipandport.c_str());

    // determine unique id for this server
    // fbdb[/env]@hostname
    myserver_id = "fbdb";
    if( config->environment.compare("prod") ){
        myserver_id.append("/");
        myserver_id.append(config->environment);
    }
    myserver_id.append("@");

    // find + remove domain (2nd dot from end)
    int dot1=0, dot2=0, dot3=0;
    int hlen = strlen(myhostname);
    for(int i=hlen-1; i>=0; i--){
        if( myhostname[i] == '.' ){
            if( dot2 ){
                dot3 = i;
                break;
            }
            if( dot1 ){
                dot2 = i;
                continue;
            }
            dot1 = i;
        }
    }

    // append local hostname
    if(!dot2)  dot2 = dot1;
    if( dot2 )
        myserver_id.append(myhostname, dot2);
    else
        myserver_id.append(myhostname);

    DEBUG("server id: %s", myserver_id.c_str());

    // datacenter: hostname.datacenter.domain...
    if( config->datacenter.empty() ){
        if( dot3 ){
            mydatacenter.append(myhostname+dot3+1, dot2-dot3-1);
        }else{
            mydatacenter.append(myhostname + (dot2 ? dot2+1 : 0));
        }
    }else{
        mydatacenter = config->datacenter;
    }
    DEBUG("datacenter: %s", mydatacenter.c_str());

    if( config->rack.empty() ){
        // hostname-r#.domain...
        const char *rs = strstr(myhostname, "-r");
        if(!rs)     rs = strstr(myhostname, "-R");
        if( rs ){
            const char *re = strchr(rs, '.');
            if( re ){
                myrack.append(rs+1, re-rs-1);
            }
        }
    }else{
        myrack = config->rack;
    }
    if( !myrack.empty() ) DEBUG("rack %s", myrack.c_str());


    // find private internal network info
    // we name the private internal address "pin-$hostname"
    // XXX - you may need to adjust this for your network

    snprintf(pinhost, sizeof(pinhost), "pin-%s", myhostname);
    he = gethostbyname( pinhost );
    if( he && he->h_length ){
        myipv4pin = ((struct in_addr *)*he->h_addr_list)->s_addr;
    }else{
        VERBOSE("no private network found: %s", pinhost);
    }
}

void
about_myself(ACPY2Status *g){
    hrtime_t now = lr_now();
    ACPIPPort *ip;
    struct statvfs vfs;

    g->set_hostname( myhostname );
    g->set_server_id( myserver_id.c_str() );
    g->set_datacenter( mydatacenter.c_str() );
    if( !myrack.empty() ) g->set_rack( myrack.c_str() );
    g->set_environment( config->environment.c_str() );
    g->set_subsystem( MYNAME );
    g->set_via( myserver_id.c_str() );
    g->set_path( "." );

    if( config->available && (runmode.mode() == RUN_MODE_RUN) ){
        g->set_status( (now > starttime + BOOTTIME) ? 200 : 102 );
    }else{
        g->set_status( 102 );
    }

    g->set_uptodate( db_uptodate );
    g->set_timesent( now );
    g->set_lastup( now );
    g->set_timeboot( starttime );
    g->set_timeconf( conftime );

    int cm = config->hw_cpus * 1000 - current_load();
    if( cm < 0 ) cm = 0;
    g->set_cpu_metric( cm );

    // determine disk space
    if( ! statvfs( config->basedir.c_str(), &vfs ) ){
        g->set_capacity_metric( vfs.f_bavail / 2048 );	// MB avail
    }

    // ip info
    ip = g->add_ip();
    ip->set_ipv4( ntohl(myipv4) );
    ip->set_port( myport );

    if( myipv4pin ){
        ip = g->add_ip();
        ip->set_ipv4( ntohl(myipv4pin) );
        ip->set_port( myport );
        ip->set_natdom( mydatacenter.c_str() );
    }

    for(DBCf_List::iterator it=config->dbs.begin(); it != config->dbs.end(); it++){
        DBConf *d   = *it;
        g->add_database( d->name );
    }
}

