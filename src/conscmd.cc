/*
  Copyright (c) 2009 by Jeff Weisberg
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2009-Jan-23 10:02 (EST)
  Function: console commands

*/
#define CURRENT_SUBSYSTEM	'C'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "hrtime.h"
#include "thread.h"
#include "config.h"
#include "console.h"
#include "network.h"
#include "lock.h"
#include "runmode.h"
#include "stats.h"
#include "partition.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <vector>
#include <string>
using std::vector;
using std::string;


static int cmd_exit(Console *, const char *, int);
static int cmd_echo(Console *, const char *, int);
static int cmd_none(Console *, const char *, int);
static int cmd_debug(Console *, const char *, int);
static int cmd_shut(Console *, const char *, int);
static int cmd_load(Console *, const char *, int);
static int cmd_reqs(Console *, const char *, int);
static int cmd_rps(Console *, const char *, int);
static int cmd_status(Console *, const char *, int);
static int cmd_help(Console *, const char *, int);
static int cmd_nohap(Console *, const char *, int);
static int cmd_happs(Console *, const char *, int);
static int cmd_look(Console *, const char *, int);
static int cmd_y2(Console *, const char *, int);
static int cmd_busy(Console *, const char *, int);
static int cmd_util(Console *, const char *, int);
static int cmd_rbits(Console *, const char *, int);
static int cmd_rreps(Console *, const char *, int);
static int cmd_raddn(Console *, const char *, int);
static int cmd_rrmn(Console *, const char *, int);


static struct {
    const char *name;
    int visible;
    int (*func)(Console *, const char *, int);
} commands[] = {
    { "",               0, cmd_none },
    { "exit",		1, cmd_exit },
    { "echo", 		1, cmd_echo },
    { "mon", 		1, cmd_debug },
    { "shutdown",       1, cmd_shut },
    { "status",         1, cmd_status },
    { "busy",           1, cmd_busy },	// busyness
    { "load",           1, cmd_load },	// load
    { "util",           1, cmd_util },	// utilization
    { "reqs",           1, cmd_reqs },	// number of requests handled
    { "rps", 		1, cmd_rps  },	// requests per second
    { "xyzzy",          0, cmd_nohap },
    { "plugh",          0, cmd_y2 },
    { "look",           0, cmd_look },
    { "ringbits",	1, cmd_rbits },	// set ringbits
    { "ringreplicas",   1, cmd_rreps }, // set # replicas
    { "ringadd",        1, cmd_raddn },	// add node
    { "ringrm",         1, cmd_rrmn  },	// remove node
    { "help",           1, cmd_help },
    { "?",              0, cmd_help },

    // RSN - add/remove nodes
};

static void
parse(const char *src, int len, vector<string> *argv){

    string arg;

    while( len >= 0 ){
        int c = *src;
        src ++;
        len --;

        if( isspace(c) || !c ){
            if( !arg.empty() ) argv->push_back( arg );
            arg.clear();

            continue;
        }

        arg.append(1, c);
    }
}


static int
cmd_none(Console *con, const char *cmd, int len){
    return 1;
}

static int
cmd_exit(Console *con, const char *cmd, int len){
    return 0;
}

static int
cmd_echo(Console *con, const char *cmd, int len){

    con->output(cmd);
    return 1;
}

static int
cmd_busy(Console *con, const char *cmd, int len){
    char buf[32];

    snprintf(buf, sizeof(buf), "%.4f\n", net_busyness);
    con->output(buf);
    return 1;
}

static int
cmd_load(Console *con, const char *cmd, int len){
    char buf[32];

    snprintf(buf, sizeof(buf), "%.4f\n", net_load_metric);
    con->output(buf);
    return 1;
}

static int
cmd_util(Console *con, const char *cmd, int len){
    char buf[32];

    snprintf(buf, sizeof(buf), "%.4f\n", net_utiliz);
    con->output(buf);
    return 1;
}

static int
cmd_reqs(Console *con, const char *cmd, int len){
    char buf[32];

    snprintf(buf, sizeof(buf), "%lld\n", stats.reqs);
    con->output(buf);
    return 1;
}

static int
cmd_rps(Console *con, const char *cmd, int len){
    char buf[32];

    snprintf(buf, sizeof(buf), "%.4f\n", net_req_per_sec);
    con->output(buf);
    return 1;
}


// debug <number>
// debug off
static int
cmd_debug(Console *con, const char *cmd, int len){
    char *ep;
    int n;

    // eat white
    while( len && isspace(*cmd) ){ cmd++; len--; }

    n = strtol(cmd, &ep, 10);

    if( ep != cmd ){
	con->set_loglevel(n);
    }else if( !strncmp(cmd, "on", 2) ){
	con->set_loglevel(8);
    }else if(  !strncmp(cmd, "off", 3) ){
	con->set_loglevel(-1);
    }else{
	con->output("? mon on|off|<number>\n");
    }

    return 1;
}

static int
cmd_shut(Console *con, const char *cmd, int len){
    time_t now = lr_now();

    // eat white
    while( len && isspace(*cmd) ){ cmd++; len--; }

    if( !strncmp(cmd, "immediate", 9) ){
	VERBOSE("immediate shutdown initiated");
	con->output("shutting down\n");
        runmode.shutdown();

    }else if( !strncmp(cmd, "graceful", 8) ){
	VERBOSE("graceful shutdown initiated");
	con->output("winding down\n");
        runmode.winddown();

    }else if( !strncmp(cmd, "restart", 7) ){
	VERBOSE("shutdown + restart initiated");
	con->output("winding down\n");
        runmode.winddown_and_restart();

    }else if( !strncmp(cmd, "crash", 5) ){
        // in case the system is hung hard (but we can somehow get to the console)
	VERBOSE("crash hard + restart initiated");
	con->output("crashing\n");
        _exit(EXIT_ERROR_RESTART);

    }else if( !strncmp(cmd, "cancel", 6) ){
        VERBOSE("canceling shutdown");
        con->output("canceling shutdown\n");
        // NB: there is a race condition here
        runmode.cancel();

    }else{
	con->output("? shutdown graceful|immediate|restart|crash|cancel\n");
    }

    return 1;
}

static int
cmd_rbits(Console *con, const char *cmd, int len){
    vector<string> argv;
    string err;

    parse(cmd, len, &argv);
    if( argv.size() != 2 ){
        con->output("ringbits dbname #bits\n");
        return 1;
    }
    if( ! ring_setbits( argv[0].c_str(), atoi(argv[1].c_str()), &err ) ){
        con->output("error: ");
        con->output(err.c_str());
        con->output("\n");
    }

    return 1;
}

static int
cmd_rreps(Console *con, const char *cmd, int len){
    vector<string> argv;
    string err;

    parse(cmd, len, &argv);
    if( argv.size() != 2 ){
        con->output("ringreplicas dbname replicas\n");
        return 1;
    }
    if( ! ring_setreplicas( argv[0].c_str(), atoi(argv[1].c_str()), &err ) ){
        con->output("error: ");
        con->output(err.c_str());
        con->output("\n");
    }

    return 1;
}

static int
cmd_raddn(Console *con, const char *cmd, int len){
    vector<string> argv;
    string err;

    parse(cmd, len, &argv);

    if( argv.size() == 4 ){
        if( argv[2] == "shard" ){
            if( ! ring_addnode( argv[0].c_str(), argv[1].c_str(), strtoul(argv[3].c_str(), 0, 0), &err ) ){
                con->output("error: ");
                con->output(err.c_str());
                con->output("\n");
            }
            return 1;
        }
        if( argv[2] == "slots" ){
            int n = atoi( argv[3].c_str() );
            for(int i=0; i<n; i++){
                uint sh = random();
                sh <<= 1;
                if( ! ring_addnode( argv[0].c_str(), argv[1].c_str(), sh, &err ) ){
                    con->output("error: ");
                    con->output(err.c_str());
                    con->output("\n");
                    break;
                }
            }
            return 1;
        }
    }

    con->output("ringadd dbname server (shard # | slots #)\n");
    return 1;
}

static int
cmd_rrmn(Console *con, const char *cmd, int len){
    vector<string> argv;
    string err;

    parse(cmd, len, &argv);
    if( argv.size() != 2 ){
        con->output("ringrm dbname server\n");
        return 1;
    }

    if( ! ring_rmnode(argv[0].c_str(), argv[1].c_str(), &err) ){
        con->output("error: ");
        con->output(err.c_str());
        con->output("\n");
    }

    return 1;
}



static int
cmd_status(Console *con, const char *cmd, int len){

    switch( runmode.mode() ){
    case RUN_LOLA_RUN:
        con->output("running OK\n");
        break;
    case RUN_MODE_WINDDOWN:
        if( runmode.final_exit_value() ){
            con->output("graceful restart underway\n");
        }else{
            con->output("graceful shutdown underway\n");
        }
        break;
    case RUN_MODE_EXITING:
        if( runmode.final_exit_value() ){
            con->output("restart underway\n");
        }else{
            con->output("shutdown underway\n");
        }
        break;
    case RUN_MODE_ERRORED:
        con->output("error recovery underway\n");
        break;
    default:
        con->output("confused\n");
        break;
    }

    return 1;
}

static int
cmd_nohap(Console *con, const char *cmd, int len){
    con->output("nothing happens\n");
    return 1;
}

static int
cmd_happs(Console *con, const char *cmd, int len){
    con->output("something happens\n");
    return 1;
}

static int
cmd_look(Console *con, const char *cmd, int len){

    if( con->y2_b ){
        con->output(
            "You are in a large room, with a passage to the south, a passage to the\n"
            "west, and a wall of broken rock to the east.  There is a large \"Y2\" on\n"
            "a rock in the room's center.\n"
            );
    }else{
        con->output("You are inside a building, a well house for a large spring.\n");
    }
    return 1;
}

static int
cmd_y2(Console *con, const char *cmd, int len){
    con->y2_b = !con->y2_b;
    cmd_look(con,cmd,len);
    return 1;
}

static int
cmd_help(Console *con, const char *cmd, int len){

    con->output("commands:");
    for(int i=0; i<ELEMENTSIN(commands); i++){
        if( !commands[i].visible ) continue;
        con->output(" ");
        con->output(commands[i].name);
    }
    con->output("\n");
    return 1;
}


//################################################################
static int
match(const char *c, const char *s, int l){
    int p = 0;

    while( 1 ){
	if( !*c ){
	    if( p == l )      return p;	// full match
	    if( isspace(*s) ) return p; // match plus more
	    return -1;			// no match
	}
	if( p == l )   return -1;	// end of input
	if( *c != *s ) return -1;	// no match

	c++;
	s++;
	p++;
    }
    return -1;
}

int
run_command(Console *con, const char *cmd, int len){

    for(int i=0; i<ELEMENTSIN(commands); i++){
	int o = match(commands[i].name, cmd, len);
	if( o != -1 ){
	    return commands[i].func(con, cmd + o, len - o);
	}
    }

    con->output("command not found\n");
    return 1;
}


