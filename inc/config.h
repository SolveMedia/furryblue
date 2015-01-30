/*
  Copyright (c) 2008 by Jeff Weisberg
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2008-Dec-28 12:17 (EST)
  Function: the config file
*/

#ifndef __fbdb_config_h_
#define __fbdb_config_h_

#include <stdint.h>

#include <list>
#include <string>
using std::list;
using std::string;


#define FILE_HW_MEM	"/var/run/adcopy.mem"
#define FILE_HW_CPU	"/var/run/adcopy.cpu"

struct sockaddr;
class NetAddr;
class Config;

struct ACL {
    uint32_t	ipv4;
    uint32_t	mask;
};


class DBConf {
public:
    string		name;
    string		pathname;
    string		backend;
    int			expire;
    int			replicas;
    int			ringbits;

    DBConf();
    DISALLOW_COPY(DBConf);

    friend int read_db(Config*, FILE*, string*);
    friend class Config;

};

typedef list<struct ACL*> ACL_List;
typedef list<NetAddr *>   NetAddr_List;
typedef list<DBConf*>     DBCf_List;

class Config {
public:
    int			hw_cpus;
    int			tcp_threads;
    int			udp_threads;
    int			cio_threads;

    int 		port_console;
    int 		port_server;
    int			available;

    int 		debuglevel;
    char 		debugflags[256/8];
    char 		traceflags[256/8];

    string 		environment;
    string		basedir;
    string		datacenter;
    string		rack;
    string		secret;

    ACL_List		acls;
    NetAddr_List	seedpeers;
    DBCf_List		dbs;

    string		error_mailto;
    string		error_mailfrom;

    int check_acl(const sockaddr *);
protected:
    Config();
    ~Config();
    DISALLOW_COPY(Config);

    friend int read_config(const char*);
};

extern Config *config;

extern int read_config(const char *);

#endif // __fbdb_config_h_

