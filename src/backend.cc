/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 11:16 (EST)
  Function: database backend

*/

#define CURRENT_SUBSYSTEM	'b'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "network.h"
#include "database.h"
#include "expire.h"
#include "partition.h"
#include "merkle.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct BECF {
    const char  *name;
    mkBE_f create;
};

static BECF *becf = 0;
static int nbecf  = 0;


BackendConf::BackendConf(const char *name, mkBE_f func){

    DEBUG("be conf %s", name);

    becf  = (BECF*) realloc( becf, (nbecf + 1) * sizeof(BECF) );
    becf[nbecf].name   = name;
    becf[nbecf].create = func;
    nbecf ++;
}


Database *
BackendConf::create(DBConf *cf){

    DEBUG("be create %s", cf->name.c_str());
    for(int i=0; i<nbecf; i++){
        if( cf->backend.empty() || cf->backend == becf[i].name ){
            Database *b = becf[i].create(cf);
            if( !b ) return 0;
            return b;
        }
    }

    FATAL("no such database backend '%s'", cf->backend.c_str());
}

