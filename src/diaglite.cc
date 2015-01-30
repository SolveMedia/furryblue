/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-19 00:18 (EST)
  Function: mini diag.cc

*/

#include "defs.h"
#include "diag.h"
#include "misc.h"
#include "config.h"
#include "hrtime.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>


int debug_enabled = 0;

void
diag(int level, const char *file, const char *func, int line, int system, const char *fmt, ...){
    char buf[1024];
    va_list ap;
    int l=0;

    va_start(ap, fmt);
    buf[0] = 0;

    if( level < LOG_INFO && !debug_enabled ) return;

    if( level != DIAG_LOG_INFO ){
	snprintf(buf, sizeof(buf), "%s:%d in %s(): ", file, line, func);
	l = strlen(buf);
    }

    // messages
    vsnprintf(buf + l, sizeof(buf) - l, fmt, ap);
    l = strlen(buf);
    va_end(ap);

    // terminate
    if( l >= sizeof(buf) - 2 ) l = sizeof(buf) - 2;
    buf[l++] = '\n';
    buf[l]   = 0;

    // to stderr
    write(2, buf, l);

    if( level == DIAG_LOG_FATAL ) exit(-1);
}

