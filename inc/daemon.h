/*
  Copyright (c) 2008 by Jeff Weisberg
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2008-Dec-28 11:21 (EST)
  Function: 
*/

#ifndef __fbdb_daemon_h_
#define __fbdb_daemon_h_

extern int  daemonize(int, const char *, int, char **);
extern void daemon_siginit(void);

#endif //  __fbdb_daemon_h_

