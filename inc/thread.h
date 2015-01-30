/*
  Copyright (c) 2008 by Jeff Weisberg
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2008-Dec-27 19:41 (EST)
  Function: 
*/

#ifndef __fbdb_thread_h_
#define __fbdb_thread_h_

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <pthread.h>

pthread_t start_thread(void *(*func)(void*), void *arg, int prio);


#endif // __fbdb_thread_h_
