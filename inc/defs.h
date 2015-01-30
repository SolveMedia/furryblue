/*
  Copyright (c) 2008 by Jeff Weisberg
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2008-Dec-27 19:08 (EST)
  Function: 
*/

#ifndef __fbdb_defs_h_
#define __fbdb_defs_h_


#define MYNAME		"furryblue"
#define DEBUGING	1

typedef unsigned char uchar;

#define DISALLOW_COPY(T) \
	T(const T &);	\
	void operator=(const T&)


#endif // __fbdb_defs_h_
