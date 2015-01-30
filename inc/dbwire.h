/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 11:17 (EST)
  Function: 

*/

#ifndef __fbdb_dbwire_h_
#define __fbdb_dbwire_h_

#define DBTYP_DELETED	0
#define DBTYP_DATA	1
// ...

// on disk record
struct DBRecord {
public:
    int64_t ver;
    int64_t expire;
    int32_t shard;
    int32_t type;

    uchar   value[0];
};


#endif /* __fbdb_dbwire_h_ */
