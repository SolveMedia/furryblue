/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Nov-18 11:17 (EST)
  Function: 

*/

#ifndef __fbdb_store_h_
#define __fbdb_store_h_

class ACPY2MapDatum;
class ACPY2CheckReply;
class ACPY2DistRequest;

extern int store_get(const char *db, ACPY2MapDatum *res);
extern int store_put(const char *db, ACPY2MapDatum *req, int64_t*, int*);
extern int store_get_internal(const char *db, char sub, const string& key, string *res);
extern int store_set_internal(const char *db, char sub, const string& key, int len, uchar *data);
extern int store_get_merkle(const char *db, int level, int shard, int64_t ver, int max, ACPY2CheckReply *res);
extern int store_distrib(const char *db, int, ACPY2DistRequest *req);

#endif /* __fbdb_store_h_ */
