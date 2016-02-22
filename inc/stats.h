/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Dec-17 16:51 (EST)
  Function: stats

*/
#ifndef __fbdb_stats_h__
#define __fbdb_stats_h__

struct Stats {
    int64_t	reqs;
    int64_t	reads;
    int64_t	writes;
    int64_t	ae_fetched;
    int64_t	repart_rmed;
    int64_t	repart_changed;
    int64_t	repart_added;

    int64_t	distrib;
    int64_t	distrib_errs;
    int64_t	distrib_seen;

    lrtime_t	last_ae_time;
};

extern Stats stats;
#define INCSTAT(s)	ATOMIC_ADD64( stats.s, 1 )

#endif /* __fbdb_stats_h__ */
