/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Dec-05 17:40 (EST)
  Function: client async i/o

*/

#ifndef __fbdb_clientio_h_
#define __fbdb_clientio_h_

#include "lock.h"

class ClientIO {
protected:
    Mutex			_lock;
    NetAddr			_addr;
    google::protobuf::Message	*_res;
    string			_rbuf,  _wbuf;
    int				_fd;
    int				_state;
    int				_wrpos;
    int				_rlen;
    bool			_polling;
    lrtime_t			_timeout;
protected:
    lrtime_t			_rel_timeout;

public:
    ClientIO(const NetAddr&, int, const google::protobuf::Message*);
    virtual ~ClientIO();
    void set_timeout(lrtime_t);
    void start(void);
protected:
    void retry(const NetAddr&);
    void discard(void);
private:
    void do_connect(void);
    void do_read(void);
    void do_write(void);
    void do_timeout(void);
    void do_error(const char *);
    void do_work(void);
    void _close(void);

    virtual void on_error(void)    = 0;
    virtual void on_success(void)  = 0;


    friend int  build_pfd(struct pollfd *);
    friend void process_pfd(struct pollfd *, int);
};


#endif /* __fbdb_clientio_h_ */
