/*
  Copyright (c) 2008 by Jeff Weisberg
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2008-Dec-28 13:39 (EST)
  Function: mutexes
 
  $Id$

*/

#include "defs.h"
#include "thread.h"
#include "lock.h"
#include "diag.h"
#include "runmode.h"

static void
lock_report(hrtime_t t0, hrtime_t t1, hrtime_t t2){

    if( t1 - t0 > 1000000 || t2 - t1 > 1000000 )
        VERBOSE("slow lock wait %lld, held %lld", t1 - t0, t2 - t1);
}

class Mutex_Attr {
public:
    pthread_mutexattr_t attr;
    Mutex_Attr();
};

Mutex_Attr::Mutex_Attr() {
    pthread_mutexattr_init( &attr );
    pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_ERRORCHECK );
}

static Mutex_Attr *default_mutex_attr = 0;

//################################################################

Mutex::Mutex(){
    if( ! default_mutex_attr ){
        default_mutex_attr = new Mutex_Attr;
    }

    pthread_mutex_init( &_mutex, &default_mutex_attr->attr );
}

Mutex::~Mutex(){
    trylock();
    unlock();
    pthread_mutex_destroy( &_mutex );
}

void
Mutex::lock(void){
    int e = pthread_mutex_lock( &_mutex );
    if(e) FATAL("mutex lock failed %d", e);
}

void
Mutex::unlock(void){
    int e = pthread_mutex_unlock( &_mutex );
    if(e && !runmode.is_stopping() ) FATAL("mutex unlock failed %d", e);
}

int
Mutex::trylock(void){
    // 0 => got it
    return pthread_mutex_trylock( &_mutex );
}

//################################################################


SpinLock::SpinLock(){

    pthread_spin_init( &_spin, PTHREAD_PROCESS_SHARED );
}

SpinLock::~SpinLock(){
    trylock();
    unlock();
    pthread_spin_destroy( &_spin );
}

void
SpinLock::lock(void){
    pthread_spin_lock( &_spin );
}

void
SpinLock::unlock(void){
    pthread_spin_unlock( &_spin );
}

int
SpinLock::trylock(void){
    return pthread_spin_trylock( &_spin );
}

//################################################################

class RWLock_Attr {
public:
    pthread_rwlockattr_t attr;
    RWLock_Attr();
};

RWLock_Attr::RWLock_Attr() {
    pthread_rwlockattr_init( &attr );
}

static RWLock_Attr *default_rwlock_attr = 0;

//################################################################

RWLock::RWLock(){
    if( ! default_rwlock_attr ){
        default_rwlock_attr = new RWLock_Attr;
    }
    pthread_rwlock_init( &_rwlock, &default_rwlock_attr->attr );
}

RWLock::~RWLock(){
    w_lock();
    w_unlock();
    pthread_rwlock_destroy( &_rwlock );
}

void
RWLock::r_lock(void){
    pthread_rwlock_rdlock( &_rwlock );
}

void
RWLock::r_unlock(void){
    pthread_rwlock_unlock( &_rwlock );
}

void
RWLock::w_lock(void){
    pthread_rwlock_wrlock( &_rwlock );
}

void
RWLock::w_unlock(void){
    pthread_rwlock_unlock( &_rwlock );
}

int
RWLock::r_trylock(void){
    return pthread_rwlock_tryrdlock( &_rwlock );
}

int
RWLock::w_trylock(void){
    return pthread_rwlock_trywrlock( &_rwlock );
}

