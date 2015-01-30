/*
  Copyright (c) 2014
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2014-Dec-17 11:27 (EST)
  Function: 

*/

#include <lock.h>

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <dlfcn.h>


static FILE *logf = 0;
static Mutex lock;

static void
cleanup(void){

    if( logf ) fclose(logf);
}

extern void install_handler(int sig, void(*func)(int));

static void
reset(int){

    lock.lock();
    fclose(logf);
    logf = fopen("mem.log", "w");
    lock.unlock();
    printf("reset\n");
}

static void
init(void){

    logf = fopen("mem.log", "w");
    atexit( cleanup );

    install_handler( 7, reset );
}

static void*
myalloc(size_t size){
    Dl_info dli;

    // determine caller
    void **bp;
    asm( "mov %%rbp, %0" : "=r" (bp) );
    bp = (void**)*bp;	// next frame
    void *caller = bp[1];
    int d = dladdr( caller, &dli );
    const char *name = d? dli.dli_sname : "?";

    void *p = malloc(size);

    lock.lock();
    if( !logf ) init();
    fprintf(logf, "+ %p %d %p %s\n", p, size, caller, name);
    lock.unlock();
    return p;
}
static void
myfree(void *p){
    free(p);

    lock.lock();
    if( !logf ) init();
    fprintf(logf, "- %p\n", p);
    lock.unlock();

}

//################################################################

void*
operator new (size_t size){
    return myalloc(size);
}

void*
operator new[] (size_t size){
    return myalloc(size);
}

void
operator delete (void *p){
    myfree(p);
}

void
operator delete[] (void *p){
    myfree(p);
}


