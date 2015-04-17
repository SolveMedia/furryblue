/*
  Copyright (c) 2015
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2015-Apr-14 15:57 (EDT)
  Function: 

*/

#define CURRENT_SUBSYSTEM	'j'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "hrtime.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "duktape.h"
#include "y2db_getset.pb.h"
#include "y2db_check.pb.h"


int
json_decode(duk_context *ctx){
    duk_json_decode(ctx, -1);
}


bool
run_program(ACPY2MapDatum *req){
    duk_context *ctx = duk_create_heap_default();
    duk_push_global_object(ctx);

    if( duk_pcompile_string(ctx, DUK_COMPILE_FUNCTION, req->mutable_program(0)->c_str()) ){
        PROBLEM("cannot compile javascript: %s: %s", duk_safe_to_string(ctx, -1), req->mutable_program(0)->c_str());
        duk_destroy_heap(ctx);
        return 0;
    }

    if( req->has_value() ){
        DEBUG("this: %s", req->mutable_value()->c_str());
        duk_push_string(ctx, req->mutable_value()->c_str());

        if( duk_safe_call(ctx, json_decode, 0, 0) ){
            VERBOSE("not valid json: %s", req->mutable_value()->c_str());
            // and continue
        }
    }else{
        duk_push_undefined(ctx);
    }

    int args = req->program_size();
    for(int i=1; i<args; i++){
        DEBUG("arg[%d]: %s", i, req->mutable_program(i)->c_str());
        duk_push_string(ctx, req->mutable_program(i)->c_str());
    }

    if( duk_pcall(ctx, args) ){
        PROBLEM("javascript error: %s: %s", duk_safe_to_string(ctx, -1), req->mutable_program(0)->c_str());
        duk_destroy_heap(ctx);
        return 0;
    }

    bool ok = 0;
    if( duk_is_valid_index(ctx, -1) ){
        duk_json_encode(ctx, -1);
        const char *r = duk_safe_to_string(ctx, -1);

        req->set_value( r );
        DEBUG("res: %s", r);
        ok = 1;
    }

    duk_destroy_heap(ctx);
    return ok;
}

