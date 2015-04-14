# Copyright (c) 2014
# Author: Jeff Weisberg <jaw @ solvemedia.com>
# Created: 2014-Mar-13 11:41 (EDT)
# Function: Makefile


PROTO = heartbeat.o std_ipport.o std_reply.o y2db_crypto.o y2db_getset.o y2db_check.o y2db_status.o y2db_ring.o

OBJS =  lock.o diag.o misc.o config.o daemon.o thread.o network.o protocol.o netutil.o crypto.o base64.o \
	kibitz_myself.o kibitz_server.o kibitz_client.o peers.o peerdb.o clientio.o console.o conscmd.o \
	server.o store.o database.o merkle.o expire.o backend.o partition.o distrib.o ae.o \
	duktape.o program.o \
	furryblue.o

OBJS += be_leveldb.o
OBJS += be_rocksdb.o
#OBJS += be_core.o
#OBJS += alloc.o


# import site-wide compiler options
include ../../Makefile.inc

CFLAGS = -g  $(FLAGS) -O3 -pthreads -I. -I`pwd`/../inc  -I/usr/local/include -I/usr/sfw/include -I$(LOCALDIR)/include
CCFLAGS=$(CFLAGS)
LDFLAGS = -L$(LOCALDIR)/lib -L/usr/sfw/lib/amd64 -lprotobuf -lpthread -lrt -lsocket -lnsl -lgen -lssl -lcrypto -lz -lsendfile -lleveldb -lrocksdb
PCC=protoc
CVT=../../../tools/proto2pl

all: furryblued

furryblued: $(PROTO) $(OBJS)
	$(CCC) -o furryblued $(CFLAGS) $(PROTO) $(OBJS) $(LDFLAGS)

install:
	-mv ../../../bin/furryblued ../../../bin/furryblued-
	cp furryblued ../../../bin/

clean:
	rm -f $(OBJS) furryblued

realclean:
	rm -f $(OBJS) $(PROTO) furryblued

TESTOBJ = netutil.o diaglite.o crypto.o base64.o y2db_getset.o y2db_check.o y2db_ring.o y2db_crypto.o
test_put: test_put.o $(TESTOBJ)
	$(CCC) -o test_put test_put.o $(TESTOBJ) $(CFLAGS) $(LDFLAGS)

test_get: test_get.o $(TESTOBJ)
	$(CCC) -o test_get test_get.o $(TESTOBJ) $(CFLAGS) $(LDFLAGS)

test_merk: test_merk.o $(TESTOBJ)
	$(CCC) -o test_merk test_merk.o $(TESTOBJ) $(CFLAGS) $(LDFLAGS)

test_ringcf: test_ringcf.o $(TESTOBJ)
	$(CCC) -o test_ringcf test_ringcf.o $(TESTOBJ) $(CFLAGS) $(LDFLAGS)

test_hammer: test_hammer.o $(TESTOBJ) clientio.o lock.o thread.o
	$(CCC) -o test_hammer test_hammer.o clientio.o lock.o thread.o $(TESTOBJ) $(CFLAGS) $(LDFLAGS)

test_crypto: test_crypto.o $(TESTOBJ) crypto.o auth.o base64.o
	$(CCC) -o test_crypto test_crypto.o crypto.o auth.o base64.o $(TESTOBJ) $(CFLAGS) $(LDFLAGS)


# rocksdb needs c++11
be_rocksdb.o:
	$(CCC) -std=c++11 $(CCFLAGS) -c be_rocksdb.cc


%.o:%.proto
	$(PCC) --proto_path=. --cpp_out=. $<
	$(CCC) $(CFLAGS) -c -o $*.o $*.pb.cc
	$(CVT) $< ../lib/AC/FurryBlue/proto/$*.pl


depend:
	makedepend -I../inc -Y *.cc 2> /dev/null


# DO NOT DELETE

ae.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h ../inc/lock.h
ae.o: ../inc/hrtime.h ../inc/network.h std_reply.pb.h ../inc/netutil.h
ae.o: ../inc/dbwire.h ../inc/merkle.h ../inc/expire.h ../inc/partition.h
ae.o: ../inc/database.h ../inc/stats.h y2db_getset.pb.h y2db_check.pb.h
alloc.o: ../inc/lock.h ../inc/defs.h ../inc/hrtime.h
backend.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
backend.o: ../inc/network.h std_reply.pb.h ../inc/database.h ../inc/expire.h
backend.o: ../inc/lock.h ../inc/hrtime.h ../inc/partition.h ../inc/merkle.h
be_berkeley.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
be_berkeley.o: ../inc/network.h std_reply.pb.h
be_core.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
be_core.o: ../inc/lock.h ../inc/hrtime.h ../inc/network.h std_reply.pb.h
be_core.o: ../inc/merkle.h ../inc/expire.h ../inc/database.h
be_leveldb.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
be_leveldb.o: ../inc/network.h std_reply.pb.h ../inc/merkle.h ../inc/lock.h
be_leveldb.o: ../inc/hrtime.h ../inc/expire.h ../inc/database.h
be_rocksdb.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
be_rocksdb.o: ../inc/network.h std_reply.pb.h ../inc/merkle.h ../inc/lock.h
be_rocksdb.o: ../inc/hrtime.h ../inc/expire.h ../inc/database.h
be_sqlite.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
be_sqlite.o: ../inc/network.h std_reply.pb.h
clientio.o: ../inc/defs.h ../inc/diag.h ../inc/thread.h ../inc/lock.h
clientio.o: ../inc/hrtime.h ../inc/misc.h ../inc/network.h std_reply.pb.h
clientio.o: ../inc/netutil.h ../inc/runmode.h ../inc/clientio.h
clientio.o: ../inc/crypto.h
config.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
config.o: ../inc/network.h std_reply.pb.h
conscmd.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/hrtime.h
conscmd.o: ../inc/thread.h ../inc/config.h ../inc/console.h ../inc/lock.h
conscmd.o: ../inc/network.h std_reply.pb.h ../inc/runmode.h ../inc/stats.h
conscmd.o: ../inc/partition.h
console.o: ../inc/defs.h ../inc/diag.h ../inc/thread.h ../inc/config.h
console.o: ../inc/console.h ../inc/lock.h ../inc/hrtime.h ../inc/network.h
console.o: std_reply.pb.h ../inc/runmode.h
crypto.o: ../inc/defs.h ../inc/diag.h ../inc/misc.h ../inc/config.h
crypto.o: ../inc/hrtime.h ../inc/crypto.h y2db_crypto.pb.h
daemon.o: ../inc/defs.h ../inc/diag.h ../inc/hrtime.h ../inc/runmode.h
database.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
database.o: ../inc/lock.h ../inc/hrtime.h ../inc/network.h std_reply.pb.h
database.o: ../inc/dbwire.h ../inc/merkle.h ../inc/expire.h
database.o: ../inc/partition.h ../inc/database.h y2db_getset.pb.h
database.o: y2db_check.pb.h
diag.o: ../inc/defs.h ../inc/diag.h ../inc/misc.h ../inc/config.h
diag.o: ../inc/hrtime.h ../inc/thread.h ../inc/runmode.h ../inc/console.h
diag.o: ../inc/lock.h
diaglite.o: ../inc/defs.h ../inc/diag.h ../inc/misc.h ../inc/config.h
diaglite.o: ../inc/hrtime.h
distrib.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
distrib.o: ../inc/lock.h ../inc/hrtime.h ../inc/network.h std_reply.pb.h
distrib.o: ../inc/dbwire.h ../inc/merkle.h ../inc/expire.h ../inc/partition.h
distrib.o: ../inc/database.h ../inc/clientio.h ../inc/stats.h
distrib.o: y2db_getset.pb.h
expire.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
expire.o: ../inc/thread.h ../inc/network.h std_reply.pb.h ../inc/hrtime.h
expire.o: ../inc/lock.h ../inc/merkle.h ../inc/expire.h ../inc/partition.h
expire.o: ../inc/database.h y2db_check.pb.h
furryblue.o: ../inc/defs.h ../inc/diag.h ../inc/daemon.h ../inc/config.h
furryblue.o: ../inc/network.h std_reply.pb.h ../inc/hrtime.h ../inc/thread.h
furryblue.o: ../inc/runmode.h
heartbeat.pb.o: heartbeat.pb.h
kibitz_client.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
kibitz_client.o: ../inc/network.h std_reply.pb.h ../inc/netutil.h
kibitz_client.o: ../inc/runmode.h ../inc/hrtime.h ../inc/thread.h
kibitz_client.o: ../inc/peers.h ../inc/lock.h y2db_status.pb.h
kibitz_client.o: std_ipport.pb.h
kibitz_myself.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
kibitz_myself.o: ../inc/runmode.h ../inc/hrtime.h ../inc/network.h
kibitz_myself.o: std_reply.pb.h std_ipport.pb.h y2db_status.pb.h
kibitz_server.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
kibitz_server.o: ../inc/network.h std_reply.pb.h ../inc/hrtime.h
kibitz_server.o: ../inc/peers.h ../inc/lock.h std_ipport.pb.h
kibitz_server.o: y2db_status.pb.h
lock.o: ../inc/defs.h ../inc/thread.h ../inc/lock.h ../inc/hrtime.h
lock.o: ../inc/diag.h
merkle.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
merkle.o: ../inc/thread.h ../inc/crypto.h ../inc/network.h std_reply.pb.h
merkle.o: ../inc/hrtime.h ../inc/merkle.h ../inc/lock.h ../inc/expire.h
merkle.o: ../inc/database.h ../inc/partition.h ../inc/runmode.h
merkle.o: ../inc/stats.h y2db_check.pb.h y2db_getset.pb.h
misc.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
misc.o: ../inc/hrtime.h ../inc/network.h std_reply.pb.h ../inc/crypto.h
misc.o: ../inc/lock.h
netutil.o: ../inc/defs.h ../inc/diag.h ../inc/thread.h ../inc/config.h
netutil.o: ../inc/lock.h ../inc/hrtime.h ../inc/misc.h ../inc/network.h
netutil.o: std_reply.pb.h ../inc/netutil.h ../inc/crypto.h y2db_getset.pb.h
netutil.o: y2db_check.pb.h heartbeat.pb.h
network.o: ../inc/defs.h ../inc/diag.h ../inc/thread.h ../inc/config.h
network.o: ../inc/lock.h ../inc/hrtime.h ../inc/misc.h ../inc/network.h
network.o: std_reply.pb.h ../inc/netutil.h ../inc/runmode.h ../inc/peers.h
network.o: ../inc/crypto.h ../inc/stats.h heartbeat.pb.h
partition.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
partition.o: ../inc/thread.h ../inc/network.h std_reply.pb.h ../inc/hrtime.h
partition.o: ../inc/peers.h ../inc/lock.h ../inc/store.h ../inc/partition.h
partition.o: ../inc/database.h ../inc/merkle.h ../inc/runmode.h
partition.o: y2db_getset.pb.h y2db_ring.pb.h
peerdb.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
peerdb.o: ../inc/network.h std_reply.pb.h ../inc/runmode.h ../inc/hrtime.h
peerdb.o: ../inc/thread.h ../inc/peers.h ../inc/lock.h y2db_status.pb.h
peerdb.o: std_ipport.pb.h
peers.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
peers.o: ../inc/network.h std_reply.pb.h ../inc/runmode.h ../inc/hrtime.h
peers.o: ../inc/thread.h ../inc/peers.h ../inc/lock.h y2db_status.pb.h
peers.o: std_ipport.pb.h
protocol.o: ../inc/defs.h ../inc/diag.h ../inc/thread.h ../inc/config.h
protocol.o: ../inc/lock.h ../inc/hrtime.h ../inc/misc.h ../inc/network.h
protocol.o: std_reply.pb.h ../inc/netutil.h ../inc/runmode.h ../inc/peers.h
protocol.o: heartbeat.pb.h
server.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
server.o: ../inc/network.h std_reply.pb.h ../inc/netutil.h ../inc/hrtime.h
server.o: ../inc/database.h ../inc/store.h ../inc/stats.h y2db_getset.pb.h
server.o: y2db_check.pb.h
std_ipport.pb.o: std_ipport.pb.h
std_reply.pb.o: std_reply.pb.h
store.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
store.o: ../inc/thread.h ../inc/network.h std_reply.pb.h ../inc/store.h
store.o: ../inc/database.h y2db_getset.pb.h
test_crypto.o: ../inc/defs.h ../inc/diag.h ../inc/misc.h ../inc/config.h
test_crypto.o: ../inc/crypto.h
test_get.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/network.h
test_get.o: std_reply.pb.h ../inc/netutil.h ../inc/hrtime.h ../inc/config.h
test_get.o: y2db_getset.pb.h
test_hammer.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/network.h
test_hammer.o: std_reply.pb.h ../inc/netutil.h ../inc/hrtime.h
test_hammer.o: ../inc/clientio.h ../inc/lock.h y2db_getset.pb.h
test_merk.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/network.h
test_merk.o: std_reply.pb.h ../inc/netutil.h ../inc/hrtime.h y2db_check.pb.h
test_put.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/network.h
test_put.o: std_reply.pb.h ../inc/netutil.h ../inc/hrtime.h y2db_getset.pb.h
test_ringcf.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/network.h
test_ringcf.o: std_reply.pb.h ../inc/netutil.h ../inc/hrtime.h
test_ringcf.o: ../inc/config.h y2db_getset.pb.h y2db_ring.pb.h
thread.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/thread.h
y2db_check.pb.o: y2db_check.pb.h
y2db_crypto.pb.o: y2db_crypto.pb.h
y2db_getset.pb.o: y2db_getset.pb.h
y2db_ring.pb.o: y2db_ring.pb.h
y2db_status.pb.o: y2db_status.pb.h std_ipport.pb.h
