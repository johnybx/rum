CC=gcc
LD=ld

LIBEVENT_DIR=libevent-release-2.1.8-stable

#LDFLAGS=-flto
LDLIBS=-L ${LIBEVENT_DIR}/.libs -lrt -lcdb -lm
#CFLAGS=-Wall -O2 -flto -g -I ${LIBEVENT_DIR}/include
CFLAGS=-Wall -O2 -march=sandybridge -flto -g -I ${LIBEVENT_DIR}/include
LDFLAGS=-Wall -O2 -march=sandybridge -flto -g


all: ${LIBEVENT_DIR}/.libs/libevent.a rum 

rum: rum.o socket.o default_callback.o mysql_callback.o postgresql_callback.o stats_callback.o mysql_cdb.o postgresql_cdb.o mysql_mitm.o postgresql_mitm.o parse_arg.o mysql_password/sha1.o mysql_password.o
	$(CC) $(LDFLAGS) rum.o socket.o default_callback.o mysql_callback.o postgresql_callback.o stats_callback.o mysql_cdb.o postgresql_cdb.o mysql_mitm.o postgresql_mitm.o mysql_password/sha1.o mysql_password.o parse_arg.o $(LDLIBS) -o rum ${LIBEVENT_DIR}/.libs/libevent.a
	#strip rum

${LIBEVENT_DIR}/.libs/libevent.a:
	-$(shell echo 'compiling libevent, wait' >&2)
	-$(shell echo 'cd $(LIBEVENT_DIR); AR=gcc-ar RANLIB=gcc-ranlib CFLAGS="-O2 -flto -fno-fat-lto-objects -march=sandybridge" LDFLAGS="-O2 -flto -fno-fat-lto-objects -march=sandybridge"./configure --disable-shared --enable-static --disable-openssl --disable-debug-mode; make clean; make' >&2)
	-$(shell cd $(LIBEVENT_DIR); AR=gcc-ar RANLIB=gcc-ranlib CFLAGS="-O2 -flto -fno-fat-lto-objects -march=sandybridge" LDFLAGS="-O2 -flto -fno-fat-lto-objects -march=sandybridge" ./configure --disable-shared --enable-static --disable-openssl --disable-debug-mode; make clean; make)

.PHONY : clean cleanlibevent

clean: cleanrum
cleanall: cleanrum cleanlibevent

cleanrum:
	-rm rum *.o mysql_password/*.o

cleanlibevent:
	-make -C ${LIBEVENT_DIR} clean
