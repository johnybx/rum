CC=gcc
LD=ld

LIBEVENT_DIR=libevent-2.1.5-beta

#LDFLAGS=-flto
LDLIBS=-L ${LIBEVENT_DIR}/.libs -levent_core -lrt -lcdb -lm
#CFLAGS=-Wall -O2 -flto -I ${LIBEVENT_DIR}/include
CFLAGS=-Wall -O1 -g -I ${LIBEVENT_DIR}/include

all: ${LIBEVENT_DIR}/.libs/libevent.a rum 

rum: rum.o socket.o default_callback.o mysql_callback.o stats_callback.o mysql_cdb.o mysql_mitm.o parse_arg.o mysql_password/sha1.o mysql_password.o
	$(CC) $(LDFLAGS) rum.o socket.o default_callback.o mysql_callback.o stats_callback.o mysql_cdb.o mysql_mitm.o mysql_password/sha1.o mysql_password.o parse_arg.o $(LDLIBS) -o rum
	#strip rum

${LIBEVENT_DIR}/.libs/libevent.a:
	-$(shell echo 'compiling libevent, wait' >&2)
	-$(shell echo 'cd $(LIBEVENT_DIR); CFLAGS="-O2" ./configure --disable-shared --enable-static; make clean; make' >&2)
	-$(shell cd $(LIBEVENT_DIR); CFLAGS="-O2" ./configure --disable-shared --enable-static; make clean; make)

.PHONY : clean cleanlibevent

clean: cleanrum
cleanall: cleanrum cleanlibevent

cleanrum:
	-rm rum *.o mysql_password/*.o

cleanlibevent:
	-make -C ${LIBEVENT_DIR} clean
