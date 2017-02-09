CC=gcc
LD=ld

LIBUV_DIR=libuv-1.11.0

#LDFLAGS=-flto
LDLIBS=-L ${LIBUV_DIR}/.libs -lrt -lcdb -lm -lpthread -ldl
#CFLAGS=-Wall -O2 -flto -g -I ${LIBUV_DIR}/include
CFLAGS=-Wall -march=sandybridge -Ofast -flto -g -I ${LIBUV_DIR}/include
LDFLAGS=-Wall -march=sandybridge -Ofast -flto -fuse-linker-plugin -g

all: ${LIBUV_DIR}/.libs/libuv.a rum 

rum: rum.o socket.o default_callback.o mysql_callback.o postgresql_callback.o stats_callback.o mysql_cdb.o postgresql_cdb.o mysql_mitm.o postgresql_mitm.o parse_arg.o mysql_password/sha1.o mysql_password.o bufpool.o
	$(CC) $(LDFLAGS) rum.o socket.o default_callback.o mysql_callback.o postgresql_callback.o stats_callback.o mysql_cdb.o postgresql_cdb.o mysql_mitm.o postgresql_mitm.o mysql_password/sha1.o mysql_password.o parse_arg.o bufpool.o -o rum ${LIBUV_DIR}/.libs/libuv.a $(LDLIBS)
#	$(CC) $(LDFLAGS) rum.o socket.o default_callback.o mysql_callback.o postgresql_callback.o stats_callback.o mysql_cdb.o postgresql_cdb.o mysql_mitm.o postgresql_mitm.o mysql_password/sha1.o mysql_password.o parse_arg.o bufpool.o -o rum ${LIBUV_DIR}/.libs/libuv.a jemalloc-4.4.0/lib/libjemalloc.a $(LDLIBS)
	#strip rum

${LIBUV_DIR}/.libs/libuv.a:
	-$(shell echo 'compiling libuv, wait' >&2)
	-$(shell echo 'cd $(LIBUV_DIR); AR=gcc-ar RANLIB=gcc-ranlib CFLAGS="-Ofast -flto -fno-fat-lto-objects -march=sandybridge" LDFLAGS="-Ofast -fno-strict-aliasing -flto -fno-fat-lto-objects -march=sandybridge" ./configure --disable-shared --enable-static; make clean; make' >&2)
	-$(shell cd $(LIBUV_DIR); AR=gcc-ar RANLIB=gcc-ranlib CFLAGS="-Ofast -flto -fno-fat-lto-objects -march=sandybridge" LDFLAGS="-Ofast -flto -fno-fat-lto-objects -march=sandybridge" ./configure --disable-shared --enable-static ; make clean; make)

.PHONY : clean cleanlibuv

clean: cleanrum
cleanall: cleanrum cleanlibuv

cleanrum:
	-rm rum *.o mysql_password/*.o

cleanlibuv:
	-make -C ${LIBUV_DIR} clean
