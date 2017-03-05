CC=clang-4.0
LD=clang-4.0

LIBUV_DIR=libuv-1.11.0

#LDFLAGS=-flto
LDLIBS=-L ${LIBUV_DIR}/.libs -lrt -lcdb -lm -lpthread -ldl
#CFLAGS=-Wall -O2 -flto -g -I ${LIBUV_DIR}/include
CFLAGS=-Wall -march=sandybridge -O2 -flto -g -I ${LIBUV_DIR}/include
LDFLAGS=-Wall -march=sandybridge -O2 -flto -fuse-linker-plugin -g

all: ${LIBUV_DIR}/.libs/libuv.a rum 

rum: rum.o socket.o default_callback.o mysql_callback.o postgresql_callback.o stats.o mysql_cdb.o postgresql_cdb.o mysql_mitm.o postgresql_mitm.o parse_arg.o mysql_password/sha1.o mysql_password.o bufpool.o
	$(CC) $(LDFLAGS) rum.o socket.o default_callback.o mysql_callback.o postgresql_callback.o stats.o mysql_cdb.o postgresql_cdb.o mysql_mitm.o postgresql_mitm.o mysql_password/sha1.o mysql_password.o parse_arg.o bufpool.o -o rum ${LIBUV_DIR}/.libs/libuv.a $(LDLIBS)
#	$(CC) $(LDFLAGS) rum.o socket.o default_callback.o mysql_callback.o postgresql_callback.o stats.o mysql_cdb.o postgresql_cdb.o mysql_mitm.o postgresql_mitm.o mysql_password/sha1.o mysql_password.o parse_arg.o bufpool.o -o rum ${LIBUV_DIR}/.libs/libuv.a jemalloc-4.4.0/lib/libjemalloc.a $(LDLIBS)
	#strip rum

${LIBUV_DIR}/.libs/libuv.a:
	-$(shell echo 'compiling libuv, wait' >&2)
#	-$(shell echo 'cd $(LIBUV_DIR); CC=clang-4.0 AR=llvm-ar-4.0 RANLIB=llvm-ranlib-4.0 CFLAGS="-Os -march=sandybridge -flto" LDFLAGS="-Os -flto -fuse-linker-plugin -march=sandybridge" ./configure --disable-shared --enable-static; make clean; make' >&2)
#	-$(shell cd $(LIBUV_DIR); CC=clang-4.0 AR=llvm-ar-4.0 RANLIB=llvm-ranlib-4.0 LD=clang-4.0 CFLAGS="-Os -march=sandybridge -flto" LDFLAGS="-Os -march=sandybridge -flto -fuse-linker-plugin" ./configure --disable-shared --enable-static ; make clean; make)
	-$(shell echo 'cd $(LIBUV_DIR); CC=clang-4.0 AR=llvm-ar-4.0 RANLIB=llvm-ranlib-4.0 CFLAGS="-O2 -flto -fuse-linker-plugin -march=sandybridge" LDFLAGS="-O2 -march=sandybridge -flto -fuse-linker-plugin" ./configure --disable-shared --enable-static; make clean; make' >&2)
	-$(shell cd $(LIBUV_DIR); CC=clang-4.0 AR=llvm-ar-4.0 RANLIB=llvm-ranlib-4.0 LD=clang-4.0 CFLAGS="-O2 -flto -fuse-linker-plugin -march=sandybridge" LDFLAGS="-O2 -flto -fuse-linker-plugin -march=sandybridge" ./configure --disable-shared --enable-static ; make clean; make)

.PHONY : clean cleanlibuv

clean: cleanrum
cleanall: cleanrum cleanlibuv

cleanrum:
	-rm rum *.o mysql_password/*.o

cleanlibuv:
	-make -C ${LIBUV_DIR} clean
