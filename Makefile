CC=clang
LD=clang

#LDFLAGS=-flto
LDLIBS=-ljemalloc -luv -lrt -lcdb -lm -lpthread -ldl -lcrypto -lssl -lmaxminddb -lcurl -ljson-c -lconfuse
CFLAGS=-Wall -Wextra -Wno-unused-parameter -march=sandybridge -O2 -flto -g
LDFLAGS=-Wall -Wextra -march=sandybridge -O2 -flto -fuse-linker-plugin -g

all: rum 

rum: rum.o socket.o default_callback.o mysql_callback.o postgresql_callback.o stats.o mysql_cdb.o postgresql_cdb.o mysql_mitm.o postgresql_mitm.o parse_arg.o mysql_password/sha1.o mysql_password.o geoip.o curl.o
	$(CC) $(LDFLAGS) rum.o socket.o default_callback.o mysql_callback.o postgresql_callback.o stats.o mysql_cdb.o postgresql_cdb.o mysql_mitm.o postgresql_mitm.o mysql_password/sha1.o mysql_password.o parse_arg.o geoip.o curl.o -o rum $(LDLIBS)
	#strip rum

.PHONY : clean

clean: cleanrum
cleanall: cleanrum

cleanrum:
	-rm rum *.o mysql_password/*.o
