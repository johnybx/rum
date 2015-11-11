#define _GNU_SOURCE
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <cdb.h>
#include <string.h>

#include "event2/event.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/util.h"

#define MYSQL50_INIT_PACKET "\x38\x00\x00\x00\x0a\x35\x2e\x30\x2e\x39\x32\x2d\x6c\x6f\x67\x00\x8c\xc0\xc0\x08\x2c\x50\x2f\x38\x6d\x3f\x2f\x6b\x00\x2c\xa2\x3f\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x51"
#define MYSQL51_INIT_PACKET "\x38\x00\x00\x00\x0a\x35\x2e\x31\x2e\x36\x33\x2d\x6c\x6f\x67\x00\x9c\x25\x33\x60\x24\x2e\x5b\x62\x59\x78\x6d\x3e\x00\xff\xf7\x3f\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2d"
//#define MARIADB55_INIT_PACKET "\x57\x00\x00\x00\x0a\x35\x2e\x35\x2e\x32\x38\x61\x2d\x4d\x61\x72\x69\x61\x44\x42\x2d\x6c\x6f\x67\x00\xca\x83\xc5\x00\x2c\x53\x3b\x6f\x3e\x27\x46\x6c\x00\xff\xf7\x3f\x02\x00\x0f\xa0\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6f\x65\x30\x5a\x55\x7c\x33\x25\x5d\x29\x53\x46\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define MARIADB55_INIT_PACKET "\x56\x00\x00\x00\x0a\x35\x2e\x35\x2e\x34\x35\x2d\x4d\x61\x72\x69\x61\x44\x42\x2d\x6c\x6f\x67\x00\x9d\xfa\x21\x00\x30\x61\x7a\x63\x61\x3e\x52\x5f\x00\xff\xf7\x3f\x02\x00\x0f\xa0\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x66\x63\x3e\x4c\x44\x4e\x3b\x7c\x23\x36\x23\x4d\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"


/* max length of data in socket output buffer */
#define INPUT_BUFFER_LIMIT 65535
#define OUTPUT_BUFFER_LIMIT 65535

#define CONNECT_TIMEOUT 3

/* cdb file is reopened every 2 seconds */
#define CDB_RELOAD_TIME 2

#define MYSQL_PACKET_HEADER_SIZE 4
#define MYSQL_INIT_PACKET_MIN_SIZE 46
#define MYSQL_AUTH_PACKET_USER_POS 32

#define SOCKET_TCP 't'
#define SOCKET_UNIX 's'

struct listener {
	int fd; /* listening socket */
	char *s; /* string (tcp:blah:blah or sock:blah) */

	/* statistics */
	unsigned int nr_allconn,nr_conn; 
	unsigned int input_bytes,output_bytes;

	/* normal port or stats port */
	char type;
#define LISTENER_DEFAULT 1
#define LISTENER_STATS 2

	struct listener *next;
};

struct destination {
	char *s; /* string (tcp:blah:blah or sock:blah) */
	union {
		struct sockaddr_in sin; /* if dst == tcp:blah:blah */
		struct sockaddr_un sun; /* if dst == sock:blah */
	};
	socklen_t addrlen;

	/* if we use -M we can have linked list of destinations */
	struct destination *next;
};

/* every connection has 2 bev_arg, one for client socket and one for destination socket,
 * they are linked with bev_arg->remote ptr
*/
struct bev_arg {
	struct bufferevent *bev; /* bufferevent with input/output evbuffer a 1 associated socket fd */
	struct bev_arg *remote; /* bev_arg ptr to remote socket bev_arg */
	struct listener *listener; /* used for statistics */

	/* client or destination */
	char type;
#define BEV_CLIENT 1
#define BEV_TARGET 2
#define BEV_CACHE 3

	/* if -M is used, this structure hold some data used in mysql_callback.c */
	/* if not it is NULL */
	struct mysql_mitm *ms;

	/* used as workaround for bug in bufferevent_socket_connect() */
	char connecting;
    struct event *connect_timer;
};

struct mysql_mitm {
	char handshake; /* current status of mysql handshake */

	char not_need_remote; /* if we use cached init packet we dont need bev_arg->remote set to non NULL in some situations */

	void *client_auth_packet;
	int client_auth_packet_len;

	/* for every connection filled with random string */
	char *scramble1;
	/* scramble string from server from cdb database */
	char *scramble2;

	/* storage for some mathematics */
	unsigned char *hash_stage1;
	unsigned char *hash_stage2;

	/* from cdb database */
	char *password;
};

/* main.c */
void usage();

/* socket.c */
int create_listen_socket(char *wwtf);
void accept_connect(int fd, short event, void *arg);
void prepareclient(char *wwtf, struct destination *destination);
void cache_init_packet_from_server();

/* parse_arg.c */
void parse_arg(char *arg, char *type, struct sockaddr_in *sin, struct sockaddr_un *sun, socklen_t *socklen, in_port_t *port, char **host_str, char **port_str, char **sockfile_str, int unlink_socket);

/* default_callback.c */
void read_callback(struct bufferevent *bev, void *ptr);
void write_callback(struct bufferevent *bev, void *ptr);
void event_callback(struct bufferevent *bev, short callbacks, void *ptr);
void connect_timeout_cb(evutil_socket_t fd, short what, void *arg);

/* mysql_callback.c */
void mysql_read_callback(struct bufferevent *bev, void *ptr);
void mysql_write_callback(struct bufferevent *bev, void *ptr);
void mysql_event_callback(struct bufferevent *bev, short callbacks, void *ptr);
void cache_mysql_init_packet_read_callback(struct bufferevent *bev, void *ptr);
void cache_mysql_init_packet_event_callback(struct bufferevent *bev, short events, void *ptr);
void mysql_connect_timeout_cb(evutil_socket_t fd, short what, void *arg);


/* mysql_mitm .c */
struct mysql_mitm *init_ms();
void free_ms(struct mysql_mitm *ms);
char *get_scramble_from_init_packet(char *packet, size_t len);
int handle_init_packet_from_server(struct bev_arg *bev_arg, struct bufferevent *bev, int len, struct bufferevent *bev_remote);
int handle_auth_packet_from_client(struct bev_arg *bev_arg, struct bufferevent *bev, int len, struct bufferevent *bev_remote);
int handle_auth_with_server(struct bev_arg *bev_arg, struct bufferevent *bev, int len, struct bufferevent *bev_remote); 
char *set_random_scramble_on_init_packet(char *packet, void *p1, void *p2);

/* mysql_cdb.h */
void init_mysql_cdb_file();
void get_data_from_cdb(char *user, int user_len, char **mysql_server, char **mysql_password);
void reopen_cdb(int sig, short event, void *a);

/* stats.c */
void stats_event_callback(struct bufferevent *bev, short callbacks, void *ptr);
void stats_write_callback(struct bufferevent *bev, void *ptr);
void send_stats_to_client(struct bufferevent *bev);
