#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
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

/* max length of data in socket output buffer */
#define INPUT_BUFFER_LIMIT 65535
#define OUTPUT_BUFFER_LIMIT 65535

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

/* mysql_callback.c */
void mysql_read_callback(struct bufferevent *bev, void *ptr);
void mysql_write_callback(struct bufferevent *bev, void *ptr);
void mysql_event_callback(struct bufferevent *bev, short callbacks, void *ptr);
void cache_mysql_init_packet_read_callback(struct bufferevent *bev, void *ptr);
void cache_mysql_init_packet_event_callback(struct bufferevent *bev, short events, void *ptr);


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
