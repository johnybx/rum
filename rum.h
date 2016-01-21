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
#include <stdarg.h>
#include <netdb.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <cdb.h>
#include <string.h>
#include <time.h>
#include <dirent.h>

#include "event2/event.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/util.h"

#define MYSQL50_INIT_PACKET "\x38\x00\x00\x00\x0a\x35\x2e\x30\x2e\x39\x32\x2d\x6c\x6f\x67\x00\xbf\x96\xc2\x10\x69\x5f\x21\x23\x2a\x49\x73\x26\x00\x2c\xa2\x3f\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x60\x36\x28\x65\x44\x66\x54\x53\x22\x4c\x3b\x22\x00"
#define MYSQL51_INIT_PACKET "\x38\x00\x00\x00\x0a\x35\x2e\x31\x2e\x36\x33\x2d\x6c\x6f\x67\x00\xc2\x0d\xca\x73\x47\x46\x65\x4b\x29\x29\x30\x57\x00\xff\xf7\x3f\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x45\x32\x6a\x42\x48\x23\x73\x3e\x76\x5c\x4b\x3f\x00"
#define MARIADB55_INIT_PACKET "\x56\x00\x00\x00\x0a\x35\x2e\x35\x2e\x34\x35\x2d\x4d\x61\x72\x69\x61\x44\x42\x2d\x6c\x6f\x67\x00\x28\xe3\x75\x01\x24\x2e\x56\x4b\x53\x40\x28\x45\x00\xff\xf7\x3f\x02\x00\x0f\xa0\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x61\x39\x39\x52\x70\x5e\x64\x5d\x27\x48\x74\x2f\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define MARIADB10_1_INIT_PACKET "\x59\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x2d\x31\x30\x2e\x31\x2e\x31\x30\x2d\x4d\x61\x72\x69\x61\x44\x42\x00\x07\x00\x00\x00\x25\x45\x6e\x78\x31\x2a\x7b\x52\x00\xff\xf7\x08\x02\x00\x3f\xa0\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x33\x64\x7e\x6d\x27\x76\x43\x28\x3c\x39\x45\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define MYSQL57_INIT_PACKET "\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x31\x30\x00\x0d\x00\x00\x00\x01\x65\x70\x62\x09\x5d\x67\x5f\x00\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5e\x23\x25\x17\x25\x76\x7e\x36\x43\x19\x25\x66\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define ERR_LOGIN_PACKET_PREFIX "\x00\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30"

/* max length of data in socket output buffer */
#define INPUT_BUFFER_LIMIT 65535
#define OUTPUT_BUFFER_LIMIT 65535

#define CONNECT_TIMEOUT 3
#define READ_TIMEOUT 3          /* only for first data from server, if mysql is stuck and dont send any data within READ_TIMEOUT we drop connection */

/* cdb file is reopened every 2 seconds */
#define CDB_RELOAD_TIME 2

#define MYSQL_PACKET_HEADER_SIZE 4
#define MYSQL_INIT_PACKET_MIN_SIZE 46
#define MYSQL_AUTH_PACKET_USER_POS 32

#define SOCKET_TCP 't'
#define SOCKET_UNIX 's'

struct listener
{
    int fd;                     /* listening socket */
    char *s;                    /* string (tcp:blah:blah or sock:blah) */

    /* statistics */
    unsigned int nr_allconn, nr_conn;
    unsigned int input_bytes, output_bytes;

    /* normal port or stats port */
    char type;
#define LISTENER_DEFAULT 1
#define LISTENER_STATS 2

    struct listener *next;
};

struct destination
{
    char *s;                    /* string (tcp:blah:blah or sock:blah) */
    union
    {
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
struct bev_arg
{
    struct bufferevent *bev;    /* bufferevent with input/output evbuffer a 1 associated socket fd */
    struct bev_arg *remote;     /* bev_arg ptr to remote socket bev_arg */
    struct listener *listener;  /* used for statistics */

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
    short read_timeout;
    struct destination *destination;
};

struct mysql_mitm
{
    char handshake;             /* current status of mysql handshake */

    char not_need_remote;       /* if we use cached init packet we dont need bev_arg->remote set to non NULL in some situations */

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
void usage ();
void logmsg (const char *fmt, ...);
int get_num_fds ();

/* socket.c */
int create_listen_socket (char *wwtf);
void accept_connect (int fd, short event, void *arg);
void prepareclient (char *wwtf, struct destination *destination);
void cache_init_packet_from_server ();

/* parse_arg.c */
void parse_arg (char *arg, char *type, struct sockaddr_in *sin,
                struct sockaddr_un *sun, socklen_t * socklen, in_port_t * port,
                char **host_str, char **port_str, char **sockfile_str,
                int unlink_socket);

/* default_callback.c */
void read_callback (struct bufferevent *bev, void *ptr);
void write_callback (struct bufferevent *bev, void *ptr);
void event_callback (struct bufferevent *bev, short callbacks, void *ptr);
void connect_timeout_cb (evutil_socket_t fd, short what, void *arg);

/* mysql_callback.c */
void mysql_read_callback (struct bufferevent *bev, void *ptr);
void mysql_write_callback (struct bufferevent *bev, void *ptr);
void mysql_event_callback (struct bufferevent *bev, short callbacks,
                           void *ptr);
void cache_mysql_init_packet_read_callback (struct bufferevent *bev,
                                            void *ptr);
void cache_mysql_init_packet_event_callback (struct bufferevent *bev,
                                             short events, void *ptr);
void mysql_connect_timeout_cb (evutil_socket_t fd, short what, void *arg);

/* postgresql_callback.c */
void postgresql_read_callback (struct bufferevent *bev, void *ptr);
void postgresql_write_callback (struct bufferevent *bev, void *ptr);
void postgresql_event_callback (struct bufferevent *bev, short callbacks,
                           void *ptr);
void postgresql_connect_timeout_cb (evutil_socket_t fd, short what, void *arg);

/* postgresql_mitm.c */
int pg_handle_init_packet_from_client (struct bev_arg *bev_arg,
                                    struct bufferevent *bev, int len,
                                    struct bufferevent *bev_remote);
int
pg_handle_auth_with_server (struct bev_arg *bev_arg, struct bufferevent *bev,
                         struct bufferevent *bev_remote);

/* mysql_mitm.c */
struct mysql_mitm *init_ms ();
void free_ms (struct mysql_mitm *ms);
char *get_scramble_from_init_packet (char *packet, size_t len);
int handle_init_packet_from_server (struct bev_arg *bev_arg,
                                    struct bufferevent *bev, int len,
                                    struct bufferevent *bev_remote);
int handle_auth_packet_from_client (struct bev_arg *bev_arg,
                                    struct bufferevent *bev, int len,
                                    struct bufferevent *bev_remote);
int handle_auth_with_server (struct bev_arg *bev_arg, struct bufferevent *bev,
                             int len, struct bufferevent *bev_remote);
char *set_random_scramble_on_init_packet (char *packet, void *p1, void *p2);

/* mysql_cdb.h */
void init_mysql_cdb_file ();
void get_data_from_cdb (char *user, int user_len, char **mysql_server,
                        char **mysql_password);
void reopen_cdb (int sig, short event, void *a);

/* postgresql_cdb.h */
void init_postgresql_cdb_file ();
void get_data_from_cdb_postgresql (char *user, int user_len, char **postgresql_server);
void reopen_cdb_postgresql (int sig, short event, void *a);


/* stats.c */
void stats_event_callback (struct bufferevent *bev, short callbacks,
                           void *ptr);
void stats_write_callback (struct bufferevent *bev, void *ptr);
void send_stats_to_client (struct bufferevent *bev);
