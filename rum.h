#define _GNU_SOURCE
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
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
#include <getopt.h>
#include <assert.h>

#include "uv.h"

#define MYSQL50_INIT_PACKET "\x38\x00\x00\x00\x0a\x35\x2e\x30\x2e\x39\x32\x2d\x6c\x6f\x67\x00\xbf\x96\xc2\x10\x69\x5f\x21\x23\x2a\x49\x73\x26\x00\x2c\xa2\x3f\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x60\x36\x28\x65\x44\x66\x54\x53\x22\x4c\x3b\x22\x00"
#define MYSQL51_INIT_PACKET "\x38\x00\x00\x00\x0a\x35\x2e\x31\x2e\x36\x33\x2d\x6c\x6f\x67\x00\xc2\x0d\xca\x73\x47\x46\x65\x4b\x29\x29\x30\x57\x00\xff\xf7\x3f\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x45\x32\x6a\x42\x48\x23\x73\x3e\x76\x5c\x4b\x3f\x00"
#define MARIADB55_INIT_PACKET "\x56\x00\x00\x00\x0a\x35\x2e\x35\x2e\x34\x35\x2d\x4d\x61\x72\x69\x61\x44\x42\x2d\x6c\x6f\x67\x00\x28\xe3\x75\x01\x24\x2e\x56\x4b\x53\x40\x28\x45\x00\xff\xf7\x3f\x02\x00\x0f\xa0\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x61\x39\x39\x52\x70\x5e\x64\x5d\x27\x48\x74\x2f\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define MARIADB10_1_INIT_PACKET "\x59\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x2d\x31\x30\x2e\x31\x2e\x31\x30\x2d\x4d\x61\x72\x69\x61\x44\x42\x00\x07\x00\x00\x00\x25\x45\x6e\x78\x31\x2a\x7b\x52\x00\xff\xf7\x08\x02\x00\x3f\xa0\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x33\x64\x7e\x6d\x27\x76\x43\x28\x3c\x39\x45\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define MYSQL57_INIT_PACKET "\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x31\x30\x00\x0d\x00\x00\x00\x01\x65\x70\x62\x09\x5d\x67\x5f\x00\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5e\x23\x25\x17\x25\x76\x7e\x36\x43\x19\x25\x66\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define ERR_LOGIN_PACKET_PREFIX "\x00\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30"

/* max length of data in socket output buffer */
#define OUTPUT_BUFFER_LIMIT 16384

#define CONNECT_TIMEOUT 60
#define READ_TIMEOUT 60          /* only for first data from server, if mysql is stuck and dont send any data within READ_TIMEOUT we drop connection */

#define MYSQL_PACKET_HEADER_SIZE 4
#define MYSQL_INIT_PACKET_MIN_SIZE 46
#define MYSQL_AUTH_PACKET_USER_POS 32

#define SOCKET_TCP 't'
#define SOCKET_UNIX 's'

#define MODE_NORMAL 0 /* -d tcp:... */
#define MODE_FAILOVER 1 /* -f tcp:...,tcp:... */
#define MODE_FAILOVER_RR 2 /* -r tcp:...,tcp:... */
#define MODE_FAILOVER_R 3 /* -R tcp:...,tcp:... */

#define BUFPOOL_CAPACITY 100
#define BUF_SIZE 64000

typedef struct bufpool_s bufpool_t;

struct bufpool_s {
    void *first;
    int used;
    int size;
    int alloc_size;
};

#define bufbase(ptr) ((bufbase_t *)((char *)(ptr) - sizeof(bufbase_t)))
#define buflen(ptr) (bufbase(ptr)->len)

typedef struct bufbase_s bufbase_t;

struct bufbase_s {
    bufpool_t *pool;
    void *next;
    int len;
};



/* bufpool.c */
void *bufpool_dummy();
void *bufpool_grow(bufpool_t *pool);
void bufpool_enqueue(bufpool_t *pool, void *ptr);
void *bufpool_dequeue(bufpool_t *pool);
void bufpool_init(bufpool_t *pool, int size);
void bufpool_done(bufpool_t *pool);
void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void *bufpool_acquire(bufpool_t *pool, int *len);
void *bufpool_alloc(bufpool_t *pool, int len);
void bufpool_done(bufpool_t *pool);
void bufpool_release(void *ptr);
void bufpool_print_stats(uv_timer_t* handle);


struct listener
{
    uv_stream_t *stream;                     /* listening stream */
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
    uv_stream_t *stream;
    struct bev_arg *remote;     /* bev_arg ptr to remote socket bev_arg */
    struct listener *listener;  /* used for statistics */
    struct destination *failover_first_dst;

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
    /* check if we need to failover or not */
    char connected;
//    struct event *connect_timer;
    uv_timer_t *connect_timer;
    uv_timer_t *read_timer;
//    short read_timeout;
    struct destination *destination;
    short uv_closed;
    short read_stopped;
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
void add_destination (char *ptr);
void randomize_destinations (void);
void shuffle(struct destination **array, size_t n);

/* socket.c */
void on_shutdown(uv_shutdown_t *shutdown, int status);
void on_close_timer(uv_handle_t* handle);
void on_close(uv_handle_t* handle);
struct bev_arg *create_server_connection(struct bev_arg *bev_arg_client, struct destination *destination, struct listener *listener);
void alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);
uv_stream_t *create_listen_socket (char *wwtf);
void on_incoming_connection (uv_stream_t *server, int status);
void prepareclient (char *wwtf, struct destination *destination);
void failover(struct bev_arg *bev_target);

/* parse_arg.c */
void parse_arg (char *arg, char *type, struct sockaddr_in *sin,
                struct sockaddr_un *sun, socklen_t * socklen, in_port_t * port,
                char **host_str, char **port_str, char **sockfile_str,
                int unlink_socket);

/* default_callback.c */

void on_write(uv_write_t* req, int status);
void on_write_then_close(uv_write_t* req, int status);
void on_write_free(uv_write_t* req, int status);
void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
/*
void read_callback (struct bufferevent *bev, void *ptr);
void write_callback (struct bufferevent *bev, void *ptr);
void event_callback (struct bufferevent *bev, short callbacks, void *ptr);
*/
//void connect_timeout_cb (evutil_socket_t fd, short what, void *arg);

/* mysql_callback.c */
void mysql_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
/*
void mysql_read_callback (struct bufferevent *bev, void *ptr);
void mysql_write_callback (struct bufferevent *bev, void *ptr);
void mysql_event_callback (struct bufferevent *bev, short callbacks,
                           void *ptr);
void cache_mysql_init_packet_read_callback (struct bufferevent *bev,
                                            void *ptr);
void cache_mysql_init_packet_event_callback (struct bufferevent *bev,
                                             short events, void *ptr);
//void mysql_connect_timeout_cb (evutil_socket_t fd, short what, void *arg);
*/

/* postgresql_callback.c */
void postgresql_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
/*
void postgresql_read_callback (struct bufferevent *bev, void *ptr);
void postgresql_write_callback (struct bufferevent *bev, void *ptr);
void postgresql_event_callback (struct bufferevent *bev, short callbacks,
                           void *ptr);
*/
//void postgresql_connect_timeout_cb (evutil_socket_t fd, short what, void *arg);

/* postgresql_mitm.c */
int pg_handle_init_packet_from_client (struct bev_arg *bev_arg,
                                     const uv_buf_t *buf, size_t nread);
int
pg_handle_auth_with_server (struct bev_arg *bev_arg, const uv_buf_t *buf, size_t nread);

/* mysql_mitm.c */
struct mysql_mitm *init_ms ();
void free_ms (struct mysql_mitm *ms);
char *get_scramble_from_init_packet (char *packet, size_t len);
int handle_init_packet_from_server (struct bev_arg *bev_arg,
                                     const uv_buf_t *buf, size_t nread);
int handle_auth_packet_from_client (struct bev_arg *bev_arg,
                                    const uv_buf_t *buf, size_t nread);
int handle_auth_with_server (struct bev_arg *bev_arg, const uv_buf_t *buf, size_t nread);
char *set_random_scramble_on_init_packet (char *packet, void *p1, void *p2);

/* mysql_cdb.h */
void init_mysql_cdb_file ();
void get_data_from_cdb (char *user, int user_len, char **mysql_server,
                        char **mysql_password);
void reopen_cdb (uv_fs_event_t *handle, const char *filename, int events, int status);

/* postgresql_cdb.h */
void init_postgresql_cdb_file ();
void get_data_from_cdb_postgresql (char *user, int user_len, char **postgresql_server);
void reopen_cdb_postgresql (uv_fs_event_t *handle, const char *filename, int events, int status);


/* stats.c */
void send_stats_to_client (uv_stream_t *stream);
/*
void stats_event_callback (struct bufferevent *bev, short callbacks,
                           void *ptr);
void stats_write_callback (struct bufferevent *bev, void *ptr);
void send_stats_to_client (struct bufferevent *bev);
*/

