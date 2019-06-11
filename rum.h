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
#include <ctype.h>

#include "uv.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define MYSQL50_INIT_PACKET "\x38\x00\x00\x00\x0a\x35\x2e\x30\x2e\x39\x32\x2d\x6c\x6f\x67\x00\xbf\x96\xc2\x10\x69\x5f\x21\x23\x2a\x49\x73\x26\x00\x2c\xa2\x3f\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x60\x36\x28\x65\x44\x66\x54\x53\x22\x4c\x3b\x22\x00"
#define MYSQL51_INIT_PACKET "\x38\x00\x00\x00\x0a\x35\x2e\x31\x2e\x36\x33\x2d\x6c\x6f\x67\x00\xc2\x0d\xca\x73\x47\x46\x65\x4b\x29\x29\x30\x57\x00\xff\xf7\x3f\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x45\x32\x6a\x42\x48\x23\x73\x3e\x76\x5c\x4b\x3f\x00"
#define MARIADB55_INIT_PACKET "\x56\x00\x00\x00\x0a\x35\x2e\x35\x2e\x34\x35\x2d\x4d\x61\x72\x69\x61\x44\x42\x2d\x6c\x6f\x67\x00\x28\xe3\x75\x01\x24\x2e\x56\x4b\x53\x40\x28\x45\x00\xff\xf7\x3f\x02\x00\x0f\xa0\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x61\x39\x39\x52\x70\x5e\x64\x5d\x27\x48\x74\x2f\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define MARIADB10_1_INIT_PACKET "\x59\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x2d\x31\x30\x2e\x31\x2e\x31\x30\x2d\x4d\x61\x72\x69\x61\x44\x42\x00\x07\x00\x00\x00\x25\x45\x6e\x78\x31\x2a\x7b\x52\x00\xff\xf7\x08\x02\x00\x3f\xa0\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x33\x64\x7e\x6d\x27\x76\x43\x28\x3c\x39\x45\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define MARIADB10_3_INIT_PACKET "\x72\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x2d\x31\x30\x2e\x33\x2e\x37\x2d\x4d\x61\x72\x69\x61\x44\x42\x2d\x31\x3a\x31\x30\x2e\x33\x2e\x37\x2b\x6d\x61\x72\x69\x61\x7e\x78\x65\x6e\x69\x61\x6c\x2d\x6c\x6f\x67\x00\xf8\x05\x00\x00\x6d\x7a\x40\x6e\x2b\x26\x7d\x68\x00\xfe\xf7\x3f\x02\x00\xbf\x81\x15\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x6e\x72\x6e\x54\x3a\x64\x6a\x65\x3e\x45\x22\x75\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define MYSQL57_INIT_PACKET "\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x31\x30\x00\x0d\x00\x00\x00\x01\x65\x70\x62\x09\x5d\x67\x5f\x00\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5e\x23\x25\x17\x25\x76\x7e\x36\x43\x19\x25\x66\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define MYSQL80_INIT_PACKET "\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x31\x31\x00\x1c\x04\x00\x00\x03\x0e\x0d\x23\x67\x41\x7a\x72\x00\xff\xff\xff\x02\x00\xff\xc3\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x33\x5e\x4b\x68\x17\x1f\x30\x2d\x17\x29\x17\x3b\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#define ERR_LOGIN_PACKET_PREFIX "\x00\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30"

/* cdb file is reopened every 2 seconds */
#define CDB_RELOAD_TIME 2

#define CONNECT_TIMEOUT 6
#define READ_TIMEOUT 6          /* only for first data from server, if mysql is stuck and dont send any data within READ_TIMEOUT we drop connection */

#define MYSQL_PACKET_HEADER_SIZE 4
#define MYSQL_INIT_PACKET_MIN_SIZE 46
#define MYSQL_AUTH_PACKET_USER_POS 32
#define MYSQL_SSL_CONN_REQUEST_PACKET_SIZE 32

#define SOCKET_TCP 't'
#define SOCKET_UNIX 's'
#define SOCKET_SSL 'S'

#define MODE_NORMAL 0           /* -d tcp:... */
#define MODE_FAILOVER 1         /* -f tcp:...,tcp:... */
#define MODE_FAILOVER_RR 2      /* -r tcp:...,tcp:... */
#define MODE_FAILOVER_R 3       /* -R tcp:...,tcp:... */

struct listener
{
    uv_stream_t *stream;        /* listening stream */
    char *s;                    /* string (tcp:blah:blah or sock:blah) */

    /* statistics */
    unsigned int nr_allconn, nr_conn;
    unsigned int input_bytes, output_bytes;

    /* normal port or stats port */
    char type;
#define LISTENER_DEFAULT 1
#define LISTENER_STATS 2

    char sockettype;

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

    /* statistics */
    unsigned int nr_allconn, nr_conn;
    unsigned int input_bytes, output_bytes;

    /* if we use -M we can have linked list of destinations */
    struct destination *next;
};

/* every connection has 2 conn_data, one for client socket and one for destination socket,
 * they are linked with conn_data->remote ptr
*/
struct conn_data
{
    uv_stream_t *stream;
    struct conn_data *remote;   /* conn_data ptr to remote socket conn_data */
    struct listener *listener;  /* used for statistics */
    struct destination *failover_first_dst;

    /* client or destination */
    char type;
#define CONN_CLIENT 1
#define CONN_TARGET 2

    /* if -M or -P is used, this structure hold some data used in mysql_callback.c/postgresql_callback.c */
    /* if not it is NULL */
    struct mitm *mitm;

    /* used as workaround for bug in bufferevent_socket_connect() */
    char connecting;
    /* check if we need to failover or not */
    char connected;
    uv_timer_t *connect_timer;
    uv_timer_t *read_timer;
    struct destination *destination;
    short uv_closed;
    short remote_read_stopped;

    /* ssl stuff */
    SSL *ssl;
    BIO *ssl_read, *ssl_write;
    struct pending *pending;
};

struct pending
{
    uv_buf_t *buf;
    struct pending *next;
};

/* if we use cdb database we need to store some information from client or server and process it */
struct mitm
{
    char handshake;             /* current status of mysql handshake */

    char not_need_remote;       /* if we use stored mysql init packet we dont need conn_data->remote set to non NULL in some situations */

    void *client_auth_packet;   /* we save client first data here and resend it to server after we pickup one */
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
int logmsg_ssl(const char *str, size_t len, void *u);
int get_num_fds ();
struct destination *add_destination (char *ptr);
void randomize_destinations (void);
void shuffle (struct destination **array, size_t n);

/* socket.c */
void on_shutdown (uv_shutdown_t * shutdown, int status);
void on_close_timer (uv_handle_t * handle);
void on_close_listener (uv_handle_t * handle);
void on_close (uv_handle_t * handle);
void on_close_handle (uv_handle_t * handle);
struct conn_data *create_server_connection (struct conn_data *conn_data_client,
                                            struct destination *destination,
                                            struct listener *listener);
void alloc_buffer (uv_handle_t * handle, size_t size, uv_buf_t * buf);
uv_stream_t *create_listen_socket (char *wwtf, char *sockettype);
void on_incoming_connection (uv_stream_t * server, int status);
void prepare_upstream (char *wwtf, struct destination *destination);
void failover (struct conn_data *bev_target);
int flush_ssl(struct conn_data *conn_data);
size_t handle_ssl (uv_stream_t * stream, ssize_t nread, uv_buf_t * buf);
int enable_server_ssl (struct conn_data *conn_data);
int enable_server_ssl_mysql (struct conn_data *conn_data, const uv_buf_t * uv_buf, size_t nread);
int enable_client_ssl (struct conn_data *conn_data);
int is_private_address(struct conn_data *conn_data);

/* parse_arg.c */
void parse_arg (char *arg, char *type, struct sockaddr_in *sin,
                struct sockaddr_un *sun, socklen_t * socklen, in_port_t * port,
                char **host_str, char **port_str, char **sockfile_str,
                int unlink_socket);
in_addr_t resolv_host_to_ip(char *host);

/* default_callback.c */
void alloc_cb (uv_handle_t * handle, size_t size, uv_buf_t * buf);
void on_write (uv_write_t * req, int status);
void on_write_then_close (uv_write_t * req, int status);
void on_write_free (uv_write_t * req, int status);
void on_read_disable_read_timeout (uv_stream_t * stream, ssize_t nread, const uv_buf_t * constbuf);
void on_read (uv_stream_t * stream, ssize_t nread, const uv_buf_t * constbuf);

/* mysql_callback.c */
void mysql_on_read_disable_read_timeout (uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf);
void mysql_on_read (uv_stream_t * stream, ssize_t nread, const uv_buf_t * constbuf);

/* postgresql_callback.c */
void postgresql_on_read_disable_read_timeout (uv_stream_t * stream, ssize_t nread,
                         const uv_buf_t * buf);

void postgresql_on_read (uv_stream_t * stream, ssize_t nread,
                         const uv_buf_t * constbuf);

/* postgresql_mitm.c */
int pg_handle_init_packet_from_client (struct conn_data *conn_data,
                                       const uv_buf_t * buf, size_t nread);
int
pg_handle_auth_with_server (struct conn_data *conn_data, const uv_buf_t * buf,
                            size_t nread);

/* mysql_mitm.c */
struct mitm *init_mitm ();
void free_mitm (struct mitm *mitm);
char *get_scramble_from_init_packet (char *packet, size_t len);
int handle_init_packet_from_server (struct conn_data *conn_data,
                                    const uv_buf_t * buf, size_t nread);
int handle_auth_packet_from_client (struct conn_data *conn_data,
                                    const uv_buf_t * buf, size_t nread);
int handle_auth_with_server (struct conn_data *conn_data, const uv_buf_t * buf,
                             size_t nread);
char *set_random_scramble_on_init_packet (char *packet, void *p1, void *p2);
int check_server_side_ssl_flag(char *packet, size_t len);
void enable_server_side_ssl_flag();
int check_client_side_ssl_flag(char *packet);
void enable_client_side_ssl_flag(char *packet);
void decrement_packet_seq(char *packet);
void increment_packet_seq(char *packet);
void print_packet_seq(char *packet);


/* mysql_cdb.h */
void init_mysql_cdb_file ();
void get_data_from_cdb (char *user, int user_len, char **mysql_server,
                        char **mysql_password);
void reopen_cdb (uv_timer_t * handle);


/* postgresql_cdb.h */
void init_postgresql_cdb_file ();
void get_data_from_cdb_postgresql (char *user, int user_len,
                                   char **postgresql_server);
void reopen_cdb_postgresql (uv_timer_t* handle);


/* stats.c */
void send_stats_to_client (uv_stream_t * stream);

void on_read_timeout (uv_timer_t * timer);
void on_connect_timeout (uv_timer_t * timer);
void on_write (uv_write_t * req, int status);
void on_write_free (uv_write_t * req, int status);
void on_write_nofree (uv_write_t * req, int status);
