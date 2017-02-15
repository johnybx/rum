#include "rum.h"

extern bufpool_t *pool;

extern struct destination *first_destination;
extern char *mysql_cdb_file;
extern char *postgresql_cdb_file;

extern char *cache_mysql_init_packet;
extern int cache_mysql_init_packet_len;
extern char *cache_mysql_init_packet_scramble;
extern int mode;

int logfd;

extern int connect_timeout;
extern int read_timeout;

extern int client_keepalive;
extern int client_keepcnt;
extern int client_keepidle;
extern int client_keepintvl;

extern int server_keepalive;
extern int server_keepcnt;
extern int server_keepidle;
extern int server_keepintvl;

/*
 * create_listen_socket return uv_stream
 * arg - tcp:blah:blah alebo sock:blah
 */
uv_stream_t *
create_listen_socket (char *arg)
{
    char *arg_copy;
    struct sockaddr *s = NULL;
    struct sockaddr_in sin;
    struct sockaddr_un sun;
    socklen_t socklen;
    uint16_t port;
    char type;
    char *host_str, *port_str, *sockfile_str;
    int r;
    uv_tcp_t *tcp_t;
    uv_pipe_t *pipe_t;

    arg_copy = strdup (arg);
    /* parse string arg_copy into variables
     * arg_copy is modified
     */
    parse_arg (arg_copy, &type, &sin, &sun, &socklen, &port, &host_str,
               &port_str, &sockfile_str, 1);

    if (type == SOCKET_TCP) {
        uv_os_fd_t fd;
        s = (struct sockaddr *) &sin;
        tcp_t = malloc(sizeof(uv_tcp_t));
        uv_tcp_init_ex(uv_default_loop(), tcp_t, AF_INET);
        /* set SO_REUSEPORT so we can bind to tcp port when it is still used by running rum */
        uv_fileno((uv_handle_t *)tcp_t, &fd);
        int optval = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    } else if (type == SOCKET_UNIX) {
        s = (struct sockaddr *) &sun;
        pipe_t = malloc(sizeof(uv_pipe_t));
        uv_pipe_init(uv_default_loop(), pipe_t, 0);
    } else {
        usage ();
        _exit (-1);
    }

    if (type == SOCKET_TCP) {
        r = uv_tcp_bind(tcp_t, (const struct sockaddr*)s, 0);
    } else if (type == SOCKET_UNIX) {
        r = uv_pipe_bind(pipe_t, sun.sun_path);
    }

    if (r) {
        fprintf(stderr,"bind() to %s failed, exiting\n", arg);
        _exit (-1);
    }

    free (arg_copy);


    if (type == SOCKET_TCP) {
        uv_tcp_nodelay((uv_tcp_t *)tcp_t,1);
        return (uv_stream_t *)tcp_t;
    } else {
        return (uv_stream_t *)pipe_t;
    }
}

/* fill destination->sin or destination->sun and destination->socklen
 */
void
prepareclient (char *arg, struct destination *destination)
{
    char *arg_copy;
    uint16_t port;
    char *host_str, *port_str, *sockfile_str;
    char type;

    arg_copy = strdup (arg);

    destination->s = strdup (arg);
    destination->next = NULL;

    parse_arg (arg_copy, &type, &destination->sin, &destination->sun,
               &destination->addrlen, &port, &host_str, &port_str,
               &sockfile_str, 0);
    free (arg_copy);
}

/* after successful/not successful connect() */
void
on_outgoing_connection (uv_connect_t *connect, int status)
{
    struct conn_data *conn_data = connect->data;
    int r;
    uv_stream_t *stream = connect->handle;
    struct destination *destination;

    free(connect);

    if (conn_data->connect_timer) {
        uv_timer_stop(conn_data->connect_timer);
        uv_close((uv_handle_t *)conn_data->connect_timer, on_close_timer);
        conn_data->connect_timer = NULL;
    }

    if (status<0) {
        /* if we hit connect_timeout, we already call uv_close() in on_connect_timeout() */
        /* calling it again will cause segfault */
        if (!conn_data->uv_closed) {
            uv_close((uv_handle_t *)stream, on_close);
        }

        if (mode == MODE_NORMAL) {
            /* connection failed, close client socket */
            if (conn_data->remote) {
                conn_data->remote->remote=NULL;
                uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
                uv_shutdown(shutdown, conn_data->remote->stream, on_shutdown);
            }
            return;
        } else if (mode == MODE_FAILOVER || mode == MODE_FAILOVER_R) {
            /* FAILOVER */
            if (conn_data->destination->next) {
                /* select next server for connection */
                logmsg("%s: failover: connection to %s failed (%s), connecting to next server %s", __FUNCTION__, conn_data->destination->s, uv_strerror(status), conn_data->destination->next->s);
                destination = conn_data->destination->next;
            } else {
                logmsg("%s: failover: no server available, closing client connection", __FUNCTION__);
                conn_data->remote->remote=NULL;
                uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
                uv_shutdown(shutdown, conn_data->remote->stream, on_shutdown);
                return;
            }
        }
 
        if (mode == MODE_FAILOVER || mode == MODE_FAILOVER_R || mode == MODE_FAILOVER_RR) {
            struct conn_data *conn_data_target;
            conn_data_target = create_server_connection(conn_data->remote, destination, conn_data->listener);
            if (!conn_data_target) {
                conn_data->remote->remote=NULL;
                uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
                uv_shutdown(shutdown, conn_data->remote->stream, on_shutdown);
            }
        }
    
        return;
    }

    conn_data->stream = stream;

    uv_tcp_nodelay((uv_tcp_t *)stream, 1);

    /* on successfull connect */
    if (mysql_cdb_file) {
        r = uv_read_start(stream, alloc_cb, mysql_on_read);

        if (r) {
        }
    } else if (postgresql_cdb_file) {
        r = uv_read_start(stream, alloc_cb, on_read);

        if (r) {
        }
        /* send server client auth packet */
        if (conn_data->ms && conn_data->ms->client_auth_packet) {
            uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
            uv_buf_t *newbuf = malloc(sizeof(uv_buf_t));
            newbuf->base=conn_data->ms->client_auth_packet;
            newbuf->len=conn_data->ms->client_auth_packet_len;
            req->data = newbuf;
            conn_data->ms->client_auth_packet = NULL;
            if (uv_write(req, stream, newbuf, 1, on_write_free)) {
                logmsg ("%s: uv_write(postgresql client_auth_packet) failed", __FUNCTION__);

                free(newbuf->base);
                free(newbuf);
                free(req);

                uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
                uv_shutdown(shutdown, stream, on_shutdown);
            }

        }
        /* change client callback to on_read */
        r = uv_read_start(conn_data->remote->stream, alloc_cb, on_read);

    } else {
        r = uv_read_start(stream, alloc_cb, on_read);

        if (r) {
        }

        /* enable client read */
        r = uv_read_start(conn_data->remote->stream, alloc_cb, on_read);

        if (r) {
        }
    }

    /* set read timeout for server socket */
    conn_data->read_timer = malloc(sizeof(uv_timer_t));
    uv_timer_init(uv_default_loop(), conn_data->read_timer);
    conn_data->read_timer->data=conn_data;
    uv_timer_start(conn_data->read_timer, on_read_timeout, read_timeout * 1000, 0);
}

/*
 * accept() new connection from client
 */
void
on_incoming_connection (uv_stream_t *server, int status)
{
    struct listener *listener = (struct listener *) server->data;
    struct conn_data *conn_data_client, *conn_data_target;

    struct destination *destination=NULL;
    int r;

    uv_stream_t *client;
    if (listener->type == SOCKET_TCP) {
        client = malloc(sizeof(uv_tcp_t));
    } else {
        client = malloc(sizeof(uv_pipe_t));
    }

    if (mode == MODE_NORMAL) {
        destination=first_destination;
    } else if (mode == MODE_FAILOVER || mode == MODE_FAILOVER_R) {
        /* use first but try second in case of fail */
        destination = first_destination;
    }

    client = malloc (sizeof (uv_tcp_t));
    uv_tcp_init(uv_default_loop(), (uv_tcp_t *)client);

    if (uv_accept(server, (uv_stream_t *)client)) {
        logmsg ("%s: uv_accept failed", __FUNCTION__);
        free(client);
        return;
    }

    listener->nr_allconn++;
    listener->nr_conn++;

    /* CLIENT conn_data */
    /* parameter for callback functions */
    conn_data_client = malloc (sizeof (struct conn_data));
    conn_data_client->type = CONN_CLIENT;
    conn_data_client->listener = listener;
    conn_data_client->stream = client;
    conn_data_client->connecting = 0;
    conn_data_client->connected = 0;
    conn_data_client->connect_timer = NULL;
    conn_data_client->read_timer = NULL;
    conn_data_client->destination = NULL;
    conn_data_client->ms = NULL;
    conn_data_client->uv_closed = 0;
    conn_data_client->read_stopped = 0;

    client->data = conn_data_client;
    conn_data_client->remote = NULL;

    if (listener->type == LISTENER_DEFAULT) {
        if (!mysql_cdb_file && !postgresql_cdb_file) {
            /* no cdb files, classic redirector */
            conn_data_target = create_server_connection(conn_data_client, destination, listener);
            if (!conn_data_target) {
                conn_data_client->remote=NULL;
                uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
                uv_shutdown(shutdown, conn_data_client->stream, on_shutdown);
            }
        } else if (mysql_cdb_file) {
            /* if mysql_cdb is enabled, use different callback functions */
            conn_data_client->ms = init_ms ();

            conn_data_client->remote = NULL;
            conn_data_client->ms->not_need_remote = 1;
            conn_data_client->ms->handshake = 1;

            /* we use conn_data_client and ms pointers as random data for generating random string filled in init packet send to client */
            /* TODO: use better random input */
            conn_data_client->ms->scramble1 =
                set_random_scramble_on_init_packet (cache_mysql_init_packet,
                                                conn_data_client->stream,
                                                conn_data_client->ms);

            r = uv_read_start((uv_stream_t *)client, alloc_cb, mysql_on_read);
            if (r) {
                logmsg("%s: uv_read_start failed (%s)", __FUNCTION__, uv_strerror(r));
                uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
                if (uv_shutdown(shutdown, conn_data_client->stream, on_shutdown)) {
                    free(shutdown);
                }

                return;
            }

            uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
            uv_buf_t *newbuf = malloc(sizeof(uv_buf_t));
            newbuf->base=cache_mysql_init_packet;
            newbuf->len=cache_mysql_init_packet_len;
            req->data = newbuf;
            if (uv_write(req, client, newbuf, 1, on_write_nofree)) {
                logmsg ("%s: uv_write(cache_mysql_init_packet) failed", __FUNCTION__);
                free(newbuf);
                free(req);

                uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
                if (uv_shutdown(shutdown, conn_data_client->stream, on_shutdown)) {
                    free(shutdown);
                }
            }

            return;
        } else if (postgresql_cdb_file) {
            /* if postgresql_cdb is enabled, use different callback functions */
            conn_data_client->ms = init_ms ();

            conn_data_client->remote = NULL;
            conn_data_client->ms->not_need_remote = 1;
            conn_data_client->ms->handshake = 1;

            int r = uv_read_start((uv_stream_t *)client, alloc_cb, postgresql_on_read);
            if (r) {
                logmsg("%s: uv_read_start failed (%s)", __FUNCTION__, uv_strerror(r));
                uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
                if (uv_shutdown(shutdown, conn_data_client->stream, on_shutdown)) {
                    free(shutdown);
                }

            }
            return;
        }
    } else if (listener->type == LISTENER_STATS) {
        return send_stats_to_client (client);
    }
}

/* return conn_data structure */
/* after un/successfull connection on_outgoing_connection() will be called */
struct conn_data *create_server_connection(struct conn_data *conn_data_client, struct destination *destination, struct listener *listener)
{
    uv_stream_t *target;
    uv_connect_t* connect;
    struct conn_data *conn_data_target;

    if (destination->s[0] == SOCKET_TCP) {
        target = malloc (sizeof (uv_tcp_t));
        uv_tcp_init(uv_default_loop(), (uv_tcp_t *)target);
        connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));
        uv_tcp_connect(connect, (uv_tcp_t *)target, (struct sockaddr *)&destination->sin, on_outgoing_connection);
    } else {
        target = malloc (sizeof (uv_pipe_t));
        uv_pipe_init(uv_default_loop(), (uv_pipe_t *)target, 0);
        connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));
        uv_pipe_connect(connect, (uv_pipe_t *)target, destination->sun.sun_path, on_outgoing_connection);
    }

    conn_data_target = malloc (sizeof (struct conn_data));
    conn_data_target->type = CONN_TARGET;
    conn_data_target->connecting = 0;
    conn_data_target->connected = 0;
    conn_data_target->uv_closed = 0;
    conn_data_target->read_stopped = 0;
    conn_data_target->destination = destination;
    conn_data_target->failover_first_dst = destination;

    conn_data_client->remote = conn_data_target;

    conn_data_target->listener = listener;
    conn_data_target->stream = target;
    conn_data_target->remote = conn_data_client;

    conn_data_target->read_timer = NULL;

    /* mysql_stuff/postgresql_stuff structure is same for client and target bufferevent */
    conn_data_target->ms = conn_data_client->ms;

    connect->data = conn_data_target;
    target->data = conn_data_target;

    /* set connnect timeout timer */
    conn_data_target->connect_timer = malloc(sizeof(uv_timer_t));
    uv_timer_init(uv_default_loop(), conn_data_target->connect_timer);
    conn_data_target->connect_timer->data=conn_data_target;
    uv_timer_start(conn_data_target->connect_timer, on_connect_timeout, connect_timeout * 1000, 0);

    return conn_data_target;
}
