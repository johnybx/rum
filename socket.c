#include "rum.h"

extern struct destination *first_destination;
extern char *mysql_cdb_file;
extern char *postgresql_cdb_file;

extern char *cache_mysql_init_packet;
extern int cache_mysql_init_packet_len;
extern char *cache_mysql_init_packet_scramble;
extern int mode;
extern SSL_CTX *ctx;
extern SSL_CTX *client_ctx;

int logfd;

extern int connect_timeout;
extern int read_timeout;

/*
 * create_listen_socket return uv_stream
 * arg - tcp:blah:blah alebo sock:blah
 */
uv_stream_t *
create_listen_socket (char *arg, char *sockettype)
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

    *sockettype = type;

    if (type == SOCKET_TCP || type == SOCKET_SSL) {
        uv_os_fd_t fd;
        s = (struct sockaddr *) &sin;
        tcp_t = malloc (sizeof (uv_tcp_t));
        uv_tcp_init_ex (uv_default_loop (), tcp_t, AF_INET);
#if defined(SO_REUSEPORT)
        /* set SO_REUSEPORT so we can bind to tcp port when it is still used by running rum */
        uv_fileno ((uv_handle_t *) tcp_t, &fd);
        int optval = 1;
        setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof (optval));
#endif
    } else if (type == SOCKET_UNIX) {
        s = (struct sockaddr *) &sun;
        pipe_t = malloc (sizeof (uv_pipe_t));
        uv_pipe_init (uv_default_loop (), pipe_t, 0);
    } else {
        usage ();
        _exit (-1);
    }

    if (type == SOCKET_TCP || type == SOCKET_SSL) {
        r = uv_tcp_bind (tcp_t, (const struct sockaddr *) s, 0);
    } else {
        mode_t oldmask = umask(0);
        r = uv_pipe_bind (pipe_t, sun.sun_path);
        umask(oldmask);
    }

    if (r) {
        fprintf (stderr, "bind() to %s failed, exiting\n", arg);
        _exit (-1);
    }

    free (arg_copy);


    if (type == SOCKET_TCP || type == SOCKET_SSL) {
        uv_tcp_nodelay ((uv_tcp_t *) tcp_t, 1);
        return (uv_stream_t *) tcp_t;
    } else {
        return (uv_stream_t *) pipe_t;
    }
}

/* fill destination->sin or destination->sun and destination->socklen
 */
void
prepare_upstream (char *arg, struct destination *destination)
{
    char *arg_copy;
    uint16_t port;
    char *host_str, *port_str, *sockfile_str;
    char type;

    arg_copy = strdup (arg);

    destination->s = strdup (arg);
    destination->next = NULL;
    destination->nr_conn = 0;
    destination->nr_allconn = 0;
    destination->input_bytes = 0;
    destination->output_bytes = 0;

    parse_arg (arg_copy, &type, &destination->sin, &destination->sun,
               &destination->addrlen, &port, &host_str, &port_str,
               &sockfile_str, 0);
    free (arg_copy);
}

/* after successful/not successful connect() */
void
on_outgoing_connection (uv_connect_t * connect, int status)
{
    struct conn_data *conn_data = connect->data;
    int r;
    uv_stream_t *stream = connect->handle;
    struct destination *destination;

    free (connect);

    conn_data->destination->nr_allconn++;
    conn_data->destination->nr_conn++;

    if (conn_data->connect_timer) {
        uv_timer_stop (conn_data->connect_timer);
        uv_close ((uv_handle_t *) conn_data->connect_timer, on_close_timer);
        conn_data->connect_timer = NULL;
    }

    if (status < 0) {
        /* if we hit connect_timeout, we already call uv_close() in on_connect_timeout() */
        /* calling it again will cause segfault */
        if (!conn_data->uv_closed) {
            uv_close ((uv_handle_t *) stream, on_close);
            conn_data->uv_closed = 1;
        }

        if (mode == MODE_NORMAL) {
            logmsg("connection to upstream %s failed (%s)", conn_data->destination->s, uv_strerror (status));
            /* connection failed, close client socket */
            if (conn_data->remote) {
                conn_data->remote->remote = NULL;
                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                uv_shutdown (shutdown, conn_data->remote->stream, on_shutdown);
            }
            return;
        } else if (mode == MODE_FAILOVER || mode == MODE_FAILOVER_R) {
            /* FAILOVER */
            if (conn_data->destination->next) {
                /* select next server for connection */
                logmsg
                    ("failover: connection to %s failed (%s), connecting to next server %s",
                     conn_data->destination->s,
                     uv_strerror (status), conn_data->destination->next->s);
                destination = conn_data->destination->next;
            } else {
                logmsg
                    ("failover: no server available, closing client connection");
                conn_data->remote->remote = NULL;
                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                uv_shutdown (shutdown, conn_data->remote->stream, on_shutdown);
                return;
            }
        }

        if (mode == MODE_FAILOVER || mode == MODE_FAILOVER_R
            || mode == MODE_FAILOVER_RR) {
            struct conn_data *conn_data_target;
            conn_data_target =
                create_server_connection (conn_data->remote, destination,
                                          conn_data->listener);
            if (!conn_data_target) {
                conn_data->remote->remote = NULL;
                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                uv_shutdown (shutdown, conn_data->remote->stream, on_shutdown);
            }
        }

        return;
    }
    conn_data->stream = stream;

    uv_tcp_nodelay ((uv_tcp_t *) stream, 1);
    uv_tcp_keepalive ((uv_tcp_t *) stream, 1, 60);

    /* on successfull connect */
    if (mysql_cdb_file) {
        r = uv_read_start (stream, alloc_cb, mysql_on_read_disable_read_timeout);
    } else if (postgresql_cdb_file) {
        /* if IP is public send ssl request */
        if (!is_private_address(conn_data)) {
            r = uv_read_start (stream, alloc_cb, postgresql_on_read_disable_read_timeout);
            char pgsslrequest[8];
            char *ptr = pgsslrequest;
            int *a, *b;
            a = (int *) ptr;
            b = (int *) (ptr + sizeof (int));
            *a = htonl(8);
            *b = htonl(80877103);

            uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
            uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
            newbuf->base = pgsslrequest;
            newbuf->len = sizeof(pgsslrequest);
            req->data = newbuf;
            conn_data->mitm->handshake = 3;
            if (uv_write (req, stream, newbuf, 1, on_write_nofree)) {
                logmsg ("%s: uv_write(postgresql client_auth_packet) failed",
                        __FUNCTION__);

                free (newbuf);
                free (req);

                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                uv_shutdown (shutdown, stream, on_shutdown);
            }
        } else {
            /* if IP is private send client auth data */
            r = uv_read_start (stream, alloc_cb, on_read_disable_read_timeout);
            /* send server client auth packet */
            if (conn_data->mitm && conn_data->mitm->client_auth_packet) {
                uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
                uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
                newbuf->base = conn_data->mitm->client_auth_packet;
                newbuf->len = conn_data->mitm->client_auth_packet_len;
                req->data = newbuf;
                conn_data->mitm->client_auth_packet = NULL;
                if (uv_write (req, stream, newbuf, 1, on_write_free)) {
                    logmsg ("%s: uv_write(postgresql client_auth_packet) failed",
                            __FUNCTION__);

                    free (newbuf->base);
                    free (newbuf);
                    free (req);

                    uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                    uv_shutdown (shutdown, stream, on_shutdown);
                }
            }

            /* change client callback to on_read if we dont request ssl */
            r = uv_read_start (conn_data->remote->stream, alloc_cb, on_read);
        }
    } else {
        r = uv_read_start (stream, alloc_cb, on_read_disable_read_timeout);

        if (r) {
        }

        /* enable client read */
        r = uv_read_start (conn_data->remote->stream, alloc_cb, on_read);

        if (r) {
        }
    }

    /* set read timeout for server socket */
    conn_data->read_timer = malloc (sizeof (uv_timer_t));
    uv_timer_init (uv_default_loop (), conn_data->read_timer);
    conn_data->read_timer->data = conn_data;
    uv_timer_start (conn_data->read_timer, on_read_timeout,
                    read_timeout * 1000, 0);
}

/*
 * accept() new connection from client
 */
void
on_incoming_connection (uv_stream_t * server, int status)
{
    struct listener *listener = (struct listener *) server->data;
    struct conn_data *conn_data_client, *conn_data_target;
    struct destination *destination = NULL;
    int r;
    uv_stream_t *client;

    if (listener->sockettype == SOCKET_TCP || listener->sockettype == SOCKET_SSL) {
        client = malloc (sizeof (uv_tcp_t));
        uv_tcp_init (uv_default_loop (), (uv_tcp_t *) client);
    } else {
        client = malloc (sizeof (uv_pipe_t));
        uv_pipe_init (uv_default_loop (), (uv_pipe_t *) client, 0);
    }

    if (mode == MODE_NORMAL) {
        destination = first_destination;
    } else if (mode == MODE_FAILOVER || mode == MODE_FAILOVER_R) {
        /* use first but try second in case of fail */
        destination = first_destination;
    }

    if (uv_accept (server, client)) {
        logmsg ("%s: uv_accept failed", __FUNCTION__);
        free (client);
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
    conn_data_client->mitm = NULL;
    conn_data_client->uv_closed = 0;
    conn_data_client->remote_read_stopped = 0;
    conn_data_client->ssl = NULL;
    conn_data_client->ssl_read = NULL;
    conn_data_client->ssl_write = NULL;
    conn_data_client->pending = NULL;

    client->data = conn_data_client;
    conn_data_client->remote = NULL;

    if (listener->type == LISTENER_DEFAULT) {
        if (!mysql_cdb_file && !postgresql_cdb_file) {
            /* no cdb files, classic redirector */
            conn_data_target =
                create_server_connection (conn_data_client, destination,
                                          listener);
            if (!conn_data_target) {
                conn_data_client->remote = NULL;
                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                uv_shutdown (shutdown, conn_data_client->stream, on_shutdown);
            }

            if (listener->sockettype == SOCKET_SSL) {
                enable_server_ssl(conn_data_client);
            }
        } else if (mysql_cdb_file) {
            /* if mysql_cdb is enabled, use different callback functions */
            conn_data_client->mitm = init_mitm ();

            conn_data_client->remote = NULL;
            conn_data_client->mitm->not_need_remote = 1;
            conn_data_client->mitm->handshake = 1;

            /* we use conn_data_client and ms pointers as random data for generating random string filled in init packet send to client */
            /* TODO: use better random input */
            conn_data_client->mitm->scramble1 =
                set_random_scramble_on_init_packet (cache_mysql_init_packet,
                                                    conn_data_client->stream,
                                                    conn_data_client->mitm);

            r = uv_read_start ((uv_stream_t *) client, alloc_cb,
                               mysql_on_read);
            if (r) {
                logmsg ("%s: uv_read_start failed (%s)", __FUNCTION__,
                        uv_strerror (r));
                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                if (uv_shutdown
                    (shutdown, conn_data_client->stream, on_shutdown)) {
                    free (shutdown);
                }

                return;
            }

            uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
            uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
            newbuf->base = cache_mysql_init_packet;
            newbuf->len = cache_mysql_init_packet_len;
            req->data = newbuf;
            if (uv_write (req, client, newbuf, 1, on_write_nofree)) {
                logmsg ("%s: uv_write(cache_mysql_init_packet) failed",
                        __FUNCTION__);
                free (newbuf);
                free (req);

                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                if (uv_shutdown
                    (shutdown, conn_data_client->stream, on_shutdown)) {
                    free (shutdown);
                }
            }

            return;
        } else if (postgresql_cdb_file) {
            /* if postgresql_cdb is enabled, use different callback functions */
            conn_data_client->mitm = init_mitm ();

            conn_data_client->remote = NULL;
            conn_data_client->mitm->not_need_remote = 1;
            conn_data_client->mitm->handshake = 1;

            int r =
                uv_read_start ((uv_stream_t *) client, alloc_cb,
                               postgresql_on_read_disable_read_timeout);
            if (r) {
                logmsg ("%s: uv_read_start failed (%s)", __FUNCTION__,
                        uv_strerror (r));
                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                if (uv_shutdown
                    (shutdown, conn_data_client->stream, on_shutdown)) {
                    free (shutdown);
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
struct conn_data *
create_server_connection (struct conn_data *conn_data_client,
                          struct destination *destination,
                          struct listener *listener)
{
    uv_stream_t *target;
    uv_connect_t *connect;
    struct conn_data *conn_data_target;
    int ret = 0;

    if (destination->s[0] == SOCKET_TCP) {
        target = malloc (sizeof (uv_tcp_t));
        ret = uv_tcp_init (uv_default_loop (), (uv_tcp_t *) target);
        if (ret) {
            logmsg("%s: uv_tcp_init: %s", __FUNCTION__, uv_strerror(ret));
            free (target);
            return NULL;
        }

        connect = (uv_connect_t *) malloc (sizeof (uv_connect_t));
        ret = uv_tcp_connect (connect, (uv_tcp_t *) target,
                        (struct sockaddr *) &destination->sin,
                        on_outgoing_connection);

        if (ret) {
            logmsg("%s: uv_tcp_connect: %s", __FUNCTION__, uv_strerror(ret));
            free (connect);
            uv_close ((uv_handle_t *) target, on_close_handle);
            return NULL;
        }
    } else {
        target = malloc (sizeof (uv_pipe_t));
        ret = uv_pipe_init (uv_default_loop (), (uv_pipe_t *) target, 0);
        if (ret) {
            logmsg("%s: uv_pipe_init: %s", __FUNCTION__, uv_strerror(ret));
            free (target);
            return NULL;
        }

        connect = (uv_connect_t *) malloc (sizeof (uv_connect_t));
        uv_pipe_connect (connect, (uv_pipe_t *) target,
                         destination->sun.sun_path, on_outgoing_connection);
    }

    conn_data_target = malloc (sizeof (struct conn_data));
    conn_data_target->type = CONN_TARGET;
    conn_data_target->connecting = 0;
    conn_data_target->connected = 0;
    conn_data_target->uv_closed = 0;
    conn_data_target->remote_read_stopped = 0;
    conn_data_target->ssl = NULL;
    conn_data_target->ssl_read = NULL;
    conn_data_target->ssl_write = NULL;
    conn_data_target->pending = NULL;
    conn_data_target->destination = destination;
    conn_data_target->failover_first_dst = destination;

    conn_data_client->remote = conn_data_target;

    conn_data_target->listener = listener;
    conn_data_target->stream = target;
    conn_data_target->remote = conn_data_client;

    conn_data_target->read_timer = NULL;

    /* mysql_stuff/postgresql_stuff structure is same for client and target bufferevent */
    conn_data_target->mitm = conn_data_client->mitm;

    connect->data = conn_data_target;
    target->data = conn_data_target;

    /* set connnect timeout timer */
    conn_data_target->connect_timer = malloc (sizeof (uv_timer_t));
    uv_timer_init (uv_default_loop (), conn_data_target->connect_timer);
    conn_data_target->connect_timer->data = conn_data_target;
    uv_timer_start (conn_data_target->connect_timer, on_connect_timeout,
                    connect_timeout * 1000, 0);

    return conn_data_target;
}

int
enable_client_ssl (struct conn_data *conn_data)
{
    conn_data->ssl = SSL_new(client_ctx);
    SSL_set_connect_state(conn_data->ssl);
    conn_data->ssl_read = BIO_new(BIO_s_mem());
    conn_data->ssl_write = BIO_new(BIO_s_mem());
    BIO_set_nbio(conn_data->ssl_read, 1);
    BIO_set_nbio(conn_data->ssl_write, 1);
    SSL_set_bio(conn_data->ssl, conn_data->ssl_read, conn_data->ssl_write);

    int rc = SSL_do_handshake (conn_data->ssl);

    if (rc <= 0) {
        SSL_get_error(conn_data->ssl, rc);
        ERR_print_errors_cb(logmsg_ssl, conn_data);
    }

    flush_ssl(conn_data);

    return 1;
}

int
enable_server_ssl (struct conn_data *conn_data)
{
    conn_data->ssl = SSL_new(ctx);
    SSL_set_accept_state(conn_data->ssl);
    conn_data->ssl_read = BIO_new(BIO_s_mem());
    conn_data->ssl_write = BIO_new(BIO_s_mem());
    BIO_set_nbio(conn_data->ssl_read, 1);
    BIO_set_nbio(conn_data->ssl_write, 1);
    SSL_set_bio(conn_data->ssl, conn_data->ssl_read, conn_data->ssl_write);

    return 1;
}

int
enable_server_ssl_mysql (struct conn_data *conn_data,
                                const uv_buf_t * uv_buf, size_t nread)
{

    enable_server_ssl(conn_data);

    /* sometimes server receive plaintext SSLRequest and SSL data in one read()
     * so lets remove SSLRequest and call again mysql_on_read()
     */
    if (nread > MYSQL_PACKET_HEADER_SIZE + MYSQL_SSL_CONN_REQUEST_PACKET_SIZE) {
        int newlen = nread - (MYSQL_PACKET_HEADER_SIZE + MYSQL_SSL_CONN_REQUEST_PACKET_SIZE);
        char *base = malloc (newlen);
        memcpy(base, uv_buf->base + (MYSQL_PACKET_HEADER_SIZE + MYSQL_SSL_CONN_REQUEST_PACKET_SIZE), nread - (MYSQL_PACKET_HEADER_SIZE + MYSQL_SSL_CONN_REQUEST_PACKET_SIZE));
        uv_buf_t new_uv_buf;
        new_uv_buf.base = base;
        new_uv_buf.len = nread - (MYSQL_PACKET_HEADER_SIZE + MYSQL_SSL_CONN_REQUEST_PACKET_SIZE);
        mysql_on_read (conn_data->stream, new_uv_buf.len, &new_uv_buf);
    }

    return 1;
}

/*
 * read incoming ssl data from buf->base and replace it with unencrypted in buf->base
 */
size_t
handle_ssl (uv_stream_t * stream, ssize_t nread, uv_buf_t * buf)
{
    struct conn_data *conn_data = stream->data;
    BIO_write(conn_data->ssl_read, buf->base, nread);
    ssize_t readbytes = 0;
    while (1)
    {
        /* check for enough space in uv_buf */
        int pending = BIO_pending(conn_data->ssl_read);
        if (readbytes + pending > buf->len) {
            buf->base = realloc(buf->base, readbytes + pending);
            buf->len = readbytes + pending;
        }
        size_t read = 0;
        int rc = SSL_read_ex(conn_data->ssl, buf->base + readbytes, pending, &read);
        readbytes += read;
        if (rc <= 0) {
            int error_rc = SSL_get_error(conn_data->ssl, rc);
            if (error_rc == SSL_ERROR_WANT_READ) {
                int flushed = flush_ssl(conn_data);
                if (flushed == 0) {
                    return readbytes;
                } else if (flushed == -1) {
                    return -1;
                }
            } else {
                ERR_print_errors_cb(logmsg_ssl, conn_data);
                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
                    free (shutdown);
                }

                return -1;
            }
        }
    }
    return readbytes;
}

int flush_ssl(struct conn_data *conn_data) {
    struct pending *p = conn_data->pending;
    /* try to write pending unencrypted data to bio */
    for (p = conn_data->pending; p; p = conn_data->pending) {
        int rc = SSL_write(conn_data->ssl, p->buf->base, p->buf->len);
        if (rc > 0) {
            conn_data->pending = p->next;
            free (p->buf->base);
            free (p->buf);
            free (p);
        } else {
            /* TODO check here for ssl_error ? */
            break;
        }
    }

    /* try to write pending encrypted data to socket */
    int pending = BIO_pending(conn_data->ssl_write);
    if (pending) {
        uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
        uv_buf_t *buf = malloc (sizeof (uv_buf_t));
        buf->base = malloc (pending);
        buf->len = BIO_read (conn_data->ssl_write, buf->base, pending);
        req->data = buf;
        int r = uv_write (req, conn_data->stream, buf, 1, on_write);
        if (r) {
            logmsg ("%s: uv_write() failed: %s\n", __FUNCTION__,
            uv_strerror (r));

            free (buf->base);
            free (buf);
            free (req);

            uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
            if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
                free (shutdown);
            }
            return -1;
        }
    }

    return pending;
}

/* check if ip address of remote is from private space */
char *get_ip(struct conn_data *conn_data) {
    struct sockaddr_storage sa;
    int sa_size = sizeof (struct sockaddr_storage);
    char ip[INET6_ADDRSTRLEN];
    uv_tcp_getpeername((uv_tcp_t *) conn_data->stream, (struct sockaddr *)&sa, &sa_size);
    switch(sa.ss_family) {
        case AF_INET: {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)&sa;
            inet_ntop(AF_INET, &(addr_in->sin_addr), (char *) &ip, INET_ADDRSTRLEN);

            return strdup(ip);
        }
        case AF_INET6: {
            /* TODO: we dont have ipv6 yet */
            return NULL;
        }
    }

    return NULL;
}
int is_private_address(struct conn_data *conn_data) {
    struct sockaddr_storage sa;
    int sa_size = sizeof (struct sockaddr_storage);
    char ip[INET6_ADDRSTRLEN];
    uv_tcp_getpeername((uv_tcp_t *) conn_data->stream, (struct sockaddr *)&sa, &sa_size);
    switch(sa.ss_family) {
        case AF_INET: {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)&sa;
            inet_ntop(AF_INET, &(addr_in->sin_addr), (char *) &ip, INET_ADDRSTRLEN);
            if (strstr(ip, "10.") == ip || strstr(ip, "172.16.") == ip || strstr(ip, "192.168.0") == ip) {
                return 1;
            } else {
                return 0;
            }
            break;
        }
        case AF_INET6: {
            /* TODO: we dont have ipv6 yet */
            return 0;
        }
    }

    return 0;
}
