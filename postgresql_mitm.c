#include "rum.h"

extern struct destination *first_destination;
extern int loglogins;
extern int server_ssl;

int
pg_handle_init_packet_from_client (struct conn_data *conn_data,
                                   const uv_buf_t * uv_buf, size_t nread)
{
    char user[64];
    char buf[512];
    char buf1[512];
    char buf2[512];
    char buf3[512];
    char buf4[512];
    int user_len, buflen, buflen_htonl, buf1len, buf2len, buf3len, buf4len;
    struct destination *destination = NULL;
    char *pg_server = NULL, *userptr;
    struct conn_data *conn_data_remote;

    /* username must have at least 2 bytes with \0 at end */
    if (nread < 2 * sizeof (int) + sizeof ("user")) {
        /* check if it is SSLRequest */
        if (nread == 8) {
            char bufx[8];
            char *ptr = bufx;
            int *a, *b;

            memcpy (bufx, uv_buf->base, nread);

            a = (int *) ptr;
            b = (int *) (ptr + sizeof (int));

            if (ntohl (*a) == 8 && ntohl (*b) == 80877103) {
                if (!server_ssl) {
                    /* send client that we dont support SSL */
                    uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
                    uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
                    newbuf->base = malloc (1);
                    newbuf->base[0] = 'N';
                    newbuf->len = 1;
                    req->data = newbuf;
                    if (uv_write
                        (req, conn_data->stream, newbuf, 1, on_write_free)) {
                        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
                            free (shutdown);
                        }
                    }
                } else {
                    uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
                    uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
                    newbuf->base = malloc (1);
                    newbuf->base[0] = 'S';
                    newbuf->len = 1;
                    req->data = newbuf;
                    if (uv_write
                        (req, conn_data->stream, newbuf, 1, on_write_free)) {
                        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
                            free (shutdown);
                        }
                    }
                    return enable_server_ssl(conn_data);
                }
                return 1;
            }
        }

        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }
        logmsg ("%s: client auth packet too short", __FUNCTION__);

        return 1;
    }

    conn_data->mitm->client_auth_packet_len = nread;
    conn_data->mitm->client_auth_packet = malloc (nread);
    memcpy (conn_data->mitm->client_auth_packet, uv_buf->base, nread);

    userptr =
        conn_data->mitm->client_auth_packet + 2 * sizeof (int) + sizeof ("user");
    user_len = strnlen (userptr, nread - 2 * sizeof (int) - sizeof ("user"));
    if (user_len > sizeof (user) - 1) {
        logmsg ("%s: user length too long", __FUNCTION__);
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
            uv_close ((uv_handle_t *) conn_data->stream, on_close);
        }
        return 1;
    }
    strncpy (user,
             conn_data->mitm->client_auth_packet + 2 * sizeof (int) +
             sizeof ("user"), user_len);
    user[user_len] = '\0';

    get_data_from_cdb_postgresql (user, user_len, &pg_server);

    if (pg_server != NULL) {
        destination = add_destination(pg_server);

        if (loglogins) {
          struct sockaddr_in sa_in;
          int sa_size = sizeof (struct sockaddr_in);
          char *ip = NULL;
          if (conn_data->listener->s[0]=='t') {
            uv_tcp_getpeername((uv_tcp_t *) conn_data->stream, (struct sockaddr *)&sa_in, &sa_size);
            ip = inet_ntoa(sa_in.sin_addr);

            char ssl[512];
            if (conn_data->ssl) {
                int reused = SSL_session_reused (conn_data->ssl);

                snprintf(ssl, sizeof(ssl), " (ssl%s %s)", (reused?" reused":""), SSL_get_cipher_name(conn_data->ssl));
            } else {
                snprintf(ssl, sizeof(ssl), "");
            }

            logmsg ("user %s login from %s%s", user, ip, ssl);
          } else {
            logmsg ("user %s login from socket", user);
          }
        }
    } else {
        /* if user is not found in cdb, sent client error msg & close connection  */
        logmsg ("user %s not found in cdb (ssl: %s)", user, (conn_data->ssl?"true":"false"));

        memset (buf, '\0', sizeof (buf));
        buf[0] = 'E';
        buf1len = snprintf (buf1, sizeof (buf1), "SFATAL");
        buf2len = snprintf (buf2, sizeof (buf2), "C28P01");
        buf3len =
            snprintf (buf3, sizeof (buf3), "MUser \"%s\" not found", user);
        buf4len = snprintf (buf4, sizeof (buf4), "Rauth_failed");
        buflen =
            1 + 4 + buf1len + 1 + buf2len + 1 + buf3len + 1 + buf4len + 1 + 1;
        buflen_htonl = htonl (buflen - 1);
        memcpy (buf + 1, &buflen_htonl, sizeof (buflen_htonl));
        memcpy (buf + 1 + 4, buf1, buf1len);
        memcpy (buf + 1 + 4 + buf1len + 1, buf2, buf2len);
        memcpy (buf + 1 + 4 + buf1len + 1 + buf2len + 1, buf3, buf3len);
        memcpy (buf + 1 + 4 + buf1len + 1 + buf2len + 1 + buf3len + 1, buf4,
                buf4len);

        if (conn_data->ssl) {
            int rc = SSL_write(conn_data->ssl, buf, buflen);
            if (rc > 0) {
                flush_ssl(conn_data);
            }
        } else {
            uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
            newbuf->base = malloc (buflen);
            newbuf->len = buflen;
            memcpy (newbuf->base, buf, buflen);

            uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
            req->data = newbuf;
            if (uv_write (req, conn_data->stream, newbuf, 1, on_write_free)) {
                free (newbuf->base);
                free (newbuf);
                free (req);
                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
                    free (shutdown);
                }
            }
        }

        if (pg_server)
            free (pg_server);

        return 1;
    }

    /* if remote connection exists free it */
    if (conn_data->remote) {
        logmsg ("%s: conn_data->remote is not NULL and should not be",
                __FUNCTION__);
        free (conn_data->remote);
    }

    if (!destination) {
        /* never happen ? */
        logmsg ("%s: destination is NULL and should not be",
                __FUNCTION__);
        if (pg_server)
            free (pg_server);

        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }

        return 1;
    }

    conn_data_remote =
        create_server_connection (conn_data, destination, conn_data->listener);
    if (!conn_data_remote) {
        if (pg_server)
            free (pg_server);

        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }

        return 1;
    }

    conn_data->mitm->not_need_remote = 0;
    conn_data_remote->mitm = conn_data->mitm;
    conn_data_remote->listener = conn_data->listener;
    conn_data->mitm->handshake = 2;

    if (pg_server)
        free (pg_server);

    uv_read_stop (conn_data->stream);

    return 1;
}
