#include "rum.h"

extern bufpool_t *pool;
extern struct destination *first_destination;

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
    struct destination *destination = NULL, *dst;
    char *pg_server = NULL, *userptr;
    struct conn_data *conn_data_remote;

    /* username must have at least 2 bytes with \0 at end */
    if (nread < 2 * sizeof (int) + sizeof ("user") + 2) {
        /* check if it is SSLRequest */
        if (nread == 8) {
            char bufx[8];
            char *ptr = bufx;
            int *a, *b;

            memcpy (bufx, uv_buf->base, nread);

            a = (int *) ptr;
            b = (int *) (ptr + sizeof (int));

            if (ntohl (*a) == 8 && ntohl (*b) == 80877103) {
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

                return 1;
            }
        }

        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }
        logmsg ("%s: error: client auth packet too short", __FUNCTION__);

        return 1;
    }

    conn_data->ms->client_auth_packet_len = nread;
    conn_data->ms->client_auth_packet = malloc (nread);
    memcpy (conn_data->ms->client_auth_packet, uv_buf->base, nread);

    userptr =
        conn_data->ms->client_auth_packet + 2 * sizeof (int) + sizeof ("user");
    // TODO
    user_len = strnlen (userptr, nread - 2 * sizeof (int) - sizeof ("user"));
    if (user_len > sizeof (user) - 1) {
        logmsg ("%s: error: user length too long", __FUNCTION__);
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
            uv_close ((uv_handle_t *) conn_data->stream, on_close);
        }
        return 1;
    }
    strncpy (user,
             conn_data->ms->client_auth_packet + 2 * sizeof (int) +
             sizeof ("user"), user_len);
    user[user_len] = '\0';

    get_data_from_cdb_postgresql (user, user_len, &pg_server);

    if (pg_server != NULL) {
        if (first_destination) {
            for (dst = first_destination; dst->next; dst = dst->next) {
                if (!strcmp (dst->s, pg_server)) {
                    destination = dst;
                    break;
                }
            }

            if (!destination) {
                dst->next = destination = malloc (sizeof (struct destination));
                prepareclient (pg_server, destination);
            }
        } else {
            first_destination = destination =
                malloc (sizeof (struct destination));
            prepareclient (pg_server, destination);
        }
    } else {
        /*if user is not found in cdb  sent client error msg & close connection  */
        logmsg ("%s: error: user %s not found in cdb", __FUNCTION__, user);

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

        uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
        uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
        newbuf->base = malloc (buflen);
        newbuf->len = buflen;
        memcpy (newbuf->base, buf, buflen);
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

        if (pg_server)
            free (pg_server);

        return 1;
    }

    /* if remote connection exists free it */
    if (conn_data->remote) {
        logmsg ("%s: error: conn_data->remote is not NULL and should not be",
                __FUNCTION__);
        free (conn_data->remote);
    }

    if (!destination) {
        /* never happen ? */
        logmsg ("%s: error: destination is NULL and should not be",
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
    conn_data->ms->not_need_remote = 0;
    conn_data_remote->ms = conn_data->ms;
    conn_data_remote->listener = conn_data->listener;
    conn_data->ms->handshake = 2;

    if (pg_server)
        free (pg_server);

    uv_read_stop (conn_data->stream);

    return 1;
}
