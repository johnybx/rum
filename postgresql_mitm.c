#include "rum.h"

extern struct destination *first_destination;
extern int loglogins;
extern int server_ssl;
extern int geoip;
extern bool external_lookup;
extern char *external_lookup_url;

int
pg_handle_init_packet_from_client (struct conn_data *conn_data,
                                   const uv_buf_t * uv_buf, size_t nread)
{
    char user[64];
    size_t user_len;
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

    if (!conn_data->mitm->client_auth_packet) {
        conn_data->mitm->client_auth_packet_len = nread;
        conn_data->mitm->client_auth_packet = malloc (nread);
        memcpy (conn_data->mitm->client_auth_packet, uv_buf->base, nread);
    }

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
    if (!conn_data->mitm->user) {
        conn_data->mitm->user = strdup(user);
    }

    if (geoip && conn_data->stream->type == UV_TCP) {
        ip_mask_pair_t* allowed_ips = NULL;
        geo_country_t* allowed_countries = NULL;

        if (conn_data->mitm->data && conn_data->mitm->data_len) {
            /* decode json and use that data as cdb value */
            struct json_object *jobj = json_tokener_parse(conn_data->mitm->data);
            if (jobj) {
                int data_len=json_object_get_string_len(jobj);
                const char *data = json_object_get_string(jobj);

                get_data_from_curl_postgresql (data_len, data,
                                               user, user_len, &pg_server, &allowed_ips, &allowed_countries);

                json_object_put(jobj);
            } else {
                logmsg("cannot decode json from str (%s)", conn_data->mitm->data);
            }
        } else {
            get_data_from_cdb_postgresql (user, user_len, &pg_server, &allowed_ips, &allowed_countries);
        }

        struct sockaddr_in peer;
        int peer_len = sizeof(peer);
        int allowed = 1;

        if (0 == uv_tcp_getpeername((uv_tcp_t*) conn_data->stream, (struct sockaddr*) &peer, &peer_len)) {
            bool ip_check = !allowed_ips || ip_in_networks(peer.sin_addr.s_addr, allowed_ips);
            bool country_check = !allowed_countries || ip_in_countries((struct sockaddr *) &peer, allowed_countries);

            if ((allowed_ips && !ip_check) || (allowed_countries && !country_check)) {
                allowed = 0;
            }

            if (allowed_ips) {
                free (allowed_ips);
            }

            if (allowed_countries) {
                free (allowed_countries);
            }

            if (!allowed) {
                if (pg_server)
                    free (pg_server);

                logmsg("Disconnected %s from %s, country check: %u, ip check: %u failed", user, get_ipport(conn_data), country_check, ip_check);
                send_postgres_error(conn_data, "MAccess denied, login from unauthorized ip or country");

                return 1;
            }
        }
    } else {
        if (conn_data->mitm->data && conn_data->mitm->data_len) {
            /* decode json and use that data as cdb value */
            struct json_object *jobj = json_tokener_parse(conn_data->mitm->data);
            if (jobj) {
                int data_len=json_object_get_string_len(jobj);
                const char *data = json_object_get_string(jobj);

                get_data_from_curl_postgresql (data_len, data,
                                               user, user_len, &pg_server, NULL, NULL);

                json_object_put(jobj);
            } else {
                logmsg("cannot decode json from str (%s)", conn_data->mitm->data);
            }
        } else {
            get_data_from_cdb_postgresql (user, user_len, &pg_server, NULL, NULL);
        }
    }

    if (pg_server != NULL) {
        if (conn_data->mitm->data && conn_data->mitm->data_len && is_this_rackunit(pg_server)) {
            logmsg ("ext api set postgresql_server this rackunit (%s) for user %s from %s%s", pg_server, user, get_ipport (conn_data), get_sslinfo (conn_data));

            send_postgres_error(conn_data, "MAccess denied, loop detected");

            if (pg_server)
                free (pg_server);

            return 1;
        }
        destination = add_destination(pg_server);
    } else {
        if (external_lookup && external_lookup_url && !conn_data->mitm->curl_handle) {
            uv_read_stop(conn_data->stream);
            make_curl_request(conn_data, user);
            return 1;
        }

        /* if user is not found in cdb, sent client error msg & close connection  */
        logmsg ("user %s not found in cdb from %s%s", user, get_ipport (conn_data), get_sslinfo (conn_data));

        send_postgres_error(conn_data, "MUser \"%s\" not found", user);

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
        logmsg ("%s: failed to create remote server connection", __FUNCTION__);
        if (pg_server)
            free (pg_server);

        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }

        return 1;
    }


    if (loglogins) {
        logmsg ("user %s login from %s%s, upstream: %s", user, get_ipport (conn_data), get_sslinfo (conn_data), pg_server);
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

void send_postgres_error(struct conn_data* conn_data, const char* fmt, ...)
{
    char buf[512];
    char buf1[512];
    char buf2[512];
    char buf3[512];
    char buf4[512];
    int buflen, buflen_htonl, buf1len, buf2len, buf3len, buf4len;

    memset (buf, '\0', sizeof (buf));
    buf[0] = 'E';
    buf1len = snprintf (buf1, sizeof (buf1), "SFATAL");
    buf2len = snprintf (buf2, sizeof (buf2), "C28P01");

    va_list ap;
    va_start(ap, fmt);

    buf3len =
            vsnprintf (buf3, sizeof (buf3), fmt, ap);
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
    }
}
