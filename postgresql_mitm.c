#include "rum.h"

extern struct event_base *event_base;

extern struct destination *first_destination;

extern int connect_timeout;
extern int read_timeout;

int
pg_handle_init_packet_from_client (struct bev_arg *bev_arg,
                                struct bufferevent *bev, int len,
                                struct bufferevent *bev_remote)
{
    char user[64];
    char buf[512];
    char buf1[512];
    char buf2[512];
    char buf3[512];
    char buf4[512];
    int user_len, buflen, buflen_htonl, buf1len, buf2len, buf3len, buf4len;
    struct bev_arg *bev_arg_remote;
    struct destination *destination = NULL, *dst;
    char *pg_server = NULL, *userptr;

    if (len < 2*sizeof(int) + sizeof("user")) {
        /* check if it is SSLRequest */
        if (len == 8) {
            char bufx[8];
            char *ptr=bufx;
            int *a,*b;

            evbuffer_copyout (bufferevent_get_input (bev),
                          bufx, len);

            evbuffer_drain (bufferevent_get_input (bev), len);

            a=(int *)ptr;
            b=(int *)(ptr+sizeof(int));

            if (ntohl(*a) == 8 && ntohl(*b) == 80877103) {
                /* send client that we dont support SSL */
                bufferevent_write (bev, "N", 1);
                return 1;
            }
        }

        bev_arg->listener->nr_conn--;

        free_ms (bev_arg->ms);
        bev_arg->ms = NULL;

        if (bev_arg->remote) {
            bev_arg->remote->ms = NULL;
            bufferevent_free (bev_arg->remote->bev);
            free (bev_arg->remote);
        }

        bufferevent_free (bev);
        free (bev_arg);

        return 1;
    }

    bev_arg->ms->client_auth_packet = malloc (len);
    bev_arg->ms->client_auth_packet_len = len;

    evbuffer_copyout (bufferevent_get_input (bev),
                      bev_arg->ms->client_auth_packet, len);
    evbuffer_drain (bufferevent_get_input (bev), len);

    userptr =
        bev_arg->ms->client_auth_packet + 2 * sizeof(int) +
        sizeof("user");
    user_len = strlen (userptr);
    if (user_len > sizeof (user)) {
        user_len = sizeof (user);
    }
    strncpy (user,
             bev_arg->ms->client_auth_packet + 2 * sizeof(int) +
             sizeof("user"), user_len);
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
            first_destination = destination = malloc (sizeof (struct destination));
            prepareclient (pg_server, destination);
        }
    } else {
        /* if user is not found in cdb we use mysql server set with -d argument
         * but connection will not be successful, we need user encrypted password which should be in cdb file
         */
        destination = first_destination;

        logmsg("user %s not found in cdb\n", user);
        /* we reply access denied  */
        //memcpy (buf, ERR_LOGIN_PACKET_PREFIX, sizeof(ERR_LOGIN_PACKET_PREFIX));

        memset(buf, '\0', sizeof(buf));
        buf[0]='E';
        buf1len = snprintf (buf1, sizeof(buf1), "SFATAL");
        buf2len = snprintf (buf2, sizeof(buf2), "C28P01");
        buf3len = snprintf (buf3, sizeof(buf3), "MUser \"%s\" not found", user);
        buf4len = snprintf (buf4, sizeof(buf4), "Rauth_failed");
        buflen = 1 + 4 + buf1len + 1 + buf2len + 1 + buf3len + 1 + buf4len + 1 + 1;
        buflen_htonl = htonl(buflen - 1);
        memcpy (buf + 1, &buflen_htonl, sizeof(buflen_htonl));
        memcpy (buf + 1 + 4, buf1, buf1len);
        memcpy (buf + 1 + 4 + buf1len + 1, buf2, buf2len);
        memcpy (buf + 1 + 4 + buf1len + 1 + buf2len + 1, buf3, buf3len);
        memcpy (buf + 1 + 4 + buf1len + 1 + buf2len + 1 + buf3len + 1, buf4, buf4len);
        bufferevent_write (bev, buf, buflen);

        /* enable write_callback so we close connection in case client doesn't */
        bufferevent_setcb (bev, postgresql_read_callback, postgresql_write_callback,
                           postgresql_event_callback, (void *) bev_arg);

        if (pg_server)
            free (pg_server);

        return 1;
    }

    /* if remote connection exists free it */
    if (bev_arg->remote) {
        bufferevent_free (bev_arg->remote->bev);
        free (bev_arg->remote);
    }

    bev_remote =
        bufferevent_socket_new (event_base, -1, BEV_OPT_CLOSE_ON_FREE);

    if (!bev_remote || !destination) {
        free_ms (bev_arg->ms);
        bev_arg->ms = NULL;
        bufferevent_free (bev);
        free (bev_arg);
        if (pg_server)
            free (pg_server);

        return 1;
    }

    bev_arg_remote = malloc (sizeof (struct bev_arg));

    bev_arg_remote->bev = bev_remote;

    bev_arg->remote = bev_arg_remote;
    bev_arg_remote->remote = bev_arg;
    bev_arg->ms->not_need_remote = 0;

    bev_arg_remote->type = BEV_TARGET;

    bev_arg_remote->ms = bev_arg->ms;
    bev_arg_remote->listener = bev_arg->listener;

    bev_arg->ms->handshake = 2;

    bev_arg_remote->read_timeout = 0;

    bev_arg_remote->connecting = 0;

    bufferevent_setcb (bev_remote, postgresql_read_callback, NULL,
                       postgresql_event_callback, (void *) bev_arg_remote);

    bufferevent_disable (bev, EV_READ);

    bufferevent_setwatermark (bev_remote, EV_READ, 0, INPUT_BUFFER_LIMIT);
    bev_arg_remote->connecting = 1;
    bev_arg_remote->destination = destination;

    if (bufferevent_socket_connect
        (bev_remote, (struct sockaddr *) &destination->sin,
         destination->addrlen) == -1) {
        logmsg ("bufferevent_socket_connect return -1 (full fd?)\n");
        /* this if is needed here, because if connect() fails libevent will call mysql_event_callback
         * immediately, and not from main event loop. so bev_arg->ms can be already freed
         */

        if (bev_arg->ms) {
            free_ms (bev_arg->ms);
            bev_arg->ms = NULL;
        }

        if (bev_arg->remote) {
            bufferevent_free (bev_arg->remote->bev);
            bev_arg->remote->ms = NULL;
            free (bev_arg->remote);
        }

        bufferevent_free (bev);
        free (bev_arg);

        if (pg_server)
            free (pg_server);

        return 1;
    }
    bev_arg_remote->connecting = 0;
    struct linger l;
    int flag = 1;

    l.l_onoff = 1;
    l.l_linger = 0;
    setsockopt (bufferevent_getfd (bev_remote), SOL_SOCKET, SO_LINGER,
                (void *) &l, sizeof (l));
    setsockopt (bufferevent_getfd (bev_remote), IPPROTO_TCP, TCP_NODELAY,
                (char *) &flag, sizeof (int));

    if (pg_server)
        free (pg_server);

    /* connect timeout timer */
    struct timeval time;
    time.tv_sec = connect_timeout;
    time.tv_usec = 0;

    bev_arg_remote->connect_timer =
        event_new (event_base, -1, 0, postgresql_connect_timeout_cb,
                   bev_arg_remote);
    if (bev_arg_remote->connect_timer) {
        event_add (bev_arg_remote->connect_timer, &time);
    }

    return 1;
}

int
pg_handle_auth_with_server (struct bev_arg *bev_arg, struct bufferevent *bev,
                         struct bufferevent *bev_remote)
{
    if (bufferevent_write
        (bev, bev_arg->ms->client_auth_packet,
         bev_arg->ms->client_auth_packet_len) == -1) {
        bev_arg->listener->nr_conn--;

        free_ms (bev_arg->ms);
        bev_arg->ms = NULL;
        if (bev_arg->remote) {
            bev_arg->remote->ms = NULL;
            bufferevent_free (bev_arg->remote->bev);
            free (bev_arg->remote);
        }

        bufferevent_free (bev);
        free (bev_arg);

        return 1;
    }

    free_ms (bev_arg->ms);
    bev_arg->ms = NULL;
    bev_arg->remote->ms = NULL;

    bufferevent_setcb (bev, read_callback, NULL, event_callback,
                       (void *) bev_arg);
    bufferevent_setcb (bev_remote, read_callback, NULL, event_callback,
                       (void *) bev_arg->remote);

    bufferevent_enable (bev_remote, EV_READ);

    return 1;
}
