#include "rum.h"

extern struct event_base *event_base;
extern struct destination *first_destination;

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


void
postgresql_read_callback (struct bufferevent *bev, void *ptr)
{
    struct bev_arg *bev_arg = ptr;
    size_t len;

    if (bev_arg->remote || (bev_arg->ms && bev_arg->ms->not_need_remote)) {
        struct bufferevent *bev_remote = NULL;

        if (bev_arg->remote) {
            bev_remote = bev_arg->remote->bev;
        }

        len = evbuffer_get_length (bufferevent_get_input (bev));
        if (len) {
            if (bev_arg->type == BEV_CLIENT) {
                bev_arg->listener->input_bytes += len;
            } else if (bev_arg->type == BEV_TARGET) {
                bev_arg->listener->output_bytes += len;
                /* disable read timeout from server when we receive first data */
                if (bev_arg->read_timeout) {
                    bufferevent_set_timeouts (bev, NULL, NULL);
                    bev_arg->read_timeout = 0;
                }

            }
        }

        if (bev_arg->type == BEV_CLIENT) {
            /* first data from client */
            if (pg_handle_init_packet_from_client
                    (bev_arg, bev, len, bev_remote)) {
                    return;
                }
        }

        if (bufferevent_read_buffer (bev, bufferevent_get_output (bev_remote))
            == -1) {
            bev_arg->listener->nr_conn--;

            if (bev_arg->ms) {
                free_ms (bev_arg->ms);
            }

            if (bev_arg->remote) {
                bufferevent_free (bev_remote);
                free (bev_arg->remote);
            }

            bufferevent_free (bev);
            free (bev_arg);

            return;
        }

        /* if remote bufferevent has more data than OUTPUT_BUFFER_LIMIT 
         *  disable EV_READ on ourself and enable write_callback on remote bev
         */
        if (evbuffer_get_length (bufferevent_get_output (bev_remote)) >=
            OUTPUT_BUFFER_LIMIT) {
            bufferevent_disable (bev, EV_READ);
            bufferevent_setcb (bev_remote, postgresql_read_callback,
                               postgresql_write_callback, postgresql_event_callback,
                               (void *) bev_arg->remote);
        }

    } else {
        bev_arg->listener->nr_conn--;

        if (bev_arg->ms) {
            free (bev_arg->ms);
        }

        if (bev_arg->remote) {
            bufferevent_free (bev_arg->remote->bev);
            free (bev_arg->remote);
        }


        bufferevent_free (bev);
        free (bev_arg);

        return;
    }
}

void
postgresql_write_callback (struct bufferevent *bev, void *ptr)
{

    struct bev_arg *bev_arg = ptr;

    if (evbuffer_get_length (bufferevent_get_output (bev)) == 0) {
        if (bev_arg->remote) {
            /* we write all our data to socket,
             * now enable EV_READ on remote socket bufferevent so we can receive data from it
             * and disable write_callback fn for self
             */

            struct bufferevent *bev_remote = bev_arg->remote->bev;

            bufferevent_enable (bev_remote, EV_READ);
            bufferevent_setcb (bev, postgresql_read_callback, NULL,
                               postgresql_event_callback, (void *) bev_arg);
        } else {
            /* if remote socket is closed and we dont have any data in output buffer, free self */

            bev_arg->listener->nr_conn--;

            /* this should be already freed, but to be sure */
            if (bev_arg->ms) {
                free_ms (bev_arg->ms);
                bev_arg->ms = NULL;
            }

            bufferevent_free (bev);
            free (bev_arg);
        }
    }
}

void
postgresql_event_callback (struct bufferevent *bev, short events, void *ptr)
{
    struct bev_arg *bev_arg = ptr;

    /* if remote socket exist */
    if (bev_arg->remote || (bev_arg->ms && bev_arg->ms->not_need_remote)) {
        struct bufferevent *bev_remote = NULL;

        if (bev_arg->remote) {
            bev_remote = bev_arg->remote->bev;
        }

        /* connection to server successful, enable EV_READ */
        if (events & BEV_EVENT_CONNECTED) {
            if (bev_arg->connect_timer) {
                event_free (bev_arg->connect_timer);
                bev_arg->connect_timer = NULL;
            }

            if (server_keepalive) {
                setsockopt(bufferevent_getfd(bev), SOL_SOCKET, SO_KEEPALIVE, &server_keepalive, sizeof(server_keepalive));

                if (server_keepcnt) {
                    setsockopt(bufferevent_getfd(bev), SOL_TCP, TCP_KEEPCNT, &server_keepcnt, sizeof(server_keepcnt));
                }
                if (server_keepidle) {
                    setsockopt(bufferevent_getfd(bev), SOL_TCP, TCP_KEEPIDLE, &server_keepidle, sizeof(server_keepidle));
                }
                if (server_keepintvl) {
                    setsockopt(bufferevent_getfd(bev), SOL_TCP, TCP_KEEPINTVL, &server_keepintvl, sizeof(server_keepintvl));
                }
            }


            bufferevent_enable (bev, EV_READ);
            if (bev_remote)
                bufferevent_enable (bev_remote, EV_READ);

            /* send saved data from client to target*/
            if (pg_handle_auth_with_server
                    (bev_arg, bev, bev_remote)) {
                    return;
                }

            /* setup read timeout for connection from target server */
            if (read_timeout) {
                struct timeval time;
                time.tv_sec = read_timeout;
                time.tv_usec = 0;
                bufferevent_set_timeouts (bev, &time, NULL);
                bev_arg->read_timeout = 1;
            }

            /* error or eof */
        } else if (events &
                   (BEV_EVENT_ERROR | BEV_EVENT_EOF | BEV_EVENT_TIMEOUT)) {
            if (bev_arg->type == BEV_TARGET) {
                if (events & BEV_EVENT_ERROR) {
                    logmsg ("BEV_EVENT_ERROR (postgresql_callback) dest: %s error: %s", bev_arg->destination->s, evutil_socket_error_to_string(evutil_socket_geterror(bufferevent_getfd(bev))));
                } else if (events & BEV_EVENT_TIMEOUT) {
                    logmsg ("BEV_EVENT_TIMEOUT (postgresql_callback) dest: %s", bev_arg->destination->s);
                }
            }
            if (bev_arg->connect_timer) {
                event_free (bev_arg->connect_timer);
                bev_arg->connect_timer = NULL;
            }

            if (bev_arg->connecting) {
                return;
            }

            if (bev_arg->ms) {
                free_ms (bev_arg->ms);
                bev_arg->ms = NULL;
                if (bev_arg->remote) {
                    bev_arg->remote->ms = NULL;
                }
            }

            if (bev_remote) {
                /* if remote socket doesnt have any data in output buffer, free structures and close it */
                if (evbuffer_get_length (bufferevent_get_output (bev_remote))
                    == 0) {
                    bev_arg->listener->nr_conn--;

                    bufferevent_free (bev_remote);
                    free (bev_arg->remote);
                } else {
                    /* if remote socket has still some data in output buffer dont close it
                     * but enable write_callback, it will free self when write all data
                     */
                    bufferevent_free (bev_remote);
                    free (bev_arg->remote);
                    bufferevent_setcb (bev_remote, postgresql_read_callback,
                                       postgresql_write_callback,
                                       postgresql_event_callback,
                                       (void *) bev_arg->remote);
                }
            }

            bufferevent_free (bev);
            free (bev_arg);
        } else {
            logmsg ("unknown events: %d", events);
        }
        /* if remote socket doesnt exist, free self */
    } else {
        logmsg ("remote socket doesnt exist ?");
        if (bev_arg->connect_timer) {
            event_free (bev_arg->connect_timer);
            bev_arg->connect_timer = NULL;
        }

        bev_arg->listener->nr_conn--;

        if (bev_arg->ms) {
            free_ms (bev_arg->ms);
        }

        bufferevent_free (bev);
        free (bev_arg);
    }
}

void
postgresql_connect_timeout_cb (evutil_socket_t fd, short what, void *arg)
{
    struct bev_arg *bev_arg = arg;

    if (bev_arg->connect_timer) {
        event_free (bev_arg->connect_timer);
        bev_arg->connect_timer = NULL;
    }

    if (bev_arg->ms) {
        free_ms (bev_arg->ms);
        bev_arg->ms = NULL;
        bev_arg->remote->ms = NULL;
    }

    if (bev_arg->remote) {
        bufferevent_free (bev_arg->remote->bev);
        free (bev_arg->remote);
    }

    bufferevent_free (bev_arg->bev);
    free (bev_arg);
}
