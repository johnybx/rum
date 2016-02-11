#include "rum.h"

extern struct event_base *event_base;
extern int mode;

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
 * if some data are in input buffer, copy it to remote bufferevent output buffer
 */
void
read_callback (struct bufferevent *bev, void *ptr)
{
    struct bev_arg *bev_arg = ptr;
    size_t len;

    /* if remote bufferevent exist */
    if (bev_arg->remote) {
        struct bufferevent *bev_remote = bev_arg->remote->bev;

        /* update stats */
        len = evbuffer_get_length (bufferevent_get_input (bev));
        if (len) {
            /* update stats */
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

        /* write data from our intput buffer to remote output buffer */
        //if (bufferevent_read_buffer(bev, bufferevent_get_output(bev_remote))==-1) {
        if (bufferevent_write_buffer (bev_remote, bufferevent_get_input (bev))
            == -1) {
            /* if error, close our socket, remote socket and free everything */
            bev_arg->listener->nr_conn--;

            bufferevent_free (bev);
            bufferevent_free (bev_remote);
            free (bev_arg->remote);
            free (bev_arg);

            return;
        }

        /* If remote bufferevent has more data than OUTPUT_BUFFER_LIMIT 
         * disable EV_READ on our bev and enable write_callback on remote bev.
         * We enable EV_READ again when all data on remote socket buffer are written,
         * this is done in write_callback() when remote socket write event is triggered.
         */
        if (evbuffer_get_length (bufferevent_get_output (bev_remote)) >=
            OUTPUT_BUFFER_LIMIT) {
            bufferevent_disable (bev, EV_READ);
            bufferevent_setcb (bev_remote, read_callback, write_callback,
                               event_callback, (void *) bev_arg->remote);
        }
    } else {
        /* remote socket is closed, free self */
        bev_arg->listener->nr_conn--;

        bufferevent_free (bev);
        free (bev_arg);
    }
}

/* if data are sent from output buffer of bev, this function is called,
 * it is not active all the time, but only in some situations (bev has too many data in output buffer)
 * we can find out if all data are written to network and free memory
 */
void
write_callback (struct bufferevent *bev, void *ptr)
{
    struct bev_arg *bev_arg = ptr;

    /* if bufferevent send all data to socket */
    if (evbuffer_get_length (bufferevent_get_output (bev)) == 0) {
        /* if remote socket exist */
        if (bev_arg->remote) {
            /*
             * now enable EV_READ on remote socket bufferevent so we can receive data from it
             * and disable write_callback fn for self
             */
            struct bufferevent *bev_remote = bev_arg->remote->bev;

            bufferevent_enable (bev_remote, EV_READ);
            bufferevent_setcb (bev, read_callback, NULL, event_callback,
                               (void *) bev_arg);
        } else {
            /* if remote socket is closed and we dont have any data in output buffer, free self */
            bev_arg->listener->nr_conn--;

            bufferevent_free (bev);
            free (bev_arg);
        }
    }
}

void
event_callback (struct bufferevent *bev, short events, void *ptr)
{
    struct bev_arg *bev_arg = ptr;
//    struct bufferevent *bev_target;

    /* if remote socket exist */
    if (bev_arg->remote) {
        struct bufferevent *bev_remote = bev_arg->remote->bev;

        /* connection to remote host is successful, enable EV_READ */
        if (events & BEV_EVENT_CONNECTED) {
            if (bev_arg->connect_timer) {
                event_free (bev_arg->connect_timer);
                bev_arg->connect_timer = NULL;
            }
            bev_arg->connected=1;

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
            bufferevent_enable (bev_remote, EV_READ);

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
                    logmsg ("BEV_EVENT_ERROR dest: %s\n", bev_arg->destination->s);
                } else if (events & BEV_EVENT_TIMEOUT) {
                    logmsg ("BEV_EVENT_TIMEOUT dest: %s\n", bev_arg->destination->s);
                }

            }

            if (bev_arg->connect_timer) {
                event_free (bev_arg->connect_timer);
                bev_arg->connect_timer = NULL;
            }

            if (bev_arg->connecting) {
                /* this code is called from another event function, return immediately and dont free anything 
                 * this is probably a bug in libevent, in evbuffer_socket_connect() when connect() fail event_callback is directly called
                 */
                return;
            }
            bufferevent_free (bev);

            /* failover */
            if (bev_arg->type==BEV_TARGET && !bev_arg->connected && (mode == MODE_FAILOVER || mode == MODE_FAILOVER_RR || mode == MODE_FAILOVER_R) && (events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT))) {
                if (bev_arg->connect_timer) {
                    event_free (bev_arg->connect_timer);
                    bev_arg->connect_timer = NULL;
                }

                return failover(bev_arg);
            }

            /* if remote socket doesnt have any data in output buffer, free structures and close it */
            if (evbuffer_get_length (bufferevent_get_output (bev_remote)) == 0) {
                bufferevent_free (bev_remote);
                free (bev_arg->remote);

                bev_arg->listener->nr_conn--;
            } else {
                /* if remote socket has still some data in output buffer dont close it
                 * but enable write_callback, it will free self when write all data
                 */
                bev_arg->remote->remote = NULL;
                bufferevent_setcb (bev_remote, read_callback, write_callback,
                                   event_callback, (void *) bev_arg->remote);
            }

            free (bev_arg);
        } else {
            logmsg ("unknown events: %d\n", events);
        }
    } else {
        logmsg ("remote socket doesnt exist ?\n");

        if (bev_arg->connect_timer) {
            event_free (bev_arg->connect_timer);
            bev_arg->connect_timer = NULL;
        }

        bufferevent_free (bev);

        /* if remote socket doesnt exist, free self and close socket */
        bev_arg->listener->nr_conn--;
        free (bev_arg);
    }
}

void
connect_timeout_cb (evutil_socket_t fd, short what, void *arg)
{
    struct bev_arg *bev_arg = arg;

    if (bev_arg->destination) {
        logmsg ("connection timeout to %s\n", bev_arg->destination->s);
    } else {
        logmsg ("connection timeout to unknown\n");
    }

    if (bev_arg->connect_timer) {
        event_free (bev_arg->connect_timer);
        bev_arg->connect_timer = NULL;
    }

    /* failover */
    if (bev_arg->type==BEV_TARGET && (mode == MODE_FAILOVER || mode == MODE_FAILOVER_RR || mode == MODE_FAILOVER_R)) {
        bufferevent_free(bev_arg->bev);
        return failover(bev_arg);
    }

    if (bev_arg->remote) {
        bufferevent_free (bev_arg->remote->bev);
        free (bev_arg->remote);
    }

    bufferevent_free (bev_arg->bev);
    free (bev_arg);
}
