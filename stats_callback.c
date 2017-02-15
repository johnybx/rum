#include "rum.h"

/* when someone connect to statistics -m port, these functions are callbacks for bufferevent with client socket */
/* there is no read_callback fn, because we dont need to read data from client */

extern struct listener *first_listener;
extern struct destination *first_destination;

#define STATS_BUF_SIZE 8192
void
send_stats_to_client (uv_stream_t * stream)
{
    char tmp[STATS_BUF_SIZE];

    struct listener *listener;
    int len;
    struct destination *destination = first_destination;
    uv_write_t *req;
    uv_buf_t *buf;
    uv_shutdown_t *shutdown;

    if (!destination) {
        return;
    }

    len =
        snprintf (tmp, STATS_BUF_SIZE,
                  "[%20s] [   %10s] [%20s] [%15s] [%18s]\n", "source", "bytes",
                  "destination", "all connections", "actual connections");

    req = (uv_write_t *) malloc (sizeof (uv_write_t));
    buf = malloc (sizeof (uv_buf_t));
    buf->base = malloc (len);
    buf->len = len;
    memcpy (buf->base, tmp, len);
    req->data = buf;
    if (uv_write (req, stream, buf, 1, on_write_free)) {
        logmsg ("%s: uv_write failed", __FUNCTION__);
        free (buf->base);
        free (buf);
        free (req);

        shutdown = malloc (sizeof (uv_shutdown_t));
        uv_shutdown (shutdown, stream, on_shutdown);
        return;
    }


    for (listener = first_listener; listener->next; listener = listener->next) {
        if (listener->type == LISTENER_STATS) {
            break;
        }
        len =
            snprintf (tmp, STATS_BUF_SIZE,
                      "[%20s] [-->%10u] [%20s] [%15u] [%18u]\n", listener->s,
                      listener->input_bytes, destination->s,
                      listener->nr_allconn, listener->nr_conn);
        req = (uv_write_t *) malloc (sizeof (uv_write_t));
        buf = malloc (sizeof (uv_buf_t));
        buf->base = malloc (len);
        buf->len = len;
        memcpy (buf->base, tmp, len);
        req->data = buf;
        if (uv_write (req, stream, buf, 1, on_write_free)) {
            logmsg ("%s: uv_write failed", __FUNCTION__);
            free (buf->base);
            free (buf);
            free (req);

            shutdown = malloc (sizeof (uv_shutdown_t));
            uv_shutdown (shutdown, stream, on_shutdown);
            return;
        }


        len =
            snprintf (tmp, STATS_BUF_SIZE,
                      " %20s  [<--%10u]  %20s   %15s   %18s\n\n", "",
                      listener->output_bytes, "", "", "");
        req = (uv_write_t *) malloc (sizeof (uv_write_t));
        buf = malloc (sizeof (uv_buf_t));
        buf->base = malloc (len);
        buf->len = len;
        memcpy (buf->base, tmp, len);
        req->data = buf;
        if (uv_write (req, stream, buf, 1, on_write_free)) {
            logmsg ("%s: uv_write failed", __FUNCTION__);
            free (buf->base);
            free (buf);
            free (req);

            shutdown = malloc (sizeof (uv_shutdown_t));
            uv_shutdown (shutdown, stream, on_shutdown);
            return;
        }
    }
    shutdown = malloc (sizeof (uv_shutdown_t));
    uv_shutdown (shutdown, stream, on_shutdown);
}
