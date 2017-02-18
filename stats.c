#include "rum.h"

/* when someone connect to statistics -m port, these functions are callbacks for bufferevent with client socket */
/* there is no read_callback fn, because we dont need to read data from client */

extern bufpool_t *pool;
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
        /* if destination is not initialized close connection */
        shutdown = malloc (sizeof (uv_shutdown_t));
        uv_shutdown (shutdown, stream, on_shutdown);
        return;
    }

    len =
        snprintf (tmp, STATS_BUF_SIZE, "{\n\"listeners\": [\n");
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


    for (listener = first_listener; listener; listener = listener->next) {
        if (listener->type == LISTENER_STATS) {
            break;
        }
        len =
            snprintf (tmp, STATS_BUF_SIZE,
                      "  { \"socket\": \"%s\",\n    \"input_bytes\": %u,\n    \"output_bytes\": %u,\n    \"all_connections\": %u,\n    \"current_connections\": %u\n  }%s\n", listener->s,
                      listener->input_bytes, listener->output_bytes,
                      listener->nr_allconn, listener->nr_conn, listener->next?(listener->next->type==LISTENER_STATS?"":","):"");
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

    len =
        snprintf (tmp, STATS_BUF_SIZE, "]\n\"upstreams\": [\n");
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

    for (destination = first_destination; destination; destination= destination->next) {
        len =
            snprintf (tmp, STATS_BUF_SIZE,
                      "  { \"socket\": \"%s\",\n    \"input_bytes\": %u,\n    \"output_bytes\": %u,\n    \"all_connections\": %u,\n    \"current_connections\": %u\n  }%s\n", destination->s,
                      destination->input_bytes, destination->output_bytes,
                      destination->nr_allconn, destination->nr_conn, destination->next?",":"");
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



    len =
        snprintf (tmp, STATS_BUF_SIZE,
                  "],\n\"pool\": {\n  \"used\": %d,\n  \"size\": %d\n  }\n}\n", pool->used, pool->available);
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


    shutdown = malloc (sizeof (uv_shutdown_t));
    uv_shutdown (shutdown, stream, on_shutdown);
}
