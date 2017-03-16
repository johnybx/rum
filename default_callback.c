#include "rum.h"

extern bufpool_t *pool;

void
alloc_cb (uv_handle_t * handle, size_t size, uv_buf_t * buf)
{
    int len = size;             /* Requested buffer size */
    void *ptr = bufpool_acquire (pool, &len);
    *buf = uv_buf_init (ptr, len);

}

void
on_read_disable_read_timeout (uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf)
{
    struct conn_data *conn_data = stream->data;

    /* disable read timeout from server when we receive first data */
    if (conn_data->read_timer) {
        uv_timer_stop (conn_data->read_timer);
        uv_close ((uv_handle_t *) conn_data->read_timer, on_close_timer);
        conn_data->read_timer = NULL;
        /* change callback to on_read() */
        stream->read_cb = on_read;
    }

    on_read(stream, nread, buf);
}

void
on_read (uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf)
{
    struct conn_data *conn_data = stream->data;
    int r;
    uv_stream_t *remote_stream;

    /* if remote stream exist */
    if (conn_data->remote) {
        /* if read return some data */
        if (nread > 0) {
            /* update stats */
            if (conn_data->type == CONN_CLIENT) {
                conn_data->listener->input_bytes += nread;
            } else if (conn_data->type == CONN_TARGET) {
                conn_data->listener->output_bytes += nread;
            }

            /* send data to remote stream */
            uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
            uv_buf_t *sndbuf = malloc (sizeof (uv_buf_t));
            sndbuf->base = buf->base;
            sndbuf->len = nread;
            req->data = sndbuf;
            remote_stream = conn_data->remote->stream;
            r = uv_write (req, remote_stream, sndbuf, 1, on_write);
            if (r) {
                logmsg ("%s: uv_write() failed: %s\n", __FUNCTION__,
                        uv_strerror (r));
                bufpool_release (buf->base);
                free (sndbuf);
                free (req);

                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                if (uv_shutdown (shutdown, stream, on_shutdown)) {
                    free (shutdown);
                }

                return;
            }

            /* we stop reading from input stream immediately when write_queue_size of remote stream is non-zero */
            /* there is tcp buffer so there is definitely some data, no need to buffer more data in rum */
            if (remote_stream->write_queue_size > 0) {
                /* disable reading on input socket */
                conn_data->remote->remote_read_stopped = 1;
                uv_read_stop (stream);
            }

            /* return because we dont want to release buf->base, we will release it in on_write() */
            return;
        } else if (nread < 0) {
            uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));

            if (uv_shutdown (shutdown, stream, on_shutdown)) {
                free (shutdown);
            }
        }                       /* else if (nread==0) {do nothing becaause read() return EAGAIN, just release bufpool} */
    } else {
        /* remote stream doesn't exist, free self */
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));

        if (uv_shutdown (shutdown, stream, on_shutdown)) {
            free (shutdown);
        }

    }

    bufpool_release (buf->base);
}

/* uv_shutdown() callback:
 *  - free all resources
 *  - shutdown opposite stream if exists (if it is still connected/not shutdowned)
 *  - call uv_close()
 */
void
on_shutdown (uv_shutdown_t * shutdown, int status)
{
    struct conn_data *conn_data = shutdown->handle->data;

    /* this can happend when client close connection before server send any data */
    if (conn_data->read_timer) {
        uv_timer_stop (conn_data->read_timer);
        uv_close ((uv_handle_t *) conn_data->read_timer, on_close_timer);
        conn_data->read_timer = NULL;
    }

    /* this can happend when client close connection before server accept connection */
    if (conn_data->connect_timer) {
        uv_timer_stop (conn_data->connect_timer);
        uv_close ((uv_handle_t *) conn_data->connect_timer, on_close_timer);
        conn_data->connect_timer = NULL;
    }

    if (conn_data->mitm) {
        free_mitm (conn_data->mitm);
        if (conn_data->remote && conn_data->remote->mitm) {
            conn_data->remote->mitm = NULL;
        }
    }

    if (conn_data->remote && conn_data->remote->stream) {
        conn_data->remote->remote = NULL;
        uv_read_stop ((uv_stream_t *) conn_data->remote->stream);

        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->remote->stream, on_shutdown)) {
            free (shutdown);
        }
    }

    if (!conn_data->uv_closed) {
        uv_close ((uv_handle_t *) shutdown->handle, on_close);
        conn_data->uv_closed = 1;
    }
    free (shutdown);
}

void
on_connect_timeout (uv_timer_t * timer)
{
    struct conn_data *conn_data = timer->data;

    conn_data->destination->nr_conn++;

    /* release timer */
    uv_timer_stop (timer);
    uv_close ((uv_handle_t *) timer, on_close_timer);

    if (conn_data->destination) {
        logmsg ("timeout connecting to upstream %s", conn_data->destination->s);
    }

    if (conn_data->remote) {
        conn_data->remote->remote = NULL;
    }

    /* close socket */
    conn_data->connect_timer = NULL;
    /* we cannot call here uv_shutdown because it will fail (socket is not connected) */
    conn_data->uv_closed = 1;
    uv_close ((uv_handle_t *) conn_data->stream, on_close);
}

void
on_read_timeout (uv_timer_t * timer)
{
    struct conn_data *conn_data = timer->data;

    /* release timer */
    uv_timer_stop (timer);
    uv_close ((uv_handle_t *) timer, on_close_timer);

    if (conn_data->destination) {
        logmsg ("timeout reading first data from upstream %s", conn_data->destination->s);
    }

    /* shutdown socket */
    conn_data->read_timer = NULL;
    uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
    uv_shutdown (shutdown, conn_data->stream, on_shutdown);
}

void
on_close_timer (uv_handle_t * handle)
{
    free (handle);
}

void
on_close (uv_handle_t * handle)
{
    struct conn_data *conn_data = handle->data;

    if (conn_data->type == CONN_CLIENT) {
        conn_data->listener->nr_conn--;
    } else if (conn_data->type == CONN_TARGET) {
        conn_data->destination->nr_conn--;
    }

    free (handle);
    free (conn_data);
}

void
on_close_listener (uv_handle_t * handle)
{
    free (handle);
}


/* after every write release buffers */
void
on_write (uv_write_t * req, int status)
{
    struct conn_data *conn_data = req->handle->data;

    uv_buf_t *buf = (uv_buf_t *) req->data;

    /* if reading from remote socket was stopped because o non-zero write_queue, reenable reading  */
    if (conn_data->remote_read_stopped && conn_data->remote
        && req->handle->write_queue_size == 0) {
        uv_read_start (conn_data->remote->stream, alloc_cb, on_read);
        conn_data->remote_read_stopped = 0;
    }

    bufpool_release (buf->base);
    free (buf);
    free (req);
}

void
on_write_free (uv_write_t * req, int status)
{
    uv_buf_t *buf = (uv_buf_t *) req->data;
    free (buf->base);
    free (buf);
    free (req);
}


/* only used if we send cache_mysql_init_packet which we dont want to free() */
void
on_write_nofree (uv_write_t * req, int status)
{
    /* Logic which handles the write result */
    uv_buf_t *buf = (uv_buf_t *) req->data;
    free (buf);
    free (req);
}
