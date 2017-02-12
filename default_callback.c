#include "rum.h"

extern bufpool_t *pool;

void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    int len = size; /* Requested buffer size */
    void *ptr = bufpool_acquire(pool, &len);
    *buf = uv_buf_init(ptr, len);

}

void
on_read (uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    struct bev_arg *bev_arg = stream->data;
    int r;
    uv_stream_t *remote_stream;

    /* disable read timeout from server when we receive first data */
    if (bev_arg->read_timer) {
        uv_timer_stop(bev_arg->read_timer);
        uv_close((uv_handle_t *)bev_arg->read_timer, on_close_timer);
        bev_arg->read_timer = NULL;
    }

    /* if remote stream exist */
    if (bev_arg->remote) {
        /* if read return some data */
        if (nread > 0) {
            /* update stats */
            if (bev_arg->type == BEV_CLIENT) {
                bev_arg->listener->input_bytes += nread;
            } else if (bev_arg->type == BEV_TARGET) {
                bev_arg->listener->output_bytes += nread;
            }

            /* send data to remote stream */
            uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
            uv_buf_t *sndbuf = malloc(sizeof(uv_buf_t));
            sndbuf->base = buf->base;
            sndbuf->len = nread;
            req->data = sndbuf;
            remote_stream = bev_arg->remote->stream;
            r = uv_write(req, remote_stream, sndbuf, 1, on_write);
            if (r) {
                logmsg("on_read(): uv_write() failed: %s\n", uv_strerror(r));
                bufpool_release(buf->base);
                free(sndbuf);
                free(req);

                uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
                if (uv_shutdown(shutdown, stream, on_shutdown)) {
                    free(shutdown);
                }

                return;
            }

            /* we stop reading from input stream immediately when write_queue_size of remote stream is non-zero */
            /* there is tcp buffer so there is definitely some data, no need to buffer more data in rum */
            if (remote_stream->write_queue_size > 0) {
                /* disable reading on input socket */
                bev_arg->remote->read_stopped=1;
                uv_read_stop(stream);
            }

            /* return because we dont want to release buf->base, we will release it in on_write() */
            return;
        } else if (nread < 0) {
            uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));

            if (uv_shutdown(shutdown, stream, on_shutdown)) {
                free(shutdown);
            }
        } /* else if (nread==0) {do nothing becaause read() return EAGAIN, just release bufpool} */
    } else {
        /* remote stream doesn't exist, free self */
        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
 
        if (uv_shutdown(shutdown, stream, on_shutdown)) {
            free(shutdown);
        }

    }

    bufpool_release(buf->base);
}

/* uv_shutdown() callback:
 *  - free all resources
 *  - shutdown opposite stream if exists (if it is still connected/not shutdowned)
 *  - call uv_close()
 */
void on_shutdown(uv_shutdown_t *shutdown, int status)
{
    struct bev_arg *bev_arg = shutdown->handle->data;

    /* this can happend when client close connection before server send any data */
    if (bev_arg->read_timer) {
        uv_timer_stop(bev_arg->read_timer);
        uv_close((uv_handle_t *)bev_arg->read_timer, on_close_timer);
        bev_arg->read_timer = NULL;
    }

    /* this can happend when client close connection before server accept connection */
    if (bev_arg->connect_timer) {
        uv_timer_stop(bev_arg->connect_timer);
        uv_close((uv_handle_t *)bev_arg->connect_timer, on_close_timer);
        bev_arg->connect_timer = NULL;
    }

    if (bev_arg->ms) {
        free_ms (bev_arg->ms);
        if (bev_arg->remote && bev_arg->remote->ms) {
            bev_arg->remote->ms = NULL;
        }
    }

    if (bev_arg->remote && bev_arg->remote->stream) {
        bev_arg->remote->remote = NULL;
        uv_read_stop((uv_stream_t *)bev_arg->remote->stream);

        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        if (uv_shutdown(shutdown, bev_arg->remote->stream, on_shutdown)) {
            free(shutdown);
        }
    }

    uv_close((uv_handle_t *)shutdown->handle, on_close);
    free(shutdown);
}

void on_connect_timeout (uv_timer_t *timer)
{
    struct bev_arg *bev_arg = timer->data;

    /* release timer */
    uv_timer_stop(timer);
    uv_close((uv_handle_t *)timer, on_close_timer);

    /* close socket */
    bev_arg->connect_timer = NULL;
    /* we cannot call here uv_shutdown because it will fail (socket is not connected) */
    bev_arg->uv_closed = 1;
    uv_close((uv_handle_t *)bev_arg->stream, on_close);
}

void on_read_timeout (uv_timer_t *timer)
{
    struct bev_arg *bev_arg = timer->data;

    /* release timer */
    uv_timer_stop(timer);
    uv_close((uv_handle_t *)timer, on_close_timer);

    /* shutdown socket */
    bev_arg->read_timer = NULL;
    uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
    uv_shutdown(shutdown, bev_arg->stream, on_shutdown);
}

void on_close_timer(uv_handle_t* handle)
{
    free(handle);
}

void on_close(uv_handle_t* handle)
{
    struct bev_arg *bev_arg = handle->data;

    if (bev_arg->type == BEV_CLIENT) {
        bev_arg->listener->nr_conn--;
    }

    free(handle);
    free(bev_arg);
}

void on_close_listener(uv_handle_t* handle)
{
    free(handle);
}


/* after every write release buffers */
void on_write(uv_write_t* req, int status) {
    struct bev_arg *bev_arg = req->handle->data;

    uv_buf_t *buf = (uv_buf_t *)req->data;

    /* if reading from remote socket was stopped because o non-zero write_queue, reenable reading  */
    if (bev_arg->read_stopped && bev_arg->remote && req->handle->write_queue_size == 0) {
        uv_read_start(bev_arg->remote->stream, alloc_cb, on_read);
        bev_arg->read_stopped=0;
    }

    bufpool_release(buf->base);
    free(buf);
    free(req);
}

void on_write_free(uv_write_t* req, int status) {
    uv_buf_t *buf = (uv_buf_t *)req->data;
    free(buf->base);
    free(buf);
    free(req);
}


/* only used if we send cache_mysql_init_packet which we dont want to free() */
void on_write_nofree(uv_write_t* req, int status) {
    /* Logic which handles the write result */
    uv_buf_t *buf = (uv_buf_t *)req->data;
    free(buf);
    free(req);
}


