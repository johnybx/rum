#include "rum.h"

extern bufpool_t *pool;

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
