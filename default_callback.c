#include "rum.h"

extern bufpool_t *pool;

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
            uv_buf_t *newbuf = malloc(sizeof(uv_buf_t));


            newbuf->base = buf->base;
            newbuf->len = nread;

            req->data = newbuf;
            remote_stream = bev_arg->remote->stream;
            r = uv_write(req, remote_stream, newbuf, 1, on_write);
            if (r) {
                fprintf(stderr,"on_read(): uv_write() failed: %s\n", uv_strerror(r));
                //logmsg ("on_read(): uv_write() failed");
                bufpool_release(buf->base);
                free(newbuf);
                free(req);

                uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
                if (uv_shutdown(shutdown, stream, on_shutdown)) {
                    free(shutdown);
                }

                return;
            }


            if (remote_stream->write_queue_size > 0) {
                /* disable reading on input socket */
                fprintf(stderr, "stopping read\n");
                bev_arg->remote->read_stopped=1;
                uv_read_stop(stream);
            }
            return;
        } else if (nread == 0) {
            fprintf(stderr, "nread = 0\n");
            bufpool_release(buf->base);
            return;
        } else {
            fprintf(stderr, "nread = %d\n", nread);
            uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));

            if (uv_shutdown(shutdown, stream, on_shutdown)) {
                free(shutdown);
            }


        }
    } else {
        /* remote stream doesn't exist, free self */
        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
 
        if (uv_shutdown(shutdown, stream, on_shutdown)) {
            free(shutdown);
        }

    }
    bufpool_release(buf->base);
}
