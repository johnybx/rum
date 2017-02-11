#include "rum.h"

extern struct event_base *event_base;
extern struct destination *first_destination;

void
postgresql_on_read (uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    struct bev_arg *bev_arg = (struct bev_arg *) stream->data;

    /* disable read timeout from server when we receive first data */
    if (bev_arg->read_timer) {
        uv_timer_stop(bev_arg->read_timer);
        uv_close((uv_handle_t *)bev_arg->read_timer, on_close_timer);
        bev_arg->read_timer = NULL;
    }


    if (bev_arg->remote || (bev_arg->ms && bev_arg->ms->not_need_remote)) {
        if (nread > 0) {
            if (bev_arg->type == BEV_CLIENT) {
                bev_arg->listener->input_bytes += nread;
            } else if (bev_arg->type == BEV_TARGET) {
                bev_arg->listener->output_bytes += nread;
            }

            if (bev_arg->type == BEV_CLIENT) {
                /* first data from client */
                pg_handle_init_packet_from_client
                        (bev_arg, buf, nread);
            }
        } else if (nread < 0) {
            uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
            if (uv_shutdown(shutdown, stream, on_shutdown)) {
                free(shutdown);
            }

        } /* else if (nread==0) {do nothing becaause read() return EAGAIN, just release bufpool} */

    } else {
        /* remote stream doesn't exist, free self */
        // TODO should not happend
        fprintf(stderr, "xxxxx\n");
        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        uv_shutdown(shutdown, stream, on_shutdown);
    }

    bufpool_release(buf->base);
}
