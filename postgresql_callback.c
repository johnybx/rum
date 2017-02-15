#include "rum.h"

extern struct event_base *event_base;
extern struct destination *first_destination;

void
postgresql_on_read (uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    struct conn_data *conn_data = (struct conn_data *) stream->data;

    /* disable read timeout from server when we receive first data */
    if (conn_data->read_timer) {
        uv_timer_stop(conn_data->read_timer);
        uv_close((uv_handle_t *)conn_data->read_timer, on_close_timer);
        conn_data->read_timer = NULL;
    }


    if (conn_data->remote || (conn_data->ms && conn_data->ms->not_need_remote)) {
        if (nread > 0) {
            if (conn_data->type == CONN_CLIENT) {
                conn_data->listener->input_bytes += nread;
            } else if (conn_data->type == CONN_TARGET) {
                conn_data->listener->output_bytes += nread;
            }

            if (conn_data->type == CONN_CLIENT) {
                /* first data from client */
                pg_handle_init_packet_from_client
                        (conn_data, buf, nread);
            }
        } else if (nread < 0) {
            uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
            if (uv_shutdown(shutdown, stream, on_shutdown)) {
                free(shutdown);
            }

        } /* else if (nread==0) {do nothing becaause read() return EAGAIN, just release bufpool} */

    } else {
        /* remote stream doesn't exist, free self */
        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        uv_shutdown(shutdown, stream, on_shutdown);
    }

    bufpool_release(buf->base);
}
