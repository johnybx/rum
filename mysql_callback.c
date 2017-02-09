#include "rum.h"

extern struct destination *first_destination;

char *cache_mysql_init_packet = NULL;
int cache_mysql_init_packet_len;
char *cache_mysql_init_packet_scramble;

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
mysql_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
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

            if (bev_arg->type == BEV_TARGET) {
                /* data from mysql server */
                if (bev_arg->ms->handshake == 0) {
                    /* first data */
                    handle_init_packet_from_server(bev_arg, buf, nread);
                } else if (bev_arg->ms->handshake == 2) {
                    /* second data from server */
                    handle_auth_with_server (bev_arg, buf, nread);
                }
            } else if (bev_arg->type == BEV_CLIENT) {
                /* data from mysql client */
                if (bev_arg->ms->handshake == 1) {
                    /* first data from client */
                    handle_auth_packet_from_client(bev_arg, buf, nread);
                }
            }
        } else if (nread < 0) {
            uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
            if (uv_shutdown(shutdown, stream, on_shutdown)) {
                free(shutdown);
                uv_close((uv_handle_t *)stream, on_close);
            }

        }

    } else {
        /* remote stream doesn't exist, free self */
        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        if (uv_shutdown(shutdown, stream, on_shutdown)) {
            free(shutdown);
            uv_close((uv_handle_t *)stream, on_close);
        }
    }

    bufpool_release(buf->base);
}
