#include "rum.h"

extern struct destination *first_destination;

char *cache_mysql_init_packet = NULL;
int cache_mysql_init_packet_len;
char *cache_mysql_init_packet_scramble;

void
mysql_on_read_disable_read_timeout (uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf)
{
    struct conn_data *conn_data = stream->data;

    /* disable read timeout from server when we receive first data */
    if (conn_data->read_timer) {
        uv_timer_stop (conn_data->read_timer);
        uv_close ((uv_handle_t *) conn_data->read_timer, on_close_timer);
        conn_data->read_timer = NULL;
        /* change callback to mysql_on_read() */
        stream->read_cb = mysql_on_read;
    }

    mysql_on_read(stream, nread, buf);
}

void
mysql_on_read (uv_stream_t * stream, ssize_t nread, const uv_buf_t * constbuf)
{
    struct conn_data *conn_data = (struct conn_data *) stream->data;

    uv_buf_t mybuf;
    uv_buf_t *buf = &mybuf;
    buf->base = constbuf->base;
    buf->len = constbuf->len;

    /* if this connection is ssl, decrypt data in buf->base */
    if (conn_data->ssl && nread > 0) {
        nread = handle_ssl(stream, nread, buf);
        if (nread <= 0) {
            free (buf->base);
            return;
        }
    }

    if (conn_data->remote || (conn_data->mitm && conn_data->mitm->not_need_remote)) {
        if (nread > 0) {
            if (conn_data->type == CONN_CLIENT) {
                conn_data->listener->input_bytes += nread;
            } else if (conn_data->type == CONN_TARGET) {
                conn_data->listener->output_bytes += nread;
            }

            if (conn_data->type == CONN_TARGET) {
                /* data from mysql server */
                if (conn_data->mitm->handshake == 0) {
                    /* first data */
                    handle_init_packet_from_server (conn_data, buf, nread);
                } else if (conn_data->mitm->handshake == 2) {
                    /* second data from server */
                    handle_auth_with_server (conn_data, buf, nread);
                } else if (conn_data->mitm->handshake == 3) {
                    // TODO check size
                    /* last auth data from server */
                    if (!conn_data->ssl && conn_data->remote->ssl) {
                        increment_packet_seq(buf->base);
                    } else if (conn_data->ssl && !conn_data->remote->ssl) {
                        decrement_packet_seq(buf->base);
                    }

                    if (conn_data->remote->ssl) {
                        SSL_write(conn_data->remote->ssl, buf->base, nread);
                        // TODO handle ssl error
                        flush_ssl(conn_data->remote);
                    } else {
                        uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
                        uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
                        newbuf->base = malloc(nread);
                        memcpy (newbuf->base, buf->base, nread);
                        newbuf->len = nread;

                        req->data = newbuf;
                        if (uv_write (req, conn_data->remote->stream, newbuf, 1, on_write)) {
                            uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                            if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
                                free (shutdown);
                            }
                        }
                    }

                    free_mitm (conn_data->mitm);
                    conn_data->remote->mitm=NULL;
                    conn_data->mitm=NULL;

                    stream->read_cb = on_read;
                }
            } else if (conn_data->type == CONN_CLIENT) {
                /* data from mysql client */
                if (conn_data->mitm->handshake == 1) {
                    /* first data from client */
                    handle_auth_packet_from_client (conn_data, buf, nread);
                }
            }
        } else if (nread < 0) {
            uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
            if (uv_shutdown (shutdown, stream, on_shutdown)) {
                free (shutdown);
            }
        }
        /* else if (nread==0) {do nothing becaause read() return EAGAIN, just release buf->base} */
    } else {
        /* remote stream doesn't exist, free self */
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, stream, on_shutdown)) {
            free (shutdown);
        }
    }

    free (buf->base);
}
