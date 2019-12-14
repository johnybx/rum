#include "rum.h"

extern struct event_base *event_base;
extern struct destination *first_destination;

void
postgresql_on_read_disable_read_timeout (uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf)
{
    struct conn_data *conn_data = stream->data;

    /* disable read timeout from server when we receive first data */
    if (conn_data->read_timer) {
        uv_timer_stop (conn_data->read_timer);
        uv_close ((uv_handle_t *) conn_data->read_timer, on_close_timer);
        conn_data->read_timer = NULL;
        /* change callback to postgresql_on_read() */
        stream->read_cb = postgresql_on_read;
    }

    postgresql_on_read(stream, nread, buf);
}


void
postgresql_on_read (uv_stream_t * stream, ssize_t nread, const uv_buf_t * constbuf)
{
    struct conn_data *conn_data = (struct conn_data *) stream->data;

    uv_buf_t *buf = NULL;
    struct pending *pending = NULL;

    if (conn_data->ssl && nread > 0) {
        pending = handle_ssl (stream, nread, constbuf);
        free (constbuf->base);
        if (!pending) {
            return;
        }

        /* TODO: pending can contain multiple data but we throw it away, probability in this phase of connection is low */
        nread = pending->buf->len;
        buf = malloc(sizeof(struct uv_buf_t));
        buf->base = pending->buf->base;
        buf->len = pending->buf->len;
        pending->buf->base = NULL;
        free_pending_ll (pending);
    } else if (!conn_data->ssl && nread > 0) {
        buf = malloc(sizeof(struct uv_buf_t));
        buf->base = constbuf->base;
        buf->len = nread;
    }

    if (conn_data->remote || (conn_data->mitm && conn_data->mitm->not_need_remote)) {
        if (nread > 0) {
            if (conn_data->type == CONN_CLIENT) {
                conn_data->listener->input_bytes += nread;
            } else if (conn_data->type == CONN_TARGET) {
                conn_data->listener->output_bytes += nread;
            }

            if (conn_data->type == CONN_CLIENT) {
                /* first data from client */
                pg_handle_init_packet_from_client (conn_data, buf, nread);
            } else if (conn_data->type == CONN_TARGET) {
                if (conn_data->mitm && conn_data->mitm->handshake == 3 && nread == 1) {
                    /* received sslrequest reply from destination server */
                    if (buf->base[0] == 'S') {
                        /* server said it support SSL, enable it */
                        enable_client_ssl(conn_data);

                        /* send server client auth packet over SSL */
                        if (conn_data->ssl && conn_data->mitm && conn_data->mitm->client_auth_packet) {
                            uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
                            newbuf->base = conn_data->mitm->client_auth_packet;
                            newbuf->len = conn_data->mitm->client_auth_packet_len;

                            conn_data->pending = malloc (sizeof (struct pending));
                            conn_data->pending->next = NULL;
                            conn_data->pending->buf = newbuf;

                            conn_data->mitm->client_auth_packet = NULL;
                        } else {
                            /* this should never happend */
                            logmsg ("%s: error debug1", __FUNCTION__);

                            uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                            uv_shutdown (shutdown, stream, on_shutdown);
                        }
                    } else {
                        /* server sait it doesnt support SSL, continue with plaintext */
                        /* send server client auth packet */
                        if (conn_data->mitm && conn_data->mitm->client_auth_packet) {
                            uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
                            uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
                            newbuf->base = conn_data->mitm->client_auth_packet;
                            newbuf->len = conn_data->mitm->client_auth_packet_len;
                            req->data = newbuf;
                            conn_data->mitm->client_auth_packet = NULL;
                            if (uv_write (req, stream, newbuf, 1, on_write_free)) {
                                logmsg ("%s: uv_write(postgresql client_auth_packet) failed",
                                        __FUNCTION__);

                                free (newbuf->base);
                                free (newbuf);
                                free (req);

                                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                                uv_shutdown (shutdown, stream, on_shutdown);
                            }
                        } else {
                            /* this should never happend */
                            logmsg ("%s: error debug2", __FUNCTION__);

                            uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                            uv_shutdown (shutdown, stream, on_shutdown);
                        }
                    }
                    /* change callbacks to on_read */
                    uv_read_start (conn_data->remote->stream, alloc_cb, on_read);
                    uv_read_start (conn_data->stream, alloc_cb, on_read);
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
        uv_shutdown (shutdown, stream, on_shutdown);
    }

    free (buf->base);
    free (buf);
}
