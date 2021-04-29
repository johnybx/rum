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

bool
mysql_is_whole_packet(const char* data, size_t len)
{
    if (len >= MYSQL_PACKET_HEADER_SIZE) {
        union {
            const char *data;
            struct {
                unsigned char payload_length[3];
                unsigned char sequence_id;
            } __attribute__((packed)) * mysql_header;
        } header;

        header.data = data;
        size_t payload_len = header.mysql_header->payload_length[0]
                             | (header.mysql_header->payload_length[1] << 8u)
                             | (header.mysql_header->payload_length[2] << 16u);

        if (len >= MYSQL_PACKET_HEADER_SIZE + payload_len) {
            return true;
        }
    }

    return false;
}

bool
mysql_build_packet(struct mitm* mitm, const uv_buf_t* incoming, uv_buf_t* outbuf)
{
    if (mitm->input_buffer.data == NULL) {
        if (mysql_is_whole_packet(incoming->base, incoming->len)) {
            outbuf->base = incoming->base;
            outbuf->len = incoming->len;
            return true;
        }

        mitm->input_buffer.data = malloc(1024);
        mitm->input_buffer.len = 1024;
        mitm->input_buffer.pos = 0;
    }

    if (incoming->len > mitm->input_buffer.len - mitm->input_buffer.pos) {
        mitm->input_buffer.data = realloc(mitm->input_buffer.data, mitm->input_buffer.len + incoming->len);
        mitm->input_buffer.len += incoming->len;
    }

    memcpy(&mitm->input_buffer.data[mitm->input_buffer.pos], incoming->base, incoming->len);
    mitm->input_buffer.pos += incoming->len;

    if (mysql_is_whole_packet(mitm->input_buffer.data, mitm->input_buffer.pos)) {
        outbuf->base = mitm->input_buffer.data;
        outbuf->len = mitm->input_buffer.pos;
        return true;
    }

    return false;
}

void
mysql_on_read (uv_stream_t * stream, ssize_t nread, const uv_buf_t * constbuf)
{
    struct conn_data *conn_data = (struct conn_data *) stream->data;

    uv_buf_t *buf = NULL;
    struct pending *pending = NULL, *p;

    if (conn_data->remote || (conn_data->mitm && conn_data->mitm->not_need_remote)) {
        if (conn_data->ssl && nread > 0) {
            pending = handle_ssl(stream, nread, constbuf);
            free (constbuf->base);
            if (!pending) {
                return;
            }

            /* merge linked-list of uv_bufs to single uv_buf */
            buf = malloc(sizeof(struct uv_buf_t));
            buf->len = 0;
            for (p=pending; p; p=p->next) {
                buf->len += p->buf->len;
            }
            buf->base = malloc(buf->len);
            int prev = 0;
            for (p=pending; p; p=p->next) {
                memcpy(buf->base + prev, p->buf->base, p->buf->len);
                prev += p->buf->len;
            }
            nread = buf->len;
            free_pending_ll (pending);
        } else if (!conn_data->ssl && nread > 0) {
            buf = malloc(sizeof(struct uv_buf_t));
            buf->base = constbuf->base;
            buf->len = nread;
        }


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
                    uv_buf_t packet;
                    if (mysql_build_packet(conn_data->mitm, buf, &packet)) {
                        handle_auth_packet_from_client (conn_data, &packet, nread);
                    }
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

    if (buf) {
        free (buf->base);
        free (buf);
    } else {
        free (constbuf->base);
    }
}
