#include "rum.h"

#include "mysql_password/my_global.h"
#include "mysql_password/mysql_com.h"
#include "mysql_password/sha1.h"

extern char *cache_mysql_init_packet;
extern int cache_mysql_init_packet_len;
extern struct destination *first_destination;
extern int loglogins;

/* initialize struct mitm */
struct mitm *
init_mitm ()
{

    struct mitm *mitm;

    mitm = malloc (sizeof (struct mitm));
    mitm->not_need_remote = 0;
    mitm->handshake = 0;
    mitm->client_auth_packet = NULL;
    mitm->password = NULL;
    mitm->scramble1 = NULL;
    mitm->scramble2 = NULL;
    mitm->hash_stage1 = NULL;
    mitm->hash_stage2 = NULL;

    return mitm;
}

/* free struct mitm and all variables inside where we use malloc() */
void
free_mitm (struct mitm *mitm)
{
    if (mitm == NULL) {
        return;
    }

    if (mitm->client_auth_packet) {
        free (mitm->client_auth_packet);
        mitm->client_auth_packet = NULL;
    }

    if (mitm->password) {
        free (mitm->password);
        mitm->password = NULL;
    }
    if (mitm->scramble1) {
        free (mitm->scramble1);
        mitm->scramble1 = NULL;
    }
    if (mitm->scramble2) {
        free (mitm->scramble2);
        mitm->scramble2 = NULL;
    }
    if (mitm->hash_stage1) {
        free (mitm->hash_stage1);
        mitm->hash_stage1 = NULL;
    }
    if (mitm->hash_stage2) {
        free (mitm->hash_stage2);
        mitm->hash_stage2 = NULL;
    }

    free (mitm);
}


/* parameter is packet, we need to concatenate bytes scramble_buff, it is split in packet in 2 places
 * and then return this string
 *
 * this variable must be null terminated, but in packet there is already '\0' character at the end of scramble_buff
 * but there can be evil people sending evil strings so we add one char with '\0'
 */
char *
get_scramble_from_init_packet (char *packet, size_t len)
{
/* packet overview:
 size			      wtf
===========================================================
 1                            protocol_version
 n (Null-Terminated String)   server_version
 4                            thread_id
 8                            scramble_buff <------------------- this
 1                            (filler) always 0x00
 2                            server_capabilities
 1                            server_language
 2                            server_status
 13                           (filler) always 0x00 ...
 13                           rest of scramble_buff (4.1)   <--- and this
*/
    char *p;
    char *scramble;

    if (len < MYSQL_PACKET_HEADER_SIZE + 1) {
        return NULL;
    }

    p = packet + MYSQL_PACKET_HEADER_SIZE + 1;

    // TODO buffer overflow, i am lazy to fix it, its handling first packet from trusted servers
    while (*p != '\0')
        p++;
    p += 1 + 4;

    scramble = malloc (8 + 13 + 1);
    scramble[8 + 13] = '\0';

    memcpy (scramble, p, 8);

    p += 8 + 1 + 2 + 1 + 2 + 13;

    memcpy (scramble + 8, p, 13);

    return scramble;
}


char *
set_random_scramble_on_init_packet (char *packet, void *p1, void *p2)
{
    struct rand_struct rand;
    char *p;
    char *scramble;

    scramble = malloc (SCRAMBLE_LENGTH + 1);

    randominit (&rand, (ulong) p1, (ulong) p2);

    create_random_string (scramble, SCRAMBLE_LENGTH, &rand);

    p = packet + MYSQL_PACKET_HEADER_SIZE + 1;

    while (*p != '\0')
        p++;
    p += 1 + 4;

    memcpy (p, scramble, 8);

    p += 8 + 1 + 2 + 1 + 2 + 13;

    memcpy (p, scramble + 8, 13);

    return scramble;
}

int
handle_init_packet_from_server (struct conn_data *conn_data,
                                const uv_buf_t * uv_buf, size_t nread)
{
    char mysql_server_init_packet[4096];
    conn_data->mitm->handshake = 1;

    /* paket too small or too big */
    if (nread < MYSQL_PACKET_HEADER_SIZE + MYSQL_INIT_PACKET_MIN_SIZE ||
        nread > sizeof (mysql_server_init_packet)) {

        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }

        return 1;
    }

    /* get scramble into shared struct mitm between our socket and client socket */
    conn_data->mitm->scramble1 =
        get_scramble_from_init_packet (uv_buf->base, nread);

    return 0;
}

int
handle_auth_packet_from_client (struct conn_data *conn_data,
                                const uv_buf_t * uv_buf, size_t nread)
{
    char user[64];
    char buf[512];
    int user_len, buflen;
    struct conn_data *conn_data_remote;
    struct destination *destination = NULL;
    char *mysql_server = NULL, *c, *i, *userptr;

    /* check for ssl flag  */
    if (nread > MYSQL_PACKET_HEADER_SIZE + 4) {
        if (!conn_data->ssl && check_client_side_ssl_flag(uv_buf->base)) {
            /* first call of handle_auth_packet_from_client */
            return enable_server_ssl_mysql(conn_data, uv_buf, nread);
        }
        if (conn_data->ssl) {
            /* second call of handle_auth_packet_from_client */
            decrement_packet_seq(uv_buf->base);
        }
    }


    /* check if size ends in user[1], so user has at least 1 char */
    if (nread < MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS + 1) {
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }

        logmsg ("%s: warning: invalid client packet size (packet too small)",
                __FUNCTION__);
        return 1;
    }

    conn_data->mitm->client_auth_packet_len = nread;
    conn_data->mitm->client_auth_packet = malloc (nread);
    memcpy (conn_data->mitm->client_auth_packet, uv_buf->base, nread);

    userptr =
        conn_data->mitm->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
        MYSQL_AUTH_PACKET_USER_POS;
    /* limit strnlen to packet length without HEADER */
    user_len =
        strnlen (userptr,
                 nread - MYSQL_PACKET_HEADER_SIZE -
                 MYSQL_AUTH_PACKET_USER_POS);
    if (user_len > sizeof (user) - 1) {
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }

        logmsg
            ("%s: warning: invalid client packet size (user_len > sizeof(user)-1)",
             __FUNCTION__);

        return 1;

    }
    strncpy (user,
             conn_data->mitm->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
             MYSQL_AUTH_PACKET_USER_POS, user_len);
    user[user_len] = '\0';

    get_data_from_cdb (user, user_len, &mysql_server,
                       &conn_data->mitm->password);

    /* another size check if we know user_len, there must be at least 21 bytes after username
     * 1 byte length
     * 20 bytes scramble data
     * https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
     * https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
     *
     * we dont support other types of auth
     */
    if (nread <
        MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS + 1 + user_len +
        1 + SCRAMBLE_LENGTH) {
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }

        logmsg ("%s: invalid client packet size (packet too small 2)",
                __FUNCTION__);

        return 1;
    }

    i = conn_data->mitm->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
        MYSQL_AUTH_PACKET_USER_POS + user_len + 1;
    c = conn_data->mitm->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
        MYSQL_AUTH_PACKET_USER_POS + user_len + 1 + 1;

    /* scramble length in client packet != 0 (client dont sent empty password) */
    if (*i && conn_data->mitm->password) {
        conn_data->mitm->hash_stage2 = malloc (SHA1_HASH_SIZE);
        get_salt_from_password (conn_data->mitm->hash_stage2,
                                conn_data->mitm->password);

        conn_data->mitm->hash_stage1 = malloc (SHA1_HASH_SIZE);

        get_hash_stage1 (c, conn_data->mitm->scramble1,
                         conn_data->mitm->hash_stage2,
                         conn_data->mitm->hash_stage1);
    }

    if (mysql_server != NULL) {
        destination = add_destination(mysql_server);

        if (loglogins) {
          struct sockaddr_in sa_in;
          int sa_size = sizeof (struct sockaddr_in);
          char *ip = NULL;
          if (conn_data->listener->s[0]=='t') {
            uv_tcp_getpeername((uv_tcp_t *) conn_data->stream, (struct sockaddr *)&sa_in, &sa_size);
            ip = inet_ntoa(sa_in.sin_addr);
            logmsg ("%s: user %s login from %s", __FUNCTION__, user, ip);
          } else {
            logmsg ("%s: user %s login from socket", __FUNCTION__, user);
          }
        }
    } else {
        /* if user is not found in cdb, sent client error msg & close connection  */
        destination = first_destination;

        logmsg ("%s: user %s not found in cdb", __FUNCTION__, user);
        /* we reply access denied  */
        memcpy (buf, ERR_LOGIN_PACKET_PREFIX,
                sizeof (ERR_LOGIN_PACKET_PREFIX));
        buflen =
            snprintf (buf + sizeof (ERR_LOGIN_PACKET_PREFIX) - 1,
                      sizeof (buf) - sizeof (ERR_LOGIN_PACKET_PREFIX),
                      "Access denied, unknown user '%s'", user);
        buf[0] = buflen + sizeof (ERR_LOGIN_PACKET_PREFIX) - 5;

        if (conn_data->ssl) {
            SSL_write(conn_data->ssl, buf, buflen + sizeof (ERR_LOGIN_PACKET_PREFIX) - 1);
            flush_ssl(conn_data);
        } else {
            uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
            uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
            newbuf->base = malloc (buflen + sizeof (ERR_LOGIN_PACKET_PREFIX) - 1);

            memcpy (newbuf->base, buf,
                    buflen + sizeof (ERR_LOGIN_PACKET_PREFIX) - 1);
            newbuf->len = buflen + sizeof (ERR_LOGIN_PACKET_PREFIX) - 1;
            req->data = newbuf;
            if (uv_write (req, conn_data->stream, newbuf, 1, on_write)) {
                uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
                if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
                    free (shutdown);
                }
                return 1;
            }
        }

        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }


        if (mysql_server)
            free (mysql_server);

        return 1;
    }

    /* if remote connection exists free it */
    if (conn_data->remote) {
        logmsg ("%s: conn_data->remote is not NULL and should not be",
                __FUNCTION__);
        free (conn_data->remote);
    }


    if (!destination) {
        logmsg ("%s: destination is NULL and should not be", __FUNCTION__);
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }
        if (mysql_server)
            free (mysql_server);

        return 1;
    }

    conn_data_remote =
        create_server_connection (conn_data, destination, conn_data->listener);

    if (!conn_data_remote) {
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }
        if (mysql_server)
            free (mysql_server);

        return 1;
    }
    conn_data->mitm->not_need_remote = 0;
    conn_data_remote->mitm = conn_data->mitm;
    conn_data_remote->listener = conn_data->listener;
    conn_data->mitm->handshake = 2;

    if (mysql_server)
        free (mysql_server);

    return 1;
}

int
handle_auth_with_server (struct conn_data *conn_data, const uv_buf_t * uv_buf,
                         size_t nread)
{
    char *user;
    int user_len;
    char *scramble_ptr;
    char mysql_server_init_packet[4096];

    if (nread < MYSQL_PACKET_HEADER_SIZE + MYSQL_INIT_PACKET_MIN_SIZE
        || nread > sizeof (mysql_server_init_packet)) {
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }

        return 1;
    }

    /* if server has support for SSL and has public IP enable SSL for connection
     * by sending SSLRequest packet and starting SSL
     */
    if (!conn_data->ssl && !is_private_address(conn_data) && check_server_side_ssl_flag(uv_buf->base, nread)) {
        if (conn_data->mitm->client_auth_packet_len < (MYSQL_PACKET_HEADER_SIZE + MYSQL_SSL_CONN_REQUEST_PACKET_SIZE)) {
            uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
            if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
                free (shutdown);
            }
            return 0;
        }

        /* prepare SSLRequest */
        char *request = malloc (MYSQL_PACKET_HEADER_SIZE + MYSQL_SSL_CONN_REQUEST_PACKET_SIZE);
        memset (request, 0, MYSQL_PACKET_HEADER_SIZE + MYSQL_SSL_CONN_REQUEST_PACKET_SIZE);
        uint32_t size = 32;
        memcpy(request, &size, 3);
        uint8_t seq = 1;
        memcpy(request + MYSQL_PACKET_HEADER_SIZE - 1, &seq, sizeof(uint8_t));

        /* copy flags & some stuff from client auth packet */
        memcpy (request + MYSQL_PACKET_HEADER_SIZE, conn_data->mitm->client_auth_packet + MYSQL_PACKET_HEADER_SIZE, 9);
        /* enable ssl flag in case client is not connected via ssl */
        enable_client_side_ssl_flag(request);

        uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
        uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
        newbuf->base = request;
        newbuf->len = MYSQL_PACKET_HEADER_SIZE + MYSQL_SSL_CONN_REQUEST_PACKET_SIZE;
        req->data = newbuf;
        if (uv_write (req, conn_data->stream, newbuf, 1, on_write)) {
            uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
            if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
                free (shutdown);
            }
            return 1;
        }

        enable_client_ssl(conn_data);
    }

    if (conn_data->mitm->hash_stage1) {
        conn_data->mitm->scramble2 =
            get_scramble_from_init_packet (uv_buf->base, nread);
    }

    if (conn_data->mitm->hash_stage1) {
        user =
            conn_data->mitm->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
            MYSQL_AUTH_PACKET_USER_POS;
        user_len = strlen (user);

        scramble_ptr =
            conn_data->mitm->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
            MYSQL_AUTH_PACKET_USER_POS + user_len + 1 + 1;

        scramble_with_hash_stage1 (scramble_ptr, conn_data->mitm->scramble2,
                                   conn_data->mitm->hash_stage1);
    }

    uv_buf_t *newbuf = malloc (sizeof (uv_buf_t));
    newbuf->base = malloc (conn_data->mitm->client_auth_packet_len);

    memcpy (newbuf->base, conn_data->mitm->client_auth_packet,
            conn_data->mitm->client_auth_packet_len);
    newbuf->len = conn_data->mitm->client_auth_packet_len;

    if (conn_data->ssl) {
        /* cannot use SSL_write here, it will fail because SSL handshake was not yet made */
        /* save data to conn_data->pending and then it will be writed in default_callback */
        increment_packet_seq(newbuf->base);
        conn_data->pending = malloc (sizeof (struct pending));
        conn_data->pending->next = NULL;
        conn_data->pending->buf = newbuf;
    } else {
        uv_write_t *req = (uv_write_t *) malloc (sizeof (uv_write_t));
        req->data = newbuf;
        if (uv_write (req, conn_data->stream, newbuf, 1, on_write)) {
            uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
            if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
                free (shutdown);
            }
            free (newbuf->base);
            free (newbuf);
            free (req);
        }
    }

    free_mitm (conn_data->mitm);
    conn_data->mitm = NULL;
    conn_data->remote->mitm = NULL;

    if (uv_read_start (conn_data->stream, alloc_cb, on_read)) {
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }
        return 0;

    }
    if (uv_read_start (conn_data->remote->stream, alloc_cb, on_read)) {
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->remote->stream, on_shutdown)) {
            free (shutdown);
        }
        return 0;
    }

    return 1;
}

void
enable_server_side_ssl_flag()
{
    uint16_t server_capabilities;
    char *ptr;
    for (ptr = cache_mysql_init_packet + MYSQL_PACKET_HEADER_SIZE + 1; *ptr!='\0'; ptr ++);
    ptr += 1 + 4;
    for (ptr = ptr + 1; *ptr!='\0'; ptr ++);
    ptr += 1;
    memcpy (&server_capabilities, (void *)ptr, sizeof(uint16_t));
    server_capabilities = server_capabilities | 0x800;
    memcpy ((void *)ptr, &server_capabilities, sizeof(uint16_t));
}

int
check_server_side_ssl_flag(char *packet, size_t len)
{
    uint16_t server_capabilities;
    char *ptr;

    if (len < MYSQL_PACKET_HEADER_SIZE + 1) {
        return 0;
    }

    // TODO buffer overflow, i am lazy to fix it, its handling first packet from trusted servers
    for (ptr = packet + MYSQL_PACKET_HEADER_SIZE + 1; *ptr!='\0'; ptr ++);
    ptr += 1 + 4;
    for (ptr = ptr + 1; *ptr!='\0'; ptr ++);
    ptr += 1;
    memcpy (&server_capabilities, (void *)ptr, sizeof(uint16_t));
    if ((server_capabilities & 0x800) == 0x800) {
        return 1;
    } else {
        return 0;
    }
}


int
check_client_side_ssl_flag(char *packet)
{
    uint16_t client_capabilities;
    char *ptr;
    ptr =  packet + MYSQL_PACKET_HEADER_SIZE;
    memcpy (&client_capabilities, (void *)ptr, sizeof(uint16_t));
    if ((client_capabilities & 0x800) == 0x800) {
        return 1;
    } else {
        return 0;
    }
}

int
disable_client_side_ssl_flag(char *packet)
{
    uint16_t client_capabilities;
    char *ptr;
    ptr =  packet + MYSQL_PACKET_HEADER_SIZE;
    memcpy (&client_capabilities, (void *)ptr, sizeof(uint16_t));
    if ((client_capabilities & 0x800) == 0x800) {
        client_capabilities = client_capabilities & !0x800;
        memcpy ((void *) ptr, &client_capabilities, sizeof(uint16_t));
        return 1;
    } else {
        return 0;
    }
}

void
enable_client_side_ssl_flag(char *packet)
{
    uint16_t client_capabilities;
    char *ptr;
    ptr =  packet + MYSQL_PACKET_HEADER_SIZE;
    memcpy (&client_capabilities, (void *) ptr, sizeof(uint16_t));
    client_capabilities = client_capabilities | 0x800;
    memcpy ((void *) ptr, &client_capabilities, sizeof(uint16_t));
}


void
decrement_packet_seq(char *packet)
{
    uint8_t seqnr;
    char *ptr;
    ptr =  packet + MYSQL_PACKET_HEADER_SIZE - 1;
    memcpy (&seqnr, (void *)ptr, sizeof(uint8_t));
    seqnr--;
    memcpy ((void *)ptr, &seqnr, sizeof(uint8_t));
}

void
increment_packet_seq(char *packet)
{
    uint8_t seqnr;
    char *ptr;
    ptr =  packet + MYSQL_PACKET_HEADER_SIZE - 1;
    memcpy (&seqnr, (void *)ptr, sizeof(uint8_t));
    seqnr++;
    memcpy ((void *)ptr, &seqnr, sizeof(uint8_t));
}

void
print_packet_seq(char *packet)
{
    uint8_t seqnr;
    char *ptr;
    ptr =  packet + MYSQL_PACKET_HEADER_SIZE - 1;
    memcpy (&seqnr, (void *)ptr, sizeof(uint8_t));
}
