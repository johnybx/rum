#include "rum.h"

#include "mysql_password/my_global.h"
#include "mysql_password/mysql_com.h"
#include "mysql_password/sha1.h"

extern bufpool_t *pool;
extern char *cache_mysql_init_packet;
extern int cache_mysql_init_packet_len;
extern struct destination *first_destination;

/* initialize struct mysql_mitm */
struct mysql_mitm *
init_ms ()
{

    struct mysql_mitm *ms;

    ms = malloc (sizeof (struct mysql_mitm));
    ms->not_need_remote = 0;
    ms->handshake = 0;
    ms->client_auth_packet = NULL;
    ms->password = NULL;
    ms->scramble1 = NULL;
    ms->scramble2 = NULL;
    ms->hash_stage1 = NULL;
    ms->hash_stage2 = NULL;

    return ms;
}

/* free struct mysql_mitm and all variables inside where we use malloc() */
void
free_ms (struct mysql_mitm *ms)
{
    if (ms == NULL) {
        return;
    }

    if (ms->client_auth_packet) {
        free (ms->client_auth_packet);
        ms->client_auth_packet = NULL;
    }

    if (ms->password) {
        free (ms->password);
        ms->password = NULL;
    }
    if (ms->scramble1) {
        free (ms->scramble1);
        ms->scramble1 = NULL;
    }
    if (ms->scramble2) {
        free (ms->scramble2);
        ms->scramble2 = NULL;
    }
    if (ms->hash_stage1) {
        free (ms->hash_stage1);
        ms->hash_stage1 = NULL;
    }
    if (ms->hash_stage2) {
        free (ms->hash_stage2);
        ms->hash_stage2 = NULL;
    }

    free (ms);
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

    // TODO: buffer overflow
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
                                const uv_buf_t *uv_buf, size_t nread)
{
    char mysql_server_init_packet[4096];
    conn_data->ms->handshake = 1;

    /* paket too small or too big */
    if (nread < MYSQL_PACKET_HEADER_SIZE + MYSQL_INIT_PACKET_MIN_SIZE ||
        nread > sizeof (mysql_server_init_packet)) {

        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        if (uv_shutdown(shutdown, conn_data->stream, on_shutdown)) {
            free(shutdown);
        }

        return 1;
    }

    /* get scramble into shared struct mysql_mitm between our socket and client socket */
    conn_data->ms->scramble1 =
        get_scramble_from_init_packet (uv_buf->base, nread);

    return 0;
}


int
handle_auth_packet_from_client (struct conn_data *conn_data,
                                const uv_buf_t *uv_buf, size_t nread)
{
    char user[64];
    char buf[512];
    int user_len, buflen;
    struct conn_data *conn_data_remote;
    struct destination *destination = NULL, *dst;
    char *mysql_server = NULL, *c, *i, *userptr;

    /* check if size ends in user[1], so user has at least 1 char */
    if (nread < MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS + 1) {
        conn_data->listener->nr_conn--;
        
        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        if (uv_shutdown(shutdown, conn_data->stream, on_shutdown)) {
            free(shutdown);
        }

        logmsg("%s: warning: invalid client packet size (packet too small)", __FUNCTION__);
        return 1;
    }

    conn_data->ms->client_auth_packet_len = nread;
    conn_data->ms->client_auth_packet = malloc (nread);
    memcpy(conn_data->ms->client_auth_packet, uv_buf->base, nread);

    userptr =
        conn_data->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
        MYSQL_AUTH_PACKET_USER_POS;
    /* limit strnlen to packet length without HEADER */
    user_len = strnlen (userptr, nread - MYSQL_PACKET_HEADER_SIZE - MYSQL_AUTH_PACKET_USER_POS);
    if (user_len > sizeof(user)-1) {
        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        if (uv_shutdown(shutdown, conn_data->stream, on_shutdown)) {
            free(shutdown);
        }

        logmsg("%s: warning: invalid client packet size (user_len > sizeof(user)-1)", __FUNCTION__);

        return 1;

    }
    strncpy (user,
             conn_data->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
             MYSQL_AUTH_PACKET_USER_POS, user_len);
    user[user_len] = '\0';

    get_data_from_cdb (user, user_len, &mysql_server, &conn_data->ms->password);

    /* another size check if we know user_len, there must be at least 21 bytes after username
    * 1 byte length
    * 20 bytes scramble data
    * https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
    * https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
    *
    * we dont support other types of auth
    */
    if (nread < MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS + 1 + user_len + 1 + SCRAMBLE_LENGTH) {
        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        if (uv_shutdown(shutdown, conn_data->stream, on_shutdown)) {
            free(shutdown);
        }

        logmsg("%s: invalid client packet size (packet too small 2)", __FUNCTION__);

        return 1;
    }

    i = conn_data->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
        MYSQL_AUTH_PACKET_USER_POS + user_len + 1;
    c = conn_data->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
        MYSQL_AUTH_PACKET_USER_POS + user_len + 1 + 1;

    /* scramble length in client packet != 0 (client dont sent empty password) */
    if (*i && conn_data->ms->password) {
        conn_data->ms->hash_stage2 = malloc (SHA1_HASH_SIZE);
        get_salt_from_password (conn_data->ms->hash_stage2,
                                conn_data->ms->password);

        conn_data->ms->hash_stage1 = malloc (SHA1_HASH_SIZE);

        get_hash_stage1 (c, conn_data->ms->scramble1, conn_data->ms->hash_stage2,
                         conn_data->ms->hash_stage1);
    }

    if (mysql_server != NULL) {
        if (first_destination) {
            for (dst = first_destination; dst->next; dst = dst->next) {
                if (!strcmp (dst->s, mysql_server)) {
                    destination = dst;
                    break;
                }
            }

            if (!destination) {
                dst->next = destination = malloc (sizeof (struct destination));
                prepareclient (mysql_server, destination);
            }
        } else {
            first_destination = destination = malloc (sizeof (struct destination));
            prepareclient (mysql_server, destination);
        }
    } else {
        /* if user is not found in cdb we use mysql server set with -d argument
         * but connection will not be successful, we need user encrypted password which should be in cdb file
         */
        destination = first_destination;

        logmsg("%s: user %s not found in cdb", __FUNCTION__, user);
        /* we reply access denied  */
        memcpy (buf, ERR_LOGIN_PACKET_PREFIX, sizeof(ERR_LOGIN_PACKET_PREFIX));
        buflen = snprintf (buf + sizeof(ERR_LOGIN_PACKET_PREFIX) - 1, sizeof(buf) - sizeof(ERR_LOGIN_PACKET_PREFIX), "Access denied, unknown user '%s'", user);
        buf[0] = buflen + sizeof(ERR_LOGIN_PACKET_PREFIX) - 5;

        uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
        uv_buf_t *newbuf = malloc(sizeof(uv_buf_t));
        int newlen = buflen + sizeof(ERR_LOGIN_PACKET_PREFIX) - 1;
        newbuf->base = bufpool_acquire(pool, &newlen);

        memcpy(newbuf->base, buf, buflen + sizeof(ERR_LOGIN_PACKET_PREFIX) - 1);
        newbuf->len=buflen + sizeof(ERR_LOGIN_PACKET_PREFIX) - 1;
        req->data=newbuf;
        if (uv_write(req, conn_data->stream, newbuf, 1, on_write)) {
            uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
            if (uv_shutdown(shutdown, conn_data->stream, on_shutdown)) {
                free(shutdown);
            }
            return 1;
        }

        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        if (uv_shutdown(shutdown, conn_data->stream, on_shutdown)) {
            free(shutdown);
        }


        if (mysql_server)
            free (mysql_server);

        return 1;
    }

    /* if remote connection exists free it */
    if (conn_data->remote) {
        logmsg("%s: conn_data->remote is not NULL and should not be", __FUNCTION__);
        free (conn_data->remote);
    }


    if (!destination) {
        logmsg("%s: destination is NULL and should not be", __FUNCTION__);
        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        if (uv_shutdown(shutdown, conn_data->stream, on_shutdown)) {
            free(shutdown);
        }
        if (mysql_server)
            free (mysql_server);

        return 1;
    }

    conn_data_remote = create_server_connection(conn_data, destination, conn_data->listener);
    conn_data->ms->not_need_remote = 0;
    conn_data_remote->ms = conn_data->ms;
    conn_data_remote->listener = conn_data->listener;
    conn_data->ms->handshake = 2;

    if (mysql_server)
        free (mysql_server);

    return 1;
}

int
handle_auth_with_server (struct conn_data *conn_data, const uv_buf_t *uv_buf, size_t nread)
{
    char *user;
    int user_len;
    char *scramble_ptr;
    char mysql_server_init_packet[4096];

    if (nread < MYSQL_PACKET_HEADER_SIZE + MYSQL_INIT_PACKET_MIN_SIZE
        || nread > sizeof (mysql_server_init_packet)) {
        uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
        if (uv_shutdown(shutdown, conn_data->stream, on_shutdown)) {
            free(shutdown);
        }

        return 1;
    }


    if (conn_data->ms->hash_stage1) {
        conn_data->ms->scramble2 =
            get_scramble_from_init_packet (uv_buf->base, nread);
    }

    if (conn_data->ms->hash_stage1) {
        user =
            conn_data->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
            MYSQL_AUTH_PACKET_USER_POS;
        user_len = strlen (user);

        scramble_ptr =
            conn_data->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
            MYSQL_AUTH_PACKET_USER_POS + user_len + 1 + 1;

        scramble_with_hash_stage1 (scramble_ptr, conn_data->ms->scramble2,
                                   conn_data->ms->hash_stage1);
    }

    uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
    uv_buf_t *newbuf = malloc(sizeof(uv_buf_t));
    int newlen = conn_data->ms->client_auth_packet_len;
    newbuf->base = bufpool_acquire(pool, &newlen);

    memcpy(newbuf->base,conn_data->ms->client_auth_packet, conn_data->ms->client_auth_packet_len);
    newbuf->len=conn_data->ms->client_auth_packet_len;
    req->data=newbuf;
    if (uv_write(req, conn_data->stream, newbuf, 1, on_write)) {
            uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
            if (uv_shutdown(shutdown, conn_data->stream, on_shutdown)) {
                free(shutdown);
            }
            bufpool_release(newbuf->base);
    }

    free_ms (conn_data->ms);
    conn_data->ms = NULL;
    conn_data->remote->ms = NULL;

    if (uv_read_start(conn_data->stream, alloc_cb, on_read)) {
            uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
            if (uv_shutdown(shutdown, conn_data->stream, on_shutdown)) {
                free(shutdown);
            }
            return 0;

    }
    if (uv_read_start(conn_data->remote->stream, alloc_cb, on_read)) {
            uv_shutdown_t *shutdown = malloc(sizeof(uv_shutdown_t));
            if (uv_shutdown(shutdown, conn_data->remote->stream, on_shutdown)) {
                free(shutdown);
            }
            return 0;
    }

    return 1;
}
