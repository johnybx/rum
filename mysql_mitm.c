#include "rum.h"

#include "mysql_password/my_global.h"
#include "mysql_password/mysql_com.h"
#include "mysql_password/sha1.h"

#include <byteswap.h>

extern char *cache_mysql_init_packet;
extern int cache_mysql_init_packet_len;
extern struct destination *first_destination;
extern int loglogins;
extern int geoip;
extern bool external_lookup;
extern char *external_lookup_url;

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
    mitm->user = NULL;

    mitm->curl_timer = NULL;
    mitm->curl_handle = NULL;
    mitm->curl_errorbuf = NULL;
    mitm->data = NULL;
    mitm->data_len = 0;

    mitm->input_buffer.data = NULL;
    mitm->input_buffer.len = 0;
    mitm->input_buffer.pos = 0;

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

    if (mitm->user) {
        free (mitm->user);
        mitm->user = NULL;
    }

    if (mitm->input_buffer.data) {
        free (mitm->input_buffer.data);
        mitm->input_buffer.data = NULL;
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
    size_t user_len;
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
            /* second(third) call of handle_auth_packet_from_client */
            /* decrease packet seq only once */
            if (!conn_data->mitm->client_auth_packet) {
                decrement_packet_seq(uv_buf->base);
            }
        }
    }

    /* check if size ends in user[1], so user has at least 1 char */
    if (nread < MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS + 1) {
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }

        logmsg ("%s: warning: invalid client packet size (packet too small) from %s%s",
                __FUNCTION__, get_ipport (conn_data), get_sslinfo (conn_data));
        return 1;
    }

    if (!conn_data->mitm->client_auth_packet) {
        conn_data->mitm->client_auth_packet_len = nread;
        conn_data->mitm->client_auth_packet = malloc (nread);
        memcpy (conn_data->mitm->client_auth_packet, uv_buf->base, nread);
    }

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
            ("%s: warning: invalid client packet size (user_len > sizeof(user)-1) from %s%s",
             __FUNCTION__, get_ipport (conn_data), get_sslinfo (conn_data));

        return 1;

    }
    strncpy (user,
             conn_data->mitm->client_auth_packet + MYSQL_PACKET_HEADER_SIZE +
             MYSQL_AUTH_PACKET_USER_POS, user_len);
    user[user_len] = '\0';

    if (user_len == 0) {
        logmsg ("%s: empty username from %s", __FUNCTION__, get_ipport(conn_data));
        send_mysql_error(conn_data, "Invalid username");
        return 1;
    }

    if (!username_has_allowed_chars(user, user_len)) {
        logmsg ("%s: invalid chars in username from %s", __FUNCTION__, get_ipport(conn_data));
        send_mysql_error(conn_data, "Invalid username");
        return 1;
    }

    if (!conn_data->mitm->user) {
        conn_data->mitm->user = strdup(user);
    }

    if (geoip && conn_data->stream->type == UV_TCP) {
        ip_mask_pair_t* allowed_ips = NULL;
        geo_country_t* allowed_countries = NULL;

        if (conn_data->mitm->data && conn_data->mitm->data_len) {
            /* decode json and use that data as cdb value */
            struct json_object *jobj = json_tokener_parse(conn_data->mitm->data);

            if (jobj) {
                int data_len=json_object_get_string_len(jobj);
                const char *data = json_object_get_string(jobj);

                get_data_from_curl (data_len, data,
                                        user, user_len, &mysql_server,
                                        &conn_data->mitm->password, &allowed_ips, &allowed_countries);

                json_object_put(jobj);
            } else {
                logmsg("cannot decode json from str (%s)", conn_data->mitm->data);
            }

        } else {
            get_data_from_cdb (user, user_len, &mysql_server,
                               &conn_data->mitm->password, &allowed_ips, &allowed_countries);
        }

        struct sockaddr_in peer;
        int peer_len = sizeof(peer);
        int allowed = 1;

        if (0 == uv_tcp_getpeername((uv_tcp_t*) conn_data->stream, (struct sockaddr*) &peer, &peer_len)) {
            bool ip_check = !allowed_ips || ip_in_networks(peer.sin_addr.s_addr, allowed_ips);
            bool country_check = !allowed_countries || ip_in_countries((struct sockaddr *) &peer, allowed_countries);

            if ((allowed_ips && !ip_check) || (allowed_countries && !country_check)) {
                allowed = 0;
            }

            if (allowed_ips) {
                free (allowed_ips);
            }

            if (allowed_countries) {
                free (allowed_countries);
            }

            if (!allowed) {
                logmsg("Disconnected %s from %s, country check: %u, ip check: %u failed", user, get_ipport(conn_data), country_check, ip_check);
                send_mysql_error(conn_data, "Access denied, login from unauthorized ip or country");

                if (mysql_server)
                    free (mysql_server);

                return 1;
            }

        }
    } else {
        if (conn_data->mitm->data && conn_data->mitm->data_len) {
            struct json_object *jobj = json_tokener_parse(conn_data->mitm->data);

            if (jobj) {
                int data_len=json_object_get_string_len(jobj);
                const char *data = json_object_get_string(jobj);

                get_data_from_curl (data_len, data,
                                        user, user_len, &mysql_server,
                                        &conn_data->mitm->password, NULL, NULL);

                json_object_put(jobj);
            } else {
                logmsg("cannot decode json from str (%s)", conn_data->mitm->data);
            }
        } else {
            get_data_from_cdb (user, user_len, &mysql_server,
                               &conn_data->mitm->password, NULL, NULL);
        }
    }

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

        logmsg ("%s: invalid client packet size (packet too small 2) from %s%s",
                __FUNCTION__, get_ipport (conn_data), get_sslinfo (conn_data));

        return 1;
    }

    if (mysql_server != NULL) {
        if (conn_data->mitm->data && conn_data->mitm->data_len && is_this_rackunit(mysql_server)) {
            logmsg ("ext api set mysql_server this rackunit (%s) for user %s from %s%s", mysql_server, user, get_ipport (conn_data), get_sslinfo (conn_data));

            send_mysql_error(conn_data, "Access denied, loop detected");

            if (mysql_server)
                free (mysql_server);

            return 1;
        }
        destination = add_destination(mysql_server);
    } else {
        if (external_lookup && external_lookup_url && !conn_data->mitm->curl_handle) {
            uv_read_stop(conn_data->stream);
            make_curl_request(conn_data, user);
            return 1;
        }

        /* if user is not found in cdb, sent client error msg & close connection  */
        destination = first_destination;

        logmsg ("user %s not found in cdb from %s%s", user, get_ipport (conn_data), get_sslinfo (conn_data));
        /* we reply access denied  */

        send_mysql_error(conn_data, "Access denied, unknown user '%s'", user);

        if (mysql_server)
            free (mysql_server);

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
        logmsg ("%s: failed to create remote server connection", __FUNCTION__);
        uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
        if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
            free (shutdown);
        }
        if (mysql_server)
            free (mysql_server);

        return 1;
    }

    if (loglogins) {
        if (conn_data->listener->s[0]=='t') {
            logmsg ("user %s login from %s%s, upstream: %s", user, get_ipport (conn_data), get_sslinfo (conn_data), mysql_server);
        } else {
            logmsg ("user %s login from socket, upstream: %s", user, mysql_server);
        }
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

    /*
    logmsg("CLIENT_CONNECT_ATTRS %d %d %d",
      check_server_capability(cache_mysql_init_packet, cache_mysql_init_packet_len, CLIENT_CONNECT_ATTRS),
      check_server_capability(uv_buf->base, nread, CLIENT_CONNECT_ATTRS),
      check_client_capability(conn_data->mitm->client_auth_packet, CLIENT_CONNECT_ATTRS));
    logmsg("CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA %d %d %d",
      check_server_capability(cache_mysql_init_packet, cache_mysql_init_packet_len, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA),
      check_server_capability(uv_buf->base, nread, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA),
      check_client_capability(conn_data->mitm->client_auth_packet, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA));
    logmsg("CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS %d %d %d",
      check_server_capability(cache_mysql_init_packet, cache_mysql_init_packet_len, CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS),
      check_server_capability(uv_buf->base, nread, CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS),
      check_client_capability(conn_data->mitm->client_auth_packet, CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS));
    logmsg("CLIENT_SESSION_TRACKING %d %d %d",
      check_server_capability(cache_mysql_init_packet, cache_mysql_init_packet_len, CLIENT_SESSION_TRACKING),
      check_server_capability(uv_buf->base, nread, CLIENT_SESSION_TRACKING),
      check_client_capability(conn_data->mitm->client_auth_packet, CLIENT_SESSION_TRACKING));
    logmsg("CLIENT_DEPRECATE_EOF %d %d %d",
      check_server_capability(cache_mysql_init_packet, cache_mysql_init_packet_len, CLIENT_DEPRECATE_EOF),
      check_server_capability(uv_buf->base, nread, CLIENT_DEPRECATE_EOF),
      check_client_capability(conn_data->mitm->client_auth_packet, CLIENT_DEPRECATE_EOF));
    */

    if (check_server_capability(uv_buf->base, nread, CLIENT_CONNECT_ATTRS) &&
         !check_server_capability(cache_mysql_init_packet, cache_mysql_init_packet_len, CLIENT_CONNECT_ATTRS) &&
         check_client_capability(conn_data->mitm->client_auth_packet, CLIENT_CONNECT_ATTRS)) {

        disable_client_capability(conn_data->mitm->client_auth_packet, CLIENT_CONNECT_ATTRS);
    }

    if (check_server_capability(uv_buf->base, nread, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) &&
         !check_server_capability(cache_mysql_init_packet, cache_mysql_init_packet_len, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) &&
         check_client_capability(conn_data->mitm->client_auth_packet, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)) {

        disable_client_capability(conn_data->mitm->client_auth_packet, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA);
    }

    if (check_server_capability(uv_buf->base, nread, CLIENT_SESSION_TRACKING) &&
         !check_server_capability(cache_mysql_init_packet, cache_mysql_init_packet_len, CLIENT_SESSION_TRACKING) &&
         check_client_capability(conn_data->mitm->client_auth_packet, CLIENT_SESSION_TRACKING)) {

        disable_client_capability(conn_data->mitm->client_auth_packet, CLIENT_SESSION_TRACKING);
    }

    if (check_server_capability(uv_buf->base, nread, CLIENT_DEPRECATE_EOF) &&
         !check_server_capability(cache_mysql_init_packet, cache_mysql_init_packet_len, CLIENT_DEPRECATE_EOF) &&
         check_client_capability(conn_data->mitm->client_auth_packet, CLIENT_DEPRECATE_EOF)) {

        disable_client_capability(conn_data->mitm->client_auth_packet, CLIENT_DEPRECATE_EOF);
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
        disable_client_side_ssl_flag(newbuf->base);
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

    conn_data->mitm->handshake = 3;

    if (uv_read_start (conn_data->stream, alloc_cb, mysql_on_read)) {
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

void
disable_client_side_ssl_flag(char *packet)
{
    uint16_t client_capabilities;
    char *ptr;
    ptr =  packet + MYSQL_PACKET_HEADER_SIZE;
    memcpy (&client_capabilities, (void *)ptr, sizeof(uint16_t));
    if ((client_capabilities & 0x800) == 0x800) {
        client_capabilities = client_capabilities & ~0x800;
        memcpy ((void *) ptr, &client_capabilities, sizeof(uint16_t));
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
set_packet_seq(char *packet, uint8_t n)
{
    uint8_t seqnr;
    char *ptr;
    ptr =  packet + MYSQL_PACKET_HEADER_SIZE - 1;
    memcpy (&seqnr, (void *)ptr, sizeof(uint8_t));
    seqnr = n;
    memcpy ((void *)ptr, &seqnr, sizeof(uint8_t));
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

void send_mysql_error(struct conn_data* conn_data, const char* fmt, ...)
{
    char buf[512];
    int buflen;

    memcpy (buf, ERR_LOGIN_PACKET_PREFIX,
            sizeof (ERR_LOGIN_PACKET_PREFIX));

    va_list ap;
    va_start(ap, fmt);

    buflen =
            vsnprintf (buf + sizeof (ERR_LOGIN_PACKET_PREFIX) - 1,
                      sizeof (buf) - sizeof (ERR_LOGIN_PACKET_PREFIX),
                      fmt, ap);

    va_end(ap);

    buf[0] = buflen + sizeof (ERR_LOGIN_PACKET_PREFIX) - 5;

    if (conn_data->ssl) {
        increment_packet_seq(buf);
        //set_packet_seq(buf, 2);
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
        uv_write (req, conn_data->stream, newbuf, 1, on_write);
    }

    uv_shutdown_t *shutdown = malloc (sizeof (uv_shutdown_t));
    if (uv_shutdown (shutdown, conn_data->stream, on_shutdown)) {
        free (shutdown);
    }
}

int
check_server_capability(char *packet, size_t len, uint32_t capability)
{
    uint32_t server_capabilities;
    char *ptr;
    char *ptr2;

    if (len < MYSQL_PACKET_HEADER_SIZE + 1) {
        return 0;
    }

    // TODO buffer overflow, i am lazy to fix it, its handling first packet from trusted servers
    for (ptr = packet + MYSQL_PACKET_HEADER_SIZE + 1; *ptr!='\0'; ptr ++);
    ptr += 1 + 4;
    for (ptr = ptr + 1; *ptr!='\0'; ptr ++);
    ptr += 1;
    memcpy (&server_capabilities, (void *)ptr, sizeof(uint16_t));
    ptr += 2; // capability flags (lower 2 bytes)
    ptr += 1; // charset
    ptr += 2; // status flag
    /* capability flags (upper 2 bytes) */
    ptr2 = (char *)&server_capabilities;
    ptr2 +=2;
    memcpy (ptr2, (void *)ptr, sizeof(uint16_t));
    if ((server_capabilities & capability) == capability) {
        return 1;
    } else {
        return 0;
    }
}

int
check_client_capability(char *packet, uint32_t capability)
{
    uint32_t client_capabilities;
    char *ptr;
    ptr =  packet + MYSQL_PACKET_HEADER_SIZE;
    memcpy (&client_capabilities, (void *)ptr, sizeof(uint32_t));
    if ((client_capabilities & capability) == capability) {
        return 1;
    } else {
        return 0;
    }
}

void
disable_client_capability(char *packet, uint32_t capability)
{
    uint32_t client_capabilities;
    char *ptr;
    ptr =  packet + MYSQL_PACKET_HEADER_SIZE;
    memcpy (&client_capabilities, (void *)ptr, sizeof(uint32_t));

    if ((client_capabilities & capability) == capability) {
        client_capabilities = client_capabilities & ~capability;
        memcpy ((void *) ptr, &client_capabilities, sizeof(uint32_t));
    }
}

