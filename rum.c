#include "rum.h"

/* some global variables */
struct listener *first_listener;
struct destination *first_destination = NULL;

extern char *mysql_cdb_file;
extern char *postgresql_cdb_file;
int mode = MODE_NORMAL;
int destinations = 0;
int connect_timeout = CONNECT_TIMEOUT;
int read_timeout = READ_TIMEOUT;
int daemonize = 0;
int loglogins = 0;
int server_ssl = 0;
SSL_CTX *ctx = NULL;
SSL_CTX *client_ctx = NULL;
char *ssl_cert = NULL;
char *ssl_key = NULL;
char *ssl_ciphers = SSL_CIPHERS;
char *ssl_min_proto = NULL;
char *ssl_max_proto = NULL;
int verbose = 0;
char *mysqltype = NULL;
int geoip = 0;

void
signal_handler (uv_signal_t * handle, int signum)
{
    uv_stop (uv_default_loop ());
}


int
main (int ac, char *av[])
{
    int ret, ch;
    char *logfile = NULL;
    int i, ok;
    char *tmp, *ptr;
    uv_signal_t *sigint;
    uv_signal_t *sigterm;
    char *pidfile = NULL;

    struct destination *destination = NULL;
    struct listener *listener;

    struct rlimit rl;
    rl.rlim_cur = 65535;
    rl.rlim_max = 65535;

    setrlimit (RLIMIT_NOFILE, &rl);

    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;

    setrlimit (RLIMIT_CORE, &rl);

    signal (SIGPIPE, SIG_IGN);

    setenv ("TZ", ":/etc/localtime", 0);
    tzset ();

    sigint = malloc (sizeof (uv_signal_t));
    sigterm = malloc (sizeof (uv_signal_t));
    uv_signal_init (uv_default_loop (), sigint);
    uv_signal_init (uv_default_loop (), sigterm);
    uv_signal_start (sigint, signal_handler, SIGINT);
    uv_signal_start (sigterm, signal_handler, SIGTERM);

    openlog ("rum", LOG_NDELAY | LOG_PID, LOG_DAEMON);

    if (ac == 1) {
        usage ();
    }

    /* destination is global variable a pointer to struct destination
     * struct destination forms a linked list
     * first_destination is pointer to first struct
     * 
     * struct listener is the same
     */

    listener = NULL;

    int option_index = 0;
    static struct option long_options[] = {
        {"background", no_argument, 0, 'b'},
        {"destination", required_argument, 0, 'd'},
        {"source", required_argument, 0, 's'},
        {"stats", required_argument, 0, 'm'},
        {"logfile", required_argument, 0, 'l'},
        {"mysql-cdb", required_argument, 0, 'M'},
        {"postgresql-cdb", required_argument, 0, 'P'},
        {"mysqltype", required_argument, 0, 't'},
        {"failover-r", required_argument, 0, 'R'},
        {"failover", required_argument, 0, 'f'},
        {"read-timeout", required_argument, 0, 0},
        {"connect-timeout", required_argument, 0, 0},
        {"pidfile", required_argument, 0, 'p'},
        {"loglogins", no_argument, 0, 'L'},
        {"ssl-server", no_argument, 0, 0},
        {"ssl-cert", required_argument, 0, 0},
        {"ssl-key", required_argument, 0, 0},
        {"ssl-ciphers", required_argument, 0, 0},
        {"ssl-min-proto", required_argument, 0, 0},
        {"ssl-max-proto", required_argument, 0, 0},
        {"geoip", required_argument, 0, 'g'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };


    while ((ch =
            getopt_long (ac, av, "bd:s:m:l:M:P:t:r:f:R:p:Lg:v", long_options,
                         &option_index)) != -1) {
        switch (ch) {
        case 0:
            if (strcmp (long_options[option_index].name, "read-timeout") == 0)
                read_timeout = atoi (optarg);
            if (strcmp (long_options[option_index].name, "connect-timeout") ==
                0)
                connect_timeout = atoi (optarg);
            if (strcmp (long_options[option_index].name, "ssl-server") == 0)
                server_ssl = 1;
            if (strcmp (long_options[option_index].name, "ssl-cert") == 0)
                ssl_cert = strdup(optarg);
            if (strcmp (long_options[option_index].name, "ssl-key") == 0)
                ssl_key = strdup(optarg);
            if (strcmp (long_options[option_index].name, "ssl-ciphers") == 0)
                ssl_ciphers = strdup(optarg);
            if (strcmp (long_options[option_index].name, "ssl-min-proto") == 0)
                ssl_min_proto = strdup(optarg);
            if (strcmp (long_options[option_index].name, "ssl-max-proto") == 0)
                ssl_max_proto = strdup(optarg);
            break;

        case 'b':
            daemonize = 1;
            break;
        case 's':
        case 'm':
            if (listener == NULL) {
                first_listener = listener = malloc (sizeof (struct listener));
            } else {
                listener->next = malloc (sizeof (struct listener));
                listener = listener->next;
            }
            listener->s = strdup (optarg);
            listener->stream = NULL;
            listener->next = NULL;
            /* vynulujeme statistiky */
            listener->nr_conn = 0;
            listener->nr_allconn = 0;
            listener->input_bytes = 0;
            listener->output_bytes = 0;
            if (ch == 's') {
                listener->type = LISTENER_DEFAULT;
            } else if (ch == 'm') {
                listener->type = LISTENER_STATS;
            }
            break;
        case 'M':
            /* enable mysql module */
            mysql_cdb_file = strdup (optarg);
            break;
        case 'P':
            /* enable mysql module */
            postgresql_cdb_file = strdup (optarg);
            break;

        case 'd':
            first_destination = destination =
                malloc (sizeof (struct destination));
            prepare_upstream (optarg, destination);
            break;
        case 'l':
            logfile = strdup (optarg);
            break;
        case 'L':
            loglogins = 1;
            break;
        case 't':
            mysqltype = optarg;
            break;
        case 'f':
            mode = MODE_FAILOVER;
            ptr = tmp = strdup (optarg);
            i = 0;
            while (tmp[i] != '\0') {
                if (tmp[i] == ',') {
                    tmp[i] = '\0';
                    add_destination (ptr);
                    destinations++;
                    ptr = tmp + i + 1;
                }
                i++;
            }

            add_destination (ptr);
            destinations++;

            break;

        case 'R':
            mode = MODE_FAILOVER_R;
            ptr = tmp = strdup (optarg);
            i = 0;
            while (tmp[i] != '\0') {
                if (tmp[i] == ',') {
                    tmp[i] = '\0';
                    add_destination (ptr);
                    destinations++;
                    ptr = tmp + i + 1;
                }
                i++;
            }

            add_destination (ptr);
            destinations++;
            randomize_destinations ();

            break;

        case 'p':
            pidfile = strdup (optarg);
            break;

        case 'g':
            logmsg("Using geoip db %s", optarg);
            init_mmdb(optarg);
            geoip = 1;
            break;

        case 'v':
            verbose = 1;
            break;
        }

    }

    /* if mysql module is enabled, open cdb file and create EV_SIGNAL event which call repoen_cdb().
     * if someone send SIGUSR1 cdb file is reopened, but this is automatically triggered by timeout with
     * CDB_RELOAD_TIME seconds (default 2s)
     *
     * reopen_cdb is called from main event loop, it is not called directly by signal,
     * so it is race condition free (safe to free and init global cdb variable)
     */
    if (mysql_cdb_file) {
        init_mysql_cdb_file (mysqltype);
    }

    if (postgresql_cdb_file) {
        init_postgresql_cdb_file (mysqltype);
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    client_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_session_cache_mode(client_ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_set_cipher_list(client_ctx, ssl_ciphers);

    ctx = SSL_CTX_new(TLS_server_method());
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE;
    if (ssl_min_proto) {
        if (strcmp(ssl_min_proto, "ssl3") == 0) {
            SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
        } else if (strcmp(ssl_min_proto, "tls1") == 0) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
        } else if (strcmp(ssl_min_proto, "tls1.1") == 0) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
        } else if (strcmp(ssl_min_proto, "tls1.2") == 0) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        }else if (strcmp(ssl_min_proto, "tls1.3") == 0) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        }
    } else {
        SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    }

    if (ssl_max_proto) {
        if (strcmp(ssl_max_proto, "ssl3") == 0) {
            SSL_CTX_set_max_proto_version(ctx, SSL3_VERSION);
        } else if (strcmp(ssl_max_proto, "tls1") == 0) {
            SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION);
        } else if (strcmp(ssl_max_proto, "tls1.1") == 0) {
            SSL_CTX_set_max_proto_version(ctx, TLS1_1_VERSION);
        } else if (strcmp(ssl_max_proto, "tls1.2") == 0) {
            SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
        } else if (strcmp(ssl_max_proto, "tls1.3") == 0) {
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        }
    } else {
        /* tls1.3 not working with mariadb-client-core-10.3, not sure why, use default max tls1.2 */
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    }

    SSL_CTX_set_options(ctx, flags);
    SSL_CTX_set_cipher_list(ctx, ssl_ciphers);
    SSL_CTX_set_ecdh_auto(ctx, 1);
    if (ssl_cert) {
        if (SSL_CTX_use_certificate_chain_file(ctx, ssl_cert) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }
    if (ssl_key) {
        if (SSL_CTX_use_PrivateKey_file(ctx, ssl_key, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    if (daemonize) {
        if (logfile) {
            if (daemon (0, 1) < 0) {
                perror ("daemon()");
                exit (0);
            }
            close (0);
            close (1);
            close (2);
            ret =
                open (logfile, O_WRONLY | O_CREAT | O_APPEND,
                      S_IRUSR | S_IWUSR);
            if (ret != -1) {
                dup2 (ret, 1);
                dup2 (ret, 2);
            }
        } else {
            if (daemon (0, 0) < 0) {
                perror ("daemon()");
                exit (0);
            }
        }
    }

    /* add all listen (-s -m) ports to event_base, if someone connect: accept_connect is executed with struct listener argument */
    for (listener = first_listener; listener; listener = listener->next) {
        for (i = 0, ok = 0; i < 10; i++) {
            listener->stream = create_listen_socket (listener->s, &listener->sockettype);
            listener->stream->data = listener;
            int r =
                uv_listen ((uv_stream_t *) listener->stream, -1,
                           on_incoming_connection);

            if (r) {
                logmsg ("listen to %s failed, retrying", listener->s);
                uv_close ((uv_handle_t *) listener->stream, on_close_listener);
                usleep (200 * 1000);
            } else {
                logmsg ("listening on %s", listener->s);
                ok = 1;
                break;
            }
        }

        if (ok == 0) {
            logmsg ("listen to %s failed, exiting", listener->s);
            _exit (-1);
        }

    }

    if (!first_destination && !mysql_cdb_file && !postgresql_cdb_file) {
        usage ();
    }

    if (daemonize) {
        if (pidfile) {
            FILE *fp = fopen(pidfile, "w");
            if (fp) {
                fprintf (fp, "%d", getpid());
                fclose (fp);
            } else {
                logmsg("cannot open pidfile %s (%s)", pidfile, strerror (errno));
            }
        }
    }

    /* main libuv loop */
    uv_run (uv_default_loop (), UV_RUN_DEFAULT);

    /* SIGINT || SIGTERM received, clean up */
    if (mysql_cdb_file) {
        stop_mysql_cdb_file();
        free (mysql_cdb_file);
    }

    if (postgresql_cdb_file) {
        stop_postgresql_cdb_file();
        free (postgresql_cdb_file);
    }

    close_mmdb();

    struct destination *dst;
    dst = first_destination;
    while (dst) {
        destination = dst->next;
        free (dst->s);
        free (dst);
        dst = destination;
    }

    SSL_CTX_free(ctx);
    SSL_CTX_free(client_ctx);

    free (sigint);
    free (sigterm);

    exit (0);
}


void
usage ()
{
    printf
        ("\n"
         "./rum -s [tcp|ssl]:host:port [-s [tcp|ssl]:host:port [-s sock:path]] [-d tcp:host:port] [-t mysqltype] [-b] [-m tcp:host:port] [-M /path/to/mysql.cdb] [-P /path/to/postgresql.cdb]"
         "\n\t"
         "-s - listen host:port or sockfile (host muste be some ip address from interface or 0.0.0.0 for all inerfaces)"
         "\n\t"
         "-d - destination host:port"
         "\n\n\t"
         "optional:"
         "\n\t"
         "-f tcp:dst1:port1,tcp:dst2:port2,tcp:dst3:port3,... - connect always to dst1 as first target and failover to second,... in case of fail"
         "\n\t"
         "-R tcp:dst1:port1,tcp:dst2:port2,tcp:dst3:port3,... - like -f but randomize tgt list"
         "\n\t"
         "-t - mysql type (mysql50, mysql51, mariadb55), when used do not use -d"
         "\n\t"
         "-b - goto background"
         "-L - log logins to syslog (when using -M or -P)"
         "\n\t"
         "--connect-timeout 6 - connect timeout when server is not available (default 6)"
         "\n\t"
         "--read-timeout 6 - read timeout from server, only for first data (default 6, use 0 to disable)"
         "\n\t"
         "--ssl-server - when using cdb (-M|-P) allow mysql/postgresql clients to connect with ssl (--ssl-cert/key required)"
         "\n\t"
         "--ssl-cert crt - path to cert file (optional intermediate certs in same file)"
         "\n\t"
         "--ssl-key key - path to key file"
         "\n\t"
         "--ssl-ciphers cipherlist (default \"%s\")"
         "\n\t"
         "--ssl-min-proto proto (default tls1)"
         "\n\t"
         "--ssl-max-proto proto (default tls1.2)"
         "\n\t"
         "-g /path/to/GeoLite2-Country.mmdb - enable ip/geoip protection (with -M|-P)"
         "\n\n", SSL_CIPHERS);
    exit (-1);
}

int logmsg_ssl(const char *str, size_t len, void *u)
{
    struct conn_data *conn_data = u;
    char *prefix;
    char *ipport = get_ipport(conn_data);

    if (conn_data->type == CONN_TARGET) {
        prefix = "upstream";
    } else {
        prefix = "client";
    }

    logmsg("%s %s %s", prefix, ipport, str);
    return 1;
}

void
logmsg (const char *fmt, ...)
{
    va_list args;
    char tmpmsg[4096];
    char *logstring;

    va_start (args, fmt);
    vsnprintf (tmpmsg, sizeof (tmpmsg), fmt, args);
    va_end (args);

    if (mysql_cdb_file) {
        logstring = mysqltype;
    } else if (postgresql_cdb_file) {
        logstring = "postgresql";
    } else {
        logstring = "rum";
    }

    syslog (LOG_DAEMON | LOG_WARNING, "[%s] %s", logstring, tmpmsg);
    if (!daemonize) {
        fprintf(stderr,"%s %s\n", logstring, tmpmsg);
    }

}

/* implementation of Donal Fellows method */
int
get_num_fds ()
{
    int fd_count;
    char buf[64];
    struct dirent *dp;

    snprintf (buf, 64, "/proc/%i/fd/", getpid ());

    fd_count = 0;
    DIR *dir = opendir (buf);
    while ((dp = readdir (dir)) != NULL) {
        fd_count++;
    }
    closedir (dir);
    return fd_count;
}

/* add upstream server to linked list of struct destination */
struct destination *
add_destination (char *ptr)
{
    struct destination *destination = NULL, *dst, *last;

    if (first_destination) {
        for (dst = first_destination; dst; dst = dst->next) {
            if (!strcmp (dst->s, ptr)) {
                destination = dst;
                break;
            }

            if (!dst->next) {
                last = dst;
            }
        }

        /* append new destination at end of linked list */
        if (!destination) {
            last->next = destination = malloc (sizeof (struct destination));
            prepare_upstream (ptr, destination);
        }
    } else {
        first_destination = destination = malloc (sizeof (struct destination));
        prepare_upstream (ptr, destination);
    }

    return destination;
}

void
randomize_destinations ()
{
    struct destination *array[destinations], *dst;
    int i;

    for (i = 0, dst = first_destination; i < destinations; i++) {
        array[i] = dst;
        dst = dst->next;
    }

    shuffle (array, destinations);


    dst = first_destination = array[0];
    for (i = 1; i < destinations; i++) {
        dst->next = array[i];
        dst = dst->next;
    }

    dst->next = NULL;
}

void
shuffle (struct destination **array, size_t n)
{
    srand (time (NULL));
    if (n > 1) {
        size_t i;
        for (i = 0; i < n - 1; i++) {
            size_t j = i + rand () / (RAND_MAX / (n - i) + 1);
            struct destination *t = array[j];
            array[j] = array[i];
            array[i] = t;
        }
    }
}

bool ip_in_networks(uint32_t ip, ip_mask_pair_t* networks)
{
    for (int i = 0; ; ++i) {
        ip_mask_pair_t* network = &networks[i];

        if (!network->ip && !network->mask) {
            break;
        }

        uint32_t start = network->ip & network->mask;
        uint32_t end = start | ~network->mask;

        if (ip >= start && ip <= end) {
            return true;
        }
    }

    return false;
}

bool ip_in_countries(struct sockaddr *sa, geo_country_t* countries)
{
    /*
    struct sockaddr_in *sin = sa;
    sin->sin_addr.s_addr = inet_addr("37.9.169.143");

    struct sockaddr_in6 sin;
    sin.sin6_family=AF_INET6;
    inet_pton(AF_INET6, "2a00:1450:4014:800::200e", (void *) &sin.sin6_addr);
    */

    return mmdb_check_allowed_countries(sa, countries);
}

void get_ip_access_from_cdb_tail(const char* buf, unsigned int remaining,
                                 ip_mask_pair_t** allowed_ips, geo_country_t** allowed_countries)
{
    unsigned int read = 0;
    unsigned int flags = (unsigned int) buf[read++];
    --remaining;

    if (flags & USER_FLAG_IP_CHECK_ENABLED) {
        unsigned char list_len = (unsigned char) (!remaining ?  0 : buf[read++]);
        remaining -= 1 + sizeof(ip_mask_pair_t) * list_len;

        if (list_len) {
            ip_mask_pair_t* pairs = calloc(list_len + 1, sizeof(ip_mask_pair_t));
            for (unsigned int i = 0; i < list_len; ++i) {
                pairs[i] = *((ip_mask_pair_t*) &buf[read]);
                read += sizeof(ip_mask_pair_t);
            }

            *allowed_ips = pairs;
        }
    }

    if (flags & USER_FLAG_COUNTRY_CHECK_ENABLED) {
        unsigned char list_len = (unsigned char) (!remaining ?  0 : buf[read++]);
        remaining -= 1 + sizeof(ip_mask_pair_t) * list_len;

        if (list_len)  {
            geo_country_t* countries = calloc(list_len + 1, sizeof(geo_country_t));
            for (unsigned int i = 0; i < list_len; ++i) {
                countries[i] = *((geo_country_t*) &buf[read]);
                read += sizeof(geo_country_t);
            }

            *allowed_countries = countries;
        }
    }
}
