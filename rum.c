#include "rum.h"

/* some global variables */
struct listener *first_listener;
struct destination *first_destination = NULL;
struct event_base *event_base;

extern char *mysql_cdb_file;
char **argvptr;
int *argcptr;

int
main (int ac, char *av[])
{
    int ret, ch, daemonize = 0;
    char *logfile = NULL;
    argvptr = av;
    argcptr = &ac;

    struct destination *destination;
    struct listener *listener;

    struct rlimit fdlimit;
    fdlimit.rlim_cur = 65535;
    fdlimit.rlim_max = 65535;

    setrlimit (RLIMIT_NOFILE, &fdlimit);

    signal (SIGPIPE, SIG_IGN);

    char *mysqltype = NULL;

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

    while ((ch = getopt (ac, av, "bd:s:m:l:M:t:")) != -1) {
        switch (ch) {
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
            listener->fd = create_listen_socket (optarg);
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
        case 'd':
            first_destination = destination =
                malloc (sizeof (struct destination));
            prepareclient (optarg, destination);
            break;
        case 'l':
            logfile = strdup (optarg);
            break;
        case 't':
            mysqltype = optarg;
            break;
        }
    }

    event_base = event_base_new ();

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
        struct event *ev;

        ev = event_new (event_base, listener->fd, EV_READ | EV_PERSIST,
                        accept_connect, listener);
        event_add (ev, NULL);
    }

    /* main libevent loop */
    event_base_loop (event_base, 0);

    usage ();

    exit (0);
}


void
usage ()
{
    printf
        ("\n./rum -s tcp:host:port [-s tcp:host:port [-s sock:path]] [-d tcp:host:port] [-t mysqltype] [-b] [-m tcp:host:port] [-M /path/to/mysql.cdb]\n\t-s - listen host:port or sockfile (host muste be some ip address from interface or 0.0.0.0 for all inerfaces)\n\t-d - destination host:port\n\n\toptional:\n\t-t - mysql type (mysql50, mysql51, mariadb55), when used do not use -d\n\t-b - goto background\n\t-m - statistics port\n\t-M - enable handling of mysql connection with more destination servers, argument is path to cdb file\n\n");
    exit (-1);
}

void
logmsg (const char *fmt, ...)
{
    va_list args;
    FILE *fp;
    char outstr[200];
    time_t t;
    struct tm *tmp;
    int i;

    t = time (NULL);
    tmp = localtime (&t);
    if (tmp == NULL) {
        perror ("localtime");
        return;
    }

    fp = fopen ("/var/log/rum.log", "a");
    if (!fp) {
        fprintf (stderr, "cannot open logfile\n");
        fflush (stderr);
        return;
    }

    if (strftime (outstr, sizeof (outstr), "%Y-%m-%d %H:%M:%S", tmp) == 0) {
        fprintf (stderr, "strftime returned 0");
        fclose (fp);
        return;
    }

    fprintf (fp, "%s ", outstr);

    fprintf (fp, "[");
    for (i = 0; i < *argcptr; i++) {
        if (i == *argcptr - 1) {
            fprintf (fp, "%s", argvptr[i]);
        } else {
            fprintf (fp, "%s ", argvptr[i]);
        }
    }
    fprintf (fp, "] ");


    va_start (args, fmt);
    vfprintf (fp, fmt, args);
    va_end (args);
/*    fprintf(fp, " (open fds: %d)\n", get_num_fds()); */
    fflush (fp);
    fclose (fp);
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
