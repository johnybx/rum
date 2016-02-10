#include "rum.h"

/* some global variables */
struct listener *first_listener;
struct destination *first_destination = NULL;
struct event_base *event_base;

extern char *mysql_cdb_file;
extern char *postgresql_cdb_file;
char logstring[512];
int mode = MODE_NORMAL;
int destinations = 0;
int connect_timeout = CONNECT_TIMEOUT;
int read_timeout = READ_TIMEOUT;

int
main (int ac, char *av[])
{
    int ret, ch, daemonize = 0;
    char *logfile = NULL;
    int i;
    char *tmp,*ptr;

    struct destination *destination = NULL;
    struct listener *listener;

    struct rlimit fdlimit;
    fdlimit.rlim_cur = 65535;
    fdlimit.rlim_max = 65535;

    setrlimit (RLIMIT_NOFILE, &fdlimit);

    signal (SIGPIPE, SIG_IGN);

    char *mysqltype = NULL;

    setenv ("TZ", ":/etc/localtime", 0);
    tzset ();

    memset (logstring, '\0', sizeof(logstring));
    for (i = 0; i < ac; i++) {
        if (strlen(logstring)+strlen(av[i])>=sizeof(logstring)) {
            break;
        }
        strcat(logstring, av[i]);

        if (i != ac - 1) {
            strcat(logstring, " ");
        }
    }


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
        {"background",  no_argument,       0, 'b' },
        {"destination", required_argument, 0, 'd' },
        {"source",      required_argument, 0, 's' },
        {"stats",       required_argument, 0, 'm' },
        {"logfile",     required_argument, 0, 'l'},
        {"mysql-cdb",   required_argument, 0,  'M' },
        {"postgresql-cdb",   required_argument, 0,  'P' },
        {"mysqltype",   required_argument, 0,  't' },
        {"failover-r",   required_argument, 0,  'R' },
        {"failover",   required_argument, 0,  'f' },
        {"failover-rr",   required_argument, 0,  'r' },
        {"read-timeout",   required_argument, &read_timeout,  0 },
        {"connect-timeout",   required_argument, &connect_timeout,  0 },
        {0,         0,                 0,  0 }
    };


    while ((ch = getopt_long (ac, av, "bd:s:m:l:M:P:t:r:f:R:", long_options, &option_index)) != -1) {
//    while ((ch = getopt (ac, av, "bd:s:m:l:M:P:t:r:f:")) != -1) {
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
        case 'P':
            /* enable mysql module */
            postgresql_cdb_file = strdup (optarg);
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
        case 'f':
            mode=MODE_FAILOVER;
            ptr=tmp=strdup(optarg);
            i=0;
            while(tmp[i]!='\0') {
                if (tmp[i]==',') {
                    tmp[i]='\0';
                    add_destination(ptr);
                    destinations++;
                    ptr=tmp+i+1;
                }
                i++;
            }

            add_destination(ptr);
            destinations++;

            break;

        case 'r':
            mode=MODE_FAILOVER_RR;
            ptr=tmp=strdup(optarg);
            i=0;
            while(tmp[i]!='\0') {
                if (tmp[i]==',') {
                    tmp[i]='\0';
                    add_destination(ptr);
                    destinations++;
                    ptr=tmp+i+1;
                }
                i++;
            }

            add_destination(ptr);
            destinations++;
            randomize_destinations();

            break;

        case 'R':
            mode=MODE_FAILOVER_R;
            ptr=tmp=strdup(optarg);
            i=0;
            while(tmp[i]!='\0') {
                if (tmp[i]==',') {
                    tmp[i]='\0';
                    add_destination(ptr);
                    destinations++;
                    ptr=tmp+i+1;
                }
                i++;
            }

            add_destination(ptr);
            destinations++;
            randomize_destinations();

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

    if (postgresql_cdb_file) {
        init_postgresql_cdb_file (mysqltype);
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
        ("\n./rum -s tcp:host:port [-s tcp:host:port [-s sock:path]] [-d tcp:host:port] [-t mysqltype] [-b] [-m tcp:host:port] [-M /path/to/mysql.cdb] [-P /path/to/postgresql.cdb]\n\t-s - listen host:port or sockfile (host muste be some ip address from interface or 0.0.0.0 for all inerfaces)\n\t-d - destination host:port\n\n\toptional:\n\t-r tcp:dst1:port1,tcp:dst2:port2,tcp:dst3:port3,... - randomize list of targets and use round-robin for first target\n\t-f tcp:dst1:port1,tcp:dst2:port2,tcp:dst3:port3,... - connect always to dst1 as first target and failover to second,... in case of fail\n\t-R tcp:dst1:port1,tcp:dst2:port2,tcp:dst3:port3,... - like -f but randomize tgt list\n\t-t - mysql type (mysql50, mysql51, mariadb55), when used do not use -d\n\t-b - goto background\n\t-m - statistics port\n\t-M - enable handling of mysql connection with more destination servers, argument is path to cdb file\n\t-P - enable handling of postgresql connection with more destination servers, argument is path to cdb file\n\t--connect-timeout 6 - connect timeout when server is not available (default 6)\n\t--read-timeout 6 - read timeout from server, only for first data (default 6, use 0 to disable)\n\n");
    exit (-1);
}

void
logmsg (const char *fmt, ...)
{
    va_list args;
    static FILE *fp = NULL;
    static ino_t inode = 0;
    char outstr[200];
    time_t t;
    struct tm *tmp;
    struct stat statbuf;
    int staterror = 0;
    static char lastmsg[4096];
    char tmpmsg[4096];
    static int samemsg=0;

    t = time (NULL);
    tmp = localtime (&t);
    if (tmp == NULL) {
        perror ("localtime");
        return;
    }

    if (stat ("/var/log/rum.log", &statbuf) !=0 )
    {
        staterror=1;
    }

    if (!fp) {
        fp = fopen ("/var/log/rum.log", "a");
    } else {
        if (inode != statbuf.st_ino || staterror) {
            fclose(fp);
            fp = fopen ("/var/log/rum.log", "a");
            inode = statbuf.st_ino;
        }
    }

    if (!fp) {
        fprintf (stderr, "cannot open logfile\n");
        fflush (stderr);
        return;
    }

    va_start (args, fmt);
    vsnprintf (tmpmsg, sizeof(tmpmsg), fmt, args);
    va_end (args);

    if (!strcmp (lastmsg, tmpmsg)) {
        samemsg++;
        return;
    } else {
        strncpy(lastmsg, tmpmsg, sizeof(lastmsg));
    }

    if (strftime (outstr, sizeof (outstr), "%Y-%m-%d %H:%M:%S", tmp) == 0) {
        fprintf (stderr, "strftime returned 0");
        fclose (fp);
        return;
    }

    if (samemsg>0) {
        fprintf (fp, "%s ", outstr);
        fprintf (fp, "[%s] ", logstring);
        fprintf (fp, "last message repeated %d times\n", samemsg);
        samemsg=0;
    }


    fprintf (fp, "%s ", outstr);
    fprintf (fp, "[%s] ", logstring);

    va_start (args, fmt);
    vfprintf (fp, fmt, args);
    va_end (args);
/*    fprintf(fp, " (open fds: %d)\n", get_num_fds()); */
    fflush (fp);
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

void add_destination (char *ptr)
{
    struct destination *destination = NULL, *dst;

    if (first_destination) {
        for (dst = first_destination; dst->next; dst = dst->next) {
            if (!strcmp (dst->s, ptr)) {
                destination = dst;
                break;
            }
        }

        if (!destination) {
            dst->next = destination = malloc (sizeof (struct destination));
            prepareclient (ptr, destination);
        }
    } else {
        first_destination = destination = malloc (sizeof (struct destination));
        prepareclient (ptr, destination);
    }

    return;
}

void randomize_destinations ()
{
    struct destination *array[destinations], *dst;
    int i;

    for (i = 0, dst = first_destination ; i < destinations ; i++) {
        array[i]=dst;
        dst=dst->next;
    }

    shuffle(array, destinations);


    dst = first_destination = array[0];
    for (i = 1 ; i < destinations ; i++) {
        dst->next=array[i];
        dst=dst->next;
    }

    dst->next=NULL;
}

void shuffle(struct destination **array, size_t n)
{
    srand(time(NULL));
    if (n > 1)
    {
        size_t i;
        for (i = 0; i < n - 1; i++)
        {
          size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
          struct destination *t = array[j];
          array[j] = array[i];
          array[i] = t;
        }
    }
}
