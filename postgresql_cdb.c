#include "rum.h"

extern struct event_base *event_base;

char *postgresql_cdb_file = NULL;
struct cdb postgresql_cdb;
int postgresql_cdb_fd;
struct event *postgresql_ev_signal;

void
init_postgresql_cdb_file (char *type)
{
    struct timeval tv;

    if ((postgresql_cdb_fd = open (postgresql_cdb_file, O_RDONLY)) == -1) {
        perror ("open(postgresql_cdb_file, O_ORDONLY)");
        exit (-1);
    } else {
        cdb_init (&postgresql_cdb, postgresql_cdb_fd);
    }

    postgresql_ev_signal = event_new (event_base, SIGUSR1, EV_SIGNAL, reopen_cdb_postgresql, NULL);
    tv.tv_usec = 0;
    tv.tv_sec = CDB_RELOAD_TIME;
    event_add (postgresql_ev_signal, &tv);
}


/* IN user - NULL terminated string with username of connecting client (from auth packet)
 * IN user_len - length of user
 * OUT postgresql_server - if user is found in cdb we fill it with "tcp:host:port"
 */
void
get_data_from_cdb_postgresql (char *user, int user_len, char **postgresql_server)
{
    int result;
    unsigned int dlen;
    uint32_t dpos;
    char tmp[1024];

    if (postgresql_cdb_fd == -1) {
        return;
    }

    result = cdb_find (&postgresql_cdb, user, user_len);

    if (result <= 0) {
        return;
    }

    dpos = cdb_datapos (&postgresql_cdb);
    dlen = cdb_datalen (&postgresql_cdb);

    if (dlen > sizeof (tmp)) {
        return;
    }

    result = cdb_read (&postgresql_cdb, tmp, dlen, dpos);

    *postgresql_server = strdup (tmp);

    return;
}

/* every CDB_RELOAD_TIME reopen postgresql_cdb_file */
void
reopen_cdb_postgresql (int sig, short event, void *a)
{
    struct timeval tv;

    if (postgresql_cdb_fd != -1) {
        cdb_free (&postgresql_cdb);
        close (postgresql_cdb_fd);
    }

    if ((postgresql_cdb_fd = open (postgresql_cdb_file, O_RDONLY)) == -1) {
        postgresql_cdb_fd = -1;
    } else {
        cdb_init (&postgresql_cdb, postgresql_cdb_fd);
    }

    tv.tv_usec = 0;
    tv.tv_sec = CDB_RELOAD_TIME;

    /* re-add the ev_signal to min event loop */
    event_add (postgresql_ev_signal, &tv);
}
