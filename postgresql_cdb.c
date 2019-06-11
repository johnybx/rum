#include "rum.h"

char *postgresql_cdb_file = NULL;
struct cdb postgresql_cdb;
int postgresql_cdb_fd;
static uv_timer_t *timer;

void
stop_postgresql_cdb_file ()
{
    uv_timer_stop(timer);
    free(timer);
    timer = NULL;
}

void
init_postgresql_cdb_file (char *type)
{
    timer = malloc (sizeof (uv_timer_t));
    uv_timer_init (uv_default_loop(), timer);
    int r = uv_timer_start (timer, reopen_cdb_postgresql, CDB_RELOAD_TIME*1000, CDB_RELOAD_TIME*1000);
    if (r) {
        fprintf (stderr, "%s: uv_timer_start failed (%s)\n", __FUNCTION__, uv_strerror(r));
        exit (1);
    }


    if ((postgresql_cdb_fd = open (postgresql_cdb_file, O_RDONLY)) == -1) {
        return;
    } else {
        cdb_init (&postgresql_cdb, postgresql_cdb_fd);
    }
}


/* IN user - NULL terminated string with username of connecting client (from auth packet)
 * IN user_len - length of user
 * OUT postgresql_server - if user is found in cdb we fill it with "tcp:host:port"
 */
void
get_data_from_cdb_postgresql (char *user, int user_len,
                              char **postgresql_server)
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

    *postgresql_server = strdup (tmp + 1);

    return;
}

void
reopen_cdb_postgresql (uv_timer_t* handle) 
{
    if (postgresql_cdb_fd != -1) {
        cdb_free (&postgresql_cdb);
        close (postgresql_cdb_fd);
    }

    if ((postgresql_cdb_fd = open (postgresql_cdb_file, O_RDONLY)) == -1) {
        postgresql_cdb_fd = -1;
    } else {
        cdb_init (&postgresql_cdb, postgresql_cdb_fd);
    }
}
