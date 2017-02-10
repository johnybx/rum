#include "rum.h"

char *postgresql_cdb_file = NULL;
struct cdb postgresql_cdb;
int postgresql_cdb_fd;
struct event *postgresql_ev_signal;

void
init_postgresql_cdb_file (char *type)
{
    uv_fs_event_t *fs_event_req = malloc(sizeof(uv_fs_event_t));
    uv_fs_event_init(uv_default_loop(), fs_event_req);
    uv_fs_event_start(fs_event_req, reopen_cdb_postgresql, postgresql_cdb_file, 0);

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

    *postgresql_server = strdup (tmp+1);

    return;
}

void
reopen_cdb_postgresql (uv_fs_event_t *handle, const char *filename, int events, int status)
{
    /* re-arm inotify watch before reopening file */
    uv_fs_event_stop(handle);
    uv_fs_event_init(uv_default_loop(), handle);
    uv_fs_event_start(handle, reopen_cdb_postgresql, postgresql_cdb_file, 0);

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
