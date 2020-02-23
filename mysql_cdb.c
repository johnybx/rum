#include "rum.h"

char *mysql_cdb_file = NULL;
struct cdb cdb;
int cdb_fd;
static uv_timer_t *timer = NULL;

extern enum dbtype dbtype;
extern char *dbtypestr;

void
stop_mysql_cdb_file ()
{
    uv_timer_stop(timer);
    free(timer);
    timer = NULL;
}

void
init_mysql_cdb_file ()
{
    timer = malloc (sizeof (uv_timer_t));
    uv_timer_init (uv_default_loop(), timer);
    int r = uv_timer_start (timer, reopen_cdb, CDB_RELOAD_TIME*1000, CDB_RELOAD_TIME*1000);
    if (r) {
        fprintf (stderr, "%s: uv_timer_start failed (%s)\n", __FUNCTION__, uv_strerror(r));
        exit (1);
    }

    if (dbtype != DBTYPE_MYSQL || dbtypestr == NULL) {
        fprintf (stderr, "you must use -t dbtype with -M\n");
        exit (1);
    }

    if ((cdb_fd = open (mysql_cdb_file, O_RDONLY)) == -1) {
        return;
    } else {
        cdb_init (&cdb, cdb_fd);
    }
}


/* IN user - NULL terminated string with username of connecting client (from auth packet)
 * IN user_len - length of user
 * OUT mysql_server - if user is found in cdb we fill it with "tcp:host:port"
 * OUT mysql_password - if user is found in cdb we fill it with hex encoded password (from mysql.user table password column)
 */
void
get_data_from_cdb (char *user, int user_len, char **mysql_server,
                   char **mysql_password, ip_mask_pair_t** allowed_ips,
                   geo_country_t** allowed_countries)
{
    int result;
    unsigned int dlen;
    uint32_t dpos;
    char tmp[1024];

    if (cdb_fd == -1) {
        logmsg ("%s: cdb_fd == -1 (user %s)", __FUNCTION__, user);
        return;
    }

    result = cdb_find (&cdb, user, user_len);

    if (result <= 0) {
        return;
    }

    dpos = cdb_datapos (&cdb);
    dlen = cdb_datalen (&cdb);

    if (dlen > sizeof (tmp)) {
        logmsg ("%s: dlen > sizeof (tmp) (user %s)", __FUNCTION__, user);
        return;
    }

    result = cdb_read (&cdb, tmp, dlen, dpos);

    *mysql_password = strdup (tmp);
    *mysql_server = strdup (tmp + strlen (*mysql_password) + 1);


    unsigned int read = strlen(*mysql_password) + strlen(*mysql_server) + 2;
    unsigned int remaining = dlen - read;

    if (remaining >= 1 && allowed_ips && allowed_countries) {
        get_ip_access_from_cdb_tail(&tmp[read], remaining, allowed_ips, allowed_countries);
    }

    return;
}

/* reopen mysql_cdb_file after inotify */
void
reopen_cdb (uv_timer_t* handle) 
{
    //uv_timer_stop (handle);
    //uv_timer_start (timer, reopen_cdb, CDB_RELOAD_TIME*1000, CDB_RELOAD_TIME*1000);

    if (cdb_fd != -1) {
        cdb_free (&cdb);
        close (cdb_fd);
    }

    if ((cdb_fd = open (mysql_cdb_file, O_RDONLY)) == -1) {
        cdb_fd = -1;
        logmsg ("%s: open failed (%s)", __FUNCTION__, strerror (errno));
    } else {
        cdb_init (&cdb, cdb_fd);
    }
}

