#include "rum.h"
#include "geoip.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <maxminddb.h>

static MMDB_s mmdb;
static int mmdb_opened = 0;
static uv_timer_t *timer = NULL;
extern int verbose;

void init_mmdb(const char* filename)
{
    int status = MMDB_open(filename, MMDB_MODE_MMAP, &mmdb);
    if (MMDB_SUCCESS != status) {
        fprintf (stderr, "cannot open MMDB %s", MMDB_strerror(status));
        logmsg ("cannot open MMDB %s", MMDB_strerror(status));
    } else {
        mmdb_opened = 1;
    }

    timer = malloc (sizeof (uv_timer_t));
    uv_timer_init (uv_default_loop(), timer);
    timer->data = (void *) strdup(filename);
    int r = uv_timer_start (timer, reopen_mmdb, MMDB_RELOAD_TIME*1000, MMDB_RELOAD_TIME*1000);
    if (r) {
        logmsg ("%s: uv_timer_start failed (%s)\n", __FUNCTION__, uv_strerror(r));
        exit (1);
    }
}

void reopen_mmdb (uv_timer_t* handle) 
{
    if (mmdb_opened) {
        MMDB_close (&mmdb);
        mmdb_opened = 0;
        int status = MMDB_open(handle->data, MMDB_MODE_MMAP, &mmdb);
        if (MMDB_SUCCESS != status) {
            logmsg("%s: cannot open MMDB %s", __FUNCTION__, MMDB_strerror(status));
        } else {
            mmdb_opened = 1;
        }
    }
}

void close_mmdb()
{
    MMDB_close(&mmdb);
    mmdb_opened = 0;

    uv_timer_stop(timer);
    free (timer->data);
    free(timer);
}

bool mmdb_check_allowed_countries(struct sockaddr *sa, geo_country_t* countries)
{

    int mmdb_error;
    int status;
    MMDB_entry_data_s entry_data;
    MMDB_lookup_result_s result;
    bool allow = false;

    if (!mmdb_opened) {
        logmsg("MMDB is not opened");
        return allow;
    }

    result = MMDB_lookup_sockaddr(&mmdb, sa, &mmdb_error);

    if (MMDB_SUCCESS != mmdb_error) {
        logmsg("MMDB_lookup failed: %s", MMDB_strerror(mmdb_error));
        return false;
    }

    status = MMDB_get_value(&result.entry, &entry_data, "registered_country", "iso_code", NULL);

    if (!result.found_entry) {
        logmsg("IP %s not found in mmdb", get_ip_sockaddr(sa));
        return allow;
    }

    if (MMDB_SUCCESS != status) {
        logmsg("MMDB_get_value for ip %s failed: %s", get_ip_sockaddr(sa), MMDB_strerror(status));
        return allow;
    }

    if (!entry_data.has_data) {
        logmsg("geo country for %s not found", get_ip_sockaddr(sa));
        return allow;
    }

    if (entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
        logmsg("MMDB result wrong datatype for %s (%d)", get_ip_sockaddr(sa), entry_data.type);
        return allow;
    }

    char isocode[4] = {0};

    if (entry_data.data_size > sizeof(isocode)-1) {
        logmsg("MMDB isocode length too big ip %s (%d)", get_ip_sockaddr(sa), entry_data.type);
        return allow;
    }
    memcpy(isocode, entry_data.utf8_string, entry_data.data_size);

    if (verbose) {
        logmsg("geoip country for %s is %s", get_ip_sockaddr(sa), isocode);
    }

    for (int i = 0; *countries[i].country_code; ++i) {
        if (!memcmp(countries[i].country_code, isocode, 2)) {
            allow = true;
        }
    }

    return allow;

}
