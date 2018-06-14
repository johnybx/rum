

#include "geoip.h"

#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define geo_perror(x) fprintf(stderr, "[geo %s:%u]: %s\n", __FILE__, __LINE__, sqlite3_errstr(x));

geo_t* geo_new(const char* filename)
{
    sqlite3* db;
    int result = sqlite3_open_v2(filename, &db, SQLITE_OPEN_READONLY, NULL);

    if (result != SQLITE_OK) {
        geo_perror(result);
        return NULL;
    }

    sqlite3_stmt* stmt_country_check;

    const char sql[] = "SELECT country_code FROM geoip WHERE ? BETWEEN ip_begin AND ip_end";
    result = sqlite3_prepare_v2(db, sql, sizeof(sql) - 1, &stmt_country_check, NULL);

    if (result != SQLITE_OK) {
        sqlite3_close_v2(db);
        geo_perror(result);
        return NULL;
    }

    geo_t* geo = (geo_t*) malloc(sizeof(geo_t));
    geo->db = db;
    geo->stmt_country_check = stmt_country_check;

    return geo;
}

bool geo_check_allowed_countries(geo_t* geo, uint32_t ip, geo_country_t* countries)
{
    int result;
    int allow = false;

    if (SQLITE_OK != (result = sqlite3_bind_int64(geo->stmt_country_check, 1, (sqlite3_int64) __bswap_32(ip)))) {
        goto error;
    }

#ifndef NDEBUG
    printf("SQLITE QUERY  %u\n", ip);
#endif

    while (SQLITE_ROW == sqlite3_step(geo->stmt_country_check)) {
        const char* code = (const char*) sqlite3_column_text(geo->stmt_country_check, 0);

#ifndef NDEBUG
        printf("[geo] country: %s\n", code);
#endif

        if (!code || strlen(code) != 2) {
            continue;
        }

        for (int i = 0; *countries[i].country_code; ++i) {
            if (!memcmp(countries[i].country_code, code, 2)) {
                allow = true;
                goto break_2;
            }
        }
    }
break_2:

    if (SQLITE_OK != (result = sqlite3_reset(geo->stmt_country_check)))  {
        goto error;
    }

    return allow;

error:
    geo_perror(result);
    return false;
}

void geo_destroy(geo_t* geo)
{
    int result = sqlite3_finalize(geo->stmt_country_check);
    if (result != SQLITE_OK)
        geo_perror(result);

    result = sqlite3_close_v2(geo->db);
    if (result != SQLITE_OK)
        geo_perror(result);

    free(geo);
}
