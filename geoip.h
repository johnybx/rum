//
// Created by marek on 30.5.2018.
//

#ifndef RUM_GEOIP_H
#define RUM_GEOIP_H

#include <sqlite3.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

typedef struct {
    sqlite3* db;
    sqlite3_stmt* stmt_country_check;
} geo_t;

typedef struct __attribute__((__packed__)) {
    char country_code[2];
} geo_country_t;

geo_t* geo_new(const char* filename);
bool geo_check_allowed_countries(geo_t* geo, uint32_t ip, geo_country_t* countries);
void geo_destroy(geo_t* geo);

#endif //RUM_GEOIP_H
