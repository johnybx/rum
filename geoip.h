//
// Created by marek on 30.5.2018.
//

#ifndef RUM_GEOIP_H
#define RUM_GEOIP_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

typedef struct __attribute__((__packed__)) {
    char country_code[2];
} geo_country_t;

void init_mmdb(const char* filename);
void reopen_mmdb (uv_timer_t* handle);
bool mmdb_check_allowed_countries(struct sockaddr *sa, geo_country_t* countries);
void close_mmdb();

#endif //RUM_GEOIP_H
