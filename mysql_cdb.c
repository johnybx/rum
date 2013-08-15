#include "rum.h"

extern struct event_base *event_base;

char *mysql_cdb_file=NULL;
struct cdb cdb;
int cdb_fd;
struct event *ev_signal;

void init_mysql_cdb_file() {
	struct timeval tv;

	if ((cdb_fd=open(mysql_cdb_file, O_RDONLY))==-1) {
		perror("open(mysql_cdb_file, O_ORDONLY)");
		exit(-1);
	} else {
		cdb_init(&cdb, cdb_fd);
	}

	ev_signal=event_new(event_base, SIGUSR1, EV_SIGNAL, reopen_cdb, NULL);
	tv.tv_usec=0;
	tv.tv_sec=CDB_RELOAD_TIME;
	event_add(ev_signal, &tv);

	cache_init_packet_from_server();
}


/* IN user - NULL terminated string with username of connecting client (from auth packet)
 * IN user_len - length of user
 * OUT mysql_server - if user is found in cdb we fill it with "tcp:host:port"
 * OUT mysql_password - if user is found in cdb we fill it with hex encoded password (from mysql.user table password column)
 */
void get_data_from_cdb(char *user, int user_len, char **mysql_server, char **mysql_password) {
	int result;
        unsigned int dlen;
        uint32_t dpos;
	char tmp[1024];

	if (cdb_fd==-1) {
		return;
	}

	result=cdb_find(&cdb, user, user_len);

	if (result<=0) {
		return;
	}

        dpos = cdb_datapos(&cdb);
        dlen = cdb_datalen(&cdb);

	if (dlen > sizeof(tmp)) {
		return;
	}

	result = cdb_read(&cdb, tmp, dlen, dpos);

	*mysql_password=strdup(tmp);
	*mysql_server=strdup(tmp + strlen(*mysql_password) + 1);

	return;
}

/* every CDB_RELOAD_TIME reopen mysql_cdb_file */
void reopen_cdb(int sig, short event, void *a)
{
	struct timeval tv;

	if (cdb_fd!=-1) {
		cdb_free(&cdb);
		close(cdb_fd);
	}

	if ((cdb_fd=open(mysql_cdb_file, O_RDONLY))==-1) {
		cdb_fd=-1;
	} else {
		cdb_init(&cdb, cdb_fd);
	}

	tv.tv_usec=0;
	tv.tv_sec=CDB_RELOAD_TIME;

	/* re-add the ev_signal to min event loop */
	event_add(ev_signal, &tv);
}


