#include "rum.h"

#include "mysql_password/my_global.h"
#include "mysql_password/mysql_com.h"
#include "mysql_password/sha1.h"

extern struct event_base *event_base;

extern char *cache_mysql_init_packet;
extern int cache_mysql_init_packet_len;

extern struct destination *first_destination;

/* initialize struct mysql_mitm */
struct mysql_mitm *init_ms() {

	struct mysql_mitm *ms;

	ms=malloc(sizeof(struct mysql_mitm));
	ms->not_need_remote=0;
	ms->handshake=0;
	ms->client_auth_packet=NULL;
	ms->password=NULL;
	ms->scramble1=NULL;
	ms->scramble2=NULL;
	ms->hash_stage1=NULL;
	ms->hash_stage2=NULL;

	return ms;
}

/* free struct mysql_mitm and all variables inside where we use malloc() */
void free_ms(struct mysql_mitm *ms) {
	if (ms==NULL) {
		return;
	}

	if (ms->client_auth_packet) {
		free(ms->client_auth_packet);
		ms->client_auth_packet=NULL;
	}

	if (ms->password) {
		free(ms->password);
		ms->password=NULL;
	}
	if (ms->scramble1) {
		free(ms->scramble1);
		ms->scramble1=NULL;
	}
	if (ms->scramble2) {
		free(ms->scramble2);
		ms->scramble2=NULL;
	}
	if (ms->hash_stage1) {
		free(ms->hash_stage1);
		ms->hash_stage1=NULL;
	}
	if (ms->hash_stage2) {
		free(ms->hash_stage2);
		ms->hash_stage2=NULL;
	}

	free(ms);
}


/* parameter is packet, we need to concatenate bytes scramble_buff, it is split in packet in 2 places
 * and then return this string
 *
 * this variable must be null terminated, but in packet there is already '\0' character at the end of scramble_buff
 * but there can be evil people sending evil strings so we add one char with '\0'
 */
char *get_scramble_from_init_packet(char *packet, size_t len) {
/* packet overview:
 size			      wtf
===========================================================
 1                            protocol_version
 n (Null-Terminated String)   server_version
 4                            thread_id
 8                            scramble_buff <------------------- this
 1                            (filler) always 0x00
 2                            server_capabilities
 1                            server_language
 2                            server_status
 13                           (filler) always 0x00 ...
 13                           rest of scramble_buff (4.1)   <--- and this
*/
	char *p;
	char *scramble;

	p=packet + MYSQL_PACKET_HEADER_SIZE + 1;

	while(*p!='\0') p++;
	p+=1+4;

	scramble = malloc(8 + 13 + 1);
	scramble[8+13]='\0';

	memcpy(scramble, p, 8);

	p+=8+1+2+1+2+13;

	memcpy(scramble+8, p, 13);

	return scramble;
}


char *set_random_scramble_on_init_packet(char *packet, void *p1, void *p2) {
	struct rand_struct rand;
	char *p;
	char *scramble;

	scramble=malloc(SCRAMBLE_LENGTH+1);

	randominit(&rand,(ulong) p1,(ulong) p2);

	create_random_string(scramble, SCRAMBLE_LENGTH, &rand);

	p=packet + MYSQL_PACKET_HEADER_SIZE + 1;

	while(*p!='\0') p++;
	p+=1+4;

	memcpy(p,scramble,8);

	p+=8+1+2+1+2+13;

	memcpy(p, scramble+8 ,13);

	return scramble;
}


int handle_init_packet_from_server(struct bev_arg *bev_arg, struct bufferevent *bev, int len, struct bufferevent *bev_remote) {
	char mysql_server_init_packet[4096];
	bev_arg->ms->handshake=1;

	/* paket too small or too big */
	if (len < MYSQL_PACKET_HEADER_SIZE + MYSQL_INIT_PACKET_MIN_SIZE ||
	len > sizeof(mysql_server_init_packet) ) {

		bev_arg->listener->nr_conn--;

		free_ms(bev_arg->ms);
		bev_arg->ms=NULL;

		if (bev_arg->remote) {
			bev_arg->remote->ms=NULL;
			bufferevent_free(bev_arg->remote->bev);
			free(bev_arg->remote);
		}

		bufferevent_free(bev);
		free(bev_arg);
		return 1;
	}

	/* copy data from server (bev) to mysql_server_init_packet_variable */
	evbuffer_copyout(bufferevent_get_input(bev), mysql_server_init_packet, len);

	/* get scramble into shared struct mysql_mitm between our socket and client socket */
	bev_arg->ms->scramble1 = get_scramble_from_init_packet(mysql_server_init_packet, len);

	return 0;
}


int handle_auth_packet_from_client(struct bev_arg *bev_arg, struct bufferevent *bev, int len, struct bufferevent *bev_remote) {
	char user[64];
	int user_len;
	struct bev_arg *bev_arg_remote;
	struct destination *destination=NULL, *dst;
	char *mysql_server=NULL, *c, *i, *userptr;

	if (len < MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS + 1) {
		bev_arg->listener->nr_conn--;

		free_ms(bev_arg->ms);
		bev_arg->ms=NULL;

		if (bev_arg->remote) {
			bev_arg->remote->ms=NULL;
			bufferevent_free(bev_arg->remote->bev);
			free(bev_arg->remote);
		}

		bufferevent_free(bev);
		free(bev_arg);

		return 1;
	}

	bev_arg->ms->client_auth_packet = malloc(len);
	bev_arg->ms->client_auth_packet_len = len;

	evbuffer_copyout(bufferevent_get_input(bev), bev_arg->ms->client_auth_packet, len);
	evbuffer_drain(bufferevent_get_input(bev), len);

	userptr=bev_arg->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS;
	user_len=strlen(userptr);
	if (user_len>sizeof(user)){
		user_len=sizeof(user);
	}
	strncpy(user, bev_arg->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS, user_len);
	user[user_len]='\0';

	get_data_from_cdb(user, user_len, &mysql_server, &bev_arg->ms->password);
	
	i = bev_arg->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS + user_len + 1;
	c = bev_arg->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS + user_len + 1 + 1;

	/* scramble length in client packet != 0 (client dont sent empty password) */
	if (*i && bev_arg->ms->password) {
		bev_arg->ms->hash_stage2=malloc(SHA1_HASH_SIZE);
		get_salt_from_password(bev_arg->ms->hash_stage2, bev_arg->ms->password);

		bev_arg->ms->hash_stage1=malloc(SHA1_HASH_SIZE);

		get_hash_stage1(c, bev_arg->ms->scramble1, bev_arg->ms->hash_stage2, bev_arg->ms->hash_stage1);
	}

	if (mysql_server!=NULL) {
		for (dst=first_destination ; dst->next ; dst=dst->next) {
			if (!strcmp(dst->s, mysql_server)) {
				destination=dst;
				break;
			}
		}

		if (!destination) {
			dst->next = destination = malloc(sizeof(struct destination));
			prepareclient(mysql_server, destination);
		}
	} else {
			/* if user is not found in cdb we use mysql server set with -d argument
			 * but connection will not be successful, we need user encrypted password which should be in cdb file
			 */
			destination=first_destination;
	}

	/* if remote connection exists free it */
	if (bev_arg->remote) {
		bufferevent_free(bev_arg->remote->bev);
		free(bev_arg->remote);
	}

	bev_remote = bufferevent_socket_new(event_base, -1, BEV_OPT_CLOSE_ON_FREE);

	if (!bev_remote) {
		free_ms(bev_arg->ms);
		bev_arg->ms=NULL;
		bufferevent_free(bev);
		free(bev_arg);
		if (mysql_server)
			free(mysql_server);

		return 1;
	}

	bev_arg_remote=malloc(sizeof (struct bev_arg));

	bev_arg_remote->bev=bev_remote;

	bev_arg->remote=bev_arg_remote;
	bev_arg_remote->remote=bev_arg;
	bev_arg->ms->not_need_remote=0;

	bev_arg_remote->type=BEV_TARGET;

	bev_arg_remote->ms=bev_arg->ms;
	bev_arg_remote->listener=bev_arg->listener;

	bev_arg->ms->handshake=2;

	bev_arg_remote->connecting=0;

	bufferevent_setcb(bev_remote, mysql_read_callback, NULL, mysql_event_callback, (void *)bev_arg_remote);

	bufferevent_disable(bev, EV_READ);

	bufferevent_setwatermark(bev_remote, EV_READ, 0, INPUT_BUFFER_LIMIT);
	bev_arg_remote->connecting=1;
	if (bufferevent_socket_connect(bev_remote, (struct sockaddr *)&destination->sin, destination->addrlen)==-1) {
		/* this if is needed here, because if connect() fails libevent will call mysql_event_callback
		 * immediately, and not from main event loop. so bev_arg->ms can be already freed
		 */
		if (bev_arg->ms) {
			free_ms(bev_arg->ms);
			bev_arg->ms=NULL;
		}

		if (bev_arg->remote) {
			bufferevent_free(bev_arg->remote->bev);
			bev_arg->remote->ms=NULL;
			free(bev_arg->remote);
		}

		bufferevent_free(bev);
		free(bev_arg);

		if (mysql_server)
			free(mysql_server);

		return 1;
	}
	bev_arg_remote->connecting=0;
	struct linger l;

	l.l_onoff=1;
	l.l_linger=0;

	setsockopt(bufferevent_getfd(bev_remote), SOL_SOCKET, SO_LINGER, (void *) &l, sizeof (l));

	if (mysql_server)
		free(mysql_server);

	return 1;
}

int handle_auth_with_server(struct bev_arg *bev_arg, struct bufferevent *bev, int len, struct bufferevent *bev_remote) {
	char *user;
	int user_len;
	char *scramble_ptr;
	char mysql_server_init_packet[4096];

	if (len < MYSQL_PACKET_HEADER_SIZE + MYSQL_INIT_PACKET_MIN_SIZE || len > sizeof(mysql_server_init_packet)) {
		bev_arg->listener->nr_conn--;

		free_ms(bev_arg->ms);
		bev_arg->ms=NULL;

		if (bev_arg->remote) {
			bev_arg->remote->ms=NULL;
			bufferevent_free(bev_arg->remote->bev);
			free(bev_arg->remote);
		}

		bufferevent_free(bev);
		free(bev_arg);

		return 1;
	}


	if (bev_arg->ms->hash_stage1) {
		evbuffer_copyout(bufferevent_get_input(bev), mysql_server_init_packet, len);

		bev_arg->ms->scramble2 = get_scramble_from_init_packet(mysql_server_init_packet, len);
	}

	evbuffer_drain(bufferevent_get_input(bev), len);

	if (bev_arg->ms->hash_stage1) {
		user=bev_arg->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS;
		user_len=strlen(user);

		scramble_ptr=bev_arg->ms->client_auth_packet + MYSQL_PACKET_HEADER_SIZE + MYSQL_AUTH_PACKET_USER_POS + user_len + 1 + 1;

		scramble_with_hash_stage1(scramble_ptr, bev_arg->ms->scramble2, bev_arg->ms->hash_stage1);
	}

	if (bufferevent_write(bev, bev_arg->ms->client_auth_packet, bev_arg->ms->client_auth_packet_len)==-1) {
		bev_arg->listener->nr_conn--;

		free_ms(bev_arg->ms);
		bev_arg->ms=NULL;
		if (bev_arg->remote) {
			bev_arg->remote->ms=NULL;
			bufferevent_free(bev_arg->remote->bev);
			free(bev_arg->remote);
		}

		bufferevent_free(bev);
		free(bev_arg);

		return 1;
	}

	free_ms(bev_arg->ms);
	bev_arg->ms=NULL;
	bev_arg->remote->ms=NULL;

	bufferevent_setcb(bev, read_callback, NULL, event_callback, (void *)bev_arg);
	bufferevent_setcb(bev_remote, read_callback, NULL, event_callback, (void *)bev_arg->remote);

	bufferevent_enable(bev_remote, EV_READ);

	return 1;
}

