#include "rum.h"

extern struct event_base *event_base;
extern struct destination *first_destination;

char *cache_mysql_init_packet=NULL;
int cache_mysql_init_packet_len;
char *cache_mysql_init_packet_scramble;

void mysql_read_callback(struct bufferevent *bev, void *ptr)
{
	struct bev_arg *bev_arg=ptr;
	size_t len;

	if (bev_arg->remote || (bev_arg->ms && bev_arg->ms->not_need_remote)) {
		struct bufferevent *bev_remote=NULL;

		if (bev_arg->remote) {
			bev_remote=bev_arg->remote->bev;
		}

		len=evbuffer_get_length(bufferevent_get_input(bev));
		if (len) {
			if (bev_arg->type==BEV_CLIENT) {
				bev_arg->listener->input_bytes+=len;
			} else if (bev_arg->type==BEV_TARGET) {
				bev_arg->listener->output_bytes+=len;
			}
		}
	
		/* data from mysql server */
		if (bev_arg->type==BEV_TARGET) {
			/* first data */
			if (bev_arg->ms->handshake==0) {
				if (handle_init_packet_from_server(bev_arg, bev, len, bev_remote)) {
					/* from all handle_ functions we want sometime to continue and sometime to return fast */
					return;
				}
			/* second data from server */
			} else if (bev_arg->ms->handshake==2) {
				if (handle_auth_with_server(bev_arg, bev, len, bev_remote)) {
					return;
				}
			}
		/* data from mysql client */
		} else if (bev_arg->type==BEV_CLIENT) {
			/* first data from client */
			if (bev_arg->ms->handshake==1) {
				if (handle_auth_packet_from_client(bev_arg, bev, len, bev_remote)) {
					return;
				}
			}
		}

		if (bufferevent_read_buffer(bev, bufferevent_get_output(bev_remote))==-1) {
			bev_arg->listener->nr_conn--;

			if (bev_arg->ms) {
				free_ms(bev_arg->ms);
			}

			if (bev_arg->remote) {
				bufferevent_free(bev_remote);
				free(bev_arg->remote);
			}

			bufferevent_free(bev);
			free(bev_arg);

			return;
		}

		/* if remote bufferevent has more data than OUTPUT_BUFFER_LIMIT 
		 *  disable EV_READ on ourself and enable write_callback on remote bev
		 */
		if (evbuffer_get_length(bufferevent_get_output(bev_remote)) >= OUTPUT_BUFFER_LIMIT) {
			bufferevent_disable(bev, EV_READ);
			bufferevent_setcb(bev_remote, mysql_read_callback, mysql_write_callback, mysql_event_callback, (void *)bev_arg->remote);
		}

	} else {
		bev_arg->listener->nr_conn--;

		if (bev_arg->ms) {
			free(bev_arg->ms);
		}

		if (bev_arg->remote) {
			bufferevent_free(bev_arg->remote->bev);
			free(bev_arg->remote);
		}

	
		bufferevent_free(bev);
		free(bev_arg);

		return;
	}
}

void mysql_write_callback(struct bufferevent *bev, void *ptr)
{

	struct bev_arg *bev_arg=ptr;

	if (evbuffer_get_length(bufferevent_get_output(bev))==0) {
		if (bev_arg->remote) {
			/* we write all our data to socket,
			 * now enable EV_READ on remote socket bufferevent so we can receive data from it
			 * and disable write_callback fn for self
			 */

			struct bufferevent *bev_remote=bev_arg->remote->bev;

			bufferevent_enable(bev_remote, EV_READ);
			bufferevent_setcb(bev, mysql_read_callback, NULL, mysql_event_callback, (void *)bev_arg);
		} else {
			/* if remote socket is closed and we dont have any data in output buffer, free self */

			bev_arg->listener->nr_conn--;

			/* this should be already freed, but to be sure */
			if (bev_arg->ms) {
				free_ms(bev_arg->ms);
				bev_arg->ms=NULL;
			}

			bufferevent_free(bev);
			free(bev_arg);
		}
	}
}

void mysql_event_callback(struct bufferevent *bev, short events, void *ptr) {
	struct bev_arg *bev_arg=ptr;

	/* if remote socket exist */
	if (bev_arg->remote || (bev_arg->ms && bev_arg->ms->not_need_remote)) {
		struct bufferevent *bev_remote=NULL;

		if (bev_arg->remote) {
			bev_remote=bev_arg->remote->bev;
		}

		/* connection to server successful, enable EV_READ */
		if (events & BEV_EVENT_CONNECTED) {
			bufferevent_enable(bev, EV_READ);
			if (bev_remote)
				bufferevent_enable(bev_remote, EV_READ);
		/* error or eof */
		} else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF) ) {
			if (bev_arg->connecting) {
				return;
			}

			if (bev_arg->ms) {
				free_ms(bev_arg->ms);
				bev_arg->ms=NULL;
				if (bev_arg->remote) {
					bev_arg->remote->ms=NULL;
				}
			}

			if (bev_remote) {
				/* if remote socket doesnt have any data in output buffer, free structures and close it */
				if (evbuffer_get_length(bufferevent_get_output(bev_remote))==0) {
					bev_arg->listener->nr_conn--;

					bufferevent_free(bev_remote);
					free(bev_arg->remote);
				} else {
					/* if remote socket has still some data in output buffer dont close it
					 * but enable write_callback, it will free self when write all data
					 */
					bufferevent_free(bev_remote);
					free(bev_arg->remote);
					bufferevent_setcb(bev_remote, mysql_read_callback, mysql_write_callback, mysql_event_callback, (void *)bev_arg->remote);
				}
			}

			bufferevent_free(bev);
			free(bev_arg);
		}
	/* if remote socket doesnt exist, free self */
	} else {
		bev_arg->listener->nr_conn--;

		if (bev_arg->ms) {
			free_ms(bev_arg->ms);
		}

		bufferevent_free(bev);
		free(bev_arg);
	}
}

/*
 * if we use mysql_cdb we read hello packet from server set with -d and copy it in global variable
 * cache_mysql_init_packet and cache_mysql_init_packet_len
 * then read scramble data
 */
void cache_mysql_init_packet_read_callback(struct bufferevent *bev, void *ptr)
{

	struct bev_arg *bev_arg=ptr;
	size_t len;

	len=evbuffer_get_length(bufferevent_get_input(bev));
	if (len) {
		cache_mysql_init_packet=malloc(len);
		cache_mysql_init_packet_len=len;

		evbuffer_copyout(bufferevent_get_input(bev), cache_mysql_init_packet, len);

		cache_mysql_init_packet_len=len;

		cache_mysql_init_packet_scramble = get_scramble_from_init_packet(cache_mysql_init_packet, cache_mysql_init_packet_len);
	}

	bufferevent_free(bev);
	free(bev_arg);
}

void cache_mysql_init_packet_event_callback(struct bufferevent *bev, short events, void *ptr) {
	struct bev_arg *bev_arg=ptr;

	if (events & BEV_EVENT_CONNECTED) {
		bufferevent_enable(bev, EV_READ);
	} else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF)) {
		bufferevent_free(bev);
		free(bev_arg);
	}
}
