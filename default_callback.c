#include "rum.h"

/*
 * if some data are in input buffer, copy it to remote bufferevent output buffer
 */
void read_callback(struct bufferevent *bev, void *ptr)
{
	struct bev_arg *bev_arg=ptr;
	size_t len;

	/* if remote bufferevent exist */
	if (bev_arg->remote) {
		struct bufferevent *bev_remote=bev_arg->remote->bev;

		/* update stats */
		len = evbuffer_get_length(bufferevent_get_input(bev));
		if (len) {
			/* update stats */
			if (bev_arg->type==BEV_CLIENT) {
				bev_arg->listener->input_bytes+=len;
			} else if (bev_arg->type==BEV_TARGET) {
				bev_arg->listener->output_bytes+=len;
			}
		}

		/* write data from our intput buffer to remote output buffer */
		//if (bufferevent_read_buffer(bev, bufferevent_get_output(bev_remote))==-1) {
		if (bufferevent_write_buffer(bev_remote, bufferevent_get_input(bev))==-1) {
			/* if error, close our socket, remote socket and free everything */
			bev_arg->listener->nr_conn--;

			bufferevent_free(bev);
			bufferevent_free(bev_remote);
			free(bev_arg->remote);
			free(bev_arg);

			return;
		}

		/* If remote bufferevent has more data than OUTPUT_BUFFER_LIMIT 
		 * disable EV_READ on our bev and enable write_callback on remote bev.
		 * We enable EV_READ again when all data on remote socket buffer are written,
		 * this is done in write_callback() when remote socket write event is triggered.
		*/
		if (evbuffer_get_length(bufferevent_get_output(bev_remote)) >= OUTPUT_BUFFER_LIMIT) {
			bufferevent_disable(bev, EV_READ);
			bufferevent_setcb(bev_remote, read_callback, write_callback, event_callback, (void *)bev_arg->remote);
		}
	} else {
		/* remote socket is closed, free self */
		bev_arg->listener->nr_conn--;

		bufferevent_free(bev);
		free(bev_arg);
	}
}

/* if data are sent from output buffer of bev, this function is called,
 * it is not active all the time, but only in some situations (bev has too many data in output buffer)
 * we can find out if all data are written to network and free memory
 */
void write_callback(struct bufferevent *bev, void *ptr)
{
	struct bev_arg *bev_arg=ptr;

	/* if bufferevent send all data to socket */
	if (evbuffer_get_length(bufferevent_get_output(bev))==0) {
		/* if remote socket exist */
		if (bev_arg->remote) {
			/*
			 * now enable EV_READ on remote socket bufferevent so we can receive data from it
			 * and disable write_callback fn for self
			 */
			struct bufferevent *bev_remote=bev_arg->remote->bev;

			bufferevent_enable(bev_remote, EV_READ);
			bufferevent_setcb(bev, read_callback, NULL, event_callback, (void *)bev_arg);
		} else {
			/* if remote socket is closed and we dont have any data in output buffer, free self */
			bev_arg->listener->nr_conn--;

			bufferevent_free(bev);
			free(bev_arg);
		}
	}
}

void event_callback(struct bufferevent *bev, short events, void *ptr) {
	struct bev_arg *bev_arg=ptr;

	/* if remote socket exist */
	if (bev_arg->remote) {
		struct bufferevent *bev_remote=bev_arg->remote->bev;

		/* connection to remote host is successful, enable EV_READ */
		if (events & BEV_EVENT_CONNECTED) {
			bufferevent_enable(bev, EV_READ);
			bufferevent_enable(bev_remote, EV_READ);
		/* error or eof */
		} else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF) ) {
			if (bev_arg->connecting) {
				/* this code is called from another event function, return immediately and dont free anything 
				 * this is probably a bug in libevent, in evbuffer_socket_connect() when connect() fail event_callback is directly called
				 */
				return;
			}
			bufferevent_free(bev);

			/* if remote socket doesnt have any data in output buffer, free structures and close it */
			if (evbuffer_get_length(bufferevent_get_output(bev_remote))==0) {
				bufferevent_free(bev_remote);
				free(bev_arg->remote);

				bev_arg->listener->nr_conn--;
			} else {
				/* if remote socket has still some data in output buffer dont close it
				 * but enable write_callback, it will free self when write all data
				 */
				bev_arg->remote->remote=NULL;
				bufferevent_setcb(bev_remote, read_callback, write_callback, event_callback, (void *)bev_arg->remote);
			}

			free(bev_arg);
		}
	} else {
		/* if remote socket doesnt exist, free self and close socket */
		bev_arg->listener->nr_conn--;

		bufferevent_free(bev);
		free(bev_arg);
	}
}
