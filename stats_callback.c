#include "rum.h"

/* when someone connect to statistics -m port, these functions are callbacks for bufferevent with client socket */
/* there is no read_callback fn, because we dont need to read data from client */

extern struct listener *first_listener;
extern struct destination *first_destination;

void stats_write_callback(struct bufferevent *bev, void *ptr) {
	struct bev_arg *bev_arg=ptr;

	/* all data send ? free everything and close socket  */
	if (evbuffer_get_length(bufferevent_get_output(bev))==0) {
		bev_arg->listener->nr_conn--;

		bufferevent_free(bev);
		free(bev_arg);

		return;
	}
}

void stats_event_callback(struct bufferevent *bev, short events, void *ptr) {
	struct bev_arg *bev_arg=ptr;

	/* connection closed or some error ? free everything and close socket  */
	if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF) ) {
		bev_arg->listener->nr_conn--;

		bufferevent_free(bev);
		free(bev_arg);
	}
}


#define STATS_BUF_SIZE 8192
/* we call this function from accept_connect() after client connect to stats port */
void send_stats_to_client (struct bufferevent *bev) {
	char tmp[STATS_BUF_SIZE];
	struct listener *listener;
	int len;
	struct destination *destination=first_destination;

	len=snprintf(tmp,STATS_BUF_SIZE,"[%20s] [   %10s] [%20s] [%15s] [%18s]\n","source","bytes","destination","all connections","actual connections");
	bufferevent_write(bev, tmp, len);
	for (listener=first_listener ; listener->next ; listener=listener->next) {
		if (listener->type==LISTENER_STATS)
			break;
		len=snprintf(tmp,STATS_BUF_SIZE,"[%20s] [-->%10u] [%20s] [%15u] [%18u]\n", listener->s, listener->input_bytes, destination->s, listener->nr_allconn,listener->nr_conn);
		bufferevent_write(bev, tmp, len);
		len=snprintf(tmp,STATS_BUF_SIZE," %20s  [<--%10u]  %20s   %15s   %18s\n\n", "", listener->output_bytes,"","","");
		bufferevent_write(bev, tmp, len);
	}
}
