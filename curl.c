#include "rum.h"

extern bool external_lookup;
extern char *external_lookup_url;
extern char *external_lookup_userpwd;
extern int external_lookup_timeout;
extern char *dbtype;
static struct hsearch_data htab;
extern cfg_bool_t external_lookup_cache;
extern long int external_lookup_cache_flush;
static struct ll_hsearch_data *mainll = NULL;

typedef struct curl_context_s {
  uv_poll_t poll_handle;
  curl_socket_t sockfd;
  struct conn_data *conn_data;
} curl_context_t;

static uv_timer_t flush_cache_timer;

/* like get_data_from_mysql() in mysql_cdb.c */
void
get_data_from_curl (int external_data_len, const char *external_data, char *user, int user_len, char **mysql_server,
                   char **mysql_password, ip_mask_pair_t** allowed_ips,
                   geo_country_t** allowed_countries)
{
    *mysql_password = strdup (external_data);
    *mysql_server = strdup (external_data + strlen (*mysql_password) + 1);

    unsigned int read = strlen(*mysql_password) + strlen(*mysql_server) + 2;
    int remaining = external_data_len - read;

    if (remaining >= 1 && allowed_ips && allowed_countries) {
        get_ip_access_from_cdb_tail(&external_data[read], remaining, allowed_ips, allowed_countries);
    }

    return;
}

static void check_multi_info(struct conn_data *conn_data)
{
  char *done_url;
  long code;
  CURLMsg *message;
  int pending;
  CURL *easy_handle;
  
  while((message = curl_multi_info_read(conn_data->mitm->curl_handle, &pending))) {
    switch(message->msg) {
    case CURLMSG_DONE:
      /* Do not use message data after calling curl_multi_remove_handle() and
         curl_easy_cleanup(). As per curl_multi_info_read() docs:
         "WARNING: The data the returned pointer points to will not survive
         calling curl_multi_cleanup, curl_multi_remove_handle or
         curl_easy_cleanup." */
      easy_handle = message->easy_handle;

      curl_easy_getinfo(easy_handle, CURLINFO_EFFECTIVE_URL, &done_url);
      curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &code);
      //printf("%s %ld DONE %d\n", done_url, code, conn_data->mitm->data_len);

      uv_buf_t uv_buf;
      uv_buf.base = conn_data->mitm->client_auth_packet;
      uv_buf.len = conn_data->mitm->client_auth_packet_len;
      if (code == 200 && conn_data->mitm->data_len) {
        if (external_lookup_cache == cfg_true) {
            add_data_to_cache(conn_data->mitm->user, conn_data->mitm->data);
        }
        handle_auth_packet_from_client (conn_data, &uv_buf, uv_buf.len);
      } else {
        if (code == 404) {
            add_data_to_cache(conn_data->mitm->user, NULL);
        }
        if (conn_data->mitm->curl_errorbuf) {
            logmsg ("curl request for %s failed, code: %ld error: %s", done_url, code, conn_data->mitm->curl_errorbuf);
        }
        /* if user is not found in external source, sent client error msg & close connection  */
        logmsg ("user %s not found in cdb/external from %s%s", conn_data->mitm->user, get_ipport (conn_data), get_sslinfo (conn_data));
        /* we reply access denied  */
        send_mysql_error(conn_data, "Access denied, unknown user '%s'", conn_data->mitm->user);
      }

      curl_multi_remove_handle(conn_data->mitm->curl_handle, easy_handle);
      curl_easy_cleanup(easy_handle);
      curl_multi_cleanup(conn_data->mitm->curl_handle);
      if (conn_data->mitm->curl_timer) {
          uv_timer_stop (conn_data->mitm->curl_timer);
          uv_close((uv_handle_t*) conn_data->mitm->curl_timer, on_close_timer);
          conn_data->mitm->curl_timer = NULL;
      }
      conn_data->mitm->curl_handle = NULL;
      free(conn_data->mitm->curl_errorbuf);
      conn_data->mitm->curl_errorbuf = NULL;

      if (conn_data->mitm->data) {
        free(conn_data->mitm->data);
      }

      break;

    default:
      fprintf(stderr, "CURLMSG default\n");
      break;
    }
  }
}

static void on_timeout(uv_timer_t *req)
{
  int running_handles;
  struct conn_data *conn_data = (struct conn_data *) req->data;
  curl_multi_socket_action(conn_data->mitm->curl_handle, CURL_SOCKET_TIMEOUT, 0,
                           &running_handles);
  check_multi_info(conn_data);
}

static int start_timeout(CURLM *multi, long timeout_ms, void *userp)
{
  struct conn_data *conn_data = (struct conn_data *) userp;
  if(timeout_ms < 0) {
    uv_timer_stop(conn_data->mitm->curl_timer);
  }
  else {
    if(timeout_ms == 0)
      timeout_ms = 1; /* 0 means directly call socket_action, but we'll do it
                         in a bit */
    uv_timer_start(conn_data->mitm->curl_timer, on_timeout, timeout_ms, 0);
  }
  return 0;
}

static curl_context_t* create_curl_context(curl_socket_t sockfd, struct conn_data *conn_data)
{
  curl_context_t *context;
 
  context = (curl_context_t *) malloc(sizeof(*context));
 
  context->sockfd = sockfd;
 
  uv_poll_init_socket(uv_default_loop (), &context->poll_handle, sockfd);
  context->poll_handle.data = context;
  context->conn_data = conn_data;
 
  return context;
}

static void curl_close_cb(uv_handle_t *handle)
{
  curl_context_t *context = (curl_context_t *) handle->data;
  free(context);
}

static void destroy_curl_context(curl_context_t *context)
{
  uv_close((uv_handle_t *) &context->poll_handle, curl_close_cb);
}

static void curl_perform(uv_poll_t *req, int status, int events)
{
  int running_handles;
  int flags = 0;
  curl_context_t *context;
  struct conn_data *conn_data;

  if(events & UV_READABLE)
    flags |= CURL_CSELECT_IN;
  if(events & UV_WRITABLE)
    flags |= CURL_CSELECT_OUT;

  context = (curl_context_t *) req->data;
  conn_data = context->conn_data;

  curl_multi_socket_action(conn_data->mitm->curl_handle, context->sockfd, flags,
                           &running_handles);

  check_multi_info(conn_data);
}

static int handle_socket(CURL *easy, curl_socket_t s, int action, void *userp,
                  void *socketp)
{
  struct conn_data *conn_data = (struct conn_data *) userp;
  curl_context_t *curl_context;
  int events = 0;

  switch(action) {
  case CURL_POLL_IN:
  case CURL_POLL_OUT:
  case CURL_POLL_INOUT:
    curl_context = socketp ?
      (curl_context_t *) socketp : create_curl_context(s, conn_data);

    curl_multi_assign(conn_data->mitm->curl_handle, s, (void *) curl_context);

    if(action != CURL_POLL_IN)
      events |= UV_WRITABLE;
    if(action != CURL_POLL_OUT)
      events |= UV_READABLE;

    uv_poll_start(&curl_context->poll_handle, events, curl_perform);
    break;
  case CURL_POLL_REMOVE:
    if(socketp) {
      uv_poll_stop(&((curl_context_t*)socketp)->poll_handle);
      destroy_curl_context((curl_context_t*) socketp);
      curl_multi_assign(conn_data->mitm->curl_handle, s, NULL);
    }
    break;
  default:
    abort();
  }

  return 0;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct conn_data *conn_data = (struct conn_data *) userdata;

    if (!conn_data->mitm->data) {
        conn_data->mitm->data = calloc(nmemb, size+1);
        memcpy(conn_data->mitm->data, ptr, nmemb*(size+1));
        conn_data->mitm->data_len = size*nmemb;
        conn_data->mitm->data[conn_data->mitm->data_len+1] = '\0';
    } else {
        conn_data->mitm->data = reallocarray(conn_data->mitm->data, nmemb, size);
        if (!conn_data->mitm->data) {
            // TODO realloc failed
        } else {
            conn_data->mitm->data_len = conn_data->mitm->data_len + (size*nmemb);
        }
    }

    return size*nmemb;
}


static void callback_flush_cache(uv_timer_t *req) {
    //logmsg ("flushing curl cache");
    hdestroy_r(&htab);
    ll_free();
    if (!hcreate_r(8192, &htab)) {
        logmsg("hcreate failed: %s", strerror (errno));
        exit(1);
    }
}

void init_curl_cache() {
    if (!hcreate_r(8192, &htab)) {
        logmsg("hcreate failed: %s", strerror (errno));
        exit(1);
    }

    uv_timer_init(uv_default_loop(), &flush_cache_timer);
    uv_timer_start(&flush_cache_timer, callback_flush_cache, external_lookup_cache_flush*1000, external_lookup_cache_flush*1000);
}

void free_curl_cache() {
    uv_timer_stop(&flush_cache_timer);

    hdestroy_r(&htab);
    ll_free();
}

char *ll_strdup(char *s) {
    struct ll_hsearch_data *ll;

    ll = calloc(1, sizeof(struct ll_hsearch_data));

    if (!ll) {
        logmsg("calloc failed");
        return NULL;
    }

    if (mainll == NULL) {
        mainll = ll;
    } else {
        ll->next = mainll;
        mainll = ll;
    }

    ll->data = strdup(s);

    return ll->data;
}

void ll_free() {
    struct ll_hsearch_data *ll=NULL, *prev=NULL;

    for (ll = mainll; ll; ll = ll->next) {
        if (ll->data) {
            free(ll->data);
        }
        if (prev) {
            free(prev);
        }
        prev = ll;
    }

    if (prev) {
        free(prev);
    }
    mainll = NULL;
}

void add_data_to_cache(char *user, char *data) {
    int ret;

    ENTRY e, *ep;

    e.key = ll_strdup(user);

    if (data) {
        e.data = ll_strdup(data);
    } else {
        e.data = NULL;
    }

    ret = hsearch_r(e, FIND, &ep, &htab);
    if (!ret && !ep) {
        ret = hsearch_r(e, ENTER, &ep, &htab);
        if (!ret) {
            logmsg("hsearch ENTER failed (%s)", strerror (errno));
        }
    }

    return;
}

char *get_data_from_cache(char *user) {
    int ret;

    ENTRY e, *ep;

    e.key = user;
    ret = hsearch_r(e, FIND, &ep, &htab);

    if (ret && ep) {
        return (char *) ep->data;
    }

    return NULL;
}

void make_curl_request(struct conn_data *conn_data, char *user) {
    char url[256];
    CURL *handle;

    if (external_lookup_cache == cfg_true) {
        char *cached = get_data_from_cache(user);
        if (cached) {
            logmsg("found user %s in curl cache", conn_data->mitm->user);
            conn_data->mitm->data = cached;
            conn_data->mitm->data_len = strlen(cached);

            uv_buf_t uv_buf;
            uv_buf.base = conn_data->mitm->client_auth_packet;
            uv_buf.len = conn_data->mitm->client_auth_packet_len;
    
            handle_auth_packet_from_client (conn_data, &uv_buf, uv_buf.len);
            return;
        }
    }

    conn_data->mitm->curl_timer = malloc (sizeof (uv_timer_t));
    uv_timer_init(uv_default_loop(), conn_data->mitm->curl_timer);
    conn_data->mitm->curl_timer->data = conn_data;

    conn_data->mitm->curl_handle = curl_multi_init();

    curl_multi_setopt(conn_data->mitm->curl_handle, CURLMOPT_SOCKETFUNCTION, handle_socket);
    curl_multi_setopt(conn_data->mitm->curl_handle, CURLMOPT_SOCKETDATA, conn_data);
    curl_multi_setopt(conn_data->mitm->curl_handle, CURLMOPT_TIMERFUNCTION, start_timeout);
    curl_multi_setopt(conn_data->mitm->curl_handle, CURLMOPT_TIMERDATA, conn_data);


    handle = curl_easy_init();
    conn_data->mitm->curl_errorbuf = calloc(1, CURL_ERROR_SIZE);
    curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, conn_data->mitm->curl_errorbuf); 
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, conn_data);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, external_lookup_timeout);
    curl_easy_setopt(handle, CURLOPT_USERPWD, external_lookup_userpwd);
    curl_easy_setopt(handle, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

    snprintf(url, sizeof(url), external_lookup_url, dbtype, user);
    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_USERAGENT, "rum");

    logmsg("making curl external lookup %s", url);
    curl_multi_add_handle(conn_data->mitm->curl_handle, handle);
}
