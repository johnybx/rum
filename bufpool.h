#define BUFPOOL_CAPACITY 100
#define BUF_SIZE 64000
#define DUMMY_BUF_SIZE 8000

typedef struct bufpool_s bufpool_t;

struct bufpool_s {
    void *first;
    int used;
    int size;
    int alloc_size;
};

#define bufbase(ptr) ((bufbase_t *)((char *)(ptr) - sizeof(bufbase_t)))
#define buflen(ptr) (bufbase(ptr)->len)

typedef struct bufbase_s bufbase_t;

struct bufbase_s {
    bufpool_t *pool;
    void *next;
    int len;
};



/* bufpool.c */
void *bufpool_dummy();
void *bufpool_grow(bufpool_t *pool);
void bufpool_enqueue(bufpool_t *pool, void *ptr);
void *bufpool_dequeue(bufpool_t *pool);
void bufpool_init(bufpool_t *pool, int size);
void bufpool_done(bufpool_t *pool);
void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void *bufpool_acquire(bufpool_t *pool, int *len);
void *bufpool_alloc(bufpool_t *pool, int len);
void bufpool_done(bufpool_t *pool);
void bufpool_release(void *ptr);
void bufpool_print_stats(uv_timer_t* handle);

