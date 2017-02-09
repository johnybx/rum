#include "rum.h"

extern bufpool_t *pool;

void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    int len = size; /* Requested buffer size */
    void *ptr = bufpool_acquire(pool, &len);
    *buf = uv_buf_init(ptr, len);

//     buf->base = malloc(size);
//     buf->len = size;

}

void bufpool_print_stats(uv_timer_t* handle)
{
    int i=0;
//    void *ptr=pool->first;

    uv_timer_stop(handle);
    uv_timer_start(handle, bufpool_print_stats, 10000, 10000);
/*
    while(ptr) {
        ptr=bufbase(ptr)->next;
        i++;
    }
*/
    fprintf(stderr, "pool->used: %d\npool->size: %d realsize: %d\n", pool->used, pool->size, i);
    
}

void bufpool_enqueue(bufpool_t *pool, void *ptr) {
    if (pool->first) {
        bufbase(ptr)->next=pool->first;
    } else {
        bufbase(ptr)->next=NULL;
    }
    pool->first=ptr;
    pool->used--;
    pool->size++;
    //fprintf(stderr,"bufpool_enqueue used--\n");
}

void *bufpool_dequeue(bufpool_t *pool) {
    void *ptr;
    if (pool->first) {
        ptr=pool->first;
        pool->first = bufbase(ptr)->next;
        //fprintf(stderr,"bufpool_dequeue used++\n");
        pool->used++;
        pool->size--;
        bufbase(ptr)->next = NULL;
        return ptr;
    } else {
        return bufpool_alloc(pool, pool->alloc_size);
    }
}

void bufpool_init(bufpool_t *pool, int size) {
    pool->alloc_size = size;
    pool->size = 0;
    pool->used = 0;
    pool->first = NULL;
}

void *bufpool_acquire(bufpool_t *pool, int *len) {
/*
    void *buf;
    int size = *len;
    if (size > DUMMY_BUF_SIZE) {
        buf = bufpool_dequeue(pool);
        if (buf) {
            if (size > BUF_SIZE) *len = BUF_SIZE;
            return buf;
        }
        size = DUMMY_BUF_SIZE;
    }
    buf = bufpool_alloc(0, size);
    *len = buf ? size : 0;
    return buf;
*/
    int size = *len;
    void *buf = bufpool_dequeue(pool);
    if (!buf) buf = bufpool_alloc(0, size);
    *len = buf ? buflen(buf) : 0;
    return buf;
}

void *bufpool_alloc(bufpool_t *pool, int len) {
    bufbase_t *base = malloc(sizeof(bufbase_t) + len);
    if (!base) return 0;
    base->pool = pool;
    base->len = len;
    base->next = NULL;
    //fprintf(stderr,"bufpool_alloc used++ %d %p\n", len, pool);
    if (pool) {
        pool->used++;
        //fprintf(stderr,"bufpool_alloc used++ XXX %d %p\n", len, pool);
    }
    return (char *)base + sizeof(bufbase_t);
}

void bufpool_release(void *ptr) {
    if (!ptr) return;
    if (bufbase(ptr)->pool) {
        bufpool_enqueue(bufbase(ptr)->pool, ptr);
    } else {
        free(bufbase(ptr));
    }
}

void bufpool_free(bufbase_t *buf) {
    free(buf);
}


void bufpool_done(bufpool_t *pool)
{
    void *ptr=pool->first;
    void *next;
//    bufbase_t *base;

    if (pool->used) {
        fprintf(stderr, "warning: %d buffers are still used\n", pool->used);
    }

    while (ptr) {
        next = bufbase(ptr)->next;
        free(bufbase(ptr));
        ptr = next;
    }
}
