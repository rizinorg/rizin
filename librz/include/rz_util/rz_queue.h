#ifndef RZ_QUEUE_H
#define RZ_QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_queue_t {
	void **elems;
	unsigned int capacity;
	unsigned int front;
	int rear;
	unsigned int size;
} RQueue;

RZ_API RQueue *rz_queue_new(int n);
RZ_API void rz_queue_free(RQueue *q);
RZ_API int rz_queue_enqueue(RQueue *q, void *el);
RZ_API void *rz_queue_dequeue(RQueue *q);
RZ_API int rz_queue_is_empty(RQueue *q);

#ifdef __cplusplus
}
#endif

#endif //  RZ_QUEUE_H
