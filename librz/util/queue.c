// SPDX-FileCopyrightText: 2007-2015 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API RQueue *rz_queue_new(int n) {
	if (n <= 0) {
		return NULL;
	}
	RQueue *q = RZ_NEW0(RQueue);
	if (!q) {
		return NULL;
	}
	q->elems = RZ_NEWS0(void *, n);
	if (!q->elems) {
		free(q);
		return NULL;
	}
	q->front = 0;
	q->rear = -1;
	q->size = 0;
	q->capacity = n;
	return q;
}

RZ_API void rz_queue_free(RQueue *q) {
	free(q->elems);
	free(q);
}

static int is_full(RQueue *q) {
	return q->size == q->capacity;
}

static int increase_capacity(RQueue *q) {
	unsigned int new_capacity = q->capacity * 2;
	void **newelems;
	int i, tmp_front;

	newelems = RZ_NEWS0(void *, new_capacity);
	if (!newelems) {
		return false;
	}

	i = -1;
	tmp_front = q->front;
	while (i + 1 < q->size) {
		i++;
		newelems[i] = q->elems[tmp_front];
		tmp_front = (tmp_front + 1) % q->capacity;
	}

	free(q->elems);
	q->elems = newelems;
	q->front = 0;
	q->rear = i;
	q->capacity = new_capacity;
	return true;
}

RZ_API int rz_queue_enqueue(RQueue *q, void *el) {
	if (is_full(q)) {
		int res = increase_capacity(q);
		if (!res) {
			return false;
		}
	}

	q->rear = (q->rear + 1) % q->capacity;
	q->elems[q->rear] = el;
	q->size++;
	return true;
}

RZ_API void *rz_queue_dequeue(RQueue *q) {
	void *res;

	if (rz_queue_is_empty(q)) {
		return NULL;
	}
	res = q->elems[q->front];
	q->front = (q->front + 1) % q->capacity;
	q->size--;
	return res;
}

RZ_API int rz_queue_is_empty(RQueue *q) {
	return q->size == 0;
}
