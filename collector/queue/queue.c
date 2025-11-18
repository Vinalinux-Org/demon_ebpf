// queue.c
#include "queue.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define QUEUE_SIZE 2048

static char* event_queue[QUEUE_SIZE];
static int q_head = 0, q_tail = 0;
static pthread_mutex_t q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t q_cond = PTHREAD_COND_INITIALIZER;

/**
 * Function: dequeue_event_nb
 * Summary:
 *   Attempts to remove and return the next JSON event from the queue without
 *   waiting. If the queue is empty, the function immediately returns NULL.
 *
 * Parameters:
 *   - None.
 *
 * Return:
 *   - char*: Pointer to the dequeued JSON string. The caller is responsible
 *            for freeing this memory.
 *   - NULL : The queue is empty.
 */
char* dequeue_event_nb(void)
{
	pthread_mutex_lock(&q_lock);
	if (q_head == q_tail) {
		pthread_mutex_unlock(&q_lock);
		return NULL;
	}
	char* item = event_queue[q_head];
	q_head = (q_head + 1) % QUEUE_SIZE;
	pthread_mutex_unlock(&q_lock);
	return item;
}

/**
 * Function: enqueue_event
 * Summary:
 *   Attempts to insert a JSON string into the fixed-size ring buffer queue.
 *   If the queue has available space, the function duplicates the input JSON
 *   and stores it at the current tail position. If the queue is full, the
 *   function performs no insertion.
 *
 * Parameters:
 *   - json: Pointer to a null-terminated JSON string. The function stores a
 *           duplicated copy of this string inside the queue.
 *
 * Return:
 *   - true  : The JSON event was successfully added to the queue.
 *   - false : The queue is full; the event was not added.
 */
bool enqueue_event(const char* json)
{
	pthread_mutex_lock(&q_lock);
	int next = (q_tail + 1) % QUEUE_SIZE;
	if (next == q_head) {
		pthread_mutex_unlock(&q_lock);
		return false; // full
	}
	event_queue[q_tail] = strdup(json);
	q_tail = next;
	pthread_cond_signal(&q_cond);
	pthread_mutex_unlock(&q_lock);
	return true;
}

/**
 * Function: dequeue_event
 * Summary:
 *   Removes and returns the next available JSON event from the queue. If the
 *   queue is empty, the function waits until a new event is inserted before
 *   returning.
 *
 * Parameters:
 *   - None.
 *
 * Return:
 *   - char*: Pointer to the dequeued JSON string. The caller must free this
 *            pointer after use.
 */
char* dequeue_event(void)
{
	pthread_mutex_lock(&q_lock);
	while (q_head == q_tail) {
		pthread_cond_wait(&q_cond, &q_lock);
	}
	char* item = event_queue[q_head];
	q_head = (q_head + 1) % QUEUE_SIZE;
	pthread_mutex_unlock(&q_lock);
	return item;
}

/**
 * Function: queue_reset_for_test
 * Summary:
 *   Utility function intended only for test environments. It frees all stored
 *   JSON strings in the queue and resets the queue indices to the empty state.
 *
 * Parameters:
 *   - None.
 *
 * Return:
 *   - None.
 */
void queue_reset_for_test(void)
{
	pthread_mutex_lock(&q_lock);
	for (int i = q_head; i != q_tail; i = (i + 1) % QUEUE_SIZE)
		free(event_queue[i]);
	q_head = q_tail = 0;
	pthread_mutex_unlock(&q_lock);
}
