// queue.h
#ifndef QUEUE_H
#define QUEUE_H
#include <stdbool.h>

char* dequeue_event_nb(void);  // non-blocking, dùng cho unit test
bool enqueue_event(const char *json);
char* dequeue_event(void);
void queue_reset_for_test(void); // dùng cho unit test

#endif
