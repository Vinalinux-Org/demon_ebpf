#ifndef COLLECTOR_H
#define COLLECTOR_H

#include <bpf/libbpf.h>
#include <stdbool.h>

// ---------------- Worker / Collector ----------------
int collector_start(const char *server_url);
void collector_stop(void);

// ---------------- Stats ----------------
unsigned long long collector_sent_ok(void);
unsigned long long collector_dropped(void);

#endif
