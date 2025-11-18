// json_builder.h
#ifndef JSON_BUILDER_H
#define JSON_BUILDER_H

#include "bpf/libbpf.h"
#include "../../ebpf/include/common.h"

void build_event_json(char* buf, size_t n, struct file_event* e, long long offset_ns);

#endif
