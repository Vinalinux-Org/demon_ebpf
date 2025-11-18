// json_builder.c
#include "json_builder.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/**
 * Function: build_event_json
 * Summary:
 *   Converts a file_event structure into a JSON-formatted string. The function
 *   adjusts the event timestamp using the provided offset, formats the resulting
 *   timestamp into an ISO-like human-readable string, identifies the syscall type,
 *   and writes all event fields into the output buffer as a JSON object.
 *
 * Parameters:
 *   - buf: Output buffer where the resulting JSON string will be written.
 *   - n  : Size of the output buffer in bytes.
 *   - e  : Pointer to the file_event structure containing event data.
 *   - offset_ns: A timestamp adjustment value (in nanoseconds) added to the
 *                original event timestamp before formatting.
 *
 * Return:
 *   - None. The function writes the generated JSON string into 'buf'.
 */
void build_event_json(char* buf, size_t n, struct file_event* e, long long offset_ns)
{
	long long real_ts = e->ts_ns + offset_ns;
	struct timespec tspec = {.tv_sec = real_ts / 1000000000ULL,
				 .tv_nsec = real_ts % 1000000000ULL};
	struct tm tm;
	localtime_r(&tspec.tv_sec, &tm);
	char tbuf[32];
	strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm);

	const char* type_str = "UNK";
	switch (e->type) {
	case SYSCALL_OPEN:
		type_str = "OPEN";
		break;
	case SYSCALL_READ:
		type_str = "READ";
		break;
	case SYSCALL_WRITE:
		type_str = "WRITE";
		break;
	}

	snprintf(buf, n,
		 "{\"time\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"tid\":%u,"
		 "\"uid\":%u,\"cgroup_id\":%llu,\"fd\":%d,\"count\":%d,"
		 "\"comm\":\"%s\",\"filename\":\"%s\"}",
		 tbuf, type_str, e->pid, e->tid, e->uid, (unsigned long long)e->cgroup_id, e->fd,
		 e->count, e->comm, e->filename);
}
