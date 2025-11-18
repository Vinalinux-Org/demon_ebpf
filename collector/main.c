#include "collector_core/collector_core.h"
#include "json_builder/json_builder.h"
#include "queue/queue.h"
#include "time_utils/time_utils.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t exiting = 0;

/**
 * Function: handle_signal
 * Summary:
 *   Handles incoming POSIX signals by setting the global exit flag. This
 *   notifies the main event loop that the program should shut down.
 *
 * Parameters:
 *   - signo: Signal number received (unused).
 *
 * Return:
 *   - None.
 */
void handle_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

/**
 * Function: on_ring_event
 * Summary:
 *   Callback invoked when a new event is received from the eBPF ring buffer.
 *   The function validates the event size, filters out events originating
 *   from the "collector" or "server" processes, converts the event timestamp
 *   to realtime using a computed offset, builds the corresponding JSON string,
 *   and enqueues it for later processing by the collector worker.
 *
 * Parameters:
 *   - ctx      : Unused context pointer.
 *   - data     : Pointer to raw event data coming from the ring buffer.
 *   - data_sz  : Size of the event data in bytes.
 *   - cb_cookie: Unused callback cookie.
 *
 * Return:
 *   - 0 : Always returns 0 to indicate the ring buffer polling may continue.
 */
static int on_ring_event(void* ctx, void* data, size_t data_sz)
{
	(void)ctx;

	if (data_sz < sizeof(struct file_event)) {
		fprintf(stderr, "Received event with invalid size: %zu\n", data_sz);
		return 0;
	}

	struct file_event* e = data;
	if (strcmp(e->comm, "collector") == 0 || strcmp(e->comm, "server") == 0)
		return 0;

	static long long offset_ns = 0;
	offset_ns = offset_ns == 0 ? monotonic_to_realtime_offset_ns() : offset_ns;

	char json_buf[1024];
	build_event_json(json_buf, sizeof(json_buf), e, offset_ns);
	enqueue_event(json_buf);
	return 0;
}

/**
 * Function: load_bpf_object
 * Summary:
 *   Opens and loads an eBPF object file (.bpf.o) into the kernel,
 *   and attaches all programs contained in the object.
 *
 * Parameters:
 *   - path: path to the eBPF object file
 *
 * Return:
 *   - pointer to bpf_object on success
 *   - NULL on failure
 */
static struct bpf_object* load_bpf_object(const char* path)
{
	struct bpf_object* obj = bpf_object__open_file(path, NULL);
	if (!obj) {
		fprintf(stderr, "Failed to open BPF object file: %s\n", path);
		return NULL;
	}

	if (bpf_object__load(obj) != 0) {
		fprintf(stderr, "Failed to load BPF object\n");
		bpf_object__close(obj);
		return NULL;
	}

	// Attach all programs
	struct bpf_program* prog;
	bpf_object__for_each_program(prog, obj)
	{
		struct bpf_link* link = bpf_program__attach(prog);
		(void)link;
	}

	return obj;
}

/**
 * Function: create_ring_buffer
 * Summary:
 *   Creates a ring buffer to receive events from the kernel eBPF map.
 *   Registers the `on_ring_event` callback for new events.
 *
 * Parameters:
 *   - obj: loaded bpf_object containing the event map
 *
 * Return:
 *   - pointer to ring_buffer on success
 *   - NULL on failure
 */
static struct ring_buffer* create_ring_buffer(struct bpf_object* obj)
{
	int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
	if (map_fd < 0) {
		fprintf(stderr, "Cannot find map 'events'\n");
		return NULL;
	}

	struct ring_buffer* rb = ring_buffer__new(map_fd, on_ring_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		return NULL;
	}
	return rb;
}

/**
 * Function: main
 * Summary:
 *   Entry point of the collector application. It loads the eBPF program,
 *   attaches all BPF programs, initializes the ring buffer for receiving
 *   kernel events, starts the user-space collector worker, and enters the
 *   event polling loop. The function exits when a termination signal is
 *   received, performs cleanup of all allocated resources, and prints final
 *   delivery statistics.
 *
 * Parameters:
 *   - argc: Number of command-line arguments.
 *   - argv: Argument vector. Supports optional usage:
 *           --bpf <path>  Override the default eBPF object file path.
 *
 * Return:
 *   - int: Exit status code (0 for normal shutdown).
 */
int main()
{
	const char* bpf_path = "../ebpf/dist/ebpf.bpf.o";

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(NULL);

	struct bpf_object* obj = NULL;
	obj = load_bpf_object(bpf_path);
	if (!obj) {
		goto cleanup;
	}

	struct ring_buffer* rb = NULL;
	rb = create_ring_buffer(obj);
	if (!rb) {
		goto cleanup;
	}

	if (collector_start("http://127.0.0.1:8080/events") != 0) {
		goto cleanup;
	}

	printf("Collector started.\n");

	while (!exiting) {
		int err = ring_buffer__poll(rb, 10);
		if (err == -EINTR)
			break;
	}

cleanup:
	exiting = 1;
	if (rb) {
		ring_buffer__free(rb);
	}
	if (obj) {
		bpf_object__close(obj);
	}
	collector_stop();

	printf("Collector stopped. Sent=%llu, Dropped=%llu\n", collector_sent_ok(),
	       collector_dropped());
	return 0;
}
