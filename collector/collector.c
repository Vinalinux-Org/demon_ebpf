#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <curl/curl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../ebpf/include/common.h"

// ==========================================================
// Configuration
// ==========================================================
#define QUEUE_SIZE 2048
#define BATCH_SIZE 10
#define BATCH_JSON_SIZE 16384    // number of bytes for batch JSON
#define RETRY_DELAY_US 100000    // retry delay in microseconds (100ms)
#define FILE_EVENT_JSON_SIZE 1024
#define TIME_STR_SIZE 32

// ==========================================================
// Logging macros
// ==========================================================
#define LOG_INFO(fmt, ...)  printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   fprintf(stderr, "[ERR] " fmt "\n", ##__VA_ARGS__)

// ==========================================================
// Global state
// ==========================================================
static volatile sig_atomic_t exiting = 0;
static long long offset_ns = 0;
static const char *server_url = "http://127.0.0.1:8080/events";

// Queue
static char *event_queue[QUEUE_SIZE];
static int queue_head = 0;
static int queue_tail = 0;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// CURL
static CURL *curl_handle = NULL;
static struct curl_slist *curl_headers = NULL;

// Stats
static uint64_t sent_ok = 0;
static uint64_t dropped = 0;

// ==========================================================
// Helper functions
// ==========================================================

// CURL write callback that discards data
static size_t discard_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

// Compute offset between CLOCK_MONOTONIC and CLOCK_REALTIME in nanoseconds
static long long compute_monotonic_to_realtime_offset_ns(void) {
    struct timespec mono, real;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_REALTIME, &real);
    long long mono_ns = (long long)mono.tv_sec * 1000000000LL + mono.tv_nsec;
    long long real_ns = (long long)real.tv_sec * 1000000000LL + real.tv_nsec;
    return real_ns - mono_ns;
}

// Signal handler
static void handle_signal(int signo) {
    (void)signo;
    exiting = 1;
    pthread_cond_signal(&queue_cond);
}

// ==========================================================
// Queue functions
// ==========================================================

// Enqueue an event JSON string
static bool enqueue_event(const char *json) {
    pthread_mutex_lock(&queue_lock);
    int next_tail = (queue_tail + 1) % QUEUE_SIZE;

    if (next_tail == queue_head) {
        // Queue full
        __sync_fetch_and_add(&dropped, 1);
        pthread_mutex_unlock(&queue_lock);
        return false;
    }

    event_queue[queue_tail] = strdup(json);
    queue_tail = next_tail;

    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_lock);
    return true;
}

// Dequeue an event JSON string
static char *dequeue_event(void) {
    pthread_mutex_lock(&queue_lock);
    while (queue_head == queue_tail && !exiting) {
        pthread_cond_wait(&queue_cond, &queue_lock);
    }

    if (exiting && queue_head == queue_tail) {
        pthread_mutex_unlock(&queue_lock);
        return NULL;
    }

    char *item = event_queue[queue_head];
    queue_head = (queue_head + 1) % QUEUE_SIZE;
    pthread_mutex_unlock(&queue_lock);
    return item;
}

// ==========================================================
// Batch sending functions
// ==========================================================

// Format batch JSON array
static void format_batch_json(char **batch, int batch_count, char *out_buf, size_t buf_size) {
    int pos = 0;
    pos += snprintf(out_buf + pos, buf_size - pos, "[");
    for (int i = 0; i < batch_count; i++) {
        if (i > 0) pos += snprintf(out_buf + pos, buf_size - pos, ",");
        pos += snprintf(out_buf + pos, buf_size - pos, "%s", batch[i]);
    }
    snprintf(out_buf + pos, buf_size - pos, "]");
}

// Send batch via HTTP POST
static void send_batch(char *batch_json, int batch_count) {
    for (int retry = 0; retry < 2; retry++) {
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, batch_json);
        CURLcode res = curl_easy_perform(curl_handle);
        if (res == CURLE_OK) {
            __sync_fetch_and_add(&sent_ok, batch_count);
            break;
        } else if (retry == 1) {
            LOG_ERR("Send batch failed: %s", curl_easy_strerror(res));
        }
        usleep(RETRY_DELAY_US);
    }
}

// Flush batch: send and free memory
static void flush_batch(char **batch, int batch_count) {
    char post_buf[BATCH_JSON_SIZE];
    format_batch_json(batch, batch_count, post_buf, sizeof(post_buf));
    send_batch(post_buf, batch_count);

    for (int i = 0; i < batch_count; i++) {
        free(batch[i]);
    }
}

// Event sender thread sends batches of events
static void *event_sender_thread(void *arg) {
    (void)arg;
    char *event_batch[BATCH_SIZE];
    int batch_count = 0;

    // Continue until exiting and all queued events are processed
    while (!exiting || (batch_count > 0)) {
        char *json = dequeue_event();
        if (json) {
            event_batch[batch_count++] = json;
        }

        // Send current batch and free memory
        if (batch_count == BATCH_SIZE || (exiting && batch_count > 0)) {
            flush_batch(event_batch, batch_count);
            batch_count = 0;
        }
    }

    return NULL;
}

// ==========================================================
// Helpers for processing file events (used in on_ring_event)
// ==========================================================

// Build JSON string for file event
static void build_file_event_json(const struct file_event *e,
                                  const char *type_str,
                                  const char *time_str,
                                  char *out_buf,
                                  size_t buf_size) 
{
    snprintf(out_buf, buf_size,
             "{\"time\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"tid\":%u,"
             "\"uid\":%u,\"cgroup_id\":%llu,\"fd\":%d,\"count\":%d,"
             "\"comm\":\"%s\",\"filename\":\"%s\"}",
             time_str, type_str, e->pid, e->tid, e->uid,
             (unsigned long long)e->cgroup_id, e->fd, e->count,
             e->comm, e->filename);
}

// Format event time from timestamp and offset
static void format_event_time(long long ts_ns, long long offset_ns,
                              char *out_buf, size_t buf_size) 
{
    long long real_ts = ts_ns + offset_ns;

    struct timespec tspec = {
        .tv_sec = real_ts / 1000000000ULL,
        .tv_nsec = real_ts % 1000000000ULL,
    };

    struct tm tm_time;
    localtime_r(&tspec.tv_sec, &tm_time);

    strftime(out_buf, buf_size, "%Y-%m-%dT%H:%M:%S", &tm_time);
}

// Get syscall type string
static const char *get_syscall_type_str(int type) {
    switch (type) {
        case SYSCALL_OPEN:
            return "OPEN";
        case SYSCALL_READ:
            return "READ";
        case SYSCALL_WRITE:
            return "WRITE";
        default:
            return "UNK";
    }
}

// Check if process should be skipped
static bool should_skip_process(const char *comm) {
    if (!comm) {
        return true;
    }

    return (strcmp(comm, "collector") == 0 || strcmp(comm, "server") == 0);
}

// ==========================================================
// eBPF ring event handler
// ==========================================================
static int on_ring_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct file_event)) {
        LOG_ERR("Invalid data size: %zu", data_sz);
        return 0;
    } 

    struct file_event *e = data;

    if (should_skip_process(e->comm)) {
        return 0;
    }

    char tbuf[TIME_STR_SIZE];
    format_event_time(e->ts_ns, offset_ns, tbuf, sizeof(tbuf));

    const char *type_str = get_syscall_type_str(e->type);

    char json_buf[FILE_EVENT_JSON_SIZE];
    build_file_event_json(e, type_str, tbuf, json_buf, sizeof(json_buf));
    enqueue_event(json_buf);
    return 0;
}

// ==========================================================
// Helpers for initialization and cleanup
// ==========================================================

// Initialize CURL
static bool init_curl(void) {
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    if (!curl_handle) {
        LOG_ERR("Failed to init CURL handle");
        return false;
    }
    curl_headers = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl_handle, CURLOPT_URL, server_url);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, curl_headers);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, 500L);
    curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, discard_callback);
    return true;
}

// Load BPF object from file
static struct bpf_object *load_bpf_object(const char *path) {
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    if (!obj) {
        LOG_ERR("Failed to open BPF object");
        return NULL;
    }

    if (bpf_object__load(obj) != 0) {
        LOG_ERR("Failed to load BPF object");
        bpf_object__close(obj);
        return NULL;
    }

    // Attach all programs
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        (void)link;
    }

    return obj;
}

// Create ring buffer
static struct ring_buffer *create_ring_buffer(struct bpf_object *obj) {
    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        LOG_ERR("Cannot find map 'events'");
        return NULL;
    }

    struct ring_buffer *rb = ring_buffer__new(map_fd, on_ring_event, NULL, NULL);
    if (!rb) {
        LOG_ERR("Failed to create ring buffer");
        return NULL;
    }
    return rb;
}

// Stop event sender thread
static void stop_event_sender_thread(pthread_t thread) {
    exiting = 1;                       
    pthread_cond_signal(&queue_cond);   
    pthread_join(thread, NULL);        
}

// Cleanup resources
static void cleanup_resources(struct ring_buffer *rb, struct bpf_object *obj) {
    if (rb) {
        ring_buffer__free(rb);
    }

    if (obj) {
        bpf_object__close(obj);
    }

    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }

    if (curl_handle) {
        curl_easy_cleanup(curl_handle);
    }

    curl_global_cleanup();
}

// ==========================================================
// Main function
// ==========================================================
int main(int argc, char **argv) {
    const char *bpf_path = "../ebpf/dist/ebpf.bpf.o";
    if (argc >= 3 && strcmp(argv[1], "--bpf") == 0) {
        bpf_path = argv[2];
    }

    offset_ns = compute_monotonic_to_realtime_offset_ns();

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(NULL);

    // Initialize CURL
    if (!init_curl()) {
        return 1;
    }

    // Setup signals
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Load BPF object
    struct bpf_object *obj = load_bpf_object(bpf_path);
    if (!obj) {
        goto cleanup;
    }

    // Create ring buffer
    struct ring_buffer *rb = create_ring_buffer(obj);
    if (!rb) {
        goto cleanup;
    }

    // Start worker thread
    pthread_t sender_thread;
    pthread_create(&sender_thread, NULL, event_sender_thread, NULL);

    LOG_INFO("Collector running. Sending to %s", server_url);

    int err;
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR || exiting) break;
    }

cleanup:
    stop_event_sender_thread(sender_thread);
    cleanup_resources(rb, obj);

    return 0;
}
