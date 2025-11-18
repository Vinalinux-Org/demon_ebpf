#include "collector_core.h"
#include "../json_builder/json_builder.h"
#include "../queue/queue.h"
#include "../time_utils/time_utils.h"
#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BATCH_SIZE 10
#define BATCH_JSON_SIZE 16384

static pthread_t worker_thread_id;
static volatile int worker_exiting = 0;
static CURL* curl = NULL;

// Stats
static unsigned long long sent_ok = 0;
static unsigned long long dropped = 0;

static bool use_nb_dequeue = false; // default false
/**
 * Function: collector_enable_test_mode
 * Summary:
 *   Enables test mode for the collector. In test mode, the worker thread
 *   uses a non-blocking dequeue operation to avoid waiting for events.
 *   This allows unit tests to run deterministically without blocking.
 *
 * Parameters:
 *   - None.
 *
 * Return:
 *   - None.
 */
void collector_enable_test_mode(void) { use_nb_dequeue = true; }

/**
 * Function: discard_callback
 * Summary:
 *   cURL write callback used to handle HTTP response data without storing it.
 *   This function simply discards all received data by returning the total
 *   number of bytes received.
 *
 * Parameters:
 *   - ptr: Pointer to the received data (not used).
 *   - size: Size of each data element (in bytes).
 *   - nmemb: Number of data elements received.
 *   - userdata: User-defined pointer passed to cURL (not used here).
 *
 * Return:
 *   - The total number of bytes handled (size * nmemb).
 */
static size_t discard_callback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
	(void)ptr;
	(void)userdata;
	return size * nmemb;
}

/**
 * Function: format_batch_json
 * Summary:
 *   Converts an array of JSON strings into a single JSON array string.
 *
 * Parameters:
 *   - batch     : Array of event JSON strings.
 *   - batch_cnt : Number of events in the batch.
 *   - out_buf   : Output buffer to store JSON array.
 *   - buf_size  : Size of output buffer.
 */
static void format_batch_json(char** batch, int batch_cnt, char* out_buf, size_t buf_size)
{
	int pos = 0;
	pos += snprintf(out_buf + pos, buf_size - pos, "[");
	for (int i = 0; i < batch_cnt; i++) {
		if (i > 0)
			pos += snprintf(out_buf + pos, buf_size - pos, ",");
		pos += snprintf(out_buf + pos, buf_size - pos, "%s", batch[i]);
	}
	snprintf(out_buf + pos, buf_size - pos, "]");
}

/**
 * Function: send_batch_json
 * Summary:
 *   Sends a JSON batch to the collector server using CURL with retry.
 *
 * Parameters:
 *   - batch_json : JSON string containing the batch.
 *   - batch_cnt  : Number of events in the batch.
 */
static void send_batch_json(const char* batch_json, int batch_cnt)
{
	for (int r = 0; r < 2; r++) {
		if (!curl)
			break;

		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, batch_json);
		if (curl_easy_perform(curl) == CURLE_OK) {
			sent_ok += batch_cnt;
			break;
		}

		usleep(100000); // retry delay
	}
}

/**
 * Function: flush_batch
 * Summary:
 *   Sends a batch of events and frees associated memory.
 *
 * Parameters:
 *   - batch     : Array of event JSON strings.
 *   - batch_cnt : Number of events in the batch.
 */
static void flush_batch(char** batch, int batch_cnt)
{
	char post_buf[BATCH_JSON_SIZE];
	format_batch_json(batch, batch_cnt, post_buf, sizeof(post_buf));
	send_batch_json(post_buf, batch_cnt);

	for (int i = 0; i < batch_cnt; i++)
		free(batch[i]);
}

/**
 * Function: collector_worker_func
 * Summary:
 *   Main worker thread function responsible for retrieving events from the
 *   queue, batching them, converting the batch into a JSON array string, and
 *   sending it to the configured server via HTTP POST. The function continues
 *   running until a stop request is issued. When terminating, it will flush
 *   any remaining events still in the batch.
 *
 * Parameters:
 *   - arg: Unused parameter.
 *
 * Return:
 *   - void*: Always returns NULL when the worker thread exits.
 */
static void* event_sender_thread(void* arg)
{
	(void)arg;
	char* batch[BATCH_SIZE];
	int batch_cnt = 0;

	while (!worker_exiting || batch_cnt > 0) {
		char* json = use_nb_dequeue ? dequeue_event_nb() : dequeue_event();
		if (!use_nb_dequeue && strcmp(json, "__EXIT__") == 0) {
			free(json);
			break;
		}

		if (json)
			batch[batch_cnt++] = json;

		if (batch_cnt == BATCH_SIZE || (worker_exiting && batch_cnt > 0)) {
			flush_batch(batch, batch_cnt);
			batch_cnt = 0;
		}
	}
	return NULL;
}

/**
 * Function: collector_start
 * Summary:
 *   Initializes the HTTP client, configures the server URL, sets timeout
 *   options, and launches the collector worker thread. After this function
 *   returns, the collector begins processing and sending batches of events.
 *
 * Parameters:
 *   - server_url: Null-terminated string specifying the HTTP endpoint used
 *                 to send batched JSON events.
 *
 * Return:
 *   - None.
 */
int collector_start(const char* server_url)
{
	worker_exiting = 0;

	if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
		fprintf(stderr, "curl_global_init failed\n");
		return -1;
	}

	curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "curl_easy_init failed\n");
		curl_global_cleanup();
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, server_url);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 500L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_callback);

	int err = pthread_create(&worker_thread_id, NULL, event_sender_thread, NULL);
	if (err != 0) {
		fprintf(stderr, "pthread_create failed: %d\n", err);
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		return -1;
	}

	return 0;
}

/**
 * Function: collector_stop
 * Summary:
 *   Signals the collector worker thread to exit, waits for it to finish
 *   processing any remaining events, and then releases all HTTP client
 *   resources. To unblock the worker if it is waiting on an empty queue,
 *   this function enqueues a special "poison pill" event ("__EXIT__").
 *
 *   After this function returns, the worker thread has exited and all
 *   resources allocated for HTTP client operations have been cleaned up.
 *
 * Parameters:
 *   - None.
 *
 * Return:
 *   - None.
 */
void collector_stop(void)
{
	worker_exiting = 1;
	enqueue_event(strdup("__EXIT__"));
	pthread_join(worker_thread_id, NULL);
	if (curl)
		curl_easy_cleanup(curl);
	curl_global_cleanup();
}

/**
 * Function: collector_sent_ok
 * Summary:
 *   Returns the total number of events that have been successfully sent to
 *   the server by the collector since startup.
 *
 * Parameters:
 *   - None.
 *
 * Return:
 *   - unsigned long long: Number of successfully delivered events.
 */
unsigned long long collector_sent_ok(void) { return sent_ok; }

/**
 * Function: collector_dropped
 * Summary:
 *   Returns the total number of events that were dropped and never delivered
 *   to the server. Events may be dropped due to queue capacity limits or
 *   repeated transmission failures.
 *
 * Parameters:
 *   - None.
 *
 * Return:
 *   - unsigned long long: Number of dropped events.
 */
unsigned long long collector_dropped(void) { return dropped; }
