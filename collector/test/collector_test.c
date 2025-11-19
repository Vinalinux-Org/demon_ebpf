#include <bpf/libbpf.h>
#include "../../ebpf/include/common.h"
#include "../collector_core/collector_core.h"
#include "../json_builder/json_builder.h"
#include "../queue/queue.h"
#include "../time_utils/time_utils.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char* mock_url = "http://127.0.0.1:8080/events";

/**
 * Function: test_collector_basic
 * Summary:
 *   This function runs a set of basic tests for the collector component. It
 *   simulates the collector's operation by enabling the test mode, resetting
 *   the event queue, starting the collector, enqueuing mock events, running
 *   the collector for a short time, and then stopping the collector. After
 *   stopping, it checks the number of sent and dropped events to ensure that
 *   events were properly processed.
 *
 * Parameters:
 *   - None
 *
 * Return:
 *   - None
 */
void test_collector_basic(void)
{
	printf("Running collector tests...\n");

	collector_enable_test_mode();

	queue_reset_for_test();

	// Start collector
	collector_start(mock_url);

	// Enqueue vài event
	enqueue_event("{\"pid\":1,\"type\":\"OPEN\"}");
	enqueue_event("{\"pid\":2,\"type\":\"READ\"}");

	// Cho thread chạy 100ms
	usleep(100 * 1000);

	// Stop collector
	collector_stop();

	// Kiểm tra stats
	unsigned long long sent = collector_sent_ok();
	unsigned long long dropped = collector_dropped();

	printf("sent_ok=%llu, dropped=%llu\n", sent, dropped);

	assert(sent + dropped >= 2);

	printf("collector tests passed!\n");
}

/**
 * Function: test_queue
 * Summary:
 *   This function performs a set of unit tests on the event queue. It tests
 *   the basic enqueue and dequeue operations in a non-blocking manner. First,
 *   it enqueues two events and dequeues them one by one to check the correct
 *   order. Afterward, it verifies that the queue returns NULL when it is empty
 *   during a non-blocking dequeue operation.
 *
 * Parameters:
 *   - None
 *
 * Return:
 *   - None
 */
void test_queue(void)
{
	printf("Running queue tests...\n");
	queue_reset_for_test();

	// enqueue và dequeue non-blocking
	assert(enqueue_event("event1") == true);
	assert(enqueue_event("event2") == true);

	char* e = dequeue_event_nb();
	assert(e != NULL && strcmp(e, "event1") == 0);
	free(e);

	e = dequeue_event_nb();
	assert(e != NULL && strcmp(e, "event2") == 0);
	free(e);

	// queue rỗng → non-blocking trả về NULL
	assert(dequeue_event_nb() == NULL);

	printf("queue tests passed!\n\n");
}

/**
 * Function: test_json_builder
 * Summary:
 *   This function performs unit tests on the JSON builder functionality.
 *   It tests whether the `build_event_json` function correctly converts
 *   a `file_event` structure into a JSON string. Various fields of the
 *   structure are validated in the generated JSON string to ensure that
 *   the corresponding values are correctly represented.
 *
 * Parameters:
 *   - None
 *
 * Return:
 *   - None
 */
void test_json_builder(void)
{
    printf("Running json_builder tests...\n");
    struct file_event e = {0};
    e.ts_ns = 1234567890;
    e.pid = 1000;
    e.tid = 1001;
    e.uid = 1000;
    e.cgroup_id = 0;
    e.fd = 5;
    e.count = 10;
    strcpy(e.comm, "test");
    strcpy(e.filename, "/tmp/testfile");

    char buf[512];

    // --- Test OPEN ---
    e.type = SYSCALL_OPEN;
    build_event_json(buf, sizeof(buf), &e, 0);
    assert(strstr(buf, "\"pid\":1000") != NULL);
    assert(strstr(buf, "\"fd\":5") != NULL);
    assert(strstr(buf, "\"type\":\"OPEN\"") != NULL);
    assert(strstr(buf, "\"comm\":\"test\"") != NULL);
    assert(strstr(buf, "\"filename\":\"/tmp/testfile\"") != NULL);

    // --- Test READ ---
    e.type = SYSCALL_READ;
    build_event_json(buf, sizeof(buf), &e, 0);
    assert(strstr(buf, "\"type\":\"READ\"") != NULL);

    // --- Test WRITE ---
    e.type = SYSCALL_WRITE;
    build_event_json(buf, sizeof(buf), &e, 0);
    assert(strstr(buf, "\"type\":\"WRITE\"") != NULL);

    // --- Test unknown type ---
    e.type = 999;
    build_event_json(buf, sizeof(buf), &e, 0);
    assert(strstr(buf, "\"type\":\"UNK\"") != NULL);

    // --- Test offset_ns khác 0 ---
    e.type = SYSCALL_OPEN;
    build_event_json(buf, sizeof(buf), &e, 1234567890LL);
    assert(strstr(buf, "\"type\":\"OPEN\"") != NULL);

    printf("json_builder tests passed!\n\n");
}


/**
 * Function: test_time_utils
 * Summary:
 *   This function performs a unit test on the time utility function
 * `monotonic_to_realtime_offset_ns`. It verifies that the time offset between monotonic time and
 * real-time is correctly calculated. The test checks that the returned offset is not zero, which
 * would indicate an error or invalid calculation.
 *
 * Parameters:
 *   - None
 *
 * Return:
 *   - None
 */
void test_time_utils(void)
{
	printf("Running time_utils tests...\n");

	long long offset = monotonic_to_realtime_offset_ns();
	printf("Offset (ns) = %lld\n", offset);

	// Chỉ assert kiểu dữ liệu hợp lệ
	// Có thể là offset hợp lý (không bằng 0 nếu muốn)
	assert(offset != 0);

	printf("time_utils tests passed!\n\n");
}

/**
 * Function: main
 * Summary:
 *   The main function for running all the unit tests for the collector module.
 *   It sequentially invokes individual test functions for the collector, queue, JSON builder,
 *   and time utilities to verify that each component works as expected.
 *   If all tests pass, it prints a success message and returns 0.
 *
 * Parameters:
 *   - None
 *
 * Return:
 *   - 0 : Always returns 0 if all tests pass.
 */
int main(void)
{
	test_collector_basic();
	test_queue();
	test_json_builder();
	test_time_utils();
	printf("All collector tests passed!\n");
	return 0;
}
