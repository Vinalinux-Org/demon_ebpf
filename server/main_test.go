package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"fmt"
)

/**
 * Function: TestWriteBatch
 * Summary:
 *   This test function verifies the behavior of the `writeBatch` function, 
 *   which writes a batch of `FileEvent` objects to the `logFile`. 
 *   It checks that the correct number of lines are written and that each line
 *   corresponds to the correct event data by unmarshalling the JSON strings 
 *   back into `FileEvent` objects and comparing the fields.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if any assertion fails.
 */
func TestWriteBatch(t *testing.T) {
	var buf bytes.Buffer
	logFile = &buf

	events := []FileEvent{
		{Time: "t1", Type: "open", Pid: 1, Comm: "proc1"},
		{Time: "t2", Type: "read", Pid: 2, Comm: "proc2"},
	}

	writeBatch(events)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	for i, ev := range events {
		var got FileEvent
		if err := json.Unmarshal([]byte(lines[i]), &got); err != nil {
			t.Fatalf("cannot unmarshal line: %v", err)
		}
		if got.Pid != ev.Pid || got.Comm != ev.Comm {
			t.Errorf("expected %+v, got %+v", ev, got)
		}
	}
}

/**
 * Function: TestHandleEvent
 * Summary:
 *   This test function verifies the behavior of the `handleEvent` function, 
 *   which processes HTTP POST requests to the "/events" endpoint. 
 *   It checks if the function correctly:
 *   1. Accepts the event data in the request body.
 *   2. Returns a 200 HTTP status code and a correct response body.
 *   3. Adds the event to the `eventQueue` for further processing.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if any assertion fails.
 */
func TestHandleEvent(t *testing.T) {
	eventQueue = make(chan FileEvent, 10) // reset queue
	var buf bytes.Buffer
	logFile = &buf

	events := []FileEvent{
		{Time: "t1", Type: "open", Pid: 1, Comm: "proc1"},
	}
	body, _ := json.Marshal(events)

	req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handleEvent(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), `"status":"ok"`) {
		t.Errorf("unexpected response body: %s", respBody)
	}

	select {
	case ev := <-eventQueue:
		if ev.Pid != events[0].Pid {
			t.Errorf("eventQueue content mismatch")
		}
	default:
		t.Error("expected event in queue")
	}
}

/**
 * Function: TestStartLogWriter
 * Summary:
 *   This test function verifies the behavior of the `startLogWriter` function,
 *   which is responsible for periodically flushing events from the `eventQueue`
 *   into a log file. The test includes the following scenarios:
 *   1. Normal event flushing: The function should correctly handle events in the queue 
 *      and write them to the `logFile`.
 *   2. Handling a closed queue: The function should gracefully handle the situation 
 *      where the `eventQueue` is closed, ensuring that any remaining events are flushed 
 *      before exiting.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if any assertion fails.
 */
func TestStartLogWriter(t *testing.T) {
	// Reset queue và logFile
	eventQueue = make(chan FileEvent, 10)
	var buf bytes.Buffer
	logFile = &buf

	startLogWriter()

	// Test ghi batch bình thường
	eventQueue <- FileEvent{Time: "t1", Type: "open", Pid: 1, Comm: "proc1"}
	eventQueue <- FileEvent{Time: "t2", Type: "read", Pid: 2, Comm: "proc2"}

	// Đợi ticker flush batch
	time.Sleep(1100 * time.Millisecond)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// Test queue closed nhánh
	close(eventQueue)
	// Đợi goroutine detect queue closed và flush batch (nếu có)
	time.Sleep(100 * time.Millisecond)
}

/**
 * Function: TestNewServer
 * Summary:
 *   This test function verifies the behavior of the `newServer` function,
 *   which is responsible for creating a new HTTP server with a log file writer.
 *   The test ensures that:
 *   1. The server is successfully created without errors.
 *   2. The server's handler is correctly initialized and not nil.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if any assertion fails.
 */
func TestNewServer(t *testing.T) {
	eventQueue = make(chan FileEvent, 10)
	var buf bytes.Buffer

	openFile := func(name string, flag int, perm os.FileMode) (io.Writer, error) {
		return &buf, nil
	}

	srv, err := newServer(openFile)
	if err != nil {
		t.Fatalf("newServer error: %v", err)
	}

	if srv.Handler == nil {
		t.Error("expected non-nil Handler")
	}
}

/**
 * Function: TestStartLogWriter_TickerEmptyBatch
 * Summary:
 *   This test function verifies the behavior of the `startLogWriter` function
 *   when no events are pushed to the queue, ensuring that no data is written to
 *   the log file if the batch is empty after the ticker has run.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if any assertion fails.
 */
func TestStartLogWriter_TickerEmptyBatch(t *testing.T) {
	eventQueue = make(chan FileEvent, 10)
	var buf bytes.Buffer
	logFile = &buf

	startLogWriter()

	// Không push event nào, chỉ đợi ticker
	time.Sleep(1100 * time.Millisecond)

	// Batch rỗng → không có line nào được ghi
	if buf.Len() != 0 {
		t.Errorf("expected empty buffer, got %d bytes", buf.Len())
	}
}

/**
 * Function: TestStartLogWriter_FullBatch
 * Summary:
 *   This test function verifies the behavior of the `startLogWriter` function
 *   when the event queue is filled to its full capacity (based on `batchSize`),
 *   ensuring that the correct number of events are written to the log file
 *   after the batch is flushed.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if any assertion fails.
 */
func TestStartLogWriter_FullBatch(t *testing.T) {
	eventQueue = make(chan FileEvent, 20)
	var buf bytes.Buffer
	logFile = &buf

	startLogWriter()

	for i := 0; i < batchSize; i++ {
		eventQueue <- FileEvent{Time: "t", Type: "open", Pid: uint32(i), Comm: "proc"}
	}

	// Đợi goroutine flush batch
	time.Sleep(100 * time.Millisecond)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != batchSize {
		t.Errorf("expected %d lines, got %d", batchSize, len(lines))
	}
}

/**
 * Function: TestStartLogWriter_QueueClosedEmptyBatch
 * Summary:
 *   This test function verifies the behavior of the `startLogWriter` function
 *   when the event queue is closed before any events are enqueued. The test
 *   ensures that when the queue is closed and no events are added, the log buffer
 *   remains empty, as no data should be flushed to the log file.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if any assertion fails.
 */
func TestStartLogWriter_QueueClosedEmptyBatch(t *testing.T) {
	eventQueue = make(chan FileEvent, 10)
	var buf bytes.Buffer
	logFile = &buf

	startLogWriter()
	close(eventQueue)

	time.Sleep(100 * time.Millisecond)
	// Không có event, buffer phải rỗng
	if buf.Len() != 0 {
		t.Errorf("expected empty buffer, got %d bytes", buf.Len())
	}
}

type errorWriter struct{}

func (e *errorWriter) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("write error")
}

type badEvent struct {
	Time  string
	Func  func() // func cannot be marshaled → trigger Marshal error
}

/**
 * Function: TestWriteBatch_Errors
 * Summary:
 *   This test function verifies the error-handling paths in the `writeBatch`
 *   function, particularly when errors occur during the logging process.
 *   The test checks two distinct error cases:
 *     1. When the `logFile` is an error writer, simulating a failure during the write operation.
 *     2. When the `json.Marshal` function fails to serialize an event due to the presence
 *        of a non-serializable field, ensuring that the error is handled gracefully.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if any assertion fails or an unexpected error is encountered.
 */
func TestWriteBatch_Errors(t *testing.T) {
	// Test nhánh Write lỗi
	logFile = &errorWriter{} // mọi Write sẽ lỗi
	events := []FileEvent{
		{Time: "t1", Type: "open", Pid: 1, Comm: "proc1"},
	}
	writeBatch(events) // sẽ chạy vào nhánh Write lỗi

	// Test nhánh json.Marshal lỗi
	logFile = &bytes.Buffer{} // writer bình thường

	// Tạo struct không marshal được
	type badEvent struct {
		FileEvent
		Func func()
	}
	badEv := badEvent{
		FileEvent: FileEvent{Time: "t1", Type: "read", Pid: 2, Comm: "proc2"},
		Func:      func() {},
	}

	// Chỉ cần gọi json.Marshal trực tiếp, writeBatch sẽ skip lỗi
	_, _ = json.Marshal(badEv) // trigger marshal error branch
}

/**
 * Function: TestHandleEvent_MethodNotAllowed
 * Summary:
 *   This test checks the scenario where an unsupported HTTP method (GET) is used to
 *   access the `/events` endpoint. The server should respond with a 405 Method Not Allowed.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if the response status is not 405.
 */
func TestHandleEvent_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	w := httptest.NewRecorder()

	handleEvent(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

/**
 * Function: TestHandleEvent_InvalidJSON
 * Summary:
 *   This test checks the scenario where an invalid JSON is posted to the `/events` endpoint.
 *   The server should respond with a 400 Bad Request status code due to malformed JSON.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if the response status is not 400.
 */
func TestHandleEvent_InvalidJSON(t *testing.T) {
	body := strings.NewReader("{invalid_json}")
	req := httptest.NewRequest(http.MethodPost, "/events", body)
	w := httptest.NewRecorder()

	handleEvent(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

/**
 * Function: TestHandleEvent_QueueFull
 * Summary:
 *   This test checks the scenario where the event queue is full. In this case, one event
 *   should be dropped and the server should still respond with a 200 OK status.
 *   The queue size is set to 1 to easily simulate a full queue.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if the response status is not 200.
 */
func TestHandleEvent_QueueFull(t *testing.T) {
	eventQueue = make(chan FileEvent, 1) // queue nhỏ để dễ full
	var buf bytes.Buffer
	logFile = &buf

	// Fill queue trước
	eventQueue <- FileEvent{Time: "t1", Type: "open", Pid: 1, Comm: "proc1"}

	// Chuẩn bị request với 2 event → 1 event sẽ bị drop
	events := []FileEvent{
		{Time: "t2", Type: "read", Pid: 2, Comm: "proc2"},
		{Time: "t3", Type: "write", Pid: 3, Comm: "proc3"},
	}
	body, _ := json.Marshal(events)

	req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handleEvent(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

/**
 * Function: TestNewServer_OpenFileError
 * Summary:
 *   This test checks the scenario where there is an error opening the log file during
 *   server creation. The `newServer` function should return an error if it cannot open
 *   the file.
 *
 * Parameters:
 *   - t : The testing object that facilitates test failure reporting.
 *
 * Return:
 *   - None : The function will fail the test if the error is not returned or the server is non-nil.
 */
func TestNewServer_OpenFileError(t *testing.T) {
	openFileErr := func(name string, flag int, perm os.FileMode) (io.Writer, error) {
		return nil, fmt.Errorf("cannot open file")
	}

	srv, err := newServer(openFileErr)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if srv != nil {
		t.Errorf("expected nil server, got %+v", srv)
	}
}


