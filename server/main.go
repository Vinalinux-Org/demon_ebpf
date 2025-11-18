package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// ------------------- Struct -------------------
type FileEvent struct {
	Time     string `json:"time"`
	Type     string `json:"type"`
	Pid      uint32 `json:"pid"`
	Tid      uint32 `json:"tid"`
	Uid      uint32 `json:"uid"`
	CgroupID uint64 `json:"cgroup_id"`
	Fd       int    `json:"fd"`
	Count    int    `json:"count"`
	Comm     string `json:"comm"`
	Filename string `json:"filename"`
}

// ------------------- Global -------------------
// var logFile *os.File
var logFile io.Writer
var eventQueue = make(chan FileEvent, 10000) // channel queue
const batchSize = 10

/**
 * Function: startLogWriter
 * Summary:
 *   Launches a background goroutine that continuously consumes events from
 *   the eventQueue, batches them, and periodically writes them to a log file.
 *   The function ensures batched writes either when the batch reaches a
 *   predefined size or after a fixed time interval.
 *
 * Parameters:
 *   - None.
 *
 * Return:
 *   - None (runs asynchronously in a goroutine).
 */
func startLogWriter() {
	go func() {
		batch := make([]FileEvent, 0, batchSize)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case ev, ok := <-eventQueue:
				if !ok {
					// queue closed, flush remaining
					if len(batch) > 0 {
						writeBatch(batch)
					}
					return
				}
				batch = append(batch, ev)
				if len(batch) >= batchSize {
					writeBatch(batch)
					batch = batch[:0]
				}
			case <-ticker.C:
				if len(batch) > 0 {
					writeBatch(batch)
					batch = batch[:0]
				}
			}
		}
	}()
}

/**
 * Function: writeBatch
 * Summary:
 *   Serializes and writes a batch of FileEvent objects to the log file in JSON format.
 *   Each event is written as a single line, followed by a newline character.
 *   Logs any errors encountered during marshaling or writing.
 *
 * Parameters:
 *   - batch: slice of FileEvent objects to write.
 *
 * Return:
 *   - None.
 */
func writeBatch(batch []FileEvent) {
	for _, ev := range batch {
		b, err := json.Marshal(ev)
		if err != nil {
			log.Printf("Cannot marshal event: %v", err)
			continue
		}
		if _, err := logFile.Write(b); err != nil {
			log.Printf("Error writing log: %v", err)
		}
		if _, err := logFile.Write([]byte("\n")); err != nil {
			log.Printf("Error writing newline: %v", err)
		}
	}
}

/**
 * Function: handleEvent
 * Summary:
 *   Handles incoming HTTP POST requests containing a JSON array of FileEvent objects.
 *   Validates the request method, decodes JSON, and enqueues each event into the eventQueue.
 *   If the queue is full, the event is dropped with a warning log.
 *   Responds with a JSON status message and timestamp upon success.
 *
 * Parameters:
 *   - w: HTTP response writer for sending responses.
 *   - r: HTTP request containing JSON payload of FileEvent objects.
 *
 * Return:
 *   - None (writes HTTP response directly).
 */
func handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var events []FileEvent
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&events); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Push events into queue (non-blocking)
	for _, ev := range events {
		select {
		case eventQueue <- ev:
		default:
			log.Println("Event queue full, dropping event")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","received_at":"%s"}`, time.Now().Format(time.RFC3339))
}

/**
 * Function: newServer
 * Summary:
 *   Creates and configures a new HTTP server instance for receiving events.
 *   The function opens the log file using the provided openFile callback,
 *   initializes the background log writer, registers the /events HTTP handler,
 *   and returns a fully constructed http.Server ready to be started.
 *
 * Parameters:
 *   - openFile: A function used to open or create the log file. This allows
 *               unit tests to inject a mock implementation and verify behavior.
 *
 * Return:
 *   - *http.Server: A pointer to the newly created server instance.
 *   - error       : Non-nil if the log file cannot be opened.
 */
func newServer(openFile func(name string, flag int, perm os.FileMode) (io.Writer, error)) (*http.Server, error) {
	f, err := openFile("events.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("cannot open log file: %v", err)
	}
	logFile = f

	startLogWriter()

	mux := http.NewServeMux()
	mux.HandleFunc("/events", handleEvent)

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	return srv, nil
}

/**
 * Function: main
 * Summary:
 *   Entry point of the server application. It creates a new HTTP server
 *   instance by opening the log file "events.log", starts the server,
 *   and listens for incoming HTTP requests on port 8080. If server startup
 *   fails or an error occurs during runtime, the function logs the error
 *   and exits.
 *
 * Parameters:
 *   - None.
 *
 * Return:
 *   - None. Exits the program on error or after server termination.
 */
func main() {
	srv, err := newServer(func(name string, flag int, perm os.FileMode) (io.Writer, error) {
		return os.OpenFile(name, flag, perm) // *os.File implements io.Writer
	})

	if err != nil {
		log.Fatalf("server startup failed: %v", err)
	}

	log.Println("Server listening on :8080 — writing to events.log")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
