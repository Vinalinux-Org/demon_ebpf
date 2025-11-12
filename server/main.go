package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// ==========================================================
// Structs
// ==========================================================
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

// ==========================================================
// Globals
// ==========================================================
var (
	logFile    *os.File
	eventQueue = make(chan FileEvent, 10000)
)

const (
	eventQueueSize     = 10000
	batchSize          = 10
	batchFlushInterval = time.Second
)

// ==========================================================
// Logging helpers
// ==========================================================

/**
 * Function: logInfo
 * Summary:
 *   Logs an informational message to standard output with a consistent
 *   "[INFO]" prefix. Accepts format strings similar to fmt.Printf.
 *
 * Parameters:
 *   - format: format string for the message
 *   - v: optional variadic arguments for formatting
 *
 * Return:
 *   - None
 */
func logInfo(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

/**
 * Function: logError
 * Summary:
 *   Logs an error message to standard output with a consistent
 *   "[ERROR]" prefix. Accepts format strings similar to fmt.Printf.
 *
 * Parameters:
 *   - format: format string for the message
 *   - v: optional variadic arguments for formatting
 *
 * Return:
 *   - None
 */
func logError(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

// ==========================================================
// Event sender (batch + log)
// ==========================================================

/**
 * Function: flushBatch
 * Summary:
 *   Serializes a slice of FileEvent objects into JSON and writes them
 *   to the log file, one event per line. Logs any errors encountered
 *   during marshaling or writing.
 *
 * Parameters:
 *   - batch: slice of FileEvent objects to write
 *
 * Return:
 *   - None
 */
func flushBatch(batch []FileEvent) {
	for _, ev := range batch {
		b, err := json.Marshal(ev)
		if err != nil {
			logError("Cannot marshal event: %v", err)
			continue
		}
		if _, err := logFile.Write(b); err != nil {
			logError("Error writing log: %v", err)
		}
		if _, err := logFile.WriteString("\n"); err != nil {
			logError("Error writing newline: %v", err)
		}
	}
}

/**
 * Function: eventSenderLoop
 * Summary:
 *   Launches a background goroutine that continuously consumes events
 *   from the eventQueue, accumulates them into batches, and flushes
 *   them to the log file either when the batch reaches a predefined
 *   size or after a fixed time interval.
 *
 * Parameters:
 *   - None
 *
 * Return:
 *   - None (runs asynchronously in a goroutine)
 */
func eventSenderLoop() {
	go func() {
		batch := make([]FileEvent, 0, batchSize)
		ticker := time.NewTicker(batchFlushInterval)
		defer ticker.Stop()

		for {
			select {
			case ev, ok := <-eventQueue:
				if !ok {
					if len(batch) > 0 {
						flushBatch(batch)
					}
					return
				}
				batch = append(batch, ev)
				if len(batch) >= batchSize {
					flushBatch(batch)
					batch = batch[:0]
				}
			case <-ticker.C:
				if len(batch) > 0 {
					flushBatch(batch)
					batch = batch[:0]
				}
			}
		}
	}()
}

// ==========================================================
// HTTP handler helpers
// ==========================================================

/**
 * Function: parseEvents
 * Summary:
 *   Reads and decodes a JSON array of FileEvent objects from an HTTP request body.
 *   Ensures the body is closed after reading.
 *
 * Parameters:
 *   - r: pointer to the HTTP request containing the JSON payload
 *
 * Return:
 *   - []FileEvent: slice of decoded events
 *   - error: decoding error, if any
 */
func parseEvents(r *http.Request) ([]FileEvent, error) {
	defer r.Body.Close()
	var events []FileEvent
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&events); err != nil {
		return nil, err
	}
	return events, nil
}

/**
 * Function: enqueueEvents
 * Summary:
 *   Pushes a slice of FileEvent objects into the internal eventQueue for
 *   asynchronous processing. If the queue is full, events are dropped
 *   with an error log.
 *
 * Parameters:
 *   - events: slice of FileEvent objects to enqueue
 *
 * Return:
 *   - None
 */
func enqueueEvents(events []FileEvent) {
	for _, ev := range events {
		select {
		case eventQueue <- ev:
		default:
			logError("Event queue full, dropping event")
		}
	}
}

// ==========================================================
// HTTP handler
// ==========================================================

/**
 * Function: handleEvent
 * Summary:
 *   HTTP handler for receiving POST requests containing a JSON array of
 *   FileEvent objects. Validates the request method, decodes the JSON payload,
 *   enqueues the events for processing, and responds with a status message
 *   including the server timestamp.
 *
 * Parameters:
 *   - w: HTTP response writer used to send back the response
 *   - r: HTTP request containing the JSON array of events
 *
 * Return:
 *   - None (writes HTTP response directly)
 */
func handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	events, err := parseEvents(r)
	if err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	enqueueEvents(events)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","received_at":"%s"}`, time.Now().Format(time.RFC3339))
}

// ==========================================================
// Server helpers
// ==========================================================

/**
 * Function: startHTTPServer
 * Summary:
 *   Initializes and starts the HTTP server in a background goroutine. Registers
 *   the "/events" endpoint to handle incoming event batches. Configures read
 *   and write timeouts and logs server startup information.
 *
 * Parameters:
 *   - addr: string representing the address and port to listen on (e.g., ":8080")
 *
 * Return:
 *   - Pointer to the http.Server instance, allowing for future shutdown or configuration
 */
func startHTTPServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/events", handleEvent)

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		logInfo("Server listening on %s — writing to events.log", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logError("Server error: %v", err)
		}
	}()

	return server
}

// ==========================================================
// Main
// ==========================================================

/**
 * Function: main
 * Summary:
 *   Entry point of the server application. Opens or creates the log file for
 *   writing events, starts the background event sender loop that flushes
 *   events from the internal queue to the log file, and starts the HTTP server
 *   to receive event batches from collectors. Blocks indefinitely to keep
 *   the server running.
 *
 * Parameters:
 *   - None
 *
 * Return:
 *   - None (program runs indefinitely until terminated)
 */
func main() {
	var err error
	logFile, err = os.OpenFile("events.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logError("Cannot open log file: %v", err)
		return
	}
	defer logFile.Close()

	eventSenderLoop()
	startHTTPServer(":8080")

	select {}
}
