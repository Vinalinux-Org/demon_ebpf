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
func logInfo(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

func logError(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

// ==========================================================
// Event sender (batch + log)
// ==========================================================
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
func parseEvents(r *http.Request) ([]FileEvent, error) {
	defer r.Body.Close()
	var events []FileEvent
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&events); err != nil {
		return nil, err
	}
	return events, nil
}

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
