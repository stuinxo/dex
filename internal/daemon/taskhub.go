package daemon

import (
	"sync"
	"time"
)

// LogEntry represents one structured operational log line streamed to SSE clients and CLI.
type LogEntry struct {
	Time      string `json:"time"`
	Level     string `json:"level"`
	Subsystem string `json:"subsystem"`
	Message   string `json:"message"`
}

// TaskHub maintains a bounded ring buffer of logs and fans out live events to SSE subscribers.
type TaskHub struct {
	mu      sync.RWMutex
	cap     int
	entries []LogEntry
	subs    map[uint64]chan LogEntry
	nextID  uint64
}

// NewTaskHub creates a TaskHub retaining the last capacity log entries.
func NewTaskHub(capacity int) *TaskHub {
	if capacity <= 0 {
		capacity = 300
	}
	return &TaskHub{
		cap:     capacity,
		entries: make([]LogEntry, 0, capacity),
		subs:    make(map[uint64]chan LogEntry),
	}
}

// Log records an entry and broadcasts it without blocking.
func (h *TaskHub) Log(level, subsystem, message string) {
	entry := LogEntry{
		Time:      time.Now().Format("2006-01-02 15:04:05"),
		Level:     level,
		Subsystem: subsystem,
		Message:   message,
	}
	h.mu.Lock()
	if len(h.entries) >= h.cap {
		copy(h.entries, h.entries[1:])
		h.entries[len(h.entries)-1] = entry
	} else {
		h.entries = append(h.entries, entry)
	}
	for _, ch := range h.subs {
		select {
		case ch <- entry:
		default:
		}
	}
	h.mu.Unlock()
}

// Snapshot returns a copy of buffered log entries.
func (h *TaskHub) Snapshot() []LogEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]LogEntry, len(h.entries))
	copy(out, h.entries)
	return out
}

// Subscribe registers a subscriber channel and returns a cancel function.
func (h *TaskHub) Subscribe() (<-chan LogEntry, func()) {
	ch := make(chan LogEntry, 64)
	h.mu.Lock()
	h.nextID++
	id := h.nextID
	h.subs[id] = ch
	h.mu.Unlock()

	return ch, func() {
		h.mu.Lock()
		if c, ok := h.subs[id]; ok {
			delete(h.subs, id)
			close(c)
		}
		h.mu.Unlock()
	}
}
