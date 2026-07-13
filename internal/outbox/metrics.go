package outbox

import "sync/atomic"

// Metrics contains concurrency-safe, process-local delivery counters.
type Metrics struct {
	claimed      atomic.Uint64
	published    atomic.Uint64
	retried      atomic.Uint64
	deadLettered atomic.Uint64
	failures     atomic.Uint64
}

// MetricsSnapshot is a consistent-enough operational view of monotonic
// counters. Individual counters may advance while the snapshot is read.
type MetricsSnapshot struct {
	Claimed      uint64
	Published    uint64
	Retried      uint64
	DeadLettered uint64
	Failures     uint64
}

func (m *Metrics) recordClaimed(count int) {
	if m != nil && count > 0 {
		m.claimed.Add(uint64(count))
	}
}

func (m *Metrics) recordPublished() {
	if m != nil {
		m.published.Add(1)
	}
}

func (m *Metrics) recordRetried() {
	if m != nil {
		m.retried.Add(1)
	}
}

func (m *Metrics) recordDeadLettered() {
	if m != nil {
		m.deadLettered.Add(1)
	}
}

func (m *Metrics) recordFailure() {
	if m != nil {
		m.failures.Add(1)
	}
}

// Snapshot returns the current delivery counters.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}

	return MetricsSnapshot{
		Claimed:      m.claimed.Load(),
		Published:    m.published.Load(),
		Retried:      m.retried.Load(),
		DeadLettered: m.deadLettered.Load(),
		Failures:     m.failures.Load(),
	}
}
