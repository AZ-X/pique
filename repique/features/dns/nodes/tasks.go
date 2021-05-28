package nodes

import (
	"sort"
	"time"
)

type smith struct {
	scheduler    *time.Timer
	events       []*struct{base *time.Time; off uint32; task func()}
}

func (t *smith) addevent(base *time.Time, off uint32, task func()) {
	if base == nil {
		now := time.Now()
		base = &now
	}
	event := &struct{base *time.Time; off uint32; task func()}{base:base, off:off, task:task,}
	t.events = append(t.events, event)
	if t.scheduler != nil && len(t.events) > 1 {
		if t.duration(len(t.events) - 1) < t.duration(len(t.events) - 2) {
			if !t.scheduler.Reset(1 * time.Second) {
				t.scheduler.Stop()
			}
			t.scheduler = nil
			return
		}
	}
	sort.Slice(t.events, func(i, j int) bool {
		return t.duration(i) > t.duration(j)
	})
}

func (t *smith) duration(idx int) time.Duration {
	event := t.events[idx]
	return time.Duration(event.off) * time.Second + event.base.Sub(time.Now())
}

func (t *smith) pilot() {
	var f func()
	f = func() {
		const cascade = 5 * time.Minute // serial within partition goroutine
		if len(t.events) > 0 {
			tail := len(t.events) - 1
			d := t.duration(tail)
			if t.scheduler != nil {
				task := t.events[tail].task
				t.events = t.events[:tail]
				task()
				for {
					tail = len(t.events) - 1
					if tail < 0 {
						return
					}
					if d = t.duration(tail); d <= cascade {
						time.Sleep(d)
						task = t.events[tail].task
						t.events = t.events[:tail]
						task()
					} else {
						break
					}
				}
			}
			t.scheduler = time.AfterFunc(d, f)
		}
	}
	f()
}