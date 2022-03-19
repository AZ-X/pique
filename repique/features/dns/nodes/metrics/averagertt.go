package metrics

import (
	mm "github.com/RobinUS2/golang-moving-average"
)

//approximate; maybe 2 rounds
type RTT interface {
	Add(string, float64)
	Avg(string) float64
	Min(string) float64
	Max(string) float64
}

type movingRTT struct{
	data map[string]*mm.ConcurrentMovingAverage
}

func (m *movingRTT) Add(name string, value float64) {
	m.data[name].Add(value)
}

func (m *movingRTT) Avg(name string) float64 {
	return m.data[name].Avg()
}

func (m *movingRTT) Min(name string) float64 {
	m1, _ := m.data[name].Min()
	return m1
}

func (m *movingRTT) Max(name string) float64 {
	m1, _ := m.data[name].Max()
	return m1
}

func NewRTT(names []string, window int, fake bool) RTT {
	if fake {
		return &fakeRTT{}
	}
	rtt := &movingRTT{data:make(map[string]*mm.ConcurrentMovingAverage, len(names)),}
	for _, name := range names {
		rtt.data[name] = mm.Concurrent(mm.New(window))
	}
	return rtt
}

type fakeRTT struct{}

func (m *fakeRTT) Add(name string, value float64) {
}

func (m *fakeRTT) Avg(name string) float64 {
	return 0
}

func (m *fakeRTT) Min(name string) float64 {
	return 0
}

func (m *fakeRTT) Max(name string) float64 {
	return 0
}