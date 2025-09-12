package core

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/bl4ck0w1/deepFuzz/internal/ai"
	"github.com/bl4ck0w1/deepFuzz/internal/evasion"
)

type TimingAnalyzer struct {
	mu          sync.RWMutex
	hostData    map[string]*hostTimingStats
	anomalyChan chan TimingAnomaly
	evasion     *evasion.StealthEngine
	aiScorer    ai.ScoringInterface
}

type hostTimingStats struct {
	count        uint64
	meanUS       float64
	m2US         float64 
	stdUS        float64
	lastUpdated  time.Time
	responseMap  map[int]time.Duration
	threshold    time.Duration
	anomalyCount uint16
}

type TimingAnomaly struct {
	URL        string
	Host       string
	Duration   time.Duration
	Baseline   time.Duration
	Deviation  float64
	StatusCode int
	Signature  string
	IsCritical bool
}

func NewTimingAnalyzer(evasion *evasion.StealthEngine, ai ai.ScoringInterface) *TimingAnalyzer {
	return &TimingAnalyzer{
		hostData:    make(map[string]*hostTimingStats),
		anomalyChan: make(chan TimingAnomaly, 1000),
		evasion:     evasion,
		aiScorer:    ai,
	}
}

func (t *TimingAnalyzer) Record(host, url string, status int, duration time.Duration, responseHash string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stats, exists := t.hostData[host]
	if !exists {
		stats = &hostTimingStats{
			count:       0,
			responseMap: make(map[int]time.Duration),
			threshold:   50 * time.Millisecond,
		}
		t.hostData[host] = stats
	}

	if avg, ok := stats.responseMap[status]; ok {
		stats.responseMap[status] = time.Duration(0.7*float64(avg) + 0.3*float64(duration))
	} else {
		stats.responseMap[status] = duration
	}

	x := float64(duration.Microseconds())
	stats.count++
	if stats.count == 1 {
		stats.meanUS = x
		stats.m2US = 0
	} else {
		delta := x - stats.meanUS
		stats.meanUS += delta / float64(stats.count)
		delta2 := x - stats.meanUS
		stats.m2US += delta * delta2
	}

	if stats.count > 1 {
		stats.stdUS = math.Sqrt(stats.m2US / float64(stats.count-1))
	}
	stats.threshold = t.calculateThreshold(stats)

	if stats.count >= 8 && stats.stdUS > 0 {
		dev := (x - stats.meanUS) / stats.stdUS
		if math.Abs(dev) > 3.0 { 
			critical := t.evaluateAnomalyCriticality(url, status, duration, responseHash)
			t.anomalyChan <- TimingAnomaly{
				URL:        url,
				Host:       host,
				Duration:   duration,
				Baseline:   time.Duration(stats.meanUS) * time.Microsecond,
				Deviation:  dev,
				StatusCode: status,
				Signature:  responseHash,
				IsCritical: critical,
			}
			stats.anomalyCount++

			if stats.anomalyCount > 3 {
				t.evasion.RotatePersona()
				stats.anomalyCount = 0
			}
		}
	}
}

func (t *TimingAnalyzer) calculateThreshold(stats *hostTimingStats) time.Duration {
	if stats.count < 2 || stats.stdUS <= 0 {
		return stats.threshold
	}
	baseThreshold := time.Duration(3*stats.stdUS) * time.Microsecond

	if t.aiScorer != nil && t.aiScorer.IsActive() {
		riskFactor := t.aiScorer.GetTimingRisk(time.Duration(stats.meanUS) * time.Microsecond)
		return time.Duration(float64(baseThreshold) * riskFactor)
	}

	switch {
	case stats.count < 10:
		return 100 * time.Millisecond
	case time.Duration(stats.meanUS)*time.Microsecond > 500*time.Millisecond:
		return 150 * time.Millisecond
	default:
		return baseThreshold
	}
}

func (t *TimingAnalyzer) evaluateAnomalyCriticality(url string, status int, duration time.Duration, hash string) bool {
	if t.aiScorer != nil {
		return t.aiScorer.IsCriticalTimingAnomaly(url, status, duration, hash)
	}

	return status == 200 || status == 403 || duration > 2*time.Second
}

func (t *TimingAnalyzer) Anomalies() <-chan TimingAnomaly {
	return t.anomalyChan
}

func (t *TimingAnalyzer) Deviation(host string, duration time.Duration) (dev float64, ok bool) {
	t.mu.RLock()
	stats, exists := t.hostData[host]
	t.mu.RUnlock()
	if !exists || stats == nil || stats.count < 8 || stats.stdUS <= 0 {
		return 0, false
	}
	x := float64(duration.Microseconds())
	return (x - stats.meanUS) / stats.stdUS, true
}

func (t *TimingAnalyzer) DetectSideChannels(url string, responses []*http.Response) bool {
	if t.aiScorer != nil {
		return t.aiScorer.DetectSideChannels(responses)
	}

	var timings []time.Duration
	for _, resp := range responses {
		if resp == nil {
			continue
		}
		if d, ok := parseServerTiming(resp); ok {
			timings = append(timings, d)
			continue
		}
		if s := resp.Header.Get("X-Processing-Time"); s != "" {
			if d, err := time.ParseDuration(s); err == nil {
				timings = append(timings, d)
			}
		}
	}

	cv := t.coeffOfVariation(timings)
	return cv > 0.8
}

func (t *TimingAnalyzer) coeffOfVariation(timings []time.Duration) float64 {
	if len(timings) < 5 {
		return 0
	}

	var sum float64
	us := make([]float64, 0, len(timings))
	for _, d := range timings {
		v := float64(d.Microseconds())
		us = append(us, v)
		sum += v
	}
	mean := sum / float64(len(us))
	if mean <= 0 {
		return 0
	}

	var s2 float64
	for _, v := range us {
		d := v - mean
		s2 += d * d
	}
	s2 /= float64(len(us))
	std := math.Sqrt(s2)
	return std / mean
}

func parseServerTiming(resp *http.Response) (time.Duration, bool) {
	if resp == nil {
		return 0, false
	}
	values := resp.Header.Values("Server-Timing")
	for _, v := range values {
		parts := strings.Split(v, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if idx := strings.Index(p, "dur="); idx != -1 {
				num := p[idx+4:]
				if sc := strings.IndexByte(num, ';'); sc != -1 {
					num = num[:sc]
				}
				num = strings.TrimSpace(num)
				if num == "" {
					continue
				}
				if f, err := strconv.ParseFloat(num, 64); err == nil {
					d := time.Duration(f * float64(time.Millisecond))
					return d, true
				}
			}
		}
	}
	return 0, false
}
