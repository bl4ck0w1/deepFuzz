package core

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"github.com/bl4ck0w1/deepFuzz/internal/ai" 
	"github.com/spaolacci/murmur3"
)

type ResponseStore struct {
	mu                 sync.RWMutex
	tlshMap            map[string]string  
	knownSoft404Hosts  map[uint64]struct{}  
	knownSoft404Bodies map[uint64]struct{}  
	dynamicThreshold   float64
	aiValidator        ai.SimilarityValidator 
	minHasher          *localMinHasher      
	soft404Sigs        [][]uint64     
}

func NewResponseStore() *ResponseStore {
	return &ResponseStore{
		tlshMap:            make(map[string]string),
		knownSoft404Hosts:  make(map[uint64]struct{}),
		knownSoft404Bodies: make(map[uint64]struct{}),
		dynamicThreshold:   0.92,
		minHasher:          newLocalMinHasher(128, 5), 
	}
}

type DecisionAction int

const (
	DecisionKeep DecisionAction = iota
	DecisionDownrank
	DecisionReplay
	DecisionDrop
)

type Decision struct {
	Action DecisionAction
	Reason string
	Scores map[string]float64
}

func (rs *ResponseStore) IsSoft404(data []byte, url string) bool {
	murmurKey := murmurHash64(data)
	rs.mu.RLock()
	_, bodySeen := rs.knownSoft404Bodies[murmurKey]
	rs.mu.RUnlock()
	if bodySeen {
		return true
	}

	if rs.aiValidator != nil {
		return rs.aiValidator.IsSoft404(data, url)
	}

	if rs.minHasher == nil {
		return false
	}
	sig := rs.minHasher.Signature(data)
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	maxSim := 0.0
	for _, ref := range rs.soft404Sigs {
		if sim := rs.minHasher.Similarity(sig, ref); sim > maxSim {
			maxSim = sim
		}
	}
	return maxSim >= rs.dynamicThreshold
}

func (rs *ResponseStore) IsKnownSoft404Host(host string) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	_, ok := rs.knownSoft404Hosts[murmurHash64([]byte(host))]
	return ok
}

func (rs *ResponseStore) AnalyzeResponse(resp *http.Response, body []byte) {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return
	}
	contentType := resp.Header.Get("Content-Type")
	url := resp.Request.URL.String()

	if rs.isKnownResponse(body, contentType) {
		return
	}
	rs.AddResponse(body, contentType)

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		rs.Learn404Pattern(resp.Request.URL.Host, body)
		return
	}

	if rs.IsSoft404(body, url) {
		rs.Learn404Pattern(resp.Request.URL.Host, body)
	}
}

func (rs *ResponseStore) Decide(resp *http.Response, body []byte, timingDev float64) Decision {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return Decision{Action: DecisionDrop, Reason: "invalid_response"}
	}
	host := resp.Request.URL.Host
	url := resp.Request.URL.String()
	status := resp.StatusCode
	ct := resp.Header.Get("Content-Type")

	if rs.isKnownResponse(body, ct) {
		return Decision{Action: DecisionDrop, Reason: "duplicate_hash"}
	}

	soft := rs.IsSoft404(body, url)
	knownSoftHost := rs.IsKnownSoft404Host(host)
	hfp := headerFingerprint(resp)
	cfp := cookieFingerprint(resp)

	if (status == 401 || status == 403 || status == 404) && (soft || knownSoftHost) {
		if timingDev > 2.5 {
			return Decision{
				Action: DecisionReplay,
				Reason: "waf_mirror_timing_outlier",
				Scores: map[string]float64{"timing_dev": timingDev},
			}
		}
		return Decision{
			Action: DecisionDownrank,
			Reason: "waf_mirror_downrank",
			Scores: map[string]float64{"timing_dev": timingDev},
		}
	}

	if status >= 200 && status < 300 && BinaryDetect(body) {
		return Decision{Action: DecisionKeep, Reason: "binary_asset"}
	}

	if status == 200 || status == 201 || status == 204 || status == 401 {
		return Decision{
			Action: DecisionKeep,
			Reason: "useful_status",
			Scores: map[string]float64{"hfp": float64(hfp), "cfp": float64(cfp)},
		}
	}

	if status >= 300 && status < 400 {
		return Decision{Action: DecisionDownrank, Reason: "redirect"}
	}

	if status >= 400 && status < 600 {
		if timingDev > 3.0 {
			return Decision{
				Action: DecisionReplay,
				Reason: "error_with_timing_outlier",
				Scores: map[string]float64{"timing_dev": timingDev},
			}
		}
		return Decision{Action: DecisionDownrank, Reason: "error_downrank"}
	}
	return Decision{Action: DecisionKeep, Reason: "default_keep"}
}

func (rs *ResponseStore) Learn404Pattern(host string, body []byte) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	hostKey := murmurHash64([]byte(host))
	rs.knownSoft404Hosts[hostKey] = struct{}{}
	bodyKey := murmurHash64(body)
	rs.knownSoft404Bodies[bodyKey] = struct{}{}
	if rs.minHasher != nil {
		rs.soft404Sigs = append(rs.soft404Sigs, rs.minHasher.Signature(body))
	}

	if rs.dynamicThreshold > 0.85 {
		rs.dynamicThreshold = math.Max(0.85, rs.dynamicThreshold-0.005)
	}
}

func BinaryDetect(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	if bytes.Contains(data, []byte{0}) {
		return true
	}

	entropy := 0.0
	size := len(data)
	freq := make([]int, 256)

	for _, b := range data {
		freq[b]++
	}

	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(size)
		entropy -= p * math.Log2(p)
	}
	return entropy > 7.0 || (entropy < 2.0 && size > 256)
}

func murmurHash64(data []byte) uint64 {
	return murmur3.Sum64WithSeed(data, 0xdeadbeef)
}

func (rs *ResponseStore) isKnownResponse(body []byte, contentType string) bool {
	h := contentHash(body)
	rs.mu.RLock()
	_, ok := rs.tlshMap[h]
	rs.mu.RUnlock()
	return ok
}

func (rs *ResponseStore) AddResponse(body []byte, contentType string) {
	h := contentHash(body)
	rs.mu.Lock()
	rs.tlshMap[h] = contentType
	rs.mu.Unlock()
}

func contentHash(body []byte) string {
	if len(body) == 0 {
		return "murmur:0"
	}
	if tl := generateTLSH(body); tl != "" {
		return tl
	}
	return fmt.Sprintf("murmur:%x", murmurHash64(body))
}

func (rs *ResponseStore) SetAIValidator(v ai.SimilarityValidator) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.aiValidator = v
}

type localMinHasher struct {
	k       int
	shingle int
	seeds   []uint32
}

func newLocalMinHasher(k int, shingle int) *localMinHasher {
	if k <= 0 {
		k = 128
	}
	if shingle <= 0 {
		shingle = 5
	}
	seeds := make([]uint32, k)
	seed := uint32(0x9e3779b9)
	for i := 0; i < m.k; i++ {
	}
	for i := 0; i < k; i++ {
		seed = seed*1664525 + 1013904223 // LCG
		seeds[i] = seed
	}
	return &localMinHasher{k: k, shingle: shingle, seeds: seeds}
}

func (m *localMinHasher) Signature(data []byte) []uint64 {
	sig := make([]uint64, m.k)
	for i := 0; i < m.k; i++ {
		sig[i] = ^uint64(0)
	}
	n := len(data)
	if n == 0 {
		return sig
	}
	if n < m.shingle {
		for i := 0; i < m.k; i++ {
			v := murmur3.Sum64WithSeed(data, m.seeds[i])
			if v < sig[i] {
				sig[i] = v
			}
		}
		return sig
	}
	for i := 0; i <= n-m.shingle; i++ {
		window := data[i : i+m.shingle]
		for j := 0; j < m.k; j++ {
			v := murmur3.Sum64WithSeed(window, m.seeds[j])
			if v < sig[j] {
				sig[j] = v
			}
		}
	}
	return sig
}

func (m *localMinHasher) Similarity(a, b []uint64) float64 {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return 0.0
	}
	match := 0
	for i := range a {
		if a[i] == b[i] {
			match++
		}
	}
	return float64(match) / float64(len(a))
}

func headerFingerprint(resp *http.Response) uint64 {
	if resp == nil {
		return 0
	}
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "date" || lk == "server" || lk == "etag" || lk == "expires" || lk == "last-modified" || lk == "cf-ray" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		vals := append([]string(nil), resp.Header.Values(k)...)
		sort.Strings(vals)
		b.WriteString(k)
		b.WriteString(":")
		for _, v := range vals {
			b.WriteString(v)
			b.WriteString("|")
		}
		b.WriteString("\n")
	}
	return murmurHash64([]byte(b.String()))
}

func cookieFingerprint(resp *http.Response) uint64 {
	if resp == nil {
		return 0
	}
	cookies := append([]string(nil), resp.Header.Values("Set-Cookie")...)
	if len(cookies) == 0 {
		return 0
	}
	sort.Strings(cookies)
	return murmurHash64([]byte(strings.Join(cookies, "\n")))
}
