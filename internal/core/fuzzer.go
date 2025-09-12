package core

import (
	"container/heap"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"github.com/bl4ck0w1/deepFuzz/internal/ai"
	"github.com/bl4ck0w1/deepFuzz/internal/cluster"
	"github.com/bl4ck0w1/deepFuzz/configs"
	"github.com/bl4ck0w1/deepFuzz/internal/discovery"
	"github.com/bl4ck0w1/deepFuzz/internal/evasion"
	"github.com/bl4ck0w1/deepFuzz/internal/js"
	"github.com/bl4ck0w1/deepFuzz/internal/secrets"
	"github.com/glaslos/tlsh"
)

type Request struct {
	URL          string
	Depth        int
	StaticScore  int
	DynamicScore float64
	Retries      int
	Discovered   time.Time
	Source       string
}

type PriorityQueue []*Request

func (pq PriorityQueue) Len() int { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool {
	if ai.IsActive() {
		return pq[i].DynamicScore > pq[j].DynamicScore
	}
	return (pq[i].DynamicScore*0.7 + float64(pq[i].StaticScore)*0.3) >
		(pq[j].DynamicScore*0.7 + float64(pq[j].StaticScore)*0.3)
}
func (pq PriorityQueue) Swap(i, j int) { pq[i], pq[j] = pq[j], pq[i] }
func (pq *PriorityQueue) Push(x interface{}) {
	*pq = append(*pq, x.(*Request))
}
func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

type Fuzzer struct {
	Queue           *PriorityQueue
	Workers         int
	ResponseStore   *ResponseStore
	EvasionEngine   *evasion.StealthEngine
	RateLimiter     *AdaptiveRateLimiter
	ClusterCoord    *cluster.DarkFleetCoordinator
	AIScorer        ai.ScoringInterface
	JSAnalyzer      *js.Analyzer
	SecretValidator *secrets.Validator
	TimingAnalyzer  *TimingAnalyzer
	WordlistManager *discovery.WordlistManager
	Profile         *configs.Profile

	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	mu           sync.Mutex
	localStorage *ResponseStore
}

func NewFuzzer(workers int, cryptoKey [32]byte, targetURL string) *Fuzzer {
	ctx, cancel := context.WithCancel(context.Background())
	profile, _ := configs.LoadProfile("strategic")
	personaID := configs.GetActivePersona()
	persona, _ := configs.LoadPersona(personaID)
	wafID := configs.GetWAFProfile(targetURL)
	wafProfile, _ := configs.LoadWAFProfile(wafID)

	f := &Fuzzer{
		Queue:           &PriorityQueue{},
		Workers:         workers,
		ResponseStore:   NewResponseStore(),
		EvasionEngine:   evasion.NewEngine(persona, wafProfile),
		RateLimiter:     NewAdaptiveRateLimiter(50),
		JSAnalyzer:      js.NewAnalyzer(),
		SecretValidator: secrets.NewValidator(),
		ctx:             ctx,
		cancel:          cancel,
		localStorage:    NewResponseStore(),
		Profile:         profile,
	}
	f.TimingAnalyzer = NewTimingAnalyzer(f.EvasionEngine, f.AIScorer)
	f.WordlistManager = discovery.NewWordlistManager("ai:50053", cryptoKey)
	heap.Init(f.Queue)
	go f.processTimingAnomalies()
	return f
}

func (f *Fuzzer) EnhanceWithDiscovery(targetURL string, githubTokens []string) {
	crawler := discovery.NewReconCrawler(targetURL, githubTokens)
	manager := f.WordlistManager

	crawler.Crawl(context.Background(),
		discovery.SourceGitHub,
		discovery.SourceCommonCrawl,
		discovery.SourceJS,
	)

	for disc := range crawler.Results() {
		manager.AddDiscoveries([]*discovery.Discovery{disc})
	}

	manager.ExportToFuzzer(f)
}

func (f *Fuzzer) worker() {
	for {
		select {
		case <-f.ctx.Done():
			return
		default:
			f.mu.Lock()
			if f.Queue.Len() == 0 {
				f.mu.Unlock()
				time.Sleep(20 * time.Millisecond)
				continue
			}
			req := heap.Pop(f.Queue).(*Request)
			f.mu.Unlock()

			mutatedURL := f.applyEvasion(req)
			headers := f.EvasionEngine.RotateHeaders()
			start := time.Now()
			resp, err := f.sendRequest(mutatedURL, headers)
			elapsed := time.Since(start)

			if err == nil && resp != nil {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				host := resp.Request.URL.Host
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				hash := generateTLSH(body)
				f.TimingAnalyzer.Record(host, req.URL, resp.StatusCode, elapsed, hash)
				dev, _ := f.TimingAnalyzer.Deviation(host, elapsed)
				decision := f.ResponseStore.Decide(resp, body, dev)
				switch decision.Action {
				case DecisionDrop:
					f.processResponse(req, resp, body)
					f.RateLimiter.Adjust(elapsed)
					continue
				case DecisionDownrank:
					req.DynamicScore *= 0.5
				case DecisionReplay:
					if req.Retries < 2 {
						f.EvasionEngine.RotatePersona()
						replay := &Request{
							URL:          req.URL,
							Depth:        req.Depth,
							StaticScore:  req.StaticScore,
							DynamicScore: req.DynamicScore * 0.8,
							Retries:      req.Retries + 1,
							Source:       "replay",
							Discovered:   time.Now(),
						}
						f.mu.Lock()
						heap.Push(f.Queue, replay)
						f.mu.Unlock()
					}
				case DecisionKeep:
					// proceed normally
				}

				f.updateScoring(req, resp)
				f.processResponse(req, resp, body)

				if isJSResponse(resp) {
					jsPaths := f.JSAnalyzer.ExtractEndpoints(body)
					for _, path := range jsPaths {
						newReq := &Request{
							URL:          path,
							Depth:        req.Depth + 1,
							StaticScore:  60,
							DynamicScore: 60,
							Source:       "js",
							Discovered:   time.Now(),
						}
						f.mu.Lock()
						heap.Push(f.Queue, newReq)
						f.mu.Unlock()
					}

					secrets := f.JSAnalyzer.FindSecrets(body)
					for _, secret := range secrets {
						if f.SecretValidator.Validate(secret) {
							result := FuzzResult{
								Path:       req.URL,
								Confidence: "high",
								Detail:     secret,
								Source:     "js/secret",
							}
							f.StoreResult(result)
						}
					}
				}
			}
			f.RateLimiter.Adjust(elapsed)
		}
	}
}

func (f *Fuzzer) processResponse(req *Request, resp *http.Response, body []byte) {
	f.ResponseStore.AnalyzeResponse(resp, body)
}

func (f *Fuzzer) processTimingAnomalies() {
	for anomaly := range f.TimingAnalyzer.Anomalies() {
		if anomaly.IsCritical {
			f.EvasionEngine.ApplyCountermeasures(anomaly.Host)
			if f.ClusterCoord != nil {
				f.ClusterCoord.ReportAnomaly(anomaly)
			}
			if f.AIScorer != nil {
				f.AIScorer.SubmitTimingFeedback(anomaly)
			}
			result := FuzzResult{
				Path:       anomaly.URL,
				Confidence: "critical",
				Detail:     fmt.Sprintf("Timing anomaly: %.2fσ deviation", anomaly.Deviation),
				Source:     "timing",
			}
			f.StoreResult(result)
		}
	}
}

func (f *Fuzzer) applyEvasion(req *Request) string {
	if f.AIScorer != nil && f.AIScorer.IsActive() {
		return f.AIScorer.GenerateEvasion(req.URL)
	}
	return f.EvasionEngine.MutatePath(req.URL)
}

func (f *Fuzzer) updateScoring(req *Request, resp *http.Response) {
	if f.AIScorer != nil {
		score := f.AIScorer.EvaluateResponse(resp)
		req.DynamicScore = 0.9*req.DynamicScore + 0.1*score
	} else {
		switch {
		case resp.StatusCode == 200:
			req.DynamicScore = 0.9*req.DynamicScore + 0.1*100
		case resp.StatusCode == 403 || resp.StatusCode == 401:
			req.DynamicScore = 0.9*req.DynamicScore + 0.1*30
		default:
			req.DynamicScore = 0.9*req.DynamicScore + 0.1*10
		}
	}
}

func (f *Fuzzer) ConnectCluster(coordinator *cluster.DarkFleetCoordinator) {
	f.ClusterCoord = coordinator
	go f.processClusterTasks()
}

func (f *Fuzzer) processClusterTasks() {
	for task := range f.ClusterCoord.ReceiveTasks() {
		f.mu.Lock()
		heap.Push(f.Queue, &Request{
			URL:          task.URL,
			Depth:        task.Depth,
			StaticScore:  task.Priority,
			DynamicScore: float64(task.Priority),
			Source:       "cluster",
		})
		f.mu.Unlock()
	}
}

func (f *Fuzzer) StoreResult(res FuzzResult) {
	if f.AIScorer == nil || f.AIScorer.ValidateFinding(res) {
		if f.ClusterCoord != nil {
			f.ClusterCoord.StoreFinding(res)
		} else {
			f.localStorage.Store(res)
		}
	}
}

func isJSResponse(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "javascript") || strings.HasSuffix(resp.Request.URL.Path, ".js")
}

func (f *Fuzzer) Start() {
	heap.Init(f.Queue)
	for i := 0; i < f.Workers; i++ {
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.worker()
		}()
	}
}

func (f *Fuzzer) Stop() {
	f.cancel()
	f.wg.Wait()
}

func generateTLSH(data []byte) string {
	h, err := tlsh.Hash(data)
	if err != nil || h == nil {
		return ""
	}
	return h.String()
}
