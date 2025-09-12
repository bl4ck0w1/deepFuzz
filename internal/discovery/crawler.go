package discovery
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ReconCrawler struct {
	httpClient     *http.Client
	target         *url.URL
	aiPredictor    *PathPredictor
	manager        *WordlistManager
	githubTokens   []string
	commonCrawlIdx []string
	results        chan *Discovery
	mu             sync.Mutex
}

type CrawlSource int

const (
	SourceGitHub CrawlSource = iota
	SourceCommonCrawl
	SourceJS
	SourceHistory
)

func NewReconCrawler(targetURL string, tokens []string) *ReconCrawler {
	u, _ := url.Parse(targetURL)
	return &ReconCrawler{
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        128,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     30 * time.Second,
			},
		},
		target:         u,
		githubTokens:   tokens,
		aiPredictor:    NewPathPredictor(),
		manager:        NewWordlistManager(),
		results:        make(chan *Discovery, 1000),
		commonCrawlIdx: []string{
			"CC-MAIN-2023-50",
			"CC-MAIN-2023-40",
			"CC-MAIN-2023-22",
		},
	}
}

func (rc *ReconCrawler) Crawl(ctx context.Context, sources ...CrawlSource) {
	rc.manager.LoadStrategicWordlists()
	var wg sync.WaitGroup
	for _, source := range sources {
		wg.Add(1)
		switch source {
		case SourceGitHub:
			go func() { defer wg.Done(); rc.crawlGitHub(ctx) }()
		case SourceCommonCrawl:
			go func() { defer wg.Done(); rc.crawlCommonCrawl(ctx) }()
		case SourceJS:
			go func() { defer wg.Done(); rc.crawlJavaScriptSources(ctx) }()
		case SourceHistory:
			go func() { defer wg.Done(); rc.crawlHistoricalVersions(ctx) }()
		}
	}

	go func() {
		wg.Wait()
		rc.manager.SaveWordlists()
		close(rc.results)
	}()
}

func (rc *ReconCrawler) Results() <-chan *Discovery {
	return rc.results
}

func (rc *ReconCrawler) crawlGitHub(ctx context.Context) {
	searchTypes := []string{"code", "repos", "commits"}
	var wg sync.WaitGroup

	for _, searchType := range searchTypes {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			rc.githubSearch(ctx, t, rc.target.Hostname())
		}(searchType)
	}

	wg.Wait()
}

func (rc *ReconCrawler) githubSearch(ctx context.Context, searchType, query string) {
	reqURL := fmt.Sprintf("https://api.github.com/search/%s?q=%s", searchType, url.QueryEscape(query))
	req, _ := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if tok := rc.rotateGitHubToken(); tok != "" {
		req.Header.Set("Authorization", "token "+tok)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "deepfuzz-recon")
	resp, err := rc.httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Items []struct {
			Path string `json:"path"`
			URL  string `json:"html_url"`
		} `json:"items"`
	}

	_ = json.NewDecoder(resp.Body).Decode(&result)

	for _, item := range result.Items {
		content := rc.fetchGitHubContent(ctx, item.URL)
		rc.extractAndScorePaths(content, SourceGitHub)
	}
}

func (rc *ReconCrawler) crawlCommonCrawl(ctx context.Context) {
	var wg sync.WaitGroup
	warcChan := make(chan string, len(rc.commonCrawlIdx))

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for warc := range warcChan {
				rc.processWARCFile(ctx, warc)
			}
		}()
	}

	for _, idx := range rc.commonCrawlIdx {
		warcURL := fmt.Sprintf("https://data.commoncrawl.org/%s.warc.gz", idx)
		warcChan <- warcURL
	}
	close(warcChan)
	wg.Wait()
}

func (rc *ReconCrawler) processWARCFile(ctx context.Context, warcURL string) {
	req, _ := http.NewRequestWithContext(ctx, "GET", warcURL, nil)
	req.Header.Set("Range", "bytes=0-10000000") // First 10MB only

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = io.CopyN(buf, resp.Body, 10_000_000)
	content := buf.String()
	rc.extractAndScorePaths(string(content), SourceCommonCrawl)
}

func (rc *ReconCrawler) crawlJavaScriptSources(ctx context.Context) {
	req, _ := http.NewRequestWithContext(ctx, "GET", rc.target.String(), nil)
	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	jsPaths := extractJSPaths(body)

	var wg sync.WaitGroup
	for _, path := range jsPaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			content := rc.fetchContent(ctx, p)
			rc.extractAndScorePaths(content, SourceJS)
		}(path)
	}
	wg.Wait()
}

func (rc *ReconCrawler) crawlHistoricalVersions(ctx context.Context) {
	timeMachine := []struct {
		URL  string
		Year int
	}{
		{"http://web.archive.org/web/2020", 2020},
		{"http://web.archive.org/web/2021", 2021},
		{"http://web.archive.org/web/2022", 2022},
	}

	for _, snapshot := range timeMachine {
		content := rc.fetchContent(ctx, snapshot.URL+rc.target.Path)
		rc.extractAndScorePaths(content, SourceHistory)
	}
}

func (rc *ReconCrawler) extractAndScorePaths(content string, source CrawlSource) {
	paths := extractPaths(content)
	for _, path := range paths {
		score := rc.calculatePathScore(path, source)
		rc.results <- &Discovery{
			Path:   path,
			Score:  score,
			Source: source.String(),
		}
	}
}

func (rc *ReconCrawler) calculatePathScore(path string, source CrawlSource) int {
	score := 100
	switch source {
	case SourceGitHub:
		score += 200
	case SourceJS:
		score += 300
	case SourceHistory:
		score += 150
	}

	if strings.Contains(path, "api") {
		score += 100
	}
	if strings.Contains(path, "admin") {
		score += 200
	}
	if strings.Contains(path, "v1") || strings.Contains(path, "v2") {
		score += 50
	}

	if rc.aiPredictor.IsHighProbability(path) {
		score *= 2
	}

	return score
}

func (rc *ReconCrawler) rotateGitHubToken() string {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if len(rc.githubTokens) == 0 {
		return ""
	}
	token := rc.githubTokens[0]
	rc.githubTokens = append(rc.githubTokens[1:], token)
	return token
}

func (rc *ReconCrawler) fetchContent(ctx context.Context, rawURL string) string {
	req, _ := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	req.Header.Set("User-Agent", "deepfuzz-recon")
	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	content, _ := io.ReadAll(resp.Body)
	return string(content)
}

func (rc *ReconCrawler) fetchGitHubContent(ctx context.Context, htmlURL string) string {
	return rc.fetchContent(ctx, htmlURL)
}

func extractPaths(content string) []string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)["'](https?://[^\s"']+)["']`),
		regexp.MustCompile(`(?i)["'](/[^\s"']+)["']`),
		regexp.MustCompile(`(?i)(?:router\.|path=)['"]([^"']+)['"]`),
	}

	var paths []string
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				paths = append(paths, match[1])
			}
		}
	}
	return paths
}

func extractJSPaths(content []byte) []string {
	pattern := regexp.MustCompile(`(?i)src=["']([^"']+\.js)["']`)
	matches := pattern.FindAllStringSubmatch(string(content), -1)

	var paths []string
	for _, match := range matches {
		if len(match) > 1 {
			paths = append(paths, match[1])
		}
	}
	return paths
}

func (s CrawlSource) String() string {
	return [...]string{"github", "commoncrawl", "js", "history"}[s]
}

type Discovery struct {
	Path   string `json:"path"`
	Score  int    `json:"score"`
	Source string `json:"source"`
}
