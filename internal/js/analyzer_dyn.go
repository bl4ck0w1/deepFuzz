package js

import (
	"context"
	"errors"
	"math/rand"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

type DynStrategy string

const (
	StrategyBalanced DynStrategy = "balanced"
	StrategyStealth  DynStrategy = "stealth"
	StrategyAggro    DynStrategy = "aggressive"
)

type Coverage struct {
	Enabled      bool 
	LogBodies    bool 
	MaxBodyBytes int 
}


type Budget struct {
	MaxRequests int          
	MaxDuration time.Duration
}

type DynOptions struct {
	Headless     bool
	Timeout      time.Duration
	PoolSize     int
	ProxyURL     string
	UserAgent    string           
	ExtraHeaders map[string]string
	Strategy     DynStrategy     
	Coverage     Coverage
	Budget       Budget
}

type DynAnalyzer struct {
	browser *rod.Browser
	pages   chan *rod.Page
	opts    DynOptions
	static *Analyzer
	closeOnce sync.Once
	closed    chan struct{}
}

func NewDynAnalyzer(opts DynOptions) (*DynAnalyzer, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	if opts.PoolSize <= 0 {
		opts.PoolSize = 2
	}
	if opts.Coverage.MaxBodyBytes <= 0 {
		opts.Coverage.MaxBodyBytes = 64 * 1024
	}
	if opts.Strategy == "" {
		opts.Strategy = StrategyBalanced
	}

	ua, hdr := personaHeaders(opts.Strategy)
	if opts.UserAgent != "" {
		ua = opts.UserAgent
	}

	for k, v := range opts.ExtraHeaders {
		hdr[k] = v
	}

	l := launcher.New()
	l = l.Headless(opts.Headless || !launcher.IsLinux)
	l = l.
		Set("disable-blink-features", "AutomationControlled").
		Set("disable-features", "IsolateOrigins,site-per-process").
		Set("disable-extensions").
		Set("disable-infobars").
		Set("no-first-run").
		Set("no-default-browser-check")

	if opts.ProxyURL != "" {
		l = l.Proxy(opts.ProxyURL)
	}

	controlURL, err := l.Launch()
	if err != nil {
		return nil, err
	}

	browser := rod.New().
		ControlURL(controlURL).
		MustConnect().
		MustIgnoreCertErrors(true)

	pool := make(chan *rod.Page, opts.PoolSize)
	for i := 0; i < opts.PoolSize; i++ {
		p := newStealthPage(browser, ua, hdr)
		pool <- p
	}

	return &DynAnalyzer{
		browser: browser,
		pages:   pool,
		opts:    opts,
		static:  NewAnalyzer(),
		closed:  make(chan struct{}),
	}, nil
}

func (d *DynAnalyzer) AnalyzeURL(ctx context.Context, target string) ([]string, []string, error) {
	select {
	case <-d.closed:
		return nil, nil, errors.New("dynamic analyzer closed")
	default:
	}

	var page *rod.Page
	select {
	case page = <-d.pages:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	defer func() { d.pages <- page }()

	timeout := d.opts.Timeout
	if d.opts.Budget.MaxDuration > 0 && d.opts.Budget.MaxDuration < timeout {
		timeout = d.opts.Budget.MaxDuration
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	_ = page.SetExtraHeaders(d.strategyHeaders())
	if ua := d.strategyUA(); ua != "" {
		_ = page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: ua})
	}

	endpoints := make(map[string]struct{})
	secrets := make(map[string]struct{})

	var stopReq, stopResp func()
	var reqCount int32
	if d.opts.Coverage.Enabled {
		_ = page.EnableDomain(&proto.NetworkEnable{})

		stopReq = page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
			atomic.AddInt32(&reqCount, 1)
			if u := e.Request.URL; plausibleEndpoint(u) {
				endpoints[u] = struct{}{}
			}
		})

		if d.opts.Coverage.LogBodies {
			stopResp = page.EachEvent(func(e *proto.NetworkResponseReceived) {
				u := e.Response.URL
				if plausibleEndpoint(u) {
					endpoints[u] = struct{}{}
				}

				if e.Response.EncodedDataLength > 0 && e.Response.EncodedDataLength <= int64(d.opts.Coverage.MaxBodyBytes) {
					body, err := proto.NetworkGetResponseBody{RequestID: e.RequestID}.Call(page)
					if err == nil && len(body.Body) > 0 {
						for _, ep := range d.static.ExtractEndpoints([]byte(body.Body)) {
							endpoints[ep] = struct{}{}
						}
						for _, s := range d.static.FindSecrets([]byte(body.Body)) {
							secrets[s] = struct{}{}
						}
					}
				}
			})
		}

		go func() {
			ticker := time.NewTicker(150 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-pctx.Done():
					return
				case <-ticker.C:
					if d.opts.Budget.MaxRequests > 0 && atomic.LoadInt32(&reqCount) >= int32(d.opts.Budget.MaxRequests) {
						_ = page.Call(&proto.PageStopLoading{})
						return
					}
				}
			}
		}()

		d.injectCoverageJS(page)
	}

	if err := page.Context(pctx).Navigate(target); err != nil {
		if stopReq != nil {
			stopReq()
		}
		if stopResp != nil {
			stopResp()
		}
		return nil, nil, err
	}
	_ = page.Context(pctx).WaitLoad()

	d.humanize(page)

	arr, _ := page.Eval(`() => {
		const s = new Set();
		const add = v => { try { if (v && typeof v === 'string') s.add(v); } catch (_) {} };
		document.querySelectorAll('[href],[src]').forEach(el => {
			if (el.href) add(el.href);
			if (el.src) add(el.src);
		});
		return Array.from(s);
	}`)
	if arr != nil && arr.Value != nil {
		if list, ok := arr.Value.([]interface{}); ok {
			for _, v := range list {
				if s, ok := v.(string); ok && plausibleEndpoint(s) {
					endpoints[s] = struct{}{}
				}
			}
		}
	}

	_ = page.Eval(`() => {
		try {
			const scripts = document.querySelectorAll('script');
			for (const sc of scripts) {
				if (!sc.textContent) continue;
				// Common P.A.C.K.E.R. signature
				if (sc.textContent.includes('eval(function(p,a,c,k,e,d)')) {
					try { sc.textContent = (0,eval)(sc.textContent); } catch(e) {}
				}
				// Base64 blobs (naive heuristic)
				const m = sc.textContent.match(/[A-Za-z0-9+/=]{120,}/g);
				if (m) {
					for (const blob of m) {
						try {
							const dec = atob(blob);
							if (dec && dec.length > 80) sc.textContent += "\n/*DF-DECODE*/\n" + dec;
						} catch(e) {}
					}
				}
			}
		} catch(_) {}
	}`)
	html, _ := page.HTML()

	for _, ep := range d.static.ExtractEndpoints([]byte(html)) {
		endpoints[ep] = struct{}{}
	}
	for _, s := range d.static.FindSecrets([]byte(html)) {
		secrets[s] = struct{}{}
	}

	if d.opts.Coverage.Enabled {
		val, _ := page.Eval(`() => (window.__DF_LOG__ && Array.from(window.__DF_LOG__)) || []`)
		if val != nil && val.Value != nil {
			if list, ok := val.Value.([]interface{}); ok {
				for _, v := range list {
					if s, ok := v.(string); ok && plausibleEndpoint(s) {
						endpoints[s] = struct{}{}
					}
				}
			}
		}
	}

	if stopReq != nil {
		stopReq()
	}
	if stopResp != nil {
		stopResp()
	}

	ep := mapToSortedSlice(endpoints)
	sec := mapToSortedSlice(secrets)
	return ep, sec, nil
}

func (d *DynAnalyzer) Close() error {
	var err error
	d.closeOnce.Do(func() {
		close(d.closed)
		close(d.pages)
		for p := range d.pages {
			_ = p.Close()
		}
		err = d.browser.Close()
	})
	return err
}

func newStealthPage(browser *rod.Browser, ua string, headers map[string]string) *rod.Page {
	p := browser.MustPage("about:blank")
	p.MustEval(`() => {
		Object.defineProperty(navigator, 'webdriver', { get: () => false });
		try { window.chrome = { runtime: {} }; } catch(_) {}
		try { Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3] }); } catch(_) {}
		try { Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] }); } catch(_) {}
		try { window.screen = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040 }; } catch(_) {}
	}`)
	if ua != "" {
		_ = p.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: ua})
	}
	if len(headers) > 0 {
		_ = p.SetExtraHeaders(headers)
	}
	return p
}

func (d *DynAnalyzer) humanize(page *rod.Page) {
	for i := 0; i < 2+rand.Intn(3); i++ {
		_, _ = page.Eval(`(y) => { try { window.scrollBy(0, y); } catch(_) {} }`, rand.Intn(600))
		time.Sleep(time.Duration(200+rand.Intn(400)) * time.Millisecond)
	}
}

func (d *DynAnalyzer) injectCoverageJS(page *rod.Page) {
	_ = page.Eval(`() => {
		if (!window.__DF_LOG__) window.__DF_LOG__ = new Set();
		try {
			const oldFetch = window.fetch;
			window.fetch = async (...args) => {
				try {
					const url = (typeof args[0] === 'string') ? args[0] : (args[0] && args[0].url) || '';
					if (url) window.__DF_LOG__.add(url);
				} catch(_) {}
				const res = await oldFetch(...args);
				try { if (res && res.url) window.__DF_LOG__.add(res.url); } catch(_) {}
				return res;
			};
		} catch(_) {}

		try {
			const OldXHR = window.XMLHttpRequest;
			function X() {
				const xhr = new OldXHR();
				const open = xhr.open;
				xhr.open = function(method, url) {
					try { if (url) window.__DF_LOG__.add(url.toString()); } catch(_) {}
					return open.apply(this, arguments);
				};
				return xhr;
			}
			window.XMLHttpRequest = X;
		} catch(_) {}
	}`)
}

func personaHeaders(s DynStrategy) (ua string, hdr map[string]string) {
	hdr = map[string]string{
		"Accept-Language": "en-US,en;q=0.9",
		"DNT":             "1",
	}
	switch s {
	case StrategyStealth:
		ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
	case StrategyAggro:
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
		hdr["Sec-CH-UA"] = `"Chromium";v="125", "Google Chrome";v="125", "Not-A.Brand";v="24"`
	default:
		ua = "Mozilla/5.0 (X11; Linux x86_64; rv:117.0) Gecko/20100101 Firefox/117.0"
	}
	return
}

func (d *DynAnalyzer) strategyUA() string {
	ua, _ := personaHeaders(d.opts.Strategy)
	if d.opts.UserAgent != "" {
		return d.opts.UserAgent
	}
	return ua
}

func (d *DynAnalyzer) strategyHeaders() map[string]string {
	_, base := personaHeaders(d.opts.Strategy)
	for k, v := range d.opts.ExtraHeaders {
		base[k] = v
	}
	return base
}

func plausibleEndpoint(s string) bool {
	if s == "" {
		return false
	}
	if !(strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")) {
		return false
	}
	if strings.HasPrefix(s, "http") {
		if _, err := url.ParseRequestURI(s); err != nil {
			return false
		}
	}
	ls := strings.ToLower(s)
	drops := []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".css"}
	for _, ext := range drops {
		if strings.HasSuffix(ls, ext) {
			return false
		}
	}
	return true
}

func mapToSortedSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
