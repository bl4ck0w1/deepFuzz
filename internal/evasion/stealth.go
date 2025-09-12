package evasion

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"github.com/bl4ck0w1/deepFuzz/internal/ai" 
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type StealthEngine struct {
	mu                 sync.RWMutex
	ja3IDs             []utls.ClientHelloID
	currentFpIndex     uint32
	headerTemplates    []map[string]string
	currentPersona     *Persona
	proxyPool          []string
	cookieJar          map[string]string
	delayProfile       DelayProfile
	wafBypassTemplates []string
	mutator *MutationEngine
}

type Persona struct {
	Name        string
	TLSHello    utls.ClientHelloID
	HTTPVersion string
	Headers     map[string]string
}

type DelayProfile struct {
	Min       time.Duration
	Max       time.Duration
	Jitter    float64
	HumanLike bool
}

func NewStealthEngine(personaConfig map[string]interface{}, wafConfig map[string]interface{}) *StealthEngine {
	engine := &StealthEngine{
		ja3IDs: []utls.ClientHelloID{
			utls.HelloChrome_120,
			utls.HelloFirefox_117,
			utls.HelloSafari_16_0,
			utls.HelloRandomizedALPN,
		},
		headerTemplates: []map[string]string{
			{
				"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
				"Accept-Language": "en-US,en;q=0.9",
				"Sec-CH-UA":       `"Chromium";v="125", "Google Chrome";v="125", "Not-A.Brand";v="24"`,
			},
			{
				"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
				"Accept-Language": "en-US,en;q=0.9",
			},
			{
				"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
				"Accept-Language": "en-US,en;q=0.5",
			},
		},
		proxyPool:   make([]string, 0),
		cookieJar:   make(map[string]string),
		delayProfile: DelayProfile{
			Min:       500 * time.Millisecond,
			Max:       2500 * time.Millisecond,
			Jitter:    0.25,
			HumanLike: true,
		},
		currentPersona: &Persona{
			Name:        "chrome_windows",
			TLSHello:    utls.HelloChrome_120,
			HTTPVersion: "2",
			Headers:     map[string]string{},
		},
		mutator: NewMutationEngine(),
	}

	if headers, ok := personaConfig["headers"].(map[string]string); ok {
		engine.headerTemplates = append(engine.headerTemplates, headers)
	}

	if raw, ok := personaConfig["headers"]; ok && raw != nil {
		if m, ok := raw.(map[string]interface{}); ok {
			hdr := make(map[string]string, len(m))
			for k, v := range m {
				hdr[strings.ToLower(k)] = fmt.Sprint(v)
			}
			engine.headerTemplates = append(engine.headerTemplates, hdr)
		} else if m2, ok := raw.(map[string]string); ok {
			engine.headerTemplates = append(engine.headerTemplates, m2)
		}
	}

	if bypass, ok := wafConfig["bypass_templates"].([]string); ok {
		engine.wafBypassTemplates = bypass
	}
	return engine
}

func NewEngine(persona interface{}, wafProfile interface{}) *StealthEngine {
	var p map[string]interface{}
	var w map[string]interface{}
	if pm, ok := persona.(map[string]interface{}); ok {
		p = pm
	} else {
		p = map[string]interface{}{}
	}
	if wm, ok := wafProfile.(map[string]interface{}); ok {
		w = wm
	} else {
		w = map[string]interface{}{}
	}
	return NewStealthEngine(p, w)
}

func (s *StealthEngine) GetHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:             s.rotateProxy(),
		TLSClientConfig:   s.getTLSConfig(),
		ForceAttemptHTTP2: true,
		DialTLSContext:    s.dialTLSContext,
	}

	switch s.currentPersona.HTTPVersion {
	case "2":
		_ = http2.ConfigureTransport(transport)
	case "3":
		// TODO: HTTP/3
	}

	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *StealthEngine) dialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	idx := atomic.AddUint32(&s.currentFpIndex, 1) % uint32(len(s.ja3IDs))
	fp := s.ja3IDs[idx]

	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	uconn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}, fp)

	if err := uconn.Handshake(); err != nil {
		return nil, err
	}

	if tcp, ok := rawConn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	return uconn, nil
}

func (s *StealthEngine) getTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
}

func (s *StealthEngine) RotateHeaders() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rand.Intn(15) > 12 {
		s.rotatePersonaLocked()
	}

	headers := make(http.Header)
	for k, v := range s.currentPersona.Headers {
		headers.Set(k, v)
	}

	headers.Set("X-Forwarded-For", generateRandomIP())
	headers.Set("X-Request-ID", generateUUID())
	headers.Set("CF-Connecting-IP", generateRandomIP())
	headers.Set("CF-IPCountry", randomCountryCode())
	s.applyCookies(headers)
	return headers
}

func (s *StealthEngine) RotatePersona() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotatePersonaLocked()
}

func (s *StealthEngine) rotatePersonaLocked() {
	personas := []*Persona{
		{
			Name:        "chrome_windows",
			TLSHello:    utls.HelloChrome_120,
			HTTPVersion: "2",
			Headers:     s.headerTemplates[0],
		},
		{
			Name:        "safari_macos",
			TLSHello:    utls.HelloSafari_16_0,
			HTTPVersion: "2",
			Headers:     s.headerTemplates[1],
		},
		{
			Name:        "firefox_linux",
			TLSHello:    utls.HelloFirefox_117,
			HTTPVersion: "1.1",
			Headers:     s.headerTemplates[2],
		},
	}
	s.currentPersona = personas[rand.Intn(len(personas))]
}

func (s *StealthEngine) MaintainSessionCookies(resp *http.Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range resp.Cookies() {
		s.cookieJar[c.Name] = c.Value
	}
}

func (s *StealthEngine) applyCookies(headers http.Header) {
	var cookies strings.Builder
	for name, value := range s.cookieJar {
		cookies.WriteString(name)
		cookies.WriteString("=")
		cookies.WriteString(value)
		cookies.WriteString("; ")
	}
	if cookies.Len() > 0 {
		headers.Set("Cookie", cookies.String())
	}
}

func (s *StealthEngine) ApplyDelay() {
	p := s.delayProfile
	var delay time.Duration
	if p.HumanLike {
		shape := 2.0
		scale := float64(p.Max-p.Min) / (shape * 2)
		delay = time.Duration(rand.ExpFloat64()*scale*shape) + p.Min
	} else {
		delay = p.Min + time.Duration(rand.Int63n(int64(p.Max-p.Min)))
	}
	jitter := time.Duration(float64(delay) * (p.Jitter * (rand.Float64()*2 - 1)))
	time.Sleep(delay + jitter)
}

func (s *StealthEngine) rotateProxy() func(*http.Request) (*url.URL, error) {
	if len(s.proxyPool) == 0 {
		return nil
	}
	proxy := s.proxyPool[rand.Intn(len(s.proxyPool))]
	return func(*http.Request) (*url.URL, error) {
		return url.Parse(proxy)
	}
}

func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(253)+1, rand.Intn(256), rand.Intn(256), rand.Intn(253)+1)
}

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func randomCountryCode() string {
	codes := []string{"US", "GB", "DE", "FR", "JP", "CA", "AU"}
	return codes[rand.Intn(len(codes))]
}

func (s *StealthEngine) HandleBlock(resp *http.Response) bool {
	if isBlocked(resp) {
		atomic.AddUint32(&s.currentFpIndex, 1)
		s.RotatePersona()
		return true
	}
	return false
}

func isBlocked(resp *http.Response) bool {
	return resp.StatusCode == 403 ||
		resp.StatusCode == 429 ||
		strings.Contains(resp.Header.Get("Server"), "Cloudflare") ||
		resp.Header.Get("CF-RAY") != ""
}

func (s *StealthEngine) MutatePath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}

	var baseVariants []string
	baseVariants = append(baseVariants, path)
	baseVariants = append(baseVariants,
		path+"%2e/",                         
		path+";/",                          
		strings.TrimRight(path, "/")+"/./", 
		path+"%00",                      
	)

	s.mu.RLock()
	if len(s.wafBypassTemplates) > 0 {
		for _, tpl := range s.wafBypassTemplates {
			baseVariants = append(baseVariants, strings.ReplaceAll(tpl, "{PATH}", path))
		}
	}
	s.mu.RUnlock()

	variant := baseVariants[rand.Intn(len(baseVariants))]
	if s.mutator != nil {
		variant = s.mutator.MutatePath(variant)
	}

	if i := strings.IndexByte(variant, '?'); i != -1 {
		u.RawPath = variant[:i]
		u.Path = u.RawPath
		u.RawQuery = variant[i+1:]
	} else {
		u.RawPath = variant
		u.Path = u.RawPath
	}
	return u.String()
}

func (s *StealthEngine) ApplyCountermeasures(host string) {
	atomic.AddUint32(&s.currentFpIndex, 1)
	s.RotatePersona()
	s.mu.Lock()
	if s.delayProfile.Jitter < 0.45 {
		s.delayProfile.Jitter += 0.05
	}
	if s.delayProfile.Min < 800*time.Millisecond {
		s.delayProfile.Min += 100 * time.Millisecond
	}
	s.mu.Unlock()
}

func (s *StealthEngine) SetMutationEngine(m *MutationEngine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutator = m
}

func (s *StealthEngine) SetMutationAIGenerator(g ai.MutationGenerator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mutator == nil {
		s.mutator = NewMutationEngine()
	}
	s.mutator.SetAIGenerator(g)
}
