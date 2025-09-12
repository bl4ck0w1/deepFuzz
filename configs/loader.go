package configs

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"gopkg.in/yaml.v3"
)

type Profile struct {
	Strategy       string `yaml:"strategy"`
	Concurrency    int    `yaml:"concurrency"`
	MaxDepth       int    `yaml:"max_depth"`
	AIIntegration  bool   `yaml:"ai_integration"`
	EvasionLevel   int    `yaml:"evasion_level"`
	TimingAnalysis string `yaml:"timing_analysis"`
	ClusterMode    string `yaml:"cluster_mode"`
}

type Persona struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	TLSConfig   string            `yaml:"tls_config"`  
	HTTPVersion string            `yaml:"http_version"`
	Headers     map[string]string `yaml:"headers"`
	TCPParams   struct {
		TTL        int `yaml:"ttl"`
		WindowSize int `yaml:"window_size"`
		MSS        int `yaml:"mss"`
	} `yaml:"tcp_parameters"`
}

type WAFProfile struct {
	ID                  string `yaml:"id"`
	Name                string `yaml:"name"`
	DetectionSignatures struct {
		Headers     []string `yaml:"headers"`
		StatusCodes []int    `yaml:"status_codes"`
	} `yaml:"detection_signatures"`
	BypassTemplates []string `yaml:"bypass_templates"`
	InjectionPoints struct {
		Headers []string `yaml:"headers"`
		Cookies []string `yaml:"cookies"`
	} `yaml:"injection_points"`
}

var (
	profileCache = struct {
		sync.RWMutex
		m map[string]*Profile
	}{m: make(map[string]*Profile)}

	personaCache = struct {
		sync.RWMutex
		m map[string]*Persona
	}{m: make(map[string]*Persona)}

	wafCache = struct {
		sync.RWMutex
		m map[string]*WAFProfile
	}{m: make(map[string]*WAFProfile)}
)

func ConfigRoot() string {
	if v := os.Getenv("DEEPFUZZ_CONFIG_DIR"); v != "" {
		return v
	}
	return "configs"
}

func LoadProfile(name string) (*Profile, error) {
	profileCache.RLock()
	if p, ok := profileCache.m[name]; ok {
		profileCache.RUnlock()
		return p, nil
	}
	profileCache.RUnlock()

	path := filepath.Join(ConfigRoot(), "profiles", name+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Profile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := validateProfile(&cfg); err != nil {
		return nil, err
	}
	profileCache.Lock()
	profileCache.m[name] = &cfg
	profileCache.Unlock()
	return &cfg, nil
}

func LoadPersona(id string) (*Persona, error) {
	personaCache.RLock()
	if p, ok := personaCache.m[id]; ok {
		personaCache.RUnlock()
		return p, nil
	}
	personaCache.RUnlock()

	path := filepath.Join(ConfigRoot(), "personas", id+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Persona
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := validatePersona(&cfg); err != nil {
		return nil, err
	}
	personaCache.Lock()
	personaCache.m[id] = &cfg
	personaCache.Unlock()
	return &cfg, nil
}

func LoadWAFProfile(id string) (*WAFProfile, error) {
	wafCache.RLock()
	if w, ok := wafCache.m[id]; ok {
		wafCache.RUnlock()
		return w, nil
	}
	wafCache.RUnlock()

	path := filepath.Join(ConfigRoot(), "waf_profiles", id+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg WAFProfile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := validateWAF(&cfg); err != nil {
		return nil, err
	}
	wafCache.Lock()
	wafCache.m[id] = &cfg
	wafCache.Unlock()
	return &cfg, nil
}

func validateProfile(p *Profile) error {
	if p.Concurrency <= 0 {
		p.Concurrency = 10
	}
	if p.MaxDepth < 0 {
		p.MaxDepth = 0
	}
	if p.TimingAnalysis == "" {
		p.TimingAnalysis = "microsecond"
	}
	if p.Strategy == "" {
		p.Strategy = "strategic_default"
	}
	return nil
}

func validatePersona(p *Persona) error {
	if p.ID == "" {
		p.ID = p.Name
	}
	if p.HTTPVersion == "" {
		p.HTTPVersion = "2"
	}
	if p.Headers == nil {
		p.Headers = map[string]string{}
	}
	return nil
}

func validateWAF(w *WAFProfile) error {

	if w.DetectionSignatures.Headers == nil {
		w.DetectionSignatures.Headers = []string{}
	}
	if w.DetectionSignatures.StatusCodes == nil {
		w.DetectionSignatures.StatusCodes = []int{}
	}
	if w.BypassTemplates == nil {
		w.BypassTemplates = []string{}
	}
	if w.InjectionPoints.Headers == nil {
		w.InjectionPoints.Headers = []string{}
	}
	if w.InjectionPoints.Cookies == nil {
		w.InjectionPoints.Cookies = []string{}
	}
	return nil
}

func GetActivePersona() string {
	if v := os.Getenv("DEEPFUZZ_PERSONA"); v != "" {
		return v
	}
	return "chrome_windows"
}

func GetWAFProfile(target string) string {
	if v := os.Getenv("DEEPFUZZ_WAF"); v != "" {
		return v
	}
	t := strings.ToLower(target)
	switch {
	case strings.Contains(t, "cloudflare"):
		return "cloudflare"
	default:
		return "cloudflare"
	}
}

func ClearCaches() {
	profileCache.Lock()
	profileCache.m = make(map[string]*Profile)
	profileCache.Unlock()

	personaCache.Lock()
	personaCache.m = make(map[string]*Persona)
	personaCache.Unlock()

	wafCache.Lock()
	wafCache.m = make(map[string]*WAFProfile)
	wafCache.Unlock()
}
