package discovery

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"regexp"
	"strings"
	"sync"
	"time"
)

type PathPredictor struct {
	mu       sync.RWMutex
	aiEnabled bool
	patterns map[string]int 
	rng      *mrand.Rand  
}

func NewPathPredictor() *PathPredictor {
	var b [8]byte
	_, _ = rand.Read(b[:])
	seed := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
	return &PathPredictor{
		patterns: make(map[string]int),
		rng:      mrand.New(mrand.NewSource(seed)),
	}
}

func (p *PathPredictor) Train(paths []string) {
	p.mu.Lock()
	for _, path := range paths {
		lp := strings.ToLower(path)
		p.patterns(lp)++
	}
	p.mu.Unlock()
}

func (p *PathPredictor) Predict(domain string, count int) []string {
	if count <= 0 {
		return nil
	}
	out := make([]string, 0, count)
	type kv struct{ path string; freq int }
	var learned []kv
	p.mu.RLock()
	for path, freq := range p.patterns {
		learned = append(learned, kv{path: path, freq: freq})
	}
	p.mu.RUnlock()
	topK := count
	if topK < 8 {
		topK = 8
	}
	limit := topK
	if len(learned) < limit {
		limit = len(learned)
	}

	for i := 0; i < limit; i++ {
		maxIdx := i
		for j := i + 1; j < len(learned); j++ {
			if learned[j].freq > learned[maxIdx].freq {
				maxIdx = j
			}
		}
		learned[i], learned[maxIdx] = learned[maxIdx], learned[i]
	}

	for i := 0; i < limit && len(out) < count/2; i++ {
		lp := learned[i].path
		candidate := lp
		if p.rng.Intn(2) == 0 {
			candidate = parametrizePath(candidate)
		}
		if p.rng.Intn(2) == 0 {
			candidate = modernizePath(candidate)
		}
		if p.rng.Intn(2) == 0 {
			candidate = versionPath(candidate, p.rng)
		}
		if p.rng.Intn(2) == 0 {
			candidate = obfuscatePath(candidate, p.rng)
		}
		out = append(out, ensureLeadingSlash(candidate))
	}

	if p.aiEnabled && len(out) < count {
		out = append(out, p.aiPredict(domain, count-len(out))...)
	}

	if len(out) < count {
		out = append(out, p.heuristicPredict(domain, count-len(out))...)
	}

	uniq := make(map[string]struct{}, len(out))
	final := make([]string, 0, count)
	for _, v := range out {
		if v == "" {
			continue
		}
		if _, ok := uniq[v]; ok {
			continue
		}
		uniq[v] = struct{}{}
		final = append(final, v)
		if len(final) == count {
			break
		}
	}
	return final
}

func (p *PathPredictor) aiPredict(domain string, count int) []string {
	core := []string{
		"/api/v3/graphql",
		"/internal/admin",
		"/debug/pprof",
		"/.well-known/security.txt",
		"/.git/config",
		"/.env",
	}
	if count <= len(core) {
		return core[:count]
	}
	extra := p.heuristicPredict(domain, count-len(core))
	return append(core, extra...)
}

func (p *PathPredictor) heuristicPredict(domain string, count int) []string {
	r := p.rng
	verbs := []string{"users", "config", "settings", "env", "db", "backup", "logs", "secrets", "tokens", "sessions"}
	versions := []int{1, 2, 3, 4}
	build := func() string {
		switch r.Intn(10) {
		case 0, 1, 2, 3:
			return fmt.Sprintf("/api/v%d/%s", versions[r.Intn(len(versions))], verbs[r.Intn(len(verbs))])
		case 4:
			return "/admin/" + verbs[r.Intn(len(verbs))]
		case 5:
			return "/internal/" + verbs[r.Intn(len(verbs))]
		case 6:
			return "/debug/" + verbs[r.Intn(len(verbs))]
		case 7:
			return "/.git/" + []string{"config", "HEAD", "index"}[r.Intn(3)]
		case 8:
			return "/backup/" + []string{"backup.zip", "db.sql", "site.tar.gz"}[r.Intn(3)]
		default:
			return "/api/" + verbs[r.Intn(len(verbs))]
		}
	}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, build())
	}
	return out
}

func (p *PathPredictor) IsHighProbability(path string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	lp := strings.ToLower(path)
	if _, exists := p.patterns[lp]; exists {
		return true
	}

	for pattern := range p.patterns {
		if strings.Contains(lp, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

func parametrizePath(path string) string {
	re := regexp.MustCompile(`/\d+`)
	return re.ReplaceAllString(path, "/{id}")
}

func modernizePath(path string) string {
	replacements := map[string]string{
		".php":    "",
		"v1":      "v3",
		"action=": "mutation/",
	}
	for old, new := range replacements {
		path = strings.ReplaceAll(path, old, new)
	}
	return path
}

func versionPath(path string, r *mrand.Rand) string {
	hasV := regexp.MustCompile(`(^|/)v\d+(/|$)`).MatchString(path)
	if !hasV {
		versions := []string{"v2", "v3", "v4"}
		return "/" + versions[r.Intn(len(versions))] + ensureLeadingSlash(path)
	}
	return path
}

func obfuscatePath(path string, r *mrand.Rand) string {
	if r.Intn(2) == 0 {
		return "/.%2e" + ensureLeadingSlash(path)
	}
	return path
}

func ensureLeadingSlash(p string) string {
	if p == "" || p[0] == '/' {
		return p
	}
	return "/" + p
}
