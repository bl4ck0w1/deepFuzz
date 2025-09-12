package js

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type Analyzer struct {
	endpointRes []*regexp.Regexp
	secretRes   []*regexp.Regexp
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		endpointRes: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`),
			regexp.MustCompile(`(?i)\bfetch\(\s*['"]([^"'\\]+)['"]`),
			regexp.MustCompile(`(?i)\baxios\.(?:get|post|put|patch|delete)\(\s*['"]([^"'\\]+)['"]`),
			regexp.MustCompile(`(?i)\bXMLHttpRequest\s*\(\s*\)\s*;?\s*.*?open\(\s*['"][A-Z]+['"]\s*,\s*['"]([^"'\\]+)['"]`),
			regexp.MustCompile(`(?i)\bxhr\.open\(\s*['"][A-Z]+['"]\s*,\s*['"]([^"'\\]+)['"]`),
			regexp.MustCompile(`(?i)\bnew\s+URL\(\s*['"]([^"'\\]+)['"]`),
			regexp.MustCompile(`(?i)['"](/[^"'<> ]+\.(?:js|mjs|json))(?:\?[^"'<>]*)?['"]`),
			regexp.MustCompile(`(?i)['"](/api[^"'<> ]*)(?:\?[^"'<>]*)?['"]`),
		},
		secretRes: []*regexp.Regexp{
			regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                                           
			regexp.MustCompile(`(?i)aws(.{0,20})?(secret|access).{0,20}?([A-Za-z0-9/+=]{40})`),   
			regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),                                    
			regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),                                      
			regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,48}\b`),                            
			regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{24,}\b`),                                  
			regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),                                       
			regexp.MustCompile(`\beyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\b`),
			regexp.MustCompile(`(?i)\b(DefaultEndpointsProtocol|AccountName|AccountKey|EndpointSuffix)=[^;]+(;|$)`),
		},
	}
}

func (a *Analyzer) ExtractEndpoints(content []byte) []string {
	text := string(content)
	found := make(map[string]struct{})

	for _, re := range a.endpointRes {
		matches := re.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			var s string
			if len(m) > 1 && m[1] != "" {
				s = strings.TrimSpace(m[1])
			} else if len(m) > 0 {
				s = strings.TrimSpace(m[0])
			}
			if s == "" || !isPlausibleEndpoint(s) || len(s) > 2048 {
				continue
			}
			found[s] = struct{}{}
		}
	}
	return setToSortedSlice(found)
}

func (a *Analyzer) FindSecrets(content []byte) []string {
	text := string(content)
	found := make(map[string]struct{})

	for _, re := range a.secretRes {
		matches := re.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			s := ""
			if len(m) > 0 && m[0] != "" {
				s = strings.TrimSpace(m[0])
			} else {
				for i := 1; i < len(m); i++ {
					if m[i] != "" {
						s = strings.TrimSpace(m[i])
						break
					}
				}
			}
			if s == "" || len(s) > 4096 {
				continue
			}
			found[s] = struct{}{}
		}
	}
	return setToSortedSlice(found)
}

func isPlausibleEndpoint(s string) bool {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") {
		if strings.HasPrefix(s, "http") {
			if _, err := url.ParseRequestURI(s); err != nil {
				return false
			}
		}
		l := strings.ToLower(s)
		if strings.HasSuffix(l, ".png") || strings.HasSuffix(l, ".jpg") || strings.HasSuffix(l, ".jpeg") ||
			strings.HasSuffix(l, ".gif") || strings.HasSuffix(l, ".svg") || strings.HasSuffix(l, ".ico") ||
			strings.HasSuffix(l, ".woff") || strings.HasSuffix(l, ".woff2") || strings.HasSuffix(l, ".ttf") ||
			strings.HasSuffix(l, ".eot") || strings.HasSuffix(l, ".css") {
			return false
		}
		return true
	}
	return false
}

func setToSortedSlice(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
