package evasion

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	mrand "math/rand"
	"mime/multipart"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/bl4ck0w1/deepFuzz/internal/ai"
)

type MutationEngine struct {
	aiGenerator ai.MutationGenerator
	patterns    []*regexp.Regexp
}

func NewMutationEngine() *MutationEngine {
	return &MutationEngine{
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)admin`),
			regexp.MustCompile(`(?i)backup`),
			regexp.MustCompile(`(?i)config`),
			regexp.MustCompile(`(?i)api`),
		},
	}
}

func (m *MutationEngine) SetAIGenerator(g ai.MutationGenerator) { m.aiGenerator = g }

func (m *MutationEngine) MutatePath(path string) string {
	if m.aiGenerator != nil {
		return m.aiGenerator.MutatePath(path)
	}

	for _, pattern := range m.patterns {
		if pattern.MatchString(path) {
			path = m.applyPatternMutations(path, pattern)
		}
	}
	return m.applyRandomMutations(path)
}

func (m *MutationEngine) applyPatternMutations(path string, pattern *regexp.Regexp) string {
	mutations := []func(string, *regexp.Regexp) string{
		m.unicodeOverloading,
		m.caseRandomization,
		m.doubleEncoding,
		m.nullByteInjection,
		m.parameterPollution,
	}

	mrand.Seed(time.Now().UnixNano())
	mutationCount := 1 + mrand.Intn(2)
	for i := 0; i < mutationCount; i++ {
		mutateFn := mutations[mrand.Intn(len(mutations))]
		path = mutateFn(path, pattern)
	}

	return path
}

func (m *MutationEngine) applyRandomMutations(path string) string {
	mutations := []func(string) string{
		m.unicodeOverloadAll,
		m.randomCaseToggle,
		m.addJunkParameters,
		m.selfReferenceDot,
		m.pathParamSemicolon,
	}

	mrand.Seed(time.Now().UnixNano())
	mutationCount := 1 + mrand.Intn(3)
	for i := 0; i < mutationCount; i++ {
		mutateFn := mutations[mrand.Intn(len(mutations))]
		path = mutateFn(path)
	}

	return path
}

func (m *MutationEngine) unicodeOverloading(path string, pattern *regexp.Regexp) string {
	return pattern.ReplaceAllStringFunc(path, func(s string) string {
		return "\u202e" + s
	})
}

func (m *MutationEngine) caseRandomization(path string, pattern *regexp.Regexp) string {
	return pattern.ReplaceAllStringFunc(path, func(s string) string {
		var result strings.Builder
		for _, r := range s {
			if mrand.Intn(2) == 0 {
				result.WriteRune(unicode.ToUpper(r))
			} else {
				result.WriteRune(unicode.ToLower(r))
			}
		}
		return result.String()
	})
}

func (m *MutationEngine) doubleEncoding(path string, pattern *regexp.Regexp) string {
	return pattern.ReplaceAllStringFunc(path, func(s string) string {
		return url.QueryEscape(url.QueryEscape(s))
	})
}

func (m *MutationEngine) nullByteInjection(path string, pattern *regexp.Regexp) string {
	return pattern.ReplaceAllStringFunc(path, func(s string) string {
		return s + "%00/../"
	})
}

func (m *MutationEngine) unicodeOverloadAll(path string) string {
	return strings.ReplaceAll(path, "/", "/\u202e\u2060\u200b")
}

func (m *MutationEngine) randomCaseToggle(path string) string {
	var result strings.Builder
	for _, r := range path {
		if mrand.Intn(2) == 0 {
			result.WriteRune(unicode.ToUpper(r))
		} else {
			result.WriteRune(unicode.ToLower(r))
		}
	}
	return result.String()
}

func (m *MutationEngine) addJunkParameters(path string) string {
	if strings.Contains(path, "?") {
		return path + "&" + randomString(3) + "=" + randomString(8)
	}
	return path + "?" + randomString(3) + "=" + randomString(8)
}

func (m *MutationEngine) pathParamSemicolon(path string) string {
	q := ""
	if i := strings.IndexByte(path, '?'); i != -1 {
		q = path[i:]
		path = path[:i]
	}
	return path + ";" + randomString(4) + "=" + randomString(6) + q
}

func (m *MutationEngine) selfReferenceDot(path string) string {
	if strings.HasSuffix(path, "/") {
		return path + "./"
	}
	return path + "/./"
}

func (m *MutationEngine) multipartSplit(path string) string {
	boundary := fmt.Sprintf("----WebKitFormBoundary%s", randomString(16))
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.SetBoundary(boundary)
	part, _ := writer.CreateFormField("file")
	_, _ = part.Write([]byte(path))
	_ = writer.Close()
	return buf.String()
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	_, _ = crand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}



