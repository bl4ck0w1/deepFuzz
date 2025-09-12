package ai

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
	pb "github.com/bl4ck0w1/deepFuzz/proto/gen/waf_generator"

)

type MutationGenerator interface {
	MutatePath(path string) string
}

type WAFBypassClient struct {
	conn   *grpc.ClientConn
	client pb.WAFGeneratorClient
}

func NewWAFBypassClient(addr string) (*WAFBypassClient, error) {
	if addr == "" {
		return nil, fmt.Errorf("WAF AI address is required")
	}
	ka := keepalive.ClientParameters{
		Time:                20 * time.Second,
		Timeout:             5 * time.Second,
		PermitWithoutStream: true,
	}
	conn, err := grpc.Dial(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(ka),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)),
		grpc.WithDefaultServiceConfig(`{
			"loadBalancingConfig": [{"round_robin":{}}],
			"methodConfig": [{
				"name": [{"service": "waf_generator.WAFGenerator"}],
				"timeout": "0.10s",
				"retryPolicy": {
					"MaxAttempts": 3,
					"InitialBackoff": "0.03s",
					"MaxBackoff": "0.20s",
					"BackoffMultiplier": 1.5,
					"RetryableStatusCodes": ["UNAVAILABLE","DEADLINE_EXCEEDED"]
				}
			}]
		}`),
	)
	if err != nil {
		return nil, fmt.Errorf("WAF AI connection failed: %v", err)
	}
	return &WAFBypassClient{
		conn:   conn,
		client: pb.NewWAFGeneratorClient(conn),
	}, nil
}

func (c *WAFBypassClient) IsActive() bool {
	return c != nil && c.client != nil
}

func (c *WAFBypassClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *WAFBypassClient) GenerateEvasion(u string) (string, error) {
	if c == nil || c.client == nil {
		return u, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	req := &pb.EvadeRequest{TargetUrl: u}
	resp, err := c.client.GenerateEvasion(ctx, req)
	if err != nil {
		return cheapEvasion(u), nil
	}

	return resp.GetEvadedUrl(), nil
}

func (c *WAFBypassClient) MutatePath(path string) []string {
	if c == nil || c.client == nil {
		return fallbackMutations(path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	req := &pb.MutateRequest{OriginalPath: path}
	resp, err := c.client.MutatePath(ctx, req)
	if err != nil {
		return fallbackMutations(path)
	}

	return resp.GetVariants()
}

func (c *WAFBypassClient) ReportBlockedPayload(payload string) {
	go func() {
		if c == nil || c.client == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
		defer cancel()

		_, _ = c.client.AdversarialFeedback(ctx, &pb.FeedbackRequest{
			Payload:    payload,
			WasBlocked: true,
		})
	}()
}

func (c *WAFBypassClient) MutatePathSingle(path string) string {
	variants := c.MutatePath(path)
	if len(variants) == 0 {
		return path
	}
	return variants[0]
}

func fallbackMutations(p string) []string {
	base := p
	if base == "" {
		base = "/"
	}
	
	if u, err := url.Parse(base); err == nil && u.Scheme != "" {
		base = u.EscapedPath()
		if u.RawQuery != "" {
			base += "?" + u.RawQuery
		}
	}
	var out []string
	out = append(out, encodeSegments(base, 2))
	out = append(out, strings.ReplaceAll(base, "/", "/.;/"))
	out = append(out, strings.ReplaceAll(base, "/", "/.%2e/"))

	if strings.Contains(base, "?") {
		out = append(out, base+"&_="+randToken(6))
		out = append(out, base+"&__proto__=x&constructor=1")
	} else {
		out = append(out, base+"?"+randToken(3)+"="+randToken(8))
	}

	out = append(out, toggleCase(base))
	out = append(out, base+";/")
	out = append(out, base+"/.")
	
	if !strings.Contains(base, ".") {
		out = append(out, base+".json", base+".xml", base+"/graphql")
	}
	return dedupe(out)
}

func cheapEvasion(u string) string {
	if strings.Contains(u, "?") {
		return u + "&__dfz__=" + randToken(5) + "#_"
	}
	return u + "?__dfz__=" + randToken(5) + "#_"
}

func encodeSegments(p string, times int) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		s := seg
		for t := 0; t < times; t++ {
			s = url.QueryEscape(s)
		}
		parts[i] = s
	}
	return strings.Join(parts, "/")
}

func toggleCase(s string) string {
	var b strings.Builder
	for i := range s {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' {
			ch = 'A' + (ch - 'a')
		} else if ch >= 'A' && ch <= 'Z' {
			ch = 'a' + (ch - 'A')
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func randToken(n int) string {
	alpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = alpha[rand.Intn(len(alpha))]
	}
	return string(out)
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
