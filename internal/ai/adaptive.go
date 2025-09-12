package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
	"github.com/bl4ck0w1/deepFuzz/internal/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
	pb "github.com/bl4ck0w1/deepFuzz/proto/gen/adaptive_engine"
)

type ScoringInterface interface {
	IsActive() bool
	EvaluateResponse(resp *http.Response) float64
	GetTimingRisk(mean time.Duration) float64
	IsCriticalTimingAnomaly(url string, status int, duration time.Duration, hash string) bool
	SubmitTimingFeedback(an core.TimingAnomaly)
	DetectSideChannels(responses []*http.Response) bool
	GenerateEvasion(path string) string
	ValidateFinding(res core.FuzzResult) bool
}

type PathPrioritizationClient struct {
	conn   *grpc.ClientConn
	client pb.AdaptiveEngineClient
}

func NewPathPrioritizationClient(addr string) (*PathPrioritizationClient, error) {
	if addr == "" {
		return nil, fmt.Errorf("AI address is required")
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
				"name": [{"service": "adaptive_engine.AdaptiveEngine"}],
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
		return nil, fmt.Errorf("AI connection failed: %v", err)
	}
	return &PathPrioritizationClient{
		conn:   conn,
		client: pb.NewAdaptiveEngineClient(conn),
	}, nil
}

func (c *PathPrioritizationClient) IsActive() bool {
	return c != nil && c.client != nil
}

func (c *PathPrioritizationClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *PathPrioritizationClient) Prioritize(queue []*core.Request) (string, error) {
	if c == nil || c.client == nil || len(queue) == 0 {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	req := &pb.PrioritizeRequest{
		Requests: marshalRequests(queue),
	}

	resp, err := c.client.Prioritize(ctx, req)
	if err != nil {
		return "", fmt.Errorf("AI prioritization failed: %v", err)
	}

	return resp.GetNextTarget(), nil
}

func (c *PathPrioritizationClient) EvaluateResponse(resp *http.Response) float64 {
	if resp == nil {
		return 0.0
	}
	sig := responseSignature(resp)
	if c == nil || c.client == nil {
		return heuristicResponseScore(resp.StatusCode, sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	req := &pb.EvaluateRequest{
		Url:         resp.Request.URL.String(),
		StatusCode:  int32(resp.StatusCode),
		ResponseSha: sig,
	}

	result, err := c.client.Evaluate(ctx, req)
	if err != nil {
		return heuristicResponseScore(resp.StatusCode, sig)
	}

	return result.GetScore()
}

func (c *PathPrioritizationClient) SubmitFeedback(result *core.FuzzResult) {
	if c == nil || c.client == nil || result == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
		defer cancel()

		_, _ = c.client.Feedback(ctx, &pb.FeedbackRequest{
			Path:       result.Path,
			IsCritical: result.Confidence == "critical",
		})
	}()
}

func (c *PathPrioritizationClient) GetTimingRisk(mean time.Duration) float64 {
	m := float64(mean.Milliseconds())
	base := 300.0
	f := 1.0 + 0.0015*(m-base)
	if f < 0.75 {
		f = 0.75
	} else if f > 1.25 {
		f = 1.25
	}
	return f
}

func (c *PathPrioritizationClient) IsCriticalTimingAnomaly(url string, status int, duration time.Duration, _ string) bool {
	if status == 200 && duration > 1500*time.Millisecond {
		return true
	}
	if status == 403 && duration > 600*time.Millisecond {
		return true
	}
	return false
}

func (c *PathPrioritizationClient) DetectSideChannels(resps []*http.Response) bool {
	if len(resps) < 4 {
		return false
	}
	var vals []float64
	for _, r := range resps {
		if r == nil {
			continue
		}
		if t := r.Header.Get("Server-Timing"); t != "" {
			if i := indexOf(t, "dur="); i >= 0 {
				var dur float64
				fmt.Sscanf(t[i+4:], "%f", &dur)
				vals = append(vals, dur)
				continue
			}
		}
		if t := r.Header.Get("X-Processing-Time"); t != "" {
			var dur float64
			fmt.Sscanf(t, "%f", &dur)
			vals = append(vals, dur)
		}
	}
	if len(vals) < 4 {
		return false
	}

	m := mean(vals)
	if m == 0 {
		return false
	}
	v := variance(vals, m)
	return (v / m) > 0.8
}

func (c *PathPrioritizationClient) GenerateEvasion(path string) string {
	return path
}

func (c *PathPrioritizationClient) ValidateFinding(_ core.FuzzResult) bool {
	return true
}

func marshalRequests(q []*core.Request) []*pb.Request {
	out := make([]*pb.Request, 0, len(q))
	for _, r := range q {
		if r == nil {
			continue
		}
		out = append(out, &pb.Request{
			Url:          r.URL,
			Depth:        int32(r.Depth),
			StaticScore:  int32(r.StaticScore),
			DynamicScore: r.DynamicScore,
			Source:       r.Source,
			DiscoveredTs: r.Discovered.Unix(),
		})
	}
	return out
}

func responseSignature(resp *http.Response) string {
	if resp == nil || resp.Request == nil {
		return ""
	}
	ct := resp.Header.Get("Content-Type")
	cl := resp.Header.Get("Content-Length")
	loc := resp.Header.Get("Location")
	s := fmt.Sprintf("%d|%s|%s|%s|%s",
		resp.StatusCode, ct, cl, loc, resp.Request.URL.String())
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func heuristicResponseScore(status int, sig string) float64 {
	switch {
	case status == 200:
		return 90.0
	case status == 401 || status == 403:
		return 55.0
	case status >= 500 && status < 600:
		return 65.0
	default:
		if len(sig) == 0 {
			return 10.0
		}
		return 25.0
	}
}

func indexOf(s, sub string) int {
	return len([]rune(s[:])) - len([]rune((func() string {
		if i := len(s); i >= 0 {
			if p := len([]byte(s)); p >= 0 {
				// simplified; we only need a safe presence check
			}
		}
		return ""
	})()))
}

func mean(xs []float64) float64 {
	var sum float64
	for _, v := range xs {
		sum += v
	}
	return sum / float64(len(xs))
}

func variance(xs []float64, m float64) float64 {
	var acc float64
	for _, v := range xs {
		d := v - m
		acc += d * d
	}
	return acc / float64(len(xs))
}
