package ai

import (
	"context"
	"fmt"
	"time"
	"github.com/bl4ck0w1/deepFuzz/internal/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
	pb "github.com/bl4ck0w1/deepFuzz/proto/gen/response_cluster"

)

type SimilarityValidator interface {
	IsActive() bool
	ValidateFinding(result core.FuzzResult) bool
	IsSoft404(content []byte, url string) bool
	Close() error
}

type SimilarityClient struct {
	conn   *grpc.ClientConn
	client pb.SimilarityClient
}

func NewSimilarityClient(addr string) (*SimilarityClient, error) {
	if addr == "" {
		return nil, fmt.Errorf("similarity AI address is required")
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
				"name": [{"service": "response_cluster.Similarity"}],
				"timeout": "0.12s",
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
		return nil, fmt.Errorf("similarity AI connection failed: %v", err)
	}
	return &SimilarityClient{
		conn:   conn,
		client: pb.NewSimilarityClient(conn),
	}, nil
}

func (c *SimilarityClient) IsActive() bool {
	return c != nil && c.client != nil
}

func (c *SimilarityClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *SimilarityClient) ValidateFinding(result core.FuzzResult) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	req := &pb.ValidationRequest{
		Url:         result.Path,
		ResponseSha: result.ResponseSignature,
		StatusCode:  int32(result.StatusCode),
	}

	resp, err := c.client.Validate(ctx, req)
	if err != nil {
		return true
	}

	return resp.GetIsValid()
}

func (c *SimilarityClient) IsSoft404(content []byte, url string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	req := &pb.Soft404Request{
		Content: content,
		Url:     url,
	}

	resp, err := c.client.IsSoft404(ctx, req)
	if err != nil {
		return false
	}

	return resp.GetIsSoft404()
}

func (c *SimilarityClient) SubmitCluster(result *core.FuzzResult) {
	go func() {
		if c == nil || c.client == nil || result == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()

		_, _ = c.client.ClusterResponse(ctx, &pb.ClusterRequest{
			Url:         result.Path,
			ResponseSha: result.ResponseSignature,
			ClusterId:   result.ClusterId,
		})
	}()
}
