package cluster

import (
	"context"
	mrand "math/rand"
	"time"
	"github.com/bl4ck0w1/deepFuzz/internal/core"
	"github.com/go-redis/redis/v8"
)

func (df *DarkFleetCoordinator) StartWorker(ctx context.Context, processor core.TaskProcessor) {
	go df.maintainDarkPresence(ctx)

	pubsub := df.redis.Subscribe(ctx, df.stealthChannel)
	defer pubsub.Close()
	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			if msg == nil || msg.Payload == "" {
				continue
			}
			task, err := df.decryptTask(msg.Payload)
			if err != nil {
				_ = df.buryTaskRaw(ctx, msg.Payload)
				continue
			}
			time.Sleep(time.Duration(50+mrand.Intn(200)) * time.Millisecond)

			if err := processor.Process(task); err != nil {
				df.resurrectTask(task, err)
			}
			df.UpdateClusterLoad(ctx, -1)
		}
	}
}

func (df *DarkFleetCoordinator) UpdateClusterLoad(ctx context.Context, delta int64) {
	if df.redis == nil {
		return
	}
	_ = df.redis.ZIncrBy(ctx, "cluster_load", float64(delta), df.clusterID).Err()
}

func (df *DarkFleetCoordinator) buryTaskRaw(ctx context.Context, payload string) error {
	if df.redis == nil {
		return nil
	}
	key := "graveyard:" + df.clusterID
	return df.redis.LPush(ctx, key, payload).Err()
}
