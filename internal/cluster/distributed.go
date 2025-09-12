package cluster

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/bl4ck0w1/deepFuzz/internal/core"
	"github.com/go-redis/redis/v8"
	_ "github.com/mattn/go-sqlite3"
	"github.com/google/uuid"
)

type DarkFleetCoordinator struct {
	redis          *redis.Client
	db             *sql.DB
	aead           cipher.AEAD
	clusterID      string
	stealthChannel string
	shredder       chan []byte
	key            [32]byte
	mu             sync.Mutex

	taskChan  chan core.FuzzTask
	retention time.Duration
}

type DarkStoreConfig struct {
	RedisAddr      string
	RedisPassword  string
	SQLitePath     string
	AutoShredAfter time.Duration
	KeyRotation    time.Duration
}

func NewDarkFleetCoordinator(cfg DarkStoreConfig) (*DarkFleetCoordinator, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(key[:])
	aead, _ := cipher.NewGCM(block)

	redisClient := redis.NewClient(&redis.Options{
		Addr:         cfg.RedisAddr,
		Password:     cfg.RedisPassword,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		PoolSize:     1000,
		PoolTimeout:  30 * time.Second,
		IdleTimeout:  5 * time.Minute,
		MaxConnAge:   10 * time.Minute,
	})

	db, err := sql.Open("sqlite3", cfg.SQLitePath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS findings (
			uuid TEXT PRIMARY KEY,
			data BLOB,
			node TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS anomalies (
			id TEXT PRIMARY KEY,
			data BLOB,
			node TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return nil, err
	}

	coordinator := &DarkFleetCoordinator{
		redis:          redisClient,
		db:             db,
		aead:           aead,
		clusterID:      generateClusterID(),
		stealthChannel: generatePolymorphicChannel(),
		shredder:       make(chan []byte, 1000),
		key:            key,
		taskChan:       make(chan core.FuzzTask, 1024),
		retention:      cfg.AutoShredAfter,
	}

	go coordinator.activateDarkProtocols(cfg)
	go coordinator.maintainDarkPresence(context.Background())
	go coordinator.taskPump(context.Background())

	return coordinator, nil
}

func (df *DarkFleetCoordinator) DistributeTask(task core.FuzzTask) error {
	encrypted, err := df.encryptTask(task)
	if err != nil {
		return err
	}
	ctx := context.Background()
	return df.redis.Publish(ctx, df.stealthChannel, encrypted).Err()
}

func (df *DarkFleetCoordinator) ReceiveTasks() <-chan core.FuzzTask { return df.taskChan }

func (df *DarkFleetCoordinator) StoreFinding(finding core.FuzzResult) error {
	encrypted, err := df.encryptData(finding)
	if err != nil {
		return err
	}
	_, err = df.db.Exec(`
		INSERT INTO findings (uuid, data, node) 
		VALUES (?, ?, ?)
		ON CONFLICT DO UPDATE SET data=excluded.data`,
		generateUUID(),
		encrypted,
		df.clusterID,
	)
	return err
}

func (df *DarkFleetCoordinator) ReportAnomaly(a core.TimingAnomaly) error {
	encrypted, err := df.encryptData(a)
	if err != nil {
		return err
	}
	_, err = df.db.Exec(`
		INSERT INTO anomalies (id, data, node)
		VALUES (?, ?, ?)
		ON CONFLICT DO UPDATE SET data=excluded.data`,
		generateUUID(), encrypted, df.clusterID,
	)
	return err
}

func (df *DarkFleetCoordinator) activateDarkProtocols(cfg DarkStoreConfig) {
	keyTicker := time.NewTicker(cfg.KeyRotation)
	shredTicker := time.NewTicker(cfg.AutoShredAfter)

	for {
		select {
		case <-keyTicker.C:
			df.rotateEncryptionKey()
		case <-shredTicker.C:
			df.shredExpiredData()
		case data := <-df.shredder:
			df.secureShred(data)
		}
	}
}

func (df *DarkFleetCoordinator) maintainDarkPresence(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		df.redis.ZAdd(ctx, "active_nodes", &redis.Z{
			Score:  float64(time.Now().Unix()),
			Member: df.clusterID,
		})
	}
}

func (df *DarkFleetCoordinator) taskPump(ctx context.Context) {
	pubsub := df.redis.Subscribe(ctx, df.stealthChannel)
	defer pubsub.Close()
	ch := pubsub.Channel()
	for {
		select {
		case msg := <-ch:
			if msg == nil {
				continue
			}
			task, err := df.decryptTask(msg.Payload)
			if err != nil {
				continue
			}
			select {
			case df.taskChan <- task:
			default:
				select {
				case <-df.taskChan:
				default:
				}
				df.taskChan <- task
			}
		case <-ctx.Done():
			return
		}
	}
}

func (df *DarkFleetCoordinator) encryptTask(task core.FuzzTask) (string, error) {
	nonce := make([]byte, df.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	data, _ := json.Marshal(task)
	encrypted := df.aead.Seal(nil, nonce, data, nil)
	return fmt.Sprintf("%x|%x", nonce, encrypted), nil
}

func (df *DarkFleetCoordinator) decryptTask(payload string) (core.FuzzTask, error) {
	var task core.FuzzTask
	parts := strings.Split(payload, "|")
	if len(parts) != 2 {
		return task, fmt.Errorf("invalid payload")
	}

	nonce, _ := hex.DecodeString(parts[0])
	ciphertext, _ := hex.DecodeString(parts[1])

	data, err := df.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return task, err
	}

	err = json.Unmarshal(data, &task)
	return task, err
}

func (df *DarkFleetCoordinator) encryptData(data interface{}) ([]byte, error) {
	nonce := make([]byte, df.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	raw, _ := json.Marshal(data)
	return df.aead.Seal(nonce, nonce, raw, nil), nil
}

func generatePolymorphicChannel() string {
	return fmt.Sprintf("chan-%s-%d", generateUUID(), time.Now().UnixNano())
}

func generateClusterID() string {
	return fmt.Sprintf("node-%s", generateUUID()[:8])
}

func generateUUID() string {
	return uuid.New().String()
}

func (df *DarkFleetCoordinator) rotateEncryptionKey() {
	var newKey [32]byte
	_, _ = rand.Read(newKey[:])
	df.mu.Lock()
	defer df.mu.Unlock()
	df.key = newKey
	block, _ := aes.NewCipher(df.key[:])
	df.aead, _ = cipher.NewGCM(block)
}

func (df *DarkFleetCoordinator) shredExpiredData() {
	if df.retention <= 0 {
		return
	}
	cutoff := time.Now().Add(-df.retention).Format("2006-01-02 15:04:05")
	_, _ = df.db.Exec(`DELETE FROM findings WHERE timestamp < ?`, cutoff)
	_, _ = df.db.Exec(`DELETE FROM anomalies WHERE timestamp < ?`, cutoff)
}

func (df *DarkFleetCoordinator) secureShred(data []byte) {
	df.mu.Lock()
	for i := range data {
		data[i] = 0
	}
	df.mu.Unlock()
}

func (df *DarkFleetCoordinator) resurrectTask(task core.FuzzTask, err error) {
	script := redis.NewScript(`
		local task = ARGV[1]
		local retries = tonumber(ARGV[2])
		if retries < 3 then
			redis.call('LPUSH', 'zombie_q', task)
			redis.call('HINCRBY', 'task_errors', ARGV[3], 1)
		else
			redis.call('LPUSH', 'graveyard', task)
		end
	`)

	ctx := context.Background()
	localTask, _ := json.Marshal(task)
	_, _ = script.Run(ctx, df.redis, nil, string(localTask), task.Retries+1, err.Error()).Result()
}

func (df *DarkFleetCoordinator) Close() error {
	_ = df.redis.Close()
	return df.db.Close()
}
