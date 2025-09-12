package cluster

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
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

type StealthVault struct {
	db          *sql.DB
	aead        cipher.AEAD
	redis       *redis.Client
	cache       *sync.Map
	shredder    chan []byte
	key         [32]byte
	clusterNode string
	retention   time.Duration
}

type VaultConfig struct {
	RedisAddr      string
	RedisPassword  string
	SQLitePath     string 
	ClusterID      string
	AutoShredAfter time.Duration
	KeyRotation    time.Duration
}

func NewStealthVault(cfg VaultConfig) (*StealthVault, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(key[:])
	aead, _ := cipher.NewGCM(block)
	db, err := sql.Open("sqlite3", cfg.SQLitePath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}

	vault := &StealthVault{
		db:          db,
		aead:        aead,
		redis:       redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword}),
		cache:       &sync.Map{},
		shredder:    make(chan []byte, 1000),
		key:         key,
		clusterNode: cfg.ClusterID,
		retention:   cfg.AutoShredAfter,
	}

	if err := vault.initSchema(); err != nil {
		return nil, err
	}

	go vault.activateDarkProtocols(cfg.AutoShredAfter, cfg.KeyRotation)
	return vault, nil
}

func (v *StealthVault) initSchema() error {
	_, err := v.db.Exec(`
		CREATE TABLE IF NOT EXISTS findings (
			uuid TEXT PRIMARY KEY,
			data BLOB NOT NULL,
			node TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	return err
}

func (v *StealthVault) StoreFinding(finding core.FuzzResult) error {
	v.cache.Store(cacheKeyForFinding(finding), finding)
	encrypted, err := v.encryptData(finding)
	if err != nil {
		return err
	}

	_, err = v.db.Exec(`
		INSERT INTO findings (uuid, data, node) 
		VALUES (?, ?, ?)
		ON CONFLICT DO UPDATE SET data=excluded.data`,
		uuid.New().String(),
		encrypted,
		v.clusterNode,
	)

	go v.shadowReplicate(context.Background(), finding)
	return err
}

func (v *StealthVault) shadowReplicate(ctx context.Context, finding core.FuzzResult) {
	if v.redis == nil {
		return
	}
	payload, _ := json.Marshal(finding)
	_ = v.redis.XAdd(ctx, &redis.XAddArgs{
		Stream: "darknet:" + v.clusterNode,
		Values: map[string]interface{}{
			"payload": hex.EncodeToString(payload),
			"nonce":   time.Now().UnixNano(),
		},
	}).Err()
}

func (v *StealthVault) activateDarkProtocols(autoShred, keyRotation time.Duration) {
	keyTicker := time.NewTicker(keyRotation)
	defer keyTicker.Stop()
	shredTicker := time.NewTicker(autoShred)
	defer shredTicker.Stop()

	for {
		select {
		case <-keyTicker.C:
			_ = v.rotateEncryptionKey()
		case <-shredTicker.C:
			_ = v.shredExpiredData()
		case data := <-v.shredder:
			v.secureShred(data)
		}
	}
}

func (v *StealthVault) rotateEncryptionKey() error {
	var newKey [32]byte
	if _, err := rand.Read(newKey[:]); err != nil {
		return err
	}
	block, _ := aes.NewCipher(newKey[:])
	newAEAD, _ := cipher.NewGCM(block)
	rows, err := v.db.Query(`SELECT uuid, data FROM findings`)
	if err != nil {
		return err
	}
	defer rows.Close()

	tx, err := v.db.Begin()
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			_ = tx.Rollback()
			return err
		}
		pt, err := v.decryptRaw(blob)
		if err != nil {
			_ = tx.Rollback()
			return err
		}

		nonce := make([]byte, newAEAD.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			_ = tx.Rollback()
			return err
		}
		ct := newAEAD.Seal(nonce, nonce, pt, nil)
		if _, err := tx.Exec(`UPDATE findings SET data=? WHERE uuid=?`, ct, id); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	v.key = newKey
	v.aead = newAEAD
	return nil
}

func (v *StealthVault) secureShred(data []byte) {
	for i := range data {
		data[i] = 0x00
	}
	for i := range data {
		data[i] = 0xFF
	}
	for i := range data {
		data[i] = 0x00
	}
}

func (v *StealthVault) encryptData(data interface{}) ([]byte, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	raw, _ := json.Marshal(data)
	return v.aead.Seal(nonce, nonce, raw, nil), nil
}

func (v *StealthVault) decryptData(ciphertext []byte, result interface{}) error {
	nonceSize := v.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := v.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, result)
}

func (v *StealthVault) decryptRaw(ciphertext []byte) ([]byte, error) {
	nonceSize := v.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return v.aead.Open(nil, nonce, ciphertext, nil)
}

func (v *StealthVault) shredExpiredData() error {
	if v.retention <= 0 {
		return nil
	}
	cutoff := time.Now().Add(-v.retention).Format("2006-01-02 15:04:05")
	_, err := v.db.Exec(`DELETE FROM findings WHERE timestamp < ?`, cutoff)
	return err
}

func cacheKeyForFinding(fr core.FuzzResult) string {
	type keyish struct{ Path, Source string }
	k := keyish{}
	b, _ := json.Marshal(fr)
	s := string(b)
	if i := strings.Index(s, `"Path":"`); i >= 0 {
		j := i + len(`"Path":"`)
		if kEnd := strings.Index(s[j:], `"`); kEnd > 0 {
			k.Path = s[j : j+kEnd]
		}
	}
	if i := strings.Index(s, `"Source":"`); i >= 0 {
		j := i + len(`"Source":"`)
		if kEnd := strings.Index(s[j:], `"`); kEnd > 0 {
			k.Source = s[j : j+kEnd]
		}
	}
	joined := k.Path + "|" + k.Source
	if joined == "|" {
		if len(s) > 80 {
			return s[:80]
		}
		return s
	}
	return joined
}

func (v *StealthVault) Close() error {
	if v.redis != nil {
		_ = v.redis.Close()
	}
	return v.db.Close()
}
