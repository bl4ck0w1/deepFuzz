package discovery

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/hex"
	"io"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
	"github.com/bl4ck0w1/deepFuzz/internal/ai"
	"github.com/bl4ck0w1/deepFuzz/internal/evasion"
)

type WordlistManager struct {
	mu            sync.Mutex
	predictor     *PathPredictor
	crypto        *evasion.CryptoSystem
	torTransport  *evasion.TorTransport
	mutator       *evasion.MutationEngine
	lastUpdated   time.Time
	strategic     []string
	tactical      []string
	aiClient      *ai.PathPredictorClient
	publicKey     ed25519.PublicKey
	updateSources []string
}

func NewWordlistManager() *WordlistManager {
	var key [32]byte
	_, _ = crand.Read(key[:])
	return NewWordlistManagerWithAI("", key)
}

func NewWordlistManagerWithAI(aiAddr string, cryptoKey [32]byte) *WordlistManager {
	cs := evasion.NewCryptoSystem(cryptoKey)
	return NewWordlistManagerWithKeys(aiAddr, cryptoKey, cs.PublicKey)
}

func NewWordlistManagerWithKeys(aiAddr string, cryptoKey [32]byte, pubKey ed25519.PublicKey) *WordlistManager {
	wm := &WordlistManager{
		predictor:    NewPathPredictor(),
		crypto:       evasion.NewCryptoSystem(cryptoKey),
		torTransport: evasion.NewTorTransport(),
		mutator:      evasion.NewMutationEngine(),
		publicKey:    pubKey,
		updateSources: []string{
			"http://darkzzurls2vath5.onion/deepfuzz/v1/strategic.bin",
			"http://darkzzurls2vath5.onion/deepfuzz/v1/tactical.bin",
		},
	}
	if wm.publicKey == nil || len(wm.publicKey) == 0 {
		wm.publicKey = wm.crypto.PublicKey
	}
	wm.LoadWordlists()
	if aiAddr != "" {
		wm.aiClient = ai.NewPathPredictorClient(aiAddr)
	}
	go wm.autoUpdate()
	return wm
}

func (wm *WordlistManager) LoadWordlists() {
	wm.LoadStrategicWordlists()
	wm.loadTacticalWordlists()
	wm.lastUpdated = time.Now()
}

func (wm *WordlistManager) LoadStrategicWordlists() {
	wm.strategic = []string{}

	strategicFiles := []string{
		"wordlists/strategic/api_paths.bin",
		"wordlists/strategic/cloud_leaks.bin",
		"wordlists/strategic/framework_specific/graphql.bin",
	}

	for _, file := range strategicFiles {
		if paths, valid := wm.loadAndVerifyWordlist(file); valid {
			wm.strategic = append(wm.strategic, paths...)
		}
	}
}

func (wm *WordlistManager) loadTacticalWordlists() {
	wm.tactical = []string{}

	tacticalFiles := []string{
		"wordlists/tactical/quick.bin",
		"wordlists/tactical/nuclear.bin",
	}

	for _, file := range tacticalFiles {
		if paths, valid := wm.loadAndVerifyWordlist(file); valid {
			wm.tactical = append(wm.tactical, paths...)
		}
	}
}

func (wm *WordlistManager) loadAndVerifyWordlist(path string) ([]string, bool) {
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return []string{}, false
	}

	if !wm.verifyIntegrity(encrypted) {
		return []string{}, false
	}

	decrypted, err := wm.crypto.Decrypt(encrypted)
	if err != nil {
		return []string{}, false
	}

	return strings.Split(string(decrypted), "\n"), true
}

func (wm *WordlistManager) verifyIntegrity(encrypted []byte) bool {
	if len(encrypted) < ed25519.SignatureSize {
		return false
	}

	signature := encrypted[len(encrypted)-ed25519.SignatureSize:]
	data := encrypted[:len(encrypted)-ed25519.SignatureSize]
	return ed25519.Verify(wm.publicKey, data, signature)
}

func (wm *WordlistManager) autoUpdate() {
	time.Sleep(time.Duration(secureRandomInt(300)) * time.Second)
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		wm.updateFromDarkWeb()
		wm.updateFromAI()
		wm.lastUpdated = time.Now()
	}
}

func (wm *WordlistManager) updateFromDarkWeb() {
	for _, source := range wm.updateSources {
		encryptedUpdate := wm.torTransport.Get(source)
		if encryptedUpdate == "" {
			continue
		}
		encrypted, err := hex.DecodeString(encryptedUpdate)
		if err != nil {
			continue
		}
		if !wm.verifyIntegrity(encrypted) {
			continue
		}
		decrypted, err := wm.crypto.Decrypt(encrypted)
		if err != nil {
			continue
		}

		newPaths := strings.Split(string(decrypted), "\n")
		wm.mu.Lock()
		if strings.Contains(source, "strategic") {
			wm.strategic = wm.mergeUnique(wm.strategic, newPaths)
		} else {
			wm.tactical = wm.mergeUnique(wm.tactical, newPaths)
		}
		wm.mu.Unlock()
	}
	wm.SaveWordlists()
}

func (wm *WordlistManager) updateFromAI() {
	if wm.aiClient == nil {
		return
	}

	aiPaths := wm.aiClient.PredictNuclearPaths(500)
	wm.mu.Lock()
	wm.tactical = wm.mergeUnique(wm.tactical, aiPaths)
	wm.mu.Unlock()

	wm.SaveWordlists()
}

func (wm *WordlistManager) SaveWordlists() {
	wm.saveWordlist("wordlists/strategic/api_paths.bin", wm.filterCategory(wm.strategic, "api"))
	wm.saveWordlist("wordlists/strategic/cloud_leaks.bin", wm.filterCategory(wm.strategic, "cloud"))
	wm.saveWordlist("wordlists/strategic/framework_specific/graphql.bin", wm.filterCategory(wm.strategic, "graphql"))
	wm.saveWordlist("wordlists/tactical/quick.bin", wm.filterCategory(wm.tactical, "quick"))
	wm.saveWordlist("wordlists/tactical/nuclear.bin", wm.filterCategory(wm.tactical, "nuclear"))
}

func (wm *WordlistManager) saveWordlist(path string, paths []string) {
	content := strings.Join(paths, "\n")
	data := []byte(content)
	encrypted := wm.crypto.Encrypt(data)
	signature := ed25519.Sign(wm.crypto.PrivateKey, encrypted)
	signedEncrypted := append(encrypted, signature...)

	_ = os.WriteFile(path, signedEncrypted, 0600)
}

func (wm *WordlistManager) GenerateTargets(domain string, count int) []string {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	var targets []string

	targets = append(targets, wm.tactical...)

	if wm.aiClient != nil {
		aiPaths := wm.aiClient.Predict(domain, count/2)
		targets = append(targets, aiPaths...)
	}

	targets = append(targets, wm.strategic...)

	mutated := wm.applyEvasion(targets)

	uniq := wm.deduplicateAndShuffle(mutated)
	if count > len(uniq) {
		count = len(uniq)
	}
	return uniq[:count]
}

func (wm *WordlistManager) applyEvasion(paths []string) []string {
	var result []string
	for _, path := range paths {
		result = append(result, wm.mutator.MutatePath(path))
		result = append(result, wm.mutator.MutatePath(path))
		result = append(result, wm.mutator.MutatePath(path))
	}
	return result
}

func (wm *WordlistManager) mergeUnique(a, b []string) []string {
	set := make(map[string]struct{})
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		if _, exists := set[s]; !exists {
			a = append(a, s)
		}
	}
	return a
}

func (wm *WordlistManager) deduplicateAndShuffle(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, item := range slice {
		if _, value := keys[item]; !value {
			keys[item] = true
			list = append(list, item)
		}
	}

	seed := int64(binarySeed())
	r := rand.New(rand.NewSource(seed))
	r.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })
	return list
}

func (wm *WordlistManager) filterCategory(paths []string, category string) []string {
	var result []string
	for _, path := range paths {
		switch category {
		case "api":
			if strings.Contains(path, "/api") || strings.Contains(path, "/v1") || strings.Contains(path, "/rest") {
				result = append(result, path)
			}
		case "cloud":
			if strings.Contains(path, ".aws") || strings.Contains(path, "gcp") ||
				strings.Contains(path, "azure") || strings.Contains(path, "secret") {
				result = append(result, path)
			}
		case "graphql":
			if strings.Contains(path, "graphql") || strings.Contains(path, "gql") {
				result = append(result, path)
			}
		case "quick":
			if !strings.Contains(path, "%") && !strings.Contains(path, "\\") && len(path) < 30 {
				result = append(result, path)
			}
		case "nuclear":
			if strings.Contains(path, "%") || strings.Contains(path, "\\") || strings.Contains(path, "..") {
				result = append(result, path)
			}
		}
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (wm *WordlistManager) EncryptPlaintextWordlists() error {
	files := map[string]string{
		"wordlists/strategic/api_paths.txt":                  "wordlists/strategic/api_paths.bin",
		"wordlists/strategic/cloud_leaks.txt":                "wordlists/strategic/cloud_leaks.bin",
		"wordlists/strategic/framework_specific/graphql.txt": "wordlists/strategic/framework_specific/graphql.bin",
		"wordlists/tactical/quick.txt":                       "wordlists/tactical/quick.bin",
		"wordlists/tactical/nuclear.txt":                     "wordlists/tactical/nuclear.bin",
	}

	for plainPath, encryptedPath := range files {
		plaintext, err := os.ReadFile(plainPath)
		if err != nil {
			return err
		}
		encrypted := wm.crypto.Encrypt(plaintext)
		signature := ed25519.Sign(wm.crypto.PrivateKey, encrypted)
		signedEncrypted := append(encrypted, signature...)

		if err := os.WriteFile(encryptedPath, signedEncrypted, 0600); err != nil {
			return err
		}

		wm.secureShredFile(plainPath)
	}

	return nil
}

func (wm *WordlistManager) secureShredFile(path string) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer file.Close()

	for i := 0; i < 7; i++ {
		_, _ = file.Seek(0, 0)
		_, _ = io.CopyN(file, crand.Reader, 1024)
		_ = file.Sync()
	}
	_ = os.Remove(path)
}

func secureRandomInt(max int) int {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	_, _ = crand.Read(b[:])
	seed := int(b[0])<<8 | int(b[1])
	return seed % max
}
func binarySeed() uint64 {
	var b [8]byte
	_, _ = crand.Read(b[:])
	return (uint64(b[0]) << 56) | (uint64(b[1]) << 48) | (uint64(b[2]) << 40) | (uint64(b[3]) << 32) |
		(uint64(b[4]) << 24) | (uint64(b[5]) << 16) | (uint64(b[6]) << 8) | uint64(b[7])
}
