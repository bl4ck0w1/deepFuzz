package evasion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"golang.org/x/crypto/hkdf"
)

const cryptoEnvelopeVersion = byte(0x01)

type CryptoSystem struct {
	key        [32]byte      
	aead       cipher.AEAD        
	PrivateKey ed25519.PrivateKey  
	PublicKey  ed25519.PublicKey
}

func NewCryptoSystem(master [32]byte) *CryptoSystem {
	kdf := hkdf.New(sha256.New, master[:], nil, []byte("deepfuzz-crypto-v1"))
	var aesKey [32]byte
	var edSeed [32]byte
	_, _ = io.ReadFull(kdf, aesKey[:])
	_, _ = io.ReadFull(kdf, edSeed[:])

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	priv := ed25519.NewKeyFromSeed(edSeed[:])
	pub := priv.Public().(ed25519.PublicKey)

	return &CryptoSystem{
		key:        master,
		aead:       aead,
		PrivateKey: priv,
		PublicKey:  pub,
	}
}

func (cs *CryptoSystem) Encrypt(plaintext []byte) []byte {
	out, _ := cs.EncryptWithAAD(plaintext, nil)
	return out
}

func (cs *CryptoSystem) EncryptWithAAD(plaintext, aad []byte) ([]byte, error) {
	if cs == nil || cs.aead == nil {
		return nil, errors.New("crypto system not initialized")
	}
	nonce := make([]byte, cs.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := cs.aead.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 1+len(nonce)+len(ct))
	out[0] = cryptoEnvelopeVersion
	copy(out[1:], nonce)
	copy(out[1+len(nonce):], ct)
	return out, nil
}

func (cs *CryptoSystem) Decrypt(ciphertext []byte) ([]byte, error) {
	return cs.DecryptWithAAD(ciphertext, nil)
}

func (cs *CryptoSystem) DecryptWithAAD(envelope, aad []byte) ([]byte, error) {
	if cs == nil || cs.aead == nil {
		return nil, errors.New("crypto system not initialized")
	}
	if len(envelope) < 1 {
		return nil, errors.New("ciphertext too short")
	}
	if envelope[0] != cryptoEnvelopeVersion {
		return nil, errors.New("unsupported crypto envelope version")
	}
	ns := cs.aead.NonceSize()
	if len(envelope) < 1+ns {
		return nil, errors.New("ciphertext missing nonce")
	}
	nonce := envelope[1 : 1+ns]
	ct := envelope[1+ns:]
	return cs.aead.Open(nil, nonce, ct, aad)
}

func (cs *CryptoSystem) Sign(msg []byte) []byte {
	return ed25519.Sign(cs.PrivateKey, msg)
}

func (cs *CryptoSystem) Verify(msg, sig []byte) bool {
	return ed25519.Verify(cs.PublicKey, msg, sig)
}
