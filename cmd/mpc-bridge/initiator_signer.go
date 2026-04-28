package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/encryption"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/zalando/go-keyring"
)

type bridgeInMemorySigner struct {
	algorithm  types.EventInitiatorKeyType
	ed25519Key ed25519.PrivateKey
	p256Key    *ecdsa.PrivateKey
}

func newBridgeSigner(algorithm string) (client.Signer, error) {
	keyType := types.EventInitiatorKeyType(algorithm)
	if keyType != types.EventInitiatorKeyTypeEd25519 && keyType != types.EventInitiatorKeyTypeP256 {
		return nil, errors.New("event_initiator_algorithm must be ed25519 or p256")
	}
	if keyMaterial, ok := loadEventInitiatorKeyMaterial(); ok {
		return newBridgeInMemorySigner(keyType, keyMaterial)
	}
	keyPath := strings.TrimSpace(os.Getenv("MPC_BRIDGE_EVENT_INITIATOR_KEY_PATH"))
	if keyPath == "" {
		keyPath = "./event_initiator.key"
	}
	return client.NewLocalSigner(keyType, client.LocalSignerOptions{KeyPath: keyPath})
}

func loadEventInitiatorKeyMaterial() ([]byte, bool) {
	if v := strings.TrimSpace(os.Getenv("MPC_BRIDGE_EVENT_INITIATOR_KEY")); v != "" {
		return []byte(v), true
	}
	service := strings.TrimSpace(os.Getenv("MPC_BRIDGE_KEYRING_SERVICE"))
	if service == "" {
		service = "mpc-bridge"
	}
	user := strings.TrimSpace(os.Getenv("MPC_BRIDGE_KEYRING_USER"))
	if user == "" {
		user = "event_initiator_key"
	}
	v, err := keyring.Get(service, user)
	if err != nil || strings.TrimSpace(v) == "" {
		return nil, false
	}
	return []byte(v), true
}

func newBridgeInMemorySigner(keyType types.EventInitiatorKeyType, keyMaterial []byte) (client.Signer, error) {
	keyText := strings.TrimSpace(string(keyMaterial))
	switch keyType {
	case types.EventInitiatorKeyTypeEd25519:
		seed, err := hex.DecodeString(strings.TrimPrefix(keyText, "0x"))
		if err != nil {
			return nil, fmt.Errorf("decode ed25519 seed: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid ed25519 seed length: %d", len(seed))
		}
		return &bridgeInMemorySigner{
			algorithm:  keyType,
			ed25519Key: ed25519.NewKeyFromSeed(seed),
		}, nil
	case types.EventInitiatorKeyTypeP256:
		pk, err := encryption.ParseP256PrivateKey([]byte(keyText))
		if err != nil {
			return nil, fmt.Errorf("parse p256 private key: %w", err)
		}
		return &bridgeInMemorySigner{algorithm: keyType, p256Key: pk}, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

func (s *bridgeInMemorySigner) Sign(data []byte) ([]byte, error) {
	switch s.algorithm {
	case types.EventInitiatorKeyTypeEd25519:
		return ed25519.Sign(s.ed25519Key, data), nil
	case types.EventInitiatorKeyTypeP256:
		return encryption.SignWithP256(s.p256Key, data)
	default:
		return nil, errors.New("unsupported key type")
	}
}

func (s *bridgeInMemorySigner) Algorithm() types.EventInitiatorKeyType {
	return s.algorithm
}

func (s *bridgeInMemorySigner) PublicKey() (string, error) {
	switch s.algorithm {
	case types.EventInitiatorKeyTypeEd25519:
		return hex.EncodeToString(s.ed25519Key.Public().(ed25519.PublicKey)), nil
	case types.EventInitiatorKeyTypeP256:
		pubBytes, err := encryption.MarshalP256PublicKey(&s.p256Key.PublicKey)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(pubBytes), nil
	default:
		return "", errors.New("unsupported key type")
	}
}
