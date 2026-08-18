package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/spf13/viper"
)

// bridgeAuthorizerSpec configures one authorizer the manual reshare endpoint
// must collect a signature from when the network enables
// identity.RequiredAuthorizers (auto_reshare_design.md §5.3D). It mirrors the
// orchestrator's authorizer config so operator-triggered reshares are not
// rejected once authorizers are turned on. ID must match a node's
// AuthorizerPublicKeys / RequiredAuthorizers entry.
type bridgeAuthorizerSpec struct {
	ID        string `mapstructure:"id"`
	Mode      string `mapstructure:"mode"` // local | remote (default local)
	KeyPath   string `mapstructure:"key_path"`
	Algorithm string `mapstructure:"algorithm"` // default ed25519
	URL       string `mapstructure:"url"`
	Token     string `mapstructure:"token"`
	TokenEnv  string `mapstructure:"token_env"`
}

// bridgeAuthorizer signs authorizer raw bytes with a local key or a remote HTTP
// signing service.
type bridgeAuthorizer struct {
	id      string
	signer  client.Signer // local mode
	url     string        // remote mode
	token   string
	http    *http.Client
	timeout time.Duration
}

func (b *bridgeAuthorizer) sign(ctx context.Context, raw []byte) ([]byte, error) {
	if b.signer != nil {
		return b.signer.Sign(raw)
	}
	return b.signRemote(ctx, raw)
}

func (b *bridgeAuthorizer) signRemote(ctx context.Context, raw []byte) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"authorizer_id": b.id,
		"raw":           base64.StdEncoding.EncodeToString(raw),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out struct {
		Signature string `json:"signature"`
		Error     string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return nil, fmt.Errorf("remote authorizer status %d: %s", resp.StatusCode, out.Error)
		}
		return nil, fmt.Errorf("remote authorizer status %d", resp.StatusCode)
	}
	return base64.StdEncoding.DecodeString(out.Signature)
}

// loadBridgeAuthorizers builds the authorizer set from bridge.authorizers.list.
// Returns nil when none configured (Phase 1 / authorizers disabled).
func loadBridgeAuthorizers() ([]*bridgeAuthorizer, error) {
	var specs []bridgeAuthorizerSpec
	if err := viper.UnmarshalKey("bridge.authorizers.list", &specs); err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return nil, nil
	}
	timeout := 10 * time.Second
	if v := viper.GetInt("bridge.authorizers.request_timeout_seconds"); v > 0 {
		timeout = time.Duration(v) * time.Second
	}

	out := make([]*bridgeAuthorizer, 0, len(specs))
	for _, spec := range specs {
		if spec.ID == "" {
			return nil, fmt.Errorf("bridge authorizer spec missing id")
		}
		token := spec.Token
		if token == "" && spec.TokenEnv != "" {
			token = os.Getenv(spec.TokenEnv)
		}
		switch spec.Mode {
		case "", "local":
			if spec.KeyPath == "" {
				return nil, fmt.Errorf("bridge authorizer %q: key_path required for local mode", spec.ID)
			}
			algorithm := spec.Algorithm
			if algorithm == "" {
				algorithm = string(types.EventInitiatorKeyTypeEd25519)
			}
			s, err := client.NewLocalSigner(types.EventInitiatorKeyType(algorithm), client.LocalSignerOptions{KeyPath: spec.KeyPath})
			if err != nil {
				return nil, fmt.Errorf("bridge authorizer %q: %w", spec.ID, err)
			}
			out = append(out, &bridgeAuthorizer{id: spec.ID, signer: s})
		case "remote":
			if spec.URL == "" {
				return nil, fmt.Errorf("bridge authorizer %q: url required for remote mode", spec.ID)
			}
			out = append(out, &bridgeAuthorizer{
				id:      spec.ID,
				url:     spec.URL,
				token:   token,
				http:    &http.Client{Timeout: timeout},
				timeout: timeout,
			})
		default:
			return nil, fmt.Errorf("bridge authorizer %q: unknown mode %q (want local|remote)", spec.ID, spec.Mode)
		}
	}
	return out, nil
}

// collectBridgeAuthorizerSignatures returns a collect callback for
// client.ResharingWithAuthorizers, or nil when no authorizers are configured.
func collectBridgeAuthorizerSignatures(ctx context.Context, authorizers []*bridgeAuthorizer) func([]byte) ([]types.AuthorizerSignature, error) {
	if len(authorizers) == 0 {
		return nil
	}
	return func(raw []byte) ([]types.AuthorizerSignature, error) {
		sigs := make([]types.AuthorizerSignature, 0, len(authorizers))
		for _, a := range authorizers {
			sig, err := a.sign(ctx, raw)
			if err != nil {
				return nil, fmt.Errorf("authorizer %q: %w", a.id, err)
			}
			if len(sig) == 0 {
				return nil, fmt.Errorf("authorizer %q returned empty signature", a.id)
			}
			sigs = append(sigs, types.AuthorizerSignature{AuthorizerID: a.id, Signature: sig})
		}
		return sigs, nil
	}
}
