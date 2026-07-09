package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/fystack/mpcium/pkg/encryption"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/spf13/viper"
)

const (
	defaultPredictAPIBase       = "https://predict-api-544f.onrender.com"
	defaultSecretDBPath         = "./bridge-secrets-db"
	secretKeyPrefix             = "predict_api_key:"
	walletMappingPrefix         = "ai_pk_to_wallet_id:"
	walletReverseMappingPrefix  = "wallet_id_to_ai_pk:"
	headerEventSig              = "X-Event-Initiator-Signature"
	headerEventTimestamp        = "X-Event-Initiator-Timestamp"
	requestSkewSecondsTolerance = int64(300)
)

var (
	httpClient  = &http.Client{Timeout: 30 * time.Second}
	walletIDRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)
	allowMethod = map[string]bool{
		http.MethodGet:    true,
		http.MethodPost:   true,
		http.MethodPatch:  true,
		http.MethodDelete: true,
		http.MethodPut:    true,
	}
	bridgeState struct {
		secretDB   *badger.DB
		predictAPI string
	}
)

type storeSecretRequest struct {
	MPCWalletID string `json:"mpc_wallet_id"`
	APIKey      string `json:"api_key"`
}

type proxyPredictRequest struct {
	MPCWalletID   string          `json:"mpc_wallet_id"`
	AIAgentPubkey string          `json:"ai_agent_pubkey,omitempty"`
	Method        string          `json:"method"`
	Path          string          `json:"path"`
	Query         string          `json:"query,omitempty"`
	Body          json.RawMessage `json:"body,omitempty"`
}

func initBridgeSecretStore() error {
	rawSecret := strings.TrimSpace(os.Getenv("MPC_BRIDGE_SECRET_KEY"))
	if rawSecret == "" {
		rawSecret = strings.TrimSpace(viper.GetString("badger_password"))
	}
	if rawSecret == "" {
		return errors.New("missing MPC_BRIDGE_SECRET_KEY or badger_password")
	}
	path := strings.TrimSpace(os.Getenv("MPC_BRIDGE_SECRET_DB_PATH"))
	if path == "" {
		path = defaultSecretDBPath
	}
	encKey := sha256.Sum256([]byte(rawSecret))
	opts := badger.DefaultOptions(path).
		WithEncryptionKey(encKey[:]).
		WithIndexCacheSize(64 << 20).
		WithSyncWrites(true)
	db, err := badger.Open(opts)
	if err != nil {
		return fmt.Errorf("open bridge secret db: %w", err)
	}
	bridgeState.secretDB = db
	bridgeState.predictAPI = strings.TrimRight(
		firstNonEmpty(os.Getenv("PREDICT_API_BASE"), defaultPredictAPIBase),
		"/",
	)
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func closeBridgeSecretStore() {
	if bridgeState.secretDB != nil {
		_ = bridgeState.secretDB.Close()
	}
}

func secretDBKey(walletID string) []byte {
	return []byte(secretKeyPrefix + walletID)
}

func putPredictAPIKey(walletID, apiKey string) error {
	if bridgeState.secretDB == nil {
		return errors.New("secret db is not initialized")
	}
	return bridgeState.secretDB.Update(func(txn *badger.Txn) error {
		return txn.Set(secretDBKey(walletID), []byte(apiKey))
	})
}

func getPredictAPIKey(walletID string) (string, error) {
	if bridgeState.secretDB == nil {
		return "", errors.New("secret db is not initialized")
	}
	var out []byte
	err := bridgeState.secretDB.View(func(txn *badger.Txn) error {
		item, err := txn.Get(secretDBKey(walletID))
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			out = append([]byte{}, v...)
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// walletMappingKey returns the DB key for AI PK -> wallet ID mapping
func walletMappingKey(aiPubkeyB58 string) []byte {
	return []byte(walletMappingPrefix + aiPubkeyB58)
}

// putAIPKToWalletID stores the bidirectional mapping between AI agent pubkey and MPC wallet ID
func putAIPKToWalletID(aiPubkeyB58, walletID string) error {
	if bridgeState.secretDB == nil {
		return errors.New("secret db is not initialized")
	}
	return bridgeState.secretDB.Update(func(txn *badger.Txn) error {
		if err := txn.Set(walletMappingKey(aiPubkeyB58), []byte(walletID)); err != nil {
			return err
		}
		return txn.Set(walletReverseMappingKey(walletID), []byte(aiPubkeyB58))
	})
}

func walletReverseMappingKey(walletID string) []byte {
	return []byte(walletReverseMappingPrefix + walletID)
}

// getAIPKByWalletID retrieves the AI agent pubkey for a given MPC wallet ID
func getAIPKByWalletID(walletID string) (string, error) {
	if bridgeState.secretDB == nil {
		return "", errors.New("secret db is not initialized")
	}
	var out []byte
	err := bridgeState.secretDB.View(func(txn *badger.Txn) error {
		item, err := txn.Get(walletReverseMappingKey(walletID))
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			out = append([]byte{}, v...)
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// getWalletIDByAIPK retrieves the MPC wallet ID for a given AI agent pubkey
func getWalletIDByAIPK(aiPubkeyB58 string) (string, error) {
	if bridgeState.secretDB == nil {
		return "", errors.New("secret db is not initialized")
	}
	var out []byte
	err := bridgeState.secretDB.View(func(txn *badger.Txn) error {
		item, err := txn.Get(walletMappingKey(aiPubkeyB58))
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			out = append([]byte{}, v...)
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Security limit:
// Event-initiator key is the root credential. If compromised, attacker can operate
// bridge features including secret-backed proxy calls.
func verifyEventInitiatorSignature(r *http.Request, body []byte) error {
	pubHex := strings.TrimSpace(viper.GetString("event_initiator_pubkey"))
	if pubHex == "" {
		return errors.New("event_initiator_pubkey missing in config")
	}
	algorithm := strings.TrimSpace(viper.GetString("event_initiator_algorithm"))
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}
	ts := strings.TrimSpace(r.Header.Get(headerEventTimestamp))
	sigRaw := strings.TrimSpace(r.Header.Get(headerEventSig))
	if ts == "" || sigRaw == "" {
		return fmt.Errorf("%s and %s required", headerEventTimestamp, headerEventSig)
	}
	tsUnix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("invalid event timestamp")
	}
	now := time.Now().Unix()
	if abs64(now-tsUnix) > requestSkewSecondsTolerance {
		return errors.New("event signature timestamp out of allowed window")
	}
	signature, err := decodeMaybeHexOrB64(sigRaw)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	bodyHash := sha256.Sum256(body)
	signPayload := fmt.Sprintf("%s\n%s\n%s\n%x", ts, r.Method, r.URL.Path, bodyHash[:])

	switch algorithm {
	case string(types.EventInitiatorKeyTypeEd25519):
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return errors.New("bad event_initiator_pubkey for ed25519")
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), []byte(signPayload), signature) {
			return errors.New("event signature verify failed")
		}
		return nil
	case string(types.EventInitiatorKeyTypeP256):
		pubBytes, err := hex.DecodeString(pubHex)
		if err != nil {
			return errors.New("bad event_initiator_pubkey hex for p256")
		}
		pub, err := encryption.ParseP256PublicKeyFromBytes(pubBytes)
		if err != nil {
			return fmt.Errorf("parse p256 pubkey: %w", err)
		}
		if err := encryption.VerifyP256Signature(pub, []byte(signPayload), signature); err != nil {
			return errors.New("event signature verify failed")
		}
		return nil
	default:
		return errors.New("event_initiator_algorithm must be ed25519 or p256")
	}
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func decodeMaybeHexOrB64(raw string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
		return b, nil
	}
	return hex.DecodeString(raw)
}

func readAndVerifySignedBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return nil, false
	}
	// Local-only bypass: keep legacy OpenClaw flow working on same host.
	if isLoopbackRequest(r) {
		return body, true
	}
	if err := verifyEventInitiatorSignature(r, body); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}

func isLoopbackRequest(r *http.Request) bool {
	host := strings.TrimSpace(r.RemoteAddr)
	if host == "" {
		return false
	}
	// RemoteAddr is usually "ip:port"
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func handleStoreSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	rawBody, ok := readAndVerifySignedBody(w, r)
	if !ok {
		return
	}
	var body storeSecretRequest
	if err := json.Unmarshal(rawBody, &body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	body.MPCWalletID = strings.TrimSpace(body.MPCWalletID)
	body.APIKey = strings.TrimSpace(body.APIKey)
	if body.MPCWalletID == "" || !walletIDRe.MatchString(body.MPCWalletID) {
		http.Error(w, "invalid mpc_wallet_id", http.StatusBadRequest)
		return
	}
	if body.APIKey == "" {
		http.Error(w, "api_key required", http.StatusBadRequest)
		return
	}
	if err := putPredictAPIKey(body.MPCWalletID, body.APIKey); err != nil {
		http.Error(w, "failed to store secret", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"mpc_wallet_id": body.MPCWalletID,
		"stored":        true,
	})
}

func handleProxyPredict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	rawBody, ok := readAndVerifySignedBody(w, r)
	if !ok {
		return
	}
	var body proxyPredictRequest
	if err := json.Unmarshal(rawBody, &body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	body.MPCWalletID = strings.TrimSpace(body.MPCWalletID)
	body.Method = strings.ToUpper(strings.TrimSpace(body.Method))
	body.Path = strings.TrimSpace(body.Path)
	body.Query = strings.TrimSpace(body.Query)
	if body.MPCWalletID == "" || !walletIDRe.MatchString(body.MPCWalletID) {
		http.Error(w, "invalid mpc_wallet_id", http.StatusBadRequest)
		return
	}
	if !allowMethod[body.Method] {
		http.Error(w, "unsupported method", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(body.Path, "/api/v1/") {
		http.Error(w, "path must start with /api/v1/", http.StatusBadRequest)
		return
	}

	// AICW death check: resolve AI agent pubkey and verify wallet is alive
	aiPubkey := strings.TrimSpace(body.AIAgentPubkey)
	if aiPubkey == "" {
		resolved, err := getAIPKByWalletID(body.MPCWalletID)
		if err == nil && resolved != "" {
			aiPubkey = resolved
		}
	}
	if aiPubkey != "" {
		if err := checkAICWNotDead(r.Context(), aiPubkey); err != nil {
			http.Error(w, fmt.Sprintf("AICW wallet dead — proxy blocked: %v", err), http.StatusForbidden)
			return
		}
	}

	apiKey, err := getPredictAPIKey(body.MPCWalletID)
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			http.Error(w, "stored api key not found for mpc_wallet_id", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to read secret", http.StatusInternalServerError)
		return
	}

	targetURL := bridgeState.predictAPI + body.Path
	if body.Query != "" {
		targetURL += "?" + body.Query
	}
	var reqBody io.Reader
	if len(body.Body) > 0 && body.Method != http.MethodGet {
		reqBody = bytes.NewReader(body.Body)
	}
	req, err := http.NewRequestWithContext(r.Context(), body.Method, targetURL, reqBody)
	if err != nil {
		http.Error(w, "failed to build proxy request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if len(body.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "predict api request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read predict api response", http.StatusBadGateway)
		return
	}
	copyHeaderIfExists(w, resp.Header, "Content-Type")
	copyHeaderIfExists(w, resp.Header, "Cache-Control")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

func copyHeaderIfExists(w http.ResponseWriter, src http.Header, key string) {
	if v := src.Values(key); len(v) > 0 {
		w.Header()[key] = append([]string{}, v...)
	}
}
