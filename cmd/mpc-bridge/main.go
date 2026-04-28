// predict 대시보드용 HTTP 브리지: NATS + Mpcium 노드에 keygen 요청 → Ed25519 공개키 JSON 반환.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

const defaultListen = ":8081"

var clientIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

type pubkeyRequest struct {
	ClientID string `json:"clientId"`
}

func main() {
	listen := os.Getenv("MPC_BRIDGE_LISTEN")
	if listen == "" {
		listen = defaultListen
	}
	// 기본: 바이너리를 mpcium 루트에서 실행 (config.yaml, event_initiator.key)
	if d := os.Getenv("MPCIUM_DIR"); d != "" {
		if err := os.Chdir(d); err != nil {
			log.Fatalf("chdir MPCIUM_DIR: %v", err)
		}
	}
	if cfg := os.Getenv("MPCIUM_CONFIG"); cfg != "" {
		config.InitViperConfig(cfg)
	} else {
		config.InitViperConfig("")
	}
	logger.Init(viper.GetString("environment"), false)
	if err := initBridgeSecretStore(); err != nil {
		log.Fatalf("init bridge secret store: %v", err)
	}
	defer closeBridgeSecretStore()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "mpc-bridge"})
	})
	mux.HandleFunc("OPTIONS /v1/mpc/ai-agent-pubkey", withCORS(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	mux.HandleFunc("POST /v1/mpc/ai-agent-pubkey", withCORS(handleAIAgentPubkey))
	mux.HandleFunc("OPTIONS /v1/mpc/sign-solana-message", withCORS(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	mux.HandleFunc("POST /v1/mpc/sign-solana-message", withCORS(handleSignSolanaMessage))
	mux.HandleFunc("OPTIONS /v1/mpc/store-secret", withCORS(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	mux.HandleFunc("POST /v1/mpc/store-secret", withCORS(handleStoreSecret))
	mux.HandleFunc("OPTIONS /v1/mpc/proxy-predict", withCORS(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	mux.HandleFunc("POST /v1/mpc/proxy-predict", withCORS(handleProxyPredict))
	wd, _ := os.Getwd()
	log.Printf("MPC bridge %s (cwd=%s)", listen, wd)
	log.Fatal(http.ListenAndServe(listen, mux))
}

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := os.Getenv("MPC_BRIDGE_CORS"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Event-Initiator-Signature, X-Event-Initiator-Timestamp")
		w.Header().Set("Access-Control-Max-Age", "3600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		h(w, r)
	}
}

func validClientID(s string) bool { return len(s) <= 128 && clientIDRe.MatchString(s) }

func handleAIAgentPubkey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var body pubkeyRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if body.ClientID == "" {
		body.ClientID = "bridge-" + uuid.New().String()
	}
	if !validClientID(body.ClientID) {
		http.Error(w, "invalid clientId", 400)
		return
	}

	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}
	if !slices.Contains([]string{
		string(types.EventInitiatorKeyTypeEd25519),
		string(types.EventInitiatorKeyTypeP256),
	}, algorithm) {
		http.Error(w, "event_initiator_algorithm must be ed25519 or p256", 500)
		return
	}

	natsURL := viper.GetString("nats.url")
	if natsURL == "" {
		http.Error(w, "nats.url missing in config", 500)
		return
	}
	nc, err := nats.Connect(natsURL, nats.Name("predict-mpc-bridge"), nats.Timeout(8*time.Second), nats.MaxReconnects(2))
	if err != nil {
		http.Error(w, fmt.Sprintf("NATS: %v", err), 502)
		return
	}
	defer func() { _ = nc.Drain() }()
	defer nc.Close()

	signer, err := newBridgeSigner(algorithm)
	if err != nil {
		http.Error(w, fmt.Sprintf("signer: %v", err), 500)
		return
	}
	mpcCl := client.NewMPCClient(client.Options{NatsConn: nc, Signer: signer, ClientID: body.ClientID})
	walletID := uuid.New().String()
	resCh := make(chan event.KeygenResultEvent, 1)
	if err := mpcCl.OnWalletCreationResult(func(e event.KeygenResultEvent) { resCh <- e }); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := mpcCl.CreateWallet(walletID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	var res event.KeygenResultEvent
	select {
	case res = <-resCh:
	case <-ctx.Done():
		http.Error(w, "keygen timeout — NATS, Docker, 3 nodes running?", 504)
		return
	}
	if res.ResultType != event.ResultTypeSuccess {
		reason := res.ErrorReason
		if reason == "" {
			reason = string(res.ErrorCode)
		}
		http.Error(w, reason, 502)
		return
	}
	if len(res.EDDSAPubKey) != 32 {
		http.Error(w, "bad eddsa pubkey", 502)
		return
	}
	b64 := base64.StdEncoding.EncodeToString(res.EDDSAPubKey)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"walletId":      res.WalletID,
		"eddsaPubKey":   b64,
		"eddsa_pub_key": b64,
	})
}

// Solana `MessageV0` 직렬화(bytes) + wallet_id → Mpcium 임계 서명.
type signSolanaRequest struct {
	ClientID        string `json:"clientId"`
	WalletID        string `json:"walletId"`
	MessageBytesB64 string `json:"messageBytesB64"`
	NetworkCode     string `json:"networkCode"`
}

func handleSignSolanaMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var body signSolanaRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if body.WalletID == "" || body.MessageBytesB64 == "" {
		http.Error(w, "walletId and messageBytesB64 required", 400)
		return
	}
	if body.ClientID == "" {
		body.ClientID = "sign-" + uuid.New().String()
	}
	if !validClientID(body.ClientID) {
		http.Error(w, "invalid clientId", 400)
		return
	}
	if body.NetworkCode == "" {
		body.NetworkCode = "solana-devnet"
		if v := os.Getenv("MPC_SOLANA_NETWORK"); v != "" {
			body.NetworkCode = v
		} else if v := viper.GetString("mpc.network_internal_code"); v != "" {
			body.NetworkCode = v
		}
	}
	msgBytes, err := base64.StdEncoding.DecodeString(body.MessageBytesB64)
	if err != nil || len(msgBytes) < 32 {
		http.Error(w, "bad messageBytesB64", 400)
		return
	}

	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}
	natsURL := viper.GetString("nats.url")
	if natsURL == "" {
		http.Error(w, "nats.url missing in config", 500)
		return
	}
	nc, err := nats.Connect(natsURL, nats.Name("predict-mpc-bridge-sign"), nats.Timeout(8*time.Second), nats.MaxReconnects(2))
	if err != nil {
		http.Error(w, fmt.Sprintf("NATS: %v", err), 502)
		return
	}
	defer func() { _ = nc.Drain() }()
	defer nc.Close()
	signer, err := newBridgeSigner(algorithm)
	if err != nil {
		http.Error(w, fmt.Sprintf("signer: %v", err), 500)
		return
	}
	mpcCl := client.NewMPCClient(client.Options{NatsConn: nc, Signer: signer, ClientID: body.ClientID})
	txID := uuid.New().String()
	resCh := make(chan event.SigningResultEvent, 1)
	if err := mpcCl.OnSignResult(func(e event.SigningResultEvent) {
		if e.TxID == txID {
			resCh <- e
		}
	}); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	signMsg := &types.SignTxMessage{
		KeyType:             types.KeyTypeEd25519,
		WalletID:            body.WalletID,
		NetworkInternalCode: body.NetworkCode,
		TxID:                txID,
		Tx:                  msgBytes,
	}
	if err := mpcCl.SignTransaction(signMsg); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	var out event.SigningResultEvent
	select {
	case out = <-resCh:
	case <-ctx.Done():
		http.Error(w, "signing timeout (nodes up? same walletId as keygen?)", 504)
		return
	}
	if out.ResultType != event.ResultTypeSuccess {
		reason := out.ErrorReason
		if reason == "" {
			reason = string(out.ErrorCode)
		}
		http.Error(w, reason, 502)
		return
	}
	if len(out.Signature) != 64 {
		// R,S 가 따로일 수 있음: 합치기
		if len(out.R) == 32 && len(out.S) == 32 {
			out.Signature = append(append([]byte{}, out.R...), out.S...)
		}
	}
	if len(out.Signature) != 64 {
		http.Error(w, "unexpected signature size", 502)
		return
	}
	sigB64 := base64.StdEncoding.EncodeToString(out.Signature)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"txId":         txID,
		"signatureB64": sigB64,
		"networkCode":  body.NetworkCode,
		"walletId":     body.WalletID,
	})
}
