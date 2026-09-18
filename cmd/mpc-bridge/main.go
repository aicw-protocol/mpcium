// predict 대시보드용 HTTP 브리지: NATS + Mpcium 노드에 keygen 요청 → Ed25519 공개키 JSON 반환.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

const defaultListen = ":8081"
const aiAgentPubkeyDailyLimit = 100
const aiAgentPubkeyMinuteLimit = 10

var clientIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)
var aiAgentPubkeyLimiter = newIPRateLimiter()

type pubkeyRequest struct {
	ClientID string `json:"clientId"`
}

type rateWindowCounter struct {
	windowStart time.Time
	count       int
}

type ipRateLimiter struct {
	mu      sync.Mutex
	daily   map[string]rateWindowCounter
	minute  map[string]rateWindowCounter
	nowFunc func() time.Time
}

func newIPRateLimiter() *ipRateLimiter {
	return &ipRateLimiter{
		daily:   make(map[string]rateWindowCounter),
		minute:  make(map[string]rateWindowCounter),
		nowFunc: time.Now,
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	now := l.nowFunc()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	minuteStart := now.Truncate(time.Minute)

	l.mu.Lock()
	defer l.mu.Unlock()

	if !incrementWindow(l.daily, ip, dayStart, aiAgentPubkeyDailyLimit) {
		return false
	}
	if !incrementWindow(l.minute, ip, minuteStart, aiAgentPubkeyMinuteLimit) {
		l.daily[ip] = rateWindowCounter{windowStart: dayStart, count: l.daily[ip].count - 1}
		return false
	}
	return true
}

func incrementWindow(counters map[string]rateWindowCounter, key string, start time.Time, limit int) bool {
	counter := counters[key]
	if !counter.windowStart.Equal(start) {
		counter = rateWindowCounter{windowStart: start}
	}
	if counter.count >= limit {
		counters[key] = counter
		return false
	}
	counter.count++
	counters[key] = counter
	return true
}

func requestIP(r *http.Request) string {
	if forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
		ip := strings.TrimSpace(strings.Split(forwardedFor, ",")[0])
		if ip != "" {
			return ip
		}
	}
	host := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = ip
	}
	return strings.TrimSpace(host)
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
	mux.HandleFunc("OPTIONS /v1/mpc/execute-will", withCORS(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	mux.HandleFunc("POST /v1/mpc/execute-will", withCORS(handleExecuteWill))
	mux.HandleFunc("OPTIONS /v1/mpc/issuer-regions", withCORS(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	mux.HandleFunc("GET /v1/mpc/issuer-regions", withCORS(handleListIssuerRegions))
	mux.HandleFunc("POST /v1/mpc/issuer-regions", withCORS(handleRegisterIssuerRegion))
	// Internal, operator-only manual reshare (§5.1 / §13.6). Not CORS-exposed;
	// gated by bearer token and/or IP allowlist (see internalAuthOK).
	mux.HandleFunc("POST /internal/reshare", handleInternalReshare)
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, ngrok-skip-browser-warning, X-Event-Initiator-Signature, X-Event-Initiator-Timestamp")
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
	if !aiAgentPubkeyLimiter.allow(requestIP(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
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
	// AICW-FORK: the result consumer is durable per clientId and shared across
	// requests. A result that arrives after a previous request already returned
	// (e.g. a node-side timeout that outlived the 90s budget) stays pending and
	// is delivered to the NEXT request first. Without this filter the bridge
	// answered in ~40ms with another wallet's result while the real keygen ran
	// unobserved, producing the alternating 200/502 pattern. Only accept the
	// result for the wallet this request created; stale ones are acked and
	// dropped, which also drains the backlog.
	if err := mpcCl.OnWalletCreationResult(func(e event.KeygenResultEvent) {
		if e.WalletID != walletID {
			log.Printf("[ai-agent-pubkey] ignoring stale keygen result: got wallet %s, want %s", e.WalletID, walletID)
			return
		}
		select {
		case resCh <- e:
		default:
		}
	}); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// AICW-FORK: the Bridge decides which key families every wallet gets
	// (bridge config `keygen_key_types`, default Ed25519 only). The list is
	// signed into the request, so enabling ECDSA later is a one-line change on
	// this server — no coordinated config rollout across operator nodes.
	keyTypes := bridgeKeygenKeyTypes()
	if err := mpcCl.CreateWalletWithKeyTypes(walletID, keyTypes, nil); err != nil {
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
		// AICW-FORK (auto_reshare_design.md §13.3 / §1.7 AC): when the cluster or
		// peers are not ready — which includes the committee-local ECDH exchange
		// not yet being complete — return a distinct 503 ecdh_not_ready instead of
		// a generic 502. This tells the client it is a transient "not ready yet"
		// condition to retry, rather than a hard TSS failure.
		switch res.ErrorCode {
		case string(event.ErrorCodeClusterNotReady), string(event.ErrorCodePeerNotReady):
			http.Error(w, "ecdh_not_ready", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, reason, 502)
		return
	}
	if len(res.EDDSAPubKey) != 32 {
		http.Error(w, "bad eddsa pubkey", 502)
		return
	}

	// Store AI PK -> wallet ID mapping for execute-will lookups
	aiPubkeyB58 := base58.Encode(res.EDDSAPubKey)
	if err := putAIPKToWalletID(aiPubkeyB58, res.WalletID); err != nil {
		log.Printf("[ai-agent-pubkey] Warning: failed to store AI PK -> wallet ID mapping: %v", err)
	} else {
		log.Printf("[ai-agent-pubkey] Stored mapping: %s -> %s", aiPubkeyB58, res.WalletID)
	}

	b64 := base64.StdEncoding.EncodeToString(res.EDDSAPubKey)
	out := map[string]any{
		"walletId":      res.WalletID,
		"eddsaPubKey":   b64,
		"eddsa_pub_key": b64,
	}
	// Present only when the Bridge requested secp256k1 (EVM) as well.
	if len(res.ECDSAPubKey) > 0 {
		out["ecdsaPubKey"] = base64.StdEncoding.EncodeToString(res.ECDSAPubKey)
		out["ecdsa_pub_key"] = out["ecdsaPubKey"]
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// bridgeKeygenKeyTypes returns the key families the Bridge requests for every
// new wallet, from `keygen_key_types` in the bridge config (default Ed25519
// only). Invalid config falls back to the default and is logged, so a typo
// cannot take wallet creation down.
func bridgeKeygenKeyTypes() []types.KeyType {
	kts, err := types.ParseKeyTypes(viper.GetStringSlice(types.KeygenKeyTypesConfigKey))
	if err != nil {
		log.Printf("[ai-agent-pubkey] invalid %s in bridge config (%v); defaulting to %v",
			types.KeygenKeyTypesConfigKey, err, types.DefaultKeygenKeyTypes)
		return append([]types.KeyType(nil), types.DefaultKeygenKeyTypes...)
	}
	return kts
}

// Solana `MessageV0` 직렬화(bytes) + wallet_id → Mpcium 임계 서명.
type signSolanaRequest struct {
	ClientID        string `json:"clientId"`
	WalletID        string `json:"walletId"`
	MessageBytesB64 string `json:"messageBytesB64"`
	NetworkCode     string `json:"networkCode"`
	AIAgentPubkey   string `json:"aiAgentPubkey,omitempty"` // Base58-encoded AI agent pubkey for AICW death check
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

	// AICW death check: verify wallet is alive before signing
	if body.AIAgentPubkey != "" {
		if err := checkAICWNotDead(r.Context(), body.AIAgentPubkey); err != nil {
			http.Error(w, fmt.Sprintf("AICW wallet dead: %v", err), 403)
			return
		}
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
	postMpcRewardEvent(body.WalletID, detectMpcRewardEventType(msgBytes), txID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"txId":         txID,
		"signatureB64": sigB64,
		"networkCode":  body.NetworkCode,
		"walletId":     body.WalletID,
	})
}

// executeWillRequest is the request body for /v1/mpc/execute-will
type executeWillRequest struct {
	ClientID      string `json:"clientId"`
	WalletID      string `json:"walletId"`      // MPC wallet ID (from keygen)
	AIAgentPubkey string `json:"aiAgentPubkey"` // Base58-encoded AI agent pubkey
	NetworkCode   string `json:"networkCode"`
}

// handleExecuteWill handles will execution for dead AI agents.
// It verifies the AI is dead, constructs transfer transactions to beneficiaries,
// signs them with MPC, and broadcasts to the network.
func handleExecuteWill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}

	var body executeWillRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if body.AIAgentPubkey == "" {
		http.Error(w, "aiAgentPubkey required", 400)
		return
	}

	// Auto-lookup wallet ID if not provided
	if body.WalletID == "" {
		walletID, err := getWalletIDByAIPK(body.AIAgentPubkey)
		if err != nil {
			http.Error(w, fmt.Sprintf("walletId not provided and lookup failed: %v. Please provide walletId or ensure the AI agent was created via this MPC bridge.", err), 400)
			return
		}
		body.WalletID = walletID
		log.Printf("[execute-will] Auto-resolved walletId for %s: %s", body.AIAgentPubkey, walletID)
	}
	if body.ClientID == "" {
		body.ClientID = "execute-will-" + uuid.New().String()
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

	ctx := r.Context()

	// 1. Verify AI is DEAD
	willData, err := checkAICWIsDead(ctx, body.AIAgentPubkey)
	if err != nil {
		errMsg := fmt.Sprintf("Cannot execute will: %v", err)
		log.Printf("[execute-will] REJECTED: %s", errMsg)
		http.Error(w, errMsg, 403)
		return
	}

	log.Printf("[execute-will] AI %s is confirmed DEAD. Beneficiaries: %d", body.AIAgentPubkey, len(willData.Beneficiaries))

	// 2. Get AI agent balance
	balance, err := getAIAgentBalance(ctx, body.AIAgentPubkey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get AI agent balance: %v", err), 500)
		return
	}

	// AI PK wallet is a normal EOA (0 data bytes) — no rent-exempt reserve needed.
	// Only reserve enough for transaction fees (5000 lamports per transfer).
	const txFee = uint64(5000)
	totalFees := txFee * uint64(len(willData.Beneficiaries))

	if balance <= totalFees {
		http.Error(w, fmt.Sprintf("Insufficient balance: %d lamports (need > %d for fees)", balance, totalFees), 400)
		return
	}

	distributable := balance - totalFees
	log.Printf("[execute-will] Balance: %d lamports, Distributable: %d lamports", balance, distributable)

	// 3. Calculate amounts for each beneficiary
	type beneficiaryTransfer struct {
		Pubkey string
		Amount uint64
	}
	var transfers []beneficiaryTransfer
	var allocated uint64 = 0

	for i, b := range willData.Beneficiaries {
		var amount uint64
		if i == len(willData.Beneficiaries)-1 {
			// Last beneficiary gets remainder to avoid rounding errors
			amount = distributable - allocated
		} else {
			amount = (distributable * uint64(b.Pct)) / 100
			allocated += amount
		}
		if amount > 0 {
			transfers = append(transfers, beneficiaryTransfer{
				Pubkey: base58.Encode(b.Pubkey[:]),
				Amount: amount,
			})
		}
	}

	if len(transfers) == 0 {
		http.Error(w, "No transfers to execute (all amounts are 0)", 400)
		return
	}

	// 4. Get recent blockhash
	blockhash, _, err := getRecentBlockhash(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get blockhash: %v", err), 500)
		return
	}
	blockhashBytes, err := base58.Decode(blockhash)
	if err != nil {
		http.Error(w, "Failed to decode blockhash", 500)
		return
	}

	// 5. Setup MPC client
	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}
	natsURL := viper.GetString("nats.url")
	if natsURL == "" {
		http.Error(w, "nats.url missing in config", 500)
		return
	}
	nc, err := nats.Connect(natsURL, nats.Name("mpc-bridge-execute-will"), nats.Timeout(8*time.Second), nats.MaxReconnects(2))
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

	// 6. Execute transfers one by one
	var results []map[string]any
	var willExecuteSig string
	aiAgentPubkeyBytes, _ := base58.Decode(body.AIAgentPubkey)

	for _, transfer := range transfers {
		toPubkeyBytes, err := base58.Decode(transfer.Pubkey)
		if err != nil {
			results = append(results, map[string]any{
				"beneficiary": transfer.Pubkey,
				"amount":      transfer.Amount,
				"error":       "invalid beneficiary pubkey",
			})
			continue
		}

		// Build Solana transfer instruction (System Program Transfer)
		// Instruction data: [2, 0, 0, 0] + amount (8 bytes LE) = transfer instruction
		txMessage := buildSolanaTransferMessage(aiAgentPubkeyBytes, toPubkeyBytes, transfer.Amount, blockhashBytes)

		// Sign with MPC
		txID := uuid.New().String()
		resCh := make(chan event.SigningResultEvent, 1)
		if err := mpcCl.OnSignResult(func(e event.SigningResultEvent) {
			if e.TxID == txID {
				resCh <- e
			}
		}); err != nil {
			results = append(results, map[string]any{
				"beneficiary": transfer.Pubkey,
				"amount":      transfer.Amount,
				"error":       fmt.Sprintf("setup sign listener: %v", err),
			})
			continue
		}

		signMsg := &types.SignTxMessage{
			KeyType:             types.KeyTypeEd25519,
			WalletID:            body.WalletID,
			NetworkInternalCode: body.NetworkCode,
			TxID:                txID,
			Tx:                  txMessage,
		}
		if err := mpcCl.SignTransaction(signMsg); err != nil {
			results = append(results, map[string]any{
				"beneficiary": transfer.Pubkey,
				"amount":      transfer.Amount,
				"error":       fmt.Sprintf("sign request: %v", err),
			})
			continue
		}

		// Wait for signature
		signCtx, signCancel := context.WithTimeout(ctx, 120*time.Second)
		var signResult event.SigningResultEvent
		select {
		case signResult = <-resCh:
		case <-signCtx.Done():
			signCancel()
			results = append(results, map[string]any{
				"beneficiary": transfer.Pubkey,
				"amount":      transfer.Amount,
				"error":       "signing timeout",
			})
			continue
		}
		signCancel()

		if signResult.ResultType != event.ResultTypeSuccess {
			reason := signResult.ErrorReason
			if reason == "" {
				reason = string(signResult.ErrorCode)
			}
			results = append(results, map[string]any{
				"beneficiary": transfer.Pubkey,
				"amount":      transfer.Amount,
				"error":       fmt.Sprintf("sign failed: %s", reason),
			})
			continue
		}

		// Combine signature
		var signature []byte
		if len(signResult.Signature) == 64 {
			signature = signResult.Signature
		} else if len(signResult.R) == 32 && len(signResult.S) == 32 {
			signature = append(append([]byte{}, signResult.R...), signResult.S...)
		} else {
			results = append(results, map[string]any{
				"beneficiary": transfer.Pubkey,
				"amount":      transfer.Amount,
				"error":       "unexpected signature format",
			})
			continue
		}

		// Build signed transaction and send
		signedTx := buildSignedTransaction(txMessage, signature)
		txSig, err := sendAndConfirmTransaction(ctx, base64.StdEncoding.EncodeToString(signedTx))
		if err != nil {
			results = append(results, map[string]any{
				"beneficiary": transfer.Pubkey,
				"amount":      transfer.Amount,
				"error":       fmt.Sprintf("send failed: %v", err),
			})
			continue
		}

		log.Printf("[execute-will] Transfer %d lamports to %s: %s", transfer.Amount, transfer.Pubkey, txSig)
		if willExecuteSig == "" {
			willExecuteSig = txSig
		}
		results = append(results, map[string]any{
			"beneficiary": transfer.Pubkey,
			"amount":      transfer.Amount,
			"signature":   txSig,
			"success":     true,
		})
	}

	postMpcRewardEvent(body.WalletID, "will_execute", willExecuteSig)

	// 7. Return results
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"aiAgentPubkey": body.AIAgentPubkey,
		"walletId":      body.WalletID,
		"totalBalance":  balance,
		"distributed":   distributable,
		"transfers":     results,
	})
}

// buildSolanaTransferMessage builds a Solana legacy transaction message for SOL transfer
func buildSolanaTransferMessage(from, to []byte, lamports uint64, recentBlockhash []byte) []byte {
	// System Program ID (all zeros)
	systemProgram := make([]byte, 32)

	// Build instruction data: transfer = [2, 0, 0, 0] + lamports (8 bytes LE)
	instructionData := make([]byte, 12)
	instructionData[0] = 2 // Transfer instruction index
	// lamports in little-endian
	instructionData[4] = byte(lamports)
	instructionData[5] = byte(lamports >> 8)
	instructionData[6] = byte(lamports >> 16)
	instructionData[7] = byte(lamports >> 24)
	instructionData[8] = byte(lamports >> 32)
	instructionData[9] = byte(lamports >> 40)
	instructionData[10] = byte(lamports >> 48)
	instructionData[11] = byte(lamports >> 56)

	// Legacy transaction message format:
	// - 1 byte: number of required signatures
	// - 1 byte: number of read-only signed accounts
	// - 1 byte: number of read-only unsigned accounts
	// - compact array of account addresses
	// - recent blockhash (32 bytes)
	// - compact array of instructions

	var msg bytes.Buffer

	// Header
	msg.WriteByte(1) // 1 signature required (from account)
	msg.WriteByte(0) // 0 read-only signed
	msg.WriteByte(1) // 1 read-only unsigned (system program)

	// Account addresses (compact array): from, to, system_program
	msg.WriteByte(3) // 3 accounts
	msg.Write(from)
	msg.Write(to)
	msg.Write(systemProgram)

	// Recent blockhash
	msg.Write(recentBlockhash)

	// Instructions (compact array)
	msg.WriteByte(1) // 1 instruction

	// Instruction: program_id_index, accounts, data
	msg.WriteByte(2)                     // program_id_index = 2 (system program)
	msg.WriteByte(2)                     // 2 accounts in instruction
	msg.WriteByte(0)                     // from account index
	msg.WriteByte(1)                     // to account index
	msg.WriteByte(byte(len(instructionData))) // data length
	msg.Write(instructionData)

	return msg.Bytes()
}

// buildSignedTransaction combines message with signature into a full transaction
func buildSignedTransaction(message, signature []byte) []byte {
	var tx bytes.Buffer

	// Compact array of signatures (1 signature)
	tx.WriteByte(1) // 1 signature
	tx.Write(signature)

	// Message
	tx.Write(message)

	return tx.Bytes()
}
