package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/google/uuid"
	"github.com/hashicorp/consul/api"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
)

// reshareRequest is the manual/operator reshare trigger body
// (auto_reshare_design.md §5.1 — manual reshare via mpc-bridge). The operator
// supplies the target committee explicitly; the Bridge does not auto-select a
// committee (that is the orchestrator's job). This endpoint is intended for
// operations and legacy-wallet migration (§13.6).
type reshareRequest struct {
	WalletID     string   `json:"wallet_id"`
	NodeIDs      []string `json:"node_ids"`
	NewThreshold int      `json:"new_threshold"`
	KeyTypes     []string `json:"key_types"` // optional; default ed25519 then secp256k1
	Force        bool     `json:"force"`
	ClientID     string   `json:"client_id"`
}

type reshareKeyResult struct {
	KeyType string `json:"key_type"`
	Result  string `json:"result"` // success|error
	PubKey  string `json:"pub_key,omitempty"`
	Error   string `json:"error,omitempty"`
}

type reshareResponse struct {
	WalletID  string             `json:"wallet_id"`
	SessionID string             `json:"session_id"`
	Committee []string           `json:"committee"`
	Results   []reshareKeyResult `json:"results"`
}

// manualReshareKeyTypes is the default ordered set (§4.4): EdDSA then ECDSA.
var manualReshareKeyTypes = []types.KeyType{types.KeyTypeEd25519, types.KeyTypeSecp256k1}

// internalAuthOK gates the internal endpoint (§5.1: mTLS / IP allowlist). We
// support a bearer token (env MPC_BRIDGE_INTERNAL_TOKEN) and/or an IP allowlist
// (config bridge.internal_allow_ips). At least one must be configured, else the
// endpoint is denied by default (fail-closed).
func internalAuthOK(r *http.Request) (bool, string) {
	token := strings.TrimSpace(os.Getenv("MPC_BRIDGE_INTERNAL_TOKEN"))
	allow := viper.GetStringSlice("bridge.internal_allow_ips")

	if token == "" && len(allow) == 0 {
		return false, "internal reshare endpoint not configured (set MPC_BRIDGE_INTERNAL_TOKEN or bridge.internal_allow_ips)"
	}

	if token != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(token)) != 1 {
			return false, "invalid or missing bearer token"
		}
	}

	if len(allow) > 0 {
		ip := requestIP(r)
		if !containsString(allow, ip) {
			return false, fmt.Sprintf("ip %s not allowed", ip)
		}
	}

	return true, ""
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if strings.TrimSpace(s) == v {
			return true
		}
	}
	return false
}

func handleInternalReshare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if ok, reason := internalAuthOK(r); !ok {
		logger.Warn("Internal reshare denied", "ip", requestIP(r), "reason", reason)
		http.Error(w, "forbidden: "+reason, http.StatusForbidden)
		return
	}

	var body reshareRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.WalletID == "" {
		http.Error(w, "wallet_id required", http.StatusBadRequest)
		return
	}
	if body.NewThreshold < 1 {
		http.Error(w, "new_threshold must be >= 1", http.StatusBadRequest)
		return
	}
	if len(body.NodeIDs) < body.NewThreshold+1 {
		http.Error(w, fmt.Sprintf("node_ids (%d) must be >= new_threshold+1 (%d)", len(body.NodeIDs), body.NewThreshold+1), http.StatusBadRequest)
		return
	}

	keyTypes, err := parseReshareKeyTypes(body.KeyTypes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	algorithm := viper.GetString("event_initiator_algorithm")
	if algorithm == "" {
		algorithm = string(types.EventInitiatorKeyTypeEd25519)
	}

	natsURL := viper.GetString("nats.url")
	if natsURL == "" {
		http.Error(w, "nats.url missing in config", http.StatusInternalServerError)
		return
	}
	nc, err := nats.Connect(natsURL, nats.Name("mpc-bridge-reshare"), nats.Timeout(8*time.Second), nats.MaxReconnects(2))
	if err != nil {
		http.Error(w, fmt.Sprintf("NATS: %v", err), http.StatusBadGateway)
		return
	}
	defer func() { _ = nc.Drain() }()
	defer nc.Close()

	signer, err := newBridgeSigner(algorithm)
	if err != nil {
		http.Error(w, fmt.Sprintf("signer: %v", err), http.StatusInternalServerError)
		return
	}
	initiatorPub, _ := signer.PublicKey()

	clientID := body.ClientID
	if clientID == "" {
		clientID = "bridge-reshare-" + uuid.New().String()
	}
	if !validClientID(clientID) {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}

	mpcCl := client.NewMPCClient(client.Options{NatsConn: nc, Signer: signer, ClientID: clientID})

	authorizers, err := loadBridgeAuthorizers()
	if err != nil {
		http.Error(w, fmt.Sprintf("authorizers: %v", err), http.StatusInternalServerError)
		return
	}

	resCh := make(chan event.ResharingResultEvent, len(keyTypes))
	if err := mpcCl.OnResharingResult(func(e event.ResharingResultEvent) { resCh <- e }); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionID := uuid.New().String()
	resp := reshareResponse{WalletID: body.WalletID, SessionID: sessionID, Committee: body.NodeIDs}

	logger.Info("Manual reshare requested",
		"walletID", body.WalletID, "committee", body.NodeIDs, "newThreshold", body.NewThreshold,
		"keyTypes", body.KeyTypes, "force", body.Force, "ip", requestIP(r))

	// Sequential per key type (§4.4). Stop early if a family fails, unless force.
	allOK := true
	for _, kt := range keyTypes {
		kr := publishAndWaitReshare(r.Context(), mpcCl, resCh, body, kt, authorizers)
		resp.Results = append(resp.Results, kr)
		if kr.Result != "success" {
			allOK = false
			if !body.Force {
				break
			}
		}
	}

	writeManualReshareAudit(sessionID, body, initiatorPub, resp, allOK)

	w.Header().Set("Content-Type", "application/json")
	if !allOK {
		w.WriteHeader(http.StatusBadGateway)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func publishAndWaitReshare(
	ctx context.Context,
	mpcCl client.MPCClient,
	resCh <-chan event.ResharingResultEvent,
	body reshareRequest,
	kt types.KeyType,
	authorizers []*bridgeAuthorizer,
) reshareKeyResult {
	kr := reshareKeyResult{KeyType: string(kt)}

	msg := &types.ResharingMessage{
		SessionID:    uuid.New().String(),
		NodeIDs:      body.NodeIDs,
		NewThreshold: body.NewThreshold,
		KeyType:      kt,
		WalletID:     body.WalletID,
	}
	var pubErr error
	if collect := collectBridgeAuthorizerSignatures(ctx, authorizers); collect != nil {
		pubErr = mpcCl.ResharingWithAuthorizers(msg, collect)
	} else {
		pubErr = mpcCl.Resharing(msg)
	}
	if pubErr != nil {
		kr.Result = "error"
		kr.Error = pubErr.Error()
		return kr
	}

	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	for {
		select {
		case <-waitCtx.Done():
			kr.Result = "error"
			kr.Error = "timeout waiting for reshare result"
			return kr
		case e := <-resCh:
			// Match this key type (per-wallet single in-flight in this handler).
			if e.KeyType != kt {
				continue
			}
			if e.ResultType != event.ResultTypeSuccess {
				kr.Result = "error"
				kr.Error = e.ErrorReason
				if kr.Error == "" {
					kr.Error = e.ErrorCode
				}
				return kr
			}
			kr.Result = "success"
			kr.PubKey = hex.EncodeToString(e.PubKey)
			return kr
		}
	}
}

func parseReshareKeyTypes(in []string) ([]types.KeyType, error) {
	if len(in) == 0 {
		return manualReshareKeyTypes, nil
	}
	out := make([]types.KeyType, 0, len(in))
	for _, s := range in {
		switch types.KeyType(s) {
		case types.KeyTypeEd25519:
			out = append(out, types.KeyTypeEd25519)
		case types.KeyTypeSecp256k1:
			out = append(out, types.KeyTypeSecp256k1)
		default:
			return nil, fmt.Errorf("unknown key_type %q (want ed25519 or secp256k1)", s)
		}
	}
	return out, nil
}

// writeManualReshareAudit records the manual reshare to Consul reshare_audit/*
// (§5.3C, trigger=manual). Audit failure is logged but does not fail the request.
func writeManualReshareAudit(sessionID string, body reshareRequest, initiatorPub string, resp reshareResponse, allOK bool) {
	result := "success"
	if !allOK {
		result = "failure"
	}
	pubKeys := map[string]string{}
	for _, kr := range resp.Results {
		if kr.PubKey != "" {
			pubKeys[kr.KeyType] = kr.PubKey
		}
	}
	record := map[string]any{
		"session_id":       sessionID,
		"wallet_id":        body.WalletID,
		"trigger":          "manual",
		"new_committee":    body.NodeIDs,
		"new_threshold":    body.NewThreshold,
		"force":            body.Force,
		"initiator_pubkey": initiatorPub,
		"result":           result,
		"results":          resp.Results,
		"pub_keys":         pubKeys,
		"published_at":     time.Now().UTC().Format(time.RFC3339),
	}
	val, err := json.Marshal(record)
	if err != nil {
		logger.Error("Manual reshare: audit marshal failed", err, "walletID", body.WalletID)
		return
	}

	// Best-effort audit write. Unlike infra.GetConsulClient (which Fatal()s on a
	// connectivity error), we build the client directly and never crash the
	// Bridge if Consul is momentarily unreachable — the reshare itself already
	// happened and is logged.
	consul, cerr := newAuditConsulClient()
	if cerr != nil {
		logger.Error("Manual reshare: audit consul client failed (reshare still logged)", cerr, "walletID", body.WalletID)
		return
	}
	if _, err := consul.KV().Put(&api.KVPair{Key: "reshare_audit/" + sessionID, Value: val}, nil); err != nil {
		logger.Error("Manual reshare: audit write failed", err, "walletID", body.WalletID)
	}
}

// newAuditConsulClient builds a Consul client from the same viper config as
// infra.GetConsulClient, but returns an error instead of Fatal()-ing so a
// transient Consul outage cannot take down the Bridge from an HTTP handler.
func newAuditConsulClient() (*api.Client, error) {
	config := api.DefaultConfig()
	if viper.GetString("environment") == "production" {
		config.Token = viper.GetString("consul.token")
		username := viper.GetString("consul.username")
		password := viper.GetString("consul.password")
		if username != "" || password != "" {
			config.HttpAuth = &api.HttpBasicAuth{Username: username, Password: password}
		}
	}
	if addr := viper.GetString("consul.address"); addr != "" {
		config.Address = addr
	}
	config.WaitTime = 10 * time.Second
	return api.NewClient(config)
}
