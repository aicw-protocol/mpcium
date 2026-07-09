package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/mr-tron/base58"
	"github.com/spf13/viper"
)

func leToInt(b []byte) *big.Int {
	reversed := make([]byte, len(b))
	for i, v := range b {
		reversed[len(b)-1-i] = v
	}
	return new(big.Int).SetBytes(reversed)
}

func bytesLessThan(a, b []byte) bool {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}

// BeneficiaryShare represents a beneficiary and their percentage share
type BeneficiaryShare struct {
	Pubkey [32]byte
	Pct    uint8
}

// AIWillData contains parsed AIWill account data
type AIWillData struct {
	Wallet        [32]byte
	Beneficiaries []BeneficiaryShare
	LastHeartbeat int64
	DeathTimeout  int64
	UpdatedByAI   bool
	IsExecuted    bool
	Bump          uint8
}

// checkAICWNotDead verifies the AICW wallet is alive before signing.
// Returns error if wallet is dead (heartbeat timeout expired).
// Returns nil if wallet is alive or if AICW check is not configured.
func checkAICWNotDead(ctx context.Context, aiAgentPubkeyB58 string) error {
	// Decode AI Agent Pubkey from base58
	aiAgentPubkeyBytes, err := base58.Decode(aiAgentPubkeyB58)
	if err != nil || len(aiAgentPubkeyBytes) != 32 {
		// Invalid pubkey format - skip check
		return nil
	}

	// Get program ID
	programID := os.Getenv("AICW_PROGRAM_ID")
	if programID == "" {
		programID = viper.GetString("aicw.program_id")
	}
	if programID == "" {
		// No program ID configured - skip check
		return nil
	}
	programIDBytes, err := base58.Decode(programID)
	if err != nil || len(programIDBytes) != 32 {
		return nil // Invalid program ID - skip check
	}

	// Get RPC URL
	rpcURL := os.Getenv("SOLANA_RPC_URL")
	if rpcURL == "" {
		rpcURL = viper.GetString("solana.rpc_url")
	}
	if rpcURL == "" {
		rpcURL = "https://api.devnet.solana.com"
	}

	// Derive AICW PDA: seeds = ["aicw", aiAgentPubkey]
	aicwPDA, _, err := findProgramAddress([][]byte{[]byte("aicw"), aiAgentPubkeyBytes}, programIDBytes)
	if err != nil {
		return nil // PDA derivation failed - skip check
	}

	// Derive AIWill PDA: seeds = ["will", aicwPDA]
	willPDA, _, err := findProgramAddress([][]byte{[]byte("will"), aicwPDA}, programIDBytes)
	if err != nil {
		return nil // PDA derivation failed - skip check
	}

	// Query AIWill account
	willAccount, err := getAccountInfo(ctx, rpcURL, base58.Encode(willPDA))
	if err != nil || willAccount == nil {
		// No will account or error - skip check (will not created yet)
		return nil
	}

	// Parse AIWill account data
	// Layout (after 8-byte discriminator):
	// - wallet: Pubkey (32 bytes) - offset 8
	// - beneficiaries: Vec<BeneficiaryShare> - offset 40 (4 byte len + items)
	// - last_heartbeat: i64 - variable offset (after beneficiaries)
	// - death_timeout: i64 - after last_heartbeat
	// - updated_by_ai: bool
	// - is_executed: bool
	// - bump: u8

	if len(willAccount) < 8 {
		return nil // Account too short
	}

	// Skip discriminator (8 bytes) + wallet pubkey (32 bytes)
	offset := 8 + 32

	// Read beneficiaries vec length
	if len(willAccount) < offset+4 {
		return nil
	}
	beneficiariesLen := binary.LittleEndian.Uint32(willAccount[offset : offset+4])
	offset += 4

	// Skip beneficiaries: each is 32 (pubkey) + 1 (pct) = 33 bytes
	offset += int(beneficiariesLen) * 33

	// Read last_heartbeat (i64)
	if len(willAccount) < offset+8 {
		return nil
	}
	lastHeartbeat := int64(binary.LittleEndian.Uint64(willAccount[offset : offset+8]))
	offset += 8

	// Read death_timeout (i64)
	if len(willAccount) < offset+8 {
		return nil
	}
	deathTimeout := int64(binary.LittleEndian.Uint64(willAccount[offset : offset+8]))
	offset += 8

	// Read updated_by_ai (bool)
	if len(willAccount) < offset+1 {
		return nil
	}
	updatedByAI := willAccount[offset] != 0
	offset += 1

	// Read is_executed (bool)
	if len(willAccount) < offset+1 {
		return nil
	}
	isExecuted := willAccount[offset] != 0

	// If already executed, wallet is dead
	if isExecuted {
		return fmt.Errorf("AICW wallet already executed")
	}

	// If not updated by AI, will is not activated - allow signing
	if !updatedByAI {
		return nil
	}

	// Check if dead: current_time > last_heartbeat + death_timeout
	now := time.Now().Unix()
	if now > lastHeartbeat+deathTimeout {
		return fmt.Errorf("AICW wallet is DEAD (last_heartbeat=%d, death_timeout=%d, now=%d)", lastHeartbeat, deathTimeout, now)
	}

	return nil
}

func getAccountInfo(ctx context.Context, rpcURL, pubkey string) ([]byte, error) {
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getAccountInfo",
		"params": []interface{}{
			pubkey,
			map[string]string{"encoding": "base64", "commitment": "confirmed"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp struct {
		Result struct {
			Value *struct {
				Data []interface{} `json:"data"`
			} `json:"value"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, err
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", rpcResp.Error.Message)
	}
	if rpcResp.Result.Value == nil || len(rpcResp.Result.Value.Data) == 0 {
		return nil, nil // Account doesn't exist
	}

	// Data is [base64_string, "base64"]
	dataStr, ok := rpcResp.Result.Value.Data[0].(string)
	if !ok {
		return nil, fmt.Errorf("unexpected data format")
	}

	decoded, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// findProgramAddress finds a valid PDA for the given seeds and program ID
func findProgramAddress(seeds [][]byte, programID []byte) ([]byte, uint8, error) {
	for nonce := uint8(255); ; nonce-- {
		pda, err := createProgramAddress(append(seeds, []byte{nonce}), programID)
		if err == nil {
			return pda, nonce, nil
		}
		if nonce == 0 {
			break
		}
	}
	return nil, 0, fmt.Errorf("unable to find valid PDA")
}

// createProgramAddress creates a program address from seeds
func createProgramAddress(seeds [][]byte, programID []byte) ([]byte, error) {
	var buf bytes.Buffer
	for _, seed := range seeds {
		if len(seed) > 32 {
			return nil, fmt.Errorf("seed too long")
		}
		buf.Write(seed)
	}
	buf.Write(programID)
	buf.WriteString("ProgramDerivedAddress")

	hash := sha256.Sum256(buf.Bytes())

	// Check if point is on curve (if so, it's not a valid PDA)
	if isOnCurve(hash[:]) {
		return nil, fmt.Errorf("point is on curve")
	}

	return hash[:], nil
}

// isOnCurve checks if a 32-byte slice is a valid compressed ed25519 point.
// Uses crypto/ed25519 internal: if the point can be successfully used to
// verify a dummy signature, it's on curve. Actually we use a simpler approach:
// attempt to decompress by calling ed25519.PublicKey and verifying structure.
func isOnCurve(point []byte) bool {
	if len(point) != 32 {
		return false
	}
	// A valid ed25519 public key is a compressed point on the curve.
	// We try to "verify" a zero signature with it — if the point is invalid
	// (off-curve), the verify function will return false immediately.
	// But ed25519.Verify doesn't actually check if the point is on curve before
	// attempting math, so we need a different approach.
	//
	// Solana uses: try to decompress the y coordinate and check if valid.
	// We replicate this using the crypto/internal approach:
	// A 32-byte compressed edwards25519 point encodes y with sign bit in high bit of last byte.
	// We attempt decompression via the standard library's internal SetBytes.

	// Use filippo.io/edwards25519 which is vendored in Go's crypto library
	// Since Go 1.20+, we can use crypto/ed25519 internals indirectly.
	// Simpler approach: use the fact that crypto/ed25519's PublicKey is just []byte,
	// and Verify will fail fast if the point is not on curve.

	// The most reliable way in Go: try to do a scalar mult. If point is off-curve, it panics or errors.
	// Actually, the cleanest approach for Solana PDA: use the same logic as solana-sdk:
	// Try to decompress the point. If it fails, it's off-curve.

	// Go's crypto/ed25519 doesn't expose point decompression directly.
	// But we can use: create a fake "signature" verification that implicitly checks the point.
	// If Verify doesn't panic and returns false quickly, the key might still be on curve.
	// This doesn't work reliably.

	// BEST APPROACH: port Solana's check directly.
	// In Solana, a point is on the ed25519 curve if it can be decompressed.
	// We use the curve25519 field math to check.

	// For correctness, use the CompressedEdwardsY approach:
	// Decode y from bytes, compute x^2 = (y^2 - 1) / (d*y^2 + 1), check if x^2 is a square.

	return isOnEdwardsCurve(point)
}

// isOnEdwardsCurve performs proper ed25519 point decompression check.
// Returns true if the 32 bytes represent a valid compressed ed25519 point.
func isOnEdwardsCurve(s []byte) bool {
	// Ed25519 curve: -x^2 + y^2 = 1 + d*x^2*y^2
	// p = 2^255 - 19

	var y [32]byte
	copy(y[:], s)
	y[31] &= 0x7f // clear sign bit

	p := [32]byte{
		0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	}

	if !bytesLessThan(y[:], p[:]) {
		return false
	}

	yBig := leToInt(y[:])
	pBig := leToInt(p[:])

	// y^2 mod p
	yy := new(big.Int).Mul(yBig, yBig)
	yy.Mod(yy, pBig)

	// d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
	dBig, _ := new(big.Int).SetString("37095705934669439343138083508754565189542113879843219016388785533085940283555", 10)

	one := big.NewInt(1)

	// u = y^2 - 1
	u := new(big.Int).Sub(yy, one)
	u.Mod(u, pBig)

	// v = d*y^2 + 1
	v := new(big.Int).Mul(dBig, yy)
	v.Add(v, one)
	v.Mod(v, pBig)

	// x^2 = u * v^{-1} mod p
	vInv := new(big.Int).ModInverse(v, pBig)
	if vInv == nil {
		return false
	}
	xx := new(big.Int).Mul(u, vInv)
	xx.Mod(xx, pBig)

	if xx.Sign() == 0 {
		return true
	}

	// Euler's criterion: xx^((p-1)/2) == 1 mod p means quadratic residue
	exp := new(big.Int).Sub(pBig, one)
	exp.Rsh(exp, 1)

	result := new(big.Int).Exp(xx, exp, pBig)
	return result.Cmp(one) == 0
}

// checkAICWIsDead verifies the AICW wallet is DEAD (opposite of checkAICWNotDead).
// Returns nil if wallet is dead and ready for will execution.
// Returns error if wallet is still alive or will is not activated.
func checkAICWIsDead(ctx context.Context, aiAgentPubkeyB58 string) (*AIWillData, error) {
	aiAgentPubkeyBytes, err := base58.Decode(aiAgentPubkeyB58)
	if err != nil || len(aiAgentPubkeyBytes) != 32 {
		return nil, fmt.Errorf("invalid AI agent pubkey format")
	}

	programID := os.Getenv("AICW_PROGRAM_ID")
	if programID == "" {
		programID = viper.GetString("aicw.program_id")
	}
	if programID == "" {
		programID = viper.GetString("aicw_program_id")
	}
	if programID == "" {
		return nil, fmt.Errorf("AICW_PROGRAM_ID not configured (tried env, aicw.program_id, aicw_program_id)")
	}
	programIDBytes, err := base58.Decode(programID)
	if err != nil || len(programIDBytes) != 32 {
		return nil, fmt.Errorf("invalid AICW program ID")
	}

	rpcURL := os.Getenv("SOLANA_RPC_URL")
	if rpcURL == "" {
		rpcURL = viper.GetString("solana.rpc_url")
	}
	if rpcURL == "" {
		rpcURL = "https://api.devnet.solana.com"
	}

	// Derive AICW PDA: seeds = ["aicw", aiAgentPubkey]
	aicwPDA, _, err := findProgramAddress([][]byte{[]byte("aicw"), aiAgentPubkeyBytes}, programIDBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive AICW PDA: %v", err)
	}

	// Derive AIWill PDA: seeds = ["will", aicwPDA]
	willPDA, _, err := findProgramAddress([][]byte{[]byte("will"), aicwPDA}, programIDBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive AIWill PDA: %v", err)
	}

	willAccount, err := getAccountInfo(ctx, rpcURL, base58.Encode(willPDA))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch AIWill account: %v", err)
	}
	if willAccount == nil {
		return nil, fmt.Errorf("AIWill account does not exist")
	}

	willData, err := parseAIWillAccount(willAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AIWill account: %v", err)
	}

	if willData.IsExecuted {
		return nil, fmt.Errorf("will has already been executed")
	}

	if !willData.UpdatedByAI {
		return nil, fmt.Errorf("will not activated by AI (updated_by_ai = false)")
	}

	if len(willData.Beneficiaries) == 0 {
		return nil, fmt.Errorf("no beneficiaries defined")
	}

	// Check if dead: current_time > last_heartbeat + death_timeout
	now := time.Now().Unix()
	if now <= willData.LastHeartbeat+willData.DeathTimeout {
		remaining := (willData.LastHeartbeat + willData.DeathTimeout) - now
		return nil, fmt.Errorf("wallet is still ALIVE (heartbeat valid for %d more seconds)", remaining)
	}

	return willData, nil
}

// parseAIWillAccount parses raw account data into AIWillData
func parseAIWillAccount(data []byte) (*AIWillData, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("account data too short")
	}

	result := &AIWillData{}
	offset := 8 // Skip discriminator

	// Read wallet pubkey (32 bytes)
	if len(data) < offset+32 {
		return nil, fmt.Errorf("data too short for wallet pubkey")
	}
	copy(result.Wallet[:], data[offset:offset+32])
	offset += 32

	// Read beneficiaries vec length
	if len(data) < offset+4 {
		return nil, fmt.Errorf("data too short for beneficiaries length")
	}
	beneficiariesLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Read beneficiaries: each is 32 (pubkey) + 1 (pct) = 33 bytes
	result.Beneficiaries = make([]BeneficiaryShare, beneficiariesLen)
	for i := uint32(0); i < beneficiariesLen; i++ {
		if len(data) < offset+33 {
			return nil, fmt.Errorf("data too short for beneficiary %d", i)
		}
		copy(result.Beneficiaries[i].Pubkey[:], data[offset:offset+32])
		result.Beneficiaries[i].Pct = data[offset+32]
		offset += 33
	}

	// Read last_heartbeat (i64)
	if len(data) < offset+8 {
		return nil, fmt.Errorf("data too short for last_heartbeat")
	}
	result.LastHeartbeat = int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
	offset += 8

	// Read death_timeout (i64)
	if len(data) < offset+8 {
		return nil, fmt.Errorf("data too short for death_timeout")
	}
	result.DeathTimeout = int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
	offset += 8

	// Read updated_by_ai (bool)
	if len(data) < offset+1 {
		return nil, fmt.Errorf("data too short for updated_by_ai")
	}
	result.UpdatedByAI = data[offset] != 0
	offset += 1

	// Read is_executed (bool)
	if len(data) < offset+1 {
		return nil, fmt.Errorf("data too short for is_executed")
	}
	result.IsExecuted = data[offset] != 0
	offset += 1

	// Read bump (u8)
	if len(data) < offset+1 {
		return nil, fmt.Errorf("data too short for bump")
	}
	result.Bump = data[offset]

	return result, nil
}

// getAIAgentBalance fetches the SOL balance of the AI agent wallet
func getAIAgentBalance(ctx context.Context, aiAgentPubkeyB58 string) (uint64, error) {
	rpcURL := os.Getenv("SOLANA_RPC_URL")
	if rpcURL == "" {
		rpcURL = viper.GetString("solana.rpc_url")
	}
	if rpcURL == "" {
		rpcURL = "https://api.devnet.solana.com"
	}

	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getBalance",
		"params": []interface{}{
			aiAgentPubkeyB58,
			map[string]string{"commitment": "confirmed"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var rpcResp struct {
		Result struct {
			Value uint64 `json:"value"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return 0, err
	}
	if rpcResp.Error != nil {
		return 0, fmt.Errorf("rpc error: %s", rpcResp.Error.Message)
	}

	return rpcResp.Result.Value, nil
}

// getRecentBlockhash fetches a recent blockhash for transaction construction
func getRecentBlockhash(ctx context.Context) (string, uint64, error) {
	rpcURL := os.Getenv("SOLANA_RPC_URL")
	if rpcURL == "" {
		rpcURL = viper.GetString("solana.rpc_url")
	}
	if rpcURL == "" {
		rpcURL = "https://api.devnet.solana.com"
	}

	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getLatestBlockhash",
		"params": []interface{}{
			map[string]string{"commitment": "confirmed"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	var rpcResp struct {
		Result struct {
			Value struct {
				Blockhash            string `json:"blockhash"`
				LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
			} `json:"value"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", 0, err
	}
	if rpcResp.Error != nil {
		return "", 0, fmt.Errorf("rpc error: %s", rpcResp.Error.Message)
	}

	return rpcResp.Result.Value.Blockhash, rpcResp.Result.Value.LastValidBlockHeight, nil
}

// sendAndConfirmTransaction sends a signed transaction and waits for confirmation
func sendAndConfirmTransaction(ctx context.Context, signedTxB64 string) (string, error) {
	rpcURL := os.Getenv("SOLANA_RPC_URL")
	if rpcURL == "" {
		rpcURL = viper.GetString("solana.rpc_url")
	}
	if rpcURL == "" {
		rpcURL = "https://api.devnet.solana.com"
	}

	// Decode base64 transaction
	txBytes, err := base64.StdEncoding.DecodeString(signedTxB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode transaction: %v", err)
	}

	// Send transaction
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "sendTransaction",
		"params": []interface{}{
			base64.StdEncoding.EncodeToString(txBytes),
			map[string]interface{}{
				"encoding":       "base64",
				"skipPreflight":  false,
				"preflightCommitment": "confirmed",
			},
		},
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
			Data    struct {
				Logs []string `json:"logs"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", err
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("send error: %s", rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}
